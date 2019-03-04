/*
// Copyright (c) 2010-2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_version.h>

#include "rx_pkt.h"
#include "task_base.h"
#include "clock.h"
#include "stats.h"
#include "log.h"
#include "mbuf_utils.h"
#include "prefetch.h"
#include "arp.h"
#include "tx_pkt.h"
#include "handle_master.h"
#include "input.h" /* Needed for callback on dump */

/* _param version of the rx_pkt_hw functions are used to create two
   instances of very similar variations of these functions. The
   variations are specified by the "multi" parameter which significies
   that the rte_eth_rx_burst function should be called multiple times.
   The reason for this is that with the vector PMD, the maximum number
   of packets being returned is 32. If packets have been split in
   multiple mbufs then rte_eth_rx_burst might even receive less than
   32 packets.
   Some algorithms (like QoS) only work correctly if more than 32
   packets are received if the dequeue step involves finding 32 packets.
*/

#define MIN_PMD_RX 32

static uint16_t rx_pkt_hw_port_queue(struct port_queue *pq, struct rte_mbuf **mbufs, int multi)
{
	uint16_t nb_rx, n;

	nb_rx = rte_eth_rx_burst(pq->port, pq->queue, mbufs, MAX_PKT_BURST);

	if (multi) {
		n = nb_rx;
		while (n != 0 && MAX_PKT_BURST - nb_rx >= MIN_PMD_RX) {
			n = rte_eth_rx_burst(pq->port, pq->queue, mbufs + nb_rx, MIN_PMD_RX);
			nb_rx += n;
			PROX_PANIC(nb_rx > 64, "Received %d packets while expecting maximum %d\n", n, MIN_PMD_RX);
		}
	}
	return nb_rx;
}

static void next_port(struct rx_params_hw *rx_params_hw)
{
	++rx_params_hw->last_read_portid;
	if (unlikely(rx_params_hw->last_read_portid == rx_params_hw->nb_rxports)) {
		rx_params_hw->last_read_portid = 0;
	}
}

static void next_port_pow2(struct rx_params_hw *rx_params_hw)
{
	rx_params_hw->last_read_portid = (rx_params_hw->last_read_portid + 1) & rx_params_hw->rxport_mask;
}

static inline void dump_l3(struct task_base *tbase, struct rte_mbuf *mbuf)
{
	if (unlikely(tbase->aux->task_rt_dump.n_print_rx)) {
		if ((tbase->aux->task_rt_dump.input == NULL) || (tbase->aux->task_rt_dump.input->reply == NULL)) {
			plogdx_info(mbuf, "RX: ");
		} else {
			struct input *input = tbase->aux->task_rt_dump.input;
			char tmp[128];
			int strlen;
#if RTE_VERSION >= RTE_VERSION_NUM(1,8,0,0)
			int port_id = mbuf->port;
#else
			int port_id = mbuf->pkt.in_port;
#endif
			strlen = snprintf(tmp, sizeof(tmp), "pktdump,%d,%d\n", port_id,
			      rte_pktmbuf_pkt_len(mbuf));
			input->reply(input, tmp, strlen);
			input->reply(input, rte_pktmbuf_mtod(mbuf, char *), rte_pktmbuf_pkt_len(mbuf));
			input->reply(input, "\n", 1);
		}
		tbase->aux->task_rt_dump.n_print_rx --;
		if (0 == tbase->aux->task_rt_dump.n_print_rx) {
			task_base_del_rx_pkt_function(tbase, rx_pkt_dump);
		}
	}
	if (unlikely(tbase->aux->task_rt_dump.n_trace)) {
		plogdx_info(mbuf, "RX: ");
		tbase->aux->task_rt_dump.n_trace--;
	}
}

static uint16_t rx_pkt_hw_param(struct task_base *tbase, struct rte_mbuf ***mbufs_ptr, int multi,
				void (*next)(struct rx_params_hw *rx_param_hw), int l3)
{
	uint8_t last_read_portid;
	uint16_t nb_rx;
	int skip = 0;

	START_EMPTY_MEASSURE();
	*mbufs_ptr = tbase->ws_mbuf->mbuf[0] +
		(RTE_ALIGN_CEIL(tbase->ws_mbuf->idx[0].prod, 2) & WS_MBUF_MASK);

	last_read_portid = tbase->rx_params_hw.last_read_portid;
	struct port_queue *pq = &tbase->rx_params_hw.rx_pq[last_read_portid];

	nb_rx = rx_pkt_hw_port_queue(pq, *mbufs_ptr, multi);
	next(&tbase->rx_params_hw);

	if (l3) {
		struct rte_mbuf **mbufs = *mbufs_ptr;
		int i;
		struct ether_hdr_arp *hdr[MAX_PKT_BURST];
		for (i = 0; i < nb_rx; i++) {
			PREFETCH0(mbufs[i]);
		}
		for (i = 0; i < nb_rx; i++) {
			hdr[i] = rte_pktmbuf_mtod(mbufs[i], struct ether_hdr_arp *);
			PREFETCH0(hdr[i]);
		}
		for (i = 0; i < nb_rx; i++) {
			if (unlikely(hdr[i]->ether_hdr.ether_type == ETYPE_ARP)) {
				dump_l3(tbase, mbufs[i]);
				tx_ring(tbase, tbase->l3.ctrl_plane_ring, ARP_TO_CTRL, mbufs[i]);
				skip++;
			} else if (unlikely(skip)) {
				mbufs[i - skip] = mbufs[i];
			}
		}
	}

	if (skip)
		TASK_STATS_ADD_RX_NON_DP(&tbase->aux->stats, skip);
	if (likely(nb_rx > 0)) {
		TASK_STATS_ADD_RX(&tbase->aux->stats, nb_rx);
		return nb_rx - skip;
	}
	TASK_STATS_ADD_IDLE(&tbase->aux->stats, rte_rdtsc() - cur_tsc);
	return 0;
}

static inline uint16_t rx_pkt_hw1_param(struct task_base *tbase, struct rte_mbuf ***mbufs_ptr, int multi, int l3)
{
	uint16_t nb_rx, n;
	int skip = 0;

	START_EMPTY_MEASSURE();
	*mbufs_ptr = tbase->ws_mbuf->mbuf[0] +
		(RTE_ALIGN_CEIL(tbase->ws_mbuf->idx[0].prod, 2) & WS_MBUF_MASK);

	nb_rx = rte_eth_rx_burst(tbase->rx_params_hw1.rx_pq.port,
				 tbase->rx_params_hw1.rx_pq.queue,
				 *mbufs_ptr, MAX_PKT_BURST);

	if (multi) {
		n = nb_rx;
		while ((n != 0) && (MAX_PKT_BURST - nb_rx >= MIN_PMD_RX)) {
			n = rte_eth_rx_burst(tbase->rx_params_hw1.rx_pq.port,
				 tbase->rx_params_hw1.rx_pq.queue,
				 *mbufs_ptr + nb_rx, MIN_PMD_RX);
			nb_rx += n;
			PROX_PANIC(nb_rx > 64, "Received %d packets while expecting maximum %d\n", n, MIN_PMD_RX);
		}
	}

	if (l3) {
		struct rte_mbuf **mbufs = *mbufs_ptr;
		int i;
		struct ether_hdr_arp *hdr[MAX_PKT_BURST];
		for (i = 0; i < nb_rx; i++) {
			PREFETCH0(mbufs[i]);
		}
		for (i = 0; i < nb_rx; i++) {
			hdr[i] = rte_pktmbuf_mtod(mbufs[i], struct ether_hdr_arp *);
			PREFETCH0(hdr[i]);
		}
		for (i = 0; i < nb_rx; i++) {
			if (unlikely(hdr[i]->ether_hdr.ether_type == ETYPE_ARP)) {
				dump_l3(tbase, mbufs[i]);
				tx_ring(tbase, tbase->l3.ctrl_plane_ring, ARP_TO_CTRL, mbufs[i]);
				skip++;
			} else if (unlikely(skip)) {
				mbufs[i - skip] = mbufs[i];
			}
		}
	}

	if (skip)
		TASK_STATS_ADD_RX_NON_DP(&tbase->aux->stats, skip);
	if (likely(nb_rx > 0)) {
		TASK_STATS_ADD_RX(&tbase->aux->stats, nb_rx);
		return nb_rx - skip;
	}
	TASK_STATS_ADD_IDLE(&tbase->aux->stats, rte_rdtsc() - cur_tsc);
	return 0;
}

uint16_t rx_pkt_hw(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	return rx_pkt_hw_param(tbase, mbufs, 0, next_port, 0);
}

uint16_t rx_pkt_hw_pow2(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	return rx_pkt_hw_param(tbase, mbufs, 0, next_port_pow2, 0);
}

uint16_t rx_pkt_hw1(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	return rx_pkt_hw1_param(tbase, mbufs, 0, 0);
}

uint16_t rx_pkt_hw_multi(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	return rx_pkt_hw_param(tbase, mbufs, 1, next_port, 0);
}

uint16_t rx_pkt_hw_pow2_multi(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	return rx_pkt_hw_param(tbase, mbufs, 1, next_port_pow2, 0);
}

uint16_t rx_pkt_hw1_multi(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	return rx_pkt_hw1_param(tbase, mbufs, 1, 0);
}

uint16_t rx_pkt_hw_l3(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	return rx_pkt_hw_param(tbase, mbufs, 0, next_port, 1);
}

uint16_t rx_pkt_hw_pow2_l3(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	return rx_pkt_hw_param(tbase, mbufs, 0, next_port_pow2, 1);
}

uint16_t rx_pkt_hw1_l3(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	return rx_pkt_hw1_param(tbase, mbufs, 0, 1);
}

uint16_t rx_pkt_hw_multi_l3(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	return rx_pkt_hw_param(tbase, mbufs, 1, next_port, 1);
}

uint16_t rx_pkt_hw_pow2_multi_l3(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	return rx_pkt_hw_param(tbase, mbufs, 1, next_port_pow2, 1);
}

uint16_t rx_pkt_hw1_multi_l3(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	return rx_pkt_hw1_param(tbase, mbufs, 1, 1);
}

/* The following functions implement ring access */
uint16_t ring_deq(struct rte_ring *r, struct rte_mbuf **mbufs)
{
	void **v_mbufs = (void **)mbufs;
#ifdef BRAS_RX_BULK
#if RTE_VERSION < RTE_VERSION_NUM(17,5,0,1)
	return rte_ring_sc_dequeue_bulk(r, v_mbufs, MAX_RING_BURST) < 0? 0 : MAX_RING_BURST;
#else
	return rte_ring_sc_dequeue_bulk(r, v_mbufs, MAX_RING_BURST, NULL);
#endif
#else
#if RTE_VERSION < RTE_VERSION_NUM(17,5,0,1)
	return rte_ring_sc_dequeue_burst(r, v_mbufs, MAX_RING_BURST);
#else
	return rte_ring_sc_dequeue_burst(r, v_mbufs, MAX_RING_BURST, NULL);
#endif
#endif
}

uint16_t rx_pkt_sw(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	START_EMPTY_MEASSURE();
	*mbufs = tbase->ws_mbuf->mbuf[0] + (tbase->ws_mbuf->idx[0].prod & WS_MBUF_MASK);
	uint8_t lr = tbase->rx_params_sw.last_read_ring;
	uint16_t nb_rx;

	do {
		nb_rx = ring_deq(tbase->rx_params_sw.rx_rings[lr], *mbufs);
		lr = lr + 1 == tbase->rx_params_sw.nb_rxrings? 0 : lr + 1;
	} while(!nb_rx && lr != tbase->rx_params_sw.last_read_ring);

	tbase->rx_params_sw.last_read_ring = lr;

	if (nb_rx != 0) {
		TASK_STATS_ADD_RX(&tbase->aux->stats, nb_rx);
		return nb_rx;
	}
	else {
		TASK_STATS_ADD_IDLE(&tbase->aux->stats, rte_rdtsc() - cur_tsc);
		return 0;
	}
}

/* Same as rx_pkt_sw expect with a mask for the number of receive
   rings (can only be used if nb_rxring is a power of 2). */
uint16_t rx_pkt_sw_pow2(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	START_EMPTY_MEASSURE();
	*mbufs = tbase->ws_mbuf->mbuf[0] + (tbase->ws_mbuf->idx[0].prod & WS_MBUF_MASK);
	uint8_t lr = tbase->rx_params_sw.last_read_ring;
	uint16_t nb_rx;

	do {
		nb_rx = ring_deq(tbase->rx_params_sw.rx_rings[lr], *mbufs);
		lr = (lr + 1) & tbase->rx_params_sw.rxrings_mask;
	} while(!nb_rx && lr != tbase->rx_params_sw.last_read_ring);

	tbase->rx_params_sw.last_read_ring = lr;

	if (nb_rx != 0) {
		TASK_STATS_ADD_RX(&tbase->aux->stats, nb_rx);
		return nb_rx;
	}
	else {
		TASK_STATS_ADD_IDLE(&tbase->aux->stats, rte_rdtsc() - cur_tsc);
		return 0;
	}
}

uint16_t rx_pkt_self(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	START_EMPTY_MEASSURE();
	uint16_t nb_rx = tbase->ws_mbuf->idx[0].nb_rx;
	if (nb_rx) {
		tbase->ws_mbuf->idx[0].nb_rx = 0;
		*mbufs = tbase->ws_mbuf->mbuf[0] + (tbase->ws_mbuf->idx[0].prod & WS_MBUF_MASK);
		TASK_STATS_ADD_RX(&tbase->aux->stats, nb_rx);
		return nb_rx;
	}
	else {
		TASK_STATS_ADD_IDLE(&tbase->aux->stats, rte_rdtsc() - cur_tsc);
		return 0;
	}
}

/* Used for tasks that do not receive packets (i.e. Packet
generation).  Always returns 1 but never returns packets and does not
increment statistics. This function allows to use the same code path
as for tasks that actually receive packets. */
uint16_t rx_pkt_dummy(__attribute__((unused)) struct task_base *tbase,
		      __attribute__((unused)) struct rte_mbuf ***mbufs)
{
	return 1;
}

/* After the system has been configured, it is known if there is only
   one RX ring. If this is the case, a more specialized version of the
   function above can be used to save cycles. */
uint16_t rx_pkt_sw1(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	START_EMPTY_MEASSURE();
	*mbufs = tbase->ws_mbuf->mbuf[0] + (tbase->ws_mbuf->idx[0].prod & WS_MBUF_MASK);
	uint16_t nb_rx = ring_deq(tbase->rx_params_sw1.rx_ring, *mbufs);

	if (nb_rx != 0) {
		TASK_STATS_ADD_RX(&tbase->aux->stats, nb_rx);
		return nb_rx;
	}
	else {
		TASK_STATS_ADD_IDLE(&tbase->aux->stats, rte_rdtsc() - cur_tsc);
		return 0;
	}
}

static uint16_t call_prev_rx_pkt(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	uint16_t ret;

	tbase->aux->rx_prev_idx++;
	ret = tbase->aux->rx_pkt_prev[tbase->aux->rx_prev_idx - 1](tbase, mbufs);
	tbase->aux->rx_prev_idx--;

	return ret;
}

/* Only used when there are packets to be dumped. This function is
   meant as a debugging tool and is therefore not optimized. When the
   number of packets to dump falls back to 0, the original (optimized)
   rx function is restored. This allows to support dumping packets
   without any performance impact if the feature is not used. */
uint16_t rx_pkt_dump(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	uint16_t ret = call_prev_rx_pkt(tbase, mbufs);

	if (ret) {
		uint32_t n_dump = tbase->aux->task_rt_dump.n_print_rx;
		n_dump = ret < n_dump? ret : n_dump;

		if ((tbase->aux->task_rt_dump.input == NULL) || (tbase->aux->task_rt_dump.input->reply == NULL)) {
			for (uint32_t i = 0; i < n_dump; ++i) {
				plogdx_info((*mbufs)[i], "RX: ");
			}
		}
		else {
			struct input *input = tbase->aux->task_rt_dump.input;

			for (uint32_t i = 0; i < n_dump; ++i) {
				/* TODO: Execute callback with full
				   data in a single call. */
				char tmp[128];
				int strlen;

#if RTE_VERSION >= RTE_VERSION_NUM(1,8,0,0)
				int port_id = ((*mbufs)[i])->port;
#else
				int port_id = ((*mbufs)[i])->pkt.in_port;
#endif
				strlen = snprintf(tmp, sizeof(tmp), "pktdump,%d,%d\n", port_id,
						      rte_pktmbuf_pkt_len((*mbufs)[i]));

				input->reply(input, tmp, strlen);
				input->reply(input, rte_pktmbuf_mtod((*mbufs)[i], char *), rte_pktmbuf_pkt_len((*mbufs)[i]));
				input->reply(input, "\n", 1);
			}
		}

		tbase->aux->task_rt_dump.n_print_rx -= n_dump;

		if (0 == tbase->aux->task_rt_dump.n_print_rx) {
			task_base_del_rx_pkt_function(tbase, rx_pkt_dump);
		}
	}
	return ret;
}

uint16_t rx_pkt_trace(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	tbase->aux->task_rt_dump.cur_trace = 0;
	uint16_t ret = call_prev_rx_pkt(tbase, mbufs);

	if (ret) {
		uint32_t n_trace = tbase->aux->task_rt_dump.n_trace;
		n_trace = ret < n_trace? ret : n_trace;
		n_trace = n_trace <= MAX_RING_BURST ? n_trace : MAX_RING_BURST;

		for (uint32_t i = 0; i < n_trace; ++i) {
			uint8_t *pkt = rte_pktmbuf_mtod((*mbufs)[i], uint8_t *);
			rte_memcpy(tbase->aux->task_rt_dump.pkt_cpy[i], pkt, sizeof(tbase->aux->task_rt_dump.pkt_cpy[i]));
			tbase->aux->task_rt_dump.pkt_cpy_len[i] = rte_pktmbuf_pkt_len((*mbufs)[i]);
			tbase->aux->task_rt_dump.pkt_mbuf_addr[i] = (*mbufs)[i];
		}
		tbase->aux->task_rt_dump.cur_trace += n_trace;

		tbase->aux->task_rt_dump.n_trace -= n_trace;
		/* Unset by TX when n_trace = 0 */
	}
	return ret;
}

/* Gather the distribution of the number of packets that have been
   received from one RX call. Since the value is only modified by the
   task that receives the packet, no atomic operation is needed. */
uint16_t rx_pkt_distr(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	uint16_t ret = call_prev_rx_pkt(tbase, mbufs);

	if (likely(ret < RX_BUCKET_SIZE))
		tbase->aux->rx_bucket[ret]++;
	else
		tbase->aux->rx_bucket[RX_BUCKET_SIZE - 1]++;
	return ret;
}

uint16_t rx_pkt_bw(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	uint16_t ret = call_prev_rx_pkt(tbase, mbufs);
	uint32_t tot_bytes = 0;

	for (uint16_t i = 0; i < ret; ++i) {
		tot_bytes += mbuf_wire_size((*mbufs)[i]);
	}

	TASK_STATS_ADD_RX_BYTES(&tbase->aux->stats, tot_bytes);

	return ret;
}

uint16_t rx_pkt_tsc(struct task_base *tbase, struct rte_mbuf ***mbufs)
{
	uint64_t before = rte_rdtsc();
	uint16_t ret = call_prev_rx_pkt(tbase, mbufs);
	uint64_t after = rte_rdtsc();

	tbase->aux->tsc_rx.before = before;
	tbase->aux->tsc_rx.after = after;

	return ret;
}
