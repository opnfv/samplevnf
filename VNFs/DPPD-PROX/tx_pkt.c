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

#include <rte_ethdev.h>
#include <rte_version.h>

#include "rx_pkt.h"
#include "tx_pkt.h"
#include "task_base.h"
#include "stats.h"
#include "prefetch.h"
#include "prox_assert.h"
#include "log.h"
#include "mbuf_utils.h"
#include "handle_master.h"

static void buf_pkt_single(struct task_base *tbase, struct rte_mbuf *mbuf, const uint8_t out)
{
	const uint16_t prod = tbase->ws_mbuf->idx[out].prod++;
	tbase->ws_mbuf->mbuf[out][prod & WS_MBUF_MASK] = mbuf;
}

static inline void buf_pkt_all(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out)
{
	for (uint16_t j = 0; j < n_pkts; ++j) {
		if (unlikely(out[j] >= OUT_HANDLED)) {
			rte_pktmbuf_free(mbufs[j]);
			if (out[j] == OUT_HANDLED)
				TASK_STATS_ADD_DROP_HANDLED(&tbase->aux->stats, 1);
			else
				TASK_STATS_ADD_DROP_DISCARD(&tbase->aux->stats, 1);
		}
		else {
			buf_pkt_single(tbase, mbufs[j], out[j]);
		}
	}
}
#define MAX_PMD_TX 32

int tx_pkt_l3(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out)
{
	uint32_t ip_dst;
	int first = 0, ret, ok = 0, rc;
	const struct port_queue *port_queue = &tbase->tx_params_hw.tx_port_queue[0];
	struct rte_mbuf *arp_mbuf = NULL;       // used when one need to send both an ARP and a mbuf

	for (int j = 0; j < n_pkts; j++) {
		if ((out) && (out[j] >= OUT_HANDLED))
			continue;
		if (unlikely((rc = write_dst_mac(tbase, mbufs[j], &ip_dst)) != SEND_MBUF)) {
			if (j - first) {
				ret = tbase->aux->tx_pkt_l2(tbase, mbufs + first, j - first, out);
				ok += ret;
			}
			first = j + 1;
			switch(rc) {
			case SEND_ARP:
				// We re-use the mbuf - no need to create a arp_mbuf and delete the existing mbuf
				mbufs[j]->port = tbase->l3.reachable_port_id;
				tx_ring_cti(tbase, tbase->l3.ctrl_plane_ring, REQ_MAC_TO_CTRL, mbufs[j], tbase->l3.core_id, tbase->l3.task_id, ip_dst);
				break;
			case SEND_MBUF_AND_ARP:
				// We send the mbuf and an ARP - we need to allocate another mbuf for ARP
				ret = rte_mempool_get(tbase->l3.arp_pool, (void **)&arp_mbuf);
				if (likely(ret == 0))   {
					arp_mbuf->port = tbase->l3.reachable_port_id;
					tx_ring_cti(tbase, tbase->l3.ctrl_plane_ring, REQ_MAC_TO_CTRL, arp_mbuf, tbase->l3.core_id, tbase->l3.task_id, ip_dst);
				} else {
					plog_err("Failed to get a mbuf from arp mempool\n");
					// We still send the initial mbuf
				}
				ret = tbase->aux->tx_pkt_l2(tbase, mbufs + j, 1, out);
				break;
			case DROP_MBUF:
				tx_drop(mbufs[j]);
				TASK_STATS_ADD_DROP_DISCARD(&tbase->aux->stats, 1);
				break;
			}
		}
	}
	if (n_pkts - first) {
		ret = tbase->aux->tx_pkt_l2(tbase, mbufs + first, n_pkts - first, out);
		ok += ret;
	}
	return ok;
}

/* The following help functions also report stats. Therefore we need
   to pass the task_base struct. */
static inline int txhw_drop(const struct port_queue *port_queue, struct rte_mbuf **mbufs, uint16_t n_pkts, struct task_base *tbase)
{
	uint16_t ntx;
	int ret;

	/* TX vector mode can't transmit more than 32 packets */
	if (n_pkts > MAX_PMD_TX) {
		ntx = rte_eth_tx_burst(port_queue->port, port_queue->queue, mbufs, MAX_PMD_TX);
		ntx += rte_eth_tx_burst(port_queue->port, port_queue->queue, mbufs + ntx, n_pkts - ntx);
	} else {
		ntx = rte_eth_tx_burst(port_queue->port, port_queue->queue, mbufs, n_pkts);
	}
	TASK_STATS_ADD_TX(&tbase->aux->stats, ntx);

	ret =  n_pkts - ntx;
	if (ntx < n_pkts) {
		plog_dbg("Failed to send %d packets from %p\n", ret, mbufs[0]);
		TASK_STATS_ADD_DROP_TX_FAIL(&tbase->aux->stats, n_pkts - ntx);
		if (tbase->tx_pkt == tx_pkt_bw) {
			uint32_t drop_bytes = 0;
			do {
				drop_bytes += mbuf_wire_size(mbufs[ntx]);
				rte_pktmbuf_free(mbufs[ntx++]);
			} while (ntx < n_pkts);
			TASK_STATS_ADD_DROP_BYTES(&tbase->aux->stats, drop_bytes);
		}
		else {
			do {
				rte_pktmbuf_free(mbufs[ntx++]);
			} while (ntx < n_pkts);
		}
	}
	return ret;
}

static inline int txhw_no_drop(const struct port_queue *port_queue, struct rte_mbuf **mbufs, uint16_t n_pkts, struct task_base *tbase)
{
	uint16_t ret;
	uint16_t n = n_pkts;

	TASK_STATS_ADD_TX(&tbase->aux->stats, n_pkts);
	do {
		ret = rte_eth_tx_burst(port_queue->port, port_queue->queue, mbufs, n_pkts);
		mbufs += ret;
		n_pkts -= ret;
	}
	while (n_pkts);
	return (n != ret);
}

static inline int ring_enq_drop(struct rte_ring *ring, struct rte_mbuf *const *mbufs, uint16_t n_pkts, __attribute__((unused)) struct task_base *tbase)
{
	int ret = 0;
	/* return 0 on succes, -ENOBUFS on failure */
	// Rings can be single or multiproducer (ctrl rings are multi producer)
#if RTE_VERSION < RTE_VERSION_NUM(17,5,0,1)
	if (unlikely(rte_ring_enqueue_bulk(ring, (void *const *)mbufs, n_pkts))) {
#else
	if (unlikely(rte_ring_enqueue_bulk(ring, (void *const *)mbufs, n_pkts, NULL) == 0)) {
#endif
		ret = n_pkts;
		if (tbase->tx_pkt == tx_pkt_bw) {
			uint32_t drop_bytes = 0;
			for (uint16_t i = 0; i < n_pkts; ++i) {
				drop_bytes += mbuf_wire_size(mbufs[i]);
				rte_pktmbuf_free(mbufs[i]);
			}
			TASK_STATS_ADD_DROP_BYTES(&tbase->aux->stats, drop_bytes);
			TASK_STATS_ADD_DROP_TX_FAIL(&tbase->aux->stats, n_pkts);
		}
		else {
			for (uint16_t i = 0; i < n_pkts; ++i)
				rte_pktmbuf_free(mbufs[i]);
			TASK_STATS_ADD_DROP_TX_FAIL(&tbase->aux->stats, n_pkts);
		}
	}
	else {
		TASK_STATS_ADD_TX(&tbase->aux->stats, n_pkts);
	}
	return ret;
}

static inline int ring_enq_no_drop(struct rte_ring *ring, struct rte_mbuf *const *mbufs, uint16_t n_pkts, __attribute__((unused)) struct task_base *tbase)
{
	int i = 0;
#if RTE_VERSION < RTE_VERSION_NUM(17,5,0,1)
	while (rte_ring_enqueue_bulk(ring, (void *const *)mbufs, n_pkts)) {
#else
	while (rte_ring_enqueue_bulk(ring, (void *const *)mbufs, n_pkts, NULL) == 0) {
#endif
		i++;
	};
	TASK_STATS_ADD_TX(&tbase->aux->stats, n_pkts);
	return (i != 0);
}

void flush_queues_hw(struct task_base *tbase)
{
	uint16_t prod, cons;

	for (uint8_t i = 0; i < tbase->tx_params_hw.nb_txports; ++i) {
		prod = tbase->ws_mbuf->idx[i].prod;
		cons = tbase->ws_mbuf->idx[i].cons;

		if (prod != cons) {
			tbase->ws_mbuf->idx[i].prod = 0;
			tbase->ws_mbuf->idx[i].cons = 0;
			txhw_drop(&tbase->tx_params_hw.tx_port_queue[i], tbase->ws_mbuf->mbuf[i] + (cons & WS_MBUF_MASK), prod - cons, tbase);
		}
	}

	tbase->flags &= ~FLAG_TX_FLUSH;
}

void flush_queues_sw(struct task_base *tbase)
{
	uint16_t prod, cons;

	for (uint8_t i = 0; i < tbase->tx_params_sw.nb_txrings; ++i) {
		prod = tbase->ws_mbuf->idx[i].prod;
		cons = tbase->ws_mbuf->idx[i].cons;

		if (prod != cons) {
			tbase->ws_mbuf->idx[i].prod = 0;
			tbase->ws_mbuf->idx[i].cons = 0;
			ring_enq_drop(tbase->tx_params_sw.tx_rings[i], tbase->ws_mbuf->mbuf[i] + (cons & WS_MBUF_MASK), prod - cons, tbase);
		}
	}
	tbase->flags &= ~FLAG_TX_FLUSH;
}

void flush_queues_no_drop_hw(struct task_base *tbase)
{
	uint16_t prod, cons;

	for (uint8_t i = 0; i < tbase->tx_params_hw.nb_txports; ++i) {
		prod = tbase->ws_mbuf->idx[i].prod;
		cons = tbase->ws_mbuf->idx[i].cons;

		if (prod != cons) {
			tbase->ws_mbuf->idx[i].prod = 0;
			tbase->ws_mbuf->idx[i].cons = 0;
			txhw_no_drop(&tbase->tx_params_hw.tx_port_queue[i], tbase->ws_mbuf->mbuf[i] + (cons & WS_MBUF_MASK), prod - cons, tbase);
		}
	}

	tbase->flags &= ~FLAG_TX_FLUSH;
}

void flush_queues_no_drop_sw(struct task_base *tbase)
{
	uint16_t prod, cons;

	for (uint8_t i = 0; i < tbase->tx_params_sw.nb_txrings; ++i) {
		prod = tbase->ws_mbuf->idx[i].prod;
		cons = tbase->ws_mbuf->idx[i].cons;

		if (prod != cons) {
			tbase->ws_mbuf->idx[i].prod = 0;
			tbase->ws_mbuf->idx[i].cons = 0;
			ring_enq_no_drop(tbase->tx_params_sw.tx_rings[i], tbase->ws_mbuf->mbuf[i] + (cons & WS_MBUF_MASK), prod - cons, tbase);
		}
	}
	tbase->flags &= ~FLAG_TX_FLUSH;
}

/* "try" functions try to send packets to sw/hw w/o failing or blocking;
   They return if ring/queue is full and are used by aggregators.
   "try" functions do not have drop/no drop flavors
   They are only implemented in never_discard mode (as by default they
   use only one outgoing ring. */
uint16_t tx_try_self(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	if (n_pkts < 64) {
		tx_pkt_never_discard_self(tbase, mbufs, n_pkts, NULL);
		return n_pkts;
	} else {
		tx_pkt_never_discard_self(tbase, mbufs, 64, NULL);
		return 64;
	}
}

uint16_t tx_try_sw1(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	const int bulk_size = 64;
	uint16_t ret = bulk_size, sent = 0, n_bulks;
	n_bulks = n_pkts >> __builtin_ctz(bulk_size);

	for (int i = 0; i < n_bulks; i++) {
#if RTE_VERSION < RTE_VERSION_NUM(17,5,0,1)
		ret = rte_ring_enqueue_burst(tbase->tx_params_sw.tx_rings[0], (void *const *)mbufs, bulk_size);
#else
		ret = rte_ring_enqueue_burst(tbase->tx_params_sw.tx_rings[0], (void *const *)mbufs, bulk_size, NULL);
#endif
		mbufs += ret;
		sent += ret;
		if (ret != bulk_size)
			break;
	}
	if ((ret == bulk_size) && (n_pkts & (bulk_size - 1))) {
#if RTE_VERSION < RTE_VERSION_NUM(17,5,0,1)
		ret = rte_ring_enqueue_burst(tbase->tx_params_sw.tx_rings[0], (void *const *)mbufs, (n_pkts & (bulk_size - 1)));
#else
		ret = rte_ring_enqueue_burst(tbase->tx_params_sw.tx_rings[0], (void *const *)mbufs, (n_pkts & (bulk_size - 1)), NULL);
#endif
		mbufs += ret;
		sent += ret;
	}
	TASK_STATS_ADD_TX(&tbase->aux->stats, sent);
	return sent;
}

uint16_t tx_try_hw1(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	const int bulk_size = 64;
	uint16_t ret = bulk_size, n_bulks, sent = 0;
	n_bulks = n_pkts >>  __builtin_ctz(bulk_size);

	const struct port_queue *port_queue = &tbase->tx_params_hw.tx_port_queue[0];
	for (int i = 0; i < n_bulks; i++) {
		ret = rte_eth_tx_burst(port_queue->port, port_queue->queue, mbufs, bulk_size);
		mbufs += ret;
		sent += ret;
		if (ret != bulk_size)
			break;
	}
	if ((ret == bulk_size) && (n_pkts & (bulk_size - 1))) {
		ret = rte_eth_tx_burst(port_queue->port, port_queue->queue, mbufs, (n_pkts & (bulk_size - 1)));
		mbufs += ret;
		sent += ret;
	}
	TASK_STATS_ADD_TX(&tbase->aux->stats, sent);
	return sent;
}

int tx_pkt_no_drop_never_discard_hw1_lat_opt(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, __attribute__((unused)) uint8_t *out)
{
	return txhw_no_drop(&tbase->tx_params_hw.tx_port_queue[0], mbufs, n_pkts, tbase);
}

int tx_pkt_no_drop_never_discard_hw1_thrpt_opt(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, __attribute__((unused)) uint8_t *out)
{
	static uint8_t fake_out[MAX_PKT_BURST] = {0};
	int ret = 0;
	if (n_pkts == MAX_PKT_BURST) {
		// First xmit what was queued
        	uint16_t prod, cons;

               	prod = tbase->ws_mbuf->idx[0].prod;
               	cons = tbase->ws_mbuf->idx[0].cons;

		if ((uint16_t)(prod - cons)){
                	tbase->flags &= ~FLAG_TX_FLUSH;
                	tbase->ws_mbuf->idx[0].prod = 0;
                	tbase->ws_mbuf->idx[0].cons = 0;
                	ret+= txhw_no_drop(&tbase->tx_params_hw.tx_port_queue[0], tbase->ws_mbuf->mbuf[0] + (cons & WS_MBUF_MASK), (uint16_t)(prod - cons), tbase);
		}
		ret+= txhw_no_drop(&tbase->tx_params_hw.tx_port_queue[0], mbufs, n_pkts, tbase);
	} else {
		ret+= tx_pkt_no_drop_hw(tbase, mbufs, n_pkts, fake_out);
	}
	return ret;
}

int tx_pkt_never_discard_hw1_lat_opt(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, __attribute__((unused)) uint8_t *out)
{
	return txhw_drop(&tbase->tx_params_hw.tx_port_queue[0], mbufs, n_pkts, tbase);
}

int tx_pkt_never_discard_hw1_thrpt_opt(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, __attribute__((unused)) uint8_t *out)
{
	static uint8_t fake_out[MAX_PKT_BURST] = {0};
	int ret = 0;
	if (n_pkts == MAX_PKT_BURST) {
		// First xmit what was queued
        	uint16_t prod, cons;

               	prod = tbase->ws_mbuf->idx[0].prod;
               	cons = tbase->ws_mbuf->idx[0].cons;

		if ((uint16_t)(prod - cons)){
                	tbase->flags &= ~FLAG_TX_FLUSH;
                	tbase->ws_mbuf->idx[0].prod = 0;
                	tbase->ws_mbuf->idx[0].cons = 0;
                	ret+= txhw_drop(&tbase->tx_params_hw.tx_port_queue[0], tbase->ws_mbuf->mbuf[0] + (cons & WS_MBUF_MASK), (uint16_t)(prod - cons), tbase);
		}
		ret+= txhw_drop(&tbase->tx_params_hw.tx_port_queue[0], mbufs, n_pkts, tbase);
	} else {
		ret+= tx_pkt_hw(tbase, mbufs, n_pkts, fake_out);
	}
	return ret;
}

/* Transmit to hw using tx_params_hw_sw structure
   This function is used  to transmit to hw when tx_params_hw_sw should be used
   i.e. when the task needs to transmit both to hw and sw */
int tx_pkt_no_drop_never_discard_hw1_no_pointer(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, __attribute__((unused)) uint8_t *out)
{
	txhw_no_drop(&tbase->tx_params_hw_sw.tx_port_queue, mbufs, n_pkts, tbase);
	return 0;
}

int tx_pkt_no_drop_never_discard_sw1(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, __attribute__((unused)) uint8_t *out)
{
	return ring_enq_no_drop(tbase->tx_params_sw.tx_rings[0], mbufs, n_pkts, tbase);
}

int tx_pkt_never_discard_sw1(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, __attribute__((unused)) uint8_t *out)
{
	return ring_enq_drop(tbase->tx_params_sw.tx_rings[0], mbufs, n_pkts, tbase);
}

static uint16_t tx_pkt_free_dropped(__attribute__((unused)) struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out)
{
	uint64_t v = 0;
	uint16_t i;
	/* The most probable and most important optimize case is if
	   the no packets should be dropped. */
	for (i = 0; i + 8 < n_pkts; i += 8) {
		v |= *((uint64_t*)(&out[i]));
	}
	for (; i < n_pkts; ++i) {
		v |= out[i];
	}

	if (unlikely(v)) {
		/* At least some packets need to be dropped, so the
		   mbufs array needs to be updated. */
		uint16_t n_kept = 0;
		uint16_t n_discard = 0;
		for (uint16_t i = 0; i < n_pkts; ++i) {
			if (unlikely(out[i] >= OUT_HANDLED)) {
				rte_pktmbuf_free(mbufs[i]);
				n_discard += out[i] == OUT_DISCARD;
				continue;
			}
			mbufs[n_kept++] = mbufs[i];
		}
		TASK_STATS_ADD_DROP_DISCARD(&tbase->aux->stats, n_discard);
		TASK_STATS_ADD_DROP_HANDLED(&tbase->aux->stats, n_pkts - n_kept - n_discard);
		return n_kept;
	}
	return n_pkts;
}

int tx_pkt_no_drop_hw1(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out)
{
	const uint16_t n_kept = tx_pkt_free_dropped(tbase, mbufs, n_pkts, out);
	int ret = 0;

	if (likely(n_kept))
		ret = txhw_no_drop(&tbase->tx_params_hw.tx_port_queue[0], mbufs, n_kept, tbase);
	return ret;
}

int tx_pkt_no_drop_sw1(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out)
{
	const uint16_t n_kept = tx_pkt_free_dropped(tbase, mbufs, n_pkts, out);
	int ret = 0;

	if (likely(n_kept))
		ret = ring_enq_no_drop(tbase->tx_params_sw.tx_rings[0], mbufs, n_kept, tbase);
	return ret;
}

int tx_pkt_hw1(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out)
{
	const uint16_t n_kept = tx_pkt_free_dropped(tbase, mbufs, n_pkts, out);

	if (likely(n_kept))
		return txhw_drop(&tbase->tx_params_hw.tx_port_queue[0], mbufs, n_kept, tbase);
	return n_pkts;
}

int tx_pkt_sw1(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out)
{
	const uint16_t n_kept = tx_pkt_free_dropped(tbase, mbufs, n_pkts, out);

	if (likely(n_kept))
		return ring_enq_drop(tbase->tx_params_sw.tx_rings[0], mbufs, n_kept, tbase);
	return 0;
}

int tx_pkt_self(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out)
{
	const uint16_t n_kept = tx_pkt_free_dropped(tbase, mbufs, n_pkts, out);

	TASK_STATS_ADD_TX(&tbase->aux->stats, n_kept);
	tbase->ws_mbuf->idx[0].nb_rx = n_kept;
	struct rte_mbuf **tx_mbuf = tbase->ws_mbuf->mbuf[0] + (tbase->ws_mbuf->idx[0].prod & WS_MBUF_MASK);
	for (uint16_t i = 0; i < n_kept; ++i) {
		tx_mbuf[i] = mbufs[i];
	}
	return 0;
}

int tx_pkt_never_discard_self(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, __attribute__((unused)) uint8_t *out)
{
	TASK_STATS_ADD_TX(&tbase->aux->stats, n_pkts);
	tbase->ws_mbuf->idx[0].nb_rx = n_pkts;
	struct rte_mbuf **tx_mbuf = tbase->ws_mbuf->mbuf[0] + (tbase->ws_mbuf->idx[0].prod & WS_MBUF_MASK);
	for (uint16_t i = 0; i < n_pkts; ++i) {
		tx_mbuf[i] = mbufs[i];
	}
	return 0;
}

int tx_pkt_no_drop_hw(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out)
{
	int ret = 0;
	buf_pkt_all(tbase, mbufs, n_pkts, out);

	const uint8_t nb_bufs = tbase->tx_params_hw.nb_txports;
	uint16_t prod, cons;

	for (uint8_t i = 0; i < nb_bufs; ++i) {
		prod = tbase->ws_mbuf->idx[i].prod;
		cons = tbase->ws_mbuf->idx[i].cons;

		if (((uint16_t)(prod - cons)) >= MAX_PKT_BURST) {
			tbase->flags &= ~FLAG_TX_FLUSH;
			tbase->ws_mbuf->idx[i].cons = cons + MAX_PKT_BURST;
			ret+= txhw_no_drop(&tbase->tx_params_hw.tx_port_queue[i], tbase->ws_mbuf->mbuf[i] + (cons & WS_MBUF_MASK), MAX_PKT_BURST, tbase);
		}
	}
	return ret;
}

int tx_pkt_no_drop_sw(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out)
{
	int ret = 0;
	buf_pkt_all(tbase, mbufs, n_pkts, out);

	const uint8_t nb_bufs = tbase->tx_params_sw.nb_txrings;
	uint16_t prod, cons;

	for (uint8_t i = 0; i < nb_bufs; ++i) {
		prod = tbase->ws_mbuf->idx[i].prod;
		cons = tbase->ws_mbuf->idx[i].cons;

		if (((uint16_t)(prod - cons)) >= MAX_PKT_BURST) {
			tbase->flags &= ~FLAG_TX_FLUSH;
			tbase->ws_mbuf->idx[i].cons = cons + MAX_PKT_BURST;
			ret += ring_enq_no_drop(tbase->tx_params_sw.tx_rings[i], tbase->ws_mbuf->mbuf[i] + (cons & WS_MBUF_MASK), MAX_PKT_BURST, tbase);
		}
	}
	return ret;
}

int tx_pkt_hw(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out)
{
	int ret = 0;
	buf_pkt_all(tbase, mbufs, n_pkts, out);

	const uint8_t nb_bufs = tbase->tx_params_hw.nb_txports;
	uint16_t prod, cons;

	for (uint8_t i = 0; i < nb_bufs; ++i) {
		prod = tbase->ws_mbuf->idx[i].prod;
		cons = tbase->ws_mbuf->idx[i].cons;

		if (((uint16_t)(prod - cons)) >= MAX_PKT_BURST) {
			tbase->flags &= ~FLAG_TX_FLUSH;
			tbase->ws_mbuf->idx[i].cons = cons + MAX_PKT_BURST;
			ret += txhw_drop(&tbase->tx_params_hw.tx_port_queue[i], tbase->ws_mbuf->mbuf[i] + (cons & WS_MBUF_MASK), MAX_PKT_BURST, tbase);
		}
	}
	return ret;
}

int tx_pkt_sw(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out)
{
	int ret = 0;
	buf_pkt_all(tbase, mbufs, n_pkts, out);

	const uint8_t nb_bufs = tbase->tx_params_sw.nb_txrings;
	uint16_t prod, cons;
	for (uint8_t i = 0; i < nb_bufs; ++i) {
		prod = tbase->ws_mbuf->idx[i].prod;
		cons = tbase->ws_mbuf->idx[i].cons;

		if (((uint16_t)(prod - cons)) >= MAX_PKT_BURST) {
			tbase->flags &= ~FLAG_TX_FLUSH;
			tbase->ws_mbuf->idx[i].cons = cons + MAX_PKT_BURST;
			ret+= ring_enq_drop(tbase->tx_params_sw.tx_rings[i], tbase->ws_mbuf->mbuf[i] + (cons & WS_MBUF_MASK), MAX_PKT_BURST, tbase);
		}
	}
	return ret;
}

static inline void trace_one_rx_pkt(struct task_base *tbase, struct rte_mbuf *mbuf)
{
	struct rte_mbuf tmp;
	/* For each packet being transmitted, find which
	   buffer represent the packet as it was before
	   processing. */
	uint32_t j = 0;
	uint32_t len = sizeof(tbase->aux->task_rt_dump.pkt_mbuf_addr)/sizeof(tbase->aux->task_rt_dump.pkt_mbuf_addr[0]);
	for (;j < len; ++j) {
		if (tbase->aux->task_rt_dump.pkt_mbuf_addr[j] == mbuf)
			break;
	}
	if (j != len) {
#if RTE_VERSION >= RTE_VERSION_NUM(1,8,0,0)
		tmp.data_off = 0;
#endif
		rte_pktmbuf_data_len(&tmp) = tbase->aux->task_rt_dump.pkt_cpy_len[j];
		rte_pktmbuf_pkt_len(&tmp) = tbase->aux->task_rt_dump.pkt_cpy_len[j];
		tmp.buf_addr = tbase->aux->task_rt_dump.pkt_cpy[j];
		plogdx_info(&tmp, "Trace RX: ");
	}
}

static inline void trace_one_tx_pkt(struct task_base *tbase, struct rte_mbuf *mbuf, uint8_t *out, uint32_t i)
{
	if (out) {
		switch(out[i]) {
		case 0xFE:
			plogdx_info(mbuf, "Handled: ");
			break;
		case 0xFF:
			plogdx_info(mbuf, "Dropped: ");
			break;
		default:
			plogdx_info(mbuf, "TX[%d]: ", out[i]);
			break;
		}
	} else if (tbase->aux->tx_pkt_orig == tx_pkt_drop_all) {
		plogdx_info(mbuf, "Dropped: ");
	} else
		plogdx_info(mbuf, "TX[0]: ");
}

static void unset_trace(struct task_base *tbase)
{
	if (0 == tbase->aux->task_rt_dump.n_trace) {
		if (tbase->tx_pkt == tx_pkt_l3) {
			tbase->aux->tx_pkt_l2 = tbase->aux->tx_pkt_orig;
			tbase->aux->tx_pkt_orig = NULL;
		} else {
			tbase->tx_pkt = tbase->aux->tx_pkt_orig;
			tbase->aux->tx_pkt_orig = NULL;
		}
		tbase->aux->task_rt_dump.cur_trace = 0;
		task_base_del_rx_pkt_function(tbase, rx_pkt_trace);
	}
}

int tx_pkt_trace(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out)
{
	int ret = 0;
	if (tbase->aux->task_rt_dump.cur_trace == 0) {
		// No packet received since dumping...
		tbase->aux->task_rt_dump.n_print_tx = tbase->aux->task_rt_dump.n_trace;
		if (tbase->aux->task_rt_dump.n_trace < n_pkts) {
			tbase->aux->task_rt_dump.n_trace = 0;
			tbase->aux->task_rt_dump.cur_trace = 0;
			task_base_del_rx_pkt_function(tbase, rx_pkt_trace);
		} else {
			tbase->aux->task_rt_dump.n_trace -= n_pkts;
		}
		ret = tx_pkt_dump(tbase, mbufs, n_pkts, out);
		tbase->aux->task_rt_dump.n_print_tx = 0;
		return ret;
	}
	plog_info("Tracing %d pkts\n", tbase->aux->task_rt_dump.cur_trace);
	uint32_t cur_trace = (n_pkts < tbase->aux->task_rt_dump.cur_trace) ? n_pkts: tbase->aux->task_rt_dump.cur_trace;
	for (uint32_t i = 0; i < cur_trace; ++i) {
		trace_one_rx_pkt(tbase, mbufs[i]);
		trace_one_tx_pkt(tbase, mbufs[i], out, i);

	}
	ret = tbase->aux->tx_pkt_orig(tbase, mbufs, n_pkts, out);

	unset_trace(tbase);
	return ret;
}

int tx_pkt_dump(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out)
{
	uint32_t n_dump = tbase->aux->task_rt_dump.n_print_tx;
	int ret = 0;

	n_dump = n_pkts < n_dump? n_pkts : n_dump;
	for (uint32_t i = 0; i < n_dump; ++i) {
		if (out) {
			switch (out[i]) {
			case 0xFE:
				plogdx_info(mbufs[i], "Handled: ");
				break;
			case 0xFF:
				plogdx_info(mbufs[i], "Dropped: ");
				break;
			default:
				plogdx_info(mbufs[i], "TX[%d]: ", out[i]);
				break;
			}
		} else
			plogdx_info(mbufs[i], "TX: ");
	}
	tbase->aux->task_rt_dump.n_print_tx -= n_dump;

	ret = tbase->aux->tx_pkt_orig(tbase, mbufs, n_pkts, out);

	if (0 == tbase->aux->task_rt_dump.n_print_tx) {
		if (tbase->tx_pkt == tx_pkt_l3) {
			tbase->aux->tx_pkt_l2 = tbase->aux->tx_pkt_orig;
			tbase->aux->tx_pkt_orig = NULL;
		} else {
			tbase->tx_pkt = tbase->aux->tx_pkt_orig;
			tbase->aux->tx_pkt_orig = NULL;
		}
	}
	return ret;
}

/* Gather the distribution of the number of packets that have been
   xmitted from one TX call. Since the value is only modified by the
   task that xmits the packet, no atomic operation is needed. */
int tx_pkt_distr(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out)
{
	if (likely(n_pkts < TX_BUCKET_SIZE))
		tbase->aux->tx_bucket[n_pkts]++;
	else
		tbase->aux->tx_bucket[TX_BUCKET_SIZE - 1]++;
	return tbase->aux->tx_pkt_orig(tbase, mbufs, n_pkts, out);
}

int tx_pkt_bw(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out)
{
	uint32_t tx_bytes = 0;
	uint32_t drop_bytes = 0;

	for (uint16_t i = 0; i < n_pkts; ++i) {
		if (!out || out[i] < OUT_HANDLED)
			tx_bytes += mbuf_wire_size(mbufs[i]);
		else
			drop_bytes += mbuf_wire_size(mbufs[i]);
	}

	TASK_STATS_ADD_TX_BYTES(&tbase->aux->stats, tx_bytes);
	TASK_STATS_ADD_DROP_BYTES(&tbase->aux->stats, drop_bytes);
	return tbase->aux->tx_pkt_orig(tbase, mbufs, n_pkts, out);
}

int tx_pkt_drop_all(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out)
{
	for (uint16_t j = 0; j < n_pkts; ++j) {
		rte_pktmbuf_free(mbufs[j]);
	}
	if (out == NULL)
		TASK_STATS_ADD_DROP_HANDLED(&tbase->aux->stats, n_pkts);
	else {
		for (uint16_t j = 0; j < n_pkts; ++j) {
			if (out[j] == OUT_HANDLED)
				TASK_STATS_ADD_DROP_HANDLED(&tbase->aux->stats, 1);
			else
				TASK_STATS_ADD_DROP_DISCARD(&tbase->aux->stats, 1);
		}
	}
	return n_pkts;
}
static inline void dump_pkts(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	uint32_t n_dump = tbase->aux->task_rt_dump.n_print_tx;
	uint32_t n_trace = tbase->aux->task_rt_dump.n_trace;

	if (unlikely(n_dump)) {
		n_dump = n_pkts < n_dump? n_pkts : n_dump;
		for (uint32_t i = 0; i < n_dump; ++i) {
			plogdx_info(mbufs[i], "TX: ");
		}
		tbase->aux->task_rt_dump.n_print_tx -= n_dump;
	} else if (unlikely(n_trace)) {
		n_trace = n_pkts < n_trace? n_pkts : n_trace;
		for (uint32_t i = 0; i < n_trace; ++i) {
			plogdx_info(mbufs[i], "TX: ");
		}
		tbase->aux->task_rt_dump.n_trace - n_trace;
	}
}

// ctrlplane packets are slow path, hence cost of checking if dump ortrace is needed in not too important
// easier to have this implementation than an implementation similar to dataplane tx
int tx_ctrlplane_hw(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, __attribute__((unused)) uint8_t *out)
{
	dump_pkts(tbase, mbufs, n_pkts);
	return txhw_no_drop(&tbase->tx_params_hw.tx_port_queue[0], mbufs, n_pkts, tbase);
}

int tx_ctrlplane_sw(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, __attribute__((unused)) uint8_t *out)
{
	dump_pkts(tbase, mbufs, n_pkts);
        return ring_enq_no_drop(tbase->tx_params_sw.tx_rings[0], mbufs, n_pkts, tbase);
}

static inline int tx_ring_all(struct task_base *tbase, struct rte_ring *ring, uint16_t command,  struct rte_mbuf *mbuf, uint8_t core_id, uint8_t task_id, uint32_t ip)
{
	if (tbase->aux->task_rt_dump.cur_trace) {
		trace_one_rx_pkt(tbase, mbuf);
	}
	mbuf->udata64 = ((uint64_t)ip << 32) | (core_id << 16) | (task_id << 8) | command;
	return rte_ring_enqueue(ring, mbuf);
}

void tx_ring_cti(struct task_base *tbase, struct rte_ring *ring, uint16_t command,  struct rte_mbuf *mbuf, uint8_t core_id, uint8_t task_id, uint32_t ip)
{
	plogx_dbg("\tSending command %s with ip %d.%d.%d.%d to ring %p using mbuf %p, core %d and task %d - ring size now %d\n", actions_string[command], IP4(ip), ring, mbuf, core_id, task_id, rte_ring_free_count(ring));
	int ret = tx_ring_all(tbase, ring, command,  mbuf, core_id, task_id, ip);
	if (unlikely(ret != 0)) {
		plogx_dbg("\tFail to send command %s with ip %d.%d.%d.%d to ring %p using mbuf %p, core %d and task %d - ring size now %d\n", actions_string[command], IP4(ip), ring, mbuf, core_id, task_id, rte_ring_free_count(ring));
		TASK_STATS_ADD_DROP_DISCARD(&tbase->aux->stats, 1);
		rte_pktmbuf_free(mbuf);
	}
}

void tx_ring_ip(struct task_base *tbase, struct rte_ring *ring, uint16_t command,  struct rte_mbuf *mbuf, uint32_t ip)
{
	plogx_dbg("\tSending command %s with ip %d.%d.%d.%d to ring %p using mbuf %p - ring size now %d\n", actions_string[command], IP4(ip), ring, mbuf, rte_ring_free_count(ring));
	int ret = tx_ring_all(tbase, ring, command,  mbuf, 0, 0, ip);
	if (unlikely(ret != 0)) {
		plogx_dbg("\tFail to send command %s with ip %d.%d.%d.%d to ring %p using mbuf %p - ring size now %d\n", actions_string[command], IP4(ip), ring, mbuf, rte_ring_free_count(ring));
		TASK_STATS_ADD_DROP_DISCARD(&tbase->aux->stats, 1);
		rte_pktmbuf_free(mbuf);
	}
}

void tx_ring(struct task_base *tbase, struct rte_ring *ring, uint16_t command,  struct rte_mbuf *mbuf)
{
	plogx_dbg("\tSending command %s to ring %p using mbuf %p - ring size now %d\n", actions_string[command], ring, mbuf, rte_ring_free_count(ring));
	int ret = tx_ring_all(tbase, ring, command,  mbuf, 0, 0, 0);
	if (unlikely(ret != 0)) {
		plogx_dbg("\tFail to send command %s to ring %p using mbuf %p - ring size now %d\n", actions_string[command], ring, mbuf, rte_ring_free_count(ring));
		TASK_STATS_ADD_DROP_DISCARD(&tbase->aux->stats, 1);
		rte_pktmbuf_free(mbuf);
	}
}
