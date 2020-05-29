/*
// Copyright (c) 2010-2020 Intel Corporation
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
#include <rte_mbuf.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <rte_cycles.h>
#include <rte_version.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_hash_crc.h>
#include <rte_malloc.h>

#include "prox_shared.h"
#include "random.h"
#include "prox_malloc.h"
#include "handle_gen.h"
#include "handle_lat.h"
#include "task_init.h"
#include "task_base.h"
#include "prox_port_cfg.h"
#include "lconf.h"
#include "log.h"
#include "quit.h"
#include "prox_cfg.h"
#include "mbuf_utils.h"
#include "qinq.h"
#include "prox_cksum.h"
#include "etypes.h"
#include "prox_assert.h"
#include "prefetch.h"
#include "token_time.h"
#include "local_mbuf.h"
#include "arp.h"
#include "tx_pkt.h"
#include "handle_master.h"
#include "defines.h"
#include "prox_ipv6.h"

struct pkt_template {
	uint16_t len;
	uint16_t l2_len;
	uint16_t l3_len;
	uint8_t  *buf;
};

#define IP4(x) x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, x >> 24

#define DO_PANIC	1
#define DO_NOT_PANIC	0

#define FROM_PCAP	1
#define NOT_FROM_PCAP	0

#define TASK_OVERWRITE_SRC_MAC_WITH_PORT_MAC 1

static void pkt_template_init_mbuf(struct pkt_template *pkt_template, struct rte_mbuf *mbuf, uint8_t *pkt)
{
	const uint32_t pkt_size = pkt_template->len;

	rte_pktmbuf_pkt_len(mbuf) = pkt_size;
	rte_pktmbuf_data_len(mbuf) = pkt_size;
	init_mbuf_seg(mbuf);
	rte_memcpy(pkt, pkt_template->buf, pkt_template->len);
}

struct task_gen_pcap {
	struct task_base base;
	uint64_t hz;
	struct local_mbuf local_mbuf;
	uint32_t pkt_idx;
	struct pkt_template *proto;
	uint32_t loop;
	uint32_t n_pkts;
	uint64_t last_tsc;
	uint64_t *proto_tsc;
	uint32_t socket_id;
};

struct task_gen {
	struct task_base base;
	uint64_t hz;
	struct token_time token_time;
	struct local_mbuf local_mbuf;
	struct pkt_template *pkt_template; /* packet templates used at runtime */
	uint64_t write_duration_estimate; /* how long it took previously to write the time stamps in the packets */
	uint64_t earliest_tsc_next_pkt;
	uint64_t new_rate_bps;
	uint64_t pkt_queue_index;
	uint32_t n_pkts; /* number of packets in pcap */
	uint32_t orig_n_pkts; /* number of packets in pcap */
	uint32_t pkt_idx; /* current packet from pcap */
	uint32_t pkt_count; /* how many pakets to generate */
	uint32_t max_frame_size;
	uint32_t runtime_flags;
	uint16_t lat_pos;
	uint16_t packet_id_pos;
	uint16_t accur_pos;
	uint16_t sig_pos;
	uint32_t sig;
	uint32_t socket_id;
	uint8_t generator_id;
	uint8_t n_rands; /* number of randoms */
	uint8_t min_bulk_size;
	uint8_t max_bulk_size;
	uint8_t lat_enabled;
	uint8_t runtime_checksum_needed;
	struct {
		struct random state;
		uint32_t rand_mask; /* since the random vals are uniform, masks don't introduce bias  */
		uint32_t fixed_bits; /* length of each random (max len = 4) */
		uint16_t rand_offset; /* each random has an offset*/
		uint8_t rand_len; /* # bytes to take from random (no bias introduced) */
	} rand[64];
	uint64_t accur[ACCURACY_WINDOW];
	uint64_t pkt_tsc_offset[64];
	struct pkt_template *pkt_template_orig; /* packet templates (from inline or from pcap) */
	prox_rte_ether_addr  src_mac;
	uint8_t flags;
	uint8_t cksum_offload;
	struct prox_port_cfg *port;
	uint64_t *bytes_to_tsc;
	uint32_t imix_pkt_sizes[MAX_IMIX_PKTS];
	uint32_t imix_nb_pkts;
	uint32_t new_imix_nb_pkts;
} __rte_cache_aligned;

static void task_gen_set_pkt_templates_len(struct task_gen *task, uint32_t *pkt_sizes);
static void task_gen_reset_pkt_templates_content(struct task_gen *task);
static void task_gen_pkt_template_recalc_metadata(struct task_gen *task);
static int check_all_pkt_size(struct task_gen *task, int do_panic);
static int check_all_fields_in_bounds(struct task_gen *task, int do_panic);

static inline uint8_t ipv4_get_hdr_len(prox_rte_ipv4_hdr *ip)
{
	/* Optimize for common case of IPv4 header without options. */
	if (ip->version_ihl == 0x45)
		return sizeof(prox_rte_ipv4_hdr);
	if (unlikely(ip->version_ihl >> 4 != 4)) {
		plog_warn("IPv4 ether_type but IP version = %d != 4", ip->version_ihl >> 4);
		return 0;
	}
	return (ip->version_ihl & 0xF) * 4;
}

static void parse_l2_l3_len(uint8_t *pkt, uint16_t *l2_len, uint16_t *l3_len, uint16_t len)
{
	*l2_len = sizeof(prox_rte_ether_hdr);
	*l3_len = 0;
	prox_rte_vlan_hdr *vlan_hdr;
	prox_rte_ether_hdr *eth_hdr = (prox_rte_ether_hdr*)pkt;
	prox_rte_ipv4_hdr *ip;
	uint16_t ether_type = eth_hdr->ether_type;

	// Unstack VLAN tags
	while (((ether_type == ETYPE_8021ad) || (ether_type == ETYPE_VLAN)) && (*l2_len + sizeof(prox_rte_vlan_hdr) < len)) {
		vlan_hdr = (prox_rte_vlan_hdr *)(pkt + *l2_len);
		*l2_len +=4;
		ether_type = vlan_hdr->eth_proto;
	}

	// No L3 cksum offload for IPv6, but TODO L4 offload
	// ETYPE_EoGRE CRC not implemented yet

	switch (ether_type) {
	case ETYPE_MPLSU:
	case ETYPE_MPLSM:
		*l2_len +=4;
		break;
	case ETYPE_IPv6:
	case ETYPE_IPv4:
		break;
	case ETYPE_EoGRE:
	case ETYPE_ARP:
		*l2_len = 0;
		break;
	default:
		*l2_len = 0;
		plog_warn("Unsupported packet type %x - CRC might be wrong\n", ether_type);
		break;
	}

	if (*l2_len) {
		prox_rte_ipv4_hdr *ip = (prox_rte_ipv4_hdr *)(pkt + *l2_len);
		if (ip->version_ihl >> 4 == 4)
			*l3_len = ipv4_get_hdr_len(ip);
	}
}

static void checksum_packet(uint8_t *hdr, struct rte_mbuf *mbuf, struct pkt_template *pkt_template, int cksum_offload)
{
	uint16_t l2_len = pkt_template->l2_len;
	uint16_t l3_len = pkt_template->l3_len;

	prox_rte_ipv4_hdr *ip = (prox_rte_ipv4_hdr*)(hdr + l2_len);
	if (l3_len) {
		prox_ip_udp_cksum(mbuf, ip, l2_len, l3_len, cksum_offload);
	} else if (ip->version_ihl >> 4 == 6) {
		prox_rte_ipv6_hdr *ip6 = (prox_rte_ipv6_hdr *)(hdr + l2_len);
		if (ip6->proto == IPPROTO_UDP) {
			prox_rte_udp_hdr *udp = (prox_rte_udp_hdr *)(ip6 + 1);
			udp->dgram_cksum = 0;
			udp->dgram_cksum = rte_ipv6_udptcp_cksum(ip6, udp);
		} else if (ip6->proto == IPPROTO_TCP) {
			prox_rte_tcp_hdr *tcp = (prox_rte_tcp_hdr *)(ip6 + 1);
			tcp->cksum = 0;
			tcp->cksum = rte_ipv6_udptcp_cksum(ip6, tcp);
		}
	}
}

static void task_gen_reset_token_time(struct task_gen *task)
{
	token_time_set_bpp(&task->token_time, task->new_rate_bps);
	token_time_reset(&task->token_time, rte_rdtsc(), 0);
}

static void task_gen_take_count(struct task_gen *task, uint32_t send_bulk)
{
	if (task->pkt_count == (uint32_t)-1)
		return ;
	else {
		if (task->pkt_count >= send_bulk)
			task->pkt_count -= send_bulk;
		else
			task->pkt_count = 0;
	}
}

static int handle_gen_pcap_bulk(struct task_base *tbase, struct rte_mbuf **mbuf, uint16_t n_pkts)
{
	struct task_gen_pcap *task = (struct task_gen_pcap *)tbase;
	uint64_t now = rte_rdtsc();
	uint64_t send_bulk = 0;
	uint32_t pkt_idx_tmp = task->pkt_idx;

	if (pkt_idx_tmp == task->n_pkts) {
		PROX_ASSERT(task->loop);
		return 0;
	}

	for (uint16_t j = 0; j < 64; ++j) {
		uint64_t tsc = task->proto_tsc[pkt_idx_tmp];
		if (task->last_tsc + tsc <= now) {
			task->last_tsc += tsc;
			send_bulk++;
			pkt_idx_tmp++;
			if (pkt_idx_tmp == task->n_pkts) {
				if (task->loop)
					pkt_idx_tmp = 0;
				else
					break;
			}
		}
		else
			break;
	}

	struct rte_mbuf **new_pkts = local_mbuf_refill_and_take(&task->local_mbuf, send_bulk);
	if (new_pkts == NULL)
		return 0;

	for (uint16_t j = 0; j < send_bulk; ++j) {
		struct rte_mbuf *next_pkt = new_pkts[j];
		struct pkt_template *pkt_template = &task->proto[task->pkt_idx];
		uint8_t *hdr = rte_pktmbuf_mtod(next_pkt, uint8_t *);

		pkt_template_init_mbuf(pkt_template, next_pkt, hdr);

		task->pkt_idx++;
		if (task->pkt_idx == task->n_pkts) {
			if (task->loop)
				task->pkt_idx = 0;
			else
				break;
		}
	}

	return task->base.tx_pkt(&task->base, new_pkts, send_bulk, NULL);
}

static inline uint64_t bytes_to_tsc(struct task_gen *task, uint32_t bytes)
{
	return task->bytes_to_tsc[bytes];
}

static uint32_t task_gen_next_pkt_idx(const struct task_gen *task, uint32_t pkt_idx)
{
	return pkt_idx + 1 >= task->n_pkts? 0 : pkt_idx + 1;
}

static uint32_t task_gen_offset_pkt_idx(const struct task_gen *task, uint32_t offset)
{
	return (task->pkt_idx + offset) % task->n_pkts;
}

static uint32_t task_gen_calc_send_bulk(const struct task_gen *task, uint32_t *total_bytes)
{
	/* The biggest bulk we allow to send is task->max_bulk_size
	   packets. The max bulk size can also be limited by the
	   pkt_count field.  At the same time, we are rate limiting
	   based on the specified speed (in bytes per second) so token
	   bucket based rate limiting must also be applied. The
	   minimum bulk size is also constrained. If the calculated
	   bulk size is less then the minimum, then don't send
	   anything. */

	const uint32_t min_bulk = task->min_bulk_size;
	uint32_t max_bulk = task->max_bulk_size;

	if (task->pkt_count != (uint32_t)-1 && task->pkt_count < max_bulk) {
		max_bulk = task->pkt_count;
	}

	uint32_t send_bulk = 0;
	uint32_t pkt_idx_tmp = task->pkt_idx;
	uint32_t would_send_bytes = 0;
	uint32_t pkt_size;

	/*
	 * TODO - this must be improved to take into account the fact that, after applying randoms
	 * The packet can be replaced by an ARP
	 */
	for (uint16_t j = 0; j < max_bulk; ++j) {
		struct pkt_template *pktpl = &task->pkt_template[pkt_idx_tmp];
		pkt_size = pktpl->len;
		uint32_t pkt_len = pkt_len_to_wire_size(pkt_size);
		if (pkt_len + would_send_bytes > task->token_time.bytes_now)
			break;

		pkt_idx_tmp = task_gen_next_pkt_idx(task, pkt_idx_tmp);

		send_bulk++;
		would_send_bytes += pkt_len;
	}

	if (send_bulk < min_bulk)
		return 0;
	*total_bytes = would_send_bytes;
	return send_bulk;
}

static void task_gen_apply_random_fields(struct task_gen *task, uint8_t *hdr)
{
	uint32_t ret, ret_tmp;

	for (uint16_t i = 0; i < task->n_rands; ++i) {
		ret = random_next(&task->rand[i].state);
		ret_tmp = (ret & task->rand[i].rand_mask) | task->rand[i].fixed_bits;

		ret_tmp = rte_bswap32(ret_tmp);
		/* At this point, the lower order bytes (BE) contain
		   the generated value. The address where the values
		   of interest starts is at ret_tmp + 4 - rand_len. */
		uint8_t *pret_tmp = (uint8_t*)&ret_tmp;
		rte_memcpy(hdr + task->rand[i].rand_offset, pret_tmp + 4 - task->rand[i].rand_len, task->rand[i].rand_len);
	}
}

static void task_gen_apply_all_random_fields(struct task_gen *task, uint8_t **pkt_hdr, uint32_t count)
{
	if (!task->n_rands)
		return;

	for (uint16_t i = 0; i < count; ++i)
		task_gen_apply_random_fields(task, pkt_hdr[i]);
}

static void task_gen_apply_accur_pos(struct task_gen *task, uint8_t *pkt_hdr, uint32_t accuracy)
{
	*(uint32_t *)(pkt_hdr + task->accur_pos) = accuracy;
}

static void task_gen_apply_sig(struct task_gen *task, struct pkt_template *dst)
{
	if (task->sig_pos)
		*(uint32_t *)(dst->buf + task->sig_pos) = task->sig;
}

static void task_gen_apply_all_accur_pos(struct task_gen *task, struct rte_mbuf **mbufs, uint8_t **pkt_hdr, uint32_t count)
{
	if (!task->accur_pos)
		return;

	/* The accuracy of task->pkt_queue_index - ACCURACY_WINDOW is stored in
	   packet task->pkt_queue_index. The ID modulo ACCURACY_WINDOW is the
	   same. */
	for (uint16_t j = 0; j < count; ++j) {
		uint32_t accuracy = task->accur[(task->pkt_queue_index + j) & (ACCURACY_WINDOW - 1)];
		task_gen_apply_accur_pos(task, pkt_hdr[j], accuracy);
	}
}

static void task_gen_apply_unique_id(struct task_gen *task, uint8_t *pkt_hdr, const struct unique_id *id)
{
	struct unique_id *dst = (struct unique_id *)(pkt_hdr + task->packet_id_pos);

	*dst = *id;
}

static void task_gen_apply_all_unique_id(struct task_gen *task, struct rte_mbuf **mbufs, uint8_t **pkt_hdr, uint32_t count)
{
	if (!task->packet_id_pos)
		return;

	for (uint16_t i = 0; i < count; ++i) {
		struct unique_id id;
		unique_id_init(&id, task->generator_id, task->pkt_queue_index++);
		task_gen_apply_unique_id(task, pkt_hdr[i], &id);
	}
}

static void task_gen_checksum_packets(struct task_gen *task, struct rte_mbuf **mbufs, uint8_t **pkt_hdr, uint32_t count)
{
	if (!(task->runtime_flags & TASK_TX_CRC))
		return;

	if (!task->runtime_checksum_needed)
		return;

	uint32_t pkt_idx = task_gen_offset_pkt_idx(task, - count);
	for (uint16_t i = 0; i < count; ++i) {
		struct pkt_template *pkt_template = &task->pkt_template[pkt_idx];
		checksum_packet(pkt_hdr[i], mbufs[i], pkt_template, task->cksum_offload);
		pkt_idx = task_gen_next_pkt_idx(task, pkt_idx);
	}
}

static void task_gen_consume_tokens(struct task_gen *task, uint32_t tokens, uint32_t send_count)
{
	/* If max burst has been sent, we can't keep up so just assume
	   that we can (leaving a "gap" in the packet stream on the
	   wire) */
	task->token_time.bytes_now -= tokens;
	if (send_count == task->max_bulk_size && task->token_time.bytes_now > tokens) {
		task->token_time.bytes_now = tokens;
	}
}

static uint64_t task_gen_calc_bulk_duration(struct task_gen *task, uint32_t count)
{
	uint32_t pkt_idx = task_gen_offset_pkt_idx(task, - 1);
	struct pkt_template *last_pkt_template = &task->pkt_template[pkt_idx];
	uint32_t last_pkt_len = pkt_len_to_wire_size(last_pkt_template->len);
#ifdef NO_EXTRAPOLATION
	uint64_t bulk_duration = task->pkt_tsc_offset[count - 1];
#else
	uint64_t last_pkt_duration = bytes_to_tsc(task, last_pkt_len);
	uint64_t bulk_duration = task->pkt_tsc_offset[count - 1] + last_pkt_duration;
#endif

	return bulk_duration;
}

static uint64_t task_gen_write_latency(struct task_gen *task, uint8_t **pkt_hdr, uint32_t count)
{
	if (!task->lat_enabled)
		return 0;

	uint64_t tx_tsc, delta_t;
	uint64_t tsc_before_tx = 0;

	/* Just before sending the packets, apply the time stamp
	   relative to when the first packet will be sent. The first
	   packet will be sent now. The time is read for each packet
	   to reduce the error towards the actual time the packet will
	   be sent. */
	uint64_t write_tsc_after, write_tsc_before;

	write_tsc_before = rte_rdtsc();

	/* The time it took previously to write the time stamps in the
	   packets is used as an estimate for how long it will take to
	   write the time stamps now.  The estimated time at which the
	   packets will actually be sent will be at tx_tsc. */
	tx_tsc = write_tsc_before + task->write_duration_estimate;

	/* The offset delta_t tracks the difference between the actual
	   time and the time written in the packets. Adding the offset
	   to the actual time insures that the time written in the
	   packets is monotonically increasing. At the same time,
	   simply sleeping until delta_t is zero would leave a period
	   of silence on the line. The error has been introduced
	   earlier, but the packets have already been sent. */

	/* This happens typically if previous bulk was delayed
	   by an interrupt e.g.  (with Time in nsec)
	   Time x: sleep 4 microsec
	   Time x+4000: send 64 packets (64 packets as 4000 nsec, w/ 10Gbps 64 bytes)
	   Time x+5000: send 16 packets (16 packets as 1000 nsec)
	   When we send the 16 packets, the 64 ealier packets are not yet
	   fully sent */
	if (tx_tsc < task->earliest_tsc_next_pkt)
		delta_t = task->earliest_tsc_next_pkt - tx_tsc;
	else
		delta_t = 0;

	for (uint16_t i = 0; i < count; ++i) {
		uint32_t *pos = (uint32_t *)(pkt_hdr[i] + task->lat_pos);
		const uint64_t pkt_tsc = tx_tsc + delta_t + task->pkt_tsc_offset[i];
		*pos = pkt_tsc >> LATENCY_ACCURACY;
	}

	uint64_t bulk_duration = task_gen_calc_bulk_duration(task, count);
	task->earliest_tsc_next_pkt = tx_tsc + delta_t + bulk_duration;
	write_tsc_after = rte_rdtsc();
	task->write_duration_estimate = write_tsc_after - write_tsc_before;

	/* Make sure that the time stamps that were written
	   are valid. The offset must be taken into account */
	do {
		tsc_before_tx = rte_rdtsc();
	} while (tsc_before_tx < tx_tsc);

	return tsc_before_tx;
}

static void task_gen_store_accuracy(struct task_gen *task, uint32_t count, uint64_t tsc_before_tx)
{
	if (!task->accur_pos)
		return;

	uint64_t accur = rte_rdtsc() - tsc_before_tx;
	uint64_t first_accuracy_idx = task->pkt_queue_index - count;

	for (uint32_t i = 0; i < count; ++i) {
		uint32_t accuracy_idx = (first_accuracy_idx + i) & (ACCURACY_WINDOW - 1);

		task->accur[accuracy_idx] = accur;
	}
}

static void task_gen_load_and_prefetch(struct rte_mbuf **mbufs, uint8_t **pkt_hdr, uint32_t count)
{
	for (uint16_t i = 0; i < count; ++i)
		rte_prefetch0(mbufs[i]);
	for (uint16_t i = 0; i < count; ++i)
		pkt_hdr[i] = rte_pktmbuf_mtod(mbufs[i], uint8_t *);
	for (uint16_t i = 0; i < count; ++i)
		rte_prefetch0(pkt_hdr[i]);
}

static void task_gen_build_packets(struct task_gen *task, struct rte_mbuf **mbufs, uint8_t **pkt_hdr, uint32_t count)
{
	uint64_t will_send_bytes = 0;

	for (uint16_t i = 0; i < count; ++i) {
		struct pkt_template *pktpl = &task->pkt_template[task->pkt_idx];
		struct pkt_template *pkt_template = &task->pkt_template[task->pkt_idx];
		pkt_template_init_mbuf(pkt_template, mbufs[i], pkt_hdr[i]);
		prox_rte_ether_hdr *hdr = (prox_rte_ether_hdr *)pkt_hdr[i];
		if (task->lat_enabled) {
#ifdef NO_EXTRAPOLATION
			task->pkt_tsc_offset[i] = 0;
#else
			task->pkt_tsc_offset[i] = bytes_to_tsc(task, will_send_bytes);
#endif
			will_send_bytes += pkt_len_to_wire_size(pkt_template->len);
		}
		task->pkt_idx = task_gen_next_pkt_idx(task, task->pkt_idx);
	}
}

static int task_gen_allocate_templates(struct task_gen *task, uint32_t orig_nb_pkts, uint32_t nb_pkts, int do_panic, int pcap)
{
	size_t mem_size = nb_pkts * sizeof(*task->pkt_template);
	size_t orig_mem_size = orig_nb_pkts * sizeof(*task->pkt_template);
	task->pkt_template = prox_zmalloc(mem_size, task->socket_id);
	task->pkt_template_orig = prox_zmalloc(orig_mem_size, task->socket_id);

	if (task->pkt_template == NULL || task->pkt_template_orig == NULL) {
		plog_err_or_panic(do_panic, "Failed to allocate %lu bytes (in huge pages) for %s\n", mem_size, pcap ? "pcap file":"packet template");
		return -1;
	}

	for (size_t i = 0; i < orig_nb_pkts; i++) {
		task->pkt_template_orig[i].buf = prox_zmalloc(task->max_frame_size, task->socket_id);
		if (task->pkt_template_orig[i].buf == NULL) {
			plog_err_or_panic(do_panic, "Failed to allocate %u bytes (in huge pages) for %s\n", task->max_frame_size, pcap ? "packet from pcap": "packet");
			return -1;
		}
	}
	for (size_t i = 0; i < nb_pkts; i++) {
		task->pkt_template[i].buf = prox_zmalloc(task->max_frame_size, task->socket_id);
		if (task->pkt_template[i].buf == NULL) {
			plog_err_or_panic(do_panic, "Failed to allocate %u bytes (in huge pages) for %s\n", task->max_frame_size, pcap ? "packet from pcap": "packet");
			return -1;
		}
	}
	return 0;
}

static int task_gen_reallocate_templates(struct task_gen *task, uint32_t nb_pkts, int do_panic)
{
	// Need to free up bufs allocated in previous (longer) imix
	for (size_t i = nb_pkts; i < task->n_pkts; i++) {
		if (task->pkt_template[i].buf) {
			rte_free(task->pkt_template[i].buf);
			task->pkt_template[i].buf = NULL;
		}
	}

	size_t mem_size = nb_pkts * sizeof(*task->pkt_template);
	size_t old_mem_size = task->n_pkts * sizeof(*task->pkt_template);
	if (old_mem_size > mem_size)
		old_mem_size = mem_size;

	struct pkt_template *ptr;

	// re-allocate memory for new pkt_template (this might allocate additional memory or free up some...)
	if ((ptr = rte_malloc_socket(NULL, mem_size, RTE_CACHE_LINE_SIZE, task->socket_id)) != NULL) {
		memcpy(ptr, task->pkt_template, old_mem_size);
		rte_free(task->pkt_template);
		task->pkt_template = ptr;
	} else {
		plog_err_or_panic(do_panic, "Failed to allocate %lu bytes (in huge pages) for packet template for IMIX\n", mem_size);
		return -1;
	}

	// Need to allocate bufs for new template but no need to reallocate for existing ones
	for (size_t i = task->n_pkts; i < nb_pkts; ++i) {
		task->pkt_template[i].buf = prox_zmalloc(task->max_frame_size, task->socket_id);
		if (task->pkt_template[i].buf == NULL) {
			plog_err_or_panic(do_panic, "Failed to allocate %u bytes (in huge pages) for packet %zd in IMIX\n", task->max_frame_size, i);
			return -1;
		}
	}
	return 0;
}

static int check_pkt_size(struct task_gen *task, uint32_t pkt_size, int do_panic)
{
	const uint16_t min_len = sizeof(prox_rte_ether_hdr) + sizeof(prox_rte_ipv4_hdr);
	const uint16_t max_len = task->max_frame_size;

	if (do_panic) {
		PROX_PANIC(pkt_size == 0, "Invalid packet size length (no packet defined?)\n");
		PROX_PANIC(pkt_size > max_len, "pkt_size out of range (must be <= %u)\n", max_len);
		PROX_PANIC(pkt_size < min_len, "pkt_size out of range (must be >= %u)\n", min_len);
		return 0;
	} else {
		if (pkt_size == 0) {
			plog_err("Invalid packet size length (no packet defined?)\n");
			return -1;
		}
		if (pkt_size > max_len) {
			if (pkt_size >  PROX_RTE_ETHER_MAX_LEN + 2 * PROX_VLAN_TAG_SIZE - 4)
				plog_err("pkt_size too high and jumbo frames disabled\n");
			else
				plog_err("pkt_size out of range (must be <= (mtu=%u))\n", max_len);
			return -1;
		}
		if (pkt_size < min_len) {
			plog_err("pkt_size out of range (must be >= %u)\n", min_len);
			return -1;
		}
		return 0;
	}
}

static int check_fields_in_bounds(struct task_gen *task, uint32_t pkt_size, int do_panic)
{
	if (task->lat_enabled) {
		uint32_t pos_beg = task->lat_pos;
		uint32_t pos_end = task->lat_pos + 3U;

		if (do_panic)
			PROX_PANIC(pkt_size <= pos_end, "Writing latency at %u-%u, but packet size is %u bytes\n",
			   pos_beg, pos_end, pkt_size);
		else if (pkt_size <= pos_end) {
			plog_err("Writing latency at %u-%u, but packet size is %u bytes\n", pos_beg, pos_end, pkt_size);
			return -1;
		}
	}
	if (task->packet_id_pos) {
		uint32_t pos_beg = task->packet_id_pos;
		uint32_t pos_end = task->packet_id_pos + 4U;

		if (do_panic)
			PROX_PANIC(pkt_size <= pos_end, "Writing packet at %u-%u, but packet size is %u bytes\n",
			   pos_beg, pos_end, pkt_size);
		else if (pkt_size <= pos_end) {
			plog_err("Writing packet at %u-%u, but packet size is %u bytes\n", pos_beg, pos_end, pkt_size);
			return -1;
		}
	}
	if (task->accur_pos) {
		uint32_t pos_beg = task->accur_pos;
		uint32_t pos_end = task->accur_pos + 3U;

		if (do_panic)
			PROX_PANIC(pkt_size <= pos_end, "Writing accuracy at %u-%u, but packet size is %u bytes\n",
			   pos_beg, pos_end, pkt_size);
		else if (pkt_size <= pos_end) {
			plog_err("Writing accuracy at %u-%u, but packet size is %u bytes\n", pos_beg, pos_end, pkt_size);
			return -1;
		}
	}
	return 0;
}

static int task_gen_set_eth_ip_udp_sizes(struct task_gen *task, uint32_t n_orig_pkts, uint32_t nb_pkt_sizes, uint32_t *pkt_sizes)
{
	size_t k;
	uint32_t l4_len;
	prox_rte_ipv4_hdr *ip;
	struct pkt_template *template;

	for (size_t j = 0; j < nb_pkt_sizes; ++j) {
		for (size_t i = 0; i < n_orig_pkts; ++i) {
			k = j * n_orig_pkts + i;
			template = &task->pkt_template[k];
			if (template->l2_len == 0)
				continue;
			ip = (prox_rte_ipv4_hdr *)(template->buf + template->l2_len);
			ip->total_length = rte_bswap16(pkt_sizes[j] - template->l2_len);
			l4_len = pkt_sizes[j] - template->l2_len - template->l3_len;
			ip->hdr_checksum = 0;
			prox_ip_cksum_sw(ip);

			if (ip->next_proto_id == IPPROTO_UDP) {
				prox_rte_udp_hdr *udp = (prox_rte_udp_hdr *)(((uint8_t *)ip) + template->l3_len);
				udp->dgram_len = rte_bswap16(l4_len);
				prox_udp_cksum_sw(udp, l4_len, ip->src_addr, ip->dst_addr);
			} else if (ip->next_proto_id == IPPROTO_TCP) {
				prox_rte_tcp_hdr *tcp = (prox_rte_tcp_hdr *)(((uint8_t *)ip) + template->l3_len);
				prox_tcp_cksum_sw(tcp, l4_len, ip->src_addr, ip->dst_addr);
			}
		}
	}
	return 0;
}

static int task_gen_apply_imix(struct task_gen *task, int do_panic)
{
	struct pkt_template *ptr;
	int rc;
	task->imix_nb_pkts = task->new_imix_nb_pkts;
	uint32_t n_pkts = task->imix_nb_pkts * task->orig_n_pkts;

	if ((n_pkts != task->n_pkts) && ((rc = task_gen_reallocate_templates(task, n_pkts, do_panic)) < 0))
		return rc;

	task->n_pkts = n_pkts;
	if (task->pkt_idx >= n_pkts)
		task->pkt_idx = 0;
	task_gen_set_pkt_templates_len(task, task->imix_pkt_sizes);
	task_gen_reset_pkt_templates_content(task);
	task_gen_pkt_template_recalc_metadata(task);
	check_all_pkt_size(task, DO_NOT_PANIC);
	check_all_fields_in_bounds(task, DO_NOT_PANIC);
	task_gen_set_eth_ip_udp_sizes(task, task->orig_n_pkts, task->imix_nb_pkts, task->imix_pkt_sizes);
	return 0;
}

static void task_gen_update_config(struct task_gen *task)
{
	if (task->token_time.cfg.bpp != task->new_rate_bps)
		task_gen_reset_token_time(task);
	if (task->new_imix_nb_pkts)
		task_gen_apply_imix(task, DO_NOT_PANIC);
	task->new_imix_nb_pkts = 0;
}

static inline void build_value(struct task_gen *task, uint32_t mask, int bit_pos, uint32_t val, uint32_t fixed_bits)
{
	struct task_base *tbase = (struct task_base *)task;
	if (bit_pos < 32) {
		build_value(task, mask >> 1, bit_pos + 1, val, fixed_bits);
		if (mask & 1) {
			build_value(task, mask >> 1, bit_pos + 1, val | (1 << bit_pos), fixed_bits);
		}
	} else {
		register_ip_to_ctrl_plane(tbase->l3.tmaster, rte_cpu_to_be_32(val | fixed_bits), tbase->l3.reachable_port_id, tbase->l3.core_id, tbase->l3.task_id);
	}
}

static inline void build_value_ipv6(struct task_gen *task, uint32_t mask, int var_bit_pos, int init_var_bit_pos, struct ipv6_addr val, struct ipv6_addr fixed_bits)
{
	struct task_base *tbase = (struct task_base *)task;
	if (var_bit_pos < 32) {
		build_value_ipv6(task, mask >> 1, var_bit_pos + 1, init_var_bit_pos, val, fixed_bits);
		if (mask & 1) {
			int byte_pos = (var_bit_pos + init_var_bit_pos) / 8;
			int bit_pos = (var_bit_pos + init_var_bit_pos) % 8;
			val.bytes[byte_pos] = val.bytes[byte_pos] | (1 << bit_pos);
			build_value_ipv6(task, mask >> 1, var_bit_pos + 1, init_var_bit_pos, val, fixed_bits);
		}
	} else {
		for (uint i = 0; i < sizeof(struct ipv6_addr) / 8; i++)
			val.bytes[i] = val.bytes[i] | fixed_bits.bytes[i];
		register_node_to_ctrl_plane(tbase->l3.tmaster, &null_addr, &val, tbase->l3.reachable_port_id, tbase->l3.core_id, tbase->l3.task_id);
	}
}

static inline void register_all_ip_to_ctrl_plane(struct task_gen *task)
{
	struct task_base *tbase = (struct task_base *)task;
	int i, len, fixed;
	unsigned int offset;
	uint32_t mask, ip_len;
	struct ipv6_addr *ip6_src = NULL;
	uint32_t *ip_src;

	for (uint32_t i = 0; i < task->n_pkts; ++i) {
		struct pkt_template *pktpl = &task->pkt_template[i];
		unsigned int ip_src_pos = 0;
		int ipv4 = 0;
		unsigned int l2_len = sizeof(prox_rte_ether_hdr);

		uint8_t *pkt = pktpl->buf;
		prox_rte_ether_hdr *eth_hdr = (prox_rte_ether_hdr*)pkt;
		uint16_t ether_type = eth_hdr->ether_type;
		prox_rte_vlan_hdr *vlan_hdr;
		prox_rte_ipv4_hdr *ip;

		// Unstack VLAN tags
		while (((ether_type == ETYPE_8021ad) || (ether_type == ETYPE_VLAN)) && (l2_len + sizeof(prox_rte_vlan_hdr) < pktpl->len)) {
			vlan_hdr = (prox_rte_vlan_hdr *)(pkt + l2_len);
			l2_len +=4;
			ether_type = vlan_hdr->eth_proto;
		}
		if ((ether_type == ETYPE_MPLSU) || (ether_type == ETYPE_MPLSM)) {
			l2_len +=4;
			ip = (prox_rte_ipv4_hdr *)(pkt + l2_len);
			if (ip->version_ihl >> 4 == 4)
				ipv4 = 1;
			else if (ip->version_ihl >> 4 != 6)	// Version field at same location for IPv4 and IPv6
				continue;
		} else if (ether_type == ETYPE_IPv4) {
			ip = (prox_rte_ipv4_hdr *)(pkt + l2_len);
			PROX_PANIC(ip->version_ihl >> 4 != 4, "IPv4 ether_type but IP version = %d != 4", ip->version_ihl >> 4);	// Invalid Packet
			ipv4 = 1;
		} else if (ether_type == ETYPE_IPv6) {
			ip = (prox_rte_ipv4_hdr *)(pkt + l2_len);
			PROX_PANIC(ip->version_ihl >> 4 != 6, "IPv6 ether_type but IP version = %d != 6", ip->version_ihl >> 4);	// Invalid Packet
		} else {
			continue;
		}

		PROX_PANIC(ipv4 && ((prox_cfg.flags & DSF_L3_ENABLED) == 0), "Trying to generate an IPv4 packet in NDP mode => not supported\n");
		PROX_PANIC((ipv4 == 0) && ((prox_cfg.flags & DSF_NDP_ENABLED) == 0), "Trying to generate an IPv6 packet in L3 (IPv4) mode => not supported\n");
		if (ipv4) {
			// Even if IPv4 header contains options, options are after ip src and dst
			ip_src_pos = l2_len + sizeof(prox_rte_ipv4_hdr) - 2 * sizeof(uint32_t);
			ip_src = ((uint32_t *)(pktpl->buf + ip_src_pos));
			plog_info("\tip_src_pos = %d, ip_src = %x\n", ip_src_pos, *ip_src);
			register_ip_to_ctrl_plane(tbase->l3.tmaster, *ip_src, tbase->l3.reachable_port_id, tbase->l3.core_id, tbase->l3.task_id);
			ip_len = sizeof(uint32_t);
		} else {
			ip_src_pos = l2_len + sizeof(prox_rte_ipv6_hdr) - 2 * sizeof(struct ipv6_addr);
			ip6_src = ((struct ipv6_addr *)(pktpl->buf + ip_src_pos));
			plog_info("\tip_src_pos = %d, ip6_src = "IPv6_BYTES_FMT"\n", ip_src_pos, IPv6_BYTES(ip6_src->bytes));
			register_node_to_ctrl_plane(tbase->l3.tmaster, ip6_src, &null_addr, tbase->l3.reachable_port_id, tbase->l3.core_id, tbase->l3.task_id);
			ip_len = sizeof(struct ipv6_addr);
		}

		for (int j = 0; j < task->n_rands; j++) {
			offset = task->rand[j].rand_offset;
			len = task->rand[j].rand_len;
			mask = task->rand[j].rand_mask;
			fixed = task->rand[j].fixed_bits;
			plog_info("offset = %d, len = %d, mask = %x, fixed = %x\n", offset, len, mask, fixed);
			if (offset >= ip_src_pos + ip_len)	// First random bit after IP
				continue;
			if (offset + len < ip_src_pos)		// Last random bit before IP
				continue;

			if (ipv4) {
				if (offset >= ip_src_pos) {
					int32_t ip_src_mask = (1 << (4 + ip_src_pos - offset) * 8) - 1;
					mask = mask & ip_src_mask;
					fixed = (fixed & ip_src_mask) | (rte_be_to_cpu_32(*ip_src) & ~ip_src_mask);
					build_value(task, mask, 0, 0, fixed);
				} else {
					int32_t bits = ((ip_src_pos + 4 - offset - len) * 8);
					mask = mask << bits;
					fixed = (fixed << bits) | (rte_be_to_cpu_32(*ip_src) & ((1 << bits) - 1));
					build_value(task, mask, 0, 0, fixed);
				}
			} else {
				// We do not support when random partially covers IP - either starting before or finishing after
				if (offset + len >= ip_src_pos + ip_len) { // len over the ip
					plog_err("Not supported: random_offset = %d, random_len = %d, ip_src_pos = %d, ip_len = %d\n", offset, len, ip_src_pos, ip_len);
					continue;
				}
				if (offset < ip_src_pos) {
					plog_err("Not supported: random_offset = %d, random_len = %d, ip_src_pos = %d, ip_len = %d\n", offset, len, ip_src_pos, ip_len);
					continue;
				}
				// Even for IPv6 the random mask supported by PROX are 32 bits only
				struct ipv6_addr fixed_ipv6;
				uint init_var_byte_pos = (offset - ip_src_pos);
				for (uint i = 0; i < sizeof(struct ipv6_addr); i++) {
					if (i < init_var_byte_pos)
						fixed_ipv6.bytes[i] = ip6_src->bytes[i];
					else if (i < init_var_byte_pos + len)
						fixed_ipv6.bytes[i] = (fixed >> (i - init_var_byte_pos)) & 0xFF;
					else
						fixed_ipv6.bytes[i] = ip6_src->bytes[i];
				}
				build_value_ipv6(task, mask, 0, init_var_byte_pos * 8, null_addr, fixed_ipv6);
			}
		}
	}
}

static int handle_gen_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_gen *task = (struct task_gen *)tbase;
	uint8_t out[MAX_PKT_BURST] = {0};
	int ret;

	int i, j;

	task_gen_update_config(task);

	if (task->pkt_count == 0) {
		task_gen_reset_token_time(task);
		return 0;
	}
	if (!task->token_time.cfg.bpp)
		return 0;

	token_time_update(&task->token_time, rte_rdtsc());

	uint32_t would_send_bytes;
	uint32_t send_bulk = task_gen_calc_send_bulk(task, &would_send_bytes);

	if (send_bulk == 0)
		return 0;
	task_gen_take_count(task, send_bulk);
	task_gen_consume_tokens(task, would_send_bytes, send_bulk);

	struct rte_mbuf **new_pkts = local_mbuf_refill_and_take(&task->local_mbuf, send_bulk);
	if (new_pkts == NULL)
		return 0;
	uint8_t *pkt_hdr[MAX_RING_BURST];

	task_gen_load_and_prefetch(new_pkts, pkt_hdr, send_bulk);
	task_gen_build_packets(task, new_pkts, pkt_hdr, send_bulk);
	task_gen_apply_all_random_fields(task, pkt_hdr, send_bulk);
	task_gen_apply_all_accur_pos(task, new_pkts, pkt_hdr, send_bulk);
	task_gen_apply_all_unique_id(task, new_pkts, pkt_hdr, send_bulk);

	uint64_t tsc_before_tx;

	tsc_before_tx = task_gen_write_latency(task, pkt_hdr, send_bulk);
	task_gen_checksum_packets(task, new_pkts, pkt_hdr, send_bulk);
	ret = task->base.tx_pkt(&task->base, new_pkts, send_bulk, out);
	task_gen_store_accuracy(task, send_bulk, tsc_before_tx);

	// If we failed to send some packets, we need to do some clean-up:

	if (unlikely(ret)) {
		// We need re-use the packets indexes not being sent
		// Hence non-sent packets will not be considered as lost by the receiver when it looks at
		// packet ids. This should also increase the percentage of packets used for latency measurements
		task->pkt_queue_index -= ret;

		// In case of failures, the estimate about when we can send next packet (earliest_tsc_next_pkt) is wrong
		// This would result in under-estimated latency (up to 0 or negative)
		uint64_t bulk_duration = task_gen_calc_bulk_duration(task, ret);
		task->earliest_tsc_next_pkt -= bulk_duration;
	}
	return ret;
}

static void init_task_gen_seeds(struct task_gen *task)
{
	for (size_t i = 0; i < sizeof(task->rand)/sizeof(task->rand[0]); ++i)
		random_init_seed(&task->rand[i].state);
}

static uint32_t pcap_count_pkts(pcap_t *handle, uint32_t *max_frame_size)
{
	struct pcap_pkthdr header;
	const uint8_t *buf;
	uint32_t ret = 0;
	*max_frame_size = 0;
	long pkt1_fpos = ftell(pcap_file(handle));

	while ((buf = pcap_next(handle, &header))) {
		if (header.len > *max_frame_size)
			*max_frame_size = header.len;
		ret++;
	}
	int ret2 = fseek(pcap_file(handle), pkt1_fpos, SEEK_SET);
	PROX_PANIC(ret2 != 0, "Failed to reset reading pcap file\n");
	return ret;
}

static uint64_t avg_time_stamp(uint64_t *time_stamp, uint32_t n)
{
	uint64_t tot_inter_pkt = 0;

	for (uint32_t i = 0; i < n; ++i)
		tot_inter_pkt += time_stamp[i];
	return (tot_inter_pkt + n / 2)/n;
}

static int pcap_read_pkts(pcap_t *handle, const char *file_name, uint32_t n_pkts, struct pkt_template *proto, uint64_t *time_stamp, uint32_t max_frame_size)
{
	struct pcap_pkthdr header;
	const uint8_t *buf;
	size_t len;

	for (uint32_t i = 0; i < n_pkts; ++i) {
		buf = pcap_next(handle, &header);

		PROX_PANIC(buf == NULL, "Failed to read packet %d from pcap %s\n", i, file_name);
		proto[i].len = header.len;
		len = RTE_MIN(header.len, max_frame_size);
		if (header.len > len)
			plogx_warn("Packet truncated from %u to %zu bytes\n", header.len, len);

		if (time_stamp) {
			static struct timeval beg;
			struct timeval tv;

			if (i == 0)
				beg = header.ts;

			tv = tv_diff(&beg, &header.ts);
			tv_to_tsc(&tv, time_stamp + i);
		}
		rte_memcpy(proto[i].buf, buf, len);
	}

	if (time_stamp && n_pkts) {
		for (uint32_t i = n_pkts - 1; i > 0; --i)
			time_stamp[i] -= time_stamp[i - 1];
		/* Since the handle function will loop the packets,
		   there is one time-stamp that is not provided by the
		   pcap file. This is the time between the last and
		   the first packet. This implementation takes the
		   average of the inter-packet times here. */
		if (n_pkts > 1)
			time_stamp[0] = avg_time_stamp(time_stamp + 1, n_pkts - 1);
	}

	return 0;
}

static int check_all_pkt_size(struct task_gen *task, int do_panic)
{
	int rc;
	for (uint32_t i = 0; i < task->n_pkts;++i) {
		if ((rc = check_pkt_size(task, task->pkt_template[i].len, do_panic)) != 0)
			return rc;
	}
	return 0;
}

static int check_all_fields_in_bounds(struct task_gen *task, int do_panic)
{
	int rc;
	for (uint32_t i = 0; i < task->n_pkts;++i) {
		if ((rc = check_fields_in_bounds(task, task->pkt_template[i].len, do_panic)) != 0)
			return rc;
	}
	return 0;
}

static void task_gen_pkt_template_recalc_metadata(struct task_gen *task)
{
	struct pkt_template *template;

	for (size_t i = 0; i < task->n_pkts; ++i) {
		template = &task->pkt_template[i];
		parse_l2_l3_len(template->buf, &template->l2_len, &template->l3_len, template->len);
	}
}

static void task_gen_pkt_template_recalc_checksum(struct task_gen *task)
{
	struct pkt_template *template;
	prox_rte_ipv4_hdr *ip;

	task->runtime_checksum_needed = 0;
	for (size_t i = 0; i < task->n_pkts; ++i) {
		template = &task->pkt_template[i];
		if (template->l2_len == 0)
			continue;
		ip = (prox_rte_ipv4_hdr *)(template->buf + template->l2_len);
		if (ip->version_ihl >> 4 == 4) {
			ip->hdr_checksum = 0;
			prox_ip_cksum_sw(ip);
			uint32_t l4_len = rte_bswap16(ip->total_length) - template->l3_len;
			if (ip->next_proto_id == IPPROTO_UDP) {
				prox_rte_udp_hdr *udp = (prox_rte_udp_hdr *)(((uint8_t *)ip) + template->l3_len);
				prox_udp_cksum_sw(udp, l4_len, ip->src_addr, ip->dst_addr);
			} else if (ip->next_proto_id == IPPROTO_TCP) {
				prox_rte_tcp_hdr *tcp = (prox_rte_tcp_hdr *)(((uint8_t *)ip) + template->l3_len);
				prox_tcp_cksum_sw(tcp, l4_len, ip->src_addr, ip->dst_addr);
			}
		} else if (ip->version_ihl >> 4 == 6) {
			prox_rte_ipv6_hdr *ip6;
			ip6 = (prox_rte_ipv6_hdr *)(template->buf + template->l2_len);
			if (ip6->proto == IPPROTO_UDP) {
				prox_rte_udp_hdr *udp = (prox_rte_udp_hdr *)(ip6 + 1);
				udp->dgram_cksum = 0;
				udp->dgram_cksum = rte_ipv6_udptcp_cksum(ip6, udp);
			} else if (ip6->proto == IPPROTO_TCP) {
				prox_rte_tcp_hdr *tcp = (prox_rte_tcp_hdr *)(ip6 + 1);
				tcp->cksum = 0;
				tcp->cksum = rte_ipv6_udptcp_cksum(ip6, tcp);
			}
		}

		/* The current implementation avoids checksum
		   calculation by determining that at packet
		   construction time, no fields are applied that would
		   require a recalculation of the checksum. */
		if (task->lat_enabled && task->lat_pos > template->l2_len)
			task->runtime_checksum_needed = 1;
		if (task->accur_pos > template->l2_len)
			task->runtime_checksum_needed = 1;
		if (task->packet_id_pos > template->l2_len)
			task->runtime_checksum_needed = 1;
	}
}

static void task_gen_pkt_template_recalc_all(struct task_gen *task)
{
	task_gen_pkt_template_recalc_metadata(task);
	task_gen_pkt_template_recalc_checksum(task);
}

static void task_gen_set_pkt_templates_len(struct task_gen *task, uint32_t *pkt_sizes)
{
	struct pkt_template *src, *dst;

	for (size_t j = 0; j < task->n_pkts / task->orig_n_pkts; ++j) {
		for (size_t i = 0; i < task->orig_n_pkts; ++i) {
			dst = &task->pkt_template[j * task->orig_n_pkts + i];
			dst->len = pkt_sizes[j];
		}
	}
}

static void task_gen_reset_pkt_templates_len(struct task_gen *task)
{
	struct pkt_template *src, *dst;

	for (size_t j = 0; j < task->n_pkts / task->orig_n_pkts; ++j) {
		for (size_t i = 0; i < task->orig_n_pkts; ++i) {
			src = &task->pkt_template_orig[i];
			dst = &task->pkt_template[j * task->orig_n_pkts + i];
			dst->len = src->len;
		}
	}
}

static void task_gen_reset_pkt_templates_content(struct task_gen *task)
{
	struct pkt_template *src, *dst;

	for (size_t j = 0; j < task->n_pkts / task->orig_n_pkts; ++j) {
		for (size_t i = 0; i < task->orig_n_pkts; ++i) {
			src = &task->pkt_template_orig[i];
			dst = &task->pkt_template[j * task->orig_n_pkts + i];
			memcpy(dst->buf, src->buf, RTE_MAX(src->len, dst->len));
			if (task->flags & TASK_OVERWRITE_SRC_MAC_WITH_PORT_MAC) {
				rte_memcpy(&dst->buf[sizeof(prox_rte_ether_addr)], &task->src_mac, sizeof(prox_rte_ether_addr));
			}
			task_gen_apply_sig(task, dst);
		}
	}
}

static void task_gen_reset_pkt_templates(struct task_gen *task)
{
	task_gen_reset_pkt_templates_len(task);
	task_gen_reset_pkt_templates_content(task);
	task_gen_pkt_template_recalc_all(task);
}

static void task_init_gen_load_pkt_inline(struct task_gen *task, struct task_args *targ)
{
	int rc;

	task->orig_n_pkts = 1;
	if (task->imix_nb_pkts == 0) {
		task->n_pkts = 1;
		task->imix_pkt_sizes[0] = targ->pkt_size;
	} else {
		task->n_pkts = task->imix_nb_pkts;
	}
	task_gen_allocate_templates(task, task->orig_n_pkts, task->n_pkts, DO_PANIC, NOT_FROM_PCAP);

	rte_memcpy(task->pkt_template_orig[0].buf, targ->pkt_inline, task->max_frame_size);
	task->pkt_template_orig[0].len = task->imix_pkt_sizes[0];
	task_gen_reset_pkt_templates(task);
	check_all_pkt_size(task, DO_PANIC);
	check_all_fields_in_bounds(task, DO_PANIC);

	// If IMIX was not specified then pkt_size is specified using pkt_size parameter or the length of pkt_inline
	// In that case, for backward compatibility, we do NOT adapt the length of IP and UDP to the length of the packet
	task_gen_set_eth_ip_udp_sizes(task, task->orig_n_pkts, task->imix_nb_pkts, task->imix_pkt_sizes);
}

static void task_init_gen_load_pcap(struct task_gen *task, struct task_args *targ)
{
	char err[PCAP_ERRBUF_SIZE];
	uint32_t max_frame_size;
	pcap_t *handle = pcap_open_offline(targ->pcap_file, err);
	PROX_PANIC(handle == NULL, "Failed to open PCAP file: %s\n", err);

	task->orig_n_pkts = pcap_count_pkts(handle, &max_frame_size);
	plogx_info("%u packets in pcap file '%s'; max frame size=%d\n", task->orig_n_pkts, targ->pcap_file, max_frame_size);
	PROX_PANIC(max_frame_size > task->max_frame_size,
		max_frame_size > PROX_RTE_ETHER_MAX_LEN + 2 * PROX_VLAN_TAG_SIZE -4 ?
			"pkt_size too high and jumbo frames disabled" : "pkt_size > mtu");

	if (targ->n_pkts)
		task->orig_n_pkts = RTE_MIN(task->orig_n_pkts, targ->n_pkts);
	if (task->imix_nb_pkts == 0) {
		task->n_pkts = task->orig_n_pkts;
	} else {
		task->n_pkts = task->imix_nb_pkts * task->orig_n_pkts;
	}
	task_gen_allocate_templates(task, task->orig_n_pkts, task->n_pkts, DO_PANIC, FROM_PCAP);
	plogx_info("Loading %u packets from pcap\n", task->n_pkts);

	pcap_read_pkts(handle, targ->pcap_file, task->orig_n_pkts, task->pkt_template_orig, NULL, max_frame_size);
	pcap_close(handle);
	task_gen_reset_pkt_templates(task);
	check_all_pkt_size(task, DO_PANIC);
	check_all_fields_in_bounds(task, DO_PANIC);
	task_gen_set_eth_ip_udp_sizes(task, task->orig_n_pkts, task->imix_nb_pkts, task->imix_pkt_sizes);
}

static struct rte_mempool *task_gen_create_mempool(struct task_args *targ, uint16_t max_frame_size)
{
	static char name[] = "gen_pool";
	struct rte_mempool *ret;
	const int sock_id = rte_lcore_to_socket_id(targ->lconf->id);

	name[0]++;
	uint32_t mbuf_size = TX_MBUF_SIZE;
	if (max_frame_size + (unsigned)sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM > mbuf_size)
		mbuf_size = max_frame_size + (unsigned)sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM;
	plog_info("\tCreating mempool with name '%s'\n", name);
	ret = rte_mempool_create(name, targ->nb_mbuf - 1, mbuf_size,
				 targ->nb_cache_mbuf, sizeof(struct rte_pktmbuf_pool_private),
				 rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, 0,
				 sock_id, 0);
	PROX_PANIC(ret == NULL, "Failed to allocate dummy memory pool on socket %u with %u elements\n",
		   sock_id, targ->nb_mbuf - 1);

        plog_info("\tMempool %p size = %u * %u cache %u, socket %d\n", ret,
                  targ->nb_mbuf - 1, mbuf_size, targ->nb_cache_mbuf, sock_id);

	return ret;
}

void task_gen_set_pkt_count(struct task_base *tbase, uint32_t count)
{
	struct task_gen *task = (struct task_gen *)tbase;

	task->pkt_count = count;
}

int task_gen_set_pkt_size(struct task_base *tbase, uint32_t pkt_size)
{
	struct task_gen *task = (struct task_gen *)tbase;
	int rc;

	for (size_t i = 0; i < task->n_pkts; ++i) {
		if ((rc = check_pkt_size(task, pkt_size, 0)) != 0)
			return rc;
		if ((rc = check_fields_in_bounds(task, pkt_size, 0)) != 0)
			return rc;
	}
	for (size_t i = 0; i < task->n_pkts; ++i) {
		task->pkt_template[i].len = pkt_size;
	}
	return 0;
}

int task_gen_set_imix(struct task_base *tbase, uint32_t nb_pkt_sizes, uint32_t *pkt_sizes)
{
	struct task_gen *task = (struct task_gen *)tbase;
	int rc;

	memcpy(task->imix_pkt_sizes, pkt_sizes, nb_pkt_sizes * sizeof(uint32_t));
	for (size_t i = 0; i < nb_pkt_sizes; ++i) {
		if ((rc = check_pkt_size(task, pkt_sizes[i], DO_NOT_PANIC)) != 0)
			return rc;
		if ((rc = check_fields_in_bounds(task, pkt_sizes[i], DO_NOT_PANIC)) != 0)
			return rc;
	}
	// only set new_imix_nb_pkts if checks of pkt sizes succeeded
	task->new_imix_nb_pkts = nb_pkt_sizes;
	return 0;
}

void task_gen_set_rate(struct task_base *tbase, uint64_t bps)
{
	struct task_gen *task = (struct task_gen *)tbase;

	task->new_rate_bps = bps;
}

void task_gen_reset_randoms(struct task_base *tbase)
{
	struct task_gen *task = (struct task_gen *)tbase;

	for (uint32_t i = 0; i < task->n_rands; ++i) {
		task->rand[i].rand_mask = 0;
		task->rand[i].fixed_bits = 0;
		task->rand[i].rand_offset = 0;
	}
	task->n_rands = 0;
}

int task_gen_set_value(struct task_base *tbase, uint32_t value, uint32_t offset, uint32_t len)
{
	struct task_gen *task = (struct task_gen *)tbase;

	if (offset + len > task->max_frame_size)
		return -1;
	for (size_t i = 0; i < task->n_pkts; ++i) {
		uint32_t to_write = rte_cpu_to_be_32(value) >> ((4 - len) * 8);
		uint8_t *dst = task->pkt_template[i].buf;

		rte_memcpy(dst + offset, &to_write, len);
	}

	task_gen_pkt_template_recalc_all(task);

	return 0;
}

void task_gen_reset_values(struct task_base *tbase)
{
	struct task_gen *task = (struct task_gen *)tbase;

	task_gen_reset_pkt_templates_content(task);
	if (task->flags & TASK_OVERWRITE_SRC_MAC_WITH_PORT_MAC) {
		for (uint32_t i = 0; i < task->n_pkts; ++i) {
			rte_memcpy(&task->pkt_template[i].buf[sizeof(prox_rte_ether_addr)], &task->src_mac, sizeof(prox_rte_ether_addr));
		}
	}
}

uint32_t task_gen_get_n_randoms(struct task_base *tbase)
{
	struct task_gen *task = (struct task_gen *)tbase;

	return task->n_rands;
}

static void init_task_gen_pcap(struct task_base *tbase, struct task_args *targ)
{
	struct task_gen_pcap *task = (struct task_gen_pcap *)tbase;
	task->socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	uint32_t max_frame_size;

	task->loop = targ->loop;
	task->pkt_idx = 0;
	task->hz = rte_get_tsc_hz();

	char err[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_offline(targ->pcap_file, err);
	PROX_PANIC(handle == NULL, "Failed to open PCAP file: %s\n", err);

	task->n_pkts = pcap_count_pkts(handle, &max_frame_size);
	plogx_info("%u packets in pcap file '%s'\n", task->n_pkts, targ->pcap_file);

	task->local_mbuf.mempool = task_gen_create_mempool(targ, max_frame_size);

	PROX_PANIC(!strcmp(targ->pcap_file, ""), "No pcap file defined\n");

	if (targ->n_pkts) {
		plogx_info("Configured to load %u packets\n", targ->n_pkts);
		if (task->n_pkts > targ->n_pkts)
			task->n_pkts = targ->n_pkts;
	}
	plogx_info("Loading %u packets from pcap\n", task->n_pkts);

	size_t mem_size = task->n_pkts * (sizeof(*task->proto) + sizeof(*task->proto_tsc));
	uint8_t *mem = prox_zmalloc(mem_size, task->socket_id);

	PROX_PANIC(mem == NULL, "Failed to allocate %lu bytes (in huge pages) for pcap file\n", mem_size);
	task->proto = (struct pkt_template *) mem;
	task->proto_tsc = (uint64_t *)(mem + task->n_pkts * sizeof(*task->proto));

	for (uint i = 0; i < targ->n_pkts; i++) {
		task->proto[i].buf = prox_zmalloc(max_frame_size, task->socket_id);
		PROX_PANIC(task->proto[i].buf == NULL, "Failed to allocate %u bytes (in huge pages) for pcap file\n", max_frame_size);
	}

	pcap_read_pkts(handle, targ->pcap_file, task->n_pkts, task->proto, task->proto_tsc, max_frame_size);
	pcap_close(handle);
}

static int task_gen_find_random_with_offset(struct task_gen *task, uint32_t offset)
{
	for (uint32_t i = 0; i < task->n_rands; ++i) {
		if (task->rand[i].rand_offset == offset) {
			return i;
		}
	}

	return UINT32_MAX;
}

int task_gen_add_rand(struct task_base *tbase, const char *rand_str, uint32_t offset, uint32_t rand_id)
{
	struct task_gen *task = (struct task_gen *)tbase;
	uint32_t existing_rand;

	if (rand_id == UINT32_MAX && task->n_rands == 64) {
		plog_err("Too many randoms\n");
		return -1;
	}
	uint32_t mask, fixed, len;

	if (parse_random_str(&mask, &fixed, &len, rand_str)) {
		plog_err("%s\n", get_parse_err());
		return -1;
	}
	task->runtime_checksum_needed = 1;

	existing_rand = task_gen_find_random_with_offset(task, offset);
	if (existing_rand != UINT32_MAX) {
		plog_warn("Random at offset %d already set => overwriting len = %d %s\n", offset, len, rand_str);
		rand_id = existing_rand;
		task->rand[rand_id].rand_len = len;
		task->rand[rand_id].rand_offset = offset;
		task->rand[rand_id].rand_mask = mask;
		task->rand[rand_id].fixed_bits = fixed;
		return 0;
	}

	task->rand[task->n_rands].rand_len = len;
	task->rand[task->n_rands].rand_offset = offset;
	task->rand[task->n_rands].rand_mask = mask;
	task->rand[task->n_rands].fixed_bits = fixed;

	task->n_rands++;
	return 0;
}

static void start(struct task_base *tbase)
{
	struct task_gen *task = (struct task_gen *)tbase;
	task->pkt_queue_index = 0;

	task_gen_reset_token_time(task);
	if (tbase->l3.tmaster) {
		register_all_ip_to_ctrl_plane(task);
	}

	/* TODO
	   Handle the case when two tasks transmit to the same port
	   and one of them is stopped. In that case ARP (requests or replies)
	   might not be sent. Master will have to keep a list of rings.
	   stop will have to de-register IP from ctrl plane.
	   un-registration will remove the ring. when having more than
	   one active rings, master can always use the first one
	*/
}

static void start_pcap(struct task_base *tbase)
{
	struct task_gen_pcap *task = (struct task_gen_pcap *)tbase;
	/* When we start, the first packet is sent immediately. */
	task->last_tsc = rte_rdtsc() - task->proto_tsc[0];
	task->pkt_idx = 0;
}

static void init_task_gen_early(struct task_args *targ)
{
	uint8_t *generator_count = prox_sh_find_system("generator_count");

	if (generator_count == NULL) {
		generator_count = prox_zmalloc(sizeof(*generator_count), rte_lcore_to_socket_id(targ->lconf->id));
		PROX_PANIC(generator_count == NULL, "Failed to allocate generator count\n");
		prox_sh_add_system("generator_count", generator_count);
	}
	targ->generator_id = *generator_count;
	(*generator_count)++;
}

static void init_task_gen(struct task_base *tbase, struct task_args *targ)
{
	struct task_gen *task = (struct task_gen *)tbase;
	task->socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	task->packet_id_pos = targ->packet_id_pos;

	struct prox_port_cfg *port = find_reachable_port(targ);
	// TODO: check that all reachable ports have the same mtu...
	if (port) {
		task->cksum_offload = port->requested_tx_offload & (DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM);
		task->port = port;
		task->max_frame_size = port->mtu + PROX_RTE_ETHER_HDR_LEN + 2 * PROX_VLAN_TAG_SIZE;
	} else {
		// Not generating to any port...
		task->max_frame_size = PROX_RTE_ETHER_MAX_LEN;
	}
	task->local_mbuf.mempool = task_gen_create_mempool(targ, task->max_frame_size);
	PROX_PANIC(task->local_mbuf.mempool == NULL, "Failed to create mempool\n");
	task->pkt_idx = 0;
	task->hz = rte_get_tsc_hz();
	task->lat_pos = targ->lat_pos;
	task->accur_pos = targ->accur_pos;
	task->sig_pos = targ->sig_pos;
	task->sig = targ->sig;
	task->new_rate_bps = targ->rate_bps;

	/*
	 * For tokens, use 10 Gbps as base rate
	 * Scripts can then use speed command, with speed=100 as 10 Gbps and speed=400 as 40 Gbps
	 * Script can query prox "port info" command to find out the port link speed to know
	 * at which rate to start. Note that virtio running on OVS returns 10 Gbps, so a script has
	 * probably also to check the driver (as returned by the same "port info" command.
	 */
	struct token_time_cfg tt_cfg = token_time_cfg_create(1250000000, rte_get_tsc_hz(), -1);
	token_time_init(&task->token_time, &tt_cfg);

	init_task_gen_seeds(task);

	task->min_bulk_size = targ->min_bulk_size;
	task->max_bulk_size = targ->max_bulk_size;
	if (task->min_bulk_size < 1)
		task->min_bulk_size = 1;
	if (task->max_bulk_size < 1)
		task->max_bulk_size = 64;
	PROX_PANIC(task->max_bulk_size > 64, "max_bulk_size higher than 64\n");
	PROX_PANIC(task->max_bulk_size < task->min_bulk_size, "max_bulk_size must be > than min_bulk_size\n");

	task->pkt_count = -1;
	task->lat_enabled = targ->lat_enabled;
	task->runtime_flags = targ->runtime_flags;
	PROX_PANIC((task->lat_pos || task->accur_pos) && !task->lat_enabled, "lat not enabled by lat pos or accur pos configured\n");

	task->generator_id = targ->generator_id;
	plog_info("\tGenerator id = %d\n", task->generator_id);

	// Allocate array holding bytes to tsc for supported frame sizes
	task->bytes_to_tsc = prox_zmalloc(task->max_frame_size * MAX_PKT_BURST * sizeof(task->bytes_to_tsc[0]), task->socket_id);
	PROX_PANIC(task->bytes_to_tsc == NULL,
		"Failed to allocate %u bytes (in huge pages) for bytes_to_tsc\n", task->max_frame_size);

	// task->port->max_link_speed reports the maximum, non negotiated ink speed in Mbps e.g. 40k for a 40 Gbps NIC.
	// It can be UINT32_MAX (virtual devices or not supported by DPDK < 16.04)
	uint64_t bytes_per_hz = UINT64_MAX;
	if ((task->port) && (task->port->max_link_speed != UINT32_MAX)) {
		bytes_per_hz = task->port->max_link_speed * 125000L;
		plog_info("\tPort %u: max link speed is %ld Mbps\n",
			(uint8_t)(task->port - prox_port_cfg), 8 * bytes_per_hz / 1000000);
	}
	// There are cases where hz estimate might be slighly over-estimated
	// This results in too much extrapolation
	// Only account for 99% of extrapolation to handle cases with up to 1% error clocks
	for (unsigned int i = 0; i < task->max_frame_size * MAX_PKT_BURST ; i++) {
		if (bytes_per_hz == UINT64_MAX)
			task->bytes_to_tsc[i] = 0;
		else
			task->bytes_to_tsc[i] = (task->hz * i * 0.99) / bytes_per_hz;
	}

	task->imix_nb_pkts = targ->imix_nb_pkts;
	for (uint32_t i = 0; i < targ->imix_nb_pkts; i++) {
		task->imix_pkt_sizes[i] = targ->imix_pkt_sizes[i];
	}
	if (!strcmp(targ->pcap_file, "")) {
		plog_info("\tUsing inline definition of a packet\n");
		task_init_gen_load_pkt_inline(task, targ);
	} else {
		plog_info("Loading from pcap %s\n", targ->pcap_file);
		task_init_gen_load_pcap(task, targ);
	}

	PROX_PANIC(((targ->nb_txrings == 0) && (targ->nb_txports == 0)), "Gen mode requires a tx ring or a tx port");
	if ((targ->flags & DSF_KEEP_SRC_MAC) == 0) {
		task->flags |= TASK_OVERWRITE_SRC_MAC_WITH_PORT_MAC;
		memcpy(&task->src_mac, &prox_port_cfg[task->base.tx_params_hw.tx_port_queue->port].eth_addr, sizeof(prox_rte_ether_addr));
		for (uint32_t i = 0; i < task->n_pkts; ++i) {
			rte_memcpy(&task->pkt_template[i].buf[sizeof(prox_rte_ether_addr)], &task->src_mac, sizeof(prox_rte_ether_addr));
		}
	}
	for (uint32_t i = 0; i < targ->n_rand_str; ++i) {
		PROX_PANIC(task_gen_add_rand(tbase, targ->rand_str[i], targ->rand_offset[i], UINT32_MAX),
			   "Failed to add random\n");
	}
}

static struct task_init task_init_gen = {
	.mode_str = "gen",
	.init = init_task_gen,
	.handle = handle_gen_bulk,
	.start = start,
	.early_init = init_task_gen_early,
#ifdef SOFT_CRC
	// For SOFT_CRC, no offload is needed. If both NOOFFLOADS and NOMULTSEGS flags are set the
	// vector mode is used by DPDK, resulting (theoretically) in higher performance.
	.flag_features = TASK_FEATURE_NEVER_DISCARDS | TASK_FEATURE_NO_RX | TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS,
#else
	.flag_features = TASK_FEATURE_NEVER_DISCARDS | TASK_FEATURE_NO_RX,
#endif
	.size = sizeof(struct task_gen)
};

static struct task_init task_init_gen_l3 = {
	.mode_str = "gen",
	.sub_mode_str = "l3",
	.init = init_task_gen,
	.handle = handle_gen_bulk,
	.start = start,
	.early_init = init_task_gen_early,
#ifdef SOFT_CRC
	// For SOFT_CRC, no offload is needed. If both NOOFFLOADS and NOMULTSEGS flags are set the
	// vector mode is used by DPDK, resulting (theoretically) in higher performance.
	.flag_features = TASK_FEATURE_NEVER_DISCARDS | TASK_FEATURE_NO_RX | TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS,
#else
	.flag_features = TASK_FEATURE_NEVER_DISCARDS | TASK_FEATURE_NO_RX,
#endif
	.size = sizeof(struct task_gen)
};

/* This mode uses time stamps in the pcap file */
static struct task_init task_init_gen_pcap = {
	.mode_str = "gen",
	.sub_mode_str = "pcap",
	.init = init_task_gen_pcap,
	.handle = handle_gen_pcap_bulk,
	.start = start_pcap,
	.early_init = init_task_gen_early,
#ifdef SOFT_CRC
	.flag_features = TASK_FEATURE_NEVER_DISCARDS | TASK_FEATURE_NO_RX | TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS,
#else
	.flag_features = TASK_FEATURE_NEVER_DISCARDS | TASK_FEATURE_NO_RX,
#endif
	.size = sizeof(struct task_gen_pcap)
};

__attribute__((constructor)) static void reg_task_gen(void)
{
	reg_task(&task_init_gen);
	reg_task(&task_init_gen_l3);
	reg_task(&task_init_gen_pcap);
}
