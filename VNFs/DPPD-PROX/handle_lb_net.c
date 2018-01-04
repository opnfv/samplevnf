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

#include <string.h>

#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_table_hash.h>
#include <rte_byteorder.h>
#include <rte_version.h>

#include "prox_malloc.h"
#include "handle_lb_net.h"
#include "task_base.h"
#include "defines.h"
#include "tx_pkt.h"
#include "log.h"
#include "stats.h"
#include "mpls.h"
#include "etypes.h"
#include "gre.h"
#include "prefetch.h"
#include "qinq.h"
#include "hash_utils.h"
#include "quit.h"
#include "flow_iter.h"
#include "prox_compat.h"

#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE
#endif

struct task_lb_net {
	struct task_base      base;
	uint16_t              qinq_tag;
	uint8_t               bit_mask;
	uint8_t               nb_worker_threads;
	uint8_t               worker_byte_offset_ipv4;
	uint8_t               worker_byte_offset_ipv6;
	uint8_t               runtime_flags;
};

struct task_lb_net_lut {
	struct task_base      base;
	uint8_t               nb_worker_threads;
	uint8_t               runtime_flags;
	struct rte_table_hash *worker_hash_table;
	uint8_t               *worker_lut;
	uint32_t              keys[64];
	struct rte_mbuf       *fake_packets[64];
};

static inline uint8_t handle_lb_net(struct task_lb_net *task, struct rte_mbuf *mbuf);
static inline int extract_gre_key(struct task_lb_net_lut *task, uint32_t *key, struct rte_mbuf *mbuf);

static struct rte_table_hash *setup_gre_to_wt_lookup(struct task_args *targ, uint8_t n_workers, int socket_id)
{
	uint32_t gre_id, rss;
	void* entry_in_hash;
	int r, key_found = 0;
	struct rte_table_hash *ret;
	uint32_t count = 0;

	for (int i = 0; i < n_workers; ++i) {
		struct core_task ct = targ->core_task_set[0].core_task[i];
		struct task_args *t = core_targ_get(ct.core, ct.task);

		struct flow_iter *it = &t->task_init->flow_iter;

		PROX_PANIC(t->task_init->flow_iter.beg == NULL,
			   "Load distributor can't find flows owned by destination worker %d\n", i);

		for (it->beg(it, t); !it->is_end(it, t); it->next(it, t)) {
			count++;
		}
	}

	static char hash_name[30];
	sprintf(hash_name, "lb_hash_table_%03d", targ->lconf->id);

	// The key offset in the real packets might depend of the packet type; hence we need to extract the
	// keys and copy them.
	// The packets will be parsed runtime and keys will be created and stored in the metadata of fake mbufs.
	// Then hash functions will be used on the fake mbufs.
	// Keys are stored in (metadata of) fake mbufs to reduce the memory/cache usage: in this way we use only
	// 64  cache lines for all keys (we always use the same fake mbufs). If using metadata of real packets/mbufs,
	// we would use as many cache lines as there are mbufs, which might be very high in if QoS is supported for instance.
	//
	struct prox_rte_table_params table_hash_params = {
		.name = hash_name,
		.key_size = 4,
		.n_keys = count,
		.n_buckets = count,
		.f_hash = (rte_table_hash_op_hash)hash_crc32,
		.seed = 0,
		.key_offset = HASH_METADATA_OFFSET(0),
		.key_mask = NULL
	};

	ret = prox_rte_table_create(&table_hash_params, socket_id, sizeof(uint8_t));

	for (int i = 0; i < n_workers; ++i) {
		struct core_task ct = targ->core_task_set[0].core_task[i];
		struct task_args *t = core_targ_get(ct.core, ct.task);

		PROX_PANIC(t->task_init->flow_iter.beg == NULL,
			   "Load distributor can't find flows owned by destination worker %d\n", i);

		struct flow_iter *it = &t->task_init->flow_iter;

		for (it->beg(it, t); !it->is_end(it, t); it->next(it, t)) {
			uint32_t gre_id = it->get_gre_id(it, t);
			uint8_t dst = i;

			r = prox_rte_table_add(ret, &gre_id, &dst, &key_found, &entry_in_hash);
			if (r) {
				plog_err("Failed to add gre_id = %x, dest worker = %u\n", gre_id, i);
			}
			else {
				plog_dbg("Core %u added: gre_id %x, dest woker = %u\n", targ->lconf->id, gre_id, i);
			}
		}
	}
	return ret;
}

static uint8_t *setup_wt_indexed_table(struct task_args *targ, uint8_t n_workers, int socket_id)
{
	uint32_t gre_id, rss;
	uint32_t max_gre_id = 0;
	uint8_t queue;
	uint8_t *ret = NULL;
	void* entry_in_hash;
	int key_found = 0;

	for (int i = 0; i < n_workers; ++i) {
		struct core_task ct = targ->core_task_set[0].core_task[i];
		struct task_args *t = core_targ_get(ct.core, ct.task);

		struct flow_iter *it = &t->task_init->flow_iter;

		PROX_PANIC(t->task_init->flow_iter.beg == NULL,
			   "Load distributor can't find flows owned by destination worker %d\n", i);

		for (it->beg(it, t); !it->is_end(it, t); it->next(it, t)) {
			uint32_t gre_id = it->get_gre_id(it, t);
			if (gre_id > max_gre_id)
				max_gre_id = gre_id;
		}
	}

	PROX_PANIC(max_gre_id == 0, "Failed to get maximum GRE ID from workers");

	ret = prox_zmalloc(1 + max_gre_id, socket_id);
	PROX_PANIC(ret == NULL, "Failed to allocate worker_lut\n");

	for (int i = 0; i < n_workers; ++i) {
		struct core_task ct = targ->core_task_set[0].core_task[i];
		struct task_args *t = core_targ_get(ct.core, ct.task);

		PROX_PANIC(t->task_init->flow_iter.beg == NULL,
			   "Load distributor can't find flows owned by destination worker %d\n", i);

		struct flow_iter *it = &t->task_init->flow_iter;

		for (it->beg(it, t); !it->is_end(it, t); it->next(it, t)) {
			uint32_t gre_id = it->get_gre_id(it, t);
			uint8_t dst = i;

			ret[gre_id] = dst;
		}
	}
	return ret;
}

static void init_task_lb_net(struct task_base *tbase, struct task_args *targ)
{
	struct task_lb_net *task = (struct task_lb_net *)tbase;

	task->qinq_tag = targ->qinq_tag;
	task->runtime_flags = targ->runtime_flags;
	task->worker_byte_offset_ipv6 = 23;
	task->worker_byte_offset_ipv4 = 15;
	task->nb_worker_threads       = targ->nb_worker_threads;
	/* The optimal configuration is when the number of worker threads
	   is a power of 2. In that case, a bit_mask can be used. Setting
	   the bitmask to 0xff disables the "optimal" usage of bitmasks
	   and the actual number of worker threads will be used instead. */
	task->bit_mask = rte_is_power_of_2(targ->nb_worker_threads) ? targ->nb_worker_threads - 1 : 0xff;
}

static void init_task_lb_net_lut(struct task_base *tbase, struct task_args *targ)
{
	struct task_lb_net_lut *task = (struct task_lb_net_lut *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	task->runtime_flags = targ->runtime_flags;
	task->nb_worker_threads       = targ->nb_worker_threads;
	for (uint32_t i = 0; i < 64; ++i) {
		task->fake_packets[i] = (struct rte_mbuf*)((uint8_t*)&task->keys[i] - sizeof (struct rte_mbuf));
	}

	task->worker_hash_table = setup_gre_to_wt_lookup(targ, task->nb_worker_threads, socket_id);
}

static void init_task_lb_net_indexed_table(struct task_base *tbase, struct task_args *targ)
{
	struct task_lb_net_lut *task = (struct task_lb_net_lut *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	task->runtime_flags = targ->runtime_flags;
	task->nb_worker_threads       = targ->nb_worker_threads;

	task->worker_lut = setup_wt_indexed_table(targ, task->nb_worker_threads, socket_id);
}

static int handle_lb_net_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_lb_net *task = (struct task_lb_net *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint16_t j;

	prefetch_first(mbufs, n_pkts);

	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef PROX_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		out[j] = handle_lb_net(task, mbufs[j]);
	}
#ifdef PROX_PREFETCH_OFFSET
	PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));

	for (; j < n_pkts; ++j) {
		out[j] = handle_lb_net(task, mbufs[j]);
	}
#endif
	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static int handle_lb_net_lut_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_lb_net_lut *task = (struct task_lb_net_lut *)tbase;
	uint16_t not_dropped = 0;
	uint8_t out[MAX_PKT_BURST];
	// process packet, i.e. decide if the packet has to be dropped or not and where the packet has to go
	uint16_t j;
	prefetch_first(mbufs, n_pkts);

	uint64_t pkts_mask = RTE_LEN2MASK(n_pkts, uint64_t);
	uint8_t *wt[MAX_PKT_BURST];
	uint64_t lookup_hit_mask = 0;
	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef PROX_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		if (extract_gre_key(task, &task->keys[j], mbufs[j])) {
			// Packet will be dropped after lookup
			pkts_mask &= ~(1 << j);
			out[j] = OUT_DISCARD;
		}
	}
#ifdef PROX_PREFETCH_OFFSET
	PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		if (extract_gre_key(task, &task->keys[j], mbufs[j])) {
			pkts_mask &= ~(1 << j);
			out[j] = OUT_DISCARD;
			rte_prefetch0(RTE_MBUF_METADATA_UINT8_PTR(mbufs[j], 0));
		}
	}
#endif
	// keys have been extracted for all packets, now do the lookup
	prox_rte_table_lookup(task->worker_hash_table, task->fake_packets, pkts_mask, &lookup_hit_mask, (void**)wt);
	/* mbufs now contains the packets that have not been dropped */
	if (likely(lookup_hit_mask == RTE_LEN2MASK(n_pkts, uint64_t))) {
		for (j = 0; j < n_pkts; ++j) {
			out[j] = *wt[j];
		}
	}
	else {
		for (j = 0; j < n_pkts; ++j) {
			if (unlikely(!((lookup_hit_mask >> j) & 0x1))) {
				plog_warn("Packet %d keys %x can not be sent to worker thread => dropped\n", j, task->keys[j]);
				out[j] = OUT_DISCARD;
			}
			else {
				out[j] = *wt[j];
			}
		}
	}
	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static int handle_lb_net_indexed_table_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_lb_net_lut *task = (struct task_lb_net_lut *)tbase;
	uint8_t out[MAX_PKT_BURST];
	// process packet, i.e. decide if the packet has to be dropped or not and where the packet has to go
	uint16_t j;
	uint32_t gre_id;
	prefetch_first(mbufs, n_pkts);

	uint64_t pkts_mask = RTE_LEN2MASK(n_pkts, uint64_t);
	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef PROX_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		if (extract_gre_key(task, &gre_id, mbufs[j])) {
			// Packet will be dropped after lookup
			pkts_mask &= ~(1 << j);
			out[j] = OUT_DISCARD;
		} else {
			out[j] = task->worker_lut[rte_bswap32(gre_id)];
		}
	}
#ifdef PROX_PREFETCH_OFFSET
	PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		if (extract_gre_key(task, &gre_id, mbufs[j])) {
			pkts_mask &= ~(1 << j);
			out[j] = OUT_DISCARD;
		} else {
			out[j] = task->worker_lut[rte_bswap32(gre_id)];
		}
	}
#endif
	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static inline uint8_t worker_from_mask(struct task_lb_net *task, uint32_t val)
{
	if (task->bit_mask != 0xff) {
		return val & task->bit_mask;
	}
	else {
		return val % task->nb_worker_threads;
	}
}

static inline int extract_gre_key(struct task_lb_net_lut *task, uint32_t *key, struct rte_mbuf *mbuf)
{
	// For all packets, one by one, remove MPLS tag if any and fills in keys used by "fake" packets
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	// Check for MPLS TAG
	struct ipv4_hdr *ip;
	if (peth->ether_type == ETYPE_MPLSU) {
		struct mpls_hdr *mpls = (struct mpls_hdr *)(peth + 1);
		uint32_t mpls_len = 0;
		while (!(mpls->bytes & 0x00010000)) {
			mpls++;
			mpls_len += sizeof(struct mpls_hdr);
		}
		mpls_len += sizeof(struct mpls_hdr);
		ip = (struct ipv4_hdr *)(mpls + 1);
		switch (ip->version_ihl >> 4) {
		case 4:
			// Remove MPLS Tag if requested
			if (task->runtime_flags & TASK_MPLS_TAGGING) {
				peth = (struct ether_hdr *)rte_pktmbuf_adj(mbuf, mpls_len);
				peth->ether_type = ETYPE_IPv4;
			}
			break;
		case 6:
			plog_warn("IPv6 not supported in this mode\n");
			return 1;;
		default:
			plog_warn("Unexpected IP version %d\n", ip->version_ihl >> 4);
			return 1;
		}
	}
	else {
		ip = (struct ipv4_hdr *)(peth + 1);
	}
	// Entry point for the packet => check for packet validity
	// => do not use extract_key_core(mbufs[j], &task->keys[j]);
	//
	if (likely(ip->next_proto_id == IPPROTO_GRE)) {
		struct gre_hdr *pgre = (struct gre_hdr *)(ip + 1);
		if (likely(pgre->bits & GRE_KEY_PRESENT)) {
			uint32_t gre_id;
			if (pgre->bits & (GRE_CRC_PRESENT | GRE_ROUTING_PRESENT)) {
				// gre_id = *((uint32_t *)((uint8_t *)pgre + 8));
				*key = *(uint32_t *)((uint8_t *)pgre + 8);
			}
			else {
				// gre_id = *((uint32_t *)((uint8_t *)pgre + 4));
				*key = *(uint32_t *)((uint8_t *)pgre + 4);
			}
		}
		else {
			plog_warn("Key not present\n");
			return 1;
		}
	}
	else {
		plog_warn("Invalid protocol: GRE was expected, got 0x%x\n", ip->next_proto_id);
		return 1;
	}
	return 0;
}

static inline uint8_t lb_ip4(struct task_lb_net *task, struct ipv4_hdr *ip)
{
	if (unlikely(ip->version_ihl >> 4 != 4)) {
		plog_warn("Expected to receive IPv4 packet but IP version was %d\n",
			ip->version_ihl >> 4);
		return OUT_DISCARD;
	}

	if (ip->next_proto_id == IPPROTO_GRE) {
		struct gre_hdr *pgre = (struct gre_hdr *)(ip + 1);

		if (pgre->bits & GRE_KEY_PRESENT) {
			uint32_t gre_id;
			if (pgre->bits & (GRE_CRC_PRESENT | GRE_ROUTING_PRESENT)) {
				gre_id = *((uint32_t *)((uint8_t *)pgre + 8));
			}
			else {
				gre_id = *((uint32_t *)((uint8_t *)pgre + 4));
			}

			gre_id = rte_be_to_cpu_32(gre_id) & 0xFFFFFFF;
			uint8_t worker = worker_from_mask(task, gre_id);
			plogx_dbg("gre_id = %u worker = %u\n", gre_id, worker);
			return worker + task->nb_worker_threads * IPV4;
		}
		else {
			plog_warn("Key not present\n");
			return OUT_DISCARD;
		}
	}
	else if (ip->next_proto_id == IPPROTO_UDP) {
		uint8_t worker = worker_from_mask(task, rte_bswap32(ip->dst_addr));
		return worker + task->nb_worker_threads * IPV4;
	}
	return OUT_DISCARD;
}

static inline uint8_t lb_ip6(struct task_lb_net *task, struct ipv6_hdr *ip)
{
	if (unlikely((*(uint8_t*)ip) >> 4 != 6)) {
		plog_warn("Expected to receive IPv6 packet but IP version was %d\n",
			*(uint8_t*)ip >> 4);
		return OUT_DISCARD;
	}

	uint8_t worker = worker_from_mask(task, *((uint8_t *)ip + task->worker_byte_offset_ipv6));
	return worker + task->nb_worker_threads * IPV6;
}

static inline uint8_t lb_mpls(struct task_lb_net *task, struct ether_hdr *peth, struct rte_mbuf *mbuf)
{
	struct mpls_hdr *mpls = (struct mpls_hdr *)(peth + 1);
	uint32_t mpls_len = 0;
	while (!(mpls->bytes & 0x00010000)) {
		mpls++;
		mpls_len += sizeof(struct mpls_hdr);
	}
	mpls_len += sizeof(struct mpls_hdr);
	struct ipv4_hdr *ip = (struct ipv4_hdr *)(mpls + 1);

	switch (ip->version_ihl >> 4) {
	case 4:
		if (task->runtime_flags & TASK_MPLS_TAGGING) {
			peth = (struct ether_hdr *)rte_pktmbuf_adj(mbuf, mpls_len);
			peth->ether_type = ETYPE_IPv4;
		}
		return lb_ip4(task, ip);
	case 6:
		if (task->runtime_flags & TASK_MPLS_TAGGING) {
			peth = (struct ether_hdr *)rte_pktmbuf_adj(mbuf, mpls_len);
			peth->ether_type = ETYPE_IPv6;
		}
		return lb_ip6(task, (struct ipv6_hdr *)ip);
	default:
		plogd_warn(mbuf, "Failed Decoding MPLS Packet - neither IPv4 neither IPv6: version %u for packet : \n", ip->version_ihl);
		return OUT_DISCARD;
	}
}

static inline uint8_t lb_qinq(struct task_lb_net *task, struct qinq_hdr *qinq)
{
	if (qinq->cvlan.eth_proto != ETYPE_VLAN) {
		plog_warn("Unexpected proto in QinQ = %#04x\n", qinq->cvlan.eth_proto);
		return OUT_DISCARD;
	}
	uint32_t qinq_tags = rte_bswap16(qinq->cvlan.vlan_tci & 0xFF0F);
	return worker_from_mask(task, qinq_tags);
}

static inline uint8_t handle_lb_net(struct task_lb_net *task, struct rte_mbuf *mbuf)
{
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	const uint16_t len = rte_pktmbuf_pkt_len(mbuf);
	if (len < 60) {
		plogd_warn(mbuf, "Unexpected frame len = %d for packet : \n", len);
		return OUT_DISCARD;
	}

	switch (peth->ether_type) {
	case ETYPE_MPLSU:
		return lb_mpls(task, peth, mbuf);
	case ETYPE_8021ad:
		return lb_qinq(task, (struct qinq_hdr *)peth);
	case ETYPE_IPv4:
		return lb_ip4(task, (struct ipv4_hdr *)(peth + 1));
	case ETYPE_IPv6:
		return lb_ip6(task, (struct ipv6_hdr *)(peth + 1));
	case ETYPE_LLDP:
		return OUT_DISCARD;
	default:
		if (peth->ether_type == task->qinq_tag)
			return lb_qinq(task, (struct qinq_hdr *)peth);
		plogd_warn(mbuf, "Unexpected frame Ether type = %#06x for packet : \n", peth->ether_type);
		return OUT_DISCARD;
	}

	return 1;
}

static struct task_init task_init_lb_net = {
	.mode_str = "lbnetwork",
	.init = init_task_lb_net,
	.handle = handle_lb_net_bulk,
	.size = sizeof(struct task_lb_net),
	.flag_features = TASK_FEATURE_GRE_ID
};

static struct task_init task_init_lb_net_lut_qinq_rss = {
	.mode_str = "lbnetwork",
	.sub_mode_str = "lut_qinq_rss",
	.init = init_task_lb_net_lut,
	.handle = handle_lb_net_lut_bulk,
	.size = sizeof(struct task_lb_net_lut),
	.flag_features = TASK_FEATURE_LUT_QINQ_RSS
};

static struct task_init task_init_lb_net_lut_qinq_hash = {
	.mode_str = "lbnetwork",
	.sub_mode_str = "lut_qinq_hash",
	.init = init_task_lb_net_lut,
	.handle = handle_lb_net_lut_bulk,
	.size = sizeof(struct task_lb_net_lut),
	.flag_features = TASK_FEATURE_LUT_QINQ_HASH
};

static struct task_init task_init_lb_net_indexed_table_rss = {
	.mode_str = "lbnetwork",
	.sub_mode_str = "indexed_table_rss",
	.init = init_task_lb_net_indexed_table,
	.handle = handle_lb_net_indexed_table_bulk,
	.size = sizeof(struct task_lb_net_lut),
	.flag_features = TASK_FEATURE_LUT_QINQ_RSS
};

static struct task_init task_init_lb_net_indexed_table_hash = {
	.mode_str = "lbnetwork",
	.sub_mode_str = "indexed_table_hash",
	.init = init_task_lb_net_indexed_table,
	.handle = handle_lb_net_indexed_table_bulk,
	.size = sizeof(struct task_lb_net_lut),
	.flag_features = TASK_FEATURE_LUT_QINQ_HASH
};

__attribute__((constructor)) static void reg_task_lb_net(void)
{
	reg_task(&task_init_lb_net);
	reg_task(&task_init_lb_net_lut_qinq_rss);
	reg_task(&task_init_lb_net_lut_qinq_hash);
	reg_task(&task_init_lb_net_indexed_table_rss);
	reg_task(&task_init_lb_net_indexed_table_hash);
}
