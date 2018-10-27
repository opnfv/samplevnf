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

#include <rte_table_hash.h>
#include <rte_hash_crc.h>
#include <rte_cycles.h>

#include "mbuf_utils.h"
#include "prox_malloc.h"
#include "prox_lua.h"
#include "prox_lua_types.h"
#include "handle_qinq_encap4.h"
#include "handle_qinq_decap4.h"
#include "prox_args.h"
#include "defines.h"
#include "tx_pkt.h"
#include "prefetch.h"
#include "pkt_prototypes.h"
#include "hash_entry_types.h"
#include "task_init.h"
#include "bng_pkts.h"
#include "prox_cksum.h"
#include "hash_utils.h"
#include "quit.h"
#include "prox_port_cfg.h"
#include "handle_lb_net.h"
#include "prox_cfg.h"
#include "cfgfile.h"
#include "toeplitz.h"
#include "prox_shared.h"
#include "prox_compat.h"

static struct cpe_table_data *read_cpe_table_config(const char *name, uint8_t socket)
{
	struct lua_State *L = prox_lua();
	struct cpe_table_data *ret = NULL;

	lua_getglobal(L, name);
	PROX_PANIC(lua_isnil(L, -1), "Coudn't find cpe_table data\n");

	return ret;
}

struct qinq_gre_map *get_qinq_gre_map(struct task_args *targ)
{
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	struct qinq_gre_map *ret = prox_sh_find_socket(socket_id, "qinq_gre_map");

	if (!ret) {
		PROX_PANIC(!strcmp(targ->user_table, ""), "No user table defined\n");
		int rv = lua_to_qinq_gre_map(prox_lua(), GLOBAL, targ->user_table, socket_id, &ret);
		PROX_PANIC(rv, "Error reading mapping between qinq and gre from qinq_gre_map: \n%s\n",
			   get_lua_to_errors());
		prox_sh_add_socket(socket_id, "qinq_gre_map", ret);
	}
	return ret;
}

/* Encapsulate IPv4 packets in QinQ. QinQ tags are derived from gre_id. */
int handle_qinq_encap4_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts);
static void arp_msg(struct task_base *tbase, void **data, uint16_t n_msgs);

static void fill_table(struct task_args *targ, struct rte_table_hash *table)
{
	struct cpe_table_data *cpe_table_data;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	int ret = lua_to_cpe_table_data(prox_lua(), GLOBAL, targ->cpe_table_name, socket_id, &cpe_table_data);
	const uint8_t n_slaves = targ->nb_slave_threads;
	const uint8_t worker_id = targ->worker_thread_id;

	for (uint32_t i = 0; i < cpe_table_data->n_entries; ++i) {
		if (rte_bswap32(cpe_table_data->entries[i].ip) % n_slaves != worker_id) {
			continue;
		}
		struct cpe_table_entry *entry = &cpe_table_data->entries[i];

		uint32_t port_idx = prox_cfg.cpe_table_ports[entry->port_idx];
		PROX_PANIC(targ->mapping[port_idx] == 255, "Error reading cpe table: Mapping for port %d is missing", port_idx);

		struct cpe_key key = {
			.ip = entry->ip,
			.gre_id = entry->gre_id,
		};

		struct cpe_data data = {
			.qinq_svlan = entry->svlan,
			.qinq_cvlan = entry->cvlan,
			.user = entry->user,
			.mac_port = {
				.mac = entry->eth_addr,
				.out_idx = targ->mapping[port_idx],
			},
			.tsc = UINT64_MAX,
		};

		int key_found;
		void* entry_in_hash;
		prox_rte_table_key8_add(table, &key, &data, &key_found, &entry_in_hash);
	}
}

static void init_task_qinq_encap4(struct task_base *tbase, struct task_args *targ)
{
	struct task_qinq_encap4 *task = (struct task_qinq_encap4 *)(tbase);
	int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	task->qinq_tag = targ->qinq_tag;
	task->cpe_table = targ->cpe_table;
	task->cpe_timeout = msec_to_tsc(targ->cpe_table_timeout_ms);

	if (!strcmp(targ->task_init->sub_mode_str, "pe")) {
		PROX_PANIC(!strcmp(targ->cpe_table_name, ""), "CPE table not configured\n");
		fill_table(targ, task->cpe_table);
	}

#ifdef ENABLE_EXTRA_USER_STATISTICS
	task->n_users = targ->n_users;
	task->stats_per_user = prox_zmalloc(targ->n_users * sizeof(uint32_t), socket_id);
#endif
	if (targ->runtime_flags & TASK_CLASSIFY) {
		PROX_PANIC(!strcmp(targ->dscp, ""), "DSCP table not specified\n");
		task->dscp = prox_sh_find_socket(socket_id, targ->dscp);
		if (!task->dscp) {
			int ret = lua_to_dscp(prox_lua(), GLOBAL, targ->dscp, socket_id, &task->dscp);
			PROX_PANIC(ret, "Failed to create dscp table from config:\n%s\n",
				   get_lua_to_errors());
			prox_sh_add_socket(socket_id, targ->dscp, task->dscp);
		}
	}

	task->runtime_flags = targ->runtime_flags;

	for (uint32_t i = 0; i < 64; ++i) {
		task->fake_packets[i] = (struct rte_mbuf*)((uint8_t*)&task->keys[i] - sizeof (struct rte_mbuf));
	}

	targ->lconf->ctrl_timeout = freq_to_tsc(targ->ctrl_freq);
	targ->lconf->ctrl_func_m[targ->task] = arp_msg;

	struct prox_port_cfg *port = find_reachable_port(targ);
	if (port) {
		task->offload_crc = port->requested_tx_offload & (DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM);
	}

	/* TODO: check if it is not necessary to limit reverse mapping
	   for the elements that have been changing in mapping? */

	for (uint32_t i =0 ; i < sizeof(targ->mapping)/sizeof(targ->mapping[0]); ++i) {
		task->src_mac[targ->mapping[i]] = *(uint64_t*)&prox_port_cfg[i].eth_addr;
	}

	/* task->src_mac[entry->port_idx] = *(uint64_t*)&prox_port_cfg[entry->port_idx].eth_addr; */
}

static void arp_msg(struct task_base *tbase, void **data, uint16_t n_msgs)
{
	struct task_qinq_encap4 *task = (struct task_qinq_encap4 *)tbase;
	struct arp_msg **msgs = (struct arp_msg **)data;

	arp_update_from_msg(task->cpe_table, msgs, n_msgs, task->cpe_timeout);
}

static inline void add_key(struct task_args *targ, struct qinq_gre_map *qinq_gre_map, struct rte_table_hash* qinq_gre_table, uint32_t i, uint32_t *count)
{
	struct qinq_gre_data entry = {
		.gre_id = qinq_gre_map->entries[i].gre_id,
		.user = qinq_gre_map->entries[i].user,
	};

#ifdef USE_QINQ
	struct vlans qinq2 = {
		.svlan = {.eth_proto = targ->qinq_tag, .vlan_tci = qinq_gre_map->entries[i].svlan},
		.cvlan = {.eth_proto = ETYPE_VLAN,     .vlan_tci = qinq_gre_map->entries[i].cvlan}
	};

	int key_found = 0;
	void* entry_in_hash = NULL;
	prox_rte_table_key8_add(qinq_gre_table, &qinq2, &entry, &key_found, &entry_in_hash);

	plog_dbg("Core %u adding user %u (tag %x svlan %x cvlan %x), rss=%x\n",
		 targ->lconf->id, qinq_gre_map->entries[i].user, qinq2.svlan.eth_proto,
		 rte_bswap16(qinq_gre_map->entries[i].svlan),
		 rte_bswap16(qinq_gre_map->entries[i].cvlan),
		 qinq_gre_map->entries[i].rss);
#else
	/* lower 3 bytes of IPv4 address contain svlan/cvlan. */
	uint64_t ip = ((uint32_t)rte_bswap16(qinq_gre_map->entries[i].svlan) << 12) |
		rte_bswap16(qinq_gre_map->entries[i].cvlan);
	int key_found = 0;
	void* entry_in_hash = NULL;
	prox_rte_table_key8_add(qinq_gre_table, &ip, &entry, &key_found, &entry_in_hash);

	plog_dbg("Core %u hash table add: key = %016"PRIx64"\n",
		 targ->lconf->id, ip);
#endif
	(*count)++;
}

void init_qinq_gre_table(struct task_args *targ, struct qinq_gre_map *qinq_gre_map)
{
	struct rte_table_hash* qinq_gre_table;
	uint8_t table_part = targ->nb_slave_threads;
	if (!rte_is_power_of_2(table_part)) {
		table_part = rte_align32pow2(table_part) >> 1;
	}

	if (table_part == 0)
		table_part = 1;

	uint32_t n_entries = MAX_GRE / table_part;
	static char hash_name[30];
	sprintf(hash_name, "qinq_gre_hash_table_%03d", targ->lconf->id);

	struct prox_rte_table_params table_hash_params = {
		.name = hash_name,
		.key_size = 8,
		.n_keys = n_entries,
		.n_buckets = n_entries,
		.f_hash = (rte_table_hash_op_hash)hash_crc32,
		.seed = 0,
		.key_offset = HASH_METADATA_OFFSET(0),
		.key_mask = NULL
	};

	qinq_gre_table = prox_rte_table_create(&table_hash_params, rte_lcore_to_socket_id(targ->lconf->id), sizeof(struct qinq_gre_data));

	// LB configuration known from Network Load Balancer
	// Find LB network Load balancer, i.e. ENCAP friend.
	for (uint8_t task_id = 0; task_id < targ->lconf->n_tasks_all; ++task_id) {
		enum task_mode smode = targ->lconf->targs[task_id].mode;
		if (QINQ_ENCAP4 == smode) {
			targ->lb_friend_core =  targ->lconf->targs[task_id].lb_friend_core;
			targ->lb_friend_task =  targ->lconf->targs[task_id].lb_friend_task;
		}
	}
	// Packet coming from Load balancer. LB could balance on gre_id LSB, qinq hash or qinq RSS
	uint32_t flag_features = 0;
	if (targ->lb_friend_core != 0xFF) {
		struct task_args *lb_targ = &lcore_cfg[targ->lb_friend_core].targs[targ->lb_friend_task];
		flag_features = lb_targ->task_init->flag_features;
		plog_info("\t\tWT %d Updated features to %x from friend %d\n", targ->lconf->id, flag_features, targ->lb_friend_core);
	} else {
		plog_info("\t\tWT %d has no friend\n", targ->lconf->id);
	}
	if (targ->nb_slave_threads == 0)  {
		// No slave threads, i.e. using RSS
		plog_info("feature was %x is now %x\n", flag_features, TASK_FEATURE_LUT_QINQ_RSS);
		flag_features = TASK_FEATURE_LUT_QINQ_RSS;
	}
	if ((flag_features & (TASK_FEATURE_GRE_ID|TASK_FEATURE_LUT_QINQ_RSS|TASK_FEATURE_LUT_QINQ_HASH)) == 0) {
		plog_info("\t\tCould not find flag feature from Load balancer => supposing TASK_FEATURE_GRE_ID\n");
		flag_features = TASK_FEATURE_GRE_ID;
	}

	/* Only store QinQ <-> GRE mapping for packets that are handled by this worker thread */
	uint32_t count = 0;
	if (flag_features & TASK_FEATURE_LUT_QINQ_RSS) {
		// If there is a load balancer, number of worker thread is indicated by targ->nb_slave_threads and n_rxq = 0
		// If there is no load balancers, number of worker thread is indicated by n_rxq and nb_slave_threads = 0
		uint8_t nb_worker_threads, worker_thread_id;
		if (targ->nb_slave_threads) {
			nb_worker_threads = targ->nb_slave_threads;
			worker_thread_id = targ->worker_thread_id;
		} else if (prox_port_cfg[targ->rx_port_queue[0].port].n_rxq) {
			nb_worker_threads = prox_port_cfg[targ->rx_port_queue[0].port].n_rxq;
			worker_thread_id = targ->rx_port_queue[0].queue;
		} else {
			PROX_PANIC(1, "Unexpected: unknown number of worker thread\n");
		}
		plog_info("\t\tUsing %d worker_threads id %d\n", nb_worker_threads, worker_thread_id);
		for (uint32_t i = 0; i < qinq_gre_map->count; ++i) {
			if (targ->nb_slave_threads == 0 || rss_to_queue(qinq_gre_map->entries[i].rss, nb_worker_threads) == worker_thread_id) {
				add_key(targ, qinq_gre_map, qinq_gre_table, i, &count);
				//plog_info("Queue %d adding key %16lx, svlan %x cvlan %x, rss=%x\n", targ->rx_queue, *(uint64_t *)q, qinq_to_gre_lookup[i].svlan,  qinq_to_gre_lookup[i].cvlan, qinq_to_gre_lookup[i].rss);
			}
		}
		plog_info("\t\tAdded %d entries to worker thread %d\n", count,  worker_thread_id);
	} else if (flag_features & TASK_FEATURE_LUT_QINQ_HASH) {
		for (uint32_t i = 0; i < qinq_gre_map->count; ++i) {
			uint64_t cvlan = rte_bswap16(qinq_gre_map->entries[i].cvlan & 0xFF0F);
			uint64_t svlan = rte_bswap16((qinq_gre_map->entries[i].svlan & 0xFF0F));
			uint64_t qinq = rte_bswap64((svlan << 32) | cvlan);
			uint8_t queue = rte_hash_crc(&qinq, 8, 0) % targ->nb_slave_threads;
			if (queue == targ->worker_thread_id) {
				add_key(targ, qinq_gre_map, qinq_gre_table, i, &count);
			}
		}
		plog_info("\t\tAdded %d entries to WT %d\n", count,  targ->worker_thread_id);
	} else if (flag_features & TASK_FEATURE_GRE_ID) {
		for (uint32_t i = 0; i < qinq_gre_map->count; ++i) {
			if (qinq_gre_map->entries[i].gre_id % targ->nb_slave_threads == targ->worker_thread_id) {
				add_key(targ, qinq_gre_map, qinq_gre_table, i, &count);
			}
		}
	}

	for (uint8_t task_id = 0; task_id < targ->lconf->n_tasks_all; ++task_id) {
		enum task_mode smode = targ->lconf->targs[task_id].mode;
		if (QINQ_DECAP4 == smode) {
			targ->lconf->targs[task_id].qinq_gre_table = qinq_gre_table;
		}

	}
}

void init_cpe4_table(struct task_args *targ)
{
	char name[64];
	sprintf(name, "core_%u_CPEv4Table", targ->lconf->id);

	uint8_t table_part = targ->nb_slave_threads;
	if (!rte_is_power_of_2(table_part)) {
		table_part = rte_align32pow2(table_part) >> 1;
	}

	if (table_part == 0)
		table_part = 1;

	uint32_t n_entries = MAX_GRE / table_part;

	static char hash_name[30];
	sprintf(hash_name, "cpe4_table_%03d", targ->lconf->id);

	struct prox_rte_table_params table_hash_params = {
		.name = hash_name,
		.key_size = 8,
		.n_keys = n_entries,
		.n_buckets = n_entries >> 1,
		.f_hash = (rte_table_hash_op_hash)hash_crc32,
		.seed = 0,
		.key_offset = HASH_METADATA_OFFSET(0),
		.key_mask = NULL
	};
	size_t entry_size = sizeof(struct cpe_data);
	if (!rte_is_power_of_2(entry_size)) {
		entry_size = rte_align32pow2(entry_size);
	}

	struct rte_table_hash* phash = prox_rte_table_create(&table_hash_params, rte_lcore_to_socket_id(targ->lconf->id), entry_size);
	PROX_PANIC(NULL == phash, "Unable to allocate memory for IPv4 hash table on core %u\n", targ->lconf->id);

	/* for locality, copy the pointer to the port structure where it is needed at packet handling time */
	for (uint8_t task_id = 0; task_id < targ->lconf->n_tasks_all; ++task_id) {
		enum task_mode smode = targ->lconf->targs[task_id].mode;
		if (QINQ_ENCAP4 == smode || QINQ_DECAP4 == smode) {
			targ->lconf->targs[task_id].cpe_table = phash;
		}
	}
}

static void early_init_table(struct task_args* targ)
{
	if (!targ->cpe_table) {
		init_cpe4_table(targ);
	}
}

static inline void restore_cpe(struct cpe_pkt *packet, struct cpe_data *table, __attribute__((unused)) uint16_t qinq_tag, uint64_t *src_mac)
{
#ifdef USE_QINQ
        struct qinq_hdr *pqinq = &packet->qinq_hdr;
	rte_memcpy(pqinq, &qinq_proto, sizeof(struct qinq_hdr));
	(*(uint64_t *)(&pqinq->d_addr)) = table->mac_port_8bytes;
	/* set source as well now */
	*((uint64_t *)(&pqinq->s_addr)) = *((uint64_t *)&src_mac[table->mac_port.out_idx]);
	pqinq->svlan.vlan_tci = table->qinq_svlan;
	pqinq->cvlan.vlan_tci = table->qinq_cvlan;
	pqinq->svlan.eth_proto = qinq_tag;
	pqinq->cvlan.eth_proto = ETYPE_VLAN;
	pqinq->ether_type = ETYPE_IPv4;
#else
	(*(uint64_t *)(&packet->ether_hdr.d_addr)) = table->mac_port_8bytes;
	/* set source as well now */
	*((uint64_t *)(&packet->ether_hdr.s_addr)) = *((uint64_t *)&src_mac[table->mac_port.out_idx]);
	packet->ether_hdr.ether_type = ETYPE_IPv4;

	packet->ipv4_hdr.dst_addr = rte_bswap32(10 << 24 | rte_bswap16(table->qinq_svlan) << 12 | rte_bswap16(table->qinq_cvlan));
#endif
}

static inline uint8_t handle_qinq_encap4(struct task_qinq_encap4 *task, struct cpe_pkt *cpe_pkt, struct rte_mbuf *mbuf, struct cpe_data *entry);

/* Same functionality as handle_qinq_encap_v4_bulk but untag MPLS as well. */
static int handle_qinq_encap4_untag_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_qinq_encap4 *task = (struct task_qinq_encap4 *)tbase;
	uint8_t out[MAX_PKT_BURST];
	prefetch_pkts(mbufs, n_pkts);

	for (uint16_t j = 0; j < n_pkts; ++j) {
		if (likely(mpls_untag(mbufs[j]))) {
			struct cpe_pkt* cpe_pkt = (struct cpe_pkt*) rte_pktmbuf_adj(mbufs[j], UPSTREAM_DELTA);
			out[j] = handle_qinq_encap4(task, cpe_pkt, mbufs[j], NULL);
		}
		else {
			out[j] = OUT_DISCARD;
		}
	}

	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static inline void extract_key_bulk(struct task_qinq_encap4 *task, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	for (uint16_t j = 0; j < n_pkts; ++j) {
		extract_key_core(mbufs[j], &task->keys[j]);
	}
}

__attribute__((cold)) static void handle_error(struct rte_mbuf *mbuf)
{
	struct core_net_pkt* core_pkt = rte_pktmbuf_mtod(mbuf, struct core_net_pkt *);
	uint32_t dst_ip = core_pkt->ip_hdr.dst_addr;
	uint32_t le_gre_id = rte_be_to_cpu_32(core_pkt->gre_hdr.gre_id);

	plogx_dbg("Unknown IP %x/gre_id %x\n", dst_ip, le_gre_id);
}

static int handle_qinq_encap4_bulk_pe(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_qinq_encap4 *task = (struct task_qinq_encap4 *)tbase;
	uint64_t pkts_mask = RTE_LEN2MASK(n_pkts, uint64_t);
	struct cpe_data* entries[64];
	uint8_t out[MAX_PKT_BURST];
	uint64_t lookup_hit_mask;

	prefetch_pkts(mbufs, n_pkts);

	for (uint16_t j = 0; j < n_pkts; ++j) {
		struct ipv4_hdr* ip = (struct ipv4_hdr *)(rte_pktmbuf_mtod(mbufs[j], struct ether_hdr *) + 1);
		task->keys[j] = (uint64_t)ip->dst_addr;
	}
	prox_rte_table_key8_lookup(task->cpe_table, task->fake_packets, pkts_mask, &lookup_hit_mask, (void**)entries);

	if (likely(lookup_hit_mask == pkts_mask)) {
		for (uint16_t j = 0; j < n_pkts; ++j) {
			struct cpe_pkt* cpe_pkt = (struct cpe_pkt*) rte_pktmbuf_prepend(mbufs[j], sizeof(struct qinq_hdr) - sizeof(struct ether_hdr));
			uint16_t padlen = mbuf_calc_padlen(mbufs[j], cpe_pkt, &cpe_pkt->ipv4_hdr);

			if (padlen) {
				rte_pktmbuf_trim(mbufs[j], padlen);
			}
			out[j] = handle_qinq_encap4(task, cpe_pkt, mbufs[j], entries[j]);
		}
	}
	else {
		for (uint16_t j = 0; j < n_pkts; ++j) {
			if (unlikely(!((lookup_hit_mask >> j) & 0x1))) {
				handle_error(mbufs[j]);
				out[j] = OUT_DISCARD;
				continue;
			}
			struct cpe_pkt* cpe_pkt = (struct cpe_pkt*) rte_pktmbuf_prepend(mbufs[j], sizeof(struct qinq_hdr) - sizeof(struct ether_hdr));
			uint16_t padlen = mbuf_calc_padlen(mbufs[j], cpe_pkt, &cpe_pkt->ipv4_hdr);

			if (padlen) {
				rte_pktmbuf_trim(mbufs[j], padlen);
			}
			out[j] = handle_qinq_encap4(task, cpe_pkt, mbufs[j], entries[j]);
		}
	}

	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}
int handle_qinq_encap4_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_qinq_encap4 *task = (struct task_qinq_encap4 *)tbase;
	uint64_t pkts_mask = RTE_LEN2MASK(n_pkts, uint64_t);
	struct cpe_data* entries[64];
	uint8_t out[MAX_PKT_BURST];
	uint64_t lookup_hit_mask;

	prefetch_pkts(mbufs, n_pkts);

	// From GRE ID and IP address, retrieve QinQ and MAC addresses
	extract_key_bulk(task, mbufs, n_pkts);
	prox_rte_table_key8_lookup(task->cpe_table, task->fake_packets, pkts_mask, &lookup_hit_mask, (void**)entries);

	if (likely(lookup_hit_mask == pkts_mask)) {
		for (uint16_t j = 0; j < n_pkts; ++j) {
			struct cpe_pkt* cpe_pkt = (struct cpe_pkt*) rte_pktmbuf_adj(mbufs[j], UPSTREAM_DELTA);
			// We are receiving GRE tunnelled packets (and removing UPSTRAM_DELTA bytes), whose length is > 64 bytes
			// So there should be no padding, but in case the is one, remove it
			uint16_t padlen = mbuf_calc_padlen(mbufs[j], cpe_pkt, &cpe_pkt->ipv4_hdr);

			if (padlen) {
				rte_pktmbuf_trim(mbufs[j], padlen);
			}
			out[j] = handle_qinq_encap4(task, cpe_pkt, mbufs[j], entries[j]);
		}
	}
	else {
		for (uint16_t j = 0; j < n_pkts; ++j) {
			if (unlikely(!((lookup_hit_mask >> j) & 0x1))) {
				handle_error(mbufs[j]);
				out[j] = OUT_DISCARD;
				continue;
			}
			struct cpe_pkt* cpe_pkt = (struct cpe_pkt*) rte_pktmbuf_adj(mbufs[j], UPSTREAM_DELTA);
			uint16_t padlen = mbuf_calc_padlen(mbufs[j], cpe_pkt, &cpe_pkt->ipv4_hdr);

			if (padlen) {
				rte_pktmbuf_trim(mbufs[j], padlen);
			}
			out[j] = handle_qinq_encap4(task, cpe_pkt, mbufs[j], entries[j]);
		}
	}

	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static inline uint8_t handle_qinq_encap4(struct task_qinq_encap4 *task, struct cpe_pkt *cpe_pkt, struct rte_mbuf *mbuf, struct cpe_data *entry)
{
	PROX_ASSERT(cpe_pkt);

	if (cpe_pkt->ipv4_hdr.time_to_live) {
		cpe_pkt->ipv4_hdr.time_to_live--;
	}
	else {
		plog_info("TTL = 0 => Dropping\n");
		return OUT_DISCARD;
	}
	cpe_pkt->ipv4_hdr.hdr_checksum = 0;

	restore_cpe(cpe_pkt, entry, task->qinq_tag, task->src_mac);

	if (task->runtime_flags & TASK_CLASSIFY) {
		uint8_t queue = task->dscp[cpe_pkt->ipv4_hdr.type_of_service >> 2] & 0x3;
		uint8_t tc = task->dscp[cpe_pkt->ipv4_hdr.type_of_service >> 2] >> 2;

		rte_sched_port_pkt_write(mbuf, 0, entry->user, tc, queue, 0);
	}
#ifdef ENABLE_EXTRA_USER_STATISTICS
	task->stats_per_user[entry->user]++;
#endif
	if (task->runtime_flags & TASK_TX_CRC) {
		prox_ip_cksum(mbuf, &cpe_pkt->ipv4_hdr, sizeof(struct qinq_hdr), sizeof(struct ipv4_hdr), task->offload_crc);
	}
	return entry->mac_port.out_idx;
}

static void flow_iter_next(struct flow_iter *iter, struct task_args *targ)
{
	do {
		iter->idx++;
		uint8_t flag_features = iter->data;

		if (flag_features & TASK_FEATURE_LUT_QINQ_RSS) {
			// If there is a load balancer, number of worker thread is indicated by targ->nb_slave_threads and n_rxq = 0
			// If there is no load balancers, number of worker thread is indicated by n_rxq and nb_slave_threads = 0
			uint8_t nb_worker_threads, worker_thread_id;
			nb_worker_threads = 1;
			worker_thread_id = 1;
			if (targ->nb_slave_threads) {
				nb_worker_threads = targ->nb_slave_threads;
				worker_thread_id = targ->worker_thread_id;
			} else if (prox_port_cfg[targ->rx_port_queue[0].port].n_rxq) {
				nb_worker_threads = prox_port_cfg[targ->rx_port_queue[0].port].n_rxq;
				worker_thread_id = targ->rx_port_queue[0].queue;
			} else {
				plog_err("Unexpected: unknown number of worker thread\n");
			}

			if (targ->nb_slave_threads == 0 || rss_to_queue(get_qinq_gre_map(targ)->entries[iter->idx].rss, nb_worker_threads) == worker_thread_id)
				break;
		} else if (flag_features & TASK_FEATURE_LUT_QINQ_HASH) {
			uint64_t cvlan = rte_bswap16(get_qinq_gre_map(targ)->entries[iter->idx].cvlan & 0xFF0F);
			uint64_t svlan = rte_bswap16(get_qinq_gre_map(targ)->entries[iter->idx].svlan & 0xFF0F);
			uint64_t qinq = rte_bswap64((svlan << 32) | cvlan);
			uint8_t queue = rte_hash_crc(&qinq, 8, 0) % targ->nb_slave_threads;
			if (queue == targ->worker_thread_id)
				break;
		} else if (flag_features & TASK_FEATURE_GRE_ID) {
			if (get_qinq_gre_map(targ)->entries[iter->idx].gre_id % targ->nb_slave_threads == targ->worker_thread_id)
				break;
		}
	} while (iter->idx != (int)get_qinq_gre_map(targ)->count);
}

static void flow_iter_beg(struct flow_iter *iter, struct task_args *targ)
{
	uint32_t flag_features = 0;
	if (targ->lb_friend_core != 0xFF) {
		struct task_args *lb_targ = &lcore_cfg[targ->lb_friend_core].targs[targ->lb_friend_task];
		flag_features = lb_targ->task_init->flag_features;
		plog_info("\t\tWT %d Updated features to %x from friend %d\n", targ->lconf->id, flag_features, targ->lb_friend_core);
	} else {
		plog_info("\t\tWT %d has no friend\n", targ->lconf->id);
	}
	if (targ->nb_slave_threads == 0)  {
		// No slave threads, i.e. using RSS
		plog_info("feature was %x is now %x\n", flag_features, TASK_FEATURE_LUT_QINQ_RSS);
		flag_features = TASK_FEATURE_LUT_QINQ_RSS;
	}
	if ((flag_features & (TASK_FEATURE_GRE_ID|TASK_FEATURE_LUT_QINQ_RSS|TASK_FEATURE_LUT_QINQ_HASH)) == 0) {
		plog_info("\t\tCould not find flag feature from Load balancer => supposing TASK_FEATURE_GRE_ID\n");
		flag_features = TASK_FEATURE_GRE_ID;
	}

	iter->idx = -1;
	flow_iter_next(iter, targ);
}

static int flow_iter_is_end(struct flow_iter *iter, struct task_args *targ)
{
	return iter->idx == (int)get_qinq_gre_map(targ)->count;
}

static uint32_t flow_iter_get_gre_id(struct flow_iter *iter, struct task_args *targ)
{
	return get_qinq_gre_map(targ)->entries[iter->idx].gre_id;
}

static struct task_init task_init_qinq_encap4_table = {
	.mode = QINQ_ENCAP4,
	.mode_str = "qinqencapv4",
	.early_init = early_init_table,
	.init = init_task_qinq_encap4,
	.handle = handle_qinq_encap4_bulk,
	/* In this case user in qinq_lookup table is the QoS user
	   (from user_table), i.e. usually from 0 to 32K Otherwise it
	   would have been a user from (0 to n_interface x 32K) */
	.flow_iter = {
		.beg        = flow_iter_beg,
		.is_end     = flow_iter_is_end,
		.next       = flow_iter_next,
		.get_gre_id = flow_iter_get_gre_id,
	},
	.flag_features = TASK_FEATURE_CLASSIFY,
	.size = sizeof(struct task_qinq_encap4)
};

static struct task_init task_init_qinq_encap4_table_pe = {
	.mode = QINQ_ENCAP4,
	.mode_str = "qinqencapv4",
	.sub_mode_str = "pe",
	.early_init = early_init_table,
	.init = init_task_qinq_encap4,
	.handle = handle_qinq_encap4_bulk_pe,
	.flag_features = TASK_FEATURE_CLASSIFY,
	.size = sizeof(struct task_qinq_encap4)
};

static struct task_init task_init_qinq_encap4_untag = {
	.mode = QINQ_ENCAP4,
	.sub_mode_str = "unmpls",
	.mode_str = "qinqencapv4",
	.init = init_task_qinq_encap4,
	.handle = handle_qinq_encap4_untag_bulk,
	.flag_features = TASK_FEATURE_CLASSIFY,
	.size = sizeof(struct task_qinq_encap4)
};

__attribute__((constructor)) static void reg_task_qinq_encap4(void)
{
	reg_task(&task_init_qinq_encap4_table);
	reg_task(&task_init_qinq_encap4_table_pe);
	reg_task(&task_init_qinq_encap4_untag);
}
