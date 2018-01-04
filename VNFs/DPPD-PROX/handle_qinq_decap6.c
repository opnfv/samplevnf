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
#include <rte_table_hash.h>

#include "prox_lua.h"
#include "prox_lua_types.h"

#include "handle_qinq_encap6.h"
#include "log.h"
#include "lconf.h"
#include "task_init.h"
#include "task_base.h"
#include "tx_pkt.h"
#include "defines.h"
#include "pkt_prototypes.h"
#include "prox_assert.h"
#include "hash_utils.h"
#include "task_base.h"
#include "prefetch.h"
#include "hash_entry_types.h"
#include "prox_cfg.h"
#include "log.h"
#include "quit.h"
#include "prox_shared.h"
#include "prox_compat.h"

/* Packets must all be IPv6, always store QinQ tags for lookup (not configurable) */
struct task_qinq_decap6 {
	struct task_base                base;
	struct rte_table_hash           *cpe_table;
	uint16_t                        *user_table;
	uint32_t                        bucket_index;
	struct ether_addr 		edaddr;
	struct rte_lpm6                 *rte_lpm6;
	void*                           period_data; /* used if using dual stack*/
	void (*period_func)(void* data);
	uint64_t                        cpe_timeout;
};

void update_arp_entries6(void* data);

static void init_task_qinq_decap6(struct task_base *tbase, struct task_args *targ)
{
	struct task_qinq_decap6 *task = (struct task_qinq_decap6 *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	task->edaddr = targ->edaddr;
	task->cpe_table = targ->cpe_table;
	task->cpe_timeout = msec_to_tsc(targ->cpe_table_timeout_ms);

	if (targ->cpe_table_timeout_ms) {
		if (targ->lconf->period_func) {
			task->period_func = targ->lconf->period_func;
			task->period_data = targ->lconf->period_data;
		}
		targ->lconf->period_func = update_arp_entries6;
		targ->lconf->period_data = tbase;
		targ->lconf->period_timeout = msec_to_tsc(500) / NUM_VCPES;
	}

	task->user_table = prox_sh_find_socket(socket_id, "user_table");
	if (!task->user_table) {
		PROX_PANIC(!strcmp(targ->user_table, ""), "No user table defined\n");
		int ret = lua_to_user_table(prox_lua(), GLOBAL, targ->user_table, socket_id, &task->user_table);
		PROX_PANIC(ret, "Failed to create user table from config:\n%s\n", get_lua_to_errors());
		prox_sh_add_socket(socket_id, "user_table", task->user_table);
	}

	struct lpm6 *lpm = prox_sh_find_socket(socket_id, "lpm6");
	if (!lpm) {
		struct lpm6 *lpm6;
		int ret;

		ret = lua_to_lpm6(prox_lua(), GLOBAL, "lpm6", socket_id, &lpm6);
		PROX_PANIC(ret, "Failed to read lpm6 from config:\n%s\n", get_lua_to_errors());
		prox_sh_add_socket(socket_id, "lpm6", lpm6);
	}
	task->rte_lpm6 = lpm->rte_lpm6;
}

static void early_init(struct task_args *targ)
{
	if (!targ->cpe_table) {
		init_cpe6_table(targ);
	}
}

static inline uint8_t handle_qinq_decap6(struct task_qinq_decap6 *task, struct rte_mbuf *mbuf)
{
	struct qinq_hdr *pqinq = rte_pktmbuf_mtod(mbuf, struct qinq_hdr *);
	struct ipv6_hdr *pip6 = (struct ipv6_hdr *)(pqinq + 1);

	uint16_t svlan = pqinq->svlan.vlan_tci & 0xFF0F;
	uint16_t cvlan = pqinq->cvlan.vlan_tci & 0xFF0F;

	struct cpe_data entry;
	entry.mac_port_8bytes = *((uint64_t *)(((uint8_t *)pqinq) + 5)) << 16;
	entry.qinq_svlan = svlan;
	entry.qinq_cvlan = cvlan;
	entry.user = task->user_table[PKT_TO_LUTQINQ(svlan, cvlan)];
	entry.tsc = rte_rdtsc() + task->cpe_timeout;

	int key_found = 0;
	void* entry_in_hash = NULL;
	int ret = prox_rte_table_add(task->cpe_table, pip6->src_addr, &entry, &key_found, &entry_in_hash);

	if (unlikely(ret)) {
		plogx_err("Failed to add key " IPv6_BYTES_FMT "\n", IPv6_BYTES(pip6->src_addr));
		return OUT_DISCARD;
	}

	pqinq = (struct qinq_hdr *)rte_pktmbuf_adj(mbuf, 2 * sizeof(struct vlan_hdr));
	PROX_ASSERT(pqinq);
	pqinq->ether_type = ETYPE_IPv6;
	// Dest MAC addresses
	ether_addr_copy(&task->edaddr, &pqinq->d_addr);
	return 0;
}

static int handle_qinq_decap6_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_qinq_decap6 *task = (struct task_qinq_decap6 *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint16_t j;

	prefetch_first(mbufs, n_pkts);

	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef PROX_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		out[j] = handle_qinq_decap6(task, mbufs[j]);
	}
#ifdef PROX_PREFETCH_OFFSET
	PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		out[j] = handle_qinq_decap6(task, mbufs[j]);
	}
#endif

	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

void update_arp_entries6(void* data)
{
	uint64_t cur_tsc = rte_rdtsc();
	struct task_qinq_decap6 *task = (struct task_qinq_decap6 *)data;

	struct cpe_data *entries[4] = {0};
	void *key[4] = {0};
	uint64_t n_buckets = get_bucket(task->cpe_table, task->bucket_index, key, (void**)entries);

	for (uint8_t i = 0; i < 4 && entries[i]; ++i) {
		if (entries[i]->tsc < cur_tsc) {
			int key_found = 0;
			void* entry = 0;
			prox_rte_table_delete(task->cpe_table, key[i], &key_found, entry);
		}
	}

	task->bucket_index++;
	task->bucket_index &= (n_buckets - 1);

	if (task->period_func) {
		task->period_func(task->period_data);
	}
}

static struct task_init task_init_qinq_decap6 = {
	.mode = QINQ_DECAP6,
	.mode_str = "qinqdecapv6",
	.early_init = early_init,
	.init = init_task_qinq_decap6,
	.handle = handle_qinq_decap6_bulk,
	.size = sizeof(struct task_qinq_decap6)
};

__attribute__((constructor)) static void reg_task_qinq_decap6(void)
{
	reg_task(&task_init_qinq_decap6);
}
