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

#include <rte_ip.h>
#include <stdio.h>
#include <string.h>
#include <rte_version.h>

#include "prox_lua.h"
#include "prox_lua_types.h"

#include "lconf.h"
#include "task_base.h"
#include "task_init.h"
#include "defines.h"
#include "prefetch.h"
#include "qinq.h"
#include "prox_cfg.h"
#include "log.h"
#include "quit.h"
#include "prox_shared.h"

struct task_classify {
	struct task_base    base;
	uint16_t           *user_table;
	uint8_t             *dscp;
};

static inline void handle_classify(struct task_classify *task, struct rte_mbuf *mbuf)
{
	const struct qinq_hdr *pqinq = rte_pktmbuf_mtod(mbuf, const struct qinq_hdr *);

	uint32_t qinq = PKT_TO_LUTQINQ(pqinq->svlan.vlan_tci, pqinq->cvlan.vlan_tci);

	/* Traffic class can be set by ACL task. If this is the case,
	   don't overwrite it using dscp. Instead, use the
	   traffic class that had been set. */

	uint32_t prev_tc;
#if RTE_VERSION >= RTE_VERSION_NUM(1,8,0,0)
	uint32_t dummy;
	rte_sched_port_pkt_read_tree_path(mbuf, &dummy, &dummy, &prev_tc, &dummy);
#else
	struct rte_sched_port_hierarchy *sched = (struct rte_sched_port_hierarchy *) &mbuf->pkt.hash.sched;
	prev_tc = sched->traffic_class;
#endif

	const struct ipv4_hdr *ipv4_hdr = (const struct ipv4_hdr *)(pqinq + 1);
	uint8_t dscp = task->dscp[ipv4_hdr->type_of_service >> 2];

	uint8_t queue = dscp & 0x3;
	uint8_t tc = prev_tc? prev_tc : dscp >> 2;

	rte_sched_port_pkt_write(mbuf, 0, task->user_table[qinq], tc, queue, 0);
}

static int handle_classify_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_classify *task = (struct task_classify *)tbase;

	uint16_t j;
#ifdef PROX_PREFETCH_OFFSET
	for (j = 0; j < PROX_PREFETCH_OFFSET && j < n_pkts; ++j) {
		prefetch_nta(mbufs[j]);
	}
	for (j = 1; j < PROX_PREFETCH_OFFSET && j < n_pkts; ++j) {
		prefetch_nta(rte_pktmbuf_mtod(mbufs[j - 1], void *));
	}
#endif
	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef PROX_PREFETCH_OFFSET
		prefetch_nta(mbufs[j + PREFETCH_OFFSET]);
		prefetch_nta(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		handle_classify(task, mbufs[j]);
	}
#ifdef PROX_PREFETCH_OFFSET
	prefetch_nta(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		handle_classify(task, mbufs[j]);
	}
#endif

	return task->base.tx_pkt(&task->base, mbufs, n_pkts, NULL);
}

static void init_task_classify(struct task_base *tbase, struct task_args *targ)
{
	struct task_classify *task = (struct task_classify *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	task->user_table = prox_sh_find_socket(socket_id, "user_table");
	if (!task->user_table) {
		PROX_PANIC(!strcmp(targ->user_table, ""), "No user table defined\n");
		int ret = lua_to_user_table(prox_lua(), GLOBAL, targ->user_table, socket_id, &task->user_table);
		PROX_PANIC(ret, "Failed to create user table from config:\n%s\n", get_lua_to_errors());
		prox_sh_add_socket(socket_id, "user_table", task->user_table);
	}

	PROX_PANIC(!strcmp(targ->dscp, ""), "DSCP table not specified\n");
	task->dscp = prox_sh_find_socket(socket_id, targ->dscp);
	if (!task->dscp) {
		int ret = lua_to_dscp(prox_lua(), GLOBAL, targ->dscp, socket_id, &task->dscp);
		PROX_PANIC(ret, "Failed to create dscp table from config\n");
		prox_sh_add_socket(socket_id, targ->dscp, task->dscp);
	}
}

static struct task_init task_init_classify = {
	.mode_str = "classify",
	.init = init_task_classify,
	.handle = handle_classify_bulk,
	.flag_features = TASK_FEATURE_NEVER_DISCARDS,
	.size = sizeof(struct task_classify)
};

__attribute__((constructor)) static void reg_task_classify(void)
{
	reg_task(&task_init_classify);
}
