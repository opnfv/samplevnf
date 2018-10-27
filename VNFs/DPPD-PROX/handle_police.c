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
#include <stdio.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_version.h>

#include "prox_lua.h"
#include "prox_lua_types.h"
#include "prox_malloc.h"
#include "task_base.h"
#include "task_init.h"
#include "lconf.h"
#include "prefetch.h"
#include "quit.h"
#include "log.h"
#include "defines.h"
#include "qinq.h"
#include "prox_cfg.h"
#include "prox_shared.h"

#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE
#endif

struct task_police {
	struct task_base base;
	union {
		struct rte_meter_srtcm *sr_flows;
		struct rte_meter_trtcm *tr_flows;
	};
	union {
#if RTE_VERSION >= RTE_VERSION_NUM(18,5,0,0)
        	struct rte_meter_srtcm_profile sr_profile;
        	struct rte_meter_trtcm_profile tr_profile;
#endif
	};
	uint16_t           *user_table;
	enum police_action police_act[3][3];
	uint16_t overhead;
	uint8_t runtime_flags;
};

typedef uint8_t (*hp) (struct task_police *task, struct rte_mbuf *mbuf, uint64_t tsc, uint32_t user);

static uint8_t handle_police(struct task_police *task, struct rte_mbuf *mbuf, uint64_t tsc, uint32_t user)
{
	enum rte_meter_color in_color = e_RTE_METER_GREEN;
	enum rte_meter_color out_color;
	uint32_t pkt_len = rte_pktmbuf_pkt_len(mbuf) + task->overhead;

#if RTE_VERSION < RTE_VERSION_NUM(18,5,0,0)
	out_color = rte_meter_srtcm_color_aware_check(&task->sr_flows[user], tsc, pkt_len, in_color);
#else
	out_color = rte_meter_srtcm_color_aware_check(&task->sr_flows[user], &task->sr_profile, tsc, pkt_len, in_color);
#endif
	return task->police_act[in_color][out_color] == ACT_DROP? OUT_DISCARD : 0;
}

static uint8_t handle_police_tr(struct task_police *task, struct rte_mbuf *mbuf, uint64_t tsc, uint32_t user)
{
	enum rte_meter_color in_color = e_RTE_METER_GREEN;
	enum rte_meter_color out_color;
	uint32_t pkt_len = rte_pktmbuf_pkt_len(mbuf) + task->overhead;
#if RTE_VERSION < RTE_VERSION_NUM(18,5,0,0)
	out_color = rte_meter_trtcm_color_aware_check(&task->tr_flows[user], tsc, pkt_len, in_color);
#else
	out_color = rte_meter_trtcm_color_aware_check(&task->tr_flows[user], &task->tr_profile, tsc, pkt_len, in_color);
#endif

	if (task->runtime_flags  & TASK_MARK) {
#if RTE_VERSION >= RTE_VERSION_NUM(1,8,0,0)
		uint32_t subport, pipe, traffic_class, queue;
		enum rte_meter_color color;

		rte_sched_port_pkt_read_tree_path(mbuf, &subport, &pipe, &traffic_class, &queue);
		color = task->police_act[in_color][out_color];

		rte_sched_port_pkt_write(mbuf, subport, pipe, traffic_class, queue, color);
#else
		struct rte_sched_port_hierarchy *sched =
			(struct rte_sched_port_hierarchy *) &mbuf->pkt.hash.sched;
		sched->color = task->police_act[in_color][out_color];
#endif
	}

	return task->police_act[in_color][out_color] == ACT_DROP? OUT_DISCARD : 0;
}

static inline int get_user(struct task_police *task, struct rte_mbuf *mbuf)
{
	if (task->runtime_flags & TASK_CLASSIFY) {
		struct qinq_hdr *pqinq = rte_pktmbuf_mtod(mbuf, struct qinq_hdr *);
		return PKT_TO_LUTQINQ(pqinq->svlan.vlan_tci, pqinq->cvlan.vlan_tci);
	}

#if RTE_VERSION >= RTE_VERSION_NUM(1,8,0,0)
	uint32_t dummy;
	uint32_t pipe;

	rte_sched_port_pkt_read_tree_path(mbuf, &dummy, &pipe, &dummy, &dummy);
	return pipe;
#else
	struct rte_sched_port_hierarchy *sched =
		(struct rte_sched_port_hierarchy *) &mbuf->pkt.hash.sched;
	return sched->pipe;
#endif
}

#define PHASE1_DELAY PREFETCH_OFFSET
#define PHASE2_DELAY PREFETCH_OFFSET
#define PHASE3_DELAY PREFETCH_OFFSET
#define PHASE4_DELAY PREFETCH_OFFSET

static inline int handle_pb(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, hp handle_police_func)
{
	struct task_police *task = (struct task_police *)tbase;
	uint16_t j;
	uint64_t cur_tsc = rte_rdtsc();
	uint32_t user[64];
	uint8_t  out[MAX_PKT_BURST];
	uint32_t cur_user;
	for (j = 0; j < PHASE1_DELAY && j < n_pkts; ++j) {
		PREFETCH0(mbufs[j]);
	}

	for (j = 0; j < PHASE2_DELAY && j + PHASE1_DELAY < n_pkts; ++j) {
		PREFETCH0(mbufs[j + PHASE1_DELAY]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j], void*));
	}

	for (j = 0; j < PHASE3_DELAY && j + PHASE2_DELAY + PHASE1_DELAY < n_pkts; ++j) {
		PREFETCH0(mbufs[j + PHASE2_DELAY + PHASE1_DELAY]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PHASE2_DELAY], void*));
                cur_user = get_user(task, mbufs[j]);
		user[j] = cur_user;
		PREFETCH0(&task->user_table[cur_user]);
	}

	/* At this point, the whole pipeline is running */
	for (j = 0; j + PHASE3_DELAY + PHASE2_DELAY + PHASE1_DELAY < n_pkts; ++j) {
		PREFETCH0(mbufs[j + PHASE3_DELAY + PHASE2_DELAY + PHASE1_DELAY]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PHASE3_DELAY + PHASE2_DELAY], void*));
		cur_user = get_user(task, mbufs[j + PHASE3_DELAY]);
		user[j + PHASE3_DELAY] = cur_user;
		PREFETCH0(&task->user_table[cur_user]);

		out[j] = handle_police_func(task, mbufs[j], cur_tsc, task->user_table[user[j]]);
	}

	/* Last part of pipeline */
	for (; j + PHASE3_DELAY + PHASE2_DELAY < n_pkts; ++j) {
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PHASE3_DELAY + PHASE2_DELAY], void*));
		PREFETCH0(&task->user_table[j + PHASE3_DELAY]);
		cur_user = get_user(task, mbufs[j + PHASE3_DELAY]);
		user[j + PHASE3_DELAY] = cur_user;
		PREFETCH0(&task->user_table[cur_user]);

		out[j] = handle_police_func(task, mbufs[j], cur_tsc, task->user_table[user[j]]);
	}

	for (; j + PHASE3_DELAY < n_pkts; ++j) {
		cur_user = get_user(task, mbufs[j + PHASE3_DELAY]);
		user[j + PHASE3_DELAY] = cur_user;
		PREFETCH0(&task->user_table[cur_user]);

		out[j] = handle_police_func(task, mbufs[j], cur_tsc, task->user_table[user[j]]);
	}

	for (; j < n_pkts; ++j) {
		out[j] = handle_police_func(task, mbufs[j], cur_tsc, task->user_table[user[j]]);
	}

	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static int handle_police_bulk(struct task_base *tbase, struct rte_mbuf **mbuf, uint16_t n_pkts)
{
        return handle_pb(tbase, mbuf, n_pkts, handle_police);
}

static int handle_police_tr_bulk(struct task_base *tbase, struct rte_mbuf **mbuf, uint16_t n_pkts)
{
        return handle_pb(tbase, mbuf, n_pkts, handle_police_tr);
}

static void init_task_police(struct task_base *tbase, struct task_args *targ)
{
	struct task_police *task = (struct task_police *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	task->overhead = targ->overhead;
	task->runtime_flags = targ->runtime_flags;

	task->user_table = prox_sh_find_socket(socket_id, "user_table");
	if (!task->user_table) {
		PROX_PANIC(!strcmp(targ->user_table, ""), "No user table defined\n");
		int ret = lua_to_user_table(prox_lua(), GLOBAL, targ->user_table, socket_id, &task->user_table);
		PROX_PANIC(ret, "Failed to create user table from config:\n%s\n", get_lua_to_errors());
		prox_sh_add_socket(socket_id, "user_table", task->user_table);
	}

	if (strcmp(targ->task_init->sub_mode_str, "trtcm")) {
		task->sr_flows = prox_zmalloc(targ->n_flows * sizeof(*task->sr_flows), socket_id);
		PROX_PANIC(task->sr_flows == NULL, "Failed to allocate flow contexts\n");
		PROX_PANIC(!targ->cir, "Commited information rate is set to 0\n");
		PROX_PANIC(!targ->cbs, "Commited information bucket size is set to 0\n");
		PROX_PANIC(!targ->ebs, "Execess information bucket size is set to 0\n");

		struct rte_meter_srtcm_params params = {
			.cir = targ->cir,
			.cbs = targ->cbs,
			.ebs = targ->ebs,
		};
#if RTE_VERSION >= RTE_VERSION_NUM(18,5,0,0)
		PROX_PANIC(rte_meter_srtcm_profile_config(&task->sr_profile, &params) != 0, "Failed to rte_meter_srtcm_profile_config\n");
		for (uint32_t i = 0; i < targ->n_flows; ++i) {
			PROX_PANIC(rte_meter_srtcm_config(&task->sr_flows[i], &task->sr_profile) != 0, "Failed to rte_meter_srtcm_config");
		}
#else
		for (uint32_t i = 0; i < targ->n_flows; ++i) {
			rte_meter_srtcm_config(&task->sr_flows[i], &params);
		}
#endif
	}
	else {
		task->tr_flows = prox_zmalloc(targ->n_flows * sizeof(*task->tr_flows), socket_id);
		PROX_PANIC(task->tr_flows == NULL, "Failed to allocate flow contexts\n");
		PROX_PANIC(!targ->pir, "Peak information rate is set to 0\n");
		PROX_PANIC(!targ->cir, "Commited information rate is set to 0\n");
		PROX_PANIC(!targ->pbs, "Peak information bucket size is set to 0\n");
		PROX_PANIC(!targ->cbs, "Commited information bucket size is set to 0\n");

		struct rte_meter_trtcm_params params = {
			.pir = targ->pir,
			.pbs = targ->pbs,
			.cir = targ->cir,
			.cbs = targ->cbs,
		};
#if RTE_VERSION >= RTE_VERSION_NUM(18,5,0,0)
		PROX_PANIC(rte_meter_trtcm_profile_config(&task->tr_profile, &params) != 0, "Failed to rte_meter_srtcm_profile_config\n");
		for (uint32_t i = 0; i < targ->n_flows; ++i) {
			PROX_PANIC(rte_meter_trtcm_config(&task->tr_flows[i], &task->tr_profile) != 0, "Failed to rte_meter_trtcm_config\n");
		}
#else

		for (uint32_t i = 0; i < targ->n_flows; ++i) {
			rte_meter_trtcm_config(&task->tr_flows[i], &params);
		}
#endif
	}

	for (uint32_t i = 0; i < 3; ++i) {
		for (uint32_t j = 0; j < 3; ++j) {
			task->police_act[i][j] = targ->police_act[i][j];
		}
	}
}

static struct task_init task_init_police = {
	.mode_str = "police",
	.init = init_task_police,
	.handle = handle_police_bulk,
	.flag_features = TASK_FEATURE_CLASSIFY,
	.size = sizeof(struct task_police)
};

static struct task_init task_init_police2 = {
	.mode_str = "police",
	.sub_mode_str = "trtcm",
	.init = init_task_police,
	.handle = handle_police_tr_bulk,
	.flag_features = TASK_FEATURE_CLASSIFY,
	.size = sizeof(struct task_police)
};

__attribute__((constructor)) static void reg_task_police(void)
{
	reg_task(&task_init_police);
	reg_task(&task_init_police2);
}
