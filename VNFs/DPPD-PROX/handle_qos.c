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
#include <rte_mbuf.h>
#include <rte_sched.h>

#include "prox_lua.h"
#include "prox_lua_types.h"

#include "etypes.h"
#include "stats.h"
#include "task_init.h"
#include "lconf.h"
#include "task_base.h"
#include "defines.h"
#include "prefetch.h"
#include "handle_qos.h"
#include "log.h"
#include "quit.h"
#include "qinq.h"
#include "prox_cfg.h"
#include "prox_shared.h"

struct task_qos {
	struct task_base base;
	struct rte_sched_port *sched_port;
	uint16_t *user_table;
	uint8_t  *dscp;
	uint32_t nb_buffered_pkts;
	uint8_t runtime_flags;
};

uint32_t task_qos_n_pkts_buffered(struct task_base *tbase)
{
	struct task_qos *task = (struct task_qos *)tbase;

	return task->nb_buffered_pkts;
}

static inline int handle_qos_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_qos *task = (struct task_qos *)tbase;
	int ret = 0;

	if (n_pkts) {
		if (task->runtime_flags & TASK_CLASSIFY) {
			uint16_t j;
#ifdef PROX_PREFETCH_OFFSET
			for (j = 0; j < PROX_PREFETCH_OFFSET && j < n_pkts; ++j) {
				prefetch_nta(mbufs[j]);
			}
			for (j = 1; j < PROX_PREFETCH_OFFSET && j < n_pkts; ++j) {
				prefetch_nta(rte_pktmbuf_mtod(mbufs[j - 1], void *));
			}
#endif
			uint8_t queue = 0;
			uint8_t tc = 0;
			for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
				prefetch_nta(mbufs[j + PREFETCH_OFFSET]);
				prefetch_nta(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
				const struct qinq_hdr *pqinq = rte_pktmbuf_mtod(mbufs[j], const struct qinq_hdr *);
				uint32_t qinq = PKT_TO_LUTQINQ(pqinq->svlan.vlan_tci, pqinq->cvlan.vlan_tci);
				if (pqinq->ether_type == ETYPE_IPv4) {
					const struct ipv4_hdr *ipv4_hdr = (const struct ipv4_hdr *)(pqinq + 1);
					queue = task->dscp[ipv4_hdr->type_of_service >> 2] & 0x3;
					tc = task->dscp[ipv4_hdr->type_of_service >> 2] >> 2;
				} else {
					// Keep queue and tc = 0 for other packet types like ARP
					queue = 0;
					tc = 0;
				}

				rte_sched_port_pkt_write(mbufs[j], 0, task->user_table[qinq], tc, queue, 0);
			}
#ifdef PROX_PREFETCH_OFFSET
			prefetch_nta(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
			for (; j < n_pkts; ++j) {
				const struct qinq_hdr *pqinq = rte_pktmbuf_mtod(mbufs[j], const struct qinq_hdr *);
				uint32_t qinq = PKT_TO_LUTQINQ(pqinq->svlan.vlan_tci, pqinq->cvlan.vlan_tci);
				if (pqinq->ether_type == ETYPE_IPv4) {
					const struct ipv4_hdr *ipv4_hdr = (const struct ipv4_hdr *)(pqinq + 1);
					queue = task->dscp[ipv4_hdr->type_of_service >> 2] & 0x3;
					tc = task->dscp[ipv4_hdr->type_of_service >> 2] >> 2;
				} else {
					// Keep queue and tc = 0 for other packet types like ARP
					queue = 0;
					tc = 0;
				}

				rte_sched_port_pkt_write(mbufs[j], 0, task->user_table[qinq], tc, queue, 0);
			}
#endif
		}
		int16_t ret = rte_sched_port_enqueue(task->sched_port, mbufs, n_pkts);
		task->nb_buffered_pkts += ret;
		TASK_STATS_ADD_DROP_DISCARD(&task->base.aux->stats, n_pkts - ret);
	}

	if (task->nb_buffered_pkts) {
		n_pkts = rte_sched_port_dequeue(task->sched_port, mbufs, 32);
		if (likely(n_pkts)) {
			task->nb_buffered_pkts -= n_pkts;
			ret = task->base.tx_pkt(&task->base, mbufs, n_pkts, NULL);
		}
	}
	return ret;
}

static void init_task_qos(struct task_base *tbase, struct task_args *targ)
{
	struct task_qos *task = (struct task_qos *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	char name[64];

	snprintf(name, sizeof(name), "qos_sched_port_%u_%u", targ->lconf->id, 0);

	targ->qos_conf.port_params.name = name;
	targ->qos_conf.port_params.socket = socket_id;
	task->sched_port = rte_sched_port_config(&targ->qos_conf.port_params);

	PROX_PANIC(task->sched_port == NULL, "failed to create sched_port");

	plog_info("number of pipes: %d\n\n", targ->qos_conf.port_params.n_pipes_per_subport);
	int err = rte_sched_subport_config(task->sched_port, 0, targ->qos_conf.subport_params);
	PROX_PANIC(err != 0, "Failed setting up sched_port subport, error: %d", err);

	/* only single subport and single pipe profile is supported */
	for (uint32_t pipe = 0; pipe < targ->qos_conf.port_params.n_pipes_per_subport; ++pipe) {
		err = rte_sched_pipe_config(task->sched_port, 0 , pipe, 0);
		PROX_PANIC(err != 0, "failed setting up sched port pipe, error: %d", err);
	}

	task->runtime_flags = targ->runtime_flags;

	task->user_table = prox_sh_find_socket(socket_id, "user_table");
	if (!task->user_table) {
		PROX_PANIC(!strcmp(targ->user_table, ""), "No user table defined\n");
		int ret = lua_to_user_table(prox_lua(), GLOBAL, targ->user_table, socket_id, &task->user_table);
		PROX_PANIC(ret, "Failed to create user table from config:\n%s\n", get_lua_to_errors());
		prox_sh_add_socket(socket_id, "user_table", task->user_table);
	}

	if (task->runtime_flags & TASK_CLASSIFY) {
		PROX_PANIC(!strcmp(targ->dscp, ""), "DSCP table not specified\n");
		task->dscp = prox_sh_find_socket(socket_id, targ->dscp);
		if (!task->dscp) {
			int ret = lua_to_dscp(prox_lua(), GLOBAL, targ->dscp, socket_id, &task->dscp);
			PROX_PANIC(ret, "Failed to create dscp table from config:\n%s\n", get_lua_to_errors());
			prox_sh_add_socket(socket_id, targ->dscp, task->dscp);
		}
	}
}

static struct task_init task_init_qos = {
	.mode_str = "qos",
	.init = init_task_qos,
	.handle = handle_qos_bulk,
	.flag_features = TASK_FEATURE_CLASSIFY | TASK_FEATURE_NEVER_DISCARDS | TASK_FEATURE_MULTI_RX | TASK_FEATURE_ZERO_RX,
	.size = sizeof(struct task_qos)
};

__attribute__((constructor)) static void reg_task_qos(void)
{
	reg_task(&task_init_qos);
}
