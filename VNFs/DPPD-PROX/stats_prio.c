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

#include <stddef.h>

#include "handle_aggregator.h"
#include "stats_prio_task.h"
#include "prox_cfg.h"
#include "prox_globals.h"
#include "lconf.h"

struct lcore_task_stats {
	struct task_stats task_stats[MAX_TASKS_PER_CORE];
};

struct lcore_prio_task_stats {
	struct prio_task_stats prio_task_stats[MAX_TASKS_PER_CORE];
};

extern int last_stat;
static struct prio_task_stats   prio_task_stats_set[RTE_MAX_LCORE * MAX_TASKS_PER_CORE];
static uint8_t nb_prio_tasks_tot;

int stats_get_n_prio_tasks_tot(void)
{
        return nb_prio_tasks_tot;
}

struct prio_task_stats_sample *stats_get_prio_task_stats_sample(uint32_t prio_task_id, int l)
{
	return &prio_task_stats_set[prio_task_id].sample[l == last_stat];
}

struct prio_task_stats_sample *stats_get_prio_task_stats_sample_by_core_task(uint32_t lcore_id, uint32_t prio_task_id, int l)
{
	for (uint8_t task_id = 0; task_id < nb_prio_tasks_tot; ++task_id) {
		if ((prio_task_stats_set[task_id].lcore_id == lcore_id) && (prio_task_stats_set[task_id].task_id == task_id))
			return &prio_task_stats_set[prio_task_id].sample[l == last_stat];
	}
	return NULL;
}

void stats_prio_task_reset(void)
{
	struct prio_task_stats *cur_task_stats;

	for (uint8_t task_id = 0; task_id < nb_prio_tasks_tot; ++task_id) {
		cur_task_stats = &prio_task_stats_set[task_id];
		for (int i = 0; i < 8; i++) {
			cur_task_stats->tot_drop_tx_fail_prio[i] = 0;
			cur_task_stats->tot_rx_prio[i] = 0;
		}
	}
}

uint64_t stats_core_task_tot_drop_tx_fail_prio(uint8_t prio_task_id, uint8_t prio)
{
	return prio_task_stats_set[prio_task_id].tot_drop_tx_fail_prio[prio];
}

uint64_t stats_core_task_tot_rx_prio(uint8_t prio_task_id, uint8_t prio)
{
	return prio_task_stats_set[prio_task_id].tot_rx_prio[prio];
}

void stats_prio_task_post_proc(void)
{
	for (uint8_t task_id = 0; task_id < nb_prio_tasks_tot; ++task_id) {
		struct prio_task_stats *cur_task_stats = &prio_task_stats_set[task_id];
		const struct prio_task_stats_sample *last = &cur_task_stats->sample[last_stat];
		const struct prio_task_stats_sample *prev = &cur_task_stats->sample[!last_stat];

		for (int i=0; i<8; i++) {
			cur_task_stats->tot_rx_prio[i] += last->rx_prio[i] - prev->rx_prio[i];
			cur_task_stats->tot_drop_tx_fail_prio[i] += last->drop_tx_fail_prio[i] - prev->drop_tx_fail_prio[i];
		}
	}
}

void stats_prio_task_update(void)
{
	uint64_t before, after;

	for (uint8_t task_id = 0; task_id < nb_prio_tasks_tot; ++task_id) {
		struct prio_task_stats *cur_task_stats = &prio_task_stats_set[task_id];
		struct prio_task_rt_stats *stats = cur_task_stats->stats;
		struct prio_task_stats_sample *last = &cur_task_stats->sample[last_stat];

		before = rte_rdtsc();
		for (int i=0; i<8; i++) {
			last->drop_tx_fail_prio[i] = stats->drop_tx_fail_prio[i];
			last->rx_prio[i] = stats->rx_prio[i];
		}
		after = rte_rdtsc();
		last->tsc = (before >> 1) + (after >> 1);
	}
}

void stats_prio_task_init(void)
{
	struct lcore_cfg *lconf;
	uint32_t lcore_id;

	/* add cores that are receiving from and sending to physical ports first */
	lcore_id = -1;
	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			struct task_args *targ = &lconf->targs[task_id];
			if (strcmp(targ->task_init->mode_str, "aggreg") == 0) {
				struct prio_task_rt_stats *stats = &((struct task_aggregator *)(lconf->tasks_all[task_id]))->stats;
				prio_task_stats_set[nb_prio_tasks_tot].stats = stats;
				prio_task_stats_set[nb_prio_tasks_tot].lcore_id = lcore_id;
				prio_task_stats_set[nb_prio_tasks_tot++].task_id = task_id;
			}
		}
	}
}
