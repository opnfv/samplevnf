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

#include "prox_malloc.h"
#include "prox_cfg.h"
#include "stats_l4gen.h"
#include "task_init.h"

struct task_l4gen_stats {
	struct task_base base;
	struct l4_stats l4_stats;
};

struct stats_l4gen_manager {
	uint16_t n_l4gen;
	struct task_l4_stats task_l4_stats[0];
};

extern int last_stat;
static struct stats_l4gen_manager *sl4m;

int stats_get_n_l4gen(void)
{
	return sl4m->n_l4gen;
}

struct task_l4_stats *stats_get_l4_stats(uint32_t i)
{
	return &sl4m->task_l4_stats[i];
}

struct l4_stats_sample *stats_get_l4_stats_sample(uint32_t i, int l)
{
	return &sl4m->task_l4_stats[i].sample[l == last_stat];
}

static struct stats_l4gen_manager *alloc_stats_l4gen_manager(void)
{
	struct lcore_cfg *lconf;
	uint32_t lcore_id = -1;
	size_t mem_size;
	uint32_t n_l4gen = 0;
	const int socket_id = rte_lcore_to_socket_id(rte_lcore_id());

	lcore_id = -1;
	while (prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			struct task_args *targ = &lconf->targs[task_id];

			if (!strcmp(targ->task_init->mode_str, "genl4"))
				n_l4gen++;
		}
	}

	mem_size = sizeof(struct stats_l4gen_manager) + sizeof(struct task_l4_stats) * n_l4gen;
	return prox_zmalloc(mem_size, socket_id);
}

void stats_l4gen_init(void)
{
	struct lcore_cfg *lconf;
	uint32_t lcore_id = -1;

	sl4m = alloc_stats_l4gen_manager();

	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			struct task_args *targ = &lconf->targs[task_id];

			if (!strcmp(targ->task_init->mode_str, "genl4")) {
				sl4m->task_l4_stats[sl4m->n_l4gen].task = (struct task_l4gen_stats *)lconf->tasks_all[task_id];
				sl4m->task_l4_stats[sl4m->n_l4gen].lcore_id = lcore_id;
				sl4m->task_l4_stats[sl4m->n_l4gen].task_id = task_id;
				sl4m->n_l4gen++;
			}
		}
	}
}

void stats_l4gen_update(void)
{
	uint64_t before, after;

	for (uint16_t i = 0; i < sl4m->n_l4gen; ++i) {
		struct task_l4gen_stats *task_l4gen = sl4m->task_l4_stats[i].task;

		before = rte_rdtsc();
		sl4m->task_l4_stats[i].sample[last_stat].stats = task_l4gen->l4_stats;
		after = rte_rdtsc();

		sl4m->task_l4_stats[i].sample[last_stat].tsc = (before >> 1) + (after >> 1);
	}
}
