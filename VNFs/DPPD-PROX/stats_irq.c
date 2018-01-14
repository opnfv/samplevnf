/*
// Copyright (c) 2010-2018 Intel Corporation
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

#include "handle_irq.h"
#include "stats_irq.h"
#include "prox_cfg.h"
#include "prox_globals.h"
#include "lconf.h"

static struct irq_task_stats   irq_task_stats_set[RTE_MAX_LCORE * MAX_TASKS_PER_CORE];
static uint8_t nb_irq_tasks;

int stats_get_n_irq_tasks(void)
{
        return nb_irq_tasks;
}

struct irq_sample *get_irq_sample(uint32_t task_id, int l)
{
	return &irq_task_stats_set[task_id].sample[last_stat == l];
}

struct irq_sample *get_irq_sample_by_core_task(uint32_t lcore_id, uint32_t irq_task_id, int l)
{
	for (uint8_t task_id = 0; task_id < nb_irq_tasks; ++task_id) {
		if ((irq_task_stats_set[task_id].lcore_id == lcore_id) && (irq_task_stats_set[task_id].task_id == irq_task_id))
			return &irq_task_stats_set[task_id].sample[last_stat == l];
	}
	return NULL;
}

void stats_irq_reset(void)
{
	struct irq_task_stats *cur_task_stats;

	for (uint8_t task_id = 0; task_id < nb_irq_tasks; ++task_id) {
		cur_task_stats = &irq_task_stats_set[task_id];
		cur_task_stats->max_irq = 0;
		for (uint i = 0; i < IRQ_BUCKETS_COUNT; ++i) {
			cur_task_stats->irq[i] = 0;
		}
	}
}

void stats_irq_post_proc(void)
{
	for (uint8_t task_id = 0; task_id < nb_irq_tasks; ++task_id) {
		struct irq_task_stats *cur_task_stats = &irq_task_stats_set[task_id];
		struct irq_rt_stats *stats = cur_task_stats->stats;
		const struct irq_sample *last = &cur_task_stats->sample[last_stat];
		const struct irq_sample *prev = &cur_task_stats->sample[!last_stat];

		if (cur_task_stats->max_irq < last->max_irq)
			cur_task_stats->max_irq = last->max_irq;
		for (uint i = 0; i < IRQ_BUCKETS_COUNT; ++i) {
			cur_task_stats->irq[i] += last->irq[i] - prev->irq[i];
		}
		stats->max_irq = 0;
	}
}

void stats_irq_update(void)
{
	for (uint8_t task_id = 0; task_id < nb_irq_tasks; ++task_id) {
		struct irq_task_stats *cur_task_stats = &irq_task_stats_set[task_id];
		struct irq_rt_stats *stats = cur_task_stats->stats;
		struct irq_sample *sample = &cur_task_stats->sample[last_stat];

		sample->max_irq = stats->max_irq;
		for (uint i = 0; i < IRQ_BUCKETS_COUNT; ++i) {
			sample->irq[i] = stats->irq[i];
		}
	}
}

void stats_irq_init(void)
{
	struct lcore_cfg *lconf;
	uint32_t lcore_id;

	lcore_id = -1;
	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			struct task_args *targ = &lconf->targs[task_id];
			if (strcmp(targ->task_init->mode_str, "irq") == 0) {
				struct irq_rt_stats *stats = &((struct task_irq *)(lconf->tasks_all[task_id]))->stats;
				irq_task_stats_set[nb_irq_tasks].stats = stats;
				irq_task_stats_set[nb_irq_tasks].lcore_id = lcore_id;
				irq_task_stats_set[nb_irq_tasks++].task_id = task_id;
			}
		}
	}
}

uint64_t get_max_irq_stats_by_core_task(uint8_t lcore_id, uint8_t irq_task_id)
{
	for (uint8_t task_id = 0; task_id < nb_irq_tasks; ++task_id) {
		if ((irq_task_stats_set[task_id].lcore_id == lcore_id) && (irq_task_stats_set[task_id].task_id == irq_task_id))
			return (irq_task_stats_set[task_id].max_irq * 1000000) / rte_get_tsc_hz();
	}
	return -1;
}

uint64_t get_irq_stats_by_core_task(uint8_t lcore_id, uint8_t irq_task_id, int id)
{
	for (uint8_t task_id = 0; task_id < nb_irq_tasks; ++task_id) {
		if ((irq_task_stats_set[task_id].lcore_id == lcore_id) && (irq_task_stats_set[task_id].task_id == irq_task_id))
			return irq_task_stats_set[task_id].irq[id];
	}
	return -1;
}

uint64_t get_max_irq_stats(uint8_t task_id)
{
	return (irq_task_stats_set[task_id].max_irq * 1000000L) / rte_get_tsc_hz();
}

uint64_t get_irq_stats(uint8_t task_id, int bucket_id)
{
	return irq_task_stats_set[task_id].irq[bucket_id];
}
void get_irq_buckets_by_core_task(char *buf, uint8_t lcore_id, uint8_t irq_task_id)
{
	for (int i = 0; i < IRQ_BUCKETS_COUNT; i++) {
		sprintf(buf+strlen(buf), "%ld; ", irq_bucket_maxtime_micro[i]);
	}
	sprintf(buf+strlen(buf), "\n");
}
