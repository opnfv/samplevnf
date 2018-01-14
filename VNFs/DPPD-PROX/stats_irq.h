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

#ifndef _STATS_IRQ_H_
#define _STATS_IRQ_H_

#include <inttypes.h>

#include "clock.h"

#define IRQ_BUCKETS_COUNT      13

extern int last_stat;

// irq_rt_stats is updated real time by handle_irq. It contains total stats, from beginning
// It cannot be reset to 0, as the reset would be done by another core
struct irq_rt_stats {
        uint64_t max_irq;
	uint64_t irq[IRQ_BUCKETS_COUNT];
};

// irq_sample is updated by irq_update - as sampling of irq_rt_stats
// There is usually one sample per second; two samples in total
struct irq_sample {
	uint64_t tsc;
	uint64_t max_irq;
	uint64_t irq[IRQ_BUCKETS_COUNT];
};

// Those are the total stats; there can be reset
// They are obtained by adding samples
struct irq_task_stats {
	uint8_t lcore_id;
	uint8_t task_id;
	uint64_t max_irq;
	uint64_t irq[IRQ_BUCKETS_COUNT];
	struct irq_sample sample[2];
	struct irq_rt_stats *stats;
};

uint64_t irq_bucket_maxtime_cycles[IRQ_BUCKETS_COUNT];
extern uint64_t irq_bucket_maxtime_micro[];

void stats_irq_reset(void);
void stats_irq_post_proc(void);
void stats_irq_update(void);
void stats_irq_init(void);
int stats_get_n_irq_tasks(void);

struct irq_sample *get_irq_sample(uint32_t task_id, int last);
struct irq_sample *get_irq_sample_by_core_task(uint32_t lcore_id, uint32_t task_id, int last);
uint64_t get_max_irq_stats(uint8_t task_id);
uint64_t get_irq_stats(uint8_t task_id, int bucket_id);
uint64_t get_max_irq_stats_by_core_task(uint8_t lcore_id, uint8_t task_id);
uint64_t get_irq_stats_by_core_task(uint8_t lcore_id, uint8_t task_id, int bucket_id);
void get_irq_buckets_by_core_task(char *buf, uint8_t lcore_id, uint8_t irq_task_id);

#endif /* _STATS_IRQ_H_ */
