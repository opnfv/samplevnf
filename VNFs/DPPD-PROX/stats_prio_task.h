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

#ifndef _STATS_PRIO_TASK_H_
#define _STATS_PRIO_TASK_H_

#include <inttypes.h>

#include "clock.h"

struct prio_task_stats_sample {
	uint64_t tsc;
	uint64_t drop_tx_fail_prio[8];
	uint64_t rx_prio[8];
};

struct prio_task_rt_stats {
	uint64_t drop_tx_fail_prio[8];
	uint64_t rx_prio[8];
};

struct prio_task_stats {
	uint64_t tot_drop_tx_fail_prio[8];
	uint64_t tot_rx_prio[8];
	uint8_t lcore_id;
	uint8_t task_id;
	struct prio_task_stats_sample sample[2];
	struct prio_task_rt_stats *stats;
};

int stats_get_n_prio_tasks_tot(void);
void stats_prio_task_reset(void);
void stats_prio_task_post_proc(void);
void stats_prio_task_update(void);
void stats_prio_task_init(void);

struct prio_task_stats_sample *stats_get_prio_task_stats_sample(uint32_t task_id, int last);
struct prio_task_stats_sample *stats_get_prio_task_stats_sample_by_core_task(uint32_t lcore_id, uint32_t task_id, int last);
uint64_t stats_core_task_tot_drop_tx_fail_prio(uint8_t task_id, uint8_t prio);
uint64_t stats_core_task_tot_rx_prio(uint8_t task_id, uint8_t prio);

#endif /* _STATS_PRIO_TASK_H_ */
