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

#ifndef _STATS_LATENCY_H_
#define _STATS_LATENCY_H_

#include <inttypes.h>

#include "handle_lat.h"

struct stats_latency {
	struct time_unit_err avg;
	struct time_unit_err min;
	struct time_unit_err max;
	struct time_unit_err stddev;

	struct time_unit accuracy_limit;
	uint64_t         lost_packets;
	uint64_t         tot_packets;
	uint64_t         tot_all_packets;
};

uint32_t stats_latency_get_core_id(uint32_t i);
uint32_t stats_latency_get_task_id(uint32_t i);
struct stats_latency *stats_latency_get(uint32_t i);
struct stats_latency *stats_latency_find(uint32_t lcore_id, uint32_t task_id);

struct stats_latency *stats_latency_tot_get(uint32_t i);
struct stats_latency *stats_latency_tot_find(uint32_t lcore_id, uint32_t task_id);

void stats_latency_init(void);
void stats_latency_update(void);
void stats_latency_reset(void);

int stats_get_n_latency(void);

#ifdef LATENCY_HISTOGRAM
void stats_core_lat_histogram(uint8_t lcore_id, uint8_t task_id, uint64_t **buckets);
#endif

#endif /* _STATS_LATENCY_H_ */
