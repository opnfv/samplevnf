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

#ifndef _STATS_L4GEN_H_
#define _STATS_L4GEN_H_

#include <inttypes.h>

#include "genl4_bundle.h"

struct task_l4gen_stats;

struct l4_stats_sample {
	uint64_t        tsc;
	struct l4_stats stats;
};

struct task_l4_stats {
	struct task_l4gen_stats *task;
	struct l4_stats_sample sample[2];
	uint8_t lcore_id;
	uint8_t task_id;
};

void stats_l4gen_init(void);
void stats_l4gen_update(void);
int stats_get_n_l4gen(void);
struct task_l4_stats *stats_get_l4_stats(uint32_t i);
struct l4_stats_sample *stats_get_l4_stats_sample(uint32_t i, int l);

#endif /* _STATS_L4GEN_H_ */
