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

#ifndef _HANDLE_AGGREGATOR_H_
#define _HANDLE_AGGREGATOR_H_

#include "task_base.h"
#include "task_init.h"
#include "stats_prio_task.h"

#define MAX_PRIORITIES  8
#define LOW_PRIORITY  (MAX_PRIORITIES - 1)
#define HIGH_PRIORITY  0
#define BUFFER_LENGTH   256

struct task_buffer {
	struct rte_mbuf *buffer[BUFFER_LENGTH];
	uint16_t pkt_pos;
	uint16_t pkt_nb;
};

struct task_aggregator {
	struct task_base    base;
	struct prio_task_rt_stats stats;
	struct task_buffer  priority[MAX_PRIORITIES];
	struct task_buffer  drop;
};

#endif /* _HANDLE_AGGREGATOR_H_ */
