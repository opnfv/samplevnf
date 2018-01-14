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

#ifndef _HANDLE_IRQ_H_
#define _HANDLE_IRQ_H_

#include "task_base.h"
#include "stats_irq.h"

#define MAX_INDEX	65535 * 16

struct irq_info {
	uint64_t tsc;
	uint64_t lat;
};

struct irq_bucket {
	uint64_t index;
	struct irq_info info[MAX_INDEX];
};

struct task_irq {
	struct task_base base;
	uint64_t start_tsc;
	uint64_t first_tsc;
	uint64_t tsc;
	uint64_t max_irq;
	uint8_t  lcore_id;
	uint8_t  irq_debug;
	volatile uint16_t stats_use_lt; /* which lt to use, */
	volatile uint16_t task_use_lt; /* 0 or 1 depending on which of the 2 result records are used */
	struct irq_bucket buffer[2];
	struct irq_rt_stats stats;
};

struct input;

void task_irq_show_stats(struct task_irq *task_irq, struct input *input);

#endif /* _HANDLE_IRQ_H_ */
