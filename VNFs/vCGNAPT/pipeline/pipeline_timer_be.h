/*
// Copyright (c) 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef __INCLUDE_PIPELINE_TIMER_BE_H__
#define __INCLUDE_PIPELINE_TIMER_BE_H__

#include <rte_timer.h>
#include "pipeline_cgnapt_be.h"
#include "pipeline_common_be.h"
#include "pipeline_cgnapt_common.h"

extern struct pipeline_be_ops pipeline_timer_be_ops;
/*uint8_t  timer_ring_init;*/
struct rte_ring *timer_ring;
extern struct rte_mempool *timer_mempool;

extern struct rte_mempool *timer_key_mempool;
/*static int timer_objs_mempool_count = 70000;*/
/*static int timer_ring_alloc_cnt = 4096;*/
extern uint64_t cgnapt_timeout;
extern uint32_t timer_lcore;

/* one timer entry created for pair of egress and ingress entry */
struct timer_key {
	struct pipeline_cgnapt_entry_key egress_key, ingress_key;
	struct cgnapt_table_entry *egress_entry, *ingress_entry;
	struct pipeline *p_nat;
} __rte_cache_aligned;

/******* Function declarations ********/

void cgnapt_entry_delete(struct rte_timer *tim, void *arg);

void timer_thread_enqueue(struct pipeline_cgnapt_entry_key *egress_key,
				struct pipeline_cgnapt_entry_key *ingress_key,
				struct cgnapt_table_entry *egress_entry,
				struct cgnapt_table_entry *ingress_entry,
				struct pipeline *p_nat);

void timer_thread_dequeue(void);
extern uint64_t nextPowerOf2(uint64_t n);
#endif
