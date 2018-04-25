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

#include <rte_mbuf.h>
#include <rte_cycles.h>

#include "task_base.h"
#include "task_init.h"
#include "thread_generic.h"

struct task_tsc {
	struct task_base base;
};

static int handle_bulk_tsc(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_tsc *task = (struct task_tsc *)tbase;
	const uint64_t rx_tsc = rte_rdtsc();

	for (uint16_t j = 0; j < n_pkts; ++j)
		mbufs[j]->udata64 = rx_tsc;

	return task->base.tx_pkt(&task->base, mbufs, n_pkts, NULL);
}

static struct task_init task_init = {
	.mode_str = "tsc",
	.init = NULL,
	.handle = handle_bulk_tsc,
	.flag_features = TASK_FEATURE_NEVER_DISCARDS|TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS|TASK_FEATURE_THROUGHPUT_OPT,
	.size = sizeof(struct task_tsc),
};

__attribute__((constructor)) static void reg_task_nop(void)
{
	reg_task(&task_init);
}
