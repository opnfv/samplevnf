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

#include <rte_ip.h>

#include "task_base.h"
#include "task_init.h"
#include "defines.h"
#include "prefetch.h"
#include "log.h"

struct task_read {
	struct task_base    base;
};

static int handle_read_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_read *task = (struct task_read *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint16_t j;
	uint64_t *first;

#ifdef PROX_PREFETCH_OFFSET
	for (j = 0; j < PROX_PREFETCH_OFFSET && j < n_pkts; ++j) {
		PREFETCH0(mbufs[j]);
	}
	for (j = 1; j < PROX_PREFETCH_OFFSET && j < n_pkts; ++j) {
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j - 1], void *));
	}
#endif
	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef PROX_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		first = rte_pktmbuf_mtod(mbufs[j], uint64_t *);
		out[j] = *first != 0? 0: OUT_DISCARD;
	}
#ifdef PROX_PREFETCH_OFFSET
	prefetch_nta(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		first = rte_pktmbuf_mtod(mbufs[j], uint64_t *);
		out[j] = *first != 0? 0: OUT_DISCARD;
	}
#endif

	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static void init_task_read(__attribute__((unused)) struct task_base *tbase,
			   __attribute__((unused)) struct task_args *targ)
{
}

static struct task_init task_init_read = {
	.mode_str = "read",
	.init = init_task_read,
	.handle = handle_read_bulk,
	.size = sizeof(struct task_read)
};

__attribute__((constructor)) static void reg_task_read(void)
{
	reg_task(&task_init_read);
}
