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

#include <rte_cycles.h>

#include "log.h"
#include "lconf.h"
#include "thread_nop.h"
#include "handle_nop.h"
#include "stats.h"
#include "lconf.h"
#include "defines.h"

int thread_nop(struct lcore_cfg *lconf)
{
	struct task_base *tasks[MAX_TASKS_PER_CORE];
	struct rte_mbuf **mbufs;
	uint64_t cur_tsc = rte_rdtsc();
	uint64_t term_tsc = cur_tsc;
	uint64_t drain_tsc = cur_tsc;
	uint8_t n_tasks_run = 0;

	for (;;) {
		cur_tsc = rte_rdtsc();
		if (cur_tsc > term_tsc) {
			term_tsc = cur_tsc + TERM_TIMEOUT;
			if (lconf_is_req(lconf) && lconf_do_flags(lconf)) {
				n_tasks_run = lconf->n_tasks_run;

				if (!n_tasks_run)
					return 0;
				for (int i = 0; i < lconf->n_tasks_run; ++i) {
					tasks[i] = lconf->tasks_run[i];
				}
			}
		}
		if (cur_tsc > drain_tsc) {
			drain_tsc = cur_tsc + DRAIN_TIMEOUT;
			lconf_flush_all_queues(lconf);
		}

		for (uint8_t task_id = 0; task_id < n_tasks_run; ++task_id) {
			struct task_base *t = tasks[task_id];
			uint16_t nb_rx = t->rx_pkt(t, &mbufs);

			if (likely(nb_rx)) {
				handle_nop_bulk(t, mbufs, nb_rx);
			}
		}
	}

	return 0;
}
