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

#include "prox_malloc.h"
#include "prox_cfg.h"
#include "stats.h"
#include "stats_port.h"
#include "stats_mempool.h"
#include "stats_ring.h"
#include "stats_l4gen.h"
#include "stats_latency.h"
#include "stats_global.h"
#include "stats_core.h"
#include "stats_task.h"
#include "stats_prio_task.h"
#include "stats_latency.h"
#include "stats_irq.h"

/* Stores all readed values from the cores, displaying is done afterwards because
   displaying introduces overhead. If displaying was done right after the values
   are read, inaccuracy is introduced for later cores */
int last_stat; /* 0 or 1 to track latest 2 measurements */

void stats_reset(void)
{
	stats_task_reset();
	stats_prio_task_reset();
	stats_port_reset();
	stats_latency_reset();
	stats_irq_reset();
	stats_global_reset();
}

void stats_init(unsigned avg_start, unsigned duration)
{
	stats_lcore_init();
	stats_task_init();
	stats_prio_task_init();
	stats_irq_init();
	stats_port_init();
	stats_mempool_init();
	stats_latency_init();
	stats_l4gen_init();
	stats_ring_init();
	stats_global_init(avg_start, duration);
}

void stats_update(uint16_t flag_cons)
{
	/* Keep track of last 2 measurements. */
	last_stat = !last_stat;

	if (flag_cons & STATS_CONS_F_TASKS)
		stats_task_update();

	if (flag_cons & STATS_CONS_F_PRIO_TASKS)
		stats_prio_task_update();

	if (flag_cons & STATS_CONS_F_LCORE)
		stats_lcore_update();

	if (flag_cons & STATS_CONS_F_PORTS)
		stats_port_update();

	if (flag_cons & STATS_CONS_F_MEMPOOLS)
		stats_mempool_update();

	if (flag_cons & STATS_CONS_F_LATENCY)
		stats_latency_update();

	if (flag_cons & STATS_CONS_F_L4GEN)
		stats_l4gen_update();

	if (flag_cons & STATS_CONS_F_RINGS)
		stats_ring_update();

	if (flag_cons & STATS_CONS_F_IRQ)
		stats_irq_update();

	if (flag_cons & STATS_CONS_F_LCORE)
		stats_lcore_post_proc();

	if (flag_cons & STATS_CONS_F_TASKS)
		stats_task_post_proc();

	if (flag_cons & STATS_CONS_F_PRIO_TASKS)
		stats_prio_task_post_proc();

	if (flag_cons & STATS_CONS_F_GLOBAL)
		stats_global_post_proc();

	if (flag_cons & STATS_CONS_F_IRQ)
		stats_irq_post_proc();
}
