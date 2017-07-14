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

#ifndef _LCONF_H_
#define _LCONF_H_

#include "task_init.h"
#include "stats.h"

enum lconf_msg_type {
	LCONF_MSG_STOP,
	LCONF_MSG_START,
	LCONF_MSG_DUMP,
	LCONF_MSG_TRACE,
	LCONF_MSG_DUMP_RX,
	LCONF_MSG_DUMP_TX,
	LCONF_MSG_RX_DISTR_START,
	LCONF_MSG_RX_DISTR_STOP,
	LCONF_MSG_RX_DISTR_RESET,
	LCONF_MSG_TX_DISTR_START,
	LCONF_MSG_TX_DISTR_STOP,
	LCONF_MSG_TX_DISTR_RESET,
	LCONF_MSG_RX_BW_START,
	LCONF_MSG_RX_BW_STOP,
	LCONF_MSG_TX_BW_START,
	LCONF_MSG_TX_BW_STOP,
};

struct lconf_msg {
	/* Set by master core (if not set), unset by worker after consumption. */
	uint32_t            req;
	enum lconf_msg_type type;
	int                 task_id;
	int                 val;
};

#define LCONF_FLAG_RX_DISTR_ACTIVE 0x00000001
#define LCONF_FLAG_RUNNING         0x00000002
#define LCONF_FLAG_TX_DISTR_ACTIVE 0x00000004
#define LCONF_FLAG_RX_BW_ACTIVE    0x00000008
#define LCONF_FLAG_TX_BW_ACTIVE    0x00000010

struct lcore_cfg {
	/* All tasks running at the moment. This is empty when the core is stopped. */
	struct task_base	*tasks_run[MAX_TASKS_PER_CORE];
	uint8_t			n_tasks_run;

	void (*flush_queues[MAX_TASKS_PER_CORE])(struct task_base *tbase);

	void (*period_func)(void *data);
	void                    *period_data;
	/* call periodic_func after periodic_timeout cycles */
	uint64_t                period_timeout;

	uint64_t                ctrl_timeout;
	void (*ctrl_func_m[MAX_TASKS_PER_CORE])(struct task_base *tbase, void **data, uint16_t n_msgs);
	struct rte_ring         *ctrl_rings_m[MAX_TASKS_PER_CORE];

	void (*ctrl_func_p[MAX_TASKS_PER_CORE])(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts);
	struct rte_ring         *ctrl_rings_p[MAX_TASKS_PER_CORE];

	struct lconf_msg        msg __attribute__((aligned(4)));
	struct task_base	*tasks_all[MAX_TASKS_PER_CORE];
	int                     task_is_running[MAX_TASKS_PER_CORE];
	uint8_t			n_tasks_all;
	pthread_t		thread_id;

	/* Following variables are not accessed in main loop */
	uint32_t		flags;
	uint8_t			active_task;
	uint8_t			id;
	char			name[MAX_NAME_SIZE];
	struct task_args        targs[MAX_TASKS_PER_CORE];
	int (*thread_x)(struct lcore_cfg *lconf);
	uint32_t		cache_set;
} __rte_cache_aligned;

extern struct lcore_cfg     *lcore_cfg;
extern struct lcore_cfg      lcore_cfg_init[];

/* This function is only run on low load (when no bulk was sent within
   last drain_timeout (16kpps if DRAIN_TIMEOUT = 2 ms) */
static inline void lconf_flush_all_queues(struct lcore_cfg *lconf)
{
	struct task_base *task;

	for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
		task = lconf->tasks_all[task_id];
		if (!(task->flags & FLAG_TX_FLUSH) || (task->flags & FLAG_NEVER_FLUSH)) {
			task->flags |= FLAG_TX_FLUSH;
			continue;
		}
		lconf->flush_queues[task_id](task);
	}
}

static inline void lconf_set_req(struct lcore_cfg *lconf)
{
	(*(volatile uint32_t *)&lconf->msg.req) = 1;
}

static inline void lconf_unset_req(struct lcore_cfg *lconf)
{
	(*(volatile uint32_t *)&lconf->msg.req) = 0;
}

static inline int lconf_is_req(struct lcore_cfg *lconf)
{
	return (*(volatile uint32_t *)&lconf->msg.req);
}

/* Returns non-zero when terminate has been requested */
int lconf_do_flags(struct lcore_cfg *lconf);

int lconf_get_task_id(const struct lcore_cfg *lconf, const struct task_base *task);
int lconf_task_is_running(const struct lcore_cfg *lconf, uint8_t task_id);

int lconf_run(void *dummy);

void lcore_cfg_alloc_hp(void);

/* Returns the next active lconf/targ pair. If *lconf = NULL, the
   first active lconf/targ pair is returned. If the last lconf/targ
   pair is passed, the function returns non-zero. */
int core_targ_next(struct lcore_cfg **lconf, struct task_args **targ, const int with_master);
/* Same as above, but uses non-huge page memory (used before
   lcore_cfg_alloc_hp is called). */
int core_targ_next_early(struct lcore_cfg **lconf, struct task_args **targ, const int with_master);

struct task_args *core_targ_get(uint32_t lcore_id, uint32_t task_id);

#endif /* _LCONF_H_ */
