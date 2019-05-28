/*
// Copyright (c) 2019 Intel Corporation
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

#ifndef _PROX_SCHED_H
#define _PROX_SCHED_H

#include "task_init.h"

static void init_port_sched(struct rte_sched_port **sched_port, struct task_args *targ)
{
#if RTE_VERSION >= RTE_VERSION_NUM(19,2,0,0)
	for (uint8_t task_id = 0; task_id < targ->lconf->n_tasks_all; ++task_id) {
		struct task_args *one_targ, *starg;
		one_targ = &targ->lconf->targs[task_id];
		for (unsigned int i = 0; i < one_targ->n_prev_tasks; i++) {
			starg = one_targ->prev_tasks[i];
			enum task_mode smode = one_targ->mode;
			if ((starg == targ) && (smode == QOS))  {
				// We are the previous task and next task is QOS
				// We use the same configuration as the QoS we are transmitting to
				*sched_port = rte_sched_port_config(&one_targ->qos_conf.port_params);
				break;
			}
		}
	}
	PROX_PANIC(*sched_port == NULL, "Did not find any QoS task to transmit to => undefined sched_port parameters");
#endif
}
#endif
