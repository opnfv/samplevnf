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
#include "lconf.h"

static int init_port_sched(struct rte_sched_port **sched_port, struct task_args *targ)
{
	*sched_port = NULL;
#if RTE_VERSION >= RTE_VERSION_NUM(19,2,0,0)
	for (uint8_t idx = 0; idx < MAX_PROTOCOLS; ++idx) {
		for (uint8_t ring_idx = 0; ring_idx < targ->core_task_set[idx].n_elems; ++ring_idx) {
			struct core_task ct = targ->core_task_set[idx].core_task[ring_idx];
			struct task_args *dtarg = core_targ_get(ct.core, ct.task);
			enum task_mode dmode = dtarg->mode;
			if ((dmode == QOS)  || (dmode == POLICE)) {
				// Next task is QOS or POLICE
				// We use the same configuration as the QoS we are transmitting to
				*sched_port = rte_sched_port_config(&dtarg->qos_conf.port_params);
				plog_info("\tInitializing sched_port based on QoS config of core %d task %d\n", ct.core, ct.task);
				return 0;
			}
		}
	}
	return -1;
#endif
	return 0;
}
#endif
