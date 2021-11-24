/*
// Copyright (c) 2010-2018 Intel Corporation
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

#ifndef _HANDLE_SOFTNIC_H_
#define _HANDLE_SOFTNIC_H_
#include <rte_eth_softnic.h>
#include <rte_byteorder.h>

#include "task_base.h"
#include "task_init.h"

struct task_softnic {
	struct task_base base;
};

/*static inline int handle_softnic_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	int returnvalue;
	struct task_softnic *task = (struct task_softnic *)tbase;
	returnvalue = task->base.tx_pkt(&task->base, mbufs, n_pkts, NULL);
	rte_pmd_softnic_run(tbase->tx_params_hw.tx_port_queue->port);
	return returnvalue;
}
Moved this code to c file
*/
#endif /* _HANDLE_SOFTNIC_H_ */
