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

#ifndef _HANDLE_NOP_H_
#define _HANDLE_NOP_H_

#include "task_base.h"
#include "task_init.h"

struct task_nop {
	struct task_base base;
};

static inline int handle_nop_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_nop *task = (struct task_nop *)tbase;
	return task->base.tx_pkt(&task->base, mbufs, n_pkts, NULL);
}

#endif /* _HANDLE_NOP_H_ */
