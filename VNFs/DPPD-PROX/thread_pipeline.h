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

#ifndef _THREAD_PIPELINE_H_
#define _THREAD_PIPELINE_H_

#include <rte_pipeline.h>

#include "lconf.h"
#include "task_base.h"

/* Tasks based on Packet Framework pipelines */
struct task_pipe {
	struct task_base base;

	struct rte_pipeline *p;
	uint32_t port_in_id[MAX_RINGS_PER_TASK];
	uint32_t port_out_id[MAX_RINGS_PER_TASK];
	uint32_t table_id[MAX_RINGS_PER_TASK];
	uint8_t n_ports_in;
	uint8_t n_ports_out;
	uint8_t n_tables;
};

/* Helper function: create pipeline, input ports and output ports */
void init_pipe_create_in_out(struct task_pipe *tpipe, struct task_args *targ);

/* Helper function: connect pipeline input ports to one pipeline table */
void init_pipe_connect_one(struct task_pipe *tpipe, struct task_args *targ, uint32_t table_id);

/* Helper function: connect pipeline input ports to all pipeline tables */
void init_pipe_connect_all(struct task_pipe *tpipe, struct task_args *targ);

/* Helper function: enable pipeline input ports */
void init_pipe_enable(struct task_pipe *tpipe, struct task_args *targ);

/* Helper function: check pipeline consistency */
void init_pipe_check(struct task_pipe *tpipe, struct task_args *targ);

/* This function will panic on purpose: tasks based on Packet Framework
   pipelines should not be invoked via the usual task_base.handle_bulk method */
int handle_pipe(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts);

/* The pipeline thread can only run tasks based on Packet Framework pipelines */
int thread_pipeline(struct lcore_cfg *lconf);

#endif /* _THREAD_PIPELINE_H_ */
