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

#include <rte_table_stub.h>	//FIXME: ACL

#include "log.h"
#include "quit.h"
#include "thread_pipeline.h"

struct task_pf_acl {
	struct task_pipe pipe;
	//TODO
};

static void init_task_pf_acl(struct task_base *tbase, struct task_args *targ)
{
	struct task_pipe *tpipe = (struct task_pipe *)tbase;
//	struct task_pf_acl *task = (struct task_pf_acl *)tpipe;
	int err;

	/* create pipeline, input ports and output ports */
	init_pipe_create_in_out(tpipe, targ);

	/* create ACL pipeline table */
	//TODO

//FIXME: this is not ACL (
	/* create pipeline tables */
	for (uint8_t i = 0; i < tpipe->n_ports_in; ++i) {
		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_stub_ops,
			.arg_create = NULL,
			.f_action_hit = NULL,
			.f_action_miss = NULL,
			.arg_ah = NULL,
			.action_data_size = 0,
		};
		err = rte_pipeline_table_create(tpipe->p, &table_params,
				&tpipe->table_id[i]);
		PROX_PANIC(err != 0, "Failed to create table %u "
				"for %s pipeline on core %u task %u: "
				"err = %d\n",
				i, targ->task_init->mode_str,
				targ->lconf->id, targ->task,
				err);
	}
	tpipe->n_tables = tpipe->n_ports_in;
	PROX_PANIC(tpipe->n_tables < 1, "No table created "
			"for %s pipeline on core %u task %u\n",
			targ->task_init->mode_str, targ->lconf->id, targ->task);

	/* add default entry to tables */
	for (uint8_t i = 0; i < tpipe->n_tables; ++i) {
		struct rte_pipeline_table_entry default_entry = {
			.action = RTE_PIPELINE_ACTION_PORT,
			{.port_id = tpipe->port_out_id[i % tpipe->n_ports_out]},
		};
		struct rte_pipeline_table_entry *default_entry_ptr;
		err = rte_pipeline_table_default_entry_add(tpipe->p, tpipe->table_id[i],
				&default_entry, &default_entry_ptr);
		PROX_PANIC(err != 0, "Failed to add default entry to table %u "
				"for %s pipeline on core %u task %u: "
				"err = %d\n",
				i, targ->task_init->mode_str,
				targ->lconf->id, targ->task,
				err);
	}
//FIXME: this is not ACL )

	/* connect pipeline input ports to ACL pipeline table */
	init_pipe_connect_one(tpipe, targ, tpipe->table_id[0]);

	/* enable pipeline input ports */
	init_pipe_enable(tpipe, targ);

	/* check pipeline consistency */
	init_pipe_check(tpipe, targ);
}

static struct task_init task_init_pf_acl = {
	.mode_str = "pf_acl",
	.init = init_task_pf_acl,
	.handle = handle_pipe,
	.thread_x = thread_pipeline,
	.size = sizeof(struct task_pf_acl),
};

__attribute__((constructor)) static void reg_task_pf_acl(void)
{
	reg_task(&task_init_pf_acl);
}
