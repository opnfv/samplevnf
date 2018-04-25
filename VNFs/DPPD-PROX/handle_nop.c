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

#include "handle_nop.h"
#include "thread_nop.h"

static struct task_init task_init_nop_thrpt_opt = {
	.mode_str = "nop",
	.init = NULL,
	.handle = handle_nop_bulk,
	.thread_x = thread_nop,
	.flag_features = TASK_FEATURE_NEVER_DISCARDS|TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS|TASK_FEATURE_THROUGHPUT_OPT|TASK_FEATURE_MULTI_RX,
	.size = sizeof(struct task_nop),
};

static struct task_init task_init_nop_lat_opt = {
	.mode_str = "nop",
	.sub_mode_str = "latency optimized",
	.init = NULL,
	.handle = handle_nop_bulk,
	.thread_x = thread_nop,
	.flag_features = TASK_FEATURE_NEVER_DISCARDS|TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS|TASK_FEATURE_MULTI_RX,
	.size = sizeof(struct task_nop),
};

static struct task_init task_init_none;

__attribute__((constructor)) static void reg_task_nop(void)
{
	reg_task(&task_init_nop_thrpt_opt);
	reg_task(&task_init_nop_lat_opt);

	/* For backwards compatibility, add none */
	task_init_none = task_init_nop_thrpt_opt;
	strcpy(task_init_none.mode_str, "none");

	reg_task(&task_init_none);
}
