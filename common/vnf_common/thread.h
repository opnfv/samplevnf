/*
// Copyright (c) 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef THREAD_H_
#define THREAD_H_

#include "app.h"
#include "pipeline_be.h"

enum thread_msg_req_type {
	THREAD_MSG_REQ_PIPELINE_ENABLE = 0,
	THREAD_MSG_REQ_PIPELINE_DISABLE,
	THREAD_MSG_REQ_HEADROOM_READ,
	THREAD_MSG_REQS
};

struct thread_msg_req {
	enum thread_msg_req_type type;
};

struct thread_msg_rsp {
	int status;
};

/*
 * PIPELINE ENABLE
 */
struct thread_pipeline_enable_msg_req {
	enum thread_msg_req_type type;

	uint32_t pipeline_id;
	void *be;
	pipeline_be_op_run f_run;
	pipeline_be_op_timer f_timer;
	uint64_t timer_period;
};

struct thread_pipeline_enable_msg_rsp {
	int status;
};

/*
 * PIPELINE DISABLE
 */
struct thread_pipeline_disable_msg_req {
	enum thread_msg_req_type type;

	uint32_t pipeline_id;
};

struct thread_pipeline_disable_msg_rsp {
	int status;
};

/*
 * THREAD HEADROOM
 */
struct thread_headroom_read_msg_req {
	enum thread_msg_req_type type;
};

struct thread_headroom_read_msg_rsp {
	int status;

	double headroom_ratio;
};

#endif /* THREAD_H_ */
