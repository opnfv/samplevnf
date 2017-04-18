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

#ifndef THREAD_FE_H_
#define THREAD_FE_H_

static inline struct rte_ring *
app_thread_msgq_in_get(struct app_params *app,
		uint32_t socket_id, uint32_t core_id, uint32_t ht_id)
{
	char msgq_name[32];
	ssize_t param_idx;

	snprintf(msgq_name, sizeof(msgq_name),
		"MSGQ-REQ-CORE-s%" PRIu32 "c%" PRIu32 "%s",
		socket_id,
		core_id,
		(ht_id) ? "h" : "");
	param_idx = APP_PARAM_FIND(app->msgq_params, msgq_name);

	if (param_idx < 0)
		return NULL;

	return app->msgq[param_idx];
}

static inline struct rte_ring *
app_thread_msgq_out_get(struct app_params *app,
		uint32_t socket_id, uint32_t core_id, uint32_t ht_id)
{
	char msgq_name[32];
	ssize_t param_idx;

	snprintf(msgq_name, sizeof(msgq_name),
		"MSGQ-RSP-CORE-s%" PRIu32 "c%" PRIu32 "%s",
		socket_id,
		core_id,
		(ht_id) ? "h" : "");
	param_idx = APP_PARAM_FIND(app->msgq_params, msgq_name);

	if (param_idx < 0)
		return NULL;

	return app->msgq[param_idx];

}

int
app_pipeline_thread_cmd_push(struct app_params *app);

int
app_pipeline_enable(struct app_params *app,
		uint32_t core_id,
		uint32_t socket_id,
		uint32_t hyper_th_id,
		uint32_t pipeline_id);

int
app_pipeline_disable(struct app_params *app,
		uint32_t core_id,
		uint32_t socket_id,
		uint32_t hyper_th_id,
		uint32_t pipeline_id);

int
app_thread_headroom(struct app_params *app,
		uint32_t core_id,
		uint32_t socket_id,
		uint32_t hyper_th_id);

#endif /* THREAD_FE_H_ */
