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

#ifndef __INCLUDE_PIPELINE_COMMON_FE_H__
#define __INCLUDE_PIPELINE_COMMON_FE_H__

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <cmdline_parse.h>

#include "pipeline_common_be.h"
#include "pipeline.h"
#include "app.h"

#ifndef MSG_TIMEOUT_DEFAULT
#define MSG_TIMEOUT_DEFAULT                      1000
#endif
struct app_link_params mylink[APP_MAX_LINKS];
static inline struct app_pipeline_data *
app_pipeline_data(struct app_params *app, uint32_t id)
{
	struct app_pipeline_params *params;

	APP_PARAM_FIND_BY_ID(app->pipeline_params, "PIPELINE", id, params);
	if (params == NULL)
		return NULL;

	return &app->pipeline_data[params - app->pipeline_params];
}

static inline void *
app_pipeline_data_fe(struct app_params *app, uint32_t id, struct pipeline_type *ptype)
{
	struct app_pipeline_data *pipeline_data;

	pipeline_data = app_pipeline_data(app, id);
	if (pipeline_data == NULL)
		return NULL;

	if (strcmp(pipeline_data->ptype->name, ptype->name) != 0)
		return NULL;

	if (pipeline_data->enabled == 0)
		return NULL;

	return pipeline_data->fe;
}

static inline struct rte_ring *
app_pipeline_msgq_in_get(struct app_params *app,
	uint32_t pipeline_id)
{
	struct app_msgq_params *p;

	APP_PARAM_FIND_BY_ID(app->msgq_params,
		"MSGQ-REQ-PIPELINE",
		pipeline_id,
		p);
	if (p == NULL)
		return NULL;

	return app->msgq[p - app->msgq_params];
}

static inline struct rte_ring *
app_pipeline_msgq_out_get(struct app_params *app,
	uint32_t pipeline_id)
{
	struct app_msgq_params *p;

	APP_PARAM_FIND_BY_ID(app->msgq_params,
		"MSGQ-RSP-PIPELINE",
		pipeline_id,
		p);
	if (p == NULL)
		return NULL;

	return app->msgq[p - app->msgq_params];
}

static inline void *
app_msg_alloc(__rte_unused struct app_params *app)
{
	return rte_malloc(NULL, 2048, RTE_CACHE_LINE_SIZE);
}

static inline void
app_msg_free(__rte_unused struct app_params *app,
	void *msg)
{
	rte_free(msg);
}

static inline void
app_msg_send(struct app_params *app,
	uint32_t pipeline_id,
	void *msg)
{
	struct rte_ring *r = app_pipeline_msgq_in_get(app, pipeline_id);
	int status;

	do {
		status = rte_ring_sp_enqueue(r, msg);
	} while (status == -ENOBUFS);
}

static inline void *
app_msg_recv(struct app_params *app,
	uint32_t pipeline_id)
{
	struct rte_ring *r = app_pipeline_msgq_out_get(app, pipeline_id);
	void *msg;
	int status = rte_ring_sc_dequeue(r, &msg);

	if (status != 0)
		return NULL;

	return msg;
}

static inline void *
app_msg_send_recv(struct app_params *app,
	uint32_t pipeline_id,
	void *msg,
	uint32_t timeout_ms)
{
	struct rte_ring *r_req = app_pipeline_msgq_in_get(app, pipeline_id);
	struct rte_ring *r_rsp = app_pipeline_msgq_out_get(app, pipeline_id);
	uint64_t hz = rte_get_tsc_hz();
	void *msg_recv = NULL;
	uint64_t deadline;
	int status = 0;

	/* send */
	do {
                if(r_req)
		status = rte_ring_sp_enqueue(r_req, (void *) msg);
	} while (status == -ENOBUFS);

	/* recv */
	deadline = (timeout_ms) ?
		(rte_rdtsc() + ((hz * timeout_ms) / 1000)) :
		UINT64_MAX;

	do {
		if (rte_rdtsc() > deadline)
			return NULL;
                 if (r_rsp)
		status = rte_ring_sc_dequeue(r_rsp, &msg_recv);
	} while (status != 0);

	return msg_recv;
}

int
app_pipeline_ping(struct app_params *app,
	uint32_t pipeline_id);

int
app_pipeline_stats_port_in(struct app_params *app,
	uint32_t pipeline_id,
	uint32_t port_id,
	struct rte_pipeline_port_in_stats *stats);

int
app_pipeline_stats_port_out(struct app_params *app,
	uint32_t pipeline_id,
	uint32_t port_id,
	struct rte_pipeline_port_out_stats *stats);

int
app_pipeline_stats_table(struct app_params *app,
	uint32_t pipeline_id,
	uint32_t table_id,
	struct rte_pipeline_table_stats *stats);

int
app_pipeline_port_in_enable(struct app_params *app,
	uint32_t pipeline_id,
	uint32_t port_id);

int
app_pipeline_port_in_disable(struct app_params *app,
	uint32_t pipeline_id,
	uint32_t port_id);

int
app_link_config(struct app_params *app,
	uint32_t link_id,
	uint32_t ip,
	uint32_t depth);

int
app_link_up(struct app_params *app,
	uint32_t link_id);

int
app_link_down(struct app_params *app,
	uint32_t link_id);

int
app_pipeline_common_cmd_push(struct app_params *app);


void convert_prefixlen_to_netmask_ipv6(uint32_t depth, uint8_t netmask_ipv6[]);

void
get_host_portion_ipv6(uint8_t ipv6[], uint8_t netmask[], uint8_t host_ipv6[]);

void
get_bcast_portion_ipv6(uint8_t host[], uint8_t netmask[], uint8_t bcast_ipv6[]);

int
app_link_config_ipv6(struct app_params *app,
				 uint32_t link_id, uint8_t ipv6[], uint32_t depth);

#endif
