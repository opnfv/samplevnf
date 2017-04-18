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

#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_etheraddr.h>

#include "app.h"
#include "pipeline_common_fe.h"
#include "pipeline_cgnapt.h"
#include "pipeline_cgnapt_common.h"
#include "cgnapt_pcp_fe.h"
#include "cgnapt_pcp_be.h"

#ifdef PCP_ENABLE

/**
 * @file
 * Pipeline CG-NAPT PCP FE Implementation.
 *
 * Implementation of Pipeline CG-NAPT PCP Front End (FE).
 * Provides CLI support.
 * Runs on master core.
 *
 */

void cmd_pcp_parsed(
	void *parsed_result,
	 __rte_unused struct cmdline *cl,
	void *data);
/**
 * A structure defining PCP cmd parse arguments.
 */
struct cmd_pcp_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t pcp_string;
	uint8_t cmd;
	uint32_t lifetime;
};

static cmdline_parse_token_string_t cmd_pcp_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_pcp_result, p_string, "p");

static cmdline_parse_token_num_t cmd_pcp_p =
TOKEN_NUM_INITIALIZER(struct cmd_pcp_result, p, UINT32);

static cmdline_parse_token_string_t cmd_pcp_string =
TOKEN_STRING_INITIALIZER(struct cmd_pcp_result,
			 pcp_string, "pcp");

static cmdline_parse_token_num_t cmd_pcp_cmd =
TOKEN_NUM_INITIALIZER(struct cmd_pcp_result, cmd, UINT8);

static cmdline_parse_token_num_t cmd_pcp_lifetime =
TOKEN_NUM_INITIALIZER(struct cmd_pcp_result, lifetime, UINT32);

cmdline_parse_inst_t cmd_pcp = {
	.f = cmd_pcp_parsed,
	.data = NULL,
	.help_str = "NAPT PCP cmd",
	.tokens = {
			 (void *) &cmd_pcp_p_string,
			 (void *) &cmd_pcp_p,
			 (void *) &cmd_pcp_string,
			 (void *) &cmd_pcp_cmd,
			 (void *) &cmd_pcp_lifetime,
			 NULL,
			 },
};

 /**
 * Function to send a PCP cmd message to BE
 *
 * @param app
 *  A pointer to pipeline app
 * @param pipeline_id
 *  Pipeline id
 * @param cmd
 *  PCP specific command whether to show stats,set to get lifetime
 * @param lifetime
 *      PCP entry lifetime
 * @return
 *  0 on success, negative on error.
 */
//#ifdef PCP_ENABLE
static int
app_pipeline_cgnapt_pcp(struct app_params *app,
			uint32_t pipeline_id, uint8_t cmd, uint32_t lifetime){

	struct pipeline_cgnapt *p;
	struct pipeline_cgnapt_pcp_msg_req *req;
	struct pipeline_cgnapt_pcp_msg_rsp *rsp;

	/* Check input arguments */
	if (app == NULL)
		return -1;

	p = app_pipeline_data_fe(app, pipeline_id,
			(struct pipeline_type *)&pipeline_cgnapt);
	if (p == NULL)
		return -1;

	/* Allocate and write request */
	req = app_msg_alloc(app);
	if (req == NULL)
		return -1;

	req->type = PIPELINE_MSG_REQ_CUSTOM;
	req->subtype = PIPELINE_CGNAPT_MSG_REQ_PCP;
	req->cmd = cmd;
	req->lifetime = lifetime;

	rsp = app_msg_send_recv(app, pipeline_id, req, MSG_TIMEOUT_DEFAULT);
	if (rsp == NULL)
		return -1;

	/* Read response */
	if (rsp->status) {
		app_msg_free(app, rsp);
		printf("Error rsp->status %d\n", rsp->status);
		return -1;
	}

	/* Free response */
	app_msg_free(app, rsp);

	return 0;
}

/**
 * Helping function for PCP cmd
 *
 * @param parsed_result
 *  A pointer parsed add arguments
 * @param cl
 *  unused pointer to struct cmdline
 * @param data
 *  void pointer data
 */
void
cmd_pcp_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	void *data)
{
	struct cmd_pcp_result *params = parsed_result;
	struct app_params *app = data;
	int status;

	status = app_pipeline_cgnapt_pcp(app, params->p, params->cmd,
			params->lifetime);

	if (status != 0) {
		printf("PCP Command failed\n");
		return;
	}
}

#endif
