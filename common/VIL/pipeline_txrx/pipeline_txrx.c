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
#include "pipeline_txrx.h"
#include "vnf_common.h"
//#include "lib_arp.h"
#include "pipeline_arpicmp_be.h"

static int
app_pipeline_txrx_entry_dbg(struct app_params *app,
					uint32_t pipeline_id, uint8_t *msg)
{
	struct pipeline_txrx_entry_dbg_msg_req *req;
	struct pipeline_txrx_entry_dbg_msg_rsp *rsp;

	/* Check input arguments */
	if (app == NULL)
		return -1;

	/* Allocate and write request */
	req = app_msg_alloc(app);
	if (req == NULL)
		return -1;

	req->type = PIPELINE_MSG_REQ_CUSTOM;
	req->subtype = PIPELINE_TXRX_MSG_REQ_ENTRY_DBG;
	req->data[0] = msg[0];
	req->data[1] = msg[1];

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

/*
 * entry dbg
 */


struct cmd_entry_dbg_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t entry_string;
	cmdline_fixed_string_t dbg_string;
	uint8_t cmd;
	uint8_t d1;
};

static void
cmd_entry_dbg_parsed(void *parsed_result,
				 __rte_unused struct cmdline *cl, void *data)
{
	struct cmd_entry_dbg_result *params = parsed_result;
	struct app_params *app = data;
	uint8_t msg[2];
	int status;

	msg[0] = params->cmd;
	msg[1] = params->d1;
	status = app_pipeline_txrx_entry_dbg(app, params->p, msg);

	if (status != 0) {
		printf("Dbg Command failed\n");
		return;
	}
}

static cmdline_parse_token_string_t lb_cmd_entry_dbg_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_dbg_result, p_string, "p");

static cmdline_parse_token_num_t lb_cmd_entry_dbg_p =
TOKEN_NUM_INITIALIZER(struct cmd_entry_dbg_result, p, UINT32);

static cmdline_parse_token_string_t lb_cmd_entry_dbg_entry_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_dbg_result,
			 entry_string, "txrx");

static cmdline_parse_token_string_t lb_cmd_entry_dbg_dbg_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_dbg_result, dbg_string,
			 "dbg");

static cmdline_parse_token_num_t lb_cmd_entry_dbg_cmd =
TOKEN_NUM_INITIALIZER(struct cmd_entry_dbg_result, cmd, UINT8);

static cmdline_parse_token_num_t lb_cmd_entry_dbg_d1 =
TOKEN_NUM_INITIALIZER(struct cmd_entry_dbg_result, d1, UINT8);

static cmdline_parse_inst_t lb_cmd_entry_dbg = {
	.f = cmd_entry_dbg_parsed,
	.data = NULL,
	.help_str = "TXRX dbg cmd",
	.tokens = {
			 (void *)&lb_cmd_entry_dbg_p_string,
			 (void *)&lb_cmd_entry_dbg_p,
			 (void *)&lb_cmd_entry_dbg_entry_string,
			 (void *)&lb_cmd_entry_dbg_dbg_string,
			 (void *)&lb_cmd_entry_dbg_cmd,
			 (void *)&lb_cmd_entry_dbg_d1,
			 NULL,
			 },
};

static cmdline_parse_ctx_t pipeline_cmds[] = {
	(cmdline_parse_inst_t *) &lb_cmd_entry_dbg,
	NULL,
};

static struct pipeline_fe_ops pipeline_txrx_fe_ops = {
	.f_init = NULL,
	.f_free = NULL,
	.cmds = pipeline_cmds,
};

struct pipeline_type pipeline_txrx = {
	.name = "TXRX",
	.be_ops = &pipeline_txrx_be_ops,
	.fe_ops = &pipeline_txrx_fe_ops,
};
