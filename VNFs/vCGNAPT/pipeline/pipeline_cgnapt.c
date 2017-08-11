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

/**
 * @file
 * Pipeline CG-NAPT FE Implementation.
 *
 * Implementation of Pipeline CG-NAPT Front End (FE).
 * Provides CLI support.
 * Runs on master core.
 *
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
#include "pipeline_common_be.h"
#include "pipeline_cgnapt_be.h"
#ifdef PCP_ENABLE
#include "cgnapt_pcp_fe.h"
#endif

struct app_params *myapp;
#define MAX_BUF_SIZE	2048

/**
 * A structure defining the CG-NAPT entry that is stored on
 * front end.
 */
struct app_pipeline_cgnapt_entry {
	struct pipeline_cgnapt_entry_key key;
	struct app_pipeline_cgnapt_entry_params params;
	void *entry_ptr;

	 TAILQ_ENTRY(app_pipeline_cgnapt_entry) node;
};

/**
 * A structure defining the FE representation of a CG-NAPT pipeline
 */
struct pipeline_cgnapt_t {
	/* Parameters */
	uint32_t n_ports_in;
	uint32_t n_ports_out;

	/* entries */
	 TAILQ_HEAD(, app_pipeline_cgnapt_entry) entries;
	uint32_t n_entries;

};

/**
 * Init function for CG-NAPT FE.
 *
 * @param params
 *  A pointer to the pipeline params.
 *
 */
static void *pipeline_cgnapt_init(struct pipeline_params *params,
					__rte_unused void *arg)
{
	struct pipeline_cgnapt_t *p;
	uint32_t size;

	/* Check input arguments */
	if ((params == NULL) ||
			(params->n_ports_in == 0) || (params->n_ports_out == 0))
		return NULL;

	/* Memory allocation */
	size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct pipeline_cgnapt_t));
	p = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
	if (p == NULL)
		return NULL;

	/* Initialization */
	p->n_ports_in = params->n_ports_in;
	p->n_ports_out = params->n_ports_out;

	TAILQ_INIT(&p->entries);
	p->n_entries = 0;

	return p;
}

/**
 * Function for CG-NAPT FE cleanup.
 *
 * @param pipeline
 *  A pointer to the pipeline.
 *
 */
static int app_pipeline_cgnapt_free(void *pipeline)
{
	struct pipeline_cgnapt_t *p = pipeline;

	/* Check input arguments */
	if (p == NULL)
		return -1;

	/* Free resources */
	while (!TAILQ_EMPTY(&p->entries)) {
		struct app_pipeline_cgnapt_entry *entry;

		entry = TAILQ_FIRST(&p->entries);
		TAILQ_REMOVE(&p->entries, entry, node);
		rte_free(entry);
	}

	rte_free(p);
	return 0;
}

/**
 * Function to print an IPv6 address
 *
 * @param ipv6_addr
 *  A uint8_t array containing an IPv6 address
 */
static void print_ipv6_address_u8(uint8_t ipv6_addr[16])
{
	printf("Ipv6Address-%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x\n",
				 ipv6_addr[0], ipv6_addr[1], ipv6_addr[2], ipv6_addr[3],
				 ipv6_addr[4], ipv6_addr[5], ipv6_addr[6], ipv6_addr[7],
				 ipv6_addr[8], ipv6_addr[9], ipv6_addr[10], ipv6_addr[11],
				 ipv6_addr[12], ipv6_addr[13], ipv6_addr[14], ipv6_addr[15]);
}

/**
 * Function to print an IPv6 address
 *
 * @param ipv6_addr
 *  A uint16_t array containing an IPv6 address
 */
static void print_ipv6_address_u16(uint16_t ipv6_addr[8])
{
	printf("Ipv6Address-%x:%x:%x:%x:%x:%x:%x:%x\n", ipv6_addr[0],
				 ipv6_addr[1], ipv6_addr[2], ipv6_addr[3], ipv6_addr[4],
				 ipv6_addr[5], ipv6_addr[6], ipv6_addr[7]);
}

/**
 * Function to print an IPv6 address
 *
 * @param ipv6_addr
 *  A uint32_t array containing an IPv6 address
 */
static void print_ipv6_address_u32(uint32_t ipv6_addr[4])
{
	printf("Ipv6Address: %x:%x:%x:%x\n", ipv6_addr[0], ipv6_addr[1],
		ipv6_addr[2], ipv6_addr[3]);
}

/**
 * Function to print a NAPT entry
 *
 * @param entry
 *  A pointer to a NAPT entry
 */
static void print_entry(const struct app_pipeline_cgnapt_entry *entry)
{
	const struct pipeline_cgnapt_entry_key *key = &entry->key;

	if (entry->params.type == CGNAPT_ENTRY_IPV4) {
		printf("CGNAPT Entry: Key = %" PRIu32 ".%" PRIu32 ".%" PRIu32
					 ".%" PRIu32 ":%" PRIu32 ":%" PRIu16 " => Prv = %" PRIu32
					 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32 ":%" PRIu32
					 " => Pub = %" PRIu32 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32
					 ":%" PRIu32 " => ttl = %" PRIu32 "\n",
					 (key->ip >> 24) & 0xFF, (key->ip >> 16) & 0xFF,
					 (key->ip >> 8) & 0xFF, key->ip & 0xFF, key->port,
					 key->pid, (entry->params.u.prv_ip >> 24) & 0xFF,
					 (entry->params.u.prv_ip >> 16) & 0xFF,
					 (entry->params.u.prv_ip >> 8) & 0xFF,
					 entry->params.u.prv_ip & 0xFF, entry->params.prv_port,
					 (entry->params.pub_ip >> 24) & 0xFF,
					 (entry->params.pub_ip >> 16) & 0xFF,
					 (entry->params.pub_ip >> 8) & 0xFF,
					 entry->params.pub_ip & 0xFF, entry->params.pub_port,
					 entry->params.ttl);
	} else {
		printf("CGNAPT Entry: Key = %" PRIu32 ".%" PRIu32 ".%" PRIu32
					 ".%" PRIu32 ":%" PRIu32 ":%" PRIu16 " => Prv = %" PRIu32
					 "%" PRIu32 ":%" PRIu32 "%" PRIu32 ":%" PRIu32 "%" PRIu32
					 ":%" PRIu32 "%" PRIu32 ":%" PRIu32 "%" PRIu32 ":%" PRIu32
					 "%" PRIu32 ":%" PRIu32 "%" PRIu32 ":%" PRIu32 "%" PRIu32
					 ":%" PRIu32 " => Pub = %" PRIu32 ".%" PRIu32 ".%"
					 PRIu32 ".%" PRIu32 ":%" PRIu32 " => ttl = %" PRIu32
					 "\n", (key->ip >> 24) & 0xFF, (key->ip >> 16) & 0xFF,
					 (key->ip >> 8) & 0xFF, key->ip & 0xFF, key->port,
					 key->pid, entry->params.u.prv_ipv6[0],
					 entry->params.u.prv_ipv6[1], entry->params.u.prv_ipv6[2],
					 entry->params.u.prv_ipv6[3], entry->params.u.prv_ipv6[4],
					 entry->params.u.prv_ipv6[5], entry->params.u.prv_ipv6[6],
					 entry->params.u.prv_ipv6[7], entry->params.u.prv_ipv6[8],
					 entry->params.u.prv_ipv6[9],
					 entry->params.u.prv_ipv6[10],
					 entry->params.u.prv_ipv6[11],
					 entry->params.u.prv_ipv6[12],
					 entry->params.u.prv_ipv6[13],
					 entry->params.u.prv_ipv6[14],
					 entry->params.u.prv_ipv6[15], entry->params.prv_port,
					 (entry->params.pub_ip >> 24) & 0xFF,
					 (entry->params.pub_ip >> 16) & 0xFF,
					 (entry->params.pub_ip >> 8) & 0xFF,
					 entry->params.pub_ip & 0xFF, entry->params.pub_port,
					 entry->params.ttl);

	}
}

/**
 * Function to list NAPT entries from FE storage
 *
 * @param app
 *  A pointer to pipeline app
 * @param pipeline_id
 *  Pipeline id
 *
 * @return
 *  0 on success, negative on error.
 */
static int
app_pipeline_cgnapt_entry_ls(struct app_params *app, uint32_t pipeline_id)
{
	struct pipeline_cgnapt_t *p;
	struct app_pipeline_cgnapt_entry *it;

	p = app_pipeline_data_fe(app, pipeline_id,
				 (struct pipeline_type *)&pipeline_cgnapt);
	if (p == NULL)
		return -EINVAL;

	TAILQ_FOREACH(it, &p->entries, node)
			print_entry(it);
	print_static_cgnapt_entries();
	printf(" - end of napt fe entry list -\n");
	return 0;
}

/**
 * Function to send a debug message to BE
 *
 * @param app
 *  A pointer to pipeline app
 * @param pipeline_id
 *  Pipeline id
 * @param msg
 *  debug message contents
 *
 * @return
 *  0 on success, negative on error.
 */
static int
app_pipeline_cgnapt_entry_dbg(struct app_params *app,
						uint32_t pipeline_id, uint8_t *msg)
{
	struct pipeline_cgnapt_t *p;

	struct pipeline_cgnapt_entry_dbg_msg_req *req;
	struct pipeline_cgnapt_entry_dbg_msg_rsp *rsp;

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
	req->subtype = PIPELINE_CGNAPT_MSG_REQ_ENTRY_DBG;
	req->data[0] = msg[0];
	req->data[1] = msg[1];
	req->data[2] = msg[2];

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
 * Function to send a NAPT entry add message to BE
 *
 * @param app
 *  A pointer to pipeline app
 * @param pipeline_id
 *  Pipeline id
 * @param key
 *  A pointer to NAPT entry key
 * @param entry_params
 *  A pointer to NAPT entry params
 *
 * @return
 *  0 on success, negative on error.
 */
int app_pipeline_cgnapt_add_entry(
	struct app_params *app,
	uint32_t pipeline_id,
	struct app_pipeline_cgnapt_entry_params *entry_params)
{
	struct pipeline_cgnapt_t *p;

	struct pipeline_cgnapt_entry_add_msg_req *req;
	struct pipeline_cgnapt_entry_add_msg_rsp *rsp;

	/* Check input arguments */
	if ((app == NULL) || (entry_params == NULL))
		return -1;

	p = app_pipeline_data_fe(app, pipeline_id,
				 (struct pipeline_type *)&pipeline_cgnapt);
	if (p == NULL)
		return -2;

	/* Allocate and write request */
	req = app_msg_alloc(app);
	if (req == NULL)
		return -4;

	req->type = PIPELINE_MSG_REQ_CUSTOM;
	req->subtype = PIPELINE_CGNAPT_MSG_REQ_ENTRY_ADD;
	memcpy(&req->data, entry_params, sizeof(*entry_params));

	rsp = app_msg_send_recv(app, pipeline_id, req, MSG_TIMEOUT_DEFAULT);
	if (rsp == NULL)
		return -5;

	/* Message buffer free */
	app_msg_free(app, rsp);
	return 0;
}

/**
 * Function to send a multiple NAPT entry add message to BE
 *
 * @param app
 *  A pointer to pipeline app
 * @param pipeline_id
 *  Pipeline id
 * @param key
 *  A pointer to NAPT entry key
 * @param entry_params
 *  A pointer to multiple NAPT entry params
 *
 * @return
 *  0 on success, negative on error.
 */
int app_pipeline_cgnapt_addm_entry(
	struct app_params *app,
	uint32_t pipeline_id,
	struct app_pipeline_cgnapt_mentry_params *entry_params)
{
	struct pipeline_cgnapt_t *p;

	struct pipeline_cgnapt_entry_addm_msg_req *req;
	struct pipeline_cgnapt_entry_addm_msg_rsp *rsp;

	/* Check input arguments */
	if ((app == NULL) || (entry_params == NULL))
		return -1;

	p = app_pipeline_data_fe(app, pipeline_id,
				 (struct pipeline_type *)&pipeline_cgnapt);
	if (p == NULL)
		return -2;

	/* Allocate and write request */
	req = app_msg_alloc(app);
	if (req == NULL)
		return -4;

	req->type = PIPELINE_MSG_REQ_CUSTOM;
	req->subtype = PIPELINE_CGNAPT_MSG_REQ_ENTRY_ADDM;
	memcpy(&req->data, entry_params, sizeof(*entry_params));

	rsp = app_msg_send_recv(app, pipeline_id, req, MSG_TIMEOUT_DEFAULT);
	if (rsp == NULL)
		return -5;

	/* Message buffer free */
	app_msg_free(app, rsp);
	return 0;
}

/**
 * Function to send a NAPT entry delete message to BE
 *
 * @param app
 *  A pointer to pipeline app
 * @param pipeline_id
 *  Pipeline id
 * @param key
 *  A pointer to NAPT entry key
 *
 * @return
 *  0 on success, negative on error.
 */
int
app_pipeline_cgnapt_delete_entry(struct app_params *app,
				 uint32_t pipeline_id,
				 struct pipeline_cgnapt_entry_key *key)
{
	struct pipeline_cgnapt_t *p;

	struct pipeline_cgnapt_entry_delete_msg_req *req;
	struct pipeline_cgnapt_entry_delete_msg_rsp *rsp;

	if (CGNAPT_DEBUG) {
		uint8_t *KeyP = (uint8_t *) key;
		int i = 0;

		printf("app_pipeline_cgnapt_delete_entry - Key: ");
		for (i = 0; i < (int)sizeof(*key); i++)
			printf(" %02x", KeyP[i]);
		printf(" ,KeySize %u\n", (int)sizeof(*key));
	}
	/* Check input arguments */
	if ((app == NULL) || (key == NULL))
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
	req->subtype = PIPELINE_CGNAPT_MSG_REQ_ENTRY_DEL;
	memcpy(&req->key, key, sizeof(*key));

	rsp = app_msg_send_recv(app, pipeline_id, req, MSG_TIMEOUT_DEFAULT);
	if (rsp == NULL)
		return -1;

	/* Read response */
	if (rsp->status || !rsp->key_found) {
		app_msg_free(app, rsp);
		printf("Successfully deleted the entry\n");
		return 0;
	}

	/* Free response */
	app_msg_free(app, rsp);

	return 0;
}

/**
 * A structure defining the entry add parse arguments.
 */
struct cmd_entry_add_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t entry_string;
	cmdline_fixed_string_t add_string;
	cmdline_ipaddr_t prv_ip;
	uint16_t prv_port;
	cmdline_ipaddr_t pub_ip;
	uint16_t pub_port;
	uint16_t pid;
	uint32_t ttl;
};
/**
 * Helping function for add entry
 *
 * @param parsed_result
 *  A pointer parsed add arguments
 * @param cl
 *  unused pointer to struct cmdline
 * @param msg
 *  void pointer data
 *
 */
static void
cmd_entry_add_parsed(void *parsed_result,
					__rte_unused struct cmdline *cl, void *data)
{
	struct cmd_entry_add_result *params = parsed_result;
	struct app_params *app = data;
	struct app_pipeline_cgnapt_entry_params ent_params;
	int status;

	if (params->prv_ip.family == AF_INET) {
		ent_params.type = CGNAPT_ENTRY_IPV4;
		ent_params.u.prv_ip =
				rte_bswap32((uint32_t) params->prv_ip.addr.ipv4.s_addr);
	} else {
		print_ipv6_address_u8(params->prv_ip.addr.ipv6.s6_addr);
		print_ipv6_address_u16(params->prv_ip.addr.ipv6.s6_addr16);
		print_ipv6_address_u32(params->prv_ip.addr.ipv6.s6_addr32);
		ent_params.type = CGNAPT_ENTRY_IPV6;
		memcpy(ent_params.u.prv_ipv6, params->prv_ip.addr.ipv6.s6_addr,
					 16);
	}

	ent_params.prv_port = params->prv_port;
	ent_params.pub_ip =
			rte_bswap32((uint32_t) params->pub_ip.addr.ipv4.s_addr);
	ent_params.pub_port = params->pub_port;
	ent_params.prv_phy_port = params->pid;
	ent_params.ttl = params->ttl;

	status = app_pipeline_cgnapt_add_entry(app, params->p, &ent_params);

	if (status != 0) {
		printf("CG-NAPT add multiple entry command failed, %d\n",
					 status);
		return;
	}
}

static cmdline_parse_token_string_t cmd_entry_add_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_add_result, p_string,
			 "p");

static cmdline_parse_token_num_t cmd_entry_add_p =
TOKEN_NUM_INITIALIZER(struct cmd_entry_add_result, p, UINT32);

static cmdline_parse_token_string_t cmd_entry_add_entry_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_add_result, entry_string,
			 "entry");

static cmdline_parse_token_string_t cmd_entry_add_add_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_add_result, add_string,
			 "add");

static cmdline_parse_token_ipaddr_t cmd_entry_add_prv_ip =
TOKEN_IPADDR_INITIALIZER(struct cmd_entry_add_result, prv_ip);

static cmdline_parse_token_num_t cmd_entry_add_prv_port =
TOKEN_NUM_INITIALIZER(struct cmd_entry_add_result, prv_port, UINT16);

static cmdline_parse_token_ipaddr_t cmd_entry_add_pub_ip =
TOKEN_IPV4_INITIALIZER(struct cmd_entry_add_result, pub_ip);

static cmdline_parse_token_num_t cmd_entry_add_pub_port =
TOKEN_NUM_INITIALIZER(struct cmd_entry_add_result, pub_port, UINT16);

static cmdline_parse_token_num_t cmd_entry_add_pid =
TOKEN_NUM_INITIALIZER(struct cmd_entry_add_result, pid, UINT16);

static cmdline_parse_token_num_t cmd_entry_add_ttl =
TOKEN_NUM_INITIALIZER(struct cmd_entry_add_result, ttl, UINT32);

static cmdline_parse_inst_t cmd_entry_add = {
	.f = cmd_entry_add_parsed,
	.data = NULL,
	.help_str = "NAPT entry add",
	.tokens = {
			 (void *)&cmd_entry_add_p_string,
			 (void *)&cmd_entry_add_p,
			 (void *)&cmd_entry_add_entry_string,
			 (void *)&cmd_entry_add_add_string,
			 (void *)&cmd_entry_add_prv_ip,
			 (void *)&cmd_entry_add_prv_port,
			 (void *)&cmd_entry_add_pub_ip,
			 (void *)&cmd_entry_add_pub_port,
			 (void *)&cmd_entry_add_pid,
			 (void *)&cmd_entry_add_ttl,
			 NULL,
			 },
};

/**
 * A structure defining the multiple entry add parse arguments.
 */
struct cmd_entry_addm_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t entry_string;
	cmdline_fixed_string_t addm_string;
	cmdline_ipaddr_t prv_ip;
	uint16_t prv_port;
	cmdline_ipaddr_t pub_ip;
	uint16_t pub_port;
	uint16_t pid;
	uint32_t ttl;
	uint32_t num_ue;
	uint16_t prv_port_max;
	uint16_t pub_port_max;
};

/**
 * Helping function for add multiple entries
 *
 * @param parsed_result
 *  A pointer parsed add arguments
 * @param cl
 *  unused pointer to struct cmdline
 * @param msg
 *  void pointer data
 */
static void
cmd_entry_addm_parsed(void *parsed_result,
					__rte_unused struct cmdline *cl, void *data)
{
	struct cmd_entry_addm_result *params = parsed_result;
	struct app_params *app = data;
	struct app_pipeline_cgnapt_mentry_params ent_params;
	int status;

	if (params->prv_ip.family == AF_INET) {
		ent_params.type = CGNAPT_ENTRY_IPV4;
		ent_params.u.prv_ip =
				rte_bswap32((uint32_t) params->prv_ip.addr.ipv4.s_addr);
	} else {
		print_ipv6_address_u8(params->prv_ip.addr.ipv6.s6_addr);
		print_ipv6_address_u16(params->prv_ip.addr.ipv6.s6_addr16);
		print_ipv6_address_u32(params->prv_ip.addr.ipv6.s6_addr32);
		ent_params.type = CGNAPT_ENTRY_IPV6;
		memcpy(ent_params.u.prv_ipv6, params->prv_ip.addr.ipv6.s6_addr,
					 16);
	}

	ent_params.prv_port = params->prv_port;
	ent_params.pub_ip =
			rte_bswap32((uint32_t) params->pub_ip.addr.ipv4.s_addr);
	ent_params.pub_port = params->pub_port;
	ent_params.prv_phy_port = params->pid;
	ent_params.ttl = params->ttl;
	ent_params.num_ue = params->num_ue;
	ent_params.prv_port_max = params->prv_port_max;
	ent_params.pub_port_max = params->pub_port_max;

	status = app_pipeline_cgnapt_addm_entry(app, params->p, &ent_params);

	if (status != 0) {
		printf("CG-NAPT add multiple entry command failed, %d\n",
					 status);
		return;
	}
}

static cmdline_parse_token_string_t cmd_entry_add_addm_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_addm_result, addm_string,
			 "addm");

static cmdline_parse_token_num_t cmd_entry_addm_prv_port =
TOKEN_NUM_INITIALIZER(struct cmd_entry_addm_result, prv_port_max, UINT16);

static cmdline_parse_token_num_t cmd_entry_addm_pub_port =
TOKEN_NUM_INITIALIZER(struct cmd_entry_addm_result, pub_port_max, UINT16);

static cmdline_parse_token_num_t cmd_entry_addm_max_ue =
TOKEN_NUM_INITIALIZER(struct cmd_entry_addm_result, num_ue, UINT32);

static cmdline_parse_inst_t cmd_entry_addm = {
	.f = cmd_entry_addm_parsed,
	.data = NULL,
	.help_str = "NAPT entry add multiple",
	.tokens = {
			 (void *)&cmd_entry_add_p_string,
			 (void *)&cmd_entry_add_p,
			 (void *)&cmd_entry_add_entry_string,
			 (void *)&cmd_entry_add_addm_string,
			 (void *)&cmd_entry_add_prv_ip,
			 (void *)&cmd_entry_add_prv_port,
			 (void *)&cmd_entry_add_pub_ip,
			 (void *)&cmd_entry_add_pub_port,
			 (void *)&cmd_entry_add_pid,
			 (void *)&cmd_entry_add_ttl,
			 (void *)&cmd_entry_addm_max_ue,
			 (void *)&cmd_entry_addm_prv_port,
			 (void *)&cmd_entry_addm_pub_port,
			 NULL,
			 },
};

/**
 * A structure defining the entry delete parse arguments.
 */
struct cmd_entry_del_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t entry_string;
	cmdline_fixed_string_t del_string;
	cmdline_ipaddr_t ip;
	uint16_t port;
	uint16_t pid;
};

/**
 * Helping function for delete entry
 *
 * @param parsed_result
 *  A pointer parsed add arguments
 * @param cl
 *  unused pointer to struct cmdline
 * @param msg
 *  void pointer data
 */
static void
cmd_entry_del_parsed(void *parsed_result,
				 __rte_unused struct cmdline *cl, void *data)
{
	struct cmd_entry_del_result *params = parsed_result;
	struct app_params *app = data;
	struct pipeline_cgnapt_entry_key key;

	int status;

	/* Create entry */
	if (params->ip.family == AF_INET)
		key.ip = rte_bswap32((uint32_t) params->ip.addr.ipv4.s_addr);
	else
		key.ip =
				rte_bswap32((uint32_t) params->ip.addr.ipv6.s6_addr32[3]);
	key.port = params->port;
	key.pid = params->pid;

	status = app_pipeline_cgnapt_delete_entry(app, params->p, &key);

	if (status != 0) {
		printf("CG-NAPT entry del command failed\n");
		return;
	}
}

static cmdline_parse_token_string_t cmd_entry_del_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_del_result, p_string,
			 "p");

static cmdline_parse_token_num_t cmd_entry_del_p =
TOKEN_NUM_INITIALIZER(struct cmd_entry_del_result, p, UINT32);

static cmdline_parse_token_string_t cmd_entry_del_entry_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_del_result, entry_string,
			 "entry");

static cmdline_parse_token_string_t cmd_entry_del_del_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_del_result, del_string,
			 "del");

static cmdline_parse_token_ipaddr_t cmd_entry_del_ip =
TOKEN_IPADDR_INITIALIZER(struct cmd_entry_del_result, ip);

static cmdline_parse_token_num_t cmd_entry_del_port =
TOKEN_NUM_INITIALIZER(struct cmd_entry_del_result, port, UINT16);

static cmdline_parse_token_num_t cmd_entry_del_pid =
TOKEN_NUM_INITIALIZER(struct cmd_entry_del_result, pid, UINT16);

static cmdline_parse_inst_t cmd_entry_del = {
	.f = cmd_entry_del_parsed,
	.data = NULL,
	.help_str = "Entry delete",
	.tokens = {
			 (void *)&cmd_entry_del_p_string,
			 (void *)&cmd_entry_del_p,
			 (void *)&cmd_entry_del_entry_string,
			 (void *)&cmd_entry_del_del_string,
			 (void *)&cmd_entry_del_ip,
			 (void *)&cmd_entry_del_port,
			 (void *)&cmd_entry_del_pid,
			 NULL,
			 },
};

/**
 * A structure defining the list entry parse arguments.
 */
struct cmd_entry_ls_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t entry_string;
	cmdline_fixed_string_t ls_string;
};

/**
 * Helping function for list entry
 *
 * @param parsed_result
 *  A pointer parsed add arguments
 * @param cl
 *  unused pointer to struct cmdline
 * @param msg
 *  void pointer data
 */
static void
cmd_entry_ls_parsed(void *parsed_result,
				__rte_unused struct cmdline *cl, void *data)
{
	struct cmd_entry_ls_result *params = parsed_result;
	struct app_params *app = data;
	int status;

	status = app_pipeline_cgnapt_entry_ls(app, params->p);

	if (status != 0) {
		printf("Ls command failed\n");
		return;
	}
}

static cmdline_parse_token_string_t cmd_entry_ls_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_ls_result, p_string, "p");

static cmdline_parse_token_num_t cmd_entry_ls_p =
TOKEN_NUM_INITIALIZER(struct cmd_entry_ls_result, p, UINT32);

static cmdline_parse_token_string_t cmd_entry_ls_entry_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_ls_result,
			 entry_string, "entry");

static cmdline_parse_token_string_t cmd_entry_ls_ls_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_ls_result, ls_string,
			 "ls");

static cmdline_parse_inst_t cmd_entry_ls = {
	.f = cmd_entry_ls_parsed,
	.data = NULL,
	.help_str = "Entry list",
	.tokens = {
			 (void *)&cmd_entry_ls_p_string,
			 (void *)&cmd_entry_ls_p,
			 (void *)&cmd_entry_ls_entry_string,
			 (void *)&cmd_entry_ls_ls_string,
			 NULL,
			 },
};

/**
 * A structure defining the dbg cmd parse arguments.
 */
struct cmd_entry_dbg_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t entry_string;
	cmdline_fixed_string_t dbg_string;
	uint8_t cmd;
	uint8_t d1;
	uint8_t d2;
};

/**
 * Helping function for dbg cmd
 *
 * @param parsed_result
 *  A pointer parsed add arguments
 * @param cl
 *  unused pointer to struct cmdline
 * @param msg
 *  void pointer data
 */
static void
cmd_entry_dbg_parsed(void *parsed_result,
				 __rte_unused struct cmdline *cl, void *data)
{
	struct cmd_entry_dbg_result *params = parsed_result;
	struct app_params *app = data;
	uint8_t msg[4];
	int status;

	msg[0] = params->cmd;
	msg[1] = params->d1;
	msg[2] = params->d2;
	status = app_pipeline_cgnapt_entry_dbg(app, params->p, msg);

	if (status != 0) {
		printf("Dbg Command failed\n");
		return;
	}
}

static cmdline_parse_token_string_t cmd_entry_dbg_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_dbg_result, p_string, "p");

static cmdline_parse_token_num_t cmd_entry_dbg_p =
TOKEN_NUM_INITIALIZER(struct cmd_entry_dbg_result, p, UINT32);

static cmdline_parse_token_string_t cmd_entry_dbg_entry_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_dbg_result,
			 entry_string, "entry");

static cmdline_parse_token_string_t cmd_entry_dbg_dbg_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_dbg_result, dbg_string,
			 "dbg");

static cmdline_parse_token_num_t cmd_entry_dbg_cmd =
TOKEN_NUM_INITIALIZER(struct cmd_entry_dbg_result, cmd, UINT8);

static cmdline_parse_token_num_t cmd_entry_dbg_d1 =
TOKEN_NUM_INITIALIZER(struct cmd_entry_dbg_result, d1, UINT8);

static cmdline_parse_token_num_t cmd_entry_dbg_d2 =
TOKEN_NUM_INITIALIZER(struct cmd_entry_dbg_result, d2, UINT8);

static cmdline_parse_inst_t cmd_entry_dbg = {
	.f = cmd_entry_dbg_parsed,
	.data = NULL,
	.help_str = "NAPT dbg cmd",
	.tokens = {
			 (void *)&cmd_entry_dbg_p_string,
			 (void *)&cmd_entry_dbg_p,
			 (void *)&cmd_entry_dbg_entry_string,
			 (void *)&cmd_entry_dbg_dbg_string,
			 (void *)&cmd_entry_dbg_cmd,
			 (void *)&cmd_entry_dbg_d1,
			 (void *)&cmd_entry_dbg_d2,
			 NULL,
			 },
};

/**
 * A structure defining num ip clients cmd parse arguments.
 */
struct cmd_numipcli_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t numipcli_string;
};

/**
 * Helping function for printing num ip clients
 *
 * @param parsed_result
 *  Unused pointer parsed add arguments
 * @param cl
 *  unused pointer to struct cmdline
 * @param msg
 *  Unused void pointer data
 */
static void
cmd_numipcli_parsed(__rte_unused void *parsed_result,
				__rte_unused struct cmdline *cl, __rte_unused void *data)
{
	print_num_ip_clients();
}

static cmdline_parse_token_string_t cmd_numipcli_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_numipcli_result, p_string, "p");

static cmdline_parse_token_num_t cmd_numipcli_p =
TOKEN_NUM_INITIALIZER(struct cmd_numipcli_result, p, UINT32);

static cmdline_parse_token_string_t cmd_numipcli_string =
TOKEN_STRING_INITIALIZER(struct cmd_numipcli_result,
			 numipcli_string, "numipcli");

static cmdline_parse_inst_t cmd_numipcli = {
	.f = cmd_numipcli_parsed,
	.data = NULL,
	.help_str = "Num IP Clients command",
	.tokens = {
			 (void *)&cmd_numipcli_p_string,
			 (void *)&cmd_numipcli_p,
			 (void *)&cmd_numipcli_string,
			 NULL,
			 },
};

/**
 * Function to send a ver cmd message to BE
 *
 * @param app
 *  A pointer to pipeline app
 * @param pipeline_id
 *  Pipeline id
 * @param msg
 *  debug message contents
 *
 * @return
 *  0 on success, negative on error.
 */
static int
app_pipeline_cgnapt_ver(struct app_params *app,
			uint32_t pipeline_id, uint8_t *msg)
{

	struct pipeline_cgnapt_t *p;
	struct pipeline_cgnapt_entry_dbg_msg_req *req;
	struct pipeline_cgnapt_entry_dbg_msg_rsp *rsp;

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
	req->subtype = PIPELINE_CGNAPT_MSG_REQ_VER;
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

/**
 * A structure defining ver cmd parse arguments.
 */
struct cmd_ver_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t ver_string;
	uint8_t cmd;
	uint8_t d1;
};

/**
 * Helping function for ver cmd
 *
 * @param parsed_result
 *  A pointer parsed add arguments
 * @param cl
 *  unused pointer to struct cmdline
 * @param msg
 *  void pointer data
 */
static void
cmd_ver_parsed(void *parsed_result, __rte_unused struct cmdline *cl, void *data)
{
	struct cmd_ver_result *params = parsed_result;
	struct app_params *app = data;
	uint8_t msg[4];
	int status;

	msg[0] = params->cmd;
	msg[1] = params->d1;
	status = app_pipeline_cgnapt_ver(app, params->p, msg);

	if (status != 0) {
		printf("Version Command failed\n");
		return;
	}
}

static cmdline_parse_token_string_t cmd_ver_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_ver_result, p_string, "p");

static cmdline_parse_token_num_t cmd_ver_p =
TOKEN_NUM_INITIALIZER(struct cmd_ver_result, p, UINT32);

static cmdline_parse_token_string_t cmd_ver_string =
TOKEN_STRING_INITIALIZER(struct cmd_ver_result,
			 ver_string, "ver");

static cmdline_parse_token_num_t cmd_ver_cmd =
TOKEN_NUM_INITIALIZER(struct cmd_ver_result, cmd, UINT8);

static cmdline_parse_token_num_t cmd_ver_d1 =
TOKEN_NUM_INITIALIZER(struct cmd_ver_result, d1, UINT8);

static cmdline_parse_inst_t cmd_ver = {
	.f = cmd_ver_parsed,
	.data = NULL,
	.help_str = "NAPT ver cmd",
	.tokens = {
			 (void *)&cmd_ver_p_string,
			 (void *)&cmd_ver_p,
			 (void *)&cmd_ver_string,
			 (void *)&cmd_ver_cmd,
			 (void *)&cmd_ver_d1,
			 NULL,
			 },
};

/**
 * Function to send a nsp add cmd message to BE
 *
 * @param app
 *  A pointer to pipeline app
 * @param pipeline_id
 *  Pipeline id
 * @param nsp
 *  A pointer to struct pipeline_cgnapt_nsp_t
 *
 * @return
 *  0 on success, negative on error.
 */
static int
app_pipeline_cgnapt_add_nsp(struct app_params *app,
					uint32_t pipeline_id,
					struct pipeline_cgnapt_nsp_t *nsp)
{

	struct pipeline_cgnapt_t *p;
	struct pipeline_cgnapt_nsp_add_msg_req *req;
	struct pipeline_cgnapt_nsp_add_msg_rsp *rsp;

	/* Check input arguments */
	if (app == NULL)
		return -1;

	printf("1st if condition\n");

	p = app_pipeline_data_fe(app, pipeline_id,
				 (struct pipeline_type *)&pipeline_cgnapt);
	if (p == NULL)
		return -1;

	printf("2st if condition\n");
	/* Allocate and write request */
	req = app_msg_alloc(app);
	if (req == NULL)
		return -1;

	printf("3st if condition\n");
	req->type = PIPELINE_MSG_REQ_CUSTOM;
	req->subtype = PIPELINE_CGNAPT_MSG_REQ_NSP_ADD;
	memcpy(&req->nsp, nsp, sizeof(struct pipeline_cgnapt_nsp_t));

	rsp = app_msg_send_recv(app, pipeline_id, req, MSG_TIMEOUT_DEFAULT);
	if (rsp == NULL)
		return -1;

	printf("4st if condition\n");
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
 * A structure defining nsp add cmd parse arguments.
 */
struct cmd_nsp_add_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t nsp_string;
	cmdline_fixed_string_t add_string;
	cmdline_ipaddr_t ip;
};

/**
 * Helping function for nsp add cmd
 *
 * @param parsed_result
 *  A pointer parsed add arguments
 * @param cl
 *  unused pointer to struct cmdline
 * @param msg
 *  void pointer data
 */
static void
cmd_nsp_add_parsed(void *parsed_result, __rte_unused struct cmdline *cl,
			 void *data)
{
	struct cmd_nsp_add_result *params = parsed_result;
	struct app_params *app = data;
	int status;
	struct pipeline_cgnapt_nsp_t nsp;

	memcpy(&nsp.prefix, &params->ip.addr.ipv6.s6_addr, 16);
	nsp.depth = params->ip.prefixlen;
	status = app_pipeline_cgnapt_add_nsp(app, params->p, &nsp);
	if (status != 0) {
		printf("NSP ADD Command failed\n");
		return;
	}
}

static cmdline_parse_token_string_t cmd_add_nsp_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_nsp_add_result, p_string, "p");

static cmdline_parse_token_num_t cmd_add_nsp_p =
TOKEN_NUM_INITIALIZER(struct cmd_nsp_add_result, p, UINT32);

static cmdline_parse_token_string_t cmd_add_nsp_string =
TOKEN_STRING_INITIALIZER(struct cmd_nsp_add_result,
			 nsp_string, "nsp");

static cmdline_parse_token_string_t cmd_add_nsp_add_string =
TOKEN_STRING_INITIALIZER(struct cmd_nsp_add_result,
			 add_string, "add");

static cmdline_parse_token_ipaddr_t cmd_add_nsp_ip =
TOKEN_IPNET_INITIALIZER(struct cmd_nsp_add_result, ip);

static cmdline_parse_inst_t cmd_nsp_add = {
	.f = cmd_nsp_add_parsed,
	.data = NULL,
	.help_str = "NAPT NSP ADD cmd",
	.tokens = {
			 (void *)&cmd_add_nsp_p_string,
			 (void *)&cmd_add_nsp_p,
			 (void *)&cmd_add_nsp_string,
			 (void *)&cmd_add_nsp_add_string,
			 (void *)&cmd_add_nsp_ip,
			 NULL,
			 },
};

/**
 * Function to send a nsp del cmd message to BE
 *
 * @param app
 *  A pointer to pipeline app
 * @param pipeline_id
 *  Pipeline id
 * @param nsp
 *  A pointer to struct pipeline_cgnapt_nsp_t
 *
 * @return
 *  0 on success, negative on error.
 */
static int
app_pipeline_cgnapt_del_nsp(struct app_params *app,
					uint32_t pipeline_id,
					struct pipeline_cgnapt_nsp_t *nsp)
{

	struct pipeline_cgnapt_t *p;
	struct pipeline_cgnapt_nsp_del_msg_req *req;
	struct pipeline_cgnapt_nsp_del_msg_rsp *rsp;

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
	req->subtype = PIPELINE_CGNAPT_MSG_REQ_NSP_DEL;
	memcpy(&req->nsp, nsp, sizeof(struct pipeline_cgnapt_nsp_t));

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
 * A structure defining nsp del cmd parse arguments.
 */
struct cmd_nsp_del_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t nsp_string;
	cmdline_fixed_string_t del_string;
	cmdline_ipaddr_t ip;
};

/**
 * Helping function for nsp del cmd
 *
 * @param parsed_result
 *  A pointer parsed add arguments
 * @param cl
 *  unused pointer to struct cmdline
 * @param msg
 *  void pointer data
 */
static void
cmd_nsp_del_parsed(void *parsed_result, __rte_unused struct cmdline *cl,
			 void *data)
{
	struct cmd_nsp_del_result *params = parsed_result;
	struct app_params *app = data;
	int status;
	struct pipeline_cgnapt_nsp_t nsp;

	memcpy(&nsp.prefix, &params->ip.addr.ipv6.s6_addr, 16);
	nsp.depth = params->ip.prefixlen;
	status = app_pipeline_cgnapt_del_nsp(app, params->p, &nsp);

	if (status != 0) {
		printf("NSP DEL Command failed\n");
		return;
	}
}

static cmdline_parse_token_string_t cmd_del_nsp_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_nsp_del_result, p_string, "p");

static cmdline_parse_token_num_t cmd_del_nsp_p =
TOKEN_NUM_INITIALIZER(struct cmd_nsp_del_result, p, UINT32);

static cmdline_parse_token_string_t cmd_del_nsp_string =
TOKEN_STRING_INITIALIZER(struct cmd_nsp_del_result,
			 nsp_string, "nsp");

static cmdline_parse_token_string_t cmd_del_nsp_del_string =
TOKEN_STRING_INITIALIZER(struct cmd_nsp_del_result,
			 del_string, "del");

static cmdline_parse_token_ipaddr_t cmd_del_nsp_ip =
TOKEN_IPNET_INITIALIZER(struct cmd_nsp_del_result, ip);

static cmdline_parse_inst_t cmd_nsp_del = {
	.f = cmd_nsp_del_parsed,
	.data = NULL,
	.help_str = "NAPT NSP DEL cmd",
	.tokens = {
			 (void *)&cmd_del_nsp_p_string,
			 (void *)&cmd_del_nsp_p,
			 (void *)&cmd_del_nsp_string,
			 (void *)&cmd_del_nsp_del_string,
			 (void *)&cmd_del_nsp_ip,
			 NULL,
			 },
};

/**
 * A structure defining the cgnapt stats cmd parse arguments.
 */
struct cmd_cgnapt_stats_result {
	cmdline_fixed_string_t p_string;
	cmdline_fixed_string_t cgnapt_string;
	cmdline_fixed_string_t stats_string;
};

/**
 * Helping function for cgnapt stats cmd
 *
 * @param parsed_result
 *  A pointer parsed add arguments
 * @param cl
 *  unused pointer to struct cmdline
 * @param msg
 *  void pointer data
 */
static void
cmd_cgnapt_stats_parsed(
	__rte_unused void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	char buf[2048];
	all_cgnapt_stats(&buf[0]);
}

static cmdline_parse_token_string_t cmd_cgnapt_stats_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_cgnapt_stats_result, p_string, "p");

static cmdline_parse_token_string_t cmd_cgnapt_stats_cgnapt_string =
TOKEN_STRING_INITIALIZER(struct cmd_cgnapt_stats_result,
				cgnapt_string, "cgnapt");

static cmdline_parse_token_string_t cmd_cgnapt_stats_stats_string =
TOKEN_STRING_INITIALIZER(struct cmd_cgnapt_stats_result, stats_string,
				"stats");

static cmdline_parse_inst_t cmd_stats = {
	.f = cmd_cgnapt_stats_parsed,
	.data = NULL,
	.help_str = "CGNAPT stats cmd",
	.tokens = {
		(void *)&cmd_cgnapt_stats_p_string,
		(void *)&cmd_cgnapt_stats_cgnapt_string,
		(void *)&cmd_cgnapt_stats_stats_string,
		NULL,
	},
};

/**
 * A structure defining the cgnapt clear stats cmd parse arguments.
 */
struct cmd_cgnapt_clear_stats_result {
	cmdline_fixed_string_t p_string;
	cmdline_fixed_string_t cgnapt_string;
	cmdline_fixed_string_t clear_string;
	cmdline_fixed_string_t stats_string;
};

/**
 * Helping function for cgnapt clear stats cmd
 *
 * @param parsed_result
 *  A pointer parsed add arguments
 * @param cl
 *  unused pointer to struct cmdline
 * @param msg
 *  void pointer data
 */
static void
cmd_cgnapt_clear_stats_parsed(
	__rte_unused void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	char buf[2048];
	all_cgnapt_clear_stats(&buf[0]);
}

static cmdline_parse_token_string_t cmd_cgnapt_clear_stats_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_cgnapt_clear_stats_result, p_string, "p");

static cmdline_parse_token_string_t cmd_cgnapt_clear_stats_cgnapt_string =
TOKEN_STRING_INITIALIZER(struct cmd_cgnapt_clear_stats_result,
				cgnapt_string, "cgnapt");

static cmdline_parse_token_string_t cmd_cgnapt_clear_stats_clear_string =
TOKEN_STRING_INITIALIZER(struct cmd_cgnapt_clear_stats_result,
				clear_string, "clear");

static cmdline_parse_token_string_t cmd_cgnapt_clear_stats_stats_string =
TOKEN_STRING_INITIALIZER(struct cmd_cgnapt_clear_stats_result, stats_string,
				"stats");

#ifdef REST_API_SUPPORT
int cgnapt_stats_handler(struct mg_connection *conn, void *cbdata)
{
	uint32_t num_links = 0, len = 0;
	char buf[1024];
        const struct mg_request_info *ri = mg_get_request_info(conn);
        struct app_params *app = myapp;
	int i;

	if (!strcmp(ri->request_method, "GET")) {
		all_cgnapt_stats(&buf[0]);
        	mg_printf(conn, "%s\n", &buf[0]);
                return 1; 
        }

	if (strcmp(ri->request_method, "POST")) {
                int ret = mg_get_request_link(conn, buf, sizeof(buf));

                mg_printf(conn,
                    "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n");
                mg_printf(conn, "Content-Type: text/plain\r\n\r\n");
                mg_printf(conn,
                          "%s method not allowed in the GET handler\n",
                          ri->request_method);
	}

	all_cgnapt_clear_stats(&buf[0]);
	mg_printf(conn, "%s\n", &buf[0]);
	return 1;

}

int cgnapt_cmd_ver_handler(struct mg_connection *conn, void *cbdata)
{
        const struct mg_request_info *req_info = mg_get_request_info(conn);
	int r, status;
        uint32_t cmd = 0, d1, pipe_num;
        char buf[MAX_BUF_SIZE];
        struct app_params *app = myapp;
        uint8_t msg[4];

        mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
        mg_printf(conn, "<html><body>");
        mg_printf(conn, "</body></html>\n");

        r = mg_read(conn, buf, sizeof(buf));
	json_object * jobj = json_tokener_parse(buf);
	json_object_object_foreach(jobj, key, val) {
		if (!strcmp(key, "cmd")) {
			cmd = atoi(json_object_get_string(val));
		} else if (!strcmp(key, "d1")) {
			d1 = atoi(json_object_get_string(val));
		} else if (!strcmp(key, "pipeline")) {
			pipe_num = atoi(json_object_get_string(val));
		}
	}

        msg[0] = cmd;
        msg[1] = d1;

	status = app_pipeline_cgnapt_ver(app, pipe_num, msg);
        if (status != 0) {
        	mg_printf(conn, "<p>CG-NAPT entry ver command failed</p>");
                return 1;
        }

        mg_printf(conn, "<p>Command Passed</p>");
	return 1;
}

void rest_api_cgnapt_init(struct mg_context *ctx, struct app_params *app)
{
	myapp = app;

	mg_set_request_handler(ctx, "/vnf/status", cgnapt_cmd_ver_handler, 0);
	mg_set_request_handler(ctx, "/vnf/stats", cgnapt_stats_handler, 0);

}
#endif

static cmdline_parse_inst_t cmd_clear_stats = {
	 .f = cmd_cgnapt_clear_stats_parsed,
	 .data = NULL,
	 .help_str = "CGNAPT clear stats cmd",
	 .tokens = {
				(void *)&cmd_cgnapt_clear_stats_p_string,
				(void *)&cmd_cgnapt_clear_stats_cgnapt_string,
				(void *)&cmd_cgnapt_clear_stats_clear_string,
				(void *)&cmd_cgnapt_clear_stats_stats_string,
				NULL,
				},
};


static cmdline_parse_ctx_t pipeline_cmds[] = {
	(cmdline_parse_inst_t *) &cmd_entry_add,
	(cmdline_parse_inst_t *) &cmd_entry_del,
	(cmdline_parse_inst_t *) &cmd_entry_ls,
	(cmdline_parse_inst_t *) &cmd_entry_dbg,
	(cmdline_parse_inst_t *) &cmd_entry_addm,
	(cmdline_parse_inst_t *) &cmd_ver,
	(cmdline_parse_inst_t *) &cmd_nsp_add,
	(cmdline_parse_inst_t *) &cmd_nsp_del,
	(cmdline_parse_inst_t *) &cmd_numipcli,
	#ifdef PCP_ENABLE
	(cmdline_parse_inst_t *) &cmd_pcp,
	#endif
	(cmdline_parse_inst_t *) &cmd_stats,
	(cmdline_parse_inst_t *) &cmd_clear_stats,
	NULL,
};

static struct pipeline_fe_ops pipeline_cgnapt_fe_ops = {
	.f_init = pipeline_cgnapt_init,
	.f_free = app_pipeline_cgnapt_free,
	.cmds = pipeline_cmds,
};

struct pipeline_type pipeline_cgnapt = {
	.name = "CGNAPT",
	.be_ops = &pipeline_cgnapt_be_ops,
	.fe_ops = &pipeline_cgnapt_fe_ops,
};
