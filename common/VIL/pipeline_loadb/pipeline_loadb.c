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
#include "pipeline_loadb.h"
#include "vnf_common.h"
//#include "lib_arp.h"
#include "pipeline_arpicmp_be.h"
//#include "lib_arp.h"
//#include "interface.h"
static int
app_pipeline_loadb_entry_dbg(struct app_params *app,
					 uint32_t pipeline_id, uint8_t *msg)
{
	struct pipeline_loadb_entry_dbg_msg_req *req;
	struct pipeline_loadb_entry_dbg_msg_rsp *rsp;

	/* Check input arguments */
	if (app == NULL)
		return -1;

	/* Allocate and write request */
	req = app_msg_alloc(app);
	if (req == NULL)
		return -1;

	req->type = PIPELINE_MSG_REQ_CUSTOM;
	req->subtype = PIPELINE_LOADB_MSG_REQ_ENTRY_DBG;
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
	status = app_pipeline_loadb_entry_dbg(app, params->p, msg);

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
			 entry_string, "lbentry");

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
	.help_str = "LOADB dbg cmd",
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

/*static void*/
/*print_arp_entry(const struct app_pipeline_arp_icmp_arp_entry *entry)*/
/*{*/
/*	printf("(Port = %" PRIu32 ", IP = %" PRIu32 ".%" PRIu32*/
/*		".%" PRIu32 ".%" PRIu32 ") => "*/
/*		"HWaddress = %02" PRIx32 ":%02" PRIx32 ":%02" PRIx32*/
/*		":%02" PRIx32 ":%02" PRIx32 ":%02" PRIx32 "\n",*/
/*		entry->key.key.ipv4.port_id,*/
/*		(entry->key.key.ipv4.ip >> 24) & 0xFF,*/
/*		(entry->key.key.ipv4.ip >> 16) & 0xFF,*/
/*		(entry->key.key.ipv4.ip >> 8) & 0xFF,*/
/*		entry->key.key.ipv4.ip & 0xFF,*/

/*		entry->macaddr.addr_bytes[0],*/
/*		entry->macaddr.addr_bytes[1],*/
/*		entry->macaddr.addr_bytes[2],*/
/*		entry->macaddr.addr_bytes[3],*/
/*		entry->macaddr.addr_bytes[4],*/
/*		entry->macaddr.addr_bytes[5]);*/
/*}*/

#if 0
/*
 * arp add
 */

struct cmd_arp_add_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t arpadd_string;
	uint32_t port_id;
	cmdline_ipaddr_t ip;
	struct ether_addr macaddr;

};

static void
cmd_arp_add_parsed(void *parsed_result,
			 __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_arp_add_result *params = parsed_result;
	uint8_t ipv6[16];

/*	struct pipeline_arp_icmp_arp_key key;*/
/*	key.type = PIPELINE_ARP_ICMP_ARP_IPV4;*/
/*	key.key.ipv4.port_id = params->port_id;*/
/*	key.key.ipv4.ip = rte_cpu_to_be_32(params->ip.addr.ipv4.s_addr);*/
/*	populate_arp_entry(&req->macaddr, rte_bswap32(req->key.key.ipv4.ip),
 * req->key.key.ipv4.port_id);
 */
	if (params->ip.family == AF_INET) {
		populate_arp_entry(&params->macaddr,
					 rte_cpu_to_be_32(params->ip.addr.
								ipv4.s_addr),
					 params->port_id, STATIC_ARP);
	} else {
		memcpy(ipv6, params->ip.addr.ipv6.s6_addr, 16);
		populate_nd_entry(&params->macaddr, ipv6, params->port_id, STATIC_ND);
	}
}

static cmdline_parse_token_string_t cmd_arp_add_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_add_result, p_string,
			 "p");

static cmdline_parse_token_num_t cmd_arp_add_p =
TOKEN_NUM_INITIALIZER(struct cmd_arp_add_result, p, UINT32);

static cmdline_parse_token_string_t cmd_arp_add_arp_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_add_result, arpadd_string, "arpadd");

static cmdline_parse_token_num_t cmd_arp_add_port_id =
TOKEN_NUM_INITIALIZER(struct cmd_arp_add_result, port_id, UINT32);

static cmdline_parse_token_ipaddr_t cmd_arp_add_ip =
TOKEN_IPADDR_INITIALIZER(struct cmd_arp_add_result, ip);

static cmdline_parse_token_etheraddr_t cmd_arp_add_macaddr =
TOKEN_ETHERADDR_INITIALIZER(struct cmd_arp_add_result, macaddr);

static cmdline_parse_inst_t cmd_arp_add = {
	.f = cmd_arp_add_parsed,
	.data = NULL,
	.help_str = "ARP add",
	.tokens = {
			 (void *)&cmd_arp_add_p_string,
			 (void *)&cmd_arp_add_p,
			 (void *)&cmd_arp_add_arp_string,
			 (void *)&cmd_arp_add_port_id,
			 (void *)&cmd_arp_add_ip,
			 (void *)&cmd_arp_add_macaddr,
			 NULL,
			 },
};

/*
 * arp del
 */

struct cmd_arp_del_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t arp_string;
	uint32_t port_id;
	cmdline_ipaddr_t ip;
};

static void
cmd_arp_del_parsed(void *parsed_result,
			 __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_arp_del_result *params = parsed_result;
	uint8_t ipv6[16];

/*	struct pipeline_arp_icmp_arp_key key;*/
/*	key.type = PIPELINE_ARP_ICMP_ARP_IPV4;*/
/*	key.key.ipv4.ip = rte_cpu_to_be_32(params->ip.addr.ipv4.s_addr);*/
/*	key.key.ipv4.port_id = params->port_id;*/
/*	remove_arp_entry(rte_bswap32(req->key.key.ipv4.ip),
 * req->key.key.ipv4.port_id);
 */
	if (params->ip.family == AF_INET) {
		remove_arp_entry(rte_cpu_to_be_32(params->ip.addr.ipv4.s_addr),
				 params->port_id, NULL);
	} else {
		memcpy(ipv6, params->ip.addr.ipv6.s6_addr, 16);
		remove_nd_entry_ipv6(ipv6, params->port_id);
	}
}

static cmdline_parse_token_string_t cmd_arp_del_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_del_result, p_string,
			 "p");

static cmdline_parse_token_num_t cmd_arp_del_p =
TOKEN_NUM_INITIALIZER(struct cmd_arp_del_result, p, UINT32);

static cmdline_parse_token_string_t cmd_arp_del_arp_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_del_result, arp_string, "arpdel");

static cmdline_parse_token_num_t cmd_arp_del_port_id =
TOKEN_NUM_INITIALIZER(struct cmd_arp_del_result, port_id, UINT32);

static cmdline_parse_token_ipaddr_t cmd_arp_del_ip =
TOKEN_IPADDR_INITIALIZER(struct cmd_arp_del_result, ip);

static cmdline_parse_inst_t cmd_arp_del = {
	.f = cmd_arp_del_parsed,
	.data = NULL,
	.help_str = "ARP delete",
	.tokens = {
			 (void *)&cmd_arp_del_p_string,
			 (void *)&cmd_arp_del_p,
			 (void *)&cmd_arp_del_arp_string,
			 (void *)&cmd_arp_del_port_id,
			 (void *)&cmd_arp_del_ip,
			 NULL,
			 },
};

/*
 * arp req
 */

/*Re-uses delete structures*/

static void
cmd_arp_req_parsed(void *parsed_result,
			 __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_arp_del_result *params = parsed_result;
	/*struct app_params *app = data;*/

	struct arp_key_ipv4 key;
/*	int status;*/

/*	key.type = ARP_IPV4;*/
/*	key.key.ipv4.ip = rte_cpu_to_be_32(params->ip.addr.ipv4.s_addr);*/
/*	key.key.ipv4.port_id = params->port_id;*/
	key.ip = rte_cpu_to_be_32(params->ip.addr.ipv4.s_addr);
	key.port_id = params->port_id;
	key.filler1 = 0;
	key.filler2 = 0;
	key.filler3 = 0;

	struct arp_entry_data *arp_data = retrieve_arp_entry(key);

	if (arp_data) {
		if (ARPICMP_DEBUG)
			printf("ARP entry exists for ip 0x%x, port %d\n",
						 params->ip.addr.ipv4.s_addr, params->port_id);
		return;
	}
	/* else request an arp*/
	if (ARPICMP_DEBUG)
		printf("ARP - requesting arp for ip 0x%x, port %d\n",
					 params->ip.addr.ipv4.s_addr, params->port_id);
	request_arp(params->port_id, params->ip.addr.ipv4.s_addr);
	/*give pipeline number too*/
}

static cmdline_parse_token_string_t cmd_arp_req_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_del_result, arp_string, "arpreq");

static cmdline_parse_inst_t cmd_arp_req = {
	.f = cmd_arp_req_parsed,
	.data = NULL,
	.help_str = "ARP request",
	.tokens = {
			 (void *)&cmd_arp_del_p_string,
			 (void *)&cmd_arp_del_p,
			 (void *)&cmd_arp_req_string,
			 (void *)&cmd_arp_del_port_id,
			 (void *)&cmd_arp_del_ip,
			 NULL,
			 },
};

/*
 * arpicmp echo req
 */

/*Re-uses delete structures*/

static void
cmd_icmp_echo_req_parsed(void *parsed_result,
			 __rte_unused struct cmdline *cl,
			 __rte_unused void *data)
{
	struct cmd_arp_del_result *params = parsed_result;
	struct rte_mbuf *pkt;
	l2_phy_interface_t *port = (l2_phy_interface_t *) ifm_get_port((uint8_t)params->port_id);

	if (ARPICMP_DEBUG)
		printf("Echo Req Handler ip %x, port %d\n",
					 params->ip.addr.ipv4.s_addr, params->port_id);

	pkt = request_echo(params->port_id, params->ip.addr.ipv4.s_addr);
	port->transmit_single_pkt(port, pkt);
}

static cmdline_parse_token_string_t cmd_icmp_echo_req_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_del_result, arp_string, "icmpecho");

static cmdline_parse_inst_t cmd_icmp_echo_req = {
	.f = cmd_icmp_echo_req_parsed,
	.data = NULL,
	.help_str = "ICMP echo request",
	.tokens = {
			 (void *)&cmd_arp_del_p_string,
			 (void *)&cmd_arp_del_p,
			 (void *)&cmd_icmp_echo_req_string,
			 (void *)&cmd_arp_del_port_id,
			 (void *)&cmd_arp_del_ip,
			 NULL,
			 },
};

/*
 * arp ls
 */

struct cmd_arp_ls_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t arp_string;
};

static void
cmd_arp_ls_parsed(__rte_unused void *parsed_result,
			__rte_unused struct cmdline *cl, __rte_unused void *data)
{
	printf("\nARP table ...\n");
	printf("-------------\n");
	print_arp_table();

	printf
			("............................................................\n");

	printf("\nND IPv6 table:\n");
	printf("--------------\n");
	print_nd_table();
}

static cmdline_parse_token_string_t cmd_arp_ls_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_ls_result, p_string,
			 "p");

static cmdline_parse_token_num_t cmd_arp_ls_p =
TOKEN_NUM_INITIALIZER(struct cmd_arp_ls_result, p, UINT32);

static cmdline_parse_token_string_t cmd_arp_ls_arp_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_ls_result, arp_string,
			 "arpls");

static cmdline_parse_inst_t cmd_arp_ls = {
	.f = cmd_arp_ls_parsed,
	.data = NULL,
	.help_str = "ARP list",
	.tokens = {
			 (void *)&cmd_arp_ls_p_string,
			 (void *)&cmd_arp_ls_p,
			 (void *)&cmd_arp_ls_arp_string,
			 NULL,
			 },
};

/*
 * show ports info
 */

struct cmd_show_ports_info_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t arp_string;
};

static void
cmd_show_ports_info_parsed(__rte_unused void *parsed_result,
				 __rte_unused struct cmdline *cl,
				 __rte_unused void *data)
{
	show_ports_info();
}

static cmdline_parse_token_string_t cmd_show_ports_info_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_ls_result, arp_string,
			 "showPortsInfo");

static cmdline_parse_inst_t cmd_show_ports_info = {
	.f = cmd_show_ports_info_parsed,
	.data = NULL,
	.help_str = "show ports info",
	.tokens = {
			 (void *)&cmd_arp_ls_p_string,
			 (void *)&cmd_arp_ls_p,
			 (void *)&cmd_show_ports_info_string,
			 NULL,
			 },
};
#endif

static cmdline_parse_ctx_t pipeline_cmds[] = {
	(cmdline_parse_inst_t *) &lb_cmd_entry_dbg,
	NULL,
};

static struct pipeline_fe_ops pipeline_loadb_fe_ops = {
	.f_init = NULL,
	.f_free = NULL,
	.cmds = pipeline_cmds,
};

struct pipeline_type pipeline_loadb = {
	.name = "LOADB",
	.be_ops = &pipeline_loadb_be_ops,
	.fe_ops = &pipeline_loadb_fe_ops,
};
