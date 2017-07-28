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

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_ring.h>
#include <rte_malloc.h>
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_etheraddr.h>
#include <cmdline_socket.h>
#include <cmdline.h>

#include "pipeline_common_fe.h"
#include "interface.h"
#include "lib_arp.h"
#include "gateway.h"

int
app_pipeline_ping(struct app_params *app,
	uint32_t pipeline_id)
{
	struct app_pipeline_params *p;
	struct pipeline_msg_req *req;
	struct pipeline_msg_rsp *rsp;
	int status = 0;

	/* Check input arguments */
	if (app == NULL)
		return -1;

	APP_PARAM_FIND_BY_ID(app->pipeline_params, "PIPELINE", pipeline_id, p);
	if (p == NULL)
		return -1;

	/* Message buffer allocation */
	req = app_msg_alloc(app);
	if (req == NULL)
		return -1;

	/* Fill in request */
	req->type = PIPELINE_MSG_REQ_PING;

	/* Send request and wait for response */
	rsp = app_msg_send_recv(app, pipeline_id, req, MSG_TIMEOUT_DEFAULT);
	if (rsp == NULL)
		return -1;

	/* Check response */
	status = rsp->status;

	/* Message buffer free */
	app_msg_free(app, rsp);

	return status;
}
#if 1
int
app_pipeline_stats_port_in(struct app_params *app,
	uint32_t pipeline_id,
	uint32_t port_id,
	struct rte_pipeline_port_in_stats *stats)
{
	struct app_pipeline_params *p;
	struct pipeline_stats_msg_req *req;
	struct pipeline_stats_port_in_msg_rsp *rsp;
	int status = 0;

	/* Check input arguments */
	if ((app == NULL) ||
		(stats == NULL))
		return -1;

	APP_PARAM_FIND_BY_ID(app->pipeline_params, "PIPELINE", pipeline_id, p);
	if ((p == NULL) ||
		(port_id >= p->n_pktq_in))
		return -1;

	/* Message buffer allocation */
	req = app_msg_alloc(app);
	if (req == NULL)
		return -1;

	/* Fill in request */
	req->type = PIPELINE_MSG_REQ_STATS_PORT_IN;
	req->id = port_id;

	/* Send request and wait for response */
	rsp = (struct pipeline_stats_port_in_msg_rsp *)
		app_msg_send_recv(app, pipeline_id, req, MSG_TIMEOUT_DEFAULT);
	if (rsp == NULL)
		return -1;

	/* Check response */
	status = rsp->status;
	if (status == 0)
		memcpy(stats, &rsp->stats, sizeof(rsp->stats));

	/* Message buffer free */
	app_msg_free(app, rsp);

	return status;
}

int
app_pipeline_stats_port_out(struct app_params *app,
	uint32_t pipeline_id,
	uint32_t port_id,
	struct rte_pipeline_port_out_stats *stats)
{
	struct app_pipeline_params *p;
	struct pipeline_stats_msg_req *req;
	struct pipeline_stats_port_out_msg_rsp *rsp;
	int status = 0;

	/* Check input arguments */
	if ((app == NULL) ||
		(pipeline_id >= app->n_pipelines) ||
		(stats == NULL))
		return -1;

	APP_PARAM_FIND_BY_ID(app->pipeline_params, "PIPELINE", pipeline_id, p);
	if ((p == NULL) ||
		(port_id >= p->n_pktq_out))
		return -1;

	/* Message buffer allocation */
	req = app_msg_alloc(app);
	if (req == NULL)
		return -1;

	/* Fill in request */
	req->type = PIPELINE_MSG_REQ_STATS_PORT_OUT;
	req->id = port_id;

	/* Send request and wait for response */
	rsp = app_msg_send_recv(app, pipeline_id, req, MSG_TIMEOUT_DEFAULT);
	if (rsp == NULL)
		return -1;

	/* Check response */
	status = rsp->status;
	if (status == 0)
		memcpy(stats, &rsp->stats, sizeof(rsp->stats));

	/* Message buffer free */
	app_msg_free(app, rsp);

	return status;
}

int
app_pipeline_stats_table(struct app_params *app,
	uint32_t pipeline_id,
	uint32_t table_id,
	struct rte_pipeline_table_stats *stats)
{
	struct app_pipeline_params *p;
	struct pipeline_stats_msg_req *req;
	struct pipeline_stats_table_msg_rsp *rsp;
	int status = 0;

	/* Check input arguments */
	if ((app == NULL) ||
		(stats == NULL))
		return -1;

	APP_PARAM_FIND_BY_ID(app->pipeline_params, "PIPELINE", pipeline_id, p);
	if (p == NULL)
		return -1;

	/* Message buffer allocation */
	req = app_msg_alloc(app);
	if (req == NULL)
		return -1;

	/* Fill in request */
	req->type = PIPELINE_MSG_REQ_STATS_TABLE;
	req->id = table_id;

	/* Send request and wait for response */
	rsp = app_msg_send_recv(app, pipeline_id, req, MSG_TIMEOUT_DEFAULT);
	if (rsp == NULL)
		return -1;

	/* Check response */
	status = rsp->status;
	if (status == 0)
		memcpy(stats, &rsp->stats, sizeof(rsp->stats));

	/* Message buffer free */
	app_msg_free(app, rsp);

	return status;
}

int
app_pipeline_port_in_enable(struct app_params *app,
	uint32_t pipeline_id,
	uint32_t port_id)
{
	struct app_pipeline_params *p;
	struct pipeline_port_in_msg_req *req;
	struct pipeline_msg_rsp *rsp;
	int status = 0;

	/* Check input arguments */
	if (app == NULL)
		return -1;

	APP_PARAM_FIND_BY_ID(app->pipeline_params, "PIPELINE", pipeline_id, p);
	if ((p == NULL) ||
		(port_id >= p->n_pktq_in))
		return -1;

	/* Message buffer allocation */
	req = app_msg_alloc(app);
	if (req == NULL)
		return -1;

	/* Fill in request */
	req->type = PIPELINE_MSG_REQ_PORT_IN_ENABLE;
	req->port_id = port_id;

	/* Send request and wait for response */
	rsp = app_msg_send_recv(app, pipeline_id, req, MSG_TIMEOUT_DEFAULT);
	if (rsp == NULL)
		return -1;

	/* Check response */
	status = rsp->status;

	/* Message buffer free */
	app_msg_free(app, rsp);

	return status;
}

int
app_pipeline_port_in_disable(struct app_params *app,
	uint32_t pipeline_id,
	uint32_t port_id)
{
	struct app_pipeline_params *p;
	struct pipeline_port_in_msg_req *req;
	struct pipeline_msg_rsp *rsp;
	int status = 0;

	/* Check input arguments */
	if (app == NULL)
		return -1;

	APP_PARAM_FIND_BY_ID(app->pipeline_params, "PIPELINE", pipeline_id, p);
	if ((p == NULL) ||
		(port_id >= p->n_pktq_in))
		return -1;

	/* Message buffer allocation */
	req = app_msg_alloc(app);
	if (req == NULL)
		return -1;

	/* Fill in request */
	req->type = PIPELINE_MSG_REQ_PORT_IN_DISABLE;
	req->port_id = port_id;

	/* Send request and wait for response */
	rsp = app_msg_send_recv(app, pipeline_id, req, MSG_TIMEOUT_DEFAULT);
	if (rsp == NULL)
		return -1;

	/* Check response */
	status = rsp->status;

	/* Message buffer free */
	app_msg_free(app, rsp);

	return status;
}

int
app_link_config(struct app_params *app,
	uint32_t link_id,
	uint32_t ip,
	uint32_t depth)
{
	struct app_link_params *p;
	uint32_t i, netmask, host, bcast;

	/* Check input arguments */
	if (app == NULL)
		return -1;

	APP_PARAM_FIND_BY_ID(app->link_params, "LINK", link_id, p);
	if (p == NULL) {
		APP_LOG(app, HIGH, "LINK%" PRIu32 " is not a valid link",
			link_id);
		return -1;
	}

	if (p->state) {
		APP_LOG(app, HIGH, "%s is UP, please bring it DOWN first",
			p->name);
		return -1;
	}

	netmask = (~0U) << (32 - depth);
	host = ip & netmask;
	bcast = host | (~netmask);

	if ((ip == 0) ||
		(ip == UINT32_MAX) ||
		(ip == host) ||
		(ip == bcast)) {
		APP_LOG(app, HIGH, "Illegal IP address");
		return -1;
	}

	for (i = 0; i < app->n_links; i++) {
		struct app_link_params *link = &app->link_params[i];
		mylink[i] = *link;
		if (strcmp(p->name, link->name) == 0)
			continue;

		if (link->ip == ip) {
			APP_LOG(app, HIGH,
				"%s is already assigned this IP address",
				link->name);
			return -1;
		}
	}

	if ((depth == 0) || (depth > 32)) {
		APP_LOG(app, HIGH, "Illegal value for depth parameter "
			"(%" PRIu32 ")",
			depth);
		return -1;
	}

	/* Save link parameters */
	p->ip = ip;
	p->depth = depth;
        if (ifm_add_ipv4_port(link_id, rte_bswap32(ip), depth) == IFM_FAILURE)
            return -1;

	return 0;
}


void convert_prefixlen_to_netmask_ipv6(uint32_t depth, uint8_t netmask_ipv6[])
{
	int mod, div, i;

	memset(netmask_ipv6, 0, 16);

	mod = depth % 8;
	div = depth / 8;

	for (i = 0; i < div; i++)
		netmask_ipv6[i] = 0xff;

	netmask_ipv6[i] = (~0 << (8 - mod));

	return;
}

void
get_host_portion_ipv6(uint8_t ipv6[], uint8_t netmask[], uint8_t host_ipv6[])
{
	int i;

	for (i = 0; i < 16; i++) {
		host_ipv6[i] = ipv6[i] & netmask[i];
	}

	return;
}

void
get_bcast_portion_ipv6(uint8_t host[], uint8_t netmask[], uint8_t bcast_ipv6[])
{
	int i;

	for (i = 0; i < 16; i++) {
		bcast_ipv6[i] = host[i] | ~netmask[i];
	}

	return;
}

int
app_link_config_ipv6(struct app_params *app,
				 uint32_t link_id, uint8_t ipv6[], uint32_t depth)
{
	struct app_link_params *p;
	uint32_t i;
	uint8_t netmask_ipv6[16], host[16], bcast[16];

	/* Check input arguments */
	if (app == NULL)
		return -1;

	APP_PARAM_FIND_BY_ID(app->link_params, "LINK", link_id, p);
	if (p == NULL) {
		APP_LOG(app, HIGH, "LINK%" PRIu32 " is not a valid link",
			link_id);
		return -1;
	}

	if (p->state) {
		APP_LOG(app, HIGH, "%s is UP, please bring it DOWN first",
			p->name);
		return -1;
	}

	convert_prefixlen_to_netmask_ipv6(depth, netmask_ipv6);
	get_host_portion_ipv6(ipv6, netmask_ipv6, host);
	get_bcast_portion_ipv6(host, netmask_ipv6, bcast);

	for (i = 0; i < app->n_links; i++) {
		struct app_link_params *link = &app->link_params[i];

		if (strcmp(p->name, link->name) == 0)
			continue;

		if (!memcmp(link->ipv6, ipv6, 16)) {
			APP_LOG(app, HIGH,
				"%s is already assigned this IPv6 address",
				link->name);
			return -1;
		}
	}

	if ((depth == 0) || (depth > 128)) {
		APP_LOG(app, HIGH, "Illegal value for depth parameter "
			"(%" PRIu32 ")", depth);
		return -1;
	}

	/* Save link parameters */
	memcpy(p->ipv6, ipv6, 16);

	p->depth_ipv6 = depth;
/*
	 printf("IPv6: %x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x",
					ipv6[0], ipv6[1], ipv6[2], ipv6[3], ipv6[4], ipv6[5],
		ipv6[6], ipv6[7], ipv6[8], ipv6[9], ipv6[10], ipv6[11],
		ipv6[12], ipv6[13], ipv6[14], ipv6[15]);
*/
	if (ifm_add_ipv6_port(link_id, ipv6, depth) == IFM_FAILURE)
		return -1;
	return 0;
}

int
app_link_up(struct app_params *app,
	uint32_t link_id)
{
	struct app_link_params *p;

	/* Check input arguments */
	if (app == NULL)
		return -1;

	APP_PARAM_FIND_BY_ID(app->link_params, "LINK", link_id, p);
	if (p == NULL) {
		APP_LOG(app, HIGH, "LINK%" PRIu32 " is not a valid link",
			link_id);
		return -1;
	}

	/* Check link state */
	if (p->state) {
		APP_LOG(app, HIGH, "%s is already UP", p->name);
		return 0;
	}

	/* Check that IP address is valid */
	uint8_t temp[16];

	memset(temp, 0, 16);

	if ((p->ip || memcmp(p->ipv6, temp, 16)) == 0) {
		APP_LOG(app, HIGH, "%s IP address is not set", p->name);
		return 0;
	}

	app_link_up_internal(app, p);

	return 0;
}

int
app_link_down(struct app_params *app,
	uint32_t link_id)
{
	struct app_link_params *p;

	/* Check input arguments */
	if (app == NULL)
		return -1;

	APP_PARAM_FIND_BY_ID(app->link_params, "LINK", link_id, p);
	if (p == NULL) {
		APP_LOG(app, HIGH, "LINK%" PRIu32 " is not a valid link",
			link_id);
		return -1;
	}

	/* Check link state */
	if (p->state == 0) {
		APP_LOG(app, HIGH, "%s is already DOWN", p->name);
		return 0;
	}

	app_link_down_internal(app, p);

	return 0;
}

/*
 * Route add
 */
struct cmd_routeadd_config_result {
        cmdline_fixed_string_t routeadd_string;
        cmdline_fixed_string_t type_string;
        uint32_t port_id;
        cmdline_ipaddr_t ip;
        cmdline_fixed_string_t depth;
};

extern struct arp_data *p_arp_data;
extern uint32_t nd_route_tbl_index;

/*
 * This implements route add entries for ipv4
 */
int app_routeadd_config_ipv4(__attribute__((unused)) struct app_params *app,
	uint32_t port_id, uint32_t ip, uint32_t mask)
{
	uint32_t i = 0;
	if (port_id >= gw_get_num_ports()) {
		printf("Max ports allowed is %d\n", gw_get_num_ports());
		return 1;
	}

	printf("port id:%d ip: %x mask:%x\n", port_id, ip, mask);

	struct route_table_entry *lentry = NULL;

	/* Check for matching entry */
	for(i = 0 ; i< p_route_data[port_id]->route_ent_cnt; i++) {

		lentry = &p_route_data[port_id]->route_table[i];

		/* Entry already exists? */
		if(mask == 0) {
			if(lentry->nh == ip)
				return 1;
		} else {
			if( lentry->nh_mask == (ip & mask))
				return 1;
		}
	}
	if(i < MAX_ROUTE_ENTRY_SIZE) {

		lentry = &p_route_data[port_id]->route_table[i];

		p_route_data[port_id]->route_ent_cnt++;
		lentry->mask = mask;
		lentry->port = port_id;
		lentry->nh = ip;
		lentry->nh_mask = (ip & mask);
		/* Set the VNF Gateway flag */
		vnf_gateway = 1;
		return 0;
	} else {

		printf("Error: Number of entries more than supported\n");
		return 1;
	}

}

/*
 * This implements route add entries for ipv6
 */
int app_routeadd_config_ipv6(__attribute__((unused)) struct app_params *app,
	uint32_t port_id, uint8_t ipv6[], uint32_t depth)
{
	int i;

	if (port_id >= gw_get_num_ports()) {
		printf("Max ports allowed is %d\n", gw_get_num_ports());
		return 1;
	}

	if (port_id >= nd_route_tbl_index)
		nd_route_tbl_index++;

	printf("port id:%d depth:%d\n", port_id, depth);
	printf("ipv6 address: ");
	for(i = 0; i < IPV6_ADD_SIZE; i++)
		printf("%02x ", ipv6[i]);
	printf("\n");

	struct nd_route_table_entry *lentry = NULL;
	int k;
	uint8_t netmask_ipv6[16], netip_nd[16], netip_in[16];
	uint8_t depthflags = 0, depthflags1 = 0;

	i = 0;

	/* Check for matching entry */
	for(i = 0 ; i< p_nd_route_data[port_id]->nd_route_ent_cnt; i++) {

		lentry = &p_nd_route_data[port_id]->nd_route_table[i];

		memset(netmask_ipv6, 0, sizeof(netmask_ipv6));
		memset(netip_nd, 0, sizeof(netip_nd));
		memset(netip_in, 0, sizeof(netip_in));

		/* Create netmask from depth */
		convert_prefixlen_to_netmask_ipv6(lentry->depth, netmask_ipv6);

		for (k = 0; k < 16; k++) {
			if (lentry->nhipv6[k] & netmask_ipv6[k]) {
				depthflags++;
				netip_nd[k] = lentry->nhipv6[k];
			}

			if (ipv6[k] & netmask_ipv6[k]) {
				depthflags1++;
				netip_in[k] = ipv6[k];
			}
		}

		if ((depthflags == depthflags1)
				&& (memcmp(netip_nd, netip_in, sizeof(netip_nd)) == 0)) {
				/* Route already exists */
			printf("Route already exists \n");
				return 1;
		}
	}

	if(i < MAX_ND_ROUTE_ENTRY_SIZE) {

		lentry = &p_nd_route_data[port_id]->nd_route_table[i];

		rte_mov16(lentry->nhipv6, ipv6);

		lentry->depth = depth;
		lentry->port = port_id;
		p_nd_route_data[port_id]->nd_route_ent_cnt++;
		/* Set the VNF Gateway flag */
		vnf_gateway = 1;

		return 0;
	} else {

		printf("Error: Number of entries more than supported\n");
		return 1;
	}
}

/*
 * cmd handler for handling route abj entry at runtime.
 * the same handle takes care of both ipv4 & ipv6
 */
static void
cmd_routeadd_parsed(
        void *parsed_result,
        __attribute__((unused)) struct cmdline *cl,
         void *data)
{
        struct cmd_routeadd_config_result *params = parsed_result;
        struct app_params *app = data;
        int status;

        uint32_t port_id = params->port_id;
	uint32_t i, ip = 0, depth = 0, mask = 0;
        uint8_t ipv6[16];

	printf("Adding route for %s \n", params->type_string);

        if (params->ip.family == AF_INET) {
                ip = rte_bswap32((uint32_t) params->ip.addr.ipv4.s_addr);

		if(strcmp(params->type_string, "net") == 0)
		{
			mask = strtoul(params->depth, NULL, 16);
		} else {
			mask = 0xffffffff;
		}

		printf("nhip:0x%08x mask:%x port_id:%d\n", ip, mask, port_id);
	} else {
                memcpy(ipv6, params->ip.addr.ipv6.s6_addr, 16);
		if(strcmp(params->type_string, "net") == 0)
		{
			depth = atoi(params->depth);
		} else {
			depth = 64;
		}

		for (i=0; i < 16; i++)
			printf("%02x ", ipv6[i]);
		printf("\n port_id:%d depth:%d \n", port_id, depth);
	}


        if (params->ip.family == AF_INET)
                status = app_routeadd_config_ipv4(app, port_id, ip, mask);
        else
                status = app_routeadd_config_ipv6(app, port_id, ipv6, depth);

        if (status)
                printf("Command failed\n");
        else
                printf("Command Success\n");
}

cmdline_parse_token_string_t cmd_routeadd_config_string =
        TOKEN_STRING_INITIALIZER(struct cmd_routeadd_config_result, routeadd_string,
                "routeadd");

cmdline_parse_token_string_t cmd_routeadd_net_string =
        TOKEN_STRING_INITIALIZER(struct cmd_routeadd_config_result, type_string,
                "net");

cmdline_parse_token_string_t cmd_routeadd_host_string =
        TOKEN_STRING_INITIALIZER(struct cmd_routeadd_config_result, type_string,
                "host");

cmdline_parse_token_num_t cmd_routeadd_config_port_id =
        TOKEN_NUM_INITIALIZER(struct cmd_routeadd_config_result, port_id, UINT32);

cmdline_parse_token_ipaddr_t cmd_routeadd_config_ip =
        TOKEN_IPADDR_INITIALIZER(struct cmd_routeadd_config_result, ip);

cmdline_parse_token_string_t cmd_routeadd_config_depth_string =
        TOKEN_STRING_INITIALIZER(struct cmd_routeadd_config_result, depth, NULL);

cmdline_parse_inst_t cmd_routeadd_net = {
        .f = cmd_routeadd_parsed,
        .data = NULL,
        .help_str = "Add Route entry for gateway",
        .tokens = {
                (void *) &cmd_routeadd_config_string,
                (void *) &cmd_routeadd_net_string,
                (void *) &cmd_routeadd_config_port_id,
		(void *) &cmd_routeadd_config_ip,
		(void *) &cmd_routeadd_config_depth_string,
                NULL,
        },
};

cmdline_parse_inst_t cmd_routeadd_host = {
        .f = cmd_routeadd_parsed,
        .data = NULL,
        .help_str = "Add Route entry for host",
        .tokens = {
                (void *) &cmd_routeadd_config_string,
                (void *) &cmd_routeadd_host_string,
                (void *) &cmd_routeadd_config_port_id,
		(void *) &cmd_routeadd_config_ip,
                NULL,
        },
};

/*
 * ping
 */

struct cmd_ping_result {
	cmdline_fixed_string_t p_string;
	uint32_t pipeline_id;
	cmdline_fixed_string_t ping_string;
};

static void
cmd_ping_parsed(
	void *parsed_result,
	__rte_unused struct cmdline *cl,
	void *data)
{
	struct cmd_ping_result *params = parsed_result;
	struct app_params *app = data;
	int status;

	status = app_pipeline_ping(app,	params->pipeline_id);
	if (status != 0)
		printf("Command failed\n");
}

cmdline_parse_token_string_t cmd_ping_p_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ping_result, p_string, "p");

cmdline_parse_token_num_t cmd_ping_pipeline_id =
	TOKEN_NUM_INITIALIZER(struct cmd_ping_result, pipeline_id, UINT32);

cmdline_parse_token_string_t cmd_ping_ping_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ping_result, ping_string, "ping");

cmdline_parse_inst_t cmd_ping = {
	.f = cmd_ping_parsed,
	.data = NULL,
	.help_str = "Pipeline ping",
	.tokens = {
		(void *) &cmd_ping_p_string,
		(void *) &cmd_ping_pipeline_id,
		(void *) &cmd_ping_ping_string,
		NULL,
	},
};

/*
 * stats port in
 */

struct cmd_stats_port_in_result {
	cmdline_fixed_string_t p_string;
	uint32_t pipeline_id;
	cmdline_fixed_string_t stats_string;
	cmdline_fixed_string_t port_string;
	cmdline_fixed_string_t in_string;
	uint32_t port_in_id;

};
static void
cmd_stats_port_in_parsed(
	void *parsed_result,
	__rte_unused struct cmdline *cl,
	void *data)
{
	struct cmd_stats_port_in_result *params = parsed_result;
	struct app_params *app = data;
	struct rte_pipeline_port_in_stats stats;
	int status;

	status = app_pipeline_stats_port_in(app,
			params->pipeline_id,
			params->port_in_id,
			&stats);

	if (status != 0) {
		printf("Command failed\n");
		return;
	}

	/* Display stats */
	printf("Pipeline %" PRIu32 " - stats for input port %" PRIu32 ":\n"
		"\tPkts in: %" PRIu64 "\n"
		"\tPkts dropped by AH: %" PRIu64 "\n"
		"\tPkts dropped by other: %" PRIu64 "\n",
		params->pipeline_id,
		params->port_in_id,
		stats.stats.n_pkts_in,
		stats.n_pkts_dropped_by_ah,
		stats.stats.n_pkts_drop);
}

cmdline_parse_token_string_t cmd_stats_port_in_p_string =
	TOKEN_STRING_INITIALIZER(struct cmd_stats_port_in_result, p_string,
		"p");

cmdline_parse_token_num_t cmd_stats_port_in_pipeline_id =
	TOKEN_NUM_INITIALIZER(struct cmd_stats_port_in_result, pipeline_id,
		UINT32);

cmdline_parse_token_string_t cmd_stats_port_in_stats_string =
	TOKEN_STRING_INITIALIZER(struct cmd_stats_port_in_result, stats_string,
		"stats");

cmdline_parse_token_string_t cmd_stats_port_in_port_string =
	TOKEN_STRING_INITIALIZER(struct cmd_stats_port_in_result, port_string,
		"port");

cmdline_parse_token_string_t cmd_stats_port_in_in_string =
	TOKEN_STRING_INITIALIZER(struct cmd_stats_port_in_result, in_string,
		"in");

	cmdline_parse_token_num_t cmd_stats_port_in_port_in_id =
	TOKEN_NUM_INITIALIZER(struct cmd_stats_port_in_result, port_in_id,
		UINT32);

cmdline_parse_inst_t cmd_stats_port_in = {
	.f = cmd_stats_port_in_parsed,
	.data = NULL,
	.help_str = "Pipeline input port stats",
	.tokens = {
		(void *) &cmd_stats_port_in_p_string,
		(void *) &cmd_stats_port_in_pipeline_id,
		(void *) &cmd_stats_port_in_stats_string,
		(void *) &cmd_stats_port_in_port_string,
		(void *) &cmd_stats_port_in_in_string,
		(void *) &cmd_stats_port_in_port_in_id,
		NULL,
	},
};

/*
 * stats port out
 */

struct cmd_stats_port_out_result {
	cmdline_fixed_string_t p_string;
	uint32_t pipeline_id;
	cmdline_fixed_string_t stats_string;
	cmdline_fixed_string_t port_string;
	cmdline_fixed_string_t out_string;
	uint32_t port_out_id;
};

static void
cmd_stats_port_out_parsed(
	void *parsed_result,
	__rte_unused struct cmdline *cl,
	void *data)
{

	struct cmd_stats_port_out_result *params = parsed_result;
	struct app_params *app = data;
	struct rte_pipeline_port_out_stats stats;
	int status;

	status = app_pipeline_stats_port_out(app,
			params->pipeline_id,
			params->port_out_id,
			&stats);

	if (status != 0) {
		printf("Command failed\n");
		return;
	}

	/* Display stats */
	printf("Pipeline %" PRIu32 " - stats for output port %" PRIu32 ":\n"
		"\tPkts in: %" PRIu64 "\n"
		"\tPkts dropped by AH: %" PRIu64 "\n"
		"\tPkts dropped by other: %" PRIu64 "\n",
		params->pipeline_id,
		params->port_out_id,
		stats.stats.n_pkts_in,
		stats.n_pkts_dropped_by_ah,
		stats.stats.n_pkts_drop);
}

cmdline_parse_token_string_t cmd_stats_port_out_p_string =
	TOKEN_STRING_INITIALIZER(struct cmd_stats_port_out_result, p_string,
	"p");

cmdline_parse_token_num_t cmd_stats_port_out_pipeline_id =
	TOKEN_NUM_INITIALIZER(struct cmd_stats_port_out_result, pipeline_id,
		UINT32);

cmdline_parse_token_string_t cmd_stats_port_out_stats_string =
	TOKEN_STRING_INITIALIZER(struct cmd_stats_port_out_result, stats_string,
		"stats");

cmdline_parse_token_string_t cmd_stats_port_out_port_string =
	TOKEN_STRING_INITIALIZER(struct cmd_stats_port_out_result, port_string,
		"port");

cmdline_parse_token_string_t cmd_stats_port_out_out_string =
	TOKEN_STRING_INITIALIZER(struct cmd_stats_port_out_result, out_string,
		"out");

cmdline_parse_token_num_t cmd_stats_port_out_port_out_id =
	TOKEN_NUM_INITIALIZER(struct cmd_stats_port_out_result, port_out_id,
		UINT32);

cmdline_parse_inst_t cmd_stats_port_out = {
	.f = cmd_stats_port_out_parsed,
	.data = NULL,
	.help_str = "Pipeline output port stats",
	.tokens = {
		(void *) &cmd_stats_port_out_p_string,
		(void *) &cmd_stats_port_out_pipeline_id,
		(void *) &cmd_stats_port_out_stats_string,
		(void *) &cmd_stats_port_out_port_string,
		(void *) &cmd_stats_port_out_out_string,
		(void *) &cmd_stats_port_out_port_out_id,
		NULL,
	},
};

/*
 * stats table
 */

struct cmd_stats_table_result {
	cmdline_fixed_string_t p_string;
	uint32_t pipeline_id;
	cmdline_fixed_string_t stats_string;
	cmdline_fixed_string_t table_string;
	uint32_t table_id;
};

static void
cmd_stats_table_parsed(
	void *parsed_result,
	__rte_unused struct cmdline *cl,
	void *data)
{
	struct cmd_stats_table_result *params = parsed_result;
	struct app_params *app = data;
	struct rte_pipeline_table_stats stats;
	int status;

	status = app_pipeline_stats_table(app,
			params->pipeline_id,
			params->table_id,
			&stats);

	if (status != 0) {
		printf("Command failed\n");
		return;
	}

	/* Display stats */
	printf("Pipeline %" PRIu32 " - stats for table %" PRIu32 ":\n"
		"\tPkts in: %" PRIu64 "\n"
		"\tPkts in with lookup miss: %" PRIu64 "\n"
		"\tPkts in with lookup hit dropped by AH: %" PRIu64 "\n"
		"\tPkts in with lookup hit dropped by others: %" PRIu64 "\n"
		"\tPkts in with lookup miss dropped by AH: %" PRIu64 "\n"
		"\tPkts in with lookup miss dropped by others: %" PRIu64 "\n",
		params->pipeline_id,
		params->table_id,
		stats.stats.n_pkts_in,
		stats.stats.n_pkts_lookup_miss,
		stats.n_pkts_dropped_by_lkp_hit_ah,
		stats.n_pkts_dropped_lkp_hit,
		stats.n_pkts_dropped_by_lkp_miss_ah,
		stats.n_pkts_dropped_lkp_miss);
}

cmdline_parse_token_string_t cmd_stats_table_p_string =
	TOKEN_STRING_INITIALIZER(struct cmd_stats_table_result, p_string,
		"p");

cmdline_parse_token_num_t cmd_stats_table_pipeline_id =
	TOKEN_NUM_INITIALIZER(struct cmd_stats_table_result, pipeline_id,
		UINT32);

cmdline_parse_token_string_t cmd_stats_table_stats_string =
	TOKEN_STRING_INITIALIZER(struct cmd_stats_table_result, stats_string,
		"stats");

cmdline_parse_token_string_t cmd_stats_table_table_string =
	TOKEN_STRING_INITIALIZER(struct cmd_stats_table_result, table_string,
		"table");

cmdline_parse_token_num_t cmd_stats_table_table_id =
	TOKEN_NUM_INITIALIZER(struct cmd_stats_table_result, table_id, UINT32);

cmdline_parse_inst_t cmd_stats_table = {
	.f = cmd_stats_table_parsed,
	.data = NULL,
	.help_str = "Pipeline table stats",
	.tokens = {
		(void *) &cmd_stats_table_p_string,
		(void *) &cmd_stats_table_pipeline_id,
		(void *) &cmd_stats_table_stats_string,
		(void *) &cmd_stats_table_table_string,
		(void *) &cmd_stats_table_table_id,
		NULL,
	},
};

/*
 * port in enable
 */

struct cmd_port_in_enable_result {
	cmdline_fixed_string_t p_string;
	uint32_t pipeline_id;
	cmdline_fixed_string_t port_string;
	cmdline_fixed_string_t in_string;
	uint32_t port_in_id;
	cmdline_fixed_string_t enable_string;
};

static void
cmd_port_in_enable_parsed(
	void *parsed_result,
	__rte_unused struct cmdline *cl,
	void *data)
{
	struct cmd_port_in_enable_result *params = parsed_result;
	struct app_params *app = data;
	int status;

	status = app_pipeline_port_in_enable(app,
			params->pipeline_id,
			params->port_in_id);

	if (status != 0)
		printf("Command failed\n");
}

cmdline_parse_token_string_t cmd_port_in_enable_p_string =
	TOKEN_STRING_INITIALIZER(struct cmd_port_in_enable_result, p_string,
		"p");

cmdline_parse_token_num_t cmd_port_in_enable_pipeline_id =
	TOKEN_NUM_INITIALIZER(struct cmd_port_in_enable_result, pipeline_id,
		UINT32);

cmdline_parse_token_string_t cmd_port_in_enable_port_string =
	TOKEN_STRING_INITIALIZER(struct cmd_port_in_enable_result, port_string,
	"port");

cmdline_parse_token_string_t cmd_port_in_enable_in_string =
	TOKEN_STRING_INITIALIZER(struct cmd_port_in_enable_result, in_string,
		"in");

cmdline_parse_token_num_t cmd_port_in_enable_port_in_id =
	TOKEN_NUM_INITIALIZER(struct cmd_port_in_enable_result, port_in_id,
		UINT32);

cmdline_parse_token_string_t cmd_port_in_enable_enable_string =
	TOKEN_STRING_INITIALIZER(struct cmd_port_in_enable_result,
		enable_string, "enable");

cmdline_parse_inst_t cmd_port_in_enable = {
	.f = cmd_port_in_enable_parsed,
	.data = NULL,
	.help_str = "Pipeline input port enable",
	.tokens = {
		(void *) &cmd_port_in_enable_p_string,
		(void *) &cmd_port_in_enable_pipeline_id,
		(void *) &cmd_port_in_enable_port_string,
		(void *) &cmd_port_in_enable_in_string,
		(void *) &cmd_port_in_enable_port_in_id,
		(void *) &cmd_port_in_enable_enable_string,
		NULL,
	},
};

/*
 * port in disable
 */

struct cmd_port_in_disable_result {
	cmdline_fixed_string_t p_string;
	uint32_t pipeline_id;
	cmdline_fixed_string_t port_string;
	cmdline_fixed_string_t in_string;
	uint32_t port_in_id;
	cmdline_fixed_string_t disable_string;
};

static void
cmd_port_in_disable_parsed(
	void *parsed_result,
	__rte_unused struct cmdline *cl,
	void *data)
{
	struct cmd_port_in_disable_result *params = parsed_result;
	struct app_params *app = data;
	int status;

	status = app_pipeline_port_in_disable(app,
			params->pipeline_id,
			params->port_in_id);

	if (status != 0)
		printf("Command failed\n");
}

cmdline_parse_token_string_t cmd_port_in_disable_p_string =
	TOKEN_STRING_INITIALIZER(struct cmd_port_in_disable_result, p_string,
		"p");

cmdline_parse_token_num_t cmd_port_in_disable_pipeline_id =
	TOKEN_NUM_INITIALIZER(struct cmd_port_in_disable_result, pipeline_id,
		UINT32);

cmdline_parse_token_string_t cmd_port_in_disable_port_string =
	TOKEN_STRING_INITIALIZER(struct cmd_port_in_disable_result, port_string,
		"port");

cmdline_parse_token_string_t cmd_port_in_disable_in_string =
	TOKEN_STRING_INITIALIZER(struct cmd_port_in_disable_result, in_string,
		"in");

cmdline_parse_token_num_t cmd_port_in_disable_port_in_id =
	TOKEN_NUM_INITIALIZER(struct cmd_port_in_disable_result, port_in_id,
		UINT32);

cmdline_parse_token_string_t cmd_port_in_disable_disable_string =
	TOKEN_STRING_INITIALIZER(struct cmd_port_in_disable_result,
		disable_string, "disable");

cmdline_parse_inst_t cmd_port_in_disable = {
	.f = cmd_port_in_disable_parsed,
	.data = NULL,
	.help_str = "Pipeline input port disable",
	.tokens = {
		(void *) &cmd_port_in_disable_p_string,
		(void *) &cmd_port_in_disable_pipeline_id,
		(void *) &cmd_port_in_disable_port_string,
		(void *) &cmd_port_in_disable_in_string,
		(void *) &cmd_port_in_disable_port_in_id,
		(void *) &cmd_port_in_disable_disable_string,
		NULL,
	},
};

/*
 * link config
 */

static void
print_link_info(struct app_link_params *p)
{
	struct rte_eth_stats stats;
	struct ether_addr *mac_addr;
	uint32_t netmask = (~0U) << (32 - p->depth);
	uint32_t host = p->ip & netmask;
	uint32_t bcast = host | (~netmask);

	memset(&stats, 0, sizeof(stats));
	rte_eth_stats_get(p->pmd_id, &stats);

	mac_addr = (struct ether_addr *) &p->mac_addr;

	if (strlen(p->pci_bdf))
		printf("%s(%s): flags=<%s>\n",
			p->name,
			p->pci_bdf,
			(p->state) ? "UP" : "DOWN");
	else
		printf("%s: flags=<%s>\n",
			p->name,
			(p->state) ? "UP" : "DOWN");

	if (p->ip)
		printf("\tinet %" PRIu32 ".%" PRIu32
			".%" PRIu32 ".%" PRIu32
			" netmask %" PRIu32 ".%" PRIu32
			".%" PRIu32 ".%" PRIu32 " "
			"broadcast %" PRIu32 ".%" PRIu32
			".%" PRIu32 ".%" PRIu32 "\n",
			(p->ip >> 24) & 0xFF,
			(p->ip >> 16) & 0xFF,
			(p->ip >> 8) & 0xFF,
			p->ip & 0xFF,
			(netmask >> 24) & 0xFF,
			(netmask >> 16) & 0xFF,
			(netmask >> 8) & 0xFF,
			netmask & 0xFF,
			(bcast >> 24) & 0xFF,
			(bcast >> 16) & 0xFF,
			(bcast >> 8) & 0xFF,
			bcast & 0xFF);

	printf("\tether %02" PRIx32 ":%02" PRIx32 ":%02" PRIx32
		":%02" PRIx32 ":%02" PRIx32 ":%02" PRIx32 "\n",
		mac_addr->addr_bytes[0],
		mac_addr->addr_bytes[1],
		mac_addr->addr_bytes[2],
		mac_addr->addr_bytes[3],
		mac_addr->addr_bytes[4],
		mac_addr->addr_bytes[5]);

	printf("\tRX packets %" PRIu64
		"  bytes %" PRIu64
		"\n",
		stats.ipackets,
		stats.ibytes);

	printf("\tRX errors %" PRIu64
		"  missed %" PRIu64
		"  no-mbuf %" PRIu64
		"\n",
		stats.ierrors,
		stats.imissed,
		stats.rx_nombuf);

	printf("\tTX packets %" PRIu64
		"  bytes %" PRIu64 "\n",
		stats.opackets,
		stats.obytes);

	printf("\tTX errors %" PRIu64
		"\n",
		stats.oerrors);

	printf("\n");
}
#endif
struct cmd_link_config_result {
	cmdline_fixed_string_t link_string;
	uint32_t link_id;
	cmdline_fixed_string_t config_string;
	cmdline_ipaddr_t ip;
	uint32_t depth;
};

static void
cmd_link_config_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	 void *data)
{
	struct cmd_link_config_result *params = parsed_result;
	struct app_params *app = data;
	int status;

	uint32_t link_id = params->link_id;
	uint32_t ip;
	uint8_t ipv6[16];
	if (params->ip.family == AF_INET)
		ip = rte_bswap32((uint32_t) params->ip.addr.ipv4.s_addr);
	else
		memcpy(ipv6, params->ip.addr.ipv6.s6_addr, 16);

	uint32_t depth = params->depth;

	if (params->ip.family == AF_INET)
		status = app_link_config(app, link_id, ip, depth);
	else
		status = app_link_config_ipv6(app, link_id, ipv6, depth);

	if (status)
		printf("Command failed\n");
	else {
		struct app_link_params *p;

		APP_PARAM_FIND_BY_ID(app->link_params, "LINK", link_id, p);
		if (p)
		print_link_info(p);
	}
}

cmdline_parse_token_string_t cmd_link_config_link_string =
	TOKEN_STRING_INITIALIZER(struct cmd_link_config_result, link_string,
		"link");

cmdline_parse_token_num_t cmd_link_config_link_id =
	TOKEN_NUM_INITIALIZER(struct cmd_link_config_result, link_id, UINT32);

cmdline_parse_token_string_t cmd_link_config_config_string =
	TOKEN_STRING_INITIALIZER(struct cmd_link_config_result, config_string,
		"config");

cmdline_parse_token_ipaddr_t cmd_link_config_ip =
	TOKEN_IPADDR_INITIALIZER(struct cmd_link_config_result, ip);

cmdline_parse_token_num_t cmd_link_config_depth =
	TOKEN_NUM_INITIALIZER(struct cmd_link_config_result, depth, UINT32);

cmdline_parse_inst_t cmd_link_config = {
	.f = cmd_link_config_parsed,
	.data = NULL,
	.help_str = "Link configuration",
	.tokens = {
		(void *)&cmd_link_config_link_string,
		(void *)&cmd_link_config_link_id,
		(void *)&cmd_link_config_config_string,
		(void *)&cmd_link_config_ip,
		(void *)&cmd_link_config_depth,
		NULL,
	},
};

/*
 * link up
 */

struct cmd_link_up_result {
	cmdline_fixed_string_t link_string;
	uint32_t link_id;
	cmdline_fixed_string_t up_string;
};

static void
cmd_link_up_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	void *data)
{
	struct cmd_link_up_result *params = parsed_result;
	struct app_params *app = data;
	int status;

	status = app_link_up(app, params->link_id);
	if (status != 0)
		printf("Command failed\n");
	else {
		struct app_link_params *p;

		APP_PARAM_FIND_BY_ID(app->link_params, "LINK", params->link_id,
			p);
               if (p)
		print_link_info(p);
	}
}

cmdline_parse_token_string_t cmd_link_up_link_string =
	TOKEN_STRING_INITIALIZER(struct cmd_link_up_result, link_string,
		"link");

cmdline_parse_token_num_t cmd_link_up_link_id =
	TOKEN_NUM_INITIALIZER(struct cmd_link_up_result, link_id, UINT32);

cmdline_parse_token_string_t cmd_link_up_up_string =
	TOKEN_STRING_INITIALIZER(struct cmd_link_up_result, up_string, "up");

cmdline_parse_inst_t cmd_link_up = {
	.f = cmd_link_up_parsed,
	.data = NULL,
	.help_str = "Link UP",
	.tokens = {
		(void *)&cmd_link_up_link_string,
		(void *)&cmd_link_up_link_id,
		(void *)&cmd_link_up_up_string,
		NULL,
	},
};

/*
 * link down
 */

struct cmd_link_down_result {
	cmdline_fixed_string_t link_string;
	uint32_t link_id;
	cmdline_fixed_string_t down_string;
};

static void
cmd_link_down_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	void *data)
{
	struct cmd_link_down_result *params = parsed_result;
	struct app_params *app = data;
	int status;

	status = app_link_down(app, params->link_id);
	if (status != 0)
		printf("Command failed\n");
	else {
		struct app_link_params *p;

		APP_PARAM_FIND_BY_ID(app->link_params, "LINK", params->link_id,
			p);
                 if (p)
			print_link_info(p);
	}
}

cmdline_parse_token_string_t cmd_link_down_link_string =
	TOKEN_STRING_INITIALIZER(struct cmd_link_down_result, link_string,
		"link");

cmdline_parse_token_num_t cmd_link_down_link_id =
	TOKEN_NUM_INITIALIZER(struct cmd_link_down_result, link_id, UINT32);

cmdline_parse_token_string_t cmd_link_down_down_string =
	TOKEN_STRING_INITIALIZER(struct cmd_link_down_result, down_string,
		"down");

cmdline_parse_inst_t cmd_link_down = {
	.f = cmd_link_down_parsed,
	.data = NULL,
	.help_str = "Link DOWN",
	.tokens = {
		(void *) &cmd_link_down_link_string,
		(void *) &cmd_link_down_link_id,
		(void *) &cmd_link_down_down_string,
		NULL,
	},
};

/*
 * link ls
 */

struct cmd_link_ls_result {
	cmdline_fixed_string_t link_string;
	cmdline_fixed_string_t ls_string;
};

static void
cmd_link_ls_parsed(
	__attribute__((unused)) void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	 void *data)
{
	struct app_params *app = data;
	uint32_t link_id;

	for (link_id = 0; link_id < app->n_links; link_id++) {
		struct app_link_params *p;

		APP_PARAM_FIND_BY_ID(app->link_params, "LINK", link_id, p);
                if (p)
		print_link_info(p);
	}
        print_interface_details();
}

cmdline_parse_token_string_t cmd_link_ls_link_string =
	TOKEN_STRING_INITIALIZER(struct cmd_link_ls_result, link_string,
		"link");

cmdline_parse_token_string_t cmd_link_ls_ls_string =
	TOKEN_STRING_INITIALIZER(struct cmd_link_ls_result, ls_string, "ls");

cmdline_parse_inst_t cmd_link_ls = {
	.f = cmd_link_ls_parsed,
	.data = NULL,
	.help_str = "Link list",
	.tokens = {
		(void *)&cmd_link_ls_link_string,
		(void *)&cmd_link_ls_ls_string,
		NULL,
	},
};

/*
 * quit
 */

struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static void
cmd_quit_parsed(
	__rte_unused void *parsed_result,
	struct cmdline *cl,
	__rte_unused void *data)
{
	cmdline_quit(cl);
}

static cmdline_parse_token_string_t cmd_quit_quit =
	TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

static cmdline_parse_inst_t cmd_quit = {
	.f = cmd_quit_parsed,
	.data = NULL,
	.help_str = "Quit",
	.tokens = {
		(void *) &cmd_quit_quit,
		NULL,
	},
};

/*
 * run
 */

static void
app_run_file(
	cmdline_parse_ctx_t *ctx,
	const char *file_name)
{
	struct cmdline *file_cl;
	int fd;

	fd = open(file_name, O_RDONLY);
	if (fd < 0) {
		printf("Cannot open file \"%s\"\n", file_name);
		return;
	}

	file_cl = cmdline_new(ctx, "", fd, 1);
	cmdline_interact(file_cl);
	close(fd);
}

struct cmd_run_file_result {
	cmdline_fixed_string_t run_string;
	char file_name[APP_FILE_NAME_SIZE];
};

static void
cmd_run_parsed(
	void *parsed_result,
	struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_run_file_result *params = parsed_result;

	app_run_file(cl->ctx, params->file_name);
}

cmdline_parse_token_string_t cmd_run_run_string =
	TOKEN_STRING_INITIALIZER(struct cmd_run_file_result, run_string,
		"run");

cmdline_parse_token_string_t cmd_run_file_name =
	TOKEN_STRING_INITIALIZER(struct cmd_run_file_result, file_name, NULL);

cmdline_parse_inst_t cmd_run = {
	.f = cmd_run_parsed,
	.data = NULL,
	.help_str = "Run CLI script file",
	.tokens = {
		(void *) &cmd_run_run_string,
		(void *) &cmd_run_file_name,
		NULL,
	},
};

static cmdline_parse_ctx_t pipeline_common_cmds[] = {
	(cmdline_parse_inst_t *) &cmd_quit,
	(cmdline_parse_inst_t *) &cmd_run,
	(cmdline_parse_inst_t *) &cmd_routeadd_net,
	(cmdline_parse_inst_t *) &cmd_routeadd_host,

	(cmdline_parse_inst_t *) &cmd_link_config,
	(cmdline_parse_inst_t *) &cmd_link_up,
	(cmdline_parse_inst_t *) &cmd_link_down,
	(cmdline_parse_inst_t *) &cmd_link_ls,

	(cmdline_parse_inst_t *) &cmd_ping,
	(cmdline_parse_inst_t *) &cmd_stats_port_in,
	(cmdline_parse_inst_t *) &cmd_stats_port_out,
	(cmdline_parse_inst_t *) &cmd_stats_table,
	(cmdline_parse_inst_t *) &cmd_port_in_enable,
	(cmdline_parse_inst_t *) &cmd_port_in_disable,
	NULL,
};

int
app_pipeline_common_cmd_push(struct app_params *app)
{
	uint32_t n_cmds, i;

	/* Check for available slots in the application commands array */
	n_cmds = RTE_DIM(pipeline_common_cmds) - 1;
	if (n_cmds > APP_MAX_CMDS - app->n_cmds)
		return -ENOMEM;

	/* Push pipeline commands into the application */
	memcpy(&app->cmds[app->n_cmds],
		pipeline_common_cmds,
		n_cmds * sizeof(cmdline_parse_ctx_t));

	for (i = 0; i < n_cmds; i++)
		app->cmds[app->n_cmds + i]->data = app;

	app->n_cmds += n_cmds;
	app->cmds[app->n_cmds] = NULL;

	return 0;
}
