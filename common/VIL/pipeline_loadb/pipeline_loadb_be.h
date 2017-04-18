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

#ifndef __INCLUDE_PIPELINE_LOADB_BE_H__
#define __INCLUDE_PIPELINE_LOADB_BE_H__

#include <rte_ip.h>
#include "pipeline_common_be.h"
#include <app.h>

#define MBUF_HDR_ROOM 256
#define ETH_HDR_SIZE  14
#define IP_HDR_SRC_ADR_OFST 12
#define IP_HDR_DST_ADR_OFST 16
#define IP_HDR_PROTOCOL_OFST 9
#define IP_HDR_SIZE  20
#define IPV6_HDR_SRC_ADR_OFST 8
#define IPV6_HDR_DST_ADR_OFST 24
#define IPV6_HDR_PROTOCOL_OFST 6
#define IPV6_HDR_SIZE  40
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17
#define PIPELINE_LOADB_KEY_MAX_SIZE  64

#define LOADB_ING_DIR 0
#define LOADB_EGR_DIR 1

#define LOADB_DBG_CMD_OFST 8
#define LOADB_DBG_CMD_STATS_SHOW 0
#define LOADB_DBG_CMD_STATS_CLEAR 1
#define LOADB_DBG_CMD_DBG_LEVEL 2
#define LOADB_DBG_CMD_DBG_SHOW 3
#define LOADB_DBG_CMD_IF_STATS 4
#define LOADB_DBG_CMD_OFST1 10

#define PIPELINE_LOADB_KEY_PORT_IN_AH(f_ah, f_pkt_work, f_pkt4_work)    \
static int                                                              \
f_ah(                                                                   \
	__rte_unused struct rte_pipeline *rte_p,                        \
	struct rte_mbuf **pkts,                                         \
	uint32_t n_pkts,                                                \
	void *arg)                                                      \
{                                                                       \
	uint32_t i, j;                                                  \
									\
	for (j = 0; j < n_pkts; j++)                                    \
		rte_prefetch0(pkts[j]);                                 \
	pkt_burst_cnt = 0;                                              \
	for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)                   \
		f_pkt4_work(&pkts[i], i, arg);                          \
									\
	for ( ; i < n_pkts; i++)                                        \
		f_pkt_work(pkts[i], i, arg);                            \
									\
									\
	return 0;                                                       \
}

extern uint8_t LOADB_DEBUG;
extern uint8_t in_port_egress_prv[PIPELINE_MAX_PORT_IN];
extern uint8_t prv_que_port_index[PIPELINE_MAX_PORT_IN];
extern uint8_t in_port_dir_a[PIPELINE_MAX_PORT_IN];

extern uint8_t get_in_port_dir(uint8_t);
extern uint8_t is_port_index_privte(uint16_t);
extern uint8_t is_phy_port_privte(uint16_t);
extern uint32_t get_prv_to_pub_port(uint32_t *ip_addr, uint8_t type);
extern uint32_t get_pub_to_prv_port(uint32_t *ip_addr, uint8_t type);
extern uint8_t prv_to_pub_map[PIPELINE_MAX_PORT_IN];
//extern struct app_params *myApp;
//extern struct pipeline_arpicmp *p_arp;

/*
 * LOADB Entry
 */

struct pipeline_loadb_in_port_h_arg {
	struct pipeline_loadb *p;
	uint8_t in_port_id;
};

/*
 * Messages
 */
enum pipeline_loadb_msg_req_type {
	/* to be used for debug purposes */
	PIPELINE_LOADB_MSG_REQ_ENTRY_DBG,
	PIPELINE_LOADB_MSG_REQS
};

/*
 * MSG ENTRY DBG
 */
struct pipeline_loadb_entry_dbg_msg_req {
	enum pipeline_msg_req_type type;
	enum pipeline_loadb_msg_req_type subtype;

	/* data */
	uint8_t data[5];
};

struct pipeline_loadb_entry_dbg_msg_rsp {
	int status;
	void *entry_ptr;
};

extern struct pipeline_be_ops pipeline_loadb_be_ops;
struct ipv4_hdr_port {
	struct ipv4_hdr ipv4;
	uint16_t src_port;
	uint16_t dst_port;

} __attribute__((__packed__));
struct ipv6_hdr_port {
	struct ipv6_hdr ipv6;
	uint16_t src_port;
	uint16_t dst_port;

} __attribute__((__packed__));

struct lb_pkt {
	struct ether_hdr eth;
	union{
		struct ipv4_hdr_port ipv4_port;
		struct ipv6_hdr_port ipv6_port;
	};
} __attribute__((__packed__));

uint8_t calculate_lb_thread_prv(struct rte_mbuf *pkt, void *arg);
uint8_t calculate_lb_thread_pub(struct rte_mbuf *pkt, void *arg);
int check_loadb_thread(
	struct app_params *app,
	struct pipeline_params *params,
	int32_t n_vnf_threads);

#endif
