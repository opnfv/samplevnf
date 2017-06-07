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

#ifndef __INCLUDE_PIPELINE_ARPICMP_BE_H__
#define __INCLUDE_PIPELINE_ARPICMP_BE_H__

#include "pipeline_common_be.h"
#define PIPELINE_ARPICMP_KEY_PORT_IN_AH(f_ah, f_pkt_work, f_pkt4_work)  \
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
									\
	for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)                   \
		f_pkt4_work(&pkts[i], i, arg);                          \
									\
	for ( ; i < n_pkts; i++)                                        \
		f_pkt_work(pkts[i], i, arg);                            \
									\
									\
	return 0;                                                       \
}

extern struct app_params *myApp;
void print_pkt1(struct rte_mbuf *pkt);
struct ether_addr *get_link_hw_addr(uint8_t out_port);

uint8_t lb_outport_id[PIPELINE_MAX_PORT_IN];
struct pipeline *loadb_pipeline[PIPELINE_MAX_PORT_IN];
struct pipeline *all_pipeline[PIPELINE_MAX_PORT_IN];
uint8_t vnf_to_loadb_map[PIPELINE_MAX_PORT_IN];
uint8_t port_to_loadb_map[PIPELINE_MAX_PORT_IN];
uint8_t loadb_pipeline_nums[PIPELINE_MAX_PORT_IN];

void set_port_to_loadb_map(uint8_t pipeline_num);
uint8_t get_port_to_loadb_map(uint8_t phy_port_id);
/* acts on port_to_loadb_map */

void set_phy_inport_map(uint8_t pipeline_num, uint8_t *map);
void set_phy_outport_map(uint8_t pipeline_num, uint8_t *map);

void set_outport_id(uint8_t pipeline_num, struct pipeline *p, uint8_t *map);
/* acts on lb_outport_id */
uint8_t get_loadb_outport_id(uint8_t actual_phy_port);
/* acts on lb_outport_id */
uint8_t get_vnf_set_num(uint8_t pipeline_num);

void pipelines_port_info(void);
void pipelines_map_info(void);
void register_loadb_to_arp(uint8_t pipeline_num, struct pipeline *p,
				 __rte_unused struct app_params *app);
/* vnf_to_loadb_map[]  and loadb_pipelines[] */
uint8_t SWQ_to_Port_map[128];

extern struct pipeline_be_ops pipeline_arpicmp_be_ops;
void register_pipeline_Qs(uint8_t pipeline_num, struct pipeline *p);
void set_link_map(uint8_t pipeline_num, struct pipeline *p, uint8_t *map);
void set_outport_id(uint8_t pipeline_num, struct pipeline *p, uint8_t *map);
void set_phy_outport_id(uint8_t pipeline_num, struct pipeline *p, uint8_t *map);
void set_phy_inport_id(uint8_t pipeline_num, struct pipeline *p, uint8_t *map);

/*
 * Messages
 */
enum pipeline_arpicmp_msg_req_type {
	PIPELINE_ARPICMP_MSG_REQ_ENTRY_DBG,
	PIPELINE_ARPICMP_MSG_REQS
};

/*
 * MSG ENTRY DBG
 */
struct pipeline_arpicmp_entry_dbg_msg_req {
	enum pipeline_msg_req_type type;
	enum pipeline_arpicmp_msg_req_type subtype;

	/* data */
	uint8_t data[2];
};

/*
 * ARPICMP Entry
 */

struct pipeline_arpicmp_in_port_h_arg {
	struct pipeline_arpicmp *p;
	uint8_t in_port_id;
};

struct pipeline_arpicmp_entry_dbg_msg_rsp {
	int status;
};

#endif
