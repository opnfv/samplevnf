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

#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <app.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_table_stub.h>
#include <rte_table_hash.h>
#include <rte_pipeline.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_hexdump.h>
#include "pipeline_actions_common.h"
#include "hash_func.h"
#include "vnf_common.h"
#include "pipeline_common_be.h"
#include "pipeline_arpicmp_be.h"
#include "parser.h"
#include "hash_func.h"
#include "vnf_common.h"
#include "app.h"

#include"pipeline_common_fe.h"
#ifndef VNF_ACL
#include "lib_arp.h"
#include "lib_icmpv6.h"
#include "interface.h"
#endif

#ifdef VNF_ACL

#define NB_ARPICMP_MBUF  64
#define NB_NDICMP_MBUF  64
#define IP_VERSION_4 0x40
/* default IP header length == five 32-bits words. */
#define IP_HDRLEN  0x05
#define IP_VHL_DEF (IP_VERSION_4 | IP_HDRLEN)

#define is_multicast_ipv4_addr(ipv4_addr) \
	(((rte_be_to_cpu_32((ipv4_addr)) >> 24) & 0x000000FF) == 0xE0)


/*ND IPV6 */
#define INADDRSZ 4
#define IN6ADDRSZ 16
static int my_inet_pton_ipv6(int af, const char *src, void *dst);
static int inet_pton_ipv6(const char *src, unsigned char *dst);
static int inet_pton_ipv4(const char *src, unsigned char *dst);

uint8_t vnf_common_arp_lib_init;
uint8_t vnf_common_nd_lib_init;
uint8_t loadb_pipeline_count;

uint32_t ARPICMP_DEBUG;
uint32_t NDIPV6_DEBUG;

uint32_t arp_route_tbl_index;
uint32_t nd_route_tbl_index;
uint32_t link_hw_addr_array_idx;

uint32_t lib_arp_get_mac_req;
uint32_t lib_arp_nh_found;
uint32_t lib_arp_no_nh_found;
uint32_t lib_arp_arp_entry_found;
uint32_t lib_arp_no_arp_entry_found;
uint32_t lib_arp_populate_called;
uint32_t lib_arp_delete_called;
uint32_t lib_arp_duplicate_found;

uint32_t lib_nd_get_mac_req;
uint32_t lib_nd_nh_found;
uint32_t lib_nd_no_nh_found;
uint32_t lib_nd_nd_entry_found;
uint32_t lib_nd_no_arp_entry_found;
uint32_t lib_nd_populate_called;
uint32_t lib_nd_delete_called;
uint32_t lib_nd_duplicate_found;

struct rte_mempool *lib_arp_pktmbuf_tx_pool;
struct rte_mempool *lib_nd_pktmbuf_tx_pool;

struct rte_mbuf *lib_arp_pkt;
struct rte_mbuf *lib_nd_pkt;

static struct rte_hash_parameters arp_hash_params = {
	.name = "ARP",
	.entries = 64,
	.reserved = 0,
	.key_len = sizeof(struct arp_key_ipv4),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
};

static struct rte_hash_parameters nd_hash_params = {
	.name = "ND",
	.entries = 64,
	.reserved = 0,
	.key_len = sizeof(struct nd_key_ipv6),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
};

struct rte_hash *arp_hash_handle;
struct rte_hash *nd_hash_handle;

#endif
/* Shared among all VNFs including LB */
struct app_params *myApp;
struct rte_pipeline *myP;
struct pipeline_arpicmp *gp_arp;
uint8_t num_vnf_threads;

#ifdef VNF_ACL

struct arp_port_address {
	uint32_t ip;
	uint64_t mac_addr;
};

struct arp_port_address arp_port_addresses[RTE_MAX_ETHPORTS];

uint16_t arp_meta_offset;
#endif

struct pipeline_arpicmp {
	struct pipeline p;
	pipeline_msg_req_handler
		custom_handlers[PIPELINE_ARPICMP_MSG_REQS];
	uint64_t receivedPktCount;
	uint64_t droppedPktCount;
	uint64_t sentPktCount;
	uint8_t links_map[PIPELINE_MAX_PORT_IN];
	uint8_t outport_id[PIPELINE_MAX_PORT_IN];
	uint8_t pipeline_num;
} __rte_cache_aligned;

#ifdef VNF_ACL

#define MAX_NUM_ARP_ENTRIES 64
#define MAX_NUM_ND_ENTRIES 64


struct lib_nd_route_table_entry lib_nd_route_table[MAX_ND_RT_ENTRY] = {
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} }
};

struct lib_arp_route_table_entry lib_arp_route_table[MAX_ARP_RT_ENTRY] = {
//   {0xac102814, 1, 0xac102814},
//   {0xac106414, 0, 0xac106414},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0}
};

#endif

void pipelines_port_info(void)
{
	struct app_params *app = myApp;
	uint8_t i, pipeline;
	for (pipeline = 0; pipeline < app->n_pipelines; pipeline++) {
		printf("*** PIPELINE %d ***\n\n", pipeline);

		printf("*** OUTPORTs ***\n");
		for (i = 1; i < app->pipeline_params[pipeline].n_pktq_out;
			i++) {
			switch (app->pipeline_params[pipeline].pktq_out[i].
			type) {
			case APP_PKTQ_OUT_SWQ:
				printf("pktq_out[%d]:%s\n", i,
							 app->swq_params[app->pipeline_params
									 [pipeline].
									 pktq_out[i].id].name);
				break;
			case APP_PKTQ_OUT_HWQ:
				printf("pktq_out[%d]:%s\n", i,
							 app->hwq_out_params[app->pipeline_params
								 [pipeline].pktq_out
								 [i].id].name);
				break;
			default:
				printf("Not OUT SWQ or HWQ\n");
			}
		}
		printf("*** INPORTs ***\n");
		for (i = 0; i < app->pipeline_params[pipeline].n_pktq_in; i++) {
			switch (app->pipeline_params[pipeline].pktq_in[i]
			.type) {
			case APP_PKTQ_IN_SWQ:
				printf("pktq_in[%d]:%s\n", i,
							 app->swq_params[app->pipeline_params
									 [pipeline].
									 pktq_in[i].id].name);
				break;
			case APP_PKTQ_IN_HWQ:
				printf("pktq_in[%d]:%s\n", i,
							 app->hwq_in_params[app->pipeline_params
								[pipeline].
								pktq_in[i].id].name);
				break;
			default:
				printf("Not IN SWQ or HWQ\n");
			}
		}
	}                       //for
}

void pipelines_map_info(void)
{
	 int i = 0;

	printf("PIPELINE_MAX_PORT_IN %d\n", PIPELINE_MAX_PORT_IN);
	printf("lb_outport_id[%d", lb_outport_id[0]);
	for (i = 1; i < PIPELINE_MAX_PORT_IN; i++)
		printf(",%d", lb_outport_id[i]);
	printf("]\n");

	printf("vnf_to_loadb_map[%d", vnf_to_loadb_map[0]);
	for (i = 1; i < PIPELINE_MAX_PORT_IN; i++)
		printf(",%d", vnf_to_loadb_map[i]);
	printf("]\n");

	printf("port_to_loadb_map[%d", port_to_loadb_map[0]);
	for (i = 1; i < PIPELINE_MAX_PORT_IN; i++)
		printf(",%d", port_to_loadb_map[i]);
	printf("]\n");

	printf("loadb_pipeline_nums[%d", loadb_pipeline_nums[0]);
	for (i = 1; i < PIPELINE_MAX_PORT_IN; i++)
		printf(",%d", loadb_pipeline_nums[i]);
	printf("]\n");

	printf("loadb_pipeline[%p", loadb_pipeline[0]);
	for (i = 1; i < PIPELINE_MAX_PORT_IN; i++)
		printf(",%p", loadb_pipeline[i]);
	printf("]\n");
}

void register_pipeline_Qs(uint8_t pipeline_num, struct pipeline *p)
{
	struct rte_port_ethdev_reader *hwq;
	struct rte_port_ring_writer *out_swq;
	struct rte_port_ring_reader *in_swq;
	struct rte_pipeline *rte = p->p;
	uint8_t port_count = 0;
	int queue_out = 0xff, queue_in = 0xff;

	printf("Calling register_pipeline_Qs in PIPELINE%d\n", pipeline_num);
	for (port_count = 0; port_count < rte->num_ports_out; port_count++) {

	switch (myApp->pipeline_params[pipeline_num].
				pktq_out[port_count].type){

	case APP_PKTQ_OUT_SWQ:

		if (port_count >= rte->num_ports_in) {

			/* Dont register ARP output Q */
			if (rte->num_ports_out % rte->num_ports_in)
				if (port_count == rte->num_ports_out - 1)
					return;
			int temp;
			temp = ((port_count) % rte->num_ports_in);

			in_swq = rte->ports_in[temp].h_port;
			out_swq = rte->ports_out[port_count].h_port;
			printf("in_swq : %s\n",
				in_swq->ring->name);
			int status =
			sscanf(in_swq->ring->name, "SWQ%d",
					&queue_in);
			if (status < 0) {
				printf("Unable to read SWQ number\n");
				return;
			}
			printf("out_swq: %s\n",
					out_swq->ring->name);
			status =
			sscanf(out_swq->ring->name, "SWQ%d",
					&queue_out);
			if (status < 0) {
				printf("Unable to read SWQ number\n");
				return;
			}
			if (queue_in < 128 && queue_out < 128) {
				SWQ_to_Port_map[queue_out] =
					SWQ_to_Port_map[queue_in];
			 printf("SWQ_to_Port_map[%d]%d\n", queue_out,
				 SWQ_to_Port_map[queue_out]);
                        }
			continue;
		}

		switch (myApp->pipeline_params[pipeline_num].
			 pktq_in[port_count].type){

		case APP_PKTQ_OUT_HWQ:
			 hwq = rte->ports_in[port_count].h_port;
			 out_swq = rte->ports_out[port_count].h_port;
			 printf("out_swq: %s\n",
				 out_swq->ring->name);
			int status =
			sscanf(out_swq->ring->name, "SWQ%d",
				 &queue_out);

			if (status < 0) {
				printf("Unable to read SWQ number\n");
				return;
			}
			if (queue_out < 128) {
				SWQ_to_Port_map[queue_out] = hwq->port_id;
				printf("SWQ_to_Port_map[%d]%d\n", queue_out,
					SWQ_to_Port_map[queue_out]);
			}
		break;

		case APP_PKTQ_OUT_SWQ:
			 in_swq = rte->ports_in[port_count].h_port;
			 out_swq = rte->ports_out[port_count].h_port;
			 printf("in_swq : %s\n",
				 in_swq->ring->name);
			status =
			sscanf(in_swq->ring->name, "SWQ%d",
					 &queue_in);
			if (status < 0) {
				printf("Unable to read SWQ number\n");
				return;
			}
			printf("out_swq: %s\n",
					 out_swq->ring->name);
			status =
			sscanf(out_swq->ring->name, "SWQ%d",
					 &queue_out);
			if (status < 0) {
				printf("Unable to read SWQ number\n");
				return;
			}
			if (queue_in < 128 && queue_out < 128){
				SWQ_to_Port_map[queue_out] =
					SWQ_to_Port_map[queue_in];
			 printf("SWQ_to_Port_map[%d]%d\n", queue_out,
				 SWQ_to_Port_map[queue_out]);
                          }
		break;

		default:
			 printf("This never hits\n");
		}

	break;

	case APP_PKTQ_OUT_HWQ:
		 printf("This is HWQ\n");
	break;

	default:
		 printf("set_phy_outport_map: This never hits\n");
	}
	}
}

void set_link_map(uint8_t pipeline_num, struct pipeline *p, uint8_t *map)
{
		struct rte_port_ethdev_writer *hwq;
		struct rte_port_ring_writer *out_swq;
		struct rte_pipeline *rte = p->p;

		uint8_t port_count = 0;
		int index = 0, queue_out = 0xff;

	printf("Calling set_link_map in PIPELINE%d\n", pipeline_num);
	for (port_count = 0; port_count < rte->num_ports_out; port_count++) {

		switch (myApp->pipeline_params[pipeline_num].
				pktq_out[port_count].type){

		case APP_PKTQ_OUT_HWQ:
			hwq = rte->ports_out[port_count].h_port;
			map[index++] = hwq->port_id;
			printf("links_map[%d]:%d\n", index - 1, map[index - 1]);
		break;

		case APP_PKTQ_OUT_SWQ:
			out_swq = rte->ports_out[port_count].h_port;
			printf("set_link_map out_swq: %s\n",
				out_swq->ring->name);
			int status = sscanf(out_swq->ring->name, "SWQ%d",
					&queue_out);
			if (status < 0) {
				printf("Unable to read SWQ number\n");
				return;
			}

			if (queue_out < 128) {
			map[index++] = SWQ_to_Port_map[queue_out];
			printf("links_map[%s]:%d\n", out_swq->ring->name,
					map[index - 1]);
			}
		break;

		default:
			printf("set_phy_outport_map: This never hits\n");
		}
		}
}

void set_outport_id(uint8_t pipeline_num, struct pipeline *p, uint8_t *map)
{
	uint8_t port_count = 0;
	int queue_out = 0xff, index = 0;

	struct rte_port_ethdev_writer *hwq;
	struct rte_port_ring_writer *out_swq;
	struct rte_pipeline *rte = p->p;

	printf("\n**** set_outport_id() with pipeline_num:%d ****\n\n",
		pipeline_num);
	for (port_count = 0;
		port_count < rte->num_ports_out;
		port_count++) {

	switch (myApp->pipeline_params[pipeline_num].
			pktq_out[port_count].type) {

	case APP_PKTQ_OUT_HWQ:
		hwq = rte->ports_out[port_count].h_port;
		//if (index >= 0)
		{
			map[hwq->port_id] = index;
			printf("hwq port_id:%d index:%d\n",
				hwq->port_id, index);
			map[hwq->port_id] = index++;
			printf("hwq port_id:%d index:%d\n",
				hwq->port_id, index-1);
			printf("outport_id[%d]:%d\n", index - 1,
				map[index - 1]);
		}
		break;

	case APP_PKTQ_OUT_SWQ:

		/* Dont register ARP output Q */
		if (port_count >= rte->num_ports_in)
			if (rte->num_ports_out % rte->num_ports_in)
				if (port_count == rte->num_ports_out - 1)
					return;
		 out_swq = rte->ports_out[port_count].h_port;
		 printf("set_outport_id out_swq: %s\n",
			 out_swq->ring->name);
		int temp = sscanf(out_swq->ring->name, "SWQ%d",
				 &queue_out);
		if (temp < 0) {
			printf("Unable to read SWQ number\n");
			return;
		}

		if (queue_out < 128 && index >= 0) {
			map[SWQ_to_Port_map[queue_out]] = index++;
			printf("outport_id[%s]:%d\n", out_swq->ring->name,
					 map[SWQ_to_Port_map[queue_out]]);
		}
		break;

		default:
			 printf(" ");

		}
	}
}

void set_phy_outport_id(uint8_t pipeline_num, struct pipeline *p, uint8_t *map)
{
	uint8_t port_count = 0;
	int index = 0;

	struct rte_port_ethdev_writer *hwq;
	struct rte_pipeline *rte = p->p;

	printf("\n**** set_phy_outport_id() with pipeline_num:%d ****\n\n",
		pipeline_num);
	for (port_count = 0;
		port_count < myApp->pipeline_params[pipeline_num].n_pktq_out;
		port_count++) {

	switch (myApp->pipeline_params[pipeline_num].
			pktq_out[port_count].type) {

	case APP_PKTQ_OUT_HWQ:
		hwq = rte->ports_out[port_count].h_port;
		map[hwq->port_id] = index++;
		printf("outport_id[%d]:%d\n", index - 1,
			map[index - 1]);
	break;

	default:
		 printf(" ");

		}
	}
}

void set_phy_inport_id(uint8_t pipeline_num, struct pipeline *p, uint8_t *map)
{
	uint8_t port_count = 0;
	int index = 0;

	struct rte_port_ethdev_reader *hwq;
	struct rte_pipeline *rte = p->p;

	printf("\n**** set_phy_inport_id() with pipeline_num:%d ****\n\n",
				 pipeline_num);
	for (port_count = 0;
		port_count < myApp->pipeline_params[pipeline_num].n_pktq_in;
		port_count++) {

		switch (myApp->pipeline_params[pipeline_num].
			pktq_in[port_count].type) {

		case APP_PKTQ_OUT_HWQ:
			hwq = rte->ports_in[port_count].h_port;
			map[hwq->port_id] = index++;
			printf("outport_id[%d]:%d\n", index - 1,
				map[index - 1]);
		break;

		default:
			printf(" ");

		}
	}
}

#ifdef VNF_ACL

uint32_t get_nh(uint32_t ip, uint32_t *port)
{
	int i = 0;
	for (i = 0; i < MAX_ARP_RT_ENTRY; i++) {
		if (((lib_arp_route_table[i].
			ip & lib_arp_route_table[i].mask) ==
			(ip & lib_arp_route_table[i].mask))) {

			*port = lib_arp_route_table[i].port;
			lib_arp_nh_found++;
			return lib_arp_route_table[i].nh;
		}
	if (ARPICMP_DEBUG > 1)
		printf("No nh match ip 0x%x, port %u, t_ip "
		"0x%x, t_port %u, mask 0x%x, r1 %x, r2 %x\n",
		ip, *port, lib_arp_route_table[i].ip,
		lib_arp_route_table[i].port,
		lib_arp_route_table[i].mask,
		(lib_arp_route_table[i].ip &
		lib_arp_route_table[i].mask),
		(ip & lib_arp_route_table[i].mask));
	}
	if (ARPICMP_DEBUG && ip)
		printf("No NH - ip 0x%x, port %u\n", ip, *port);
	lib_arp_no_nh_found++;
	return 0;
}

/*ND IPv6 */
void get_nh_ipv6(uint8_t ipv6[], uint32_t *port, uint8_t nhipv6[])
{
	int i = 0;
	uint8_t netmask_ipv6[16], netip_nd[16], netip_in[16];
	uint8_t k = 0, l = 0, depthflags = 0, depthflags1 = 0;
	memset(netmask_ipv6, 0, sizeof(netmask_ipv6));
	memset(netip_nd, 0, sizeof(netip_nd));
	memset(netip_in, 0, sizeof(netip_in));
	if (!ipv6)
		return;
	for (i = 0; i < MAX_ARP_RT_ENTRY; i++) {

		convert_prefixlen_to_netmask_ipv6(
					lib_nd_route_table[i].depth,
					netmask_ipv6);

		for (k = 0; k < 16; k++) {
			if (lib_nd_route_table[i].ipv6[k] & netmask_ipv6[k]) {
				depthflags++;
				netip_nd[k] = lib_nd_route_table[i].ipv6[k];
			}
		}

		for (l = 0; l < 16; l++) {
			if (ipv6[l] & netmask_ipv6[l]) {
				depthflags1++;
				netip_in[l] = ipv6[l];
			}
		}
		int j = 0;
		if ((depthflags == depthflags1)
			&& (memcmp(netip_nd, netip_in,
				sizeof(netip_nd)) == 0)) {
			//&& (lib_nd_route_table[i].port == port))
			*port = lib_nd_route_table[i].port;
			lib_nd_nh_found++;

			for (j = 0; j < 16; j++)
				nhipv6[j] = lib_nd_route_table[i].nhipv6[j];

			return;
		}

		if (NDIPV6_DEBUG > 1)
			printf("No nh match\n");
		depthflags = 0;
		depthflags1 = 0;
	}
	if (NDIPV6_DEBUG && ipv6)
		printf("No NH - ip 0x%x, port %u\n", ipv6[0], *port);
	lib_nd_no_nh_found++;
}

/* Added for Multiport changes*/
int get_dest_mac_addr_port(const uint32_t ipaddr,
					uint32_t *phy_port, struct ether_addr *hw_addr)
{
	lib_arp_get_mac_req++;
	uint32_t nhip = 0;

	nhip = get_nh(ipaddr, phy_port);
	if (nhip == 0) {
		if (ARPICMP_DEBUG && ipaddr)
			printf("ARPICMP no nh found for ip %x, port %d\n",
						 ipaddr, *phy_port);
		//return 0;
		return NH_NOT_FOUND;
	}

	struct arp_entry_data *ret_arp_data = NULL;
	struct arp_key_ipv4 tmp_arp_key;
	tmp_arp_key.port_id = *phy_port;/* Changed for Multi Port*/
	tmp_arp_key.ip = nhip;

	ret_arp_data = retrieve_arp_entry(tmp_arp_key);
	if (ret_arp_data == NULL) {
		if (ARPICMP_DEBUG && ipaddr) {
			printf
					("ARPICMP no arp entry found for ip %x, port %d\n",
					 ipaddr, *phy_port);
			print_arp_table();
		}
		lib_arp_no_arp_entry_found++;
		return ARP_NOT_FOUND;
	}
	ether_addr_copy(&ret_arp_data->eth_addr, hw_addr);
	lib_arp_arp_entry_found++;
	return ARP_FOUND;
}

/*ND IPv6 */
int get_dest_mac_address_ipv6(uint8_t ipv6addr[], uint32_t phy_port,
						 struct ether_addr *hw_addr, uint8_t nhipv6[])
{
	int i = 0, j = 0, flag = 0;
	lib_nd_get_mac_req++;

	if (ipv6addr)
	get_nh_ipv6(ipv6addr, &phy_port, nhipv6);
	for (j = 0; j < 16; j++) {
		if (nhipv6[j])
			flag++;
	}
	if (flag == 0) {
		if (ipv6addr) {
		if (NDIPV6_DEBUG && ipv6addr)
			printf("NDIPV6 no nh found for ipv6 "
			"%02x%02x%02x%02x%02x%02x%02x%02x%02x"
			"%02x%02x%02x%02x%02x%02x%02x, port %d\n",
			ipv6addr[0], ipv6addr[1], ipv6addr[2], ipv6addr[3],
			ipv6addr[4], ipv6addr[5], ipv6addr[6], ipv6addr[7],
			ipv6addr[8], ipv6addr[9], ipv6addr[10],
			ipv6addr[11], ipv6addr[12], ipv6addr[13],
			ipv6addr[14], ipv6addr[15], phy_port);
			return 0;
	}
	}

	 struct nd_entry_data *ret_nd_data = NULL;
	 struct nd_key_ipv6 tmp_nd_key;
	 tmp_nd_key.port_id = phy_port;

	for (i = 0; i < 16; i++)
		tmp_nd_key.ipv6[i] = nhipv6[i];

	 ret_nd_data = retrieve_nd_entry(tmp_nd_key);
	if (ret_nd_data == NULL) {
		if (NDIPV6_DEBUG && ipv6addr) {
			printf("NDIPV6 no nd entry found for ip %x, port %d\n",
				ipv6addr[0], phy_port);
		}
		 lib_nd_no_arp_entry_found++;
		return 0;
	}
	 ether_addr_copy(&ret_nd_data->eth_addr, hw_addr);
	 lib_nd_nd_entry_found++;
	return 1;

}

/*ND IPv6 */
int get_dest_mac_address_ipv6_port(uint8_t ipv6addr[], uint32_t *phy_port,
						 struct ether_addr *hw_addr, uint8_t nhipv6[])
{
	int i = 0, j = 0, flag = 0;
	lib_nd_get_mac_req++;

	get_nh_ipv6(ipv6addr, phy_port, nhipv6);
	for (j = 0; j < 16; j++) {
		if (nhipv6[j])
			flag++;
	}
	if (flag == 0) {
		if (NDIPV6_DEBUG && ipv6addr)
			printf("NDIPV6 no nh found for ipv6 "
			"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
			"%02x%02x%02x%02x%02x%02x, port %d\n",
			ipv6addr[0], ipv6addr[1], ipv6addr[2], ipv6addr[3],
			ipv6addr[4], ipv6addr[5], ipv6addr[6], ipv6addr[7],
			ipv6addr[8], ipv6addr[9], ipv6addr[10],
			ipv6addr[11], ipv6addr[12], ipv6addr[13],
			ipv6addr[14], ipv6addr[15], *phy_port);
			return 0;
	}

	 struct nd_entry_data *ret_nd_data = NULL;
	 struct nd_key_ipv6 tmp_nd_key;
	 tmp_nd_key.port_id = *phy_port;

	for (i = 0; i < 16; i++)
		tmp_nd_key.ipv6[i] = nhipv6[i];

	 ret_nd_data = retrieve_nd_entry(tmp_nd_key);
	if (ret_nd_data == NULL) {
		if (NDIPV6_DEBUG && ipv6addr) {
			printf("NDIPV6 no nd entry found for ip %x, port %d\n",
				ipv6addr[0], *phy_port);
		}
		 lib_nd_no_arp_entry_found++;
		return 0;
	}
	 ether_addr_copy(&ret_nd_data->eth_addr, hw_addr);
	 lib_nd_nd_entry_found++;
	return 1;

}

/*
 * ARP table
 */
struct lib_arp_arp_table_entry {
	struct rte_pipeline_table_entry head;
	uint64_t macaddr;
};

static const char *arp_op_name(uint16_t arp_op)
{
	switch (CHECK_ENDIAN_16(arp_op)) {
	case (ARP_OP_REQUEST):
		return "ARP Request";
	case (ARP_OP_REPLY):
		return "ARP Reply";
	case (ARP_OP_REVREQUEST):
		return "Reverse ARP Request";
	case (ARP_OP_REVREPLY):
		return "Reverse ARP Reply";
	case (ARP_OP_INVREQUEST):
		return "Peer Identify Request";
	case (ARP_OP_INVREPLY):
		return "Peer Identify Reply";
	default:
		break;
	}
	return "Unkwown ARP op";
}

static void print_icmp_packet(struct icmp_hdr *icmp_h)
{
	printf("  ICMP: type=%d (%s) code=%d id=%d seqnum=%d\n",
				 icmp_h->icmp_type,
				 (icmp_h->icmp_type == IP_ICMP_ECHO_REPLY ? "Reply" :
		(icmp_h->icmp_type ==
		 IP_ICMP_ECHO_REQUEST ? "Reqest" : "Undef")), icmp_h->icmp_code,
				 CHECK_ENDIAN_16(icmp_h->icmp_ident),
				 CHECK_ENDIAN_16(icmp_h->icmp_seq_nb));
}

static void print_ipv4_h(struct ipv4_hdr *ip_h)
{
	struct icmp_hdr *icmp_h =
			(struct icmp_hdr *)((char *)ip_h + sizeof(struct ipv4_hdr));
	printf("  IPv4: Version=%d HLEN=%d Type=%d Length=%d\n",
				 (ip_h->version_ihl & 0xf0) >> 4, (ip_h->version_ihl & 0x0f),
				 ip_h->type_of_service, rte_cpu_to_be_16(ip_h->total_length));
	if (ip_h->next_proto_id == IPPROTO_ICMP)
		print_icmp_packet(icmp_h);
}

static void print_arp_packet(struct arp_hdr *arp_h)
{
	printf("  ARP:  hrd=%d proto=0x%04x hln=%d "
				 "pln=%d op=%u (%s)\n",
				 CHECK_ENDIAN_16(arp_h->arp_hrd),
				 CHECK_ENDIAN_16(arp_h->arp_pro), arp_h->arp_hln,
				 arp_h->arp_pln, CHECK_ENDIAN_16(arp_h->arp_op),
				 arp_op_name(arp_h->arp_op));

	if (CHECK_ENDIAN_16(arp_h->arp_hrd) != ARP_HRD_ETHER) {
		printf("incorrect arp_hrd format for IPv4 ARP (%d)\n",
					 (arp_h->arp_hrd));
	} else if (CHECK_ENDIAN_16(arp_h->arp_pro) != ETHER_TYPE_IPv4) {
		printf("incorrect arp_pro format for IPv4 ARP (%d)\n",
					 (arp_h->arp_pro));
	} else if (arp_h->arp_hln != 6) {
		printf("incorrect arp_hln format for IPv4 ARP (%d)\n",
					 arp_h->arp_hln);
	} else if (arp_h->arp_pln != 4) {
		printf("incorrect arp_pln format for IPv4 ARP (%d)\n",
					 arp_h->arp_pln);
	} else {
		// print remainder of ARP request
		printf("        sha=%02X:%02X:%02X:%02X:%02X:%02X",
					 arp_h->arp_data.arp_sha.addr_bytes[0],
					 arp_h->arp_data.arp_sha.addr_bytes[1],
					 arp_h->arp_data.arp_sha.addr_bytes[2],
					 arp_h->arp_data.arp_sha.addr_bytes[3],
					 arp_h->arp_data.arp_sha.addr_bytes[4],
					 arp_h->arp_data.arp_sha.addr_bytes[5]);
		printf(" sip=%d.%d.%d.%d\n",
					 (CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) >> 24) & 0xFF,
					 (CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) >> 16) & 0xFF,
					 (CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) >> 8) & 0xFF,
					 CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) & 0xFF);
		printf("        tha=%02X:%02X:%02X:%02X:%02X:%02X",
					 arp_h->arp_data.arp_tha.addr_bytes[0],
					 arp_h->arp_data.arp_tha.addr_bytes[1],
					 arp_h->arp_data.arp_tha.addr_bytes[2],
					 arp_h->arp_data.arp_tha.addr_bytes[3],
					 arp_h->arp_data.arp_tha.addr_bytes[4],
					 arp_h->arp_data.arp_tha.addr_bytes[5]);
		printf(" tip=%d.%d.%d.%d\n",
					 (CHECK_ENDIAN_32(arp_h->arp_data.arp_tip) >> 24) & 0xFF,
					 (CHECK_ENDIAN_32(arp_h->arp_data.arp_tip) >> 16) & 0xFF,
					 (CHECK_ENDIAN_32(arp_h->arp_data.arp_tip) >> 8) & 0xFF,
					 CHECK_ENDIAN_32(arp_h->arp_data.arp_tip) & 0xFF);
	}
}

static void print_eth(struct ether_hdr *eth_h)
{
	printf("  ETH:  src=%02X:%02X:%02X:%02X:%02X:%02X",
				 eth_h->s_addr.addr_bytes[0],
				 eth_h->s_addr.addr_bytes[1],
				 eth_h->s_addr.addr_bytes[2],
				 eth_h->s_addr.addr_bytes[3],
				 eth_h->s_addr.addr_bytes[4], eth_h->s_addr.addr_bytes[5]);
	printf(" dst=%02X:%02X:%02X:%02X:%02X:%02X\n",
				 eth_h->d_addr.addr_bytes[0],
				 eth_h->d_addr.addr_bytes[1],
				 eth_h->d_addr.addr_bytes[2],
				 eth_h->d_addr.addr_bytes[3],
				 eth_h->d_addr.addr_bytes[4], eth_h->d_addr.addr_bytes[5]);

}

static void
print_mbuf(const char *rx_tx, unsigned int portid, struct rte_mbuf *mbuf,
		 unsigned int line)
{
	struct ether_hdr *eth_h = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	struct arp_hdr *arp_h =
			(struct arp_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	struct ipv4_hdr *ipv4_h =
			(struct ipv4_hdr *)((char *)eth_h + sizeof(struct ether_hdr));

	printf("%s(%d): on port %d pkt-len=%u nb-segs=%u\n",
				 rx_tx, line, portid, mbuf->pkt_len, mbuf->nb_segs);
	print_eth(eth_h);
	switch (rte_cpu_to_be_16(eth_h->ether_type)) {
	case ETHER_TYPE_IPv4:
		print_ipv4_h(ipv4_h);
		break;
	case ETHER_TYPE_ARP:
		print_arp_packet(arp_h);
		break;
	default:
		printf("  unknown packet type\n");
		break;
	}
	fflush(stdout);
}

struct arp_entry_data *retrieve_arp_entry(struct arp_key_ipv4 arp_key)
{
	struct arp_entry_data *ret_arp_data = NULL;
	arp_key.filler1 = 0;
	arp_key.filler2 = 0;
	arp_key.filler3 = 0;

	int ret = rte_hash_lookup_data(arp_hash_handle, &arp_key,
							 (void **)&ret_arp_data);
	if (ret < 0) {
		if (ARPICMP_DEBUG)
			printf("arp-hash lookup failed ret %d, "
			"EINVAL %d, ENOENT %d\n",
			ret, EINVAL, ENOENT);
	} else {
		return ret_arp_data;
	}

	return NULL;
}

/*
* ND IPv6
* Validate if key-value pair already exists in the hash table
* for given key - ND IPv6
*
*/
struct nd_entry_data *retrieve_nd_entry(struct nd_key_ipv6 nd_key)
{
	struct nd_entry_data *ret_nd_data = NULL;
	nd_key.filler1 = 0;
	nd_key.filler2 = 0;
	nd_key.filler3 = 0;

	/*Find a nd IPv6 key-data pair in the hash table for ND IPv6 */
	int ret = rte_hash_lookup_data(nd_hash_handle, &nd_key,
							 (void **)&ret_nd_data);
	if (ret < 0) {
		if (NDIPV6_DEBUG)
			printf("nd-hash: no lookup Entry Found - "
			"ret %d, EINVAL %d, ENOENT %d\n",
			ret, EINVAL, ENOENT);
	} else {
		return ret_nd_data;
	}

	return NULL;
}

void print_arp_table(void)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;

	printf("\tport  hw addr            status     ip addr\n");

	while (rte_hash_iterate(arp_hash_handle, &next_key, &next_data, &iter)
				 >= 0) {

		struct arp_entry_data *tmp_arp_data =
				(struct arp_entry_data *)next_data;
		struct arp_key_ipv4 tmp_arp_key;
		memcpy(&tmp_arp_key, next_key, sizeof(struct arp_key_ipv4));
		printf
				("\t%4d  %02X:%02X:%02X:%02X:%02X:%02X  %10s %d.%d.%d.%d\n",
				 tmp_arp_data->port, tmp_arp_data->eth_addr.addr_bytes[0],
				 tmp_arp_data->eth_addr.addr_bytes[1],
				 tmp_arp_data->eth_addr.addr_bytes[2],
				 tmp_arp_data->eth_addr.addr_bytes[3],
				 tmp_arp_data->eth_addr.addr_bytes[4],
				 tmp_arp_data->eth_addr.addr_bytes[5],
				 tmp_arp_data->status ==
				 COMPLETE ? "COMPLETE" : "INCOMPLETE",
				 (tmp_arp_data->ip >> 24),
				 ((tmp_arp_data->ip & 0x00ff0000) >> 16),
				 ((tmp_arp_data->ip & 0x0000ff00) >> 8),
				 ((tmp_arp_data->ip & 0x000000ff)));
	}

	uint32_t i = 0;
	printf("\nARP routing table has %d entries\n", arp_route_tbl_index);
	printf("\nIP_Address    Mask          Port    NH_IP_Address\n");
	for (i = 0; i < arp_route_tbl_index; i++) {
		printf("0x%x    0x%x    %d       0x%x\n",
					 lib_arp_route_table[i].ip,
					 lib_arp_route_table[i].mask,
					 lib_arp_route_table[i].port, lib_arp_route_table[i].nh);
	}

	printf("\nARP Stats: Total Queries %u, ok_NH %u, no_NH %u, "
	"ok_Entry %u, no_Entry %u, PopulateCall %u, Del %u, Dup %u\n",
			 lib_arp_get_mac_req, lib_arp_nh_found, lib_arp_no_nh_found,
			 lib_arp_arp_entry_found, lib_arp_no_arp_entry_found,
			 lib_arp_populate_called, lib_arp_delete_called,
			 lib_arp_duplicate_found);

	printf("ARP table key len is %lu\n", sizeof(struct arp_key_ipv4));
}

/* ND IPv6 */
void print_nd_table(void)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;
	uint8_t ii = 0, j = 0, k = 0;

	printf("\tport  hw addr            status         ip addr\n");

	while (rte_hash_iterate(nd_hash_handle, &next_key, &next_data, &iter) >=
				 0) {

		struct nd_entry_data *tmp_nd_data =
				(struct nd_entry_data *)next_data;
		struct nd_key_ipv6 tmp_nd_key;
		memcpy(&tmp_nd_key, next_key, sizeof(struct nd_key_ipv6));
		printf("\t%4d  %02X:%02X:%02X:%02X:%02X:%02X  %10s\n",
					 tmp_nd_data->port,
					 tmp_nd_data->eth_addr.addr_bytes[0],
					 tmp_nd_data->eth_addr.addr_bytes[1],
					 tmp_nd_data->eth_addr.addr_bytes[2],
					 tmp_nd_data->eth_addr.addr_bytes[3],
					 tmp_nd_data->eth_addr.addr_bytes[4],
					 tmp_nd_data->eth_addr.addr_bytes[5],
					 tmp_nd_data->status ==
					 COMPLETE ? "COMPLETE" : "INCOMPLETE");
		printf("\t\t\t\t\t\t");
		for (ii = 0; ii < ND_IPV6_ADDR_SIZE; ii += 2) {
			printf("%02X%02X ", tmp_nd_data->ipv6[ii],
						 tmp_nd_data->ipv6[ii + 1]);
		}
		printf("\n");
	}

	uint32_t i = 0;
	printf("\n\nND IPV6 routing table has %d entries\n",
				 nd_route_tbl_index);
	printf("\nIP_Address	Depth		Port	NH_IP_Address\n");
	for (i = 0; i < nd_route_tbl_index; i++) {
		printf("\n");

		for (j = 0; j < ND_IPV6_ADDR_SIZE; j += 2) {
			printf("%02X%02X ", lib_nd_route_table[i].ipv6[j],
						 lib_nd_route_table[i].ipv6[j + 1]);
		}

		printf
				("\n\t\t\t			%d					 %d\n",
				 lib_nd_route_table[i].depth, lib_nd_route_table[i].port);
		printf("\t\t\t\t\t\t\t\t\t");
		for (k = 0; k < ND_IPV6_ADDR_SIZE; k += 2) {
			printf("%02X%02X ", lib_nd_route_table[i].nhipv6[k],
						 lib_nd_route_table[i].ipv6[k + 1]);
		}
	}
	printf("\nND IPV6 Stats:\nTotal Queries %u, ok_NH %u, no_NH %u,"
		"ok_Entry %u, no_Entry %u, PopulateCall %u, Del %u, Dup %u\n",
			 lib_nd_get_mac_req, lib_nd_nh_found, lib_nd_no_nh_found,
			 lib_nd_nd_entry_found, lib_nd_no_arp_entry_found,
			 lib_nd_populate_called, lib_nd_delete_called,
			 lib_nd_duplicate_found);
	printf("ND table key len is %lu\n\n", sizeof(struct nd_key_ipv6));
}

void remove_arp_entry(uint32_t ipaddr, uint8_t portid)
{

	/* need to lock here if multi-threaded... */
	/* rte_hash_del_key is not thread safe */
	struct arp_key_ipv4 arp_key;
	arp_key.port_id = portid;
	arp_key.ip = ipaddr;
	arp_key.filler1 = 0;
	arp_key.filler2 = 0;
	arp_key.filler3 = 0;

	lib_arp_delete_called++;

	if (ARPICMP_DEBUG)
		printf("remove_arp_entry ip %x, port %d\n", arp_key.ip,
					 arp_key.port_id);
	rte_hash_del_key(arp_hash_handle, &arp_key);
}

/* ND IPv6 */
void remove_nd_entry_ipv6(uint8_t ipv6addr[], uint8_t portid)
{
	/* need to lock here if multi-threaded */
	/* rte_hash_del_key is not thread safe */
	int i = 0;
	struct nd_key_ipv6 nd_key;
	nd_key.port_id = portid;
	/* arp_key.ip = rte_bswap32(ipaddr); */

	for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
		nd_key.ipv6[i] = ipv6addr[i];

	nd_key.filler1 = 0;
	nd_key.filler2 = 0;
	nd_key.filler3 = 0;

	lib_nd_delete_called++;

	if (NDIPV6_DEBUG) {
		printf("Deletes rte hash table nd entry for port %d ipv6=",
					 nd_key.port_id);
		for (i = 0; i < ND_IPV6_ADDR_SIZE; i += 2)
			printf("%02X%02X ", nd_key.ipv6[i], nd_key.ipv6[i + 1]);
	}
	rte_hash_del_key(nd_hash_handle, &nd_key);
}

void
populate_arp_entry(const struct ether_addr *hw_addr, uint32_t ipaddr,
			 uint8_t portid)
{
	/* need to lock here if multi-threaded */
	/* rte_hash_add_key_data is not thread safe */
	struct arp_key_ipv4 arp_key;
	arp_key.port_id = portid;
	arp_key.ip = ipaddr;
	arp_key.filler1 = 0;
	arp_key.filler2 = 0;
	arp_key.filler3 = 0;

	lib_arp_populate_called++;

	if (ARPICMP_DEBUG)
		printf("populate_arp_entry ip %x, port %d\n", arp_key.ip,
					 arp_key.port_id);
	struct arp_entry_data *new_arp_data = retrieve_arp_entry(arp_key);
	if (new_arp_data
			&& is_same_ether_addr(&new_arp_data->eth_addr, hw_addr)) {
		if (ARPICMP_DEBUG)
			printf("arp_entry exists ip%x, port %d\n", arp_key.ip,
						 arp_key.port_id);
		lib_arp_duplicate_found++;
		return;
	}
	new_arp_data = (struct arp_entry_data *)
			malloc(sizeof(struct arp_entry_data));
	if (new_arp_data == NULL) {
	printf("populate_arp_entry:new_arp_data is NULL\n");
		return;
	}
	new_arp_data->eth_addr = *hw_addr;
	new_arp_data->status = INCOMPLETE;
	new_arp_data->port = portid;
	new_arp_data->ip = ipaddr;
	rte_hash_add_key_data(arp_hash_handle, &arp_key, new_arp_data);

	if (ARPICMP_DEBUG) {
		// print entire hash table
		printf("\tARP: table update - hwaddr= "
		"%02x:%02x:%02x:%02x:%02x:%02x  ip=%d.%d.%d.%d  "
		"on port=%d\n",
		new_arp_data->eth_addr.addr_bytes[0],
		new_arp_data->eth_addr.addr_bytes[1],
		new_arp_data->eth_addr.addr_bytes[2],
		new_arp_data->eth_addr.addr_bytes[3],
		new_arp_data->eth_addr.addr_bytes[4],
		new_arp_data->eth_addr.addr_bytes[5],
		(arp_key.ip >> 24),
		((arp_key.ip & 0x00ff0000) >> 16),
		((arp_key.ip & 0x0000ff00) >> 8),
		((arp_key.ip & 0x000000ff)), portid);
		/* print_arp_table(); */
		puts("");
	}
}

/*
* ND IPv6
*
* Install key - data pair in Hash table - From Pipeline Configuration
*
*/
int
populate_nd_entry(const struct ether_addr *hw_addr, uint8_t ipv6[],
			uint8_t portid)
{

	/* need to lock here if multi-threaded */
	/* rte_hash_add_key_data is not thread safe */
	uint8_t i;
	struct nd_key_ipv6 nd_key;
	nd_key.port_id = portid;

	for (i = 0; i < ND_IPV6_ADDR_SIZE; i++ /*i+=2 */)
		nd_key.ipv6[i] = ipv6[i];

	printf("\n");
	nd_key.filler1 = 0;
	nd_key.filler2 = 0;
	nd_key.filler3 = 0;

	lib_nd_populate_called++;

	/*Validate if key-value pair already
	* exists in the hash table for ND IPv6
	*/
	struct nd_entry_data *new_nd_data = retrieve_nd_entry(nd_key);

	if (new_nd_data && is_same_ether_addr(&new_nd_data->eth_addr,
		hw_addr)) {

		if (NDIPV6_DEBUG) {
			printf("nd_entry exists port %d ipv6 = ",
						 nd_key.port_id);
			for (i = 0; i < ND_IPV6_ADDR_SIZE; i += 2) {

				printf("%02X%02X ", nd_key.ipv6[i],
							 nd_key.ipv6[i + 1]);
			}
		}

		lib_nd_duplicate_found++;
		if (NDIPV6_DEBUG)
			printf("nd_entry exists\n");
		return 0;
	}

	new_nd_data = (struct nd_entry_data *)
			malloc(sizeof(struct nd_entry_data));
	if (new_nd_data == NULL) {
		printf("populate_nd_entry: new_nd_data is NULL\n");
		return 0;
	}
	new_nd_data->eth_addr = *hw_addr;
	new_nd_data->status = COMPLETE;
	new_nd_data->port = portid;

	if (NDIPV6_DEBUG)
		printf("populate_nd_entry ipv6=");

	for (i = 0; i < ND_IPV6_ADDR_SIZE; i++ /*i+=2 */)
		new_nd_data->ipv6[i] = ipv6[i];

	if (NDIPV6_DEBUG) {
		for (i = 0; i < ND_IPV6_ADDR_SIZE; i += 2) {

			printf("%02X%02X ", new_nd_data->ipv6[i],
						 new_nd_data->ipv6[i + 1]);
		}
	}

	/*Add a key-data pair at hash table for ND IPv6 static routing */
	rte_hash_add_key_data(nd_hash_handle, &nd_key, new_nd_data);

	if (NDIPV6_DEBUG)
		printf("\n....Added a key-data pair at rte hash table "
		"for ND IPv6 static routing\n");

	if (NDIPV6_DEBUG) {
		/* print entire hash table */
		printf("\tND: table update - hwaddr= "
		"%02x:%02x:%02x:%02x:%02x:%02x on port=%d\n",
		new_nd_data->eth_addr.addr_bytes[0],
		new_nd_data->eth_addr.addr_bytes[1],
		new_nd_data->eth_addr.addr_bytes[2],
		new_nd_data->eth_addr.addr_bytes[3],
		new_nd_data->eth_addr.addr_bytes[4],
		new_nd_data->eth_addr.addr_bytes[5], portid);
		printf("\tipv6=");
		for (i = 0; i < ND_IPV6_ADDR_SIZE; i += 2) {
			new_nd_data->ipv6[i] = ipv6[i];
			printf("%02X%02X ", new_nd_data->ipv6[i],
						 new_nd_data->ipv6[i + 1]);
		}

		printf("\n");

		puts("");
	}
	return 1;
}

void print_pkt1(struct rte_mbuf *pkt)
{
	uint8_t *rd = RTE_MBUF_METADATA_UINT8_PTR(pkt, 0);
	int i = 0, j = 0;
	printf("\nPacket Contents...\n");
	for (i = 0; i < 20; i++) {
		for (j = 0; j < 20; j++)
			printf("%02x ", rd[(20 * i) + j]);
		printf("\n");
	}
}

struct ether_addr broadcast_ether_addr = {
	.addr_bytes[0] = 0xFF,
	.addr_bytes[1] = 0xFF,
	.addr_bytes[2] = 0xFF,
	.addr_bytes[3] = 0xFF,
	.addr_bytes[4] = 0xFF,
	.addr_bytes[5] = 0xFF,
};

static const struct ether_addr null_ether_addr = {
	.addr_bytes[0] = 0x00,
	.addr_bytes[1] = 0x00,
	.addr_bytes[2] = 0x00,
	.addr_bytes[3] = 0x00,
	.addr_bytes[4] = 0x00,
	.addr_bytes[5] = 0x00,
};

#define MAX_NUM_MAC_ADDRESS 16
struct ether_addr link_hw_addr[MAX_NUM_MAC_ADDRESS] = {
{.addr_bytes = {0x90, 0xe2, 0xba, 0x54, 0x67, 0xc8} },
{.addr_bytes = {0x90, 0xe2, 0xba, 0x54, 0x67, 0xc9} },
{.addr_bytes = {0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11} },
{.addr_bytes = {0x12, 0x13, 0x14, 0x15, 0x16, 0x17} },
{.addr_bytes = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77} },
{.addr_bytes = {0x12, 0x13, 0x14, 0x15, 0x16, 0x17} },
{.addr_bytes = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77} },
{.addr_bytes = {0x90, 0xe2, 0xba, 0x54, 0x67, 0xc9} },
{.addr_bytes = {0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11} },
{.addr_bytes = {0x12, 0x13, 0x14, 0x15, 0x16, 0x17} },
{.addr_bytes = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77} },
{.addr_bytes = {0x12, 0x13, 0x14, 0x15, 0x16, 0x17} },
{.addr_bytes = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77} },
{.addr_bytes = {0x12, 0x13, 0x14, 0x15, 0x16, 0x17} },
{.addr_bytes = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77} },
{.addr_bytes = {0x18, 0x19, 0x1a, 0x1b, 0xcd, 0xef} }
};

struct ether_addr *get_link_hw_addr(uint8_t out_port)
{
	return &link_hw_addr[out_port];
}

static void
request_icmp_echo(unsigned int port_id, uint32_t ip, struct ether_addr *gw_addr)
{
	struct ether_hdr *eth_h;
	struct ipv4_hdr *ip_h;
	struct icmp_hdr *icmp_h;

	struct app_link_params *link;
	link = &myApp->link_params[port_id];
	arp_port_addresses[port_id].ip = link->ip;
	arp_port_addresses[port_id].mac_addr = link->mac_addr;

	struct rte_mbuf *icmp_pkt = lib_arp_pkt;
	if (icmp_pkt == NULL) {
		if (ARPICMP_DEBUG)
			printf("Error allocating icmp_pkt rte_mbuf\n");
		return;
	}

	eth_h = rte_pktmbuf_mtod(icmp_pkt, struct ether_hdr *);
	ether_addr_copy(gw_addr, &eth_h->d_addr);
	ether_addr_copy((struct ether_addr *)
			&arp_port_addresses[port_id].mac_addr, &eth_h->s_addr);
	eth_h->ether_type = CHECK_ENDIAN_16(ETHER_TYPE_IPv4);

	ip_h = (struct ipv4_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	icmp_h = (struct icmp_hdr *)((char *)ip_h + sizeof(struct ipv4_hdr));

	ip_h->version_ihl = IP_VHL_DEF;
	ip_h->type_of_service = 0;
	ip_h->total_length =
			rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct icmp_hdr));
	ip_h->packet_id = 0xaabb;
	ip_h->fragment_offset = 0x0000;
	ip_h->time_to_live = 64;
	ip_h->next_proto_id = IPPROTO_ICMP;
	ip_h->src_addr = rte_bswap32(arp_port_addresses[port_id].ip);
	ip_h->dst_addr = ip;

	ip_h->hdr_checksum = 0;
	ip_h->hdr_checksum = rte_ipv4_cksum(ip_h);

	icmp_h->icmp_type = IP_ICMP_ECHO_REQUEST;
	icmp_h->icmp_code = 0;
	icmp_h->icmp_ident = 0xdead;
	icmp_h->icmp_seq_nb = 0xbeef;

	icmp_h->icmp_cksum = ~rte_raw_cksum(icmp_h, sizeof(struct icmp_hdr));

	icmp_pkt->pkt_len =
			sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
			sizeof(struct icmp_hdr);
	icmp_pkt->data_len = icmp_pkt->pkt_len;

	if (ARPICMP_DEBUG) {
		printf("Sending echo request\n");
		print_mbuf("TX", port_id, icmp_pkt, __LINE__);
	}

	rte_pipeline_port_out_packet_insert(gp_arp->p.p,
		gp_arp->outport_id[port_id], icmp_pkt);
	gp_arp->sentPktCount++;
}

void request_echo(unsigned int port_id, uint32_t ip)
{
	(void)port_id;
	(void)ip;

	struct ether_addr gw_addr;
	uint32_t dest_ip = rte_bswap32(ip);
	uint32_t phy_port;

	if (get_dest_mac_addr_port(dest_ip, &phy_port, &gw_addr) == ARP_FOUND) {
		request_icmp_echo(phy_port, ip, &gw_addr);
		return;
	}

	if (ARPICMP_DEBUG)
		printf("Sending echo request ... get mac failed.\n");
}

void request_arp(uint8_t port_id, uint32_t ip, struct rte_pipeline *rte_p)
{
	(void)port_id;
	(void)ip;

	struct ether_hdr *eth_h;
	struct arp_hdr *arp_h;

	struct app_link_params *link;
	link = &myApp->link_params[port_id];
	arp_port_addresses[port_id].ip = link->ip;
	arp_port_addresses[port_id].mac_addr = link->mac_addr;

	struct rte_mbuf *arp_pkt = lib_arp_pkt;

	if (arp_pkt == NULL) {
		if (ARPICMP_DEBUG)
			printf("Error allocating arp_pkt rte_mbuf\n");
		return;
	}

	eth_h = rte_pktmbuf_mtod(arp_pkt, struct ether_hdr *);

	ether_addr_copy(&broadcast_ether_addr, &eth_h->d_addr);
	ether_addr_copy((struct ether_addr *)
			&arp_port_addresses[port_id].mac_addr, &eth_h->s_addr);
	eth_h->ether_type = CHECK_ENDIAN_16(ETHER_TYPE_ARP);

	arp_h = (struct arp_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	arp_h->arp_hrd = CHECK_ENDIAN_16(ARP_HRD_ETHER);
	arp_h->arp_pro = CHECK_ENDIAN_16(ETHER_TYPE_IPv4);
	arp_h->arp_hln = ETHER_ADDR_LEN;
	arp_h->arp_pln = sizeof(uint32_t);
	arp_h->arp_op = CHECK_ENDIAN_16(ARP_OP_REQUEST);

	ether_addr_copy((struct ether_addr *)
			&arp_port_addresses[port_id].mac_addr,
			&arp_h->arp_data.arp_sha);
	arp_h->arp_data.arp_sip =
			rte_cpu_to_be_32(arp_port_addresses[port_id].ip);
	ether_addr_copy(&null_ether_addr, &arp_h->arp_data.arp_tha);
	arp_h->arp_data.arp_tip = rte_cpu_to_be_32(ip);
	printf("arp tip:%x arp sip :%x\n", arp_h->arp_data.arp_tip,
				 arp_h->arp_data.arp_sip);
	/* mmcd changed length from 60 to 42 -
	* real length of arp request, no padding on ethernet needed -
	* looks now like linux arp
	*/

	arp_pkt->pkt_len = 42;
	arp_pkt->data_len = 42;

	if (ARPICMP_DEBUG) {
		printf("Sending arp request\n");
		print_mbuf("TX", port_id, arp_pkt, __LINE__);
	}

	rte_pipeline_port_out_packet_insert(rte_p, port_id, arp_pkt);
	gp_arp->sentPktCount++;

}

void request_arp_wrap(uint8_t port_id, uint32_t ip)
{
	request_arp(port_id, ip, gp_arp->p.p);
}

void process_arpicmp_pkt(
	struct rte_mbuf *pkt,
	uint32_t out_port,
	uint32_t pkt_mask)
{
	uint8_t in_port_id = pkt->port;
	struct app_link_params *link;
	struct ether_hdr *eth_h;
	struct arp_hdr *arp_h;
	struct ipv4_hdr *ip_h;
	struct icmp_hdr *icmp_h;
	uint32_t cksum;
	uint32_t ip_addr;
	uint32_t req_tip;


	eth_h = rte_pktmbuf_mtod(pkt, struct ether_hdr *);

	if (eth_h->ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP)) {
		arp_h =
				(struct arp_hdr *)((char *)eth_h +
							 sizeof(struct ether_hdr));
		if (CHECK_ENDIAN_16(arp_h->arp_hrd) != ARP_HRD_ETHER)
			printf
					("Invalid hardware format of hardware address - "
				"not processing ARP req\n");
		else if (CHECK_ENDIAN_16(arp_h->arp_pro) != ETHER_TYPE_IPv4)
			printf
					("Invalid protocol address format - "
				"not processing ARP req\n");
		else if (arp_h->arp_hln != 6)
			printf
					("Invalid hardware address length - "
				"not processing ARP req\n");
		else if (arp_h->arp_pln != 4)
			printf
					("Invalid protocol address length - "
				"not processing ARP req\n");
		else {
			link = &myApp->link_params[in_port_id];
			arp_port_addresses[in_port_id].ip = link->ip;
			arp_port_addresses[in_port_id].mac_addr =
					link->mac_addr;

			if (arp_h->arp_data.arp_tip !=
					rte_bswap32(arp_port_addresses[in_port_id].ip)) {
				printf
						("ARP requested IP address mismatches "
					"interface IP - discarding\n");
				printf("arp_tip = %x\n",
							 arp_h->arp_data.arp_tip);
				printf("arp_port_addresses = %x\n",
							 arp_port_addresses[in_port_id].ip);
				printf("in_port_id = %x\n", in_port_id);
				printf("arp_port_addresses[0] = %x\n",
							 arp_port_addresses[0].ip);

				rte_pipeline_ah_packet_drop(gp_arp->p.p,
						pkt_mask);
				gp_arp->droppedPktCount++;

			}
			/* revise conditionals to allow processing of
			* requests with target ip = this ip and
			* processing of replies to destination ip = this ip
			*/
			else if (arp_h->arp_op ==
				 rte_cpu_to_be_16(ARP_OP_REQUEST)) {

				if (ARPICMP_DEBUG) {
				printf("arp_op %d, ARP_OP_REQUEST %d\n",
							 arp_h->arp_op,
							 rte_cpu_to_be_16(ARP_OP_REQUEST));
				print_mbuf("RX", in_port_id, pkt, __LINE__);
				}

				populate_arp_entry((struct ether_addr *)
							 &arp_h->arp_data.arp_sha,
							 rte_cpu_to_be_32
							 (arp_h->arp_data.arp_sip),
							 in_port_id);

				/* build reply */
				req_tip = arp_h->arp_data.arp_tip;
				ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);

				// set sender mac address -
				ether_addr_copy((struct ether_addr *)&
				arp_port_addresses[in_port_id].mac_addr,
				&eth_h->s_addr);

				arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
				ether_addr_copy(&eth_h->s_addr,
						&arp_h->arp_data.arp_sha);
				arp_h->arp_data.arp_tip =
						arp_h->arp_data.arp_sip;
				arp_h->arp_data.arp_sip = req_tip;
				ether_addr_copy(&eth_h->d_addr,
						&arp_h->arp_data.arp_tha);

				rte_pipeline_port_out_packet_insert(gp_arp->p.p,
						out_port, pkt);
				gp_arp->sentPktCount++;

			} else if (arp_h->arp_op ==
					 rte_cpu_to_be_16(ARP_OP_REPLY)) {
				// TODO: be sure that ARP request
				//was actually sent!!!
				if (ARPICMP_DEBUG) {
					printf("ARP_OP_REPLY received");
					print_mbuf("RX", in_port_id, pkt,
							 __LINE__);
				}
				populate_arp_entry((struct ether_addr *)
							 &arp_h->arp_data.arp_sha,
							 rte_bswap32(arp_h->
							arp_data.arp_sip),
							 in_port_id);

				/* To drop the packet from LB */
				rte_pipeline_ah_packet_drop(gp_arp->p.p,
						pkt_mask);
				gp_arp->droppedPktCount++;

			} else {
				if (ARPICMP_DEBUG)
					printf("Invalid ARP opcode - not "
					"processing ARP req %x\n",
					arp_h->arp_op);
			}
		}
	} else {
		ip_h =
				(struct ipv4_hdr *)((char *)eth_h +
					sizeof(struct ether_hdr));
		icmp_h =
				(struct icmp_hdr *)((char *)ip_h + sizeof(struct ipv4_hdr));

		if (eth_h->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {

			link = &myApp->link_params[in_port_id];
			arp_port_addresses[in_port_id].ip = link->ip;
			arp_port_addresses[in_port_id].mac_addr =
					link->mac_addr;

			if (!is_same_ether_addr((struct ether_addr *)
						&arp_port_addresses[in_port_id].
						mac_addr, &eth_h->d_addr)) {

				if (ARPICMP_DEBUG)
					printf("Ethernet frame not destined "
					"for MAC address of received network "
					"interface - discarding\n");

			} else if (ip_h->next_proto_id != IPPROTO_ICMP) {
				if (ARPICMP_DEBUG)
					printf("IP protocol ID is not set to "
					"ICMP - discarding\n");

			} else if ((ip_h->version_ihl & 0xf0) != IP_VERSION_4) {
				if (ARPICMP_DEBUG)
					printf("IP version other than 4 - "
					"discarding\n");

			} else if ((ip_h->version_ihl & 0x0f) != IP_HDRLEN) {
				if (ARPICMP_DEBUG)
					printf("Unknown IHL - discarding\n");

			} else {
				if (icmp_h->icmp_type == IP_ICMP_ECHO_REQUEST
						&& icmp_h->icmp_code == 0) {
				if (ARPICMP_DEBUG)
					print_mbuf("RX", in_port_id,
								 pkt, __LINE__);

				ip_addr = ip_h->src_addr;
				ether_addr_copy(&eth_h->s_addr,
						&eth_h->d_addr);
				ether_addr_copy((struct ether_addr *)
						&arp_port_addresses
						[in_port_id].mac_addr,
						&eth_h->s_addr);

				if (ip_h->dst_addr !=
					rte_bswap32(arp_port_addresses
					[in_port_id].ip)) {
					if (ARPICMP_DEBUG) {
					printf("IPv4 packet not destined for "
					"configured IP on RX port - "
					"discarding\n");
					printf("ip_h->dst_addr = %u, "
					"in_port_id = %u, "
					"arp_port_addresses.ip = %u\n",
					ip_h->dst_addr, in_port_id,
					arp_port_addresses[in_port_id].ip);
					}
				} else {

					if (is_multicast_ipv4_addr
						(ip_h->dst_addr)) {
						uint32_t ip_src;

					ip_src = rte_be_to_cpu_32
									(ip_addr);
					if ((ip_src & 0x00000003) == 1)
						ip_src = (ip_src &
								0xFFFFFFFC)
							| 0x00000002;
					else
						ip_src = (ip_src &
								0xFFFFFFFC)
							| 0x00000001;

					ip_h->src_addr =
								rte_cpu_to_be_32(ip_src);
					ip_h->dst_addr = ip_addr;

					ip_h->hdr_checksum = 0;
					ip_h->hdr_checksum = ~rte_raw_cksum(
							ip_h, sizeof(struct
							ipv4_hdr));
			} else {
				ip_h->src_addr = ip_h->dst_addr;
				ip_h->dst_addr = ip_addr;
				}

			icmp_h->icmp_type =
						IP_ICMP_ECHO_REPLY;
			cksum = ~icmp_h->icmp_cksum & 0xffff;
			cksum += ~htons(IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
			cksum += htons(IP_ICMP_ECHO_REPLY << 8);
			cksum = (cksum & 0xffff) + (cksum >> 16);
			cksum = (cksum & 0xffff) + (cksum >> 16);
			icmp_h->icmp_cksum = ~cksum;

			if (ARPICMP_DEBUG)
				print_mbuf("TX", in_port_id, pkt, __LINE__);

				rte_pipeline_port_out_packet_insert(gp_arp->p.p,
						out_port, pkt);
				gp_arp->sentPktCount++;

			}
			}
			else if (icmp_h->icmp_type == IP_ICMP_ECHO_REPLY
				&& icmp_h->icmp_code == 0) {
			if (ARPICMP_DEBUG)
				print_mbuf("RX", in_port_id,
							 pkt, __LINE__);

			struct arp_key_ipv4 arp_key;
			arp_key.port_id = in_port_id;
			arp_key.ip =
			rte_bswap32(ip_h->src_addr);
			arp_key.filler1 = 0;
			arp_key.filler2 = 0;
			arp_key.filler3 = 0;

			struct arp_entry_data *arp_entry =
						retrieve_arp_entry(arp_key);
			if (arp_entry == NULL) {
				printf("Received unsolicited "
				"ICMP echo reply from ip%x, "
					"port %d\n",
						 arp_key.ip,
						 arp_key.port_id);
					return;
			}

				arp_entry->status = COMPLETE;
				/* To drop the packet from LB */
				rte_pipeline_ah_packet_drop(gp_arp->p.p,
						pkt_mask);
				gp_arp->droppedPktCount++;
			}
			}
		}
	}
}



/* int
 * inet_pton(af, src, dst)
 *      convert from presentation format (which usually means ASCII printable)
 *      to network format (which is usually some kind of binary format).
 * return:
 *      1 if the address was valid for the specified address family
 *      0 if the address wasn't valid (`dst' is untouched in this case)
 *      -1 if some other error occurred (`dst' is untouched in this case, too)
 * author:
 *      Paul Vixie, 1996.
 */
static int my_inet_pton_ipv6(int af, const char *src, void *dst)
{
	switch (af) {
	case AF_INET:
		return inet_pton_ipv4(src, dst);
	case AF_INET6:
		return inet_pton_ipv6(src, dst);
	default:
		errno = EAFNOSUPPORT;
		return -1;
	}
	/* NOTREACHED */
}

/* int
 * inet_pton_ipv4(src, dst)
 *      like inet_aton() but without all the hexadecimal and shorthand.
 * return:
 *      1 if `src' is a valid dotted quad, else 0.
 * notice:
 *      does not touch `dst' unless it's returning 1.
 * author:
 *      Paul Vixie, 1996.
 */
static int inet_pton_ipv4(const char *src, unsigned char *dst)
{
	static const char digits[] = "0123456789";
	int saw_digit, octets, ch;
	unsigned char tmp[INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		pch = strchr(digits, ch);
		if (pch != NULL) {
			unsigned int new = *tp * 10 + (pch - digits);

			if (new > 255)
				return 0;
			if (!saw_digit) {
				if (++octets > 4)
					return 0;
				saw_digit = 1;
			}
			*tp = (unsigned char)new;
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return 0;
			*++tp = 0;
			saw_digit = 0;
		} else
			return 0;
	}
	if (octets < 4)
		return 0;

	memcpy(dst, tmp, INADDRSZ);
	return 1;
}

/* int
 * inet_pton_ipv6(src, dst)
 *      convert presentation level address to network order binary form.
 * return:
 *      1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *      (1) does not touch `dst' unless it's returning 1.
 *      (2) :: in a full address is silently ignored.
 * credit:
 *      inspired by Mark Andrews.
 * author:
 *      Paul Vixie, 1996.
 */
static int inet_pton_ipv6(const char *src, unsigned char *dst)
{
	static const char xdigits_l[] = "0123456789abcdef",
			xdigits_u[] = "0123456789ABCDEF";
	unsigned char tmp[IN6ADDRSZ], *tp = 0, *endp = 0, *colonp = 0;
	const char *xdigits = 0, *curtok = 0;
	int ch = 0, saw_xdigit = 0, count_xdigit = 0;
	unsigned int val = 0;
	unsigned int dbloct_count = 0;

	memset((tp = tmp), '\0', IN6ADDRSZ);
	endp = tp + IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return 0;
	curtok = src;
	saw_xdigit = count_xdigit = 0;
	val = 0;

	while ((ch = *src++) != '\0') {
		const char *pch;

		pch = strchr((xdigits = xdigits_l), ch);
		if (pch  == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			if (count_xdigit >= 4)
				return 0;
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return 0;
			saw_xdigit = 1;
			count_xdigit++;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return 0;
				colonp = tp;
				continue;
			} else if (*src == '\0') {
				return 0;
			}
			if (tp + sizeof(int16_t) > endp)
				return 0;
			*tp++ = (unsigned char)((val >> 8) & 0xff);
			*tp++ = (unsigned char)(val & 0xff);
			saw_xdigit = 0;
			count_xdigit = 0;
			val = 0;
			dbloct_count++;
			continue;
		}
		if (ch == '.' && ((tp + INADDRSZ) <= endp) &&
				inet_pton_ipv4(curtok, tp) > 0) {
			tp += INADDRSZ;
			saw_xdigit = 0;
			dbloct_count += 2;
			break;	/* '\0' was seen by inet_pton4(). */
		}
		return 0;
	}
	if (saw_xdigit) {
		if (tp + sizeof(int16_t) > endp)
			return 0;
		*tp++ = (unsigned char)((val >> 8) & 0xff);
		*tp++ = (unsigned char)(val & 0xff);
		dbloct_count++;
	}
	if (colonp != NULL) {
		/* if we already have 8 double octets,
		* having a colon means error
		*/
		if (dbloct_count == 8)
			return 0;

		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = tp - colonp;
		int i;

		for (i = 1; i <= n; i++) {
			endp[-i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return 0;
	memcpy(dst, tmp, IN6ADDRSZ);
	return 1;
}

/**
 * Function to classify ICMPv6 Packets based on NextHeader field in IPv6 Header.
 * Updates ND Cache table with link layer addresses as received from Neighbor.
 * Processes ICMPv6 Echo destined to local port and replys.
 *
 * @param pkt
 *   A pointer to the packet received from Loadbalancer pipeline
 * @param out_port
 *  A pointer to the output port action
 * @param pkt_num
 *  A packet number
 *
 * @return
 *  NULL
 */

void
process_icmpv6_pkt(
	struct rte_mbuf *pkt,
	uint32_t out_port,
	__rte_unused uint32_t pkt_num)
{

	uint8_t in_port_id = pkt->port;
	struct app_link_params *link;
	struct ether_hdr *eth_h;
	struct ipv6_hdr *ipv6_h;
	struct icmpv6_hdr *icmpv6_h;
	struct icmpv6_nd_hdr *icmpv6_nd_h;
	uint8_t ipv6_addr[16];
	uint8_t i = 0, flag = 1;
	uint8_t req_tipv6[16];

	eth_h = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	ipv6_h = (struct ipv6_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	icmpv6_h =
			(struct icmpv6_hdr *)((char *)ipv6_h + sizeof(struct ipv6_hdr));
	struct rte_mbuf *icmpv6_pkt = pkt;

	link = &myApp->link_params[in_port_id];
	icmpv6_port_addresses[in_port_id].mac_addr = link->mac_addr;

	if (!is_same_ether_addr
			((struct ether_addr *)&icmpv6_port_addresses[in_port_id].mac_addr,
			 &eth_h->d_addr)) {
		if (ARPICMP_DEBUG) {
			printf("Ethernet frame not destined for MAC address "
			"of received network interface - discarding\n");
		}
	} else {
		if ((icmpv6_h->icmpv6_type == ICMPV6_ECHO_REQUEST)
				&& (icmpv6_h->icmpv6_code == 0)) {
			for (i = 0; i < 16; i++)
				ipv6_addr[i] = ipv6_h->src_addr[i];

			for (i = 0; i < 16; i++) {
				if (ipv6_h->dst_addr[i] !=
						icmpv6_port_addresses[in_port_id].ipv6[i]) {
					flag++;
				}
			}
			if (!flag) {
				printf("IPv6 packet not destined for "
				"configured IP on RX port - discarding\n");
			} else {
				{

					ether_addr_copy(&eth_h->s_addr,
							&eth_h->d_addr);
					ether_addr_copy((struct ether_addr *)
							&icmpv6_port_addresses
							[in_port_id].mac_addr,
							&eth_h->s_addr);

					for (i = 0; i < 16; i++)
						ipv6_h->src_addr[i] =
								ipv6_h->dst_addr[i];
					for (i = 0; i < 16; i++)
						ipv6_h->dst_addr[i] =
								ipv6_addr[i];

					icmpv6_h->icmpv6_type =
							ICMPV6_ECHO_REPLY;

					rte_pipeline_port_out_packet_insert
							(gp_arp->p.p, out_port, icmpv6_pkt);
					gp_arp->sentPktCount++;
				}
			}

		} else if ((icmpv6_h->icmpv6_type == ICMPV6_ECHO_REPLY)
				 && (icmpv6_h->icmpv6_code == 0)) {
			struct nd_key_ipv6 nd_key;
			nd_key.port_id = in_port_id;

			for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
				nd_key.ipv6[i] = ipv6_h->src_addr[i];

			nd_key.filler1 = 0;
			nd_key.filler2 = 0;
			nd_key.filler3 = 0;

			/* Validate if key-value pair already
			* exists in the hash table for ND IPv6
			*/
			struct nd_entry_data *new_nd_data =
					retrieve_nd_entry(nd_key);

			if (new_nd_data == NULL) {
				printf("Received unsolicited ICMPv6 echo "
				"reply on port %d\n",
						 nd_key.port_id);
				for (i = 0; i < ND_IPV6_ADDR_SIZE; i += 2) {
					printf("%02X%02X ", nd_key.ipv6[i],
								 nd_key.ipv6[i + 1]);
				}
				return;
			}

			new_nd_data->status = COMPLETE;

		} else
		if ((icmpv6_h->icmpv6_type == ICMPV6_NEIGHBOR_SOLICITATION)
			&& (icmpv6_h->icmpv6_code == 0)) {

			icmpv6_nd_h =
					(struct icmpv6_nd_hdr *)((char *)icmpv6_h +
								 sizeof(struct icmpv6_hdr));
			struct ether_addr *src_hw_addr = &eth_h->s_addr;
			uint8_t src_ipv6[16], dst_ipv6[16];

			for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
				src_ipv6[i] = ipv6_h->src_addr[i];
			for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
				dst_ipv6[i] = ipv6_h->dst_addr[i];

			// Check for Multicast Address
			if ((IPV6_MULTICAST
					 && ((dst_ipv6[0] << 8) | dst_ipv6[1]))) {
				if (populate_nd_entry
						(src_hw_addr, src_ipv6, in_port_id)) {

					//build a Neighbor Advertisement message
					for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
						req_tipv6[i] =
								icmpv6_nd_h->target_ipv6[i];

					ether_addr_copy(&eth_h->s_addr,
							&eth_h->d_addr);
					ether_addr_copy((struct ether_addr *)
							&icmpv6_port_addresses
							[in_port_id].mac_addr,
							&eth_h->s_addr);

					// set sender mac address
					ether_addr_copy(&eth_h->s_addr,
							&icmpv6_nd_h->
							link_layer_address);
					for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
						ipv6_h->dst_addr[i] =
								ipv6_h->src_addr[i];
					for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
						ipv6_h->src_addr[i] =
								req_tipv6[i];
					icmpv6_h->icmpv6_type =
							ICMPV6_NEIGHBOR_ADVERTISEMENT;
					icmpv6_nd_h->type =
							e_Target_Link_Layer_Address;
					icmpv6_nd_h->icmpv6_reserved |=
							rte_cpu_to_be_32
							(NEIGHBOR_SOLICITATION_SET);

					rte_pipeline_port_out_packet_insert
							(gp_arp->p.p, out_port, icmpv6_pkt);
					gp_arp->sentPktCount++;
				}
			} else {
				if (ARPICMP_DEBUG) {
					printf("Non-Multicasted Neighbor "
					"Solicitation Message Received, "
					"can't do Address Resolution\n");
					printf("............Some one else "
					"is the target host here !!!\n");
				}
			}

		} else
		if ((icmpv6_h->icmpv6_type == ICMPV6_NEIGHBOR_ADVERTISEMENT)
			&& (icmpv6_h->icmpv6_code == 0)) {
			struct ether_addr *src_hw_addr = &eth_h->s_addr;
			uint8_t ipv6[16];
			for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
				ipv6[i] = ipv6_h->src_addr[i];

			if (populate_nd_entry(src_hw_addr, ipv6, in_port_id))
				if (ARPICMP_DEBUG)
					printf("Now on, unicast IPv6 traffic "
					"is possible\n");
			// Now on, unicast IPv6 traffic is possible
		} else {
			if (ARPICMP_DEBUG) {
				printf("ICMPv6 Type %d Not Supported yet !!!\n",
							 icmpv6_h->icmpv6_type);
			}
		}

	}

}

void request_icmpv6_echo(uint32_t port_id, uint8_t ipv6[])
{
	(void)port_id;
	(void)ipv6;
	int i;

	struct ether_addr gw_addr;
	uint8_t nhipv6[16];
	uint8_t dest_ipv6[16];
	uint32_t phy_port;

	for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
		dest_ipv6[i] = ipv6[i];

	if (get_dest_mac_address_ipv6_port(dest_ipv6, &phy_port,
			&gw_addr, nhipv6)) {
		request_icmpv6_echo_message(phy_port, ipv6, &gw_addr);
		return;
	}

	if (ARPICMP_DEBUG)
		printf("Sending icmpv6 echo request ... get mac failed.\n");
}

void
request_icmpv6_echo_message(uint16_t port_id, uint8_t ipv6[],
					struct ether_addr *gw_addr)
{
	struct ether_hdr *eth_h;
	struct ipv6_hdr *ipv6_h;
	struct icmpv6_hdr *icmpv6_h;
	struct icmpv6_info_hdr *icmpv6_info_h;
	int i;
	struct app_link_params *link;
	link = &mylink[port_id];

	for (i = 0; i < 16; i++)
		icmpv6_port_addresses[port_id].ipv6[i] = link->ipv6[i];

	icmpv6_port_addresses[port_id].mac_addr = link->mac_addr;

	struct rte_mbuf *icmpv6_pkt = lib_icmpv6_pkt;
	if (icmpv6_pkt == NULL) {
		if (ARPICMP_DEBUG)
			printf("Error allocating icmpv6_pkt rte_mbuf\n");
		return;
	}

	eth_h = rte_pktmbuf_mtod(icmpv6_pkt, struct ether_hdr *);
	ether_addr_copy(gw_addr, &eth_h->d_addr);
	ether_addr_copy((struct ether_addr *)&icmpv6_port_addresses[port_id].
			mac_addr, &eth_h->s_addr);
	eth_h->ether_type = CHECK_ENDIAN_16(ETHER_TYPE_IPv6);

	ipv6_h = (struct ipv6_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	icmpv6_h =
			(struct icmpv6_hdr *)((char *)ipv6_h + sizeof(struct ipv6_hdr));
	icmpv6_info_h =
			(struct icmpv6_info_hdr *)((char *)icmpv6_h +
							 sizeof(struct icmpv6_hdr));

	ipv6_h->vtc_flow = 0x60000000;
	ipv6_h->payload_len = 64;
	ipv6_h->proto = 58;
	ipv6_h->hop_limits = 64;

	for (i = 0; i < 16; i++) {
		ipv6_h->src_addr[i] = icmpv6_port_addresses[port_id].ipv6[i];
		ipv6_h->dst_addr[i] = ipv6[i];
	}

	icmpv6_h->icmpv6_type = ICMPV6_ECHO_REQUEST;
	icmpv6_h->icmpv6_code = 0;
	icmpv6_info_h->icmpv6_ident = 0x5151;
	icmpv6_info_h->icmpv6_seq_nb = 0x1;

	icmpv6_h->icmpv6_cksum =
			~rte_raw_cksum(icmpv6_h, sizeof(struct icmpv6_hdr));

	icmpv6_pkt->pkt_len =
			sizeof(struct ether_hdr) + sizeof(struct ipv6_hdr) +
			sizeof(struct icmpv6_hdr);
	icmpv6_pkt->data_len = icmpv6_pkt->pkt_len;

	if (ARPICMP_DEBUG)
		printf("Sending icmpv6 echo request\n");

	rte_pipeline_port_out_packet_insert(gp_arp->p.p,
		gp_arp->outport_id[port_id],
		icmpv6_pkt);

	gp_arp->sentPktCount++;
}


#endif

static void *pipeline_arpicmp_msg_req_custom_handler(struct pipeline *p,
							void *msg);

static pipeline_msg_req_handler handlers[] = {
	[PIPELINE_MSG_REQ_PING] =
		pipeline_msg_req_ping_handler,
	[PIPELINE_MSG_REQ_STATS_PORT_IN] =
		pipeline_msg_req_stats_port_in_handler,
	[PIPELINE_MSG_REQ_STATS_PORT_OUT] =
		pipeline_msg_req_stats_port_out_handler,
	[PIPELINE_MSG_REQ_STATS_TABLE] =
		pipeline_msg_req_stats_table_handler,
	[PIPELINE_MSG_REQ_PORT_IN_ENABLE] =
		pipeline_msg_req_port_in_enable_handler,
	[PIPELINE_MSG_REQ_PORT_IN_DISABLE] =
		pipeline_msg_req_port_in_disable_handler,
	[PIPELINE_MSG_REQ_CUSTOM] =
		pipeline_arpicmp_msg_req_custom_handler,

};

static void *pipeline_arpicmp_msg_req_entry_dbg_handler(struct pipeline *p,
								 void *msg);
static void *pipeline_arpicmp_msg_req_entry_dbg_handler(
	__rte_unused struct pipeline *p,
	__rte_unused void *msg)
{
	/*have to handle dbg commands*/
	return NULL;
}

static __rte_unused pipeline_msg_req_handler custom_handlers[] = {
	[PIPELINE_ARPICMP_MSG_REQ_ENTRY_DBG] =
			pipeline_arpicmp_msg_req_entry_dbg_handler,
};

/**
 * Function for pipeline custom handlers
 *
 * @param pipeline
 *  A void pointer to pipeline
 * @param msg
 *  void pointer for incoming data
 *
 * @return
 *  void pointer of response
 */
void *pipeline_arpicmp_msg_req_custom_handler(struct pipeline *p, void *msg)
{
	struct pipeline_arpicmp *p_arp = (struct pipeline_arpicmp *)p;
	struct pipeline_custom_msg_req *req = msg;
	pipeline_msg_req_handler f_handle;

	f_handle = (req->subtype < PIPELINE_ARPICMP_MSG_REQS) ?
			p_arp->custom_handlers[req->subtype] :
			pipeline_msg_req_invalid_handler;

	if (f_handle == NULL)
		f_handle = pipeline_msg_req_invalid_handler;

	return f_handle(p, req);
}

#ifdef VNF_ACL

/* Not needed as no arguments are needed for TxRX
 * ARP arguments are handled in ARP module
 */
int
pipeline_arpicmp_parse_args(struct pipeline_arpicmp *p,
			 struct pipeline_params *params);
int
pipeline_arpicmp_parse_args(
	__rte_unused struct pipeline_arpicmp *p,
	struct pipeline_params *params)
{

	uint32_t i;
	uint32_t arp_meta_offset_present = 0;

	uint32_t arp_route_tbl_present = 0;
	uint32_t nd_route_tbl_present = 0;
	uint32_t ports_mac_list_present = 0;
	uint32_t pktq_in_prv_present = 0;
	uint32_t prv_to_pub_map_present = 0;

	uint8_t n_prv_in_port = 0;
	for (i = 0; i < PIPELINE_MAX_PORT_IN; i++) {
		in_port_dir_a[i] = 0;	//make all RX ports ingress initially
		prv_to_pub_map[i] = 0xff;
		pub_to_prv_map[i] = 0xff;
	}

	for (i = 0; i < params->n_args; i++) {
		char *arg_name = params->args_name[i];
		char *arg_value = params->args_value[i];

		if (ARPICMP_DEBUG > 2) {
			printf("ARP args[%d]: %s %d, %s\n", i, arg_name,
					atoi(arg_value), arg_value);
		}
		if (strcmp(arg_name, "arp_meta_offset") == 0) {
			if (arp_meta_offset_present) {
				printf("arp_meta_offset "
				"initialized already\n");
				return -1;
			}
			arp_meta_offset_present = 1;
			arp_meta_offset = atoi(arg_value);
			continue;
		}
		/* pktq_in_prv */
		if (strcmp(arg_name, "pktq_in_prv") == 0) {
			if (pktq_in_prv_present) {
				printf("Duplicate pktq_in_prv ... "
				"parse failed..\n\n");
				return -1;
			}
			pktq_in_prv_present = 1;

			int rxport = 0, j = 0;
			char phy_port_num[5];
			char *token = strtok(arg_value, "RXQ");
			while (token) {
				j = 0;
				while ((j < 4) && (token[j] != '.')) {
					phy_port_num[j] = token[j];
					j++;
				}
				phy_port_num[j] = '\0';
				rxport = atoi(phy_port_num);
				printf("token: %s, phy_port_str: %s, "
				"phy_port_num %d\n",
						 token, phy_port_num, rxport);

				prv_in_port_a[n_prv_in_port++] = rxport;
				// set rxport egress
                                if(rxport < PIPELINE_MAX_PORT_IN)
				in_port_dir_a[rxport] = 1;
				token = strtok(NULL, "RXQ");
			}

			if (n_prv_in_port == 0) {
				printf
						("VNF common parse error - "
					"no prv RX phy port\n");
				return -1;
			}
			continue;
		}

		/* prv_to_pub_map */
		if (strcmp(arg_name, "prv_to_pub_map") == 0) {
			if (prv_to_pub_map_present) {
				printf
						("Duplicated prv_to_pub_map ... "
					"parse failed ...\n");
				return -1;
			}
			prv_to_pub_map_present = 1;

			int rxport = 0, txport = 0, j = 0, k = 0;
			char rx_phy_port_num[5];
			char tx_phy_port_num[5];
			char *token = strtok(arg_value, "(");
			while (token) {
				j = 0;
				while ((j < 4) && (token[j] != ',')) {
					rx_phy_port_num[j] = token[j];
					j++;
				}
				rx_phy_port_num[j] = '\0';
				rxport = atoi(rx_phy_port_num);

				j++;
				k = 0;
				while ((k < 4) && (token[j + k] != ')')) {
					tx_phy_port_num[k] = token[j + k];
					k++;
				}
				tx_phy_port_num[k] = '\0';
				txport = atoi(tx_phy_port_num);
				if (rxport < PIPELINE_MAX_PORT_IN && txport < PIPELINE_MAX_PORT_IN){
				printf("token: %s,"
							 "rx_phy_port_str: %s, phy_port_num %d,"
							 "tx_phy_port_str: %s, tx_phy_port_num %d\n",
							 token, rx_phy_port_num, rxport,
							 tx_phy_port_num, txport);
				}
				else
                                       return -1;
				if ((rxport >= PIPELINE_MAX_PORT_IN) ||
						(txport >= PIPELINE_MAX_PORT_IN) ||
						(in_port_dir_a[rxport] != 1)) {
					printf("CG-NAPT parse error - "
					"incorrect prv-pub translation. "
					"Rx %d, Tx %d, Rx Dir %d\n",
					rxport, txport, in_port_dir_a[rxport]);
					return -1;
				}

				prv_to_pub_map[rxport] = txport;
				pub_to_prv_map[txport] = rxport;
				token = strtok(NULL, "(");
			}

			continue;
		}

		/* lib_arp_debug */
		if (strcmp(arg_name, "lib_arp_debug") == 0) {
			ARPICMP_DEBUG = atoi(arg_value);

			continue;
		}

		/* ports_mac_list */
		if (strcmp(arg_name, "ports_mac_list") == 0) {
			ports_mac_list_present = 1;

			uint32_t i = 0, j = 0, k = 0, MAC_NUM_BYTES = 6;

			char byteStr[MAC_NUM_BYTES][3];
			uint32_t byte[MAC_NUM_BYTES];

			char *token = strtok(arg_value, " ");
			while (token) {
				k = 0;
				for (i = 0; i < MAC_NUM_BYTES; i++) {
					for (j = 0; j < 2; j++)
						byteStr[i][j] = token[k++];
					byteStr[i][j] = '\0';
					k++;
				}

				for (i = 0; i < MAC_NUM_BYTES; i++)
					byte[i] = strtoul(byteStr[i], NULL, 16);

				if (ARPICMP_DEBUG) {
					printf("token: %s", token);
					for (i = 0; i < MAC_NUM_BYTES; i++)
						printf(", byte[%u] %u", i,
									 byte[i]);
					printf("\n");
				}
				//Populate the static arp_route_table
				for (i = 0; i < MAC_NUM_BYTES; i++)
					link_hw_addr
							[link_hw_addr_array_idx].addr_bytes
							[i] = byte[i];

				link_hw_addr_array_idx++;
				token = strtok(NULL, " ");
			}

			continue;
		}

		/* arp_route_tbl */
		if (strcmp(arg_name, "arp_route_tbl") == 0) {
			arp_route_tbl_present = 1;

			uint32_t dest_ip = 0, mask = 0, tx_port = 0, nh_ip =
					0, i = 0, j = 0, k = 0, l = 0;
			uint32_t arp_route_tbl_str_max_len = 10;
			char dest_ip_str[arp_route_tbl_str_max_len];
			char mask_str[arp_route_tbl_str_max_len];
			char tx_port_str[arp_route_tbl_str_max_len];
			char nh_ip_str[arp_route_tbl_str_max_len];
			char *token = strtok(arg_value, "(");
			while (token) {
				i = 0;
				while ((i < (arp_route_tbl_str_max_len - 1))
							 && (token[i] != ',')) {
					dest_ip_str[i] = token[i];
					i++;
				}
				dest_ip_str[i] = '\0';
				dest_ip = strtoul(dest_ip_str, NULL, 16);

				i++;
				j = 0;
				while ((j < (arp_route_tbl_str_max_len - 1))
							 && (token[i + j] != ',')) {
					mask_str[j] = token[i + j];
					j++;
				}
				mask_str[j] = '\0';
				mask = strtoul(mask_str, NULL, 16);

				j++;
				k = 0;
				while ((k < (arp_route_tbl_str_max_len - 1))
							 && (token[i + j + k] != ',')) {
					tx_port_str[k] = token[i + j + k];
					k++;
				}
				tx_port_str[k] = '\0';
				//atoi(tx_port_str);
				tx_port = strtoul(tx_port_str, NULL, 16);

				k++;
				l = 0;
				while ((l < (arp_route_tbl_str_max_len - 1))
							 && (token[i + j + k + l] != ')')) {
					nh_ip_str[l] = token[i + j + k + l];
					l++;
				}
				nh_ip_str[l] = '\0';
				//atoi(nh_ip_str);
				nh_ip = strtoul(nh_ip_str, NULL, 16);

				if (ARPICMP_DEBUG) {
					printf("token: %s, "
								 "dest_ip_str: %s, dest_ip %u, "
								 "mask_str: %s, mask %u, "
								 "tx_port_str: %s, tx_port %u, "
								 "nh_ip_str: %s, nh_ip %u\n",
								 token, dest_ip_str, dest_ip,
								 mask_str, mask, tx_port_str,
								 tx_port, nh_ip_str, nh_ip);
				}
				#if 0
				if (tx_port >= params->n_ports_out) {
					printf("ARP-ICMP parse error - "
					"incorrect tx_port %d, max %d\n",
					tx_port, params->n_ports_out);
					return -1;
				}
				#endif

				//Populate the static arp_route_table
				lib_arp_route_table[arp_route_tbl_index].ip =
						dest_ip;
				lib_arp_route_table[arp_route_tbl_index].mask =
						mask;
				lib_arp_route_table[arp_route_tbl_index].port =
						tx_port;
				lib_arp_route_table[arp_route_tbl_index].nh =
						nh_ip;
				arp_route_tbl_index++;
				token = strtok(NULL, "(");
			}

			continue;
		}
		/*ND IPv6 */
		/* nd_route_tbl */
		if (strcmp(arg_name, "nd_route_tbl") == 0) {
			nd_route_tbl_present = 1;

			uint8_t dest_ipv6[16], depth = 0, tx_port =
					0, nh_ipv6[16], i = 0, j = 0, k = 0, l = 0;
			uint8_t nd_route_tbl_str_max_len = 128;	//64;
			char dest_ipv6_str[nd_route_tbl_str_max_len];
			char depth_str[nd_route_tbl_str_max_len];
			char tx_port_str[nd_route_tbl_str_max_len];
			char nh_ipv6_str[nd_route_tbl_str_max_len];
			char *token = strtok(arg_value, "(");
			while (token) {
				i = 0;
				while ((i < (nd_route_tbl_str_max_len - 1))
							 && (token[i] != ',')) {
					dest_ipv6_str[i] = token[i];
					i++;
				}
				dest_ipv6_str[i] = '\0';
				my_inet_pton_ipv6(AF_INET6, dest_ipv6_str,
							&dest_ipv6);

				i++;
				j = 0;
				while ((j < (nd_route_tbl_str_max_len - 1))
							 && (token[i + j] != ',')) {
					depth_str[j] = token[i + j];
					j++;
				}
				depth_str[j] = '\0';
				//converting string char to integer
				int s;
				for (s = 0; depth_str[s] != '\0'; ++s)
					depth = depth * 10 + depth_str[s] - '0';

				j++;
				k = 0;
				while ((k < (nd_route_tbl_str_max_len - 1))
							 && (token[i + j + k] != ',')) {
					tx_port_str[k] = token[i + j + k];
					k++;
				}
				tx_port_str[k] = '\0';
				//atoi(tx_port_str);
				tx_port = strtoul(tx_port_str, NULL, 16);

				k++;
				l = 0;
				while ((l < (nd_route_tbl_str_max_len - 1))
							 && (token[i + j + k + l] != ')')) {
					nh_ipv6_str[l] = token[i + j + k + l];
					l++;
				}
				nh_ipv6_str[l] = '\0';
				my_inet_pton_ipv6(AF_INET6, nh_ipv6_str,
							&nh_ipv6);

				//Populate the static arp_route_table
				for (i = 0; i < 16; i++) {
					lib_nd_route_table
							[nd_route_tbl_index].ipv6[i] =
							dest_ipv6[i];
					lib_nd_route_table
							[nd_route_tbl_index].nhipv6[i] =
							nh_ipv6[i];
				}
				lib_nd_route_table[nd_route_tbl_index].depth =
						depth;
				lib_nd_route_table[nd_route_tbl_index].port =
						tx_port;

				nd_route_tbl_index++;
				token = strtok(NULL, "(");
			} //while

			continue;
		}
		/* any other */

	}

	#if 0
	if (!arp_meta_offset_present) {
		printf("ARPICMP: arp_meta_offset not initialized\n");
		return -1;
	}
	#endif

	if (!arp_route_tbl_present && !nd_route_tbl_present) {
		printf("Neither arp_route_tbl_present nor "
			"nd_route_tbl_present declared\n");
		return -1;
	}

	if (!pktq_in_prv_present) {
		printf("pktq_in_prv not declared\n");
		return -1;
	}

	if (!ports_mac_list_present) {
		printf("ports_mac_list not declared\n");
		return -1;
	}

	return 0;
}

#endif

uint32_t arpicmp_pkt_print_count;
static inline void
pkt_key_arpicmp(struct rte_mbuf *pkt, uint32_t pkt_num, void *arg)
{

	struct pipeline_arpicmp_in_port_h_arg *ap = arg;
	struct pipeline_arpicmp *p_arp = (struct pipeline_arpicmp *)ap->p;

	p_arp->receivedPktCount++;

	uint8_t in_port_id = pkt->port;
	#ifdef VNF_ACL
	struct app_link_params *link;
	#endif
	uint8_t *protocol;
	uint32_t pkt_mask = 1 << pkt_num;
	uint32_t eth_proto_offset = MBUF_HDR_ROOM + 12;

	uint32_t prot_offset =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_PROTOCOL_OFST;

	#ifdef VNF_ACL
	uint32_t out_port;
	#endif

	uint16_t *eth_proto =
		RTE_MBUF_METADATA_UINT16_PTR(pkt, eth_proto_offset);

	/* header room + eth hdr size + src_aadr offset in ip header */
	#ifdef VNF_ACL
	uint32_t dst_addr_offset =
		MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST;
	uint32_t *dst_addr = RTE_MBUF_METADATA_UINT32_PTR(pkt, dst_addr_offset);
	#endif

	#ifdef IPV6
	 uint32_t prot_offset_ipv6 =
			 MBUF_HDR_ROOM + ETH_HDR_SIZE + IPV6_HDR_PROTOCOL_OFST;

	if (rte_be_to_cpu_16(*eth_proto) == ETHER_TYPE_IPv6)
		protocol = RTE_MBUF_METADATA_UINT8_PTR(pkt, prot_offset_ipv6);
	else
		protocol = RTE_MBUF_METADATA_UINT8_PTR(pkt, prot_offset);
	#else
	protocol = RTE_MBUF_METADATA_UINT8_PTR(pkt, prot_offset);
	#endif


	if ((ARPICMP_DEBUG > 2) && (arpicmp_pkt_print_count < 10)) {
		print_pkt1(pkt);
		arpicmp_pkt_print_count++;
		printf("\nEth Typ %x, Prot %x, ETH_TYPE_ARP %x, "
			"ETH_TYPE_IPV4 %x, IP_PROTOCOL_ICMP %x\n",
				 rte_be_to_cpu_16(*eth_proto), *protocol, ETH_TYPE_ARP,
				 ETH_TYPE_IPV4, IP_PROTOCOL_ICMP);
	}

	#ifdef VNF_ACL
	link = &myApp->link_params[in_port_id];
	#endif

	/* Classifier for ICMP pass-through*/
	if ((rte_be_to_cpu_16(*eth_proto) == ETH_TYPE_ARP) ||
			((rte_be_to_cpu_16(*eth_proto) == ETH_TYPE_IPV4)
			 && (*protocol == IP_PROTOCOL_ICMP)
		#ifdef VNF_ACL
		&& (link->ip == rte_be_to_cpu_32(*dst_addr))
		#endif
		)) {

		#ifdef VNF_ACL
		out_port = p_arp->outport_id[in_port_id];
		process_arpicmp_pkt(pkt, out_port, pkt_mask);
		#else
		process_arpicmp_pkt(pkt, ifm_get_port(in_port_id));
		#endif
		return;
	}
	#ifdef IPV6
	else if ((rte_be_to_cpu_16(*eth_proto) == ETH_TYPE_IPV6)
		&& (*protocol == ICMPV6_PROTOCOL_ID)) {
		#ifdef VNF_ACL
		out_port = p_arp->outport_id[in_port_id];
		process_icmpv6_pkt(pkt, out_port, pkt_mask);
		#else
		process_icmpv6_pkt(pkt, ifm_get_port(in_port_id));
		#endif

		return;
	}
	#endif

	/* Drop the pkt if not ARP/ICMP */
	rte_pipeline_ah_packet_drop(p_arp->p.p, pkt_mask);
	p_arp->droppedPktCount++;

}

static inline void
pkt4_key_arpicmp(struct rte_mbuf **pkt, uint32_t pkt_num, void *arg)
{

	struct pipeline_arpicmp_in_port_h_arg *ap = arg;
	struct pipeline_arpicmp *p_arp = (struct pipeline_arpicmp *)ap->p;

	p_arp->receivedPktCount += 4;

	uint32_t eth_proto_offset = MBUF_HDR_ROOM + 12;
	uint8_t in_port_id = pkt[0]->port;

	uint32_t prot_offset =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_PROTOCOL_OFST;

	/* header room + eth hdr size + src_aadr offset in ip header */
	#ifdef VNF_ACL
	uint32_t dst_addr_offset =
		MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST;
	#endif

	uint32_t pkt_mask0 = 1 << pkt_num;
	uint32_t pkt_mask1 = 1 << (pkt_num + 1);
	uint32_t pkt_mask2 = 1 << (pkt_num + 2);
	uint32_t pkt_mask3 = 1 << (pkt_num + 3);

	#ifdef VNF_ACL
	uint32_t out_port0;
	uint32_t out_port1;
	uint32_t out_port2;
	uint32_t out_port3;
	#endif

	uint16_t *eth_proto0 =
		RTE_MBUF_METADATA_UINT16_PTR(pkt[0], eth_proto_offset);
	uint16_t *eth_proto1 =
		RTE_MBUF_METADATA_UINT16_PTR(pkt[1], eth_proto_offset);
	uint16_t *eth_proto2 =
		RTE_MBUF_METADATA_UINT16_PTR(pkt[2], eth_proto_offset);
	uint16_t *eth_proto3 =
		RTE_MBUF_METADATA_UINT16_PTR(pkt[3], eth_proto_offset);

	uint8_t *protocol0;
	uint8_t *protocol1;
	uint8_t *protocol2;
	uint8_t *protocol3;

	#ifdef VNF_ACL
	uint32_t *dst_addr0 =
			RTE_MBUF_METADATA_UINT32_PTR(pkt[0], dst_addr_offset);
	uint32_t *dst_addr1 =
			RTE_MBUF_METADATA_UINT32_PTR(pkt[1], dst_addr_offset);
	uint32_t *dst_addr2 =
			RTE_MBUF_METADATA_UINT32_PTR(pkt[2], dst_addr_offset);
	uint32_t *dst_addr3 =
			RTE_MBUF_METADATA_UINT32_PTR(pkt[3], dst_addr_offset);

	struct app_link_params *link0;
	struct app_link_params *link1;
	struct app_link_params *link2;
	struct app_link_params *link3;

	link0 = &myApp->link_params[pkt[0]->port];
	link1 = &myApp->link_params[pkt[1]->port];
	link2 = &myApp->link_params[pkt[2]->port];
	link3 = &myApp->link_params[pkt[3]->port];
	#endif

	#ifdef IPV6
	uint32_t prot_offset_ipv6 =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IPV6_HDR_PROTOCOL_OFST;

	#endif

	#ifdef IPV6
/* --0-- */
	if (rte_be_to_cpu_16(*eth_proto0) == ETHER_TYPE_IPv6)
		protocol0 =
				RTE_MBUF_METADATA_UINT8_PTR(pkt[0], prot_offset_ipv6);
	else
		protocol0 = RTE_MBUF_METADATA_UINT8_PTR(pkt[0], prot_offset);

/* --1-- */
	if (rte_be_to_cpu_16(*eth_proto1) == ETHER_TYPE_IPv6)
		protocol1 =
				RTE_MBUF_METADATA_UINT8_PTR(pkt[1], prot_offset_ipv6);
	else
		protocol1 = RTE_MBUF_METADATA_UINT8_PTR(pkt[1], prot_offset);

/* --2-- */
	if (rte_be_to_cpu_16(*eth_proto2) == ETHER_TYPE_IPv6)
		protocol2 =
				RTE_MBUF_METADATA_UINT8_PTR(pkt[2], prot_offset_ipv6);
	else
		protocol2 = RTE_MBUF_METADATA_UINT8_PTR(pkt[2], prot_offset);

/* --3-- */
	if (rte_be_to_cpu_16(*eth_proto3) == ETHER_TYPE_IPv6)
		protocol3 =
				RTE_MBUF_METADATA_UINT8_PTR(pkt[3], prot_offset_ipv6);
	else
		protocol3 = RTE_MBUF_METADATA_UINT8_PTR(pkt[3], prot_offset);
	#else
	protocol0 = RTE_MBUF_METADATA_UINT8_PTR(pkt[0], prot_offset);
	protocol1 = RTE_MBUF_METADATA_UINT8_PTR(pkt[1], prot_offset);
	protocol2 = RTE_MBUF_METADATA_UINT8_PTR(pkt[2], prot_offset);
	protocol3 = RTE_MBUF_METADATA_UINT8_PTR(pkt[3], prot_offset);
	#endif

	if ((ARPICMP_DEBUG > 2) && (arpicmp_pkt_print_count < 10)) {
		print_pkt1(pkt[0]);
		arpicmp_pkt_print_count++;
		printf("\nEth Typ %x, Prot %x, ETH_TYPE_ARP %x, "
			"ETH_TYPE_IPV4 %x, IP_PROTOCOL_ICMP %x\n",
				 rte_be_to_cpu_16(*eth_proto0), *protocol0, ETH_TYPE_ARP,
				 ETH_TYPE_IPV4, IP_PROTOCOL_ICMP);
	}


	if ((rte_be_to_cpu_16(*eth_proto0) == ETH_TYPE_ARP) ||
			((rte_be_to_cpu_16(*eth_proto0) == ETH_TYPE_IPV4)
			 && (*protocol0 == IP_PROTOCOL_ICMP)
		#ifdef VNF_ACL
				&& (link0->ip == rte_be_to_cpu_32(*dst_addr0))
		#endif
		)) {

		#ifdef VNF_ACL
		out_port0 = p_arp->outport_id[pkt[0]->port];
		process_arpicmp_pkt(pkt[0], out_port0, pkt_mask0);
		#else
		process_arpicmp_pkt(pkt[0], ifm_get_port(in_port_id));
		#endif

		goto PKT1;
	}
	#ifdef IPV6
	else if ((rte_be_to_cpu_16(*eth_proto0) == ETH_TYPE_IPV6)
			 && (*protocol0 == ICMPV6_PROTOCOL_ID)) {

		#ifdef VNF_ACL
		out_port0 = p_arp->outport_id[pkt[0]->port];
		process_icmpv6_pkt(pkt[0], out_port0, pkt_mask0);
		#else
		process_icmpv6_pkt(pkt[0], ifm_get_port(in_port_id));
		#endif

		goto PKT1;
	}
	#endif

	/* Drop the pkt if not ARP/ICMP */
	rte_pipeline_ah_packet_drop(p_arp->p.p, pkt_mask0);
	p_arp->droppedPktCount++;

PKT1:
	if ((ARPICMP_DEBUG > 2) && (arpicmp_pkt_print_count < 10)) {
		print_pkt1(pkt[1]);
		arpicmp_pkt_print_count++;
		printf("\nEth Typ %x, Prot %x, ETH_TYPE_ARP %x, "
			"ETH_TYPE_IPV4 %x, IP_PROTOCOL_ICMP %x\n",
				 rte_be_to_cpu_16(*eth_proto1), *protocol1, ETH_TYPE_ARP,
				 ETH_TYPE_IPV4, IP_PROTOCOL_ICMP);
	}

	if ((rte_be_to_cpu_16(*eth_proto1) == ETH_TYPE_ARP) ||
			((rte_be_to_cpu_16(*eth_proto1) == ETH_TYPE_IPV4)
			 && (*protocol1 == IP_PROTOCOL_ICMP)
		#ifdef VNF_ACL
				&& (link1->ip == rte_be_to_cpu_32(*dst_addr1))
		#endif
		)) {

		#ifdef VNF_ACL
		out_port1 = p_arp->outport_id[pkt[1]->port];
		process_arpicmp_pkt(pkt[1], out_port1, pkt_mask1);
		#else
		process_arpicmp_pkt(pkt[1], ifm_get_port(in_port_id));
		#endif
		goto PKT2;
	}
	#ifdef IPV6
	else if ((rte_be_to_cpu_16(*eth_proto1) == ETH_TYPE_IPV6)
		&& (*protocol1 == ICMPV6_PROTOCOL_ID)) {

		#ifdef VNF_ACL
		out_port1 = p_arp->outport_id[pkt[1]->port];
		process_icmpv6_pkt(pkt[1], out_port1, pkt_mask1);
		#else
		process_icmpv6_pkt(pkt[1], ifm_get_port(in_port_id));
		#endif

		goto PKT2;
	}
	#endif

	/* Drop the pkt if not ARP/ICMP */
	rte_pipeline_ah_packet_drop(p_arp->p.p, pkt_mask1);
	p_arp->droppedPktCount++;

PKT2:
	if ((ARPICMP_DEBUG > 2) && (arpicmp_pkt_print_count < 10)) {
		print_pkt1(pkt[2]);
		arpicmp_pkt_print_count++;
		printf("\nEth Typ %x, Prot %x, ETH_TYPE_ARP %x, "
			"ETH_TYPE_IPV4 %x, IP_PROTOCOL_ICMP %x\n",
				 rte_be_to_cpu_16(*eth_proto2), *protocol2, ETH_TYPE_ARP,
				 ETH_TYPE_IPV4, IP_PROTOCOL_ICMP);
	}

	if ((rte_be_to_cpu_16(*eth_proto2) == ETH_TYPE_ARP) ||
			((rte_be_to_cpu_16(*eth_proto2) == ETH_TYPE_IPV4)
			 && (*protocol2 == IP_PROTOCOL_ICMP)
		#ifdef VNF_ACL
				&& (link2->ip == rte_be_to_cpu_32(*dst_addr2))
		#endif
		)) {

		#ifdef VNF_ACL
		out_port2 = p_arp->outport_id[pkt[2]->port];
		process_arpicmp_pkt(pkt[2], out_port2, pkt_mask2);
		#else
		process_arpicmp_pkt(pkt[2], ifm_get_port(in_port_id));
		#endif

		goto PKT3;
	}
	#ifdef IPV6
	else if ((rte_be_to_cpu_16(*eth_proto2) == ETH_TYPE_IPV6)
		&& (*protocol2 == ICMPV6_PROTOCOL_ID)) {

		#ifdef VNF_ACL
		out_port2 = p_arp->outport_id[pkt[2]->port];
		process_icmpv6_pkt(pkt[2], out_port2, pkt_mask2);
		#else
		process_icmpv6_pkt(pkt[2], ifm_get_port(in_port_id));
		#endif

		goto PKT3;
	}
	#endif

	/* Drop the pkt if not ARP/ICMP */
	rte_pipeline_ah_packet_drop(p_arp->p.p, pkt_mask2);
	p_arp->droppedPktCount++;

PKT3:
	if ((ARPICMP_DEBUG > 2) && (arpicmp_pkt_print_count < 10)) {
		print_pkt1(pkt[3]);
		arpicmp_pkt_print_count++;
		printf("\nEth Typ %x, Prot %x, ETH_TYPE_ARP %x, "
			"ETH_TYPE_IPV4 %x, IP_PROTOCOL_ICMP %x\n",
				 rte_be_to_cpu_16(*eth_proto3), *protocol3, ETH_TYPE_ARP,
				 ETH_TYPE_IPV4, IP_PROTOCOL_ICMP);
	}

	if ((rte_be_to_cpu_16(*eth_proto3) == ETH_TYPE_ARP) ||
			((rte_be_to_cpu_16(*eth_proto3) == ETH_TYPE_IPV4)
			 && (*protocol3 == IP_PROTOCOL_ICMP)

		#ifdef VNF_ACL
		&& (link3->ip == rte_be_to_cpu_32(*dst_addr3))
		#endif
		)) {

		#ifdef VNF_ACL
		out_port3 = p_arp->outport_id[pkt[3]->port];
		process_arpicmp_pkt(pkt[3], out_port3, pkt_mask3);
		#else
		process_arpicmp_pkt(pkt[3], ifm_get_port(in_port_id));
		#endif

		return;
	}
	#ifdef IPV6
	else if ((rte_be_to_cpu_16(*eth_proto3) == ETH_TYPE_IPV6)
		&& (*protocol3 == ICMPV6_PROTOCOL_ID)) {

		#ifdef VNF_ACL
		out_port3 = p_arp->outport_id[pkt[3]->port];
		process_icmpv6_pkt(pkt[3], out_port3, pkt_mask3);
		#else
		process_icmpv6_pkt(pkt[3], ifm_get_port(in_port_id));
		#endif
		return;
	}
	#endif

	/* Drop the pkt if not ARP/ICMP */
	rte_pipeline_ah_packet_drop(p_arp->p.p, pkt_mask3);
	p_arp->droppedPktCount++;


}

PIPELINE_ARPICMP_KEY_PORT_IN_AH(
	port_in_ah_arpicmp,
	pkt_key_arpicmp,
	pkt4_key_arpicmp);

static void *pipeline_arpicmp_init(struct pipeline_params *params,
				__rte_unused void *arg)
{
	struct pipeline *p;
	struct pipeline_arpicmp *p_arp;
	uint32_t size, i, in_ports_arg_size;

	printf("Start pipeline_arpicmp_init\n");

	/* Check input arguments */
	if ((params == NULL) ||
			(params->n_ports_in == 0) ||
			(params->n_ports_out == 0))
		return NULL;

	/* Memory allocation */
	size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct pipeline_arpicmp));
	p = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
	p_arp = (struct pipeline_arpicmp *)p;
	if (p == NULL)
		return NULL;

	//gp_arp = p_arp;
	struct app_params *app = (struct app_params *)arg;
	myApp = arg;

	PLOG(p, HIGH, "ARPICMP");
	strcpy(p->name, params->name);
	p->log_level = params->log_level;

	p_arp->receivedPktCount = 0;
	p_arp->droppedPktCount = 0;

#ifdef VNF_ACL
	for (i = 0; i < PIPELINE_MAX_PORT_IN; i++)
		p_arp->links_map[i] = 0xff;

	p_arp->pipeline_num = 0;

	/* Parse arguments */
	if (pipeline_arpicmp_parse_args(p_arp, params))
		return NULL;
#endif
	#ifndef VNF_ACL
	lib_arp_init(params, app);
	#endif

	/* Pipeline */
	{
		struct rte_pipeline_params pipeline_params = {
			.name = "ARPICMP",
			.socket_id = params->socket_id,
			.offset_port_id = 0,
			//.offset_port_id = arp_meta_offset,
		};

		p->p = rte_pipeline_create(&pipeline_params);
		if (p->p == NULL) {
			rte_free(p);
			return NULL;
		}
	}

	p->n_ports_in = params->n_ports_in;
	p->n_ports_out = params->n_ports_out;
	p->n_tables = 1;

	/* Memory allocation for in_port_h_arg */
	in_ports_arg_size = RTE_CACHE_LINE_ROUNDUP(
		(sizeof(struct pipeline_arpicmp_in_port_h_arg)) *
				(params->n_ports_in));
	struct pipeline_arpicmp_in_port_h_arg *ap =
		(struct pipeline_arpicmp_in_port_h_arg *)rte_zmalloc(NULL,
				in_ports_arg_size,
				RTE_CACHE_LINE_SIZE);
	if (ap == NULL)
		return NULL;

	/*Input ports */
	for (i = 0; i < p->n_ports_in; i++) {
		/* passing our txrx pipeline in call back arg */
		(ap[i]).p = p_arp;
		(ap[i]).in_port_id = i;
		struct rte_pipeline_port_in_params port_params = {
			.ops =
					pipeline_port_in_params_get_ops(&params->
									port_in[i]),
			.arg_create =
					pipeline_port_in_params_convert(&params->
									port_in[i]),
			.f_action = NULL,
			.arg_ah = &(ap[i]),
			.burst_size = params->port_in[i].burst_size,
		};

			port_params.f_action = port_in_ah_arpicmp;

		int status = rte_pipeline_port_in_create(p->p,
							 &port_params,
							 &p->port_in_id[i]);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}
	}

	/* Output ports */
	for (i = 0; i < p->n_ports_out; i++) {
		struct rte_pipeline_port_out_params port_params = {
			.ops =
					pipeline_port_out_params_get_ops(&params->
									 port_out[i]),
			.arg_create =
					pipeline_port_out_params_convert(&params->
									 port_out[i]),
			.f_action = NULL,
			.arg_ah = NULL,
		};

		int status = rte_pipeline_port_out_create(p->p,
								&port_params,
								&p->port_out_id[i]);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}
	}
	int pipeline_num = 0;

	int status = sscanf(params->name, "PIPELINE%d", &pipeline_num);

	if (status < 0) {
		return NULL;
		printf("Unable to read pipeline number\n");
	}

	p_arp->pipeline_num = (uint8_t) pipeline_num;

	register_pipeline_Qs(p_arp->pipeline_num, p);
	set_phy_outport_id(p_arp->pipeline_num, p, p_arp->outport_id);

	/* Tables */
	{
		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_stub_ops,
			.arg_create = NULL,
			.f_action_hit = NULL,
			.f_action_miss = NULL,
			.arg_ah = NULL,
			.action_data_size = 0,
		};

		int status = rte_pipeline_table_create(p->p,
									 &table_params,
									 &p->table_id[0]);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}
	}

	/* Connecting input ports to tables */
	for (i = 0; i < p->n_ports_in; i++) {

		int status = rte_pipeline_port_in_connect_to_table(p->p,
									 p->
									 port_in_id
									 [i],
									 p->
									 table_id[0]);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}

	}

	/* Enable input ports */
	for (i = 0; i < p->n_ports_in; i++) {
		int status = rte_pipeline_port_in_enable(p->p,
							 p->port_in_id[i]);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}
	}

	/* Check pipeline consistency */
	if (rte_pipeline_check(p->p) < 0) {
		rte_pipeline_free(p->p);
		rte_free(p);
		return NULL;
	}

	/* Message queues */
	p->n_msgq = params->n_msgq;
	for (i = 0; i < p->n_msgq; i++)
		p->msgq_in[i] = params->msgq_in[i];
	for (i = 0; i < p->n_msgq; i++)
		p->msgq_out[i] = params->msgq_out[i];

	/* Message handlers */
	memcpy(p->handlers, handlers, sizeof(p->handlers));

#ifdef VNF_ACL

	/* create the arpicmp mbuf rx pool */
	lib_arp_pktmbuf_tx_pool = rte_pktmbuf_pool_create(
				"lib_arp_mbuf_tx_pool",
				NB_ARPICMP_MBUF, 32,
				0, RTE_MBUF_DEFAULT_BUF_SIZE,
				app_get_socket_id());

	if (lib_arp_pktmbuf_tx_pool == NULL) {
		printf("ARP mbuf pool create failed.\n");
		return NULL;
	}

	lib_arp_pkt = rte_pktmbuf_alloc(lib_arp_pktmbuf_tx_pool);
	if (lib_arp_pkt == NULL) {
		printf("ARP lib_arp_pkt alloc failed.\n");
		return NULL;
	}

	/* ARP Table */
	arp_hash_params.socket_id = app_get_socket_id();
	arp_hash_params.entries = MAX_NUM_ARP_ENTRIES;
	arp_hash_handle = rte_hash_create(&arp_hash_params);

	if (arp_hash_handle == NULL) {
		printf("ARP rte_hash_create failed. socket %d ...\n",
					 arp_hash_params.socket_id);
		return NULL;
	}
	printf("arp_hash_handle %p\n\n", (void *)arp_hash_handle);

	/* ND IPv6 */
	nd_hash_params.socket_id = app_get_socket_id();
	nd_hash_params.entries = MAX_NUM_ND_ENTRIES;
	nd_hash_handle = rte_hash_create(&nd_hash_params);

	if (nd_hash_handle == NULL) {
		printf("ND rte_hash_create failed. socket %d ...\n",
					 nd_hash_params.socket_id);
		return NULL;
	}

	printf("nd_hash_handle %p\n\n", (void *)nd_hash_handle);
#endif
	return p;
}

static int pipeline_arpicmp_free(void *pipeline)
{
	struct pipeline *p = (struct pipeline *)pipeline;

	/* Check input arguments */
	if (p == NULL)
		return -1;

	/* Free resources */
	rte_pipeline_free(p->p);
	rte_free(p);
	return 0;
}

static int pipeline_arpicmp_timer(void *pipeline)
{
	struct pipeline *p = (struct pipeline *)pipeline;

	pipeline_msg_req_handle(p);
	rte_pipeline_flush(p->p);

	return 0;
}

static int
pipeline_arpicmp_track(void *pipeline, uint32_t port_in, uint32_t *port_out)
{
	struct pipeline *p = (struct pipeline *)pipeline;

	/* Check input arguments */
	if ((p == NULL) || (port_in >= p->n_ports_in) || (port_out == NULL))
		return -1;

	*port_out = port_in / p->n_ports_in;
	return 0;
}

struct pipeline_be_ops pipeline_arpicmp_be_ops = {
	.f_init = pipeline_arpicmp_init,
	.f_free = pipeline_arpicmp_free,
	.f_run = NULL,
	.f_timer = pipeline_arpicmp_timer,
	.f_track = pipeline_arpicmp_track,
};
