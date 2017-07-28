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
#include "lib_arp.h"
#include "lib_icmpv6.h"
#include "interface.h"
#include "gateway.h"

/* Shared among all VNFs including LB */
struct app_params *myApp;
struct rte_pipeline *myP;
struct pipeline_arpicmp *gp_arp;
uint8_t num_vnf_threads;

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

uint32_t arpicmp_pkt_print_count;
static inline void
pkt_key_arpicmp(struct rte_mbuf *pkt, uint32_t pkt_num, void *arg)
{

	struct pipeline_arpicmp_in_port_h_arg *ap = arg;
	struct pipeline_arpicmp *p_arp = (struct pipeline_arpicmp *)ap->p;

	p_arp->receivedPktCount++;

	uint8_t in_port_id = pkt->port;
	uint8_t *protocol;
	uint32_t pkt_mask = 1 << pkt_num;
	uint32_t eth_proto_offset = MBUF_HDR_ROOM + 12;

	uint32_t prot_offset =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_PROTOCOL_OFST;

	uint16_t *eth_proto =
		RTE_MBUF_METADATA_UINT16_PTR(pkt, eth_proto_offset);

	/* header room + eth hdr size + src_aadr offset in ip header */
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

	/* Classifier for ICMP pass-through*/
	if ((rte_be_to_cpu_16(*eth_proto) == ETH_TYPE_ARP) ||
			((rte_be_to_cpu_16(*eth_proto) == ETH_TYPE_IPV4)
			 && (*protocol == IP_PROTOCOL_ICMP)
		)) {
		process_arpicmp_pkt(pkt, ifm_get_port(in_port_id));
		return;
	}
	#ifdef IPV6
	else if ((rte_be_to_cpu_16(*eth_proto) == ETH_TYPE_IPV6)
		&& (*protocol == ICMPV6_PROTOCOL_ID)) {
		process_icmpv6_pkt(pkt, ifm_get_port(in_port_id));
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
	uint32_t pkt_mask0 = 1 << pkt_num;
	uint32_t pkt_mask1 = 1 << (pkt_num + 1);
	uint32_t pkt_mask2 = 1 << (pkt_num + 2);
	uint32_t pkt_mask3 = 1 << (pkt_num + 3);

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
		)) {
		process_arpicmp_pkt(pkt[0], ifm_get_port(in_port_id));

		goto PKT1;
	}
	#ifdef IPV6
	else if ((rte_be_to_cpu_16(*eth_proto0) == ETH_TYPE_IPV6)
			 && (*protocol0 == ICMPV6_PROTOCOL_ID)) {
		process_icmpv6_pkt(pkt[0], ifm_get_port(in_port_id));

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
		)) {
		process_arpicmp_pkt(pkt[1], ifm_get_port(in_port_id));
		goto PKT2;
	}
	#ifdef IPV6
	else if ((rte_be_to_cpu_16(*eth_proto1) == ETH_TYPE_IPV6)
		&& (*protocol1 == ICMPV6_PROTOCOL_ID)) {
		process_icmpv6_pkt(pkt[1], ifm_get_port(in_port_id));

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
		)) {
		process_arpicmp_pkt(pkt[2], ifm_get_port(in_port_id));
		goto PKT3;
	}
	#ifdef IPV6
	else if ((rte_be_to_cpu_16(*eth_proto2) == ETH_TYPE_IPV6)
		&& (*protocol2 == ICMPV6_PROTOCOL_ID)) {
		process_icmpv6_pkt(pkt[2], ifm_get_port(in_port_id));

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
		)) {

		process_arpicmp_pkt(pkt[3], ifm_get_port(in_port_id));

		return;
	}
	#ifdef IPV6
	else if ((rte_be_to_cpu_16(*eth_proto3) == ETH_TYPE_IPV6)
		&& (*protocol3 == ICMPV6_PROTOCOL_ID)) {

		process_icmpv6_pkt(pkt[3], ifm_get_port(in_port_id));
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
	gw_init();
	lib_arp_init(params, app);

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
