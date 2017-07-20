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

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_byteorder.h>
#include <rte_table_stub.h>
#include <rte_table_hash.h>
#include <rte_pipeline.h>

#include "pipeline_txrx_be.h"
#include "pipeline_actions_common.h"
#include "parser.h"
#include "hash_func.h"
#include "pipeline_arpicmp_be.h"
#include "vnf_common.h"
#include "app.h"
#include "lib_icmpv6.h"

uint8_t TXRX_DEBUG;
int pkt_burst_cnt;


struct pipeline_txrx {
	struct pipeline p;
	pipeline_msg_req_handler
		custom_handlers[PIPELINE_TXRX_MSG_REQS];
	uint64_t receivedPktCount;
	uint64_t droppedPktCount;
	uint8_t links_map[PIPELINE_MAX_PORT_IN];
	uint8_t outport_id[PIPELINE_MAX_PORT_IN];
	uint8_t pipeline_num;
	uint8_t txrx_type;
} __rte_cache_aligned;

enum{
TYPE_TXTX,
TYPE_RXRX,
};
static void *pipeline_txrx_msg_req_custom_handler(struct pipeline *p,
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
		pipeline_txrx_msg_req_custom_handler,

};

static void *pipeline_txrx_msg_req_entry_dbg_handler(struct pipeline *p,
								 void *msg);
static void *pipeline_txrx_msg_req_entry_dbg_handler(
	__rte_unused struct pipeline *p,
	__rte_unused void *msg)
{
	/*have to handle dbg commands*/
	return NULL;
}

static __rte_unused pipeline_msg_req_handler custom_handlers[] = {
	[PIPELINE_TXRX_MSG_REQ_ENTRY_DBG] =
			pipeline_txrx_msg_req_entry_dbg_handler,
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
void *pipeline_txrx_msg_req_custom_handler(struct pipeline *p, void *msg)
{
	struct pipeline_txrx *p_txrx = (struct pipeline_txrx *)p;
	struct pipeline_custom_msg_req *req = msg;
	pipeline_msg_req_handler f_handle;

	f_handle = (req->subtype < PIPELINE_TXRX_MSG_REQS) ?
			p_txrx->custom_handlers[req->subtype] :
			pipeline_msg_req_invalid_handler;

	if (f_handle == NULL)
		f_handle = pipeline_msg_req_invalid_handler;

	return f_handle(p, req);
}

/* Not needed as no arguments are needed for TxRX
 * ARP arguments are handled in ARP module
 */
int
pipeline_txrx_parse_args(struct pipeline_txrx *p,
			 struct pipeline_params *params);
int
pipeline_txrx_parse_args(struct pipeline_txrx *p,
			 struct pipeline_params *params)
{
	uint32_t i;
	uint8_t txrx_type_present = 0;

	if (TXRX_DEBUG > 2)
		printf("TXRX pipeline_txrx_parse_args params->n_args: %d\n",
			params->n_args);

	for (i = 0; i < params->n_args; i++) {
		char *arg_name = params->args_name[i];
		char *arg_value = params->args_value[i];

		if (TXRX_DEBUG > 2)
			printf("TXRX args[%d]: %s %d, %s\n", i, arg_name,
				atoi(arg_value), arg_value);

		 /* txrx_type = val */
		if (strcmp(arg_name, "pipeline_txrx_type") == 0) {
			if (txrx_type_present)
				return -1;
			 txrx_type_present = 1;


			if (strcmp(arg_value, "TXTX") == 0) {
				p->txrx_type = TYPE_TXTX;
				printf("pipeline_txrx_type is TXTX\n");
			}
			if (strcmp(arg_value, "RXRX") == 0) {
				p->txrx_type = TYPE_RXRX;
				printf("pipeline_txrx_type is RXRX\n");
			}
			continue;
		}
	}

	if (!txrx_type_present) {
		printf("TXRX type not specified\n");
		return -1;
	}

	return 0;

}

uint32_t txrx_pkt_print_count;
static inline void
pkt_work_txrx(struct rte_mbuf *pkt, uint32_t pkt_num, void *arg)
{

	struct pipeline_txrx_in_port_h_arg *ap = arg;
	struct pipeline_txrx *p_txrx = (struct pipeline_txrx *)ap->p;
	uint8_t solicited_node_multicast_addr[16] =
					{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00};

	p_txrx->receivedPktCount++;

	if (p_txrx->txrx_type == TYPE_TXTX)
		return;

	uint8_t in_port_id = pkt->port;
	uint32_t eth_proto_offset = MBUF_HDR_ROOM + 12;

	uint32_t pkt_mask = 1 << pkt_num;
	/* ARP outport number */
	uint32_t out_port = p_txrx->p.n_ports_out - 1;

	uint16_t *eth_proto =
			RTE_MBUF_METADATA_UINT16_PTR(pkt, eth_proto_offset);

	uint8_t *protocol;
	uint32_t prot_offset =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_PROTOCOL_OFST;

	#ifdef IPV6
	struct ipv6_hdr *ipv6_h;
	ipv6_h = rte_pktmbuf_mtod_offset (pkt, struct ipv6_hdr *, sizeof(struct ether_hdr));
	uint32_t prot_offset_ipv6 =
			 MBUF_HDR_ROOM + ETH_HDR_SIZE + IPV6_HDR_PROTOCOL_OFST;

	if (rte_be_to_cpu_16(*eth_proto) == ETHER_TYPE_IPv6)
		protocol = RTE_MBUF_METADATA_UINT8_PTR(pkt, prot_offset_ipv6);
	else
		protocol = RTE_MBUF_METADATA_UINT8_PTR(pkt, prot_offset);
	#else
	protocol = RTE_MBUF_METADATA_UINT8_PTR(pkt, prot_offset);
	#endif


	if ((TXRX_DEBUG > 2) && (txrx_pkt_print_count < 10)) {
		print_pkt1(pkt);
		txrx_pkt_print_count++;
		printf("\nEth Typ %x, Prot %x, ETH_TYPE_ARP %x, "
			"ETH_TYPE_IPV4 %x, IP_PROTOCOL_ICMP %x\n",
				 rte_be_to_cpu_16(*eth_proto), *protocol, ETH_TYPE_ARP,
				 ETH_TYPE_IPV4, IP_PROTOCOL_ICMP);
	}
	/* Classifier for ICMP pass-through*/
	struct app_link_params *link;

	link = &myApp->link_params[in_port_id];

	/* header room + eth hdr size + src_aadr offset in ip header */
	uint32_t dst_addr_offset =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST;
	uint32_t *dst_addr = RTE_MBUF_METADATA_UINT32_PTR(pkt, dst_addr_offset);

	if (TXRX_DEBUG > 2)
		if (rte_be_to_cpu_16(*eth_proto) == ETH_TYPE_IPV4)
			printf ("%s: linkIp: %x, dst_addr: %x\n", __FUNCTION__, link->ip, *dst_addr);

	#if 1
	switch (rte_be_to_cpu_16(*eth_proto)) {
	case ETH_TYPE_ARP:
		rte_pipeline_port_out_packet_insert(p_txrx->p.p,
			out_port, pkt);
		rte_pipeline_ah_packet_hijack(p_txrx->p.p, pkt_mask);
	break;

	case ETH_TYPE_IPV4:
		if ((*protocol == IP_PROTOCOL_ICMP)  &&
			(link->ip == rte_be_to_cpu_32(*dst_addr))) {
			if (is_phy_port_privte(pkt->port)) {
				rte_pipeline_port_out_packet_insert(
					p_txrx->p.p,
					out_port, pkt);
				rte_pipeline_ah_packet_drop(
					p_txrx->p.p,
					pkt_mask);
			}
		}

	break;

	#ifdef IPV6
	case ETH_TYPE_IPV6:
		if (*protocol == ICMPV6_PROTOCOL_ID) {
			if (!memcmp(ipv6_h->dst_addr, link->ipv6, 16)
			|| !memcmp(ipv6_h->dst_addr, solicited_node_multicast_addr, 13)) {
				rte_pipeline_port_out_packet_insert(p_txrx->p.p,
					out_port, pkt);
				rte_pipeline_ah_packet_hijack(p_txrx->p.p, pkt_mask);
			} else {
				rte_pipeline_ah_packet_drop(p_txrx->p.p, pkt_mask);
			}
		}
	break;
	#endif

	default: /* Not valid pkt */
		printf("Dropping the pkt\n");
		rte_pipeline_ah_packet_drop(p_txrx->p.p, pkt_mask);

	}
	#endif

}

static inline void
pkt4_work_txrx(struct rte_mbuf **pkt, uint32_t pkt_num, void *arg)
{
	struct pipeline_txrx_in_port_h_arg *ap = arg;
	struct pipeline_txrx *p_txrx = (struct pipeline_txrx *)ap->p;
	uint8_t solicited_node_multicast_addr[16] =
					{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00};

	if (p_txrx->txrx_type == TYPE_TXTX)
		return;

	uint16_t in_port_id = (*pkt)->port;
	uint32_t eth_proto_offset = MBUF_HDR_ROOM + 12;


	uint32_t pkt_mask0 = 1 << pkt_num;
	uint32_t pkt_mask1 = 1 << (pkt_num + 1);
	uint32_t pkt_mask2 = 1 << (pkt_num + 2);
	uint32_t pkt_mask3 = 1 << (pkt_num + 3);

	/* ARP outport number */
	uint32_t out_port = p_txrx->p.n_ports_out - 1;

	uint16_t *eth_proto0 =
			RTE_MBUF_METADATA_UINT16_PTR(pkt[0], eth_proto_offset);
	uint16_t *eth_proto1 =
			RTE_MBUF_METADATA_UINT16_PTR(pkt[1], eth_proto_offset);
	uint16_t *eth_proto2 =
			RTE_MBUF_METADATA_UINT16_PTR(pkt[2], eth_proto_offset);
	uint16_t *eth_proto3 =
			RTE_MBUF_METADATA_UINT16_PTR(pkt[3], eth_proto_offset);

	uint8_t *protocol0, *protocol1, *protocol2, *protocol3;
	uint32_t prot_offset =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_PROTOCOL_OFST;

	#ifdef IPV6
	struct ipv6_hdr *ipv6_h0, *ipv6_h1, *ipv6_h2, *ipv6_h3;
	ipv6_h0 = rte_pktmbuf_mtod_offset (pkt[0], struct ipv6_hdr *, sizeof(struct ether_hdr));
	uint32_t prot_offset_ipv6 =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IPV6_HDR_PROTOCOL_OFST;

/* --0-- */
	if (rte_be_to_cpu_16(*eth_proto0) == ETHER_TYPE_IPv6)
		protocol0 =
				RTE_MBUF_METADATA_UINT8_PTR(pkt[0], prot_offset_ipv6);
	else
		protocol0 = RTE_MBUF_METADATA_UINT8_PTR(pkt[0], prot_offset);

/* --1-- */
	ipv6_h1 = rte_pktmbuf_mtod_offset (pkt[1], struct ipv6_hdr *, sizeof(struct ether_hdr));
	if (rte_be_to_cpu_16(*eth_proto1) == ETHER_TYPE_IPv6)
		protocol1 =
				RTE_MBUF_METADATA_UINT8_PTR(pkt[1], prot_offset_ipv6);
	else
		protocol1 = RTE_MBUF_METADATA_UINT8_PTR(pkt[1], prot_offset);

/* --2-- */
	ipv6_h2 = rte_pktmbuf_mtod_offset (pkt[2], struct ipv6_hdr *, sizeof(struct ether_hdr));
	if (rte_be_to_cpu_16(*eth_proto2) == ETHER_TYPE_IPv6)
		protocol2 =
				RTE_MBUF_METADATA_UINT8_PTR(pkt[2], prot_offset_ipv6);
	else
		protocol2 = RTE_MBUF_METADATA_UINT8_PTR(pkt[2], prot_offset);

/* --3-- */
	ipv6_h3 = rte_pktmbuf_mtod_offset (pkt[3], struct ipv6_hdr *, sizeof(struct ether_hdr));
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

	if ((TXRX_DEBUG > 2) && (txrx_pkt_print_count < 10)) {
		print_pkt1(pkt[0]);
		txrx_pkt_print_count++;
		printf("\nEth Typ %x, Prot %x, ETH_TYPE_ARP %x, "
			"ETH_TYPE_IPV4 %x, IP_PROTOCOL_ICMP %x\n",
				 rte_be_to_cpu_16(*eth_proto0), *protocol0, ETH_TYPE_ARP,
				 ETH_TYPE_IPV4, IP_PROTOCOL_ICMP);
	}

	struct app_link_params *link;

	link = &myApp->link_params[in_port_id];

	/* header room + eth hdr size + src_aadr offset in ip header */
	uint32_t dst_addr_offset0 =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST;
	uint32_t *dst_addr0 =
			RTE_MBUF_METADATA_UINT32_PTR(pkt[0], dst_addr_offset0);

	if (TXRX_DEBUG > 2)
		if (rte_be_to_cpu_16(*eth_proto0) == ETH_TYPE_IPV4)
			printf ("%s: linkIp: %x, dst_addr0: %x\n", __FUNCTION__, link->ip, *dst_addr0);

	#if 1
	switch (rte_be_to_cpu_16(*eth_proto0)) {
	case ETH_TYPE_ARP:
		rte_pipeline_port_out_packet_insert(p_txrx->p.p,
			out_port, pkt[0]);
		rte_pipeline_ah_packet_hijack(p_txrx->p.p, pkt_mask0);
	break;

	case ETH_TYPE_IPV4:
		if ((*protocol0 == IP_PROTOCOL_ICMP)  &&
			(link->ip == rte_be_to_cpu_32(*dst_addr0))) {
			if (is_phy_port_privte(pkt[0]->port)) {
				rte_pipeline_port_out_packet_insert(
					p_txrx->p.p, out_port, pkt[0]);
				rte_pipeline_ah_packet_drop(
					p_txrx->p.p, pkt_mask0);
			}
		}

	break;

	#ifdef IPV6
	case ETH_TYPE_IPV6:
		if (*protocol0 == ICMPV6_PROTOCOL_ID) {
			if (!memcmp(ipv6_h0->dst_addr, link->ipv6, 16)
				|| !memcmp(ipv6_h0->dst_addr, solicited_node_multicast_addr, 13)) {
				rte_pipeline_port_out_packet_insert(p_txrx->p.p,
					out_port, pkt[0]);
				rte_pipeline_ah_packet_hijack(p_txrx->p.p, pkt_mask0);

			} else {
				rte_pipeline_ah_packet_drop(p_txrx->p.p, pkt_mask0);
			}
		}
	break;
	#endif

	default: /* Not valid pkt */
		rte_pipeline_ah_packet_drop(p_txrx->p.p, pkt_mask0);

	}
	#endif

	if ((TXRX_DEBUG > 2) && (txrx_pkt_print_count < 10)) {
		print_pkt1(pkt[1]);
		txrx_pkt_print_count++;
		printf("\nEth Typ %x, Prot %x, ETH_TYPE_ARP %x, "
			"ETH_TYPE_IPV4 %x, IP_PROTOCOL_ICMP %x\n",
				 rte_be_to_cpu_16(*eth_proto1), *protocol1, ETH_TYPE_ARP,
				 ETH_TYPE_IPV4, IP_PROTOCOL_ICMP);
	}

	/* header room + eth hdr size + src_aadr offset in ip header */
	uint32_t dst_addr_offset1 =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST;
	uint32_t *dst_addr1 =
			RTE_MBUF_METADATA_UINT32_PTR(pkt[1], dst_addr_offset1);

	if (TXRX_DEBUG > 2)
		if (rte_be_to_cpu_16(*eth_proto1) == ETH_TYPE_IPV4)
			printf ("%s: linkIp: %x, dst_addr1: %x\n", __FUNCTION__, link->ip, *dst_addr1);

	switch (rte_be_to_cpu_16(*eth_proto1)) {
	case ETH_TYPE_ARP:
		rte_pipeline_port_out_packet_insert(p_txrx->p.p,
			out_port, pkt[1]);
		rte_pipeline_ah_packet_hijack(p_txrx->p.p, pkt_mask1);
	break;

	case ETH_TYPE_IPV4:
		if ((*protocol1 == IP_PROTOCOL_ICMP)  &&
			(link->ip == rte_be_to_cpu_32(*dst_addr1))) {
			if (is_phy_port_privte(pkt[1]->port)) {
				rte_pipeline_port_out_packet_insert(
					p_txrx->p.p,
					out_port, pkt[1]);
				rte_pipeline_ah_packet_drop(
					p_txrx->p.p,
					pkt_mask1);
			}
		}

	break;

	#ifdef IPV6
	case ETH_TYPE_IPV6:
		if (*protocol1 == ICMPV6_PROTOCOL_ID) {
			if (!memcmp(ipv6_h1->dst_addr, link->ipv6, 16)
				|| !memcmp(ipv6_h1->dst_addr, solicited_node_multicast_addr, 13)) {
				rte_pipeline_port_out_packet_insert(p_txrx->p.p,
					out_port, pkt[1]);
				rte_pipeline_ah_packet_hijack(p_txrx->p.p, pkt_mask1);
			} else {
				rte_pipeline_ah_packet_drop(p_txrx->p.p, pkt_mask1);
			}
		}
	break;
	#endif

	default: /* Not valid pkt */
		rte_pipeline_ah_packet_drop(p_txrx->p.p, pkt_mask1);

	}

	if ((TXRX_DEBUG > 2) && (txrx_pkt_print_count < 10)) {
		print_pkt1(pkt[2]);
		txrx_pkt_print_count++;
		printf("\nEth Typ %x, Prot %x, ETH_TYPE_ARP %x, "
			"ETH_TYPE_IPV4 %x, IP_PROTOCOL_ICMP %x\n",
				 rte_be_to_cpu_16(*eth_proto2), *protocol2, ETH_TYPE_ARP,
				 ETH_TYPE_IPV4, IP_PROTOCOL_ICMP);
	}

	/* header room + eth hdr size + src_aadr offset in ip header */
	uint32_t dst_addr_offset2 =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST;
	uint32_t *dst_addr2 =
			RTE_MBUF_METADATA_UINT32_PTR(pkt[2], dst_addr_offset2);

	if (TXRX_DEBUG > 2)
		if (rte_be_to_cpu_16(*eth_proto2) == ETH_TYPE_IPV4)
			printf ("%s: linkIp: %x, dst_addr2: %x\n", __FUNCTION__, link->ip, *dst_addr2);

	switch (rte_be_to_cpu_16(*eth_proto2)) {
	case ETH_TYPE_ARP:
		rte_pipeline_port_out_packet_insert(p_txrx->p.p,
			out_port, pkt[2]);
		rte_pipeline_ah_packet_hijack(p_txrx->p.p, pkt_mask2);
	break;

	case ETH_TYPE_IPV4:
		if ((*protocol2 == IP_PROTOCOL_ICMP)  &&
			(link->ip == rte_be_to_cpu_32(*dst_addr2))) {
			if (is_phy_port_privte(pkt[2]->port)) {
				rte_pipeline_port_out_packet_insert(
					p_txrx->p.p,
					out_port, pkt[2]);
				rte_pipeline_ah_packet_drop(
					p_txrx->p.p,
					pkt_mask2);
			}
		}

	break;

	#ifdef IPV6
	case ETH_TYPE_IPV6:
		if (*protocol2 == ICMPV6_PROTOCOL_ID) {
			if (!memcmp(ipv6_h2->dst_addr, link->ipv6, 16)
				|| !memcmp(ipv6_h2->dst_addr, solicited_node_multicast_addr, 13)) {
				rte_pipeline_port_out_packet_insert(p_txrx->p.p,
					out_port, pkt[2]);
				rte_pipeline_ah_packet_hijack(p_txrx->p.p, pkt_mask2);
			} else {
				rte_pipeline_ah_packet_drop(p_txrx->p.p, pkt_mask2);
			}
		}
	break;
	#endif

	default: /* Not valid pkt */
		rte_pipeline_ah_packet_drop(p_txrx->p.p, pkt_mask2);

	}

	if ((TXRX_DEBUG > 2) && (txrx_pkt_print_count < 10)) {
		print_pkt1(pkt[3]);
		txrx_pkt_print_count++;
		printf("\nEth Typ %x, Prot %x, ETH_TYPE_ARP %x, "
			"ETH_TYPE_IPV4 %x, IP_PROTOCOL_ICMP %x\n",
				 rte_be_to_cpu_16(*eth_proto3), *protocol3, ETH_TYPE_ARP,
				 ETH_TYPE_IPV4, IP_PROTOCOL_ICMP);
	}

	/* header room + eth hdr size + src_aadr offset in ip header */
	uint32_t dst_addr_offset3 =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST;
	uint32_t *dst_addr3 =
			RTE_MBUF_METADATA_UINT32_PTR(pkt, dst_addr_offset3);

	if (TXRX_DEBUG > 2)
		if (rte_be_to_cpu_16(*eth_proto3) == ETH_TYPE_IPV4)
			printf ("%s: linkIp: %x, dst_addr3: %x\n", __FUNCTION__, link->ip, *dst_addr3);

	switch (rte_be_to_cpu_16(*eth_proto3)) {
	case ETH_TYPE_ARP:
		rte_pipeline_port_out_packet_insert(p_txrx->p.p,
			out_port, pkt[3]);
		rte_pipeline_ah_packet_hijack(p_txrx->p.p, pkt_mask3);
	break;

	case ETH_TYPE_IPV4:
		if ((*protocol3 == IP_PROTOCOL_ICMP)  &&
			(link->ip == rte_be_to_cpu_32(*dst_addr3))) {
			if (is_phy_port_privte(pkt[3]->port)) {
				rte_pipeline_port_out_packet_insert(
					p_txrx->p.p,
					out_port, pkt[3]);
				rte_pipeline_ah_packet_drop(
					p_txrx->p.p,
					pkt_mask3);
			}
		}

	break;

	#ifdef IPV6
	case ETH_TYPE_IPV6:
		if (*protocol3 == ICMPV6_PROTOCOL_ID) {
			if (!memcmp(ipv6_h3->dst_addr, link->ipv6, 16)
				|| !memcmp(ipv6_h3->dst_addr, solicited_node_multicast_addr, 13)) {
				rte_pipeline_port_out_packet_insert(p_txrx->p.p,
					out_port, pkt[3]);
				rte_pipeline_ah_packet_hijack(p_txrx->p.p, pkt_mask3);
			} else {
				rte_pipeline_ah_packet_drop(p_txrx->p.p, pkt_mask3);
			}
		}
	break;
	#endif

	default: /* Not valid pkt */
		rte_pipeline_ah_packet_drop(p_txrx->p.p, pkt_mask3);

	}

	p_txrx->receivedPktCount += 4;

}

PIPELINE_TXRX_KEY_PORT_IN_AH(port_in_ah_txrx, pkt_work_txrx, pkt4_work_txrx);

static void *pipeline_txrx_init(struct pipeline_params *params,
				__rte_unused void *arg)
{
	struct pipeline *p;
	struct pipeline_txrx *p_pt;
	uint32_t size, i, in_ports_arg_size;

	printf("Start pipeline_txrx_init\n");

	/* Check input arguments */
	if ((params == NULL) ||
			(params->n_ports_in == 0) ||
			(params->n_ports_out == 0))
		return NULL;

	/* Memory allocation */
	size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct pipeline_txrx));
	p = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
	p_pt = (struct pipeline_txrx *)p;
	if (p == NULL)
		return NULL;

	PLOG(p, HIGH, "TXRX");
	strcpy(p->name, params->name);
	p->log_level = params->log_level;

	p_pt->receivedPktCount = 0;
	p_pt->droppedPktCount = 0;
	for (i = 0; i < PIPELINE_MAX_PORT_IN; i++)
		p_pt->links_map[i] = 0xff;

	p_pt->pipeline_num = 0;
	printf("txrx initialization of variables done\n");

	/* Parse arguments */
	if (pipeline_txrx_parse_args(p_pt, params))
		return NULL;

	/* Pipeline */
	{
		struct rte_pipeline_params pipeline_params = {
			.name = "TXRX",
			.socket_id = params->socket_id,
			.offset_port_id = 0,
		};

		p->p = rte_pipeline_create(&pipeline_params);
		if (p->p == NULL) {
			rte_free(p);
			return NULL;
		}
	}

	p->n_ports_in = params->n_ports_in;
	p->n_ports_out = params->n_ports_out;
	p->n_tables = p->n_ports_in;

	/* Memory allocation for in_port_h_arg */
	in_ports_arg_size =
		RTE_CACHE_LINE_ROUNDUP((sizeof
					(struct pipeline_txrx_in_port_h_arg)) *
				(params->n_ports_in));
	struct pipeline_txrx_in_port_h_arg *ap =
		(struct pipeline_txrx_in_port_h_arg *)rte_zmalloc(NULL,
				in_ports_arg_size,
				RTE_CACHE_LINE_SIZE);
	if (ap == NULL)
		return NULL;
	/*Input ports */
	for (i = 0; i < p->n_ports_in; i++) {
		/* passing our txrx pipeline in call back arg */
		(ap[i]).p = p_pt;
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

			port_params.f_action = port_in_ah_txrx;

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
		printf("Unable to read pipeline number\n");
		return NULL;
	}
	p_pt->pipeline_num = (uint8_t) pipeline_num;

	register_pipeline_Qs(p_pt->pipeline_num, p);
	set_link_map(p_pt->pipeline_num, p, p_pt->links_map);
	set_outport_id(p_pt->pipeline_num, p, p_pt->outport_id);

	/* Tables */
	for (i = 0; i < p->n_ports_in; i++) {
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
									 &p->table_id[i]);

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
									 table_id[i]);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}
	}

	/* Add entries to tables */
	for (i = 0; i < p->n_ports_in; i++) {
		struct rte_pipeline_table_entry default_entry = {
			.action = RTE_PIPELINE_ACTION_PORT,
			.port_id = p->port_out_id[i],
		};

		struct rte_pipeline_table_entry *default_entry_ptr;

		int status = rte_pipeline_table_default_entry_add(
				p->p,
				p->
				table_id[i],
				&default_entry,
				&default_entry_ptr);

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

static int pipeline_txrx_free(void *pipeline)
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

static int pipeline_txrx_timer(void *pipeline)
{
	struct pipeline *p = (struct pipeline *)pipeline;

	pipeline_msg_req_handle(p);
	rte_pipeline_flush(p->p);

	return 0;
}

static int
pipeline_txrx_track(void *pipeline, uint32_t port_in, uint32_t *port_out)
{
	struct pipeline *p = (struct pipeline *)pipeline;

	/* Check input arguments */
	if ((p == NULL) || (port_in >= p->n_ports_in) || (port_out == NULL))
		return -1;

	*port_out = port_in / p->n_ports_in;
	return 0;
}

struct pipeline_be_ops pipeline_txrx_be_ops = {
	.f_init = pipeline_txrx_init,
	.f_free = pipeline_txrx_free,
	.f_run = NULL,
	.f_timer = pipeline_txrx_timer,
	.f_track = pipeline_txrx_track,
};
