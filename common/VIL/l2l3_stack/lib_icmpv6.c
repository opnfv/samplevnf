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
/*	Santosh Sethupathi*/

#include "lib_icmpv6.h"

static void print_pkt(uint8_t *rd)
{
	int i = 0, j = 0;

	printf("Packet Contents:\n");

	for (i = 0; i < 20; i++) {
		for (j = 0; j < 20; j++)
			printf("%02x ", rd[(20 * i) + j]);

		printf("\n");
	}
}

static uint16_t icmpv6_ipv6_nd_checksum(struct rte_mbuf *pkt)
{
	struct ether_hdr *eth_h;
	struct ipv6_hdr *ipv6_h;
	struct icmpv6_hdr *icmpv6_h;

	size_t tmplen, offset;
	uint8_t *tmppacket, *tpacket;

	eth_h = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	ipv6_h = (struct ipv6_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	icmpv6_h =
			(struct icmpv6_hdr *)((char *)ipv6_h + sizeof(struct ipv6_hdr));

	uint32_t payloadlen = 0x20;
	payloadlen = rte_bswap32(payloadlen);

	tmplen = 40 + sizeof(struct icmpv6_hdr) + sizeof(struct icmpv6_nd_hdr);
	tmplen = RTE_CACHE_LINE_ROUNDUP(tmplen);
	tmppacket = rte_zmalloc(NULL, tmplen, RTE_CACHE_LINE_SIZE);
	tpacket = tmppacket;

	offset = 16;
	memcpy(tpacket, &ipv6_h->src_addr[0], offset);
	tpacket += offset;
	memcpy(tpacket, &ipv6_h->dst_addr[0], offset);
	tpacket += offset;
	*tpacket = 0;
	tpacket++;
	*tpacket = 0;
	tpacket++;
	*tpacket = 0;
	tpacket++;
	memcpy(tpacket, &ipv6_h->proto, 1);
	tpacket++;
	memcpy(tpacket, &payloadlen, 4);
	tpacket += 4;
	memcpy(tpacket, icmpv6_h,
				 sizeof(struct icmpv6_hdr) + sizeof(struct icmpv6_nd_hdr));

	if (ARPICMP_DEBUG)
		print_pkt(tmppacket);

	return rte_raw_cksum(tmppacket, tmplen);
}

static uint16_t icmpv6_ipv6_echo_checksum(struct rte_mbuf *pkt)
{
	struct ether_hdr *eth_h;
	struct ipv6_hdr *ipv6_h;
	struct icmpv6_hdr *icmpv6_h;

	size_t tmplen, offset;
	uint8_t *tmppacket, *tpacket;

	eth_h = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	ipv6_h = (struct ipv6_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	icmpv6_h =
			(struct icmpv6_hdr *)((char *)ipv6_h + sizeof(struct ipv6_hdr));

	uint32_t payloadlen = rte_bswap16(ipv6_h->payload_len);
	uint32_t payloadlen_swap = rte_bswap32(payloadlen);

	if (ARPICMP_DEBUG)
		printf("%s: payloadlen: %u\n", __FUNCTION__, payloadlen);

	tmplen = 40 + payloadlen;
	tmplen = RTE_CACHE_LINE_ROUNDUP(tmplen);
	tmppacket = rte_zmalloc(NULL, tmplen, RTE_CACHE_LINE_SIZE);
	tpacket = tmppacket;

	offset = 16;
	memcpy(tpacket, &ipv6_h->src_addr[0], offset);
	tpacket += offset;
	memcpy(tpacket, &ipv6_h->dst_addr[0], offset);
	tpacket += offset;
	*tpacket = 0;
	tpacket++;
	*tpacket = 0;
	tpacket++;
	*tpacket = 0;
	tpacket++;
	memcpy(tpacket, &ipv6_h->proto, 1);
	tpacket++;
	memcpy(tpacket, &payloadlen_swap, 4);
	tpacket += 4;
	memcpy(tpacket, icmpv6_h, payloadlen);

	if (ARPICMP_DEBUG)
		print_pkt(tmppacket);

	return rte_raw_cksum(tmppacket, tmplen);
}

void process_icmpv6_pkt(struct rte_mbuf *pkt, l2_phy_interface_t *port)
{

	struct ether_hdr *eth_h;
	struct ipv6_hdr *ipv6_h;
	struct icmpv6_hdr *icmpv6_h;
	struct icmpv6_nd_hdr *icmpv6_nd_h;
	uint8_t ipv6_addr[16];
	uint8_t i = 0;
	uint8_t req_tipv6[16];
	/* To drop the packet */

	if (port == NULL) {
		printf("port is NULL");
		return;
	} else if (port->ipv6_list == NULL) {
		printf("IPV6 address not configured on link\n");
		return;
	}

	eth_h = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	ipv6_h = (struct ipv6_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	icmpv6_h =
			(struct icmpv6_hdr *)((char *)ipv6_h + sizeof(struct ipv6_hdr));

	if ((icmpv6_h->icmpv6_type == ICMPV6_ECHO_REQUEST)
			&& (icmpv6_h->icmpv6_code == 0)) {
		for (i = 0; i < 16; i++) {
			ipv6_addr[i] = ipv6_h->src_addr[i];
		}

		ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
		ether_addr_copy((struct ether_addr *)&port->macaddr[0],
				&eth_h->s_addr);

		for (i = 0; i < 16; i++)
			ipv6_h->src_addr[i] = ipv6_h->dst_addr[i];
		for (i = 0; i < 16; i++)
			ipv6_h->dst_addr[i] = ipv6_addr[i];

		icmpv6_h->icmpv6_type = ICMPV6_ECHO_REPLY;
		icmpv6_h->icmpv6_cksum = 0;
		icmpv6_h->icmpv6_cksum = ~icmpv6_ipv6_echo_checksum(pkt);
		port->transmit_bulk_pkts(port, &pkt, 1);

		return;
	} else if ((icmpv6_h->icmpv6_type == ICMPV6_ECHO_REPLY)
			 && (icmpv6_h->icmpv6_code == 0)) {
		struct nd_key_ipv6 nd_key;
		nd_key.port_id = port->pmdid;
		for (i = 0; i < ND_IPV6_ADDR_SIZE; i++) {
			nd_key.ipv6[i] = ipv6_h->src_addr[i];

		}
		nd_key.filler1 = 0;
		nd_key.filler2 = 0;
		nd_key.filler3 = 0;

		/*Validate if key-value pair already exists in the hash table for ND IPv6 */
		struct nd_entry_data *new_nd_data = retrieve_nd_entry(nd_key, DYNAMIC_ND);
		if (new_nd_data == NULL) {
			printf
					("Received unsolicited ICMPv6 echo reply on port %d\n",
					 nd_key.port_id);
			for (i = 0; i < ND_IPV6_ADDR_SIZE; i += 2) {
				printf("%02X%02X ", nd_key.ipv6[i],
							 nd_key.ipv6[i + 1]);
			}
			return;
		}

		new_nd_data->status = COMPLETE;
	} else if ((icmpv6_h->icmpv6_type == ICMPV6_NEIGHBOR_SOLICITATION)
			 && (icmpv6_h->icmpv6_code == 0)) {

		icmpv6_nd_h =
				(struct icmpv6_nd_hdr *)((char *)icmpv6_h +
							 sizeof(struct icmpv6_hdr));
		struct ether_addr *src_hw_addr = &eth_h->s_addr;
		uint8_t src_ipv6[16], dst_ipv6[16];
		uint16_t multi_addr;

		for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
			src_ipv6[i] = ipv6_h->src_addr[i];

		for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
			dst_ipv6[i] = ipv6_h->dst_addr[i];

		multi_addr = dst_ipv6[0];

		/*  Check for Multicast Address */
		if ((IPV6_MULTICAST & ((multi_addr << 8) | dst_ipv6[1]))
				|| !memcmp(&port->macaddr[0], &eth_h->d_addr, 6)) {

			populate_nd_entry(src_hw_addr, src_ipv6, port->pmdid,
						DYNAMIC_ND);

			/* build a Neighbor Advertisement message */
			for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
				req_tipv6[i] = icmpv6_nd_h->target_ipv6[i];

			if (!memcmp
					(&req_tipv6[0],
					 &((ipv6list_t *) port->ipv6_list)->ipaddr[0],
					 16)) {

				ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
				ether_addr_copy((struct ether_addr *)&port->
						macaddr[0], &eth_h->s_addr);

				/* set sender mac address */
				for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
					ipv6_h->dst_addr[i] =
							ipv6_h->src_addr[i];
				for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
					ipv6_h->src_addr[i] = req_tipv6[i];
				icmpv6_h->icmpv6_type =
						ICMPV6_NEIGHBOR_ADVERTISEMENT;
				icmpv6_nd_h->type = e_Target_Link_Layer_Address;
				icmpv6_nd_h->length = 1;
				memcpy(&icmpv6_nd_h->link_layer_addr[0],
							 &port->macaddr[0], 6);
				icmpv6_nd_h->icmpv6_reserved = 0;
				icmpv6_nd_h->icmpv6_reserved |=
						rte_cpu_to_be_32
						(NEIGHBOR_ROUTER_OVERRIDE_SET);

				icmpv6_h->icmpv6_cksum = 0;
				icmpv6_h->icmpv6_cksum =
						~icmpv6_ipv6_nd_checksum(pkt);

				port->transmit_bulk_pkts(port, &pkt, 1);

			} else if (ARPICMP_DEBUG) {
				printf
						("............Some one else is the target host here !!!\n");
			}

			return;
		} else {
			if (ARPICMP_DEBUG) {
				printf
						("...............Malformed ND Solicitation message!!!\n");
			}
		}

	} else if ((icmpv6_h->icmpv6_type == ICMPV6_NEIGHBOR_ADVERTISEMENT)
			 && (icmpv6_h->icmpv6_code == 0)) {
		struct ether_addr *src_hw_addr = &eth_h->s_addr;
		uint8_t ipv6[16];
		for (i = 0; i < ND_IPV6_ADDR_SIZE; i++) {
			ipv6[i] = ipv6_h->src_addr[i];

		}
		populate_nd_entry(src_hw_addr, ipv6, port->pmdid, DYNAMIC_ND);
	} else {
		if (ARPICMP_DEBUG) {
			printf("ICMPv6 Type %d Not Supported yet !!!\n",
						 icmpv6_h->icmpv6_type);
		}
	}

	rte_pktmbuf_free(pkt);
}

struct rte_mbuf *request_icmpv6_echo(uint8_t ipv6[], l2_phy_interface_t *port)
{
	struct ether_hdr *eth_h;
	struct ipv6_hdr *ipv6_h;
	struct icmpv6_hdr *icmpv6_h;
	struct icmpv6_info_hdr *icmpv6_info_h;
	int i;
	uint8_t *icmp_data;

	struct rte_mbuf *icmpv6_pkt = lib_icmpv6_pkt;
	if (icmpv6_pkt == NULL) {
		if (ARPICMP_DEBUG)
			printf("Error allocating icmpv6_pkt rte_mbuf\n");
		return NULL;
	}

	eth_h = rte_pktmbuf_mtod(icmpv6_pkt, struct ether_hdr *);

	ipv6_h = (struct ipv6_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	icmpv6_h =
			(struct icmpv6_hdr *)((char *)ipv6_h + sizeof(struct ipv6_hdr));
	icmpv6_info_h =
			(struct icmpv6_info_hdr *)((char *)icmpv6_h +
							 sizeof(struct icmpv6_hdr));

	ether_addr_copy((struct ether_addr *)&port->macaddr[0], &eth_h->s_addr);
	eth_h->ether_type = rte_bswap16(0x86dd);
	for (i = 0; i < 6; i++) {
		eth_h->d_addr.addr_bytes[i] = 0;
	}

	ipv6_h->vtc_flow = rte_bswap32(0x60000000);
	ipv6_h->payload_len = rte_bswap16(64);
	ipv6_h->proto = 58;
	ipv6_h->hop_limits = 64;

	for (i = 0; i < 16; i++) {
		ipv6_h->src_addr[i] = 0x0;
		ipv6_h->dst_addr[i] = ipv6[i];
	}

	icmpv6_h->icmpv6_type = ICMPV6_ECHO_REQUEST;
	icmpv6_h->icmpv6_code = 0;
	icmpv6_info_h->icmpv6_ident = rte_bswap16(0x5151);
	icmpv6_info_h->icmpv6_seq_nb = rte_bswap16(0x1);

	icmp_data = (uint8_t *) icmpv6_h + 8;
	for (i = 0; i < 56; i++) {
		*icmp_data = i + 1;
		icmp_data++;
	}
	icmpv6_h->icmpv6_cksum = 0;
	icmpv6_h->icmpv6_cksum = ~icmpv6_ipv6_echo_checksum(icmpv6_pkt);

	icmpv6_pkt->pkt_len =
			sizeof(struct ether_hdr) + sizeof(struct ipv6_hdr) + 64;
	icmpv6_pkt->data_len = icmpv6_pkt->pkt_len;

	if (port)
		port->transmit_single_pkt(port, icmpv6_pkt);

	return icmpv6_pkt;
}

struct rte_mbuf *request_nd(uint8_t ipv6[], l2_phy_interface_t *port)
{
	struct ether_hdr *eth_h;
	struct ipv6_hdr *ipv6_h;
	struct icmpv6_hdr *icmpv6_h;
	struct icmpv6_nd_hdr *icmpv6_nd_h;
	int i;

	struct rte_mbuf *icmpv6_pkt = lib_nd_pkt[port->pmdid];
	if ((icmpv6_pkt == NULL) || (port == NULL)) {
		if (ARPICMP_DEBUG)
			printf("Error allocating icmpv6_pkt rte_mbuf\n");
		return NULL;
	}

	uint8_t dst_ip[] = {255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 16, 100, 20};
	uint8_t dst_mac[] = {51,51,255, 16, 100, 20};

	eth_h = rte_pktmbuf_mtod(icmpv6_pkt, struct ether_hdr *);

	ipv6_h = (struct ipv6_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	icmpv6_h =
			(struct icmpv6_hdr *)((char *)ipv6_h + sizeof(struct ipv6_hdr));
	icmpv6_nd_h =
			(struct icmpv6_nd_hdr *)((char *)icmpv6_h +
						 sizeof(struct icmpv6_hdr));

	ether_addr_copy((struct ether_addr *)&port->macaddr[0], &eth_h->s_addr);
	eth_h->ether_type = rte_bswap16(0x86dd);

	for (i = 0; i < 6; i++) {
		if (i < 3)
			eth_h->d_addr.addr_bytes[i] = dst_mac[i];
		else
			eth_h->d_addr.addr_bytes[i] = ipv6[i];
	}

	for (i=13; i<16; i++)
		dst_ip[i] = ipv6[i];

	uint8_t *addr = ((ipv6list_t *) (port->ipv6_list))->ipaddr;

	ipv6_h->vtc_flow = rte_bswap32(0x60000000);
	ipv6_h->payload_len = rte_bswap16(32);
	ipv6_h->proto = 58;
	ipv6_h->hop_limits = 255;

	for (i = 0; i < 16; i++) {
		ipv6_h->src_addr[i] = *(addr + i);
		ipv6_h->dst_addr[i] = dst_ip[i];
	}

	icmpv6_h->icmpv6_type = ICMPV6_NEIGHBOR_SOLICITATION;
	icmpv6_h->icmpv6_code = 0;

	icmpv6_nd_h->icmpv6_reserved = 0x0;
	icmpv6_nd_h->icmpv6_reserved |=
			rte_cpu_to_be_32
			(NEIGHBOR_ROUTER_OVERRIDE_SET);

	for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
		icmpv6_nd_h->target_ipv6[i] = ipv6[i];
	icmpv6_nd_h->type = e_Source_Link_Layer_Address;
	icmpv6_nd_h->length = 1;
	memcpy(&icmpv6_nd_h->link_layer_addr[0], &port->macaddr[0], 6);

	icmpv6_h->icmpv6_cksum = 0;
	icmpv6_h->icmpv6_cksum = ~icmpv6_ipv6_nd_checksum(icmpv6_pkt);
	icmpv6_pkt->pkt_len =
			sizeof(struct ether_hdr) + sizeof(struct ipv6_hdr) + 32;
	icmpv6_pkt->data_len = icmpv6_pkt->pkt_len;

	if (port) {
		port->transmit_single_pkt(port, icmpv6_pkt);
	}

	return icmpv6_pkt;
}
