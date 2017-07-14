/*
// Copyright (c) 2010-2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef _PKT_PARSER_H_
#define _PKT_PARSER_H_

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_byteorder.h>

#include "log.h"
#include "etypes.h"

struct pkt_tuple {
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t proto_id;
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t l2_types[4];
} __attribute__((packed));

struct l4_meta {
	uint8_t *l4_hdr;
	uint8_t *payload;
	uint16_t len;
};

static void pkt_tuple_debug2(const struct pkt_tuple *pt)
{
	plogx_info("src_ip : %#010x\n", pt->src_addr);
	plogx_info("dst_ip : %#010x\n", pt->dst_addr);
	plogx_info("dst_port : %#06x\n", pt->dst_port);
	plogx_info("src_port : %#06x\n", pt->src_port);
	plogx_info("proto_id : %#04x\n", pt->proto_id);
	plogx_info("l2 types: \n");
	for (int i = 0; i < 4; ++i)
		plogx_info("  - %#04x\n", pt->l2_types[i]);
}

static void pkt_tuple_debug(const struct pkt_tuple *pt)
{
	plogx_dbg("src_ip : %#010x\n", pt->src_addr);
	plogx_dbg("dst_ip : %#010x\n", pt->dst_addr);
	plogx_dbg("dst_port : %#06x\n", pt->dst_port);
	plogx_dbg("src_port : %#06x\n", pt->src_port);
	plogx_dbg("proto_id : %#04x\n", pt->proto_id);
	plogx_dbg("l2 types: \n");
	for (int i = 0; i < 4; ++i)
		plogx_dbg("  - %#04x\n", pt->l2_types[i]);
}

/* Return 0 on success, i.e. packets parsed without any error. */
static int parse_pkt(struct rte_mbuf *mbuf, struct pkt_tuple *pt, struct l4_meta *l4_meta)
{
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	size_t l2_types_count = 0;
	struct ipv4_hdr* pip = 0;

	/* L2 */
	pt->l2_types[l2_types_count++] = peth->ether_type;

	switch (peth->ether_type) {
	case ETYPE_IPv4:
			pip = (struct ipv4_hdr *)(peth + 1);
		break;
	case ETYPE_VLAN: {
		struct vlan_hdr *vlan = (struct vlan_hdr *)(peth + 1);
		pt->l2_types[l2_types_count++] = vlan->eth_proto;
		if (vlan->eth_proto == ETYPE_IPv4) {
			pip = (struct ipv4_hdr *)(peth + 1);
		}
		else if (vlan->eth_proto == ETYPE_VLAN) {
			struct vlan_hdr *vlan = (struct vlan_hdr *)(peth + 1);
			pt->l2_types[l2_types_count++] = vlan->eth_proto;
			if (vlan->eth_proto == ETYPE_IPv4) {
				pip = (struct ipv4_hdr *)(peth + 1);
			}
			else if (vlan->eth_proto == ETYPE_IPv6) {
				return 1;
			}
			else {
				/* TODO: handle BAD PACKET */
				return 1;
			}
		}
	}
		break;
	case ETYPE_8021ad: {
		struct vlan_hdr *vlan = (struct vlan_hdr *)(peth + 1);
		pt->l2_types[l2_types_count++] = vlan->eth_proto;
		if (vlan->eth_proto == ETYPE_VLAN) {
			struct vlan_hdr *vlan = (struct vlan_hdr *)(peth + 1);
			pt->l2_types[l2_types_count++] = vlan->eth_proto;
			if (vlan->eth_proto == ETYPE_IPv4) {
				pip = (struct ipv4_hdr *)(peth + 1);
			}
			else {
				return 1;
			}
		}
		else {
			return 1;
		}
	}
		break;
	case ETYPE_MPLSU:
		return -1;
		break;
	default:
		plogx_err("Parsing error: unknown packet ether type = %#06x\n", peth->ether_type);
		return -1;
		break;
	}

	/* L3 */
	if ((pip->version_ihl >> 4) == 4) {

		if ((pip->version_ihl & 0x0f) != 0x05) {
			/* TODO: optional fields */
			return 1;
		}

		pt->proto_id = pip->next_proto_id;
		pt->src_addr = pip->src_addr;
		pt->dst_addr = pip->dst_addr;
	}
	else {
		/* TODO: IPv6 and bad packets */
		return 1;
	}

	/* L4 parser */
	if (pt->proto_id == IPPROTO_UDP) {
		struct udp_hdr *udp = (struct udp_hdr*)(pip + 1);
		l4_meta->l4_hdr = (uint8_t*)udp;
		pt->src_port = udp->src_port;
		pt->dst_port = udp->dst_port;
		l4_meta->payload = ((uint8_t*)udp) + sizeof(struct udp_hdr);
		l4_meta->len = rte_be_to_cpu_16(udp->dgram_len) - sizeof(struct udp_hdr);
	}
	else if (pt->proto_id == IPPROTO_TCP) {
		struct tcp_hdr *tcp = (struct tcp_hdr*)(pip + 1);
		l4_meta->l4_hdr = (uint8_t*)tcp;
		pt->src_port = tcp->src_port;
		pt->dst_port = tcp->dst_port;

		l4_meta->payload = ((uint8_t*)tcp) + ((tcp->data_off >> 4)*4);
		l4_meta->len = rte_be_to_cpu_16(pip->total_length) - sizeof(struct ipv4_hdr) - ((tcp->data_off >> 4)*4);
	}
	else {
		plog_err("unsupported protocol %d\n", pt->proto_id);
		return 1;
	}

	for (; l2_types_count < sizeof(pt->l2_types)/sizeof(pt->l2_types[0]); ++l2_types_count)
		pt->l2_types[l2_types_count] = 0;

	return 0;
}

#endif /* _PKT_PARSER_H_ */
