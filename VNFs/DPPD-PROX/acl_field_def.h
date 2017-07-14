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

#ifndef _ACL_FIELD_DEF_H_
#define _ACL_FIELD_DEF_H_

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "qinq.h"

struct pkt_eth_ipv4_udp {
	struct ether_hdr ether_hdr;
	struct ipv4_hdr ipv4_hdr;
	struct udp_hdr udp_hdr;
} __attribute__((packed));

static struct rte_acl_field_def pkt_eth_ipv4_udp_defs[] = {
	/* first input field - always one byte long. */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof (uint8_t),
		.field_index = 0,
		.input_index = 0,
		.offset = offsetof (struct pkt_eth_ipv4_udp, ipv4_hdr.next_proto_id),
	},
	/* IPv4 source address. */
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof (uint32_t),
		.field_index = 1,
		.input_index = 1,
		.offset = offsetof (struct pkt_eth_ipv4_udp, ipv4_hdr.src_addr),
	},
	/* IPv4 destination address */
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof (uint32_t),
		.field_index = 2,
		.input_index = 2,
		.offset = offsetof (struct pkt_eth_ipv4_udp, ipv4_hdr.dst_addr),
	},
	/* (L4 src/dst port) - 4 consecutive bytes. */
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof (uint16_t),
		.field_index = 3,
		.input_index = 3,
		.offset = offsetof (struct pkt_eth_ipv4_udp, udp_hdr.src_port),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof (uint16_t),
		.field_index = 4,
		.input_index = 3,
		.offset = offsetof (struct pkt_eth_ipv4_udp, udp_hdr.dst_port),
	},
};

struct pkt_qinq_ipv4_udp {
	struct qinq_hdr qinq_hdr;
	struct ipv4_hdr ipv4_hdr;
	struct udp_hdr udp_hdr;
};

static struct rte_acl_field_def pkt_qinq_ipv4_udp_defs[] = {
	/* first input field - always one byte long. */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof (uint8_t),
		.field_index = 0,
		.input_index = 0,
		.offset = offsetof (struct pkt_qinq_ipv4_udp, ipv4_hdr.next_proto_id),
	},
	/* IPv4 source address. */
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof (uint32_t),
		.field_index = 1,
		.input_index = 1,
		.offset = offsetof (struct pkt_qinq_ipv4_udp, ipv4_hdr.src_addr),
	},
	/* IPv4 destination address */
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof (uint32_t),
		.field_index = 2,
		.input_index = 2,
		.offset = offsetof (struct pkt_qinq_ipv4_udp, ipv4_hdr.dst_addr),
	},
	/* (L4 src/dst port) - 4 consecutive bytes. */
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof (uint16_t),
		.field_index = 3,
		.input_index = 3,
		.offset = offsetof (struct pkt_qinq_ipv4_udp, udp_hdr.src_port),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof (uint16_t),
		.field_index = 4,
		.input_index = 3,
		.offset = offsetof (struct pkt_qinq_ipv4_udp, udp_hdr.dst_port),
	},
	/* (SVLAN id + eth type) - 4 consecutive bytes. */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint16_t),
		.field_index = 5,
		.input_index = 4,
		.offset = offsetof (struct pkt_qinq_ipv4_udp, qinq_hdr.svlan.eth_proto),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint16_t),
		.field_index = 6,
		.input_index = 4,
		.offset = offsetof (struct pkt_qinq_ipv4_udp, qinq_hdr.svlan.vlan_tci),
	},
	/* (CVLAN id + eth type) - 4 consecutive byates. */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint16_t),
		.field_index = 7,
		.input_index = 5,
		.offset = offsetof (struct pkt_qinq_ipv4_udp, qinq_hdr.cvlan.eth_proto),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint16_t),
		.field_index = 8,
		.input_index = 5,
		.offset = offsetof (struct pkt_qinq_ipv4_udp, qinq_hdr.cvlan.vlan_tci),
	},
};

#endif /* _ACL_FIELD_DEF_H_ */
