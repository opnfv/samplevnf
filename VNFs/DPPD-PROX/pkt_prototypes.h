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

#ifndef _PKT_PROTOTYPES_H_
#define _PKT_PROTOTYPES_H_

#include <rte_ip.h>

#include "gre.h"
#include "qinq.h"
#include "etypes.h"

static const struct gre_hdr gre_hdr_proto = {
	.type = ETYPE_IPv4,
	.version = 0,
	.flags = 0,
	.recur = 0,
	.bits = GRE_KEY_PRESENT
};

static const struct ipv4_hdr tunnel_ip_proto = {
	.version_ihl = 0x45,
	.type_of_service = 0,
	.packet_id = 0,
	.fragment_offset = 0x40,
	/* no fragmentation */
	.time_to_live = 0x40,
	/* gre protocol type */
	.next_proto_id = IPPROTO_GRE,
	.hdr_checksum = 0
};

static const struct qinq_hdr qinq_proto = {
	.svlan.vlan_tci = 0,
	.cvlan.vlan_tci = 0,
	.svlan.eth_proto = ETYPE_8021ad,
	.cvlan.eth_proto = ETYPE_VLAN,
	.ether_type = ETYPE_IPv4
};

#endif /* _PKT_PROTOTYPES_H_ */
