/*
// Copyright (c) 2020 Intel Corporation
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

#ifndef _PROX_IP_V6_H_
#define _PROX_IP_V6_H_

#include "ip6_addr.h"

#define ALL_NODES_IPV6_MCAST_ADDR		"ff02:0000:0000:0000:0000:0000:0000:0001"	// FF02::1
#define ALL_ROUTERS_IPV6_MCAST_ADDR		"ff02:0000:0000:0000:0000:0000:0000:0002"	// FF02::2

#define RANDOM_IPV6				"1234:1234:1234:1234:1234:1234:1234:1234"	// Used by PROX as a flag forrandom IP

#define ALL_DHCP_RELAY_AGENTS_AND_SERVERS	"ff02:0000:0000:0000:0000:0000:0001:0002"	// FF02::1:2
#define ALL_DHCP_SERVERS			"ff05:0000:0000:0000:0000:0000:0001:0003"	// FF02::1:2

#define DHCP_CLIENT_UDP_PORT	546
#define DHCP_SERVER_UDP_PORT	547

#define PROX_UNSOLLICITED	0
#define PROX_SOLLICITED		1

#define ICMPv6	0x3a

#define ICMPv6_DU	0x01
#define ICMPv6_PTB	0x02
#define ICMPv6_TE	0x03
#define ICMPv6_PaPr	0x04
#define ICMPv6_RS	0x85
#define ICMPv6_RA	0x86
#define ICMPv6_NS	0x87
#define ICMPv6_NA	0x88
#define ICMPv6_RE	0x89

#define ICMPv6_source_link_layer_address	1
#define ICMPv6_target_link_layer_address	2
#define ICMPv6_prefix_information		3
#define ICMPv6_redirect_header			4
#define ICMPv6_mtu				5

extern struct ipv6_addr null_addr;

struct icmpv6_prefix_option {
	uint8_t type;
	uint8_t length;
	uint8_t prefix_length;
	uint8_t flag;
	uint32_t valid_lifetime;
	uint32_t preferred_lifetime;
	uint32_t reserved;
	struct ipv6_addr prefix;
};

struct icmpv6_option {
	uint8_t type;
	uint8_t length;
	uint8_t data[6];
}  __attribute__((__packed__));

struct icmpv6 {
	uint8_t   type;
	uint8_t   code;
	uint16_t  checksum;
};

struct icmpv6_RA {
	uint8_t   type;
	uint8_t   code;
	uint16_t  checksum;
	uint8_t   hop_limit;
	uint8_t   bits;
	uint16_t  router_lifespan;
	uint32_t  reachable_timeout;
	uint32_t  retrans_timeout;
	struct icmpv6_option  options;
} __attribute__((__packed__));

struct icmpv6_RS {
	uint8_t   type;
	uint8_t   code;
	uint16_t  checksum;
	uint32_t  reserved;
	struct icmpv6_option  options;
} __attribute__((__packed__));

struct icmpv6_NS {
	uint8_t   type;
	uint8_t   code;
	uint16_t  checksum;
	uint32_t  reserved;
	struct ipv6_addr target_address;
	struct icmpv6_option  options;
} __attribute__((__packed__));

struct icmpv6_NA {
	uint8_t   type;
	uint8_t   code;
	uint16_t  checksum;
	uint16_t  bits;
	uint16_t  reserved;
	struct ipv6_addr destination_address;
	struct icmpv6_option  options;
} __attribute__((__packed__));

struct icmpv6_RE {
	uint8_t   type;
	uint8_t   code;
	uint16_t  checksum;
	uint32_t  reserved;
	struct ipv6_addr destination_address_hop;
	struct ipv6_addr destination_address;
	uint32_t  Options;
} __attribute__((__packed__));

void set_mcast_mac_from_ipv6(prox_rte_ether_addr *mac, struct ipv6_addr *ipv6_addr);
char *IP6_Canonical(struct ipv6_addr *addr);
void set_link_local(struct ipv6_addr *ipv6_addr);
void set_EUI(struct ipv6_addr *ipv6_addr, prox_rte_ether_addr *mac);
void create_mac_from_EUI(struct ipv6_addr *ipv6_addr, prox_rte_ether_addr *mac);

struct task_base;
void build_router_sollicitation(struct rte_mbuf *mbuf, prox_rte_ether_addr *s_addr, struct ipv6_addr *ipv6_s_addr);
void build_router_advertisement(struct rte_mbuf *mbuf, prox_rte_ether_addr *s_addr, struct ipv6_addr *ipv6_s_addr, struct ipv6_addr *router_prefix);
void build_neighbour_sollicitation(struct rte_mbuf *mbuf, prox_rte_ether_addr *s_addr, struct ipv6_addr *dst, struct ipv6_addr *src);
void build_neighbour_advertisement(struct task_base *tbase, struct rte_mbuf *mbuf, prox_rte_ether_addr *target_mac, struct ipv6_addr *ipv6_addr, int sollicited);

#endif /* _PROX_IP_V6_H_ */
