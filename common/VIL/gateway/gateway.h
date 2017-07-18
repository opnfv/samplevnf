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

#ifndef __INCLUDE_GATEWAY_H__
#define __INCLUDE_GATEWAY_H__

/**
 * @file
 * gateway.h
 *
 * Provide APIs for Packet fowarding in gateway configuration.
 *
 */

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>

#include "pipeline.h"
#include "app.h"
#include "vnf_common.h"
#include "vnf_define.h"

/**
* A structure for Route table entries of IPv4
*/
#define MAX_ROUTE_ENTRY_SIZE	32
#define MAX_ND_ROUTE_ENTRY_SIZE 32

extern struct route_data *p_route_data[];
extern struct nd_route_data *p_nd_route_data[];

extern uint32_t vnf_gateway;

/**
 * A structure for Route table entires of IPv4
 *
 */
struct route_table_entry {
	uint32_t nh;	/**< next hop */
	uint32_t mask;	/**< mask */
	uint32_t port;	/**< Physical port */
	uint32_t nh_mask;
} __rte_cache_aligned;

/**
 * Routing table for IPv4
 *
 */
struct route_data {
	struct route_table_entry route_table[MAX_ROUTE_ENTRY_SIZE];
	uint8_t route_ent_cnt;
};

/**
 * A structure for Route table entires of IPv6
 *
 */
struct nd_route_table_entry {
	uint8_t nhipv6[16];	/**< next hop Ipv6 */
	uint8_t depth;		/**< Depth */
	uint32_t port;		/**< Port */
};

/**
 * Routing table for IPv6
 *
 */
struct nd_route_data {
	struct nd_route_table_entry nd_route_table[MAX_ND_ROUTE_ENTRY_SIZE];
	uint8_t nd_route_ent_cnt;
};

extern void gw_init(uint32_t num_ports);

extern uint32_t gw_get_num_ports(void);

extern uint32_t is_gateway(void);

extern void gw_get_nh_port_ipv4(uint32_t dst_ip_addr,
					uint32_t *dst_port, uint32_t *nhip);

extern void gw_get_nh_port_ipv6(uint8_t *dst_ipv6_addr,
					uint32_t *dst_port, uint8_t *nhipv6);

#endif
