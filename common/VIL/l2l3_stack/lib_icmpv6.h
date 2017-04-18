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
/*	Author - Santosh Sethupathi	*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_table_lpm.h>
#include <rte_table_hash.h>
#include <rte_pipeline.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include "lib_arp.h"
#include <rte_pipeline.h>
#include "rte_ether.h"

/**
* ICMPv6 Header
*/

struct icmpv6_hdr {
	uint8_t icmpv6_type;	/**< ICMPV6 packet type. */
	uint8_t icmpv6_code;	/**<  ICMPV6 packet code. */
	uint16_t icmpv6_cksum;	/**< ICMPV6 packet checksum. */
} __attribute__ ((__packed__));

/**
* ICMPV6 Info Header
*/
struct icmpv6_info_hdr {
	uint16_t icmpv6_ident;	/**< ICMPV6 packet identifier. */
	uint16_t icmpv6_seq_nb;	/**< ICMPV6 packet sequence number. */
} __attribute__ ((__packed__));

/**
 * ICMPV6 ND Header
 */
struct icmpv6_nd_hdr {
	/*ND Advertisement flags */
	uint32_t icmpv6_reserved; /**< bit31-Router, bit30-Solicited, bit29-Override, bit28-bit0 unused */

	uint8_t target_ipv6[16];  /**< target IPv6 address */
	uint8_t type;			/**< ICMPv6 Option*/
	uint8_t length;		 /**< Length */
	uint8_t link_layer_addr[6]; /**< Link layer address */
} __attribute__ ((__packed__));

/* Icmpv6 types */
#define ICMPV6_PROTOCOL_ID 58
#define ICMPV6_ECHO_REQUEST 0x0080
#define ICMPV6_ECHO_REPLY 0x0081
#define ICMPV6_NEIGHBOR_SOLICITATION 0x0087
#define ICMPV6_NEIGHBOR_ADVERTISEMENT 0x0088
#define IPV6_MULTICAST 0xFF02

#define NEIGHBOR_SOLICITATION_SET 0x40000000
#define NEIGHBOR_ROUTER_OVERRIDE_SET 0xa0000000
enum icmpv6_link_layer_Address_type {
	e_Source_Link_Layer_Address = 1,
	e_Target_Link_Layer_Address,
	e_Link_Layer_Address
};

/* Checks whether ipv6 is multicast
 * @param ipv6
 */
uint8_t is_multicast_ipv6_addr(uint8_t ipv6[]);

/**
*Icmpv6 Port address
*/
struct icmpv6_port_address {
	uint32_t ipv6[16];   /**< Ipv6 address */
	uint64_t mac_addr;   /**< Mac address */
};

/**
* To store Icmpv6 Port address
*/
struct icmpv6_port_address icmpv6_port_addresses[RTE_MAX_ETHPORTS];

#define MAX_NUM_ICMPv6_ENTRIES 64
struct rte_mbuf *lib_icmpv6_pkt;

/**
 * Processes icmpv6 packets
 * @param pkt
 *  pkt mbuf packets
 * @param port
 *  port - port structure
 */
void process_icmpv6_pkt(struct rte_mbuf *pkt, l2_phy_interface_t *port);
