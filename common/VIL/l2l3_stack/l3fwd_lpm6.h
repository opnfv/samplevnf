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

/**
* @file
* L3fwd lpm6 header file is for IPv6 specific declarations
*/

#ifndef L3FWD_LPM6_H
#define L3FWD_LPM6_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_table_lpm_ipv6.h>
#include "l3fwd_common.h"
#include "l3fwd_lpm4.h"
#include "interface.h"

/**
* Define all RTE MBUF offset size
*/

#define MBUF_HDR_ROOM 256			/**< MBUF HEADER ROOM OFFSET */
/* IPv6 */
#define IP_HDR_SIZE_IPV6  40			/**< IPv6 HEADER OFFSET */
#define IP_HDR_SRC_ADR_OFST_IPV6 8  /**< IPv6 HEADER SRC IP ADDRESS OFFSET */
#define IP_HDR_DST_ADR_OFST_IPV6 24 /**< IPv6 HEADER DST IP ADDRESS OFFSET */

/* IPV6 Rules and Tables8s */
#define IPV6_L3FWD_LPM_MAX_RULES         1024  /**< Number of LPM6 Rules*/
#define IPV6_L3FWD_LPM_NUMBER_TBL8S (1 << 16)  /**< Number of Table 8 for LPM6 */

#define MAX_FIB_PATHS 8	/**< MAX FIB PATH, If ECMP feature is enabled */

/**
* A structure used to define the routing information for IPv6
* This structure is used as input parameters for route ADD
*/
struct ipv6_routing_info {
	uint8_t dst_ipv6[RTE_LPM_IPV6_ADDR_SIZE];  /**< DST IPv6 Address */
	uint8_t depth;					 /**< Depth */
	uint32_t metric;				 /**< Metrics */
	uint32_t fib_nh_size; /**< num of fib paths, greater than if Multipath(ECMP) feature is supported*/
	uint8_t nh_ipv6[MAX_FIB_PATHS][RTE_LPM_IPV6_ADDR_SIZE];		/**< NextHop IP Address */
	uint8_t out_port[MAX_FIB_PATHS];				/**< OUTGOING PORT */
} __rte_cache_aligned;					 /**< RTE CACHE ALIGNED */

/**
* A structure used to define the fib path for Destination IPv6 Address
* This fib path is shared accross different fib_info.
*/
struct ipv6_fib_path {
	uint8_t nh_ipv6[RTE_LPM_IPV6_ADDR_SIZE];  /**< Next hop IP address (only valid for remote routes) */
	uint32_t refcount;				/**< Refcount, greater then 1 if multiple fib_info has same fib_path*/
	uint8_t out_port;				/**< Output port */
	struct l2_adj_ipv6_entry *l2_adj_ipv6_ptr;/**< Address of the L2 ADJ table entry */
} __rte_cache_aligned;					/**< RTE CACHE ALIGNED */

/**
* A structure used to define the fib info (Route info)
* This fib info structure can have multiple fib paths.
*/
struct ipv6_fib_info {
	uint8_t dst_ipv6[RTE_LPM_IPV6_ADDR_SIZE]; /**< DST IPv6 Address */
	uint8_t depth;					/**< Depth */
	uint32_t metric;				/**< Metric */
	uint32_t fib_nh_size;			/**< num of fib paths, greater than if Multipath(ECMP) feature is supported*/
	struct ipv6_fib_path *path[MAX_FIB_PATHS]; /**< Array of pointers to the fib_path */
} __rte_cache_aligned;					/**< RTE CACHE ALIGNED */

/**
* A structure used to define the L2 Adjacency table
*/
struct l2_adj_ipv6_entry {
	struct ether_addr eth_addr;		 /**< Ether address */
	uint8_t out_port_id;			 /**< Outgoing port */
	uint8_t nh_ipv6[RTE_LPM_IPV6_ADDR_SIZE]; /**< Next hop IP address (only valid for remote routes) */
	uint32_t refcount;			/**< Refcount, greater then 1 if multiple fib_path has same L2_adj_entry*/
	uint8_t l2_string[256];			 /**< L2 string, to rewrite the packet before transmission */
	l2_phy_interface_t *phy_port;  /**<  Address of the L2 physical interface structure */
	uint8_t flags;			/**< flags for marking this entry as resolved or unresolved. */
} __rte_cache_aligned;						/**< RTE CACHE ALIGNED */

/**
* A structure used to define the L2 Adjacency table
*/
struct l2_adj_key_ipv6 {
	/*128 Bit of IPv6 Address */
	/*<48bit Network> <16bit Subnet> <64bit Interface> */
	uint8_t nh_ipv6[RTE_LPM_IPV6_ADDR_SIZE]; /**< Next hop IPv6 address */
	uint8_t out_port_id;			 /**< Outgoing port */
	uint8_t filler1;    /**< Filler 1, for better hash key */
	uint8_t filler2;    /**< Filler2, for better hash key*/
	uint8_t filler3;    /**< Filler3, for better hash Key */
};

/**
* A structure used to define the fib path key for hash table
*/
struct fib_path_key_ipv6 {
	/*128 Bit of IPv6 Address */
	/*<48bit Network> <16bit Subnet> <64bit Interface> */
	uint8_t nh_ipv6[RTE_LPM_IPV6_ADDR_SIZE];  /**< Next hop IPv6 address */
	uint8_t out_port;				/**< Outgoing port */
	uint8_t filler1;    /**< Filler 1, for better hash key */
	uint8_t filler2;    /**< Filler2, for better hash key*/
	uint8_t filler3;    /**< Filler3, for better hash Key */
};

struct ipv6_protocol_type {
	uint8_t protocol_type;		/**< Protocol Type */
	void (*func) (struct rte_mbuf **, uint16_t, uint64_t,
					l2_phy_interface_t *);
} __rte_cache_aligned;

/* Function Declarations */
/**
 * To creare LPM6 table, Cuckoo hash table for fib_path and l2_adj_entry tables
 * @return
 * 0 for failure, 1 for success
 */
int lpm6_init(void);

/**
 * To add a route in LPM6 table by populating fib_path and L2 Adjacency.
 * @param data
 * To add the route based on ipv6_routing_info stucture.
 * @return
 * 0 for failure, 1 for success
 */
int lpm6_table_route_add(struct ipv6_routing_info *data);

/**
 * To Delete the IP route and corresponding fib_path and L2 Adjacency entries.
 * @param dst_ipv6
 * Destionation IPv6 for which the route need to deleted
 * @param depth
 * netmask for the Destination IP
 * @return
 * 0 for failure, 1 for success
 */
int lpm6_table_route_delete(uint8_t dst_ipv6[RTE_LPM_IPV6_ADDR_SIZE],
					uint8_t depth);

/**
 * To perform a LPM6 table lookup
 * @param pkts_burst
 * Burst of packets that needs to be lookup in LPM6 table
 * @param nb_pkts
 * Number of valid L3 packets
 * @param pkts_mask
 * number of valid pkts mask that needs to be lookup in LPM6 table
 * @return
 * 0 for failure, 1 for success
 */
int lpm6_table_lookup(struct rte_mbuf **pkts_burst, uint16_t nb_pkts,
					uint64_t pkts_mask,
					l2_phy_interface_t *port_ptr[RTE_PORT_IN_BURST_SIZE_MAX],
					uint64_t *hit_mask);

/**
 * To forward the valid L3 packets for LMP6 table lookup and forward ICMP Pkts to ICMP module
 * @param m
 * packet burst of type rte_mbuf
 * @param nb_pkts
 * Number of valid L3 packets
 * @param valid_pkts_mask
 * Valid IPv6 packets mask that needs to be processed
 * @param in_port
 * IPv6 Pkt received form the input port.
 * @return
 * None
 */
void l3fwd_rx_ipv6_packets(struct rte_mbuf **m, uint16_t nb_pkts,
				 uint64_t valid_pkts_mask,
				 l2_phy_interface_t *in_port);

/**
 * To populate the fib_path for the nexthop IPv6 and outgoing port
 * @param nh_ipv6
 * NextHop Ip Address for which L2_adj_entry needs to be populated
 * @param out_port
 * outgong port ID
 * @return
 * NULL if lookup fails, Address of the type ipv6_fib_path if lookup success
*/
struct ipv6_fib_path *populate_ipv6_fib_path(uint8_t
							 nh_ipv6[RTE_LPM_IPV6_ADDR_SIZE],
							 uint8_t out_port);

/**
 * To retrieve the fib_path entry for the nexthop IP and outgoing port
 * This queries with cuckoo hash table based on the fib_path_key_ipv4
 * @param path_key
 * Key which is required for Cuckook hash table lookup
 * @return
 * NULL if lookup fails, Address of type ipv6_fib_path if lookup success
*/
struct ipv6_fib_path *retrieve_ipv6_fib_path_entry(struct fib_path_key_ipv6
							 path_key);

/**
 * To retrieve the l2_adj_entry for the nexthop IP and outgoing port
 * This queries with cuckoo hash table based on the l2_adj_key_ipv6
 * @param l2_adj_key
 * Key which is required for Cuckook hash table lookup
 * @return
 * NULL if lookup fails, Address of type l2_adj_ipv6_entry if lookup success
*/
struct l2_adj_ipv6_entry *retrieve_ipv6_l2_adj_entry(struct l2_adj_key_ipv6
								 l2_adj_key);

/**
 * To populate the l2_adj_entry for the nexthop IP and outgoing port
 * @param nh_ip
 * NextHop Ip Address for which L2_adj_entry needs to be populated
 * @param portid
 * outgong port ID
 * @return
 * NULL if lookup fails, Address of the L2_adj_ipv6_entry if lookup success
*/
struct l2_adj_ipv6_entry *populate_ipv6_l2_adj(uint8_t
								 nh_ip[RTE_LPM_IPV6_ADDR_SIZE],
								 uint8_t portid);

/**
 * To get the destination MAC Address for the nexthop IP and outgoing port
 * @param nh_ipv6
 * Next HOP IP Address for which MAC address is needed
 * @param out_phy_port
 * Outgoing physical port
 * @param hw_addr
 * pointet to the ether_add, This gets update with valid MAC address based on nh_ip and out port
 * @return
 * 0 if failure, 1 if success
 */
int get_dest_mac_for_nexthop_ipv6(uint8_t nh_ipv6[RTE_LPM_IPV6_ADDR_SIZE],
					uint32_t out_phy_port,
					struct ether_addr *hw_addr);

/**
 * To delete the ipv6 fib path and l2 adjacency entry from the cuckoo hash table
 * @return
 * None
*/
void remove_ipv6_fib_l2_adj_entry(void *entry);

void
ipv6_l3_protocol_type_add(uint8_t protocol_type,
				void (*func) (struct rte_mbuf **, uint16_t, uint64_t,
					l2_phy_interface_t *));

void
ipv6_local_deliver(struct rte_mbuf **, uint16_t, uint64_t,
			 l2_phy_interface_t *);

void
ipv6_forward_deliver(struct rte_mbuf **, uint16_t, uint64_t,
				 l2_phy_interface_t *);

int is_valid_ipv6_pkt(struct ipv6_hdr *pkt, uint32_t link_len);
uint8_t ipv6_hash_load_balance(struct rte_mbuf *mbuf);

/**
 * To resolve l2_adj_entry based on nexthop IP, outgoing port and ether hw address.
 * @param nh_ip
 * NextHop Ip Address for which L2_adj_entry needs to be resolved
 * @param portid
 * outgong port ID
 * @hw_addr
 * Ethernet hardware address for the above nexthop IP and out port ID.
 * @return
 * Return is void.
*/

void resolve_ipv6_l2_adj(uint8_t nh_ip[RTE_LPM_IPV6_ADDR_SIZE], uint8_t portid,
			 struct ether_addr *hw_addr);

void ipv6_iterate__hash_table(void);
#endif				/* L3FWD_LPM_H */
