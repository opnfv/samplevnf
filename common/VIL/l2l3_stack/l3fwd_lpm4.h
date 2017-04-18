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
* L3fwd lpm4 header file is for IPv4 specific declarations
*/
#ifndef L3FWD_LPM_H
#define L3FWD_LPM_H

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
#include <rte_memory.h>
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
#include "l3fwd_common.h"
#include "l3fwd_lpm6.h"
#include "interface.h"

/**
* Define all RTE MBUF offset size
*/

#define MBUF_HDR_ROOM 256 /**< MBUF HEADER ROOM OFFSET */

/* IPv4 */
#define ETH_HDR_SIZE  14 /**< ETHER HEADER OFFSET */
#define IP_HDR_SIZE  20	/**< IP HEADER OFFSET */
#define IP_HDR_DST_ADR_OFST 16 /**< IP HEADER DST IP ADDRESS OFFSET */
#define IP_HDR_SRC_ADR_OFST 12 /**< IP HEADER SRC IP ADDRESS OFFSET */

/* Rules and Tables8s */
#define IPV4_L3FWD_LPM_MAX_RULES      256  /**< Number of LPM RULES */
#define IPV4_L3FWD_LPM_NUMBER_TBL8S (1 <<  8) /**< Number of TABLE 8s for LPM */
#define MAX_FIB_PATHS 8	/**< MAX FIB PATH, If ECMP feature is enabled */
#define IP_LOCAL 0 /**< for ICMP Packet destined to Local */
#define IP_REMOTE 1 /**< for ICMP Packet destined to Local */

/* ECMP MACROS */
#define MAX_SUPPORTED_FIB_PATHS 8 /**< for ECMP max supported FIB Paths */
#define HASH_BUCKET_SIZE 64  /**< size of HASH bucket for ECMP */

/* L2 Adjacency Macro */
#define L2_ADJ_RESOLVED   0x00	/** <MACRO to define a flag as Resolved*/
#define L2_ADJ_UNRESOLVED 0x01	/** <MacrO to define a flag as Unresolved */
/**
* A structure used to define the routing information for IPv4
* This structure is used as input parameters for route ADD
*/
struct routing_info {
	uint32_t dst_ip_addr;  /**< DST IP Address */
	uint8_t depth;				 /**< Depth */
	uint32_t metric;       /**< Metrics */
	uint32_t fib_nh_size; /**< num of fib paths, greater than if Multipath(ECMP) feature is supported*/
	uint32_t nh_ip_addr[MAX_FIB_PATHS];   /**< NextHop IP Address */
	uint8_t out_port[MAX_FIB_PATHS];      /**< OUTGOING PORT */
} __rte_cache_aligned;

/**
* A structure used to define the fib path for Destination IP Address
* This fib path is shared accross different fib_info.
*/
struct fib_path {
	uint32_t nh_ip;		/**< Next hop IP address (only valid for remote routes) */
	uint8_t out_port;	/**< Output port */
	uint32_t refcount;	/**< Refcount, greater then 1 if multiple fib_info has same fib_path*/
	struct l2_adj_entry *l2_adj_ptr; /**< Address of the L2 ADJ table entry */
} __rte_cache_aligned;				 /**< RTE CACHE ALIGNED */

/**
* A structure used to define the fib info (Route info)
* This fib info structure can have multiple fib paths.
*/
struct fib_info {
	uint32_t dst_ip_addr; /**< DST IP Address */
	uint32_t metric;      /**< Metrics */
	uint32_t fib_nh_size; /**< num of fib paths, greater than if Multipath(ECMP) feature is supported*/
	uint8_t depth;				/**< Depth */
	struct fib_path *path[MAX_FIB_PATHS]; /**< Array of pointers to the fib_path */
} __rte_cache_aligned;				/**< RTE CACHE ALIGNED */

/**
* A structure used to define the L2 Adjacency table
*/
struct l2_adj_entry {
	struct ether_addr eth_addr;    /**< Ether address */
	uint32_t Next_hop_ip;				 /**< Next hop IP address (only valid for remote routes) */
	uint8_t out_port_id;				 /**< Output port */
	uint32_t refcount;				 /**< Refcount, greater then 1 if multiple fib_path has same L2_adj_entry*/
	uint8_t l2_string[256];				 /**< L2 string, to rewrite the packet before transmission */
	l2_phy_interface_t *phy_port;  /**<  Address of the L2 physical interface structure */
	uint8_t flags;					 /**< Set to unresolved, when ARP entry not available. Set to resolved, when ARP is available */
} __rte_cache_aligned;					 /**< RTE CACHE ALIGNED */

/**
* A structure used to define the fib path key for hash table
*/
struct fib_path_key_ipv4 {
	uint32_t nh_ip;			/**< Next hop IP address */
	uint8_t out_port;   /**< Output port */
	uint8_t filler1;    /**< Filler 1, for better hash key */
	uint8_t filler2;    /**< Filler2, for better hash key*/
	uint8_t filler3;    /**< Filler3, for better hash Key */
};

/**
* A structure used to define the fib path key for hash table
*/
struct l2_adj_key_ipv4 {
	uint32_t Next_hop_ip;	/**< Next hop IP address */
	uint8_t out_port_id;	/**< Output port */
	uint8_t filler1;	/**< Filler 1, for better hash key */
	uint8_t filler2;	/**< Filler2, for better hash key*/
	uint8_t filler3;	/**< Filler3, for better hash Key */
};

/**
* A structure used to hold the fib info after LPM Lookup
*/
struct routing_table_entry {
	uint32_t ip;			 /**< Next hop IP address (only valid for remote routes) */
	uint8_t port_id;		 /**< Output port ID */
	struct l2_adj_entry *l2_adj_ptr; /**< Address of L2 Adjacency table entry */
} __rte_cache_aligned;			 /**< RTE CACHE ALIGNED */

/**
* A structure used to define the L3 counter statistics
*/
typedef struct l3fwd_stats {
	uint64_t nb_rx_l3_pkt;		/**< Num of L3 pkts Received */
	uint64_t nb_tx_l3_pkt;		/**< Num of L3 pkts Transmitted */
	uint64_t nb_rx_l3_icmp_pkt;
					/**< Num of ICMP pkts Received at L3*/
	uint64_t nb_tx_l3_icmp_pkt;
					/**< Num of ICMP pkts Transmitted at L3*/
	uint64_t nb_l3_drop_pkt;  /**< Num of L3 Packets Dropped*/
	uint64_t total_nb_rx_l3_pkt;
					/**< Total Num of L3 Packets received, includes ICMP Pkt*/
	uint64_t total_nb_tx_l3_pkt;
					/**< Total Num of L3 Packets Transmitted, includes ICMP Pkt*/
} l3_stats_t;

struct ip_protocol_type {
	uint8_t protocol_type;		/**< Protocol Type */
	void (*func) (struct rte_mbuf **, uint16_t, uint64_t,
					l2_phy_interface_t *);
} __rte_cache_aligned;

/* Function Declarations */

/**
 * To creare LPM table, Cuckoo hash table for fib_path and l2_adj_entry tables
 * @return
 * 0 for failure, 1 for success
 */
int lpm_init(void);

/**
 * To add a route in LPM table by populating fib_path and L2 Adjacency.
 * @param input_array
 * To add the route based on routing_info stucture.
 * @return
 * 0 for failure, 1 for success
 */
int lpm4_table_route_add(struct routing_info *input_array);

/**
 * To Delete the IP route and corresponding fib_path and L2 Adjacency entries.
 * @param ip
 * Destionation IP for which the route need to deleted
 * @param depth
 * netmask for the Destination IP
 * @return
 * 0 for failure, 1 for success
 */
int lpm4_table_route_delete(uint32_t ip, uint8_t depth);

/**
 * To perform a LPM table lookup
 * @param pkts_burst
 * Burst of packets that needs to be lookup in LPM table
 * @param nb_pkts
 * number of packets that needs to be lookup in LPM table
 * @param valid_pkts_mask
 * lookup of the valid IPv4 Pkt mask
 * @return
 * 0 for failure, 1 for success
 */
int lpm4_table_lookup(struct rte_mbuf **pkts_burst, uint16_t nb_pkts,
					uint64_t valid_pkts_mask,
					l2_phy_interface_t *port[RTE_PORT_IN_BURST_SIZE_MAX],
					uint64_t *hit_mask);

/**
 * To Verify whether the received IPv4 Packet is valid or not
 * @param pkt
 * packet pointing to IPv4 header that needs to be verifed
 * @param link_len
 * length of the IPv4 Pkt
 * @return
 * 0 for failure, 1 for success
*/
int is_valid_ipv4_pkt(struct ipv4_hdr *pkt, uint32_t link_len);

/**
 * To forward the valid L3 packets for LMP table lookup and forward ICMP Pkts to ICMP module
 * @param m
 * packet burst of type rte_mbuf
 * @param nb_pkts
 * Number of valid L3 packets
 * @param pkt_mask
 * Valid IPv4 packets mask that needs to be processed
 * @param port
 * IPv4 Pkt received form the input port structure.
 * @return
 * 0 for failure, 1 for success
*/
void l3fwd_rx_ipv4_packets(struct rte_mbuf **m, uint16_t nb_pkts,
				 uint64_t pkt_mask, l2_phy_interface_t *port);

/**
 * To get the destination MAC Address for the nexthop IP and outgoing port
 * @param next_hop_ip
 * Next HOP IP Address for which MAC address is needed
 * @param out_phy_port
 * Outgoing physical port
 * @param hw_addr
 * pointer to the ether_add, This gets update with valid MAC address based on nh_ip and out port
 * @return
 * 0 if failure, 1 if success
 */
int get_dest_mac_for_nexthop(uint32_t next_hop_ip,
					 uint8_t out_phy_port, struct ether_addr *hw_addr);
/**
 * To retrieve the l2_adj_entry for the nexthop IP and outgoing port
 * This queries with cuckoo hash table based on the l2_adj_key_ipv4
 * @param l2_adj_key
 * Key which is required for Cuckook hash table lookup
 * @return
 * NULL if lookup fails, Address of the L2_adj_entry if lookup success
*/

struct l2_adj_entry *retrieve_l2_adj_entry(struct l2_adj_key_ipv4 l2_adj_key);

/**
 * To populate the l2_adj_entry for the nexthop IP and outgoing port
 * @param ipaddr
 * NextHop Ip Address for which L2_adj_entry needs to be populated
 * @param portid
 * outgong port ID
 * @return
 * NULL if lookup fails, Address of the L2_adj_entry if lookup success
*/

struct l2_adj_entry *populate_l2_adj(uint32_t ipaddr, uint8_t portid);

/**
 * To populate the fib_path for the nexthop IP and outgoing port
 * @param nh_ip
 * NextHop Ip Address for which L2_adj_entry needs to be populated
 * @param portid
 * outgong port ID
 * @return
 * NULL if lookup fails, Address of the type fib_path if lookup success
*/
struct fib_path *populate_fib_path(uint32_t nh_ip, uint8_t portid);

/**
 * To retrieve the fib_path entry for the nexthop IP and outgoing port
 * This queries with cuckoo hash table based on the fib_path_key_ipv4
 * @param path_key
 * Key which is required for Cuckook hash table lookup
 * @return
 * NULL if lookup fails, Address of type fib_path if lookup success
*/

struct fib_path *retrieve_fib_path_entry(struct fib_path_key_ipv4 path_key);

/**
 * To delete the fib path and l2 adjacency entry from the cuckoo hash table
 * @return
 * None
*/
void remove_fib_l2_adj_entry(void *);

/**
 * To iterate the cuckoo hash table for fib_path and l2_adj_entry and print the table contents
 * @return
 * None
*/
void iterate_cuckoo_hash_table(void);

/**
 * To print the l3 counter statitics
 * @return
 * None
*/
void print_l3_stats(void);

/**
 * To get the hash resultant value based on SRC IP and DST IP
 * @param mbuf
 * packet of type rte_mbuf
 * @return
 * It returns a result of type uint8_t
 */

uint8_t ip_hash_load_balance(struct rte_mbuf *mbuf);

/**
 * Rotates the count number of bits from the value
 * @param value
 * an integer value
 * @param count
 * rotates a count number of bits from integer value
 * @return
 * It returns a result.
 */

uint32_t rotr32(uint32_t value, unsigned int count);

void
resolve_l2_adj(uint32_t nexthop_ip, uint8_t out_port_id,
				 const struct ether_addr *hw_addr);

void
l3_protocol_type_add(uint8_t protocol_type,
				 void (*func) (struct rte_mbuf **, uint16_t, uint64_t,
					 l2_phy_interface_t *));

void
ip_local_packets_process(struct rte_mbuf **, uint16_t, uint64_t,
			 l2_phy_interface_t *);
void ip_local_out_deliver(struct rte_mbuf **, uint16_t, uint64_t,
				l2_phy_interface_t *);

void
ip_forward_deliver(struct rte_mbuf **, uint16_t, uint64_t,
			 l2_phy_interface_t *);

#endif				/* L3FWD_LPM_H */
