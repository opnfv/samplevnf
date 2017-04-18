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
 *	@file
 *	L2 Protocol Handler
 *	Reads the packet from the interface and sets the
 *	masks for a burst of packets based on ethertype and
 *	calls the relevant function registered for that ethertype
 *
 */

#ifndef L2_PROTO_H
#define L2_PROTO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_eth_ctrl.h>
#include <interface.h>

/* Array indexes of proto_packet_type structure */
#define IPv4_VAL 0 /**< Array index for IPv4 */
#define ARP_VAL 1 /**< Array index for ARP */
#define IPv6_VAL 2 /**< Array index for IPv6 */

/* Enable to print L2_Proto debugs */
#define L2_PROTO_DBG 1 /**< Enable to print L2 Proto debugs */

/**
 * A structure used to call the function handlers for a certain ethertype
 */
struct proto_packet_type {
	uint16_t type;		/**< Ethertype	*/
	void (*func) (struct rte_mbuf **m, uint16_t nb_pkts, uint64_t pkt_mask, l2_phy_interface_t *port);  /**< Function pointer to the registered callback function */
} __rte_cache_aligned;/**< RTE Cache alignment */

/**
 * Function called from other modules to add the certain rx functions for particular ethertypes
 *
 * @param type
 * Ethertype
 * @param (*func)()
 * Function pointer to the function being registered by different modules
 */
void
list_add_type(uint16_t type,
				void (*func) (struct rte_mbuf **, uint16_t, uint64_t,
					l2_phy_interface_t *));

/**
 * Function to check whether the destination mac address of the packet is the mac address of the received port.
 * Drop the packet if it is not destined to the host.
 * If it is destined to this host, then set the packet masks for IPv4, IPv6 and ARP packet types for a burst of packets.
 *
 * @param m
 * rte_mbuf packet
 *
 * @param portid
 * Portid from which the packet was received
 *
 * @param pos
 * Index of the packet in the burst
 *
 * @param pkts_mask
 * Packet mask where bits are set at positions for the packets in the burst which were destined to the host
 *
 * @param arp_pkts_mask
 * Packet mask for ARP where bits are set for valid ARP packets
 *
 * @param ipv4_pkts_mask
 * Packet mask for IPv4 where bits are set for valid IPv4 packets
 *
 * @param ipv6_pkts_mask
 * Packet mask for IPv6 where bits are set for valid IPv6 packets
 *
 */
void
l2_check_mac(struct rte_mbuf *m[IFM_BURST_SIZE], l2_phy_interface_t *port,
			 uint8_t pos, uint64_t *pkts_mask, uint64_t *arp_pkts_mask,
			 uint64_t *ipv4_pkts_mask, uint64_t *ipv6_pkts_mask);

/**
 * Entry function to L2 Protocol Handler where appropriate functions are called for particular ethertypes
 *
 * @param m
 * rte_mbuf packet
 *
 * @param nb_rx
 * Number of packets read
 *
 * @param portid
 * Port-id of the port in which packet was received
 */
void
protocol_handler_recv(struct rte_mbuf *m[IFM_BURST_SIZE], uint16_t nb_rx,
					l2_phy_interface_t *port);

#endif
