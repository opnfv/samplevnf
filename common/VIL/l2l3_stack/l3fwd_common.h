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
* L3fwd common header file for LPM IPv4 and IPv6 stack initialization
*/

#ifndef L3FWD_COMMON_H
#define L3FWD_COMMON_H

/* Standard Libraries */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <getopt.h>
#include <unistd.h>

/* DPDK RTE Libraries */
#include <rte_common.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_port.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
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
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_table_hash.h>
#include <rte_table.h>
#include <rte_table_lpm.h>
#include <rte_string_fns.h>
#include <rte_cpuflags.h>
#include <l3fwd_lpm4.h>
#include <l3fwd_lpm6.h>
#include <rte_table_lpm_ipv6.h>

/**
* Define the Macros
*/
#define MAX_ROUTES 4		 /**< MAX route that can be added*/
#define L3FWD_DEBUG 1		 /**< if set, enables the fast path logs */
#define MULTIPATH_FEAT 1   /**< if set, enables the ECMP Multicast feature */

//#define IPPROTO_ICMPV6 58 /**< Protocol ID for ICMPv6 */

/**
* L3fwd initilazation for creating IPv4 and IPv6 LPM table.
*/
void l3fwd_init(void);

/**
* L3fwd IPv4 LPM table population, it calls IPv4 route add function which stores all the route in LPM table
*/
void populate_lpm4_table_routes(void);

/**
* L3fwd IPv6 LPM table population, it calls IPv6 route add function which stores all the route in LPM6 table
*/
void populate_lpm6_table_routes(void);

/**
* L3fwd LPM table population for both IPv4 and IPv6.
*/
void populate_lpm_routes(void);

#endif
