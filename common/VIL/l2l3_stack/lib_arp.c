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

#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_table_lpm.h>
#include <rte_table_hash.h>
#include <rte_pipeline.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <tsx.h>
#include "interface.h"
#include "l2_proto.h"
#include "lib_arp.h"
#include "l3fwd_lpm4.h"
#include "vnf_common.h"

#if (RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN)
#define CHECK_ENDIAN_16(x) rte_be_to_cpu_16(x)
#define CHECK_ENDIAN_32(x) rte_be_to_cpu_32(x)
#else
#define CHECK_ENDIAN_16(x) (x)
#define CHECK_ENDIAN_32(x) (x)
#endif

#define NB_ARPICMP_MBUF  64
#define NB_NDICMP_MBUF  64
#define IP_VERSION_4 0x40
#define IP_HDRLEN  0x05		/**< default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION_4 | IP_HDRLEN)
#define MAX_POOL		32
#define is_multicast_ipv4_addr(ipv4_addr) \
	(((rte_be_to_cpu_32((ipv4_addr)) >> 24) & 0x000000FF) == 0xE0)

extern uint8_t prv_in_port_a[PIPELINE_MAX_PORT_IN];
extern uint32_t timer_lcore;
extern int USE_RTM_LOCKS;
uint32_t arp_timeout = ARP_TIMER_EXPIRY;
uint32_t arp_buffer = ARP_BUF_DEFAULT;
uint32_t nd_buffer = ARP_BUF_DEFAULT;

/*ND IPV6 */
#define INADDRSZ 4
#define IN6ADDRSZ 16
#define MAX_PORTS	32

int my_inet_pton_ipv6(int af, const char *src, void *dst);
static int inet_pton_ipv6(const char *src, unsigned char *dst);
static int inet_pton_ipv4(const char *src, unsigned char *dst);
static void local_arp_cache_init(void);
struct ether_addr *get_nd_local_link_hw_addr(uint8_t out_port, uint8_t nhip[]);
extern void convert_prefixlen_to_netmask_ipv6(uint32_t depth,
								uint8_t netmask_ipv6[]);

uint8_t vnf_common_arp_lib_init;
uint8_t vnf_common_nd_lib_init;
uint8_t loadb_pipeline_count;

uint32_t ARPICMP_DEBUG;
uint32_t NDIPV6_DEBUG;

uint32_t arp_route_tbl_index;
uint32_t nd_route_tbl_index;
uint32_t link_hw_addr_array_idx;

uint32_t lib_arp_get_mac_req;
uint32_t lib_arp_nh_found;
uint32_t lib_arp_no_nh_found;
uint32_t lib_arp_arp_entry_found;
uint32_t lib_arp_no_arp_entry_found;
uint32_t lib_arp_populate_called;
uint32_t lib_arp_delete_called;
uint32_t lib_arp_duplicate_found;

uint32_t lib_nd_get_mac_req;
uint32_t lib_nd_nh_found;
uint32_t lib_nd_no_nh_found;
uint32_t lib_nd_nd_entry_found;
uint32_t lib_nd_no_arp_entry_found;
uint32_t lib_nd_populate_called;
uint32_t lib_nd_delete_called;
uint32_t lib_nd_duplicate_found;
struct rte_mempool *lib_arp_pktmbuf_tx_pool;
struct rte_mempool *lib_nd_pktmbuf_tx_pool;

struct rte_mbuf *lib_arp_pkt[MAX_PORTS];
struct rte_mbuf *lib_nd_pkt[MAX_PORTS];

uint8_t default_ether_addr[6] = { 0, 0, 0, 0, 1, 1 };
uint8_t default_ip[4] = { 0, 0, 1, 1 };

uint64_t start_tsc[4];
uint64_t end_tsc[4];
#define ticks_per_ms  (rte_get_tsc_hz()/1000)

#define MAX_NUM_ARP_CACHE_MAC_ADDRESS		16

/***** ARP local cache *****/
struct arp_data *p_arp_data;
//struct arp_cache arp_local_cache[MAX_PORTS];
uint8_t arp_cache_hw_laddr_valid[MAX_NUM_ARP_CACHE_MAC_ADDRESS] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0
};

/**
 * handler lock.
 */
rte_rwlock_t arp_hash_handle_lock;
rte_rwlock_t nd_hash_handle_lock;

void update_nhip_access(uint8_t dest_if)
{
	p_arp_data->update_tsc[dest_if] = rte_rdtsc();
}

/**
 * A structure defining the mbuf meta data for VFW.
 */
struct mbuf_arp_meta_data {
/* output port stored for RTE_PIPELINE_ACTION_PORT_META */
       uint32_t output_port;
       struct rte_mbuf *next;       /* next pointer for chained buffers */
} __rte_cache_aligned;

static struct arp_entry_data arp_entry_data_default = {
	.status = COMPLETE,
	.num_pkts = 0,
};

static struct nd_entry_data nd_entry_data_default = {
	.status = COMPLETE,
	.num_pkts = 0,
};

/**
 * memory pool for queued up user pkts.
 */
struct rte_mempool *arp_icmp_pktmbuf_tx_pool;

static struct rte_hash_parameters arp_hash_params = {
	.name = "ARP",
	.entries = 64,
	.reserved = 0,
	.key_len = sizeof(struct arp_key_ipv4),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
};

static struct rte_hash_parameters nd_hash_params = {
	.name = "ND",
	.entries = 64,
	.reserved = 0,
	.key_len = sizeof(struct nd_key_ipv6),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
};

struct ether_addr broadcast_ether_addr = {
       .addr_bytes[0] = 0xFF,
       .addr_bytes[1] = 0xFF,
       .addr_bytes[2] = 0xFF,
       .addr_bytes[3] = 0xFF,
       .addr_bytes[4] = 0xFF,
       .addr_bytes[5] = 0xFF,
};

static const struct ether_addr null_ether_addr = {
    .addr_bytes[0] = 0x00,
    .addr_bytes[1] = 0x00,
    .addr_bytes[2] = 0x00,
    .addr_bytes[3] = 0x00,
    .addr_bytes[4] = 0x00,
    .addr_bytes[5] = 0x00,
};

struct rte_hash *arp_hash_handle;
struct rte_hash *nd_hash_handle;

void print_pkt1(struct rte_mbuf *pkt);

struct app_params *myApp;
struct rte_pipeline *myP;
uint8_t num_vnf_threads;

/**
* A structure for Arp port address
*/
struct arp_port_address {
	uint32_t ip;			 /**< Ip address */
	uint8_t mac_addr[6]; /**< Mac address */
};

struct arp_port_address arp_port_addresses[RTE_MAX_ETHPORTS];
struct rte_mempool *timer_mempool_arp;

int timer_objs_mempool_count = 70000;

#define MAX_NUM_ARP_ENTRIES 64
#define MAX_NUM_ND_ENTRIES 64

inline uint32_t get_nh(uint32_t, uint32_t *, struct ether_addr *addr);
void get_nh_ipv6(uint8_t ipv6[], uint32_t *port, uint8_t nhipv6[],
	 struct ether_addr *hw_addr);

#define MAX_ARP_DATA_ENTRY_TABLE 7

struct table_arp_entry_data arp_entry_data_table[MAX_ARP_DATA_ENTRY_TABLE] = {
	{{0, 0, 0, 0, 0, 1}, 1, INCOMPLETE, IPv4(1, 1, 1, 1)},
	{{0, 0, 0, 0, 0, 2}, 0, INCOMPLETE, IPv4(1, 1, 1, 2)},
	{{0, 0, 0, 0, 0, 1}, 1, INCOMPLETE, IPv4(1, 1, 1, 3)},
	{{0, 0, 0, 0, 0, 1}, 1, INCOMPLETE, IPv4(1, 1, 1, 4)},
	{{0, 0, 0, 0, 0, 4}, 1, INCOMPLETE, IPv4(1, 1, 1, 5)},
	{{0, 0, 0, 0, 0, 5}, 0, INCOMPLETE, IPv4(1, 1, 1, 6)},
	{{0, 0, 0, 0, 0, 6}, 1, INCOMPLETE, IPv4(1, 1, 1, 7)},
};

#define MAX_ND_DATA_ENTRY_TABLE 7
struct table_nd_entry_data nd_entry_data_table[MAX_ND_DATA_ENTRY_TABLE] = {
	{{0, 0, 0, 0, 0, 8}, 1, INCOMPLETE,
	 {10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10}, 0},

	{{0, 0, 0, 0, 0, 9}, 1, INCOMPLETE,
	 {20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20}, 0},
	{{0, 0, 0, 0, 0, 10}, 2, INCOMPLETE,
	 {3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1}, 0},
	{{0, 0, 0, 0, 0, 11}, 3, INCOMPLETE,
	 {4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1}, 0},
	{{0, 0, 0, 0, 0, 12}, 4, INCOMPLETE,
	 {5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1}, 0},
	{{0, 0, 0, 0, 0, 13}, 5, INCOMPLETE,
	 {6, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1}, 0},
	{{0, 0, 0, 0, 0, 14}, 6, INCOMPLETE,
	 {7, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1}, 0},
};

struct lib_nd_route_table_entry lib_nd_route_table[MAX_ND_RT_ENTRY] = {
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0,
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} }
};

void print_trace(void);

uint32_t get_arp_buf(void)
{
       return arp_buffer;
}

uint32_t get_nd_buf(void)
{
	return nd_buffer;
}

uint8_t arp_cache_dest_mac_present(uint32_t out_port)
{
        return p_arp_data->arp_cache_hw_laddr_valid[out_port];
}

uint8_t nd_cache_dest_mac_present(uint32_t out_port)
{
	return p_arp_data->nd_cache_hw_laddr_valid[out_port];
}

/* Obtain a backtrace and print it to stdout. */
void print_trace(void)
{
	void *array[10];
	size_t size;
	char **strings;
	size_t i;

	size = backtrace(array, 10);
	strings = backtrace_symbols(array, size);

	RTE_LOG(INFO, LIBARP, "Obtained %zd stack frames.\n", size);

	for (i = 0; i < size; i++)
		RTE_LOG(INFO, LIBARP, "%s\n", strings[i]);

	free(strings);
}

uint32_t get_nh(uint32_t ip, uint32_t *port, struct ether_addr *addr)
{
	int i = 0;
	for (i = 0; i < p_arp_data->lib_arp_route_ent_cnt; i++) {
		if ((p_arp_data->lib_arp_route_table[i].nh_mask) ==
				 (ip & p_arp_data->lib_arp_route_table[i].mask)) {

			*port = p_arp_data->lib_arp_route_table[i].port;
			if (arp_cache_dest_mac_present(*port))
				ether_addr_copy(
				get_local_link_hw_addr(*port,
				p_arp_data->lib_arp_route_table[i].nh), addr);
			return p_arp_data->lib_arp_route_table[i].nh;
		}
	}
	lib_arp_no_nh_found++;
	return 0;
}

/*ND IPv6 */
void get_nh_ipv6(uint8_t ipv6[], uint32_t *port, uint8_t nhipv6[],
struct ether_addr *hw_addr)
{
	int i = 0;
	uint8_t netmask_ipv6[16], netip_nd[16], netip_in[16];
	uint8_t k = 0, l = 0, depthflags = 0, depthflags1 = 0;
	memset(netmask_ipv6, 0, sizeof(netmask_ipv6));
	memset(netip_nd, 0, sizeof(netip_nd));
	memset(netip_in, 0, sizeof(netip_in));
	if (!ipv6)
		return;
	for (i = 0; i < MAX_ARP_RT_ENTRY; i++) {

		convert_prefixlen_to_netmask_ipv6(lib_nd_route_table[i].depth,
							netmask_ipv6);

		for (k = 0; k < 16; k++) {
			if (lib_nd_route_table[i].ipv6[k] & netmask_ipv6[k]) {
				depthflags++;
				netip_nd[k] = lib_nd_route_table[i].ipv6[k];
			}
		}

		for (l = 0; l < 16; l++) {
			if (ipv6[l] & netmask_ipv6[l]) {
				depthflags1++;
				netip_in[l] = ipv6[l];
			}
		}
		int j = 0;
		if ((depthflags == depthflags1)
				&& (memcmp(netip_nd, netip_in, sizeof(netip_nd)) == 0)) {
			//&& (lib_nd_route_table[i].port == port))
			*port = lib_nd_route_table[i].port;
			lib_nd_nh_found++;

			for (j = 0; j < 16; j++)
				nhipv6[j] = lib_nd_route_table[i].nhipv6[j];

			if (nd_cache_dest_mac_present(*port)) {
				ether_addr_copy(
				get_nd_local_link_hw_addr(*port, nhipv6),
				(struct ether_addr *)hw_addr);
			}
			return;
		}

		if (NDIPV6_DEBUG)
			printf("No nh match\n");
		depthflags = 0;
		depthflags1 = 0;
	}
	if (NDIPV6_DEBUG)
		printf("No NH - ip 0x%x, \n", ipv6[0]);
	lib_nd_no_nh_found++;
}

/* Added for Multiport changes*/
struct arp_entry_data *get_dest_mac_addr_port(const uint32_t ipaddr,
				 uint32_t *phy_port, struct ether_addr *hw_addr)
{
	struct arp_entry_data *ret_arp_data = NULL;
	uint32_t nhip = 0;
	uint8_t index;

	nhip = get_nh(ipaddr, phy_port, hw_addr);
	if (unlikely(nhip == 0)) {
		if (ARPICMP_DEBUG)
			printf("ARPICMP no nh found for ip %x, port %d\n",
						 ipaddr, *phy_port);
		return ret_arp_data;
	}

	/* as part of optimization we store mac address in cache
	 * & thus can be sent without having to retrieve
	 */
	if (arp_cache_dest_mac_present(*phy_port)) {
		return &arp_entry_data_default;
	}

	struct arp_key_ipv4 tmp_arp_key;
	tmp_arp_key.port_id = *phy_port;	/* Changed for Multi Port */
	tmp_arp_key.ip = nhip;

	if (ARPICMP_DEBUG)
		printf("%s: nhip: %x, phyport: %d\n", __FUNCTION__, nhip,
					 *phy_port);

	ret_arp_data = retrieve_arp_entry(tmp_arp_key, DYNAMIC_ARP);
	if (ret_arp_data == NULL) {
	        if (ARPICMP_DEBUG && ipaddr)
                {
                       RTE_LOG(INFO, LIBARP,"ARPICMP no arp entry found for ip %x,"
			" port %u\n", ipaddr, *phy_port);
                       print_arp_table();
                }
		lib_arp_no_arp_entry_found++;
	} else if (ret_arp_data->status == COMPLETE) {
		rte_rwlock_write_lock(&ret_arp_data->queue_lock);
                ether_addr_copy(&ret_arp_data->eth_addr, hw_addr);
		p_arp_data->arp_cache_hw_laddr_valid[*phy_port] = 1;
		index = p_arp_data->arp_local_cache[*phy_port].num_nhip;
		p_arp_data->arp_local_cache[*phy_port].nhip[index] = nhip;
		ether_addr_copy(hw_addr,
		 &p_arp_data->arp_local_cache[*phy_port].link_hw_laddr[index]);
		p_arp_data->arp_local_cache[*phy_port].num_nhip++;
		rte_rwlock_write_unlock(&ret_arp_data->queue_lock);
		lib_arp_arp_entry_found++;
		if (ARPICMP_DEBUG)
			printf("%s: ARPICMP hwaddr found\n", __FUNCTION__);
        }

	if (ret_arp_data)
		p_arp_data->update_tsc[*phy_port] = rte_rdtsc();

	 return ret_arp_data;
}

struct nd_entry_data *get_dest_mac_address_ipv6_port(uint8_t ipv6addr[],
			 uint32_t *phy_port, struct ether_addr *hw_addr, uint8_t nhipv6[])
{
	int i = 0, j = 0, flag = 0;
	uint8_t index;
	lib_nd_get_mac_req++;

	get_nh_ipv6(ipv6addr, phy_port, nhipv6, hw_addr);
	for (j = 0; j < 16; j++) {
		if (nhipv6[j])
			flag++;
	}

	if (flag == 0) {
		if (NDIPV6_DEBUG)
			printf("NDIPV6 no nh found for ipv6 "
						 "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
						 "%02x%02x%02x%02x%02x%02x, port %d\n",
						 ipv6addr[0], ipv6addr[1], ipv6addr[2],
						 ipv6addr[3], ipv6addr[4], ipv6addr[5],
						 ipv6addr[6], ipv6addr[7], ipv6addr[8],
						 ipv6addr[9], ipv6addr[10], ipv6addr[11],
						 ipv6addr[12], ipv6addr[13], ipv6addr[14],
						 ipv6addr[15], *phy_port);
		return 0;
	}

	struct nd_entry_data *ret_nd_data = NULL;
	struct nd_key_ipv6 tmp_nd_key;
	tmp_nd_key.port_id = *phy_port;

	if (nd_cache_dest_mac_present(*phy_port)) {
		return &nd_entry_data_default;
	}


	for (i = 0; i < 16; i++)
		tmp_nd_key.ipv6[i] = nhipv6[i];

	ret_nd_data = retrieve_nd_entry(tmp_nd_key, DYNAMIC_ND);
	if (ret_nd_data == NULL) {
		if (NDIPV6_DEBUG) {
			printf("NDIPV6 no nd entry found for ip %x, port %d\n",
						 ipv6addr[0], *phy_port);
		}
		lib_nd_no_arp_entry_found++;
		return NULL;
	} else if (ret_nd_data->status == COMPLETE) {
		rte_rwlock_write_lock(&ret_nd_data->queue_lock);
		ether_addr_copy(&ret_nd_data->eth_addr, hw_addr);
		p_arp_data->nd_cache_hw_laddr_valid[*phy_port] = 1;
		index = p_arp_data->nd_local_cache[*phy_port].num_nhip;
		rte_mov16(&p_arp_data->nd_local_cache[*phy_port].nhip[index][0],
				 &nhipv6[0]);
		ether_addr_copy(hw_addr,
			&p_arp_data->nd_local_cache[*phy_port].link_hw_laddr[index]);
		p_arp_data->nd_local_cache[*phy_port].num_nhip++;

		lib_nd_nd_entry_found++;
		rte_rwlock_write_unlock(&ret_nd_data->queue_lock);
	}

	if (ret_nd_data)
		p_arp_data->update_tsc[*phy_port] = rte_rdtsc();

	return ret_nd_data;
}

/**
* A structure for arp entries in Arp table
*
*/
struct lib_arp_arp_table_entry {
	struct rte_pipeline_table_entry head;
	uint64_t macaddr;  /**< Mac address */
};

static const char *arp_op_name(uint16_t arp_op)
{
	switch (CHECK_ENDIAN_16(arp_op)) {
	case (ARP_OP_REQUEST):
		return "ARP Request";
	case (ARP_OP_REPLY):
		return "ARP Reply";
	case (ARP_OP_REVREQUEST):
		return "Reverse ARP Request";
	case (ARP_OP_REVREPLY):
		return "Reverse ARP Reply";
	case (ARP_OP_INVREQUEST):
		return "Peer Identify Request";
	case (ARP_OP_INVREPLY):
		return "Peer Identify Reply";
	default:
		break;
	}
	return "Unkwown ARP op";
}

static void print_icmp_packet(struct icmp_hdr *icmp_h)
{
	RTE_LOG(INFO, LIBARP, "  ICMP: type=%d (%s) code=%d id=%d seqnum=%d\n",
		icmp_h->icmp_type,
		(icmp_h->icmp_type == IP_ICMP_ECHO_REPLY ? "Reply" :
		 (icmp_h->icmp_type ==
			IP_ICMP_ECHO_REQUEST ? "Reqest" : "Undef")),
		icmp_h->icmp_code, CHECK_ENDIAN_16(icmp_h->icmp_ident),
		CHECK_ENDIAN_16(icmp_h->icmp_seq_nb));
}

static void print_ipv4_h(struct ipv4_hdr *ip_h)
{
	struct icmp_hdr *icmp_h =
			(struct icmp_hdr *)((char *)ip_h + sizeof(struct ipv4_hdr));
	RTE_LOG(INFO, LIBARP, "  IPv4: Version=%d HLEN=%d Type=%d Length=%d\n",
		(ip_h->version_ihl & 0xf0) >> 4, (ip_h->version_ihl & 0x0f),
		ip_h->type_of_service, rte_cpu_to_be_16(ip_h->total_length));
	if (ip_h->next_proto_id == IPPROTO_ICMP) {
		print_icmp_packet(icmp_h);
	}
}

static void print_arp_packet(struct arp_hdr *arp_h)
{
	RTE_LOG(INFO, LIBARP, "  ARP:  hrd=%d proto=0x%04x hln=%d "
		"pln=%d op=%u (%s)\n",
		CHECK_ENDIAN_16(arp_h->arp_hrd),
		CHECK_ENDIAN_16(arp_h->arp_pro), arp_h->arp_hln,
		arp_h->arp_pln, CHECK_ENDIAN_16(arp_h->arp_op),
		arp_op_name(arp_h->arp_op));

	if (CHECK_ENDIAN_16(arp_h->arp_hrd) != ARP_HRD_ETHER) {
		RTE_LOG(INFO, LIBARP,
			"incorrect arp_hrd format for IPv4 ARP (%d)\n",
			(arp_h->arp_hrd));
	} else if (CHECK_ENDIAN_16(arp_h->arp_pro) != ETHER_TYPE_IPv4) {
		RTE_LOG(INFO, LIBARP,
			"incorrect arp_pro format for IPv4 ARP (%d)\n",
			(arp_h->arp_pro));
	} else if (arp_h->arp_hln != 6) {
		RTE_LOG(INFO, LIBARP,
			"incorrect arp_hln format for IPv4 ARP (%d)\n",
			arp_h->arp_hln);
	} else if (arp_h->arp_pln != 4) {
		RTE_LOG(INFO, LIBARP,
			"incorrect arp_pln format for IPv4 ARP (%d)\n",
			arp_h->arp_pln);
	} else {
		RTE_LOG(INFO, LIBARP,
			"        sha=%02X:%02X:%02X:%02X:%02X:%02X",
			arp_h->arp_data.arp_sha.addr_bytes[0],
			arp_h->arp_data.arp_sha.addr_bytes[1],
			arp_h->arp_data.arp_sha.addr_bytes[2],
			arp_h->arp_data.arp_sha.addr_bytes[3],
			arp_h->arp_data.arp_sha.addr_bytes[4],
			arp_h->arp_data.arp_sha.addr_bytes[5]);
		RTE_LOG(INFO, LIBARP, " sip=%d.%d.%d.%d\n",
			(CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) >> 24) & 0xFF,
			(CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) >> 16) & 0xFF,
			(CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) >> 8) & 0xFF,
			CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) & 0xFF);
		RTE_LOG(INFO, LIBARP,
			"        tha=%02X:%02X:%02X:%02X:%02X:%02X",
			arp_h->arp_data.arp_tha.addr_bytes[0],
			arp_h->arp_data.arp_tha.addr_bytes[1],
			arp_h->arp_data.arp_tha.addr_bytes[2],
			arp_h->arp_data.arp_tha.addr_bytes[3],
			arp_h->arp_data.arp_tha.addr_bytes[4],
			arp_h->arp_data.arp_tha.addr_bytes[5]);
		RTE_LOG(INFO, LIBARP, " tip=%d.%d.%d.%d\n",
			(CHECK_ENDIAN_32(arp_h->arp_data.arp_tip) >> 24) & 0xFF,
			(CHECK_ENDIAN_32(arp_h->arp_data.arp_tip) >> 16) & 0xFF,
			(CHECK_ENDIAN_32(arp_h->arp_data.arp_tip) >> 8) & 0xFF,
			CHECK_ENDIAN_32(arp_h->arp_data.arp_tip) & 0xFF);
	}
}

static void print_eth(struct ether_hdr *eth_h)
{
	RTE_LOG(INFO, LIBARP, "  ETH:  src=%02X:%02X:%02X:%02X:%02X:%02X",
		eth_h->s_addr.addr_bytes[0],
		eth_h->s_addr.addr_bytes[1],
		eth_h->s_addr.addr_bytes[2],
		eth_h->s_addr.addr_bytes[3],
		eth_h->s_addr.addr_bytes[4], eth_h->s_addr.addr_bytes[5]);
	RTE_LOG(INFO, LIBARP, " dst=%02X:%02X:%02X:%02X:%02X:%02X\n",
		eth_h->d_addr.addr_bytes[0],
		eth_h->d_addr.addr_bytes[1],
		eth_h->d_addr.addr_bytes[2],
		eth_h->d_addr.addr_bytes[3],
		eth_h->d_addr.addr_bytes[4], eth_h->d_addr.addr_bytes[5]);

}

static void
print_mbuf(const char *rx_tx, uint8_t portid, struct rte_mbuf *mbuf,
		 unsigned line)
{
	struct ether_hdr *eth_h = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	struct arp_hdr *arp_h =
			(struct arp_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	struct ipv4_hdr *ipv4_h =
			(struct ipv4_hdr *)((char *)eth_h + sizeof(struct ether_hdr));

	RTE_LOG(INFO, LIBARP, "%s(%d): on port %d pkt-len=%u nb-segs=%u\n",
		rx_tx, line, portid, mbuf->pkt_len, mbuf->nb_segs);
	print_eth(eth_h);
	switch (rte_cpu_to_be_16(eth_h->ether_type)) {
	case ETHER_TYPE_IPv4:
		print_ipv4_h(ipv4_h);
		break;
	case ETHER_TYPE_ARP:
		print_arp_packet(arp_h);
		break;
	default:
		RTE_LOG(INFO, LIBARP, "  unknown packet type\n");
		break;
	}
	fflush(stdout);
}

/**
 * Add entry in ND table.
 *
 * @param nd_key
 *      key.
 * @param ret_nd_data
 *      return nd entry from table.
 *
 */
static int add_nd_data(struct nd_key_ipv6 *nd_key,
                struct nd_entry_data *ret_nd_data)
{
        int ret;
        struct nd_entry_data *tmp_nd_data = NULL;
        rte_rwlock_write_lock(&nd_hash_handle_lock);
        /* Check for value while locked */
        ret = rte_hash_lookup_data(nd_hash_handle, nd_key, (void **)&tmp_nd_data);

        if (ret == -ENOENT) {
                /* entry not yet added, do so now */
                ret = rte_hash_add_key_data(nd_hash_handle, nd_key, ret_nd_data);
                if (ret) {
                        /* We panic here because either:
                         * ret == -EINVAL and a parameter got messed up, or
                         * ret == -ENOSPC and the hash table isn't big enough
                         */
                        rte_panic("ND: Error on entry add for %s", rte_strerror(abs(ret)));
                }
        } else if (ret < 0) {
                /* We panic here because ret == -EINVAL and a parameter got
                 * messed up, or dpdk hash lib changed and this needs corrected */
                rte_panic("ARP: Error on entry add for %s", rte_strerror(abs(ret)));
        } else {
                /* entry already exists */
                ret = EEXIST;
        }

        rte_rwlock_write_unlock(&nd_hash_handle_lock);
        return ret;
}

/**
 * Add entry in ARP table.
 *
 * @param arp_key
 *      key.
 * @param ret_arp_data
 *      return arp entry from table.
 *
 */
static int add_arp_data(struct arp_key_ipv4 *arp_key,
                struct arp_entry_data *ret_arp_data) {
        int ret;
        struct arp_entry_data *tmp_arp_data = NULL;
        rte_rwlock_write_lock(&arp_hash_handle_lock);
        /* Check for value while locked */
        ret = rte_hash_lookup_data(arp_hash_handle, arp_key, (void **)&tmp_arp_data);

        if (ret == -ENOENT) {
                /* entry not yet added, do so now */
                ret = rte_hash_add_key_data(arp_hash_handle, arp_key, ret_arp_data);
                if (ret) {
                        /* We panic here because either:
                         * ret == -EINVAL and a parameter got messed up, or
                         * ret == -ENOSPC and the hash table isn't big enough
                         */
                        rte_panic("ARP: Error on entry add for %s - %s",
                                        inet_ntoa(*(struct in_addr *)&arp_key->ip),
                                        rte_strerror(abs(ret)));
                }
        } else if (ret < 0) {
                /* We panic here because ret == -EINVAL and a parameter got
                 * messed up, or dpdk hash lib changed and this needs corrected */
                rte_panic("ARP: Error on entry add for %s - %s",
                                inet_ntoa(*(struct in_addr *)&arp_key->ip),
                                rte_strerror(abs(ret)));
        } else {
                /* entry already exists */
                ret = EEXIST;
        }

        rte_rwlock_write_unlock(&arp_hash_handle_lock);
        return ret;
}

struct arp_entry_data *retrieve_arp_entry(struct arp_key_ipv4 arp_key, uint8_t mode)
{
	struct arp_entry_data *ret_arp_data = NULL;
	arp_key.filler1 = 0;
	arp_key.filler2 = 0;
	arp_key.filler3 = 0;

	int ret = rte_hash_lookup_data(arp_hash_handle, &arp_key,
							 (void **)&ret_arp_data);
	if (ret < 0 && (mode == DYNAMIC_ARP)) {
	        if (ARPICMP_DEBUG)
			RTE_LOG(INFO, LIBARP, "ARP entry not found for ip 0x%x\n",
				arp_key.ip);

		/* add INCOMPLETE arp entry */
		ret_arp_data = rte_malloc_socket(NULL, sizeof(struct arp_entry_data),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		ether_addr_copy(&null_ether_addr, &ret_arp_data->eth_addr);
		ret_arp_data->status = INCOMPLETE;
		ret_arp_data->port = arp_key.port_id;
		ret_arp_data->ip = arp_key.ip;
		ret_arp_data->mode = mode;
		ret_arp_data->num_pkts = 0;
		rte_rwlock_init(&ret_arp_data->queue_lock);
		rte_rwlock_write_lock(&ret_arp_data->queue_lock);

		/* attempt to add arp_entry to hash */
		ret = add_arp_data(&arp_key, ret_arp_data);

		if (ret == EEXIST) {
			rte_rwlock_write_unlock(&ret_arp_data->queue_lock);
			rte_free(ret_arp_data);
			/* Some other thread has 'beat' this thread in
				creation of arp_data, try again */
                        return NULL;
		}

                if (rte_mempool_get(timer_mempool_arp,
			(void **) &(ret_arp_data->timer) ) < 0) {
			rte_rwlock_write_unlock(&ret_arp_data->queue_lock);
                        RTE_LOG(INFO, LIBARP,"Error in getting timer alloc buf\n");
                        return NULL;
                }

		ret_arp_data->buf_pkts = (struct rte_mbuf **)rte_zmalloc_socket(
					NULL, sizeof(struct rte_mbuf *) * arp_buffer,
					RTE_CACHE_LINE_SIZE, rte_socket_id());

		if (ret_arp_data->buf_pkts == NULL) {
			rte_rwlock_write_unlock(&ret_arp_data->queue_lock);
                        RTE_LOG(INFO, LIBARP,"Could not allocate buf for queueing\n");
                        return NULL;
		}

                rte_timer_init(ret_arp_data->timer);
                struct arp_timer_key * callback_key =
			 (struct arp_timer_key*) rte_malloc(NULL,
                               sizeof(struct  arp_timer_key*),RTE_CACHE_LINE_SIZE);
                callback_key->port_id = arp_key.port_id;
                callback_key->ip = arp_key.ip;
                if(ARPICMP_DEBUG)
                      RTE_LOG(INFO, LIBARP,"TIMER STARTED FOR %u seconds\n",
			ARP_TIMER_EXPIRY);
                if(rte_timer_reset(ret_arp_data->timer,
                                        (PROBE_TIME * rte_get_tsc_hz() / 1000),
                                        SINGLE,timer_lcore,
                                        arp_timer_callback,
                                        callback_key) < 0)
                        if(ARPICMP_DEBUG)
                        RTE_LOG(INFO, LIBARP,"Err : Timer already running\n");

                ret_arp_data->timer_key = callback_key;

		/* send arp request */
		request_arp(arp_key.port_id, arp_key.ip);
		rte_rwlock_write_unlock(&ret_arp_data->queue_lock);
	} else {
		if (ret_arp_data &&
		 ret_arp_data->mode == DYNAMIC_ARP && ret_arp_data->status == STALE) {
			rte_rwlock_write_lock(&ret_arp_data->queue_lock);
			ether_addr_copy(&null_ether_addr, &ret_arp_data->eth_addr);
			ret_arp_data->status = PROBE;
			struct arp_timer_key * callback_key =
				(struct arp_timer_key*) rte_malloc(NULL,
				sizeof(struct  arp_timer_key*),RTE_CACHE_LINE_SIZE);
			callback_key->port_id = arp_key.port_id;
			callback_key->ip = arp_key.ip;
			if(ARPICMP_DEBUG)
				RTE_LOG(INFO, LIBARP,"TIMER STARTED FOR %u"
					" seconds\n",ARP_TIMER_EXPIRY);
			if(rte_timer_reset(ret_arp_data->timer,
                                        (arp_timeout * rte_get_tsc_hz()),
                                        SINGLE,timer_lcore,
                                        arp_timer_callback,
                                        callback_key) < 0)
			if(ARPICMP_DEBUG)
				RTE_LOG(INFO, LIBARP,"Err : Timer already running\n");

			ret_arp_data->timer_key = callback_key;

			/* send arp request */
			request_arp(arp_key.port_id, arp_key.ip);
			rte_rwlock_write_unlock(&ret_arp_data->queue_lock);
		}

	}

	return ret_arp_data;
}

struct nd_entry_data *retrieve_nd_entry(struct nd_key_ipv6 nd_key, uint8_t mode)
{
	struct nd_entry_data *ret_nd_data = NULL;
	nd_key.filler1 = 0;
	nd_key.filler2 = 0;
	nd_key.filler3 = 0;
	int i = 0;

	/*Find a nd IPv6 key-data pair in the hash table for ND IPv6 */
	int ret = rte_hash_lookup_data(nd_hash_handle, &nd_key,
							 (void **)&ret_nd_data);
	if (ret < 0 && (mode == DYNAMIC_ND)) {
	        if (ARPICMP_DEBUG)
			RTE_LOG(INFO, LIBARP, "ND entry not found for ip \n");

		/* add INCOMPLETE arp entry */
		ret_nd_data = rte_malloc_socket(NULL, sizeof(struct nd_entry_data),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		ether_addr_copy(&null_ether_addr, &ret_nd_data->eth_addr);
		ret_nd_data->status = INCOMPLETE;
		ret_nd_data->port = nd_key.port_id;

		for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
			ret_nd_data->ipv6[i] = nd_key.ipv6[i];
		ret_nd_data->mode = mode;
		ret_nd_data->num_pkts = 0;
		rte_rwlock_init(&ret_nd_data->queue_lock);
		rte_rwlock_write_lock(&ret_nd_data->queue_lock);

		/* attempt to add arp_entry to hash */
		ret = add_nd_data(&nd_key, ret_nd_data);

		if (ret == EEXIST) {
			rte_rwlock_write_unlock(&ret_nd_data->queue_lock);
			rte_free(ret_nd_data);
			/* Some other thread has 'beat' this thread in
				creation of arp_data, try again */
                        return NULL;
		}


                if (rte_mempool_get(timer_mempool_arp,
			(void **) &(ret_nd_data->timer) ) < 0) {
                        RTE_LOG(INFO, LIBARP,"Error in getting timer alloc buf\n");
			rte_rwlock_write_unlock(&ret_nd_data->queue_lock);
                        return NULL;
                }

		ret_nd_data->buf_pkts = (struct rte_mbuf **)rte_zmalloc_socket(
					NULL, sizeof(struct rte_mbuf *) * nd_buffer,
					RTE_CACHE_LINE_SIZE, rte_socket_id());

		if (ret_nd_data->buf_pkts == NULL) {
			rte_rwlock_write_unlock(&ret_nd_data->queue_lock);
                        RTE_LOG(INFO, LIBARP,"Could not allocate buf for queueing\n");
                        return NULL;
		}

                rte_timer_init(ret_nd_data->timer);
                struct nd_timer_key * callback_key =
			 (struct nd_timer_key*) rte_malloc(NULL,
                               sizeof(struct  nd_timer_key*),RTE_CACHE_LINE_SIZE);
                callback_key->port_id = nd_key.port_id;
		for (i = 0; i < ND_IPV6_ADDR_SIZE; i++) {
			callback_key->ipv6[i] = ret_nd_data->ipv6[i];
		}

		if(ARPICMP_DEBUG) {
			RTE_LOG(INFO, LIBARP,"TIMER STARTED FOR %u seconds\n",
			ARP_TIMER_EXPIRY);
		}

		if(rte_timer_reset(ret_nd_data->timer,
			(PROBE_TIME * rte_get_tsc_hz() / 1000),
			SINGLE,timer_lcore,
			nd_timer_callback,
			callback_key) < 0)
		if(ARPICMP_DEBUG)
			RTE_LOG(INFO, LIBARP,"Err : Timer already running\n");

                ret_nd_data->timer_key = callback_key;
		/* send nd request */
		request_nd(callback_key->ipv6, ifm_get_port(callback_key->port_id));
		rte_rwlock_write_unlock(&ret_nd_data->queue_lock);
	} else {
		if (ret_nd_data &&
		 ret_nd_data->mode == DYNAMIC_ND && ret_nd_data->status == STALE) {
			rte_rwlock_write_lock(&ret_nd_data->queue_lock);
			ether_addr_copy(&null_ether_addr, &ret_nd_data->eth_addr);
			ret_nd_data->status = PROBE;
			struct nd_timer_key * callback_key =
			 (struct nd_timer_key*) rte_malloc(NULL,
                               sizeof(struct  nd_timer_key*),RTE_CACHE_LINE_SIZE);

			callback_key->port_id = nd_key.port_id;
			for (i = 0; i < ND_IPV6_ADDR_SIZE; i++) {
				callback_key->ipv6[i] = ret_nd_data->ipv6[i];
			}

			if (rte_timer_reset
				(ret_nd_data->timer,
				 (arp_timeout * rte_get_tsc_hz()), SINGLE,
				 timer_lcore, nd_timer_callback, callback_key) < 0)
			if (ARPICMP_DEBUG)
				RTE_LOG(INFO, LIBARP,
					"Err : Timer already running\n");
			ret_nd_data->timer_key = callback_key;

			/* send nd request */
			request_nd(callback_key->ipv6, ifm_get_port(callback_key->port_id));
			rte_rwlock_write_unlock(&ret_nd_data->queue_lock);
		}
	}
	return ret_nd_data;
}

static const char* arp_status[] = {"INCOMPLETE", "COMPLETE", "PROBE", "STALE"};

void print_arp_table(void)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;

	printf("------------------------ ARP CACHE ------------------------------------\n");
	printf("-----------------------------------------------------------------------\n");
	printf("\tport  hw addr            status     ip addr\n");
	printf("-----------------------------------------------------------------------\n");

	while (rte_hash_iterate(arp_hash_handle, &next_key, &next_data, &iter)
				 >= 0) {

		struct arp_entry_data *tmp_arp_data =
				(struct arp_entry_data *)next_data;
		struct arp_key_ipv4 tmp_arp_key;
		memcpy(&tmp_arp_key, next_key, sizeof(struct arp_key_ipv4));
		printf("\t%4d  %02X:%02X:%02X:%02X:%02X:%02X"
			"  %10s %d.%d.%d.%d\n",
				 tmp_arp_data->port, tmp_arp_data->eth_addr.addr_bytes[0],
				 tmp_arp_data->eth_addr.addr_bytes[1],
				 tmp_arp_data->eth_addr.addr_bytes[2],
				 tmp_arp_data->eth_addr.addr_bytes[3],
				 tmp_arp_data->eth_addr.addr_bytes[4],
				 tmp_arp_data->eth_addr.addr_bytes[5],
				 arp_status[tmp_arp_data->status],
				 (tmp_arp_data->ip >> 24),
				 ((tmp_arp_data->ip & 0x00ff0000) >> 16),
				 ((tmp_arp_data->ip & 0x0000ff00) >> 8),
				 ((tmp_arp_data->ip & 0x000000ff)));
	}

	uint32_t i = 0;
	printf("\nARP routing table has %d entries\n", p_arp_data->lib_arp_route_ent_cnt);
	printf("\nIP_Address    Mask          Port    NH_IP_Address\n");
	for (i = 0; i < p_arp_data->lib_arp_route_ent_cnt; i++) {
		printf("0x%x    0x%x    %d       0x%x\n",
					 p_arp_data->lib_arp_route_table[i].ip,
					 p_arp_data->lib_arp_route_table[i].mask,
					 p_arp_data->lib_arp_route_table[i].port,
					 p_arp_data->lib_arp_route_table[i].nh);
	}

	printf("\nARP Stats: Total Queries %u, ok_NH %u, no_NH %u, ok_Entry %u,"
		" no_Entry %u, PopulateCall %u, Del %u, Dup %u\n",
			 lib_arp_get_mac_req, lib_arp_nh_found, lib_arp_no_nh_found,
			 lib_arp_arp_entry_found, lib_arp_no_arp_entry_found,
			 lib_arp_populate_called, lib_arp_delete_called,
			 lib_arp_duplicate_found);

	printf("ARP table key len is %lu\n", sizeof(struct arp_key_ipv4));
}

/* ND IPv6 */
void print_nd_table(void)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;
	uint8_t ii = 0, j = 0, k = 0;
	printf("-----------------------------------------------------------------------\n");
	printf("\tport  hw addr            status         ip addr\n");

	printf("-----------------------------------------------------------------------\n");
	while (rte_hash_iterate(nd_hash_handle, &next_key, &next_data, &iter) >=
				 0) {

		struct nd_entry_data *tmp_nd_data =
				(struct nd_entry_data *)next_data;
		struct nd_key_ipv6 tmp_nd_key;
		memcpy(&tmp_nd_key, next_key, sizeof(struct nd_key_ipv6));
		printf("\t%4d  %02X:%02X:%02X:%02X:%02X:%02X  %10s\n",
					 tmp_nd_data->port,
					 tmp_nd_data->eth_addr.addr_bytes[0],
					 tmp_nd_data->eth_addr.addr_bytes[1],
					 tmp_nd_data->eth_addr.addr_bytes[2],
					 tmp_nd_data->eth_addr.addr_bytes[3],
					 tmp_nd_data->eth_addr.addr_bytes[4],
					 tmp_nd_data->eth_addr.addr_bytes[5],
					 arp_status[tmp_nd_data->status]);
		printf("\t\t\t\t\t\t");
		for (ii = 0; ii < ND_IPV6_ADDR_SIZE; ii += 2) {
			printf("%02X%02X ", tmp_nd_data->ipv6[ii],
						 tmp_nd_data->ipv6[ii + 1]);
		}
		printf("\n");
	}

	uint32_t i = 0;
	printf("\n\nND IPV6 routing table has %d entries\n",
				 nd_route_tbl_index);
	printf("\nIP_Address						Depth");
	printf("          Port				NH_IP_Address\n");
	for (i = 0; i < nd_route_tbl_index; i++) {
		printf("\n");

		for (j = 0; j < ND_IPV6_ADDR_SIZE; j += 2) {
			RTE_LOG(INFO, LIBARP, "%02X%02X ",
				lib_nd_route_table[i].ipv6[j],
				lib_nd_route_table[i].ipv6[j + 1]);
		}

		printf
				("\n\t\t\t			%d					 %d					\n",
				 lib_nd_route_table[i].depth, lib_nd_route_table[i].port);
		printf("\t\t\t\t\t\t\t\t\t");
		for (k = 0; k < ND_IPV6_ADDR_SIZE; k += 2) {
			printf("%02X%02X ", lib_nd_route_table[i].nhipv6[k],
						 lib_nd_route_table[i].ipv6[k + 1]);
		}
	}
	printf("\nND IPV6 Stats: \nTotal Queries %u, ok_NH %u,"
		" no_NH %u, ok_Entry %u, no_Entry %u, PopulateCall %u, Del %u, Dup %u\n",
			 lib_nd_get_mac_req, lib_nd_nh_found, lib_nd_no_nh_found,
			 lib_nd_nd_entry_found, lib_nd_no_arp_entry_found,
			 lib_nd_populate_called, lib_nd_delete_called,
			 lib_nd_duplicate_found);
	printf("ND table key len is %lu\n\n", sizeof(struct nd_key_ipv6));
}

void remove_arp_entry(struct arp_entry_data *ret_arp_data, void *arg)
{

	struct arp_timer_key *arp_key = (struct arp_timer_key *)arg;
	lib_arp_delete_called++;

	if (ret_arp_data->timer) {
		rte_timer_stop(ret_arp_data->timer);
		rte_free(ret_arp_data->timer_key);
		rte_free(ret_arp_data->buf_pkts);
		ret_arp_data->buf_pkts = NULL;
	}

	if (ARPICMP_DEBUG) {
		RTE_LOG(INFO, LIBARP,
			"ARP Entry Deleted for IP :%d.%d.%d.%d , port %d\n",
			(arp_key->ip >> 24),
			((arp_key->ip & 0x00ff0000) >> 16),
			((arp_key->ip & 0x0000ff00) >>  8),
			((arp_key->ip & 0x000000ff)),
			arp_key->port_id);
	}
	rte_hash_del_key(arp_hash_handle, arp_key);
	print_arp_table();
}

/* ND IPv6 */
void remove_nd_entry_ipv6(struct nd_entry_data *ret_nd_data, void *arg)
{
	int i = 0;
	struct nd_timer_key *timer_key = (struct nd_timer_key *)arg;

	lib_nd_delete_called++;

        rte_timer_stop(ret_nd_data->timer);
        rte_free(ret_nd_data->timer_key);
        rte_free(ret_nd_data->buf_pkts);
        ret_nd_data->buf_pkts = NULL;

        if (NDIPV6_DEBUG) {
                RTE_LOG(INFO, LIBARP,
                        "Deletes rte hash table nd entry for port %d ipv6=",
                        timer_key->port_id);
                for (i = 0; i < ND_IPV6_ADDR_SIZE; i += 2) {
                        RTE_LOG(INFO, LIBARP, "%02X%02X ", timer_key->ipv6[i],
                                timer_key->ipv6[i + 1]);
                }
        }
        rte_hash_del_key(nd_hash_handle, timer_key);
}

int
arp_queue_unresolved_packet(struct arp_entry_data *ret_arp_data, struct rte_mbuf *pkt)
{
	rte_rwlock_write_lock(&ret_arp_data->queue_lock);
	if (ret_arp_data->num_pkts  == NUM_DESC) {
		rte_rwlock_write_unlock(&ret_arp_data->queue_lock);
		return 0;
	}

	ret_arp_data->buf_pkts[ret_arp_data->num_pkts++] = pkt;
	rte_rwlock_write_unlock(&ret_arp_data->queue_lock);
	return 0;
}

void
arp_send_buffered_pkts(struct arp_entry_data *ret_arp_data,
	struct ether_addr *hw_addr, uint8_t port_id)
{
	l2_phy_interface_t *port = ifm_get_port(port_id);
	struct rte_mbuf *pkt, *tmp;
	uint8_t *eth_dest, *eth_src;
	int i;


	if (!hw_addr || !ret_arp_data)
		return;

	rte_rwlock_write_lock(&ret_arp_data->queue_lock);
	for (i=0;i<(int)ret_arp_data->num_pkts;i++) {
		pkt = ret_arp_data->buf_pkts[i];

		eth_dest = RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
		eth_src = RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM + 6);

		memcpy(eth_dest, hw_addr, sizeof(struct ether_addr));
		memcpy(eth_src, get_link_hw_addr(port_id),
                                sizeof(struct ether_addr));
		port->transmit_single_pkt(port, pkt);
		tmp = pkt;
		rte_pktmbuf_free(tmp);
	}
	ret_arp_data->num_pkts = 0;
	rte_rwlock_write_unlock(&ret_arp_data->queue_lock);
}

int
nd_queue_unresolved_packet(struct nd_entry_data *ret_nd_data, struct rte_mbuf *pkt)
{
	rte_rwlock_write_lock(&ret_nd_data->queue_lock);
	if (ret_nd_data->num_pkts  == get_nd_buf()) {
		rte_rwlock_write_unlock(&ret_nd_data->queue_lock);
		return 0;
	}

	ret_nd_data->buf_pkts[ret_nd_data->num_pkts++] = pkt;
	rte_rwlock_write_unlock(&ret_nd_data->queue_lock);
	return 0;
}

void
nd_send_buffered_pkts(struct nd_entry_data *ret_nd_data,
	struct ether_addr *hw_addr, uint8_t port_id)
{
	l2_phy_interface_t *port = ifm_get_port(port_id);
	struct rte_mbuf *pkt, *tmp;
	uint8_t *eth_dest, *eth_src;
	int i;

	if (!hw_addr || !ret_nd_data)
		return;

	rte_rwlock_write_lock(&ret_nd_data->queue_lock);
	for (i=0;i<(int)ret_nd_data->num_pkts;i++) {
		pkt = ret_nd_data->buf_pkts[i];
		eth_dest = RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
		eth_src = RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM + 6);

		memcpy(eth_dest, hw_addr, sizeof(struct ether_addr));
		memcpy(eth_src, get_link_hw_addr(port_id),
				sizeof(struct ether_addr));
		port->transmit_single_pkt(port, pkt);
		tmp = pkt;
		rte_pktmbuf_free(tmp);
	}
	ret_nd_data->num_pkts = 0;
	rte_rwlock_write_unlock(&ret_nd_data->queue_lock);
}

void
populate_arp_entry(const struct ether_addr *hw_addr, uint32_t ipaddr,
			 uint8_t portid, uint8_t mode)
{
	struct arp_key_ipv4 arp_key;
	struct arp_entry_data *new_arp_data;
	arp_key.port_id = portid;
	arp_key.ip = ipaddr;
	arp_key.filler1 = 0;
	arp_key.filler2 = 0;
	arp_key.filler3 = 0;

	lib_arp_populate_called++;
	printf("populate_arp_entry ip %x, port %d\n", arp_key.ip, arp_key.port_id);

	if (ARPICMP_DEBUG)
		RTE_LOG(INFO, LIBARP, "populate_arp_entry ip %x, port %d\n",
			arp_key.ip, arp_key.port_id);

	new_arp_data = retrieve_arp_entry(arp_key, mode);
	if (new_arp_data && ((new_arp_data->mode == STATIC_ARP
		&& mode == DYNAMIC_ARP) || (new_arp_data->mode == DYNAMIC_ARP
		&& mode == STATIC_ARP))) {
		if (ARPICMP_DEBUG)
			RTE_LOG(INFO, LIBARP,"populate_arp_entry: ARP entry "
				"already exists(%d %d)\n", new_arp_data->mode, mode);
		return;
	}

	if (mode == DYNAMIC_ARP) {

		if (new_arp_data
				&& is_same_ether_addr(&new_arp_data->eth_addr, hw_addr)) {
			printf("entry exists\n");

			if (ARPICMP_DEBUG) {
				RTE_LOG(INFO, LIBARP,
					"arp_entry exists ip :%d.%d.%d.%d , port %d\n",
					(arp_key.ip >> 24),
					((arp_key.ip & 0x00ff0000) >> 16),
					((arp_key.ip & 0x0000ff00) >> 8),
					((arp_key.ip & 0x000000ff)),
					arp_key.port_id);
			}
			lib_arp_duplicate_found++;
			rte_rwlock_write_lock(&new_arp_data->queue_lock);
			new_arp_data->retry_count = 0;	// Reset
			if (new_arp_data->status == STALE) {
				new_arp_data->status = PROBE;
				if (ifm_chk_port_ipv4_enabled
					(new_arp_data->port) != IFM_FAILURE) {
					request_arp(new_arp_data->port,
							new_arp_data->ip);
				} else {
					if (ARPICMP_DEBUG)
						RTE_LOG(INFO, LIBARP,
						"%s: IP is not enabled on port %u, not sending GARP\n\r",
						__FUNCTION__,
						new_arp_data->port);
				}
			}

			if (rte_timer_reset(new_arp_data->timer,
						(arp_timeout * rte_get_tsc_hz()),
						SINGLE, timer_lcore,
						arp_timer_callback,
						new_arp_data->timer_key) < 0) {
				if (ARPICMP_DEBUG)
					RTE_LOG(INFO, LIBARP,
						"Err : Timer already running\n");
			}
			rte_rwlock_write_unlock(&new_arp_data->queue_lock);
			return;
		} else {
			rte_rwlock_write_lock(&new_arp_data->queue_lock);
			ether_addr_copy(hw_addr, &new_arp_data->eth_addr);
			if ((new_arp_data->status == INCOMPLETE) ||
				(new_arp_data->status == PROBE)) {
				new_arp_data->status = COMPLETE;
				new_arp_data->mode = mode;
				new_arp_data->n_confirmed = rte_rdtsc();
				new_arp_data->retry_count = 0;
				if (rte_timer_reset(new_arp_data->timer,
						(arp_timeout * rte_get_tsc_hz()),
						SINGLE, timer_lcore,
						arp_timer_callback,
						new_arp_data->timer_key) < 0) {
					if (ARPICMP_DEBUG)
						RTE_LOG(INFO, LIBARP,
						"Err : Timer already running\n");
				}
			}
			rte_rwlock_write_unlock(&new_arp_data->queue_lock);
			return;
		}
	} else {
		if (new_arp_data
                                && is_same_ether_addr(&new_arp_data->eth_addr, hw_addr)) {

			if (ARPICMP_DEBUG) {
				RTE_LOG(INFO, LIBARP,
					"arp_entry exists ip :%d.%d.%d.%d , port %d\n",
					(arp_key.ip >> 24),
					((arp_key.ip & 0x00ff0000) >> 16),
					((arp_key.ip & 0x0000ff00) >> 8),
					((arp_key.ip & 0x000000ff)),
					arp_key.port_id);
			}
			lib_arp_duplicate_found++;
		} else {
			uint32_t size =
					RTE_CACHE_LINE_ROUNDUP(sizeof
							 (struct arp_entry_data));
			new_arp_data =
					rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
			new_arp_data->eth_addr = *hw_addr;
			new_arp_data->status = COMPLETE;
			new_arp_data->port = portid;
			new_arp_data->ip = ipaddr;
			new_arp_data->mode = mode;
			new_arp_data->num_pkts = 0;

			/* attempt to add arp_entry to hash */
			int ret;
			ret = add_arp_data(&arp_key, new_arp_data);
			if (ret) {
				/* Some other thread created an entry for this ip */
				rte_free(new_arp_data);
			}

			if (ARPICMP_DEBUG) {
				RTE_LOG(INFO, LIBARP,
					"arp_entry exists ip :%d.%d.%d.%d , port %d\n",
					(arp_key.ip >> 24),
					((arp_key.ip & 0x00ff0000) >> 16),
					((arp_key.ip & 0x0000ff00) >> 8),
					((arp_key.ip & 0x000000ff)),
					arp_key.port_id);
			}
			#ifdef L3_STACK_SUPPORT
			// Call l3fwd module for resolving 2_adj structure.
			resolve_l2_adj(ipaddr, portid, hw_addr);
			#endif
		}
	}

	if (ARPICMP_DEBUG) {
		/* print entire hash table */
		RTE_LOG(INFO, LIBARP,
			"\tARP: table update - hwaddr=%02x:%02x:%02x:%02x:%02x:%02x  ip=%d.%d.%d.%d  on port=%d\n",
			new_arp_data->eth_addr.addr_bytes[0],
			new_arp_data->eth_addr.addr_bytes[1],
			new_arp_data->eth_addr.addr_bytes[2],
			new_arp_data->eth_addr.addr_bytes[3],
			new_arp_data->eth_addr.addr_bytes[4],
			new_arp_data->eth_addr.addr_bytes[5],
			(arp_key.ip >> 24), ((arp_key.ip & 0x00ff0000) >> 16),
			((arp_key.ip & 0x0000ff00) >> 8),
			((arp_key.ip & 0x000000ff)), portid);
		puts("");
	}
}

/*
 * ND IPv6
 *
 * Install key - data pair in Hash table - From Pipeline Configuration
 *
 */
void populate_nd_entry(const struct ether_addr *hw_addr, uint8_t ipv6[],
					 uint8_t portid, uint8_t mode)
{

	/* need to lock here if multi-threaded */
	/* rte_hash_add_key_data is not thread safe */
	uint8_t i, val = 0;
	struct nd_key_ipv6 nd_key;
	nd_key.port_id = portid;

	for (i = 0; i < ND_IPV6_ADDR_SIZE; i++) {
		nd_key.ipv6[i] = ipv6[i];
		val |= ipv6[i];
	}

	if (!val)
		return;

	nd_key.filler1 = 0;
	nd_key.filler2 = 0;
	nd_key.filler3 = 0;

	lib_nd_populate_called++;

	/* Validate if key-value pair already exists in the hash table for ND IPv6 */
	struct nd_entry_data *new_nd_data = retrieve_nd_entry(nd_key, mode);
	if (new_nd_data && ((new_nd_data->mode == STATIC_ND
		&& mode == DYNAMIC_ND) || (new_nd_data->mode == DYNAMIC_ND
		&& mode == STATIC_ND))) {
		if (ARPICMP_DEBUG)
		RTE_LOG(INFO, LIBARP, "populate_arp_entry: ND entry already"
				" exists(%d %d)\n", new_nd_data->mode, mode);
		return;
	}

	if (mode == DYNAMIC_ND) {
		if (new_nd_data && is_same_ether_addr(&new_nd_data->eth_addr, hw_addr)) {

			if (NDIPV6_DEBUG) {
				RTE_LOG(INFO, LIBARP,
					"nd_entry exists port %d ipv6 = ",
					nd_key.port_id);
				for (i = 0; i < ND_IPV6_ADDR_SIZE; i += 2) {

					RTE_LOG(INFO, LIBARP, "%02X%02X ",
						nd_key.ipv6[i],
						nd_key.ipv6[i + 1]);
				}
			}

			lib_nd_duplicate_found++;
			rte_rwlock_write_lock(&new_nd_data->queue_lock);
			if (new_nd_data->status == STALE) {
				new_nd_data->retry_count = 0;	// Reset
				new_nd_data->status = PROBE;
				request_nd(new_nd_data->ipv6,
					 ifm_get_port(new_nd_data->port));

				if (rte_timer_reset(new_nd_data->timer,
						(arp_timeout * rte_get_tsc_hz()),
						SINGLE, timer_lcore,
						nd_timer_callback,
						new_nd_data->timer_key) < 0) {
					if (ARPICMP_DEBUG)
						RTE_LOG(INFO, LIBARP,
						"Err : Timer already running\n");
				}
			}
			rte_rwlock_write_unlock(&new_nd_data->queue_lock);
			return;
		} else {
			rte_rwlock_write_lock(&new_nd_data->queue_lock);
			ether_addr_copy(hw_addr, &new_nd_data->eth_addr);
			if ((new_nd_data->status == INCOMPLETE) ||
				(new_nd_data->status == PROBE)) {
				new_nd_data->status = COMPLETE;
				new_nd_data->mode = mode;
				new_nd_data->n_confirmed = rte_rdtsc();
				new_nd_data->retry_count = 0;
				if (rte_timer_reset(new_nd_data->timer,
					(arp_timeout * rte_get_tsc_hz()),
					SINGLE, timer_lcore,
					nd_timer_callback,
					new_nd_data->timer_key) < 0) {
					if (ARPICMP_DEBUG)
						RTE_LOG(INFO, LIBARP,
						"Err : Timer already running\n");
				}
			}
			rte_rwlock_write_unlock(&new_nd_data->queue_lock);
                        return;
                }

	} else {
		if (new_nd_data
				&& is_same_ether_addr(&new_nd_data->eth_addr, hw_addr)) {
			if (NDIPV6_DEBUG) {
				RTE_LOG(INFO, LIBARP,
					"nd_entry exists port %d ipv6 = ",
					nd_key.port_id);
				for (i = 0; i < ND_IPV6_ADDR_SIZE; i += 2) {

					RTE_LOG(INFO, LIBARP, "%02X%02X ",
						nd_key.ipv6[i],
						nd_key.ipv6[i + 1]);
				}
			}

			lib_nd_duplicate_found++;
		} else {
			uint32_t size =
					RTE_CACHE_LINE_ROUNDUP(sizeof
							 (struct nd_entry_data));
			new_nd_data =
					rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);

			new_nd_data->eth_addr = *hw_addr;
			new_nd_data->status = COMPLETE;
			new_nd_data->port = portid;
			new_nd_data->mode = mode;
			for (i = 0; i < ND_IPV6_ADDR_SIZE; i++) {
				new_nd_data->ipv6[i] = ipv6[i];
			}
			new_nd_data->mode = mode;
			new_nd_data->num_pkts = 0;

			/*Add a key-data pair at hash table for ND IPv6 static routing */
			/* attempt to add arp_entry to hash */
			int ret;
			ret = add_nd_data(&nd_key, new_nd_data);
			if (ret) {
				rte_free(new_nd_data);
			}

			/* need to check the return value of the hash add */
			#ifdef L3_STACK_SUPPORT
			// Call l3fwd module for resolving 2_adj structure.
			resolve_l2_adj(ipaddr, portid, hw_addr);
			#endif
		}
	}

	if (NDIPV6_DEBUG)
		printf
				("\n....Added a key-data pair at rte hash table for ND IPv6 static routing\n");

	if (1) {
		/* print entire hash table */
		printf
				("\tND: table update - hwaddr=%02x:%02x:%02x:%02x:%02x:%02x on port=%d\n",
				 new_nd_data->eth_addr.addr_bytes[0],
				 new_nd_data->eth_addr.addr_bytes[1],
				 new_nd_data->eth_addr.addr_bytes[2],
				 new_nd_data->eth_addr.addr_bytes[3],
				 new_nd_data->eth_addr.addr_bytes[4],
				 new_nd_data->eth_addr.addr_bytes[5], portid);
		RTE_LOG(INFO, LIBARP, "\tipv6=");
		for (i = 0; i < ND_IPV6_ADDR_SIZE; i += 2) {
			new_nd_data->ipv6[i] = ipv6[i];
			RTE_LOG(INFO, LIBARP, "%02X%02X ", new_nd_data->ipv6[i],
				new_nd_data->ipv6[i + 1]);
		}

		RTE_LOG(INFO, LIBARP, "\n");

		puts("");
	}
}

void print_pkt1(struct rte_mbuf *pkt)
{
	uint8_t *rd = RTE_MBUF_METADATA_UINT8_PTR(pkt, 0);
	int i = 0, j = 0;
	RTE_LOG(INFO, LIBARP, "\nPacket Contents...\n");
	for (i = 0; i < 20; i++) {
		for (j = 0; j < 20; j++)
			printf("%02x ", rd[(20 * i) + j]);
		RTE_LOG(INFO, LIBARP, "\n");
	}
}

#define MAX_NUM_MAC_ADDRESS 16
struct ether_addr link_hw_addr[MAX_NUM_MAC_ADDRESS] = {
{.addr_bytes = {0x90, 0xe2, 0xba, 0x54, 0x67, 0xc8} },
{.addr_bytes = {0x90, 0xe2, 0xba, 0x54, 0x67, 0xc9} },
{.addr_bytes = {0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11} },
{.addr_bytes = {0x12, 0x13, 0x14, 0x15, 0x16, 0x17} },
{.addr_bytes = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77} },
{.addr_bytes = {0x12, 0x13, 0x14, 0x15, 0x16, 0x17} },
{.addr_bytes = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77} },
{.addr_bytes = {0x90, 0xe2, 0xba, 0x54, 0x67, 0xc9} },
{.addr_bytes = {0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11} },
{.addr_bytes = {0x12, 0x13, 0x14, 0x15, 0x16, 0x17} },
{.addr_bytes = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77} },
{.addr_bytes = {0x12, 0x13, 0x14, 0x15, 0x16, 0x17} },
{.addr_bytes = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77} },
{.addr_bytes = {0x12, 0x13, 0x14, 0x15, 0x16, 0x17} },
{.addr_bytes = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77} },
{.addr_bytes = {0x18, 0x19, 0x1a, 0x1b, 0xcd, 0xef} }
};

struct ether_addr *get_link_hw_addr(uint8_t out_port)
{
	return &p_arp_data->link_hw_addr[out_port];
}

void request_arp(uint8_t port_id, uint32_t ip)
{

	struct ether_hdr *eth_h;
	struct arp_hdr *arp_h;

	l2_phy_interface_t *link;
	link = ifm_get_port(port_id);
	struct rte_mbuf *arp_pkt = lib_arp_pkt[port_id];

	if (arp_pkt == NULL) {
		if (ARPICMP_DEBUG)
			RTE_LOG(INFO, LIBARP,
				"Error allocating arp_pkt rte_mbuf\n");
		return;
	}
	eth_h = rte_pktmbuf_mtod(arp_pkt, struct ether_hdr *);

	ether_addr_copy(&broadcast_ether_addr, &eth_h->d_addr);
	ether_addr_copy((struct ether_addr *)
			&link->macaddr[0], &eth_h->s_addr);
	eth_h->ether_type = CHECK_ENDIAN_16(ETHER_TYPE_ARP);

	arp_h = (struct arp_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	arp_h->arp_hrd = CHECK_ENDIAN_16(ARP_HRD_ETHER);
	arp_h->arp_pro = CHECK_ENDIAN_16(ETHER_TYPE_IPv4);
	arp_h->arp_hln = ETHER_ADDR_LEN;
	arp_h->arp_pln = sizeof(uint32_t);
	arp_h->arp_op = CHECK_ENDIAN_16(ARP_OP_REQUEST);

	if (link && link->ipv4_list) {
		arp_h->arp_data.arp_sip =
				(((ipv4list_t *) (link->ipv4_list))->ipaddr);
	}
	ether_addr_copy((struct ether_addr *)
			&link->macaddr[0], &arp_h->arp_data.arp_sha);
	ether_addr_copy(&null_ether_addr, &arp_h->arp_data.arp_tha);
	arp_h->arp_data.arp_tip = rte_cpu_to_be_32(ip);
	if (ARPICMP_DEBUG)
		RTE_LOG(INFO, LIBARP, "arp tip:%x arp sip :%x\n",
			arp_h->arp_data.arp_tip, arp_h->arp_data.arp_sip);
	// mmcd changed length from 60 to 42 - real length of arp request, no padding on ethernet needed - looks now like linux arp
	arp_pkt->pkt_len = 42;
	arp_pkt->data_len = 42;

	if (ARPICMP_DEBUG) {
		RTE_LOG(INFO, LIBARP, "Sending arp request\n");
		print_mbuf("TX", port_id, arp_pkt, __LINE__);
	}
	if (link)
		link->transmit_single_pkt(link, arp_pkt);
//	start_tsc[port_id] = rte_rdtsc();
	printf("Sent ARP Request %x \n", arp_h->arp_data.arp_tip);
}

struct rte_mbuf *request_echo(uint32_t port_id, uint32_t ip)
{
	struct ether_hdr *eth_h;
	struct ipv4_hdr *ip_h;
	struct icmp_hdr *icmp_h;
	l2_phy_interface_t *port = ifm_get_port(port_id);

	struct rte_mbuf *icmp_pkt = lib_arp_pkt[port_id];
	if (icmp_pkt == NULL) {
		if (ARPICMP_DEBUG)
			RTE_LOG(INFO, LIBARP,
				"Error allocating icmp_pkt rte_mbuf\n");
		return NULL;
	}

	eth_h = rte_pktmbuf_mtod(icmp_pkt, struct ether_hdr *);

	ip_h = (struct ipv4_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	icmp_h = (struct icmp_hdr *)((char *)ip_h + sizeof(struct ipv4_hdr));

	ip_h->version_ihl = IP_VHL_DEF;
	ip_h->type_of_service = 0;
	ip_h->total_length =
			rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct icmp_hdr));
	ip_h->packet_id = 0xaabb;
	ip_h->fragment_offset = 0x0000;
	ip_h->time_to_live = 64;
	ip_h->next_proto_id = IPPROTO_ICMP;
	if (port && port->ipv4_list)
		ip_h->src_addr =
				rte_cpu_to_be_32(((ipv4list_t *) port->ipv4_list)->ipaddr);
	ip_h->dst_addr = rte_cpu_to_be_32(ip);

	ip_h->hdr_checksum = 0;
	ip_h->hdr_checksum = rte_ipv4_cksum(ip_h);

	icmp_h->icmp_type = IP_ICMP_ECHO_REQUEST;
	icmp_h->icmp_code = 0;
	icmp_h->icmp_ident = 0xdead;
	icmp_h->icmp_seq_nb = 0xbeef;

	icmp_h->icmp_cksum = ~rte_raw_cksum(icmp_h, sizeof(struct icmp_hdr));

	icmp_pkt->pkt_len =
			sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
			sizeof(struct icmp_hdr);
	icmp_pkt->data_len = icmp_pkt->pkt_len;

	print_mbuf("TX", 0, icmp_pkt, __LINE__);

	return icmp_pkt;
}

void
process_arpicmp_pkt_parse(struct rte_mbuf **pkt, uint16_t pkt_num,
				uint64_t pkt_mask, l2_phy_interface_t *port)
{
	RTE_SET_USED(pkt_num);
	if (ARPICMP_DEBUG)
		RTE_LOG(INFO, LIBARP,
			"============ARP ENTRY================\n");
	if (pkt_mask) {
		if (ARPICMP_DEBUG)
			RTE_LOG(INFO, LIBARP,
				"============ARP PROCESS================\n");
	}

	uint64_t pkts_for_process = pkt_mask;
	for (; pkts_for_process;) {
/**< process only valid packets. */
		uint8_t pos = (uint8_t) __builtin_ctzll(pkts_for_process);
		uint64_t pkts_mask = 1LLU << pos;    /** <bitmask representing only this packet. */
		pkts_for_process &= ~pkts_mask;				/** <remove this packet from the mask. */
		process_arpicmp_pkt(pkt[pos], port);
	}

}

void process_arpicmp_pkt(struct rte_mbuf *pkt, l2_phy_interface_t *port)
{
	uint8_t in_port_id = pkt->port;
	struct ether_hdr *eth_h;
	struct arp_hdr *arp_h;
	struct ipv4_hdr *ip_h;
	struct icmp_hdr *icmp_h;

	uint32_t cksum;
	uint32_t ip_addr;

	uint32_t req_tip;
	eth_h = rte_pktmbuf_mtod(pkt, struct ether_hdr *);

	if (eth_h->ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP)) {
		if (ARPICMP_DEBUG)
			RTE_LOG(INFO, LIBARP, "%s, portid %u. Line %d\n\r",
				__FUNCTION__, port->pmdid, __LINE__);
		arp_h =
				(struct arp_hdr *)((char *)eth_h +
							 sizeof(struct ether_hdr));
		if (CHECK_ENDIAN_16(arp_h->arp_hrd) != ARP_HRD_ETHER)
			RTE_LOG(INFO, LIBARP,
				"Invalid hardware format of hardware address - not processing ARP req\n");
		else if (CHECK_ENDIAN_16(arp_h->arp_pro) != ETHER_TYPE_IPv4)
			RTE_LOG(INFO, LIBARP,
				"Invalid protocol address format - not processing ARP req\n");
		else if (arp_h->arp_hln != 6)
			RTE_LOG(INFO, LIBARP,
				"Invalid hardware address length - not processing ARP req\n");
		else if (arp_h->arp_pln != 4)
			RTE_LOG(INFO, LIBARP,
				"Invalid protocol address length - not processing ARP req\n");
		else {
			if (port->ipv4_list == NULL) {
				RTE_LOG(INFO, LIBARP,
					"Ports IPV4 List is NULL.. Unable to Process\n");
				return;
			}

			if (arp_h->arp_data.arp_tip !=
					((ipv4list_t *) (port->ipv4_list))->ipaddr) {
				if (arp_h->arp_data.arp_tip == arp_h->arp_data.arp_sip) {
					printf("gratuitous arp received\n");
					populate_arp_entry(
							(struct ether_addr *)&arp_h->arp_data.arp_sha,
							rte_cpu_to_be_32(arp_h->arp_data.arp_sip),
							in_port_id,
							DYNAMIC_ARP);

				} else {
		   if (ARPICMP_DEBUG)
					    RTE_LOG(INFO, LIBARP,"ARP requested IP address mismatches interface IP - discarding\n");
				}
			}
			/// revise conditionals to allow processing of requests with target ip = this ip and
			//                               processing of replies to destination ip = this ip
			else if (arp_h->arp_op ==
				 rte_cpu_to_be_16(ARP_OP_REQUEST)) {
				if (ARPICMP_DEBUG) {
					RTE_LOG(INFO, LIBARP,
						"%s, portid %u. Line %d\n\r",
						__FUNCTION__, port->pmdid,
						__LINE__);

					RTE_LOG(INFO, LIBARP,
						"arp_op %d, ARP_OP_REQUEST %d\n",
						arp_h->arp_op,
						rte_cpu_to_be_16
						(ARP_OP_REQUEST));
					print_mbuf("RX", in_port_id, pkt,
							 __LINE__);
				}
				populate_arp_entry((struct ether_addr *)
							 &arp_h->arp_data.arp_sha,
							 rte_cpu_to_be_32
							 (arp_h->arp_data.arp_sip),
							 in_port_id, DYNAMIC_ARP);

				/*build reply */
				req_tip = arp_h->arp_data.arp_tip;
				ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
				ether_addr_copy((struct ether_addr *)&port->macaddr[0], &eth_h->s_addr);  /**< set sender mac address*/
				arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
				ether_addr_copy(&eth_h->s_addr,
						&arp_h->arp_data.arp_sha);
				arp_h->arp_data.arp_tip =
						arp_h->arp_data.arp_sip;
				arp_h->arp_data.arp_sip = req_tip;
				ether_addr_copy(&eth_h->d_addr,
						&arp_h->arp_data.arp_tha);
				if (ARPICMP_DEBUG)
					print_mbuf("TX ARP REPLY PKT",
							 port->pmdid, pkt, __LINE__);
				port->transmit_bulk_pkts(port, &pkt, 1);
				if (ARPICMP_DEBUG)
					print_mbuf("TX", port->pmdid, pkt,
							 __LINE__);
				printf("replying arp pkt done\n");
				return;
			} else if (arp_h->arp_op ==
					 rte_cpu_to_be_16(ARP_OP_REPLY)) {
				if (ARPICMP_DEBUG) {
					RTE_LOG(INFO, LIBARP,
						"ARP_OP_REPLY received");
					print_mbuf("RX", port->pmdid, pkt,
							 __LINE__);
				}
				populate_arp_entry((struct ether_addr *)
							 &arp_h->arp_data.arp_sha,
							 rte_bswap32(arp_h->
										 arp_data.arp_sip),
							 in_port_id, DYNAMIC_ARP);

				return;
			} else {
				if (ARPICMP_DEBUG)
					RTE_LOG(INFO, LIBARP,
						"Invalid ARP opcode - not processing ARP req %x\n",
						arp_h->arp_op);
			}
		}

		rte_pktmbuf_free(pkt);
	} else {
		ip_h =
				(struct ipv4_hdr *)((char *)eth_h +
					sizeof(struct ether_hdr));
		icmp_h =
				(struct icmp_hdr *)((char *)ip_h + sizeof(struct ipv4_hdr));

		if (eth_h->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {

			if (ip_h->next_proto_id != IPPROTO_ICMP) {
				if (ARPICMP_DEBUG) {
					RTE_LOG(INFO, LIBARP,
						"IP protocol ID is not set to ICMP - discarding\n");
				}
			} else if ((ip_h->version_ihl & 0xf0) != IP_VERSION_4) {
				if (ARPICMP_DEBUG) {
					RTE_LOG(INFO, LIBARP,
						"IP version other than 4 - discarding\n");
				}
			} else if ((ip_h->version_ihl & 0x0f) != IP_HDRLEN) {
				if (ARPICMP_DEBUG) {
					RTE_LOG(INFO, LIBARP,
						"Unknown IHL - discarding\n");
				}
			} else {
				if (icmp_h->icmp_type == IP_ICMP_ECHO_REQUEST
						&& icmp_h->icmp_code == 0) {
					if (ARPICMP_DEBUG)
						print_mbuf("RX", in_port_id,
								 pkt, __LINE__);

					ip_addr = ip_h->src_addr;
					ether_addr_copy(&eth_h->s_addr,
							&eth_h->d_addr);
					ether_addr_copy((struct ether_addr *)
							&port->macaddr[0],
							&eth_h->s_addr);
					if (ARPICMP_DEBUG)
						RTE_LOG(INFO, LIBARP,
							"%s, portid %u. Line %d\n\r",
							__FUNCTION__,
							port->pmdid, __LINE__);

					if (is_multicast_ipv4_addr
							(ip_h->dst_addr)) {
						uint32_t ip_src;

						ip_src =
								rte_be_to_cpu_32(ip_addr);
						if ((ip_src & 0x00000003) == 1)
							ip_src =
									(ip_src &
									 0xFFFFFFFC) |
									0x00000002;
						else
							ip_src =
									(ip_src &
									 0xFFFFFFFC) |
									0x00000001;
						ip_h->src_addr =
								rte_cpu_to_be_32(ip_src);
						ip_h->dst_addr = ip_addr;

						ip_h->hdr_checksum = 0;
						ip_h->hdr_checksum =
								~rte_raw_cksum(ip_h,
									 sizeof(struct
										ipv4_hdr));
					} else {
						if (ARPICMP_DEBUG)
							RTE_LOG(INFO, LIBARP,
								"%s, portid %u. Line %d\n\r",
								__FUNCTION__,
								port->pmdid,
								__LINE__);
						ip_h->src_addr = ip_h->dst_addr;
						ip_h->dst_addr = ip_addr;
					}

					icmp_h->icmp_type = IP_ICMP_ECHO_REPLY;
					cksum = ~icmp_h->icmp_cksum & 0xffff;
					cksum +=
							~htons(IP_ICMP_ECHO_REQUEST << 8) &
							0xffff;
					cksum += htons(IP_ICMP_ECHO_REPLY << 8);
					cksum =
							(cksum & 0xffff) + (cksum >> 16);
					cksum =
							(cksum & 0xffff) + (cksum >> 16);
					icmp_h->icmp_cksum = ~cksum;

					if (ARPICMP_DEBUG)
						print_mbuf
								("TX ICMP ECHO REPLY PKT",
								 in_port_id, pkt, __LINE__);
					port->transmit_bulk_pkts(port, &pkt, 1);
					if (ARPICMP_DEBUG)
						print_mbuf("TX", port->pmdid,
								 pkt, __LINE__);

					return;
				} else if (icmp_h->icmp_type ==
						 IP_ICMP_ECHO_REPLY
						 && icmp_h->icmp_code == 0) {
					if (ARPICMP_DEBUG)
						print_mbuf("RX", in_port_id,
								 pkt, __LINE__);

					struct arp_key_ipv4 arp_key;
					arp_key.port_id = in_port_id;
					arp_key.ip =
							rte_bswap32(ip_h->src_addr);
					arp_key.filler1 = 0;
					arp_key.filler2 = 0;
					arp_key.filler3 = 0;

					struct arp_entry_data *arp_entry =
							retrieve_arp_entry(arp_key,
								 DYNAMIC_ARP);
					if (arp_entry == NULL) {
						if (ARPICMP_DEBUG)
							RTE_LOG(INFO, LIBARP,
								"Received unsolicited ICMP echo reply from ip%x, port %d\n",
								arp_key.ip,
								arp_key.port_id);
						return;
					}
					arp_entry->status = COMPLETE;
				}
			}
		}

		rte_pktmbuf_free(pkt);
	}
}

/* int
 * inet_pton(af, src, dst)
 *      convert from presentation format (which usually means ASCII printable)
 *      to network format (which is usually some kind of binary format).
 * return:
 *      1 if the address was valid for the specified address family
 *      0 if the address wasn't valid (`dst' is untouched in this case)
 *      -1 if some other error occurred (`dst' is untouched in this case, too)
 * author:
 *      Paul Vixie, 1996.
 */
int my_inet_pton_ipv6(int af, const char *src, void *dst)
{
	switch (af) {
	case AF_INET:
		return inet_pton_ipv4(src, dst);
	case AF_INET6:
		return inet_pton_ipv6(src, dst);
	default:
		errno = EAFNOSUPPORT;
		return -1;
	}
	/* NOTREACHED */
}

/* int
 * inet_pton_ipv4(src, dst)
 *      like inet_aton() but without all the hexadecimal and shorthand.
 * return:
 *      1 if `src' is a valid dotted quad, else 0.
 * notice:
 *      does not touch `dst' unless it's returning 1.
 * author:
 *      Paul Vixie, 1996.
 */
static int inet_pton_ipv4(const char *src, unsigned char *dst)
{
	static const char digits[] = "0123456789";
	int saw_digit, octets, ch;
	unsigned char tmp[INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		pch = strchr(digits, ch);
		if (pch != NULL) {
			unsigned int new = *tp * 10 + (pch - digits);

			if (new > 255)
				return 0;
			if (!saw_digit) {
				if (++octets > 4)
					return 0;
				saw_digit = 1;
			}
			*tp = (unsigned char)new;
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return 0;
			*++tp = 0;
			saw_digit = 0;
		} else
			return 0;
	}
	if (octets < 4)
		return 0;

	memcpy(dst, tmp, INADDRSZ);
	return 1;
}

/* int
 * inet_pton_ipv6(src, dst)
 *      convert presentation level address to network order binary form.
 * return:
 *      1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *      (1) does not touch `dst' unless it's returning 1.
 *      (2) :: in a full address is silently ignored.
 * credit:
 *      inspired by Mark Andrews.
 * author:
 *      Paul Vixie, 1996.
 */
static int inet_pton_ipv6(const char *src, unsigned char *dst)
{
	static const char xdigits_l[] = "0123456789abcdef",
			xdigits_u[] = "0123456789ABCDEF";
	unsigned char tmp[IN6ADDRSZ], *tp = 0, *endp = 0, *colonp = 0;
	const char *xdigits = 0, *curtok = 0;
	int ch = 0, saw_xdigit = 0, count_xdigit = 0;
	unsigned int val = 0;
	unsigned int dbloct_count = 0;

	memset((tp = tmp), '\0', IN6ADDRSZ);
	endp = tp + IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return 0;
	curtok = src;
	saw_xdigit = count_xdigit = 0;
	val = 0;

	while ((ch = *src++) != '\0') {
		const char *pch;

		pch = strchr((xdigits = xdigits_l), ch);
		if (pch == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			if (count_xdigit >= 4)
				return 0;
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return 0;
			saw_xdigit = 1;
			count_xdigit++;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return 0;
				colonp = tp;
				continue;
			} else if (*src == '\0') {
				return 0;
			}
			if (tp + sizeof(int16_t) > endp)
				return 0;
			*tp++ = (unsigned char)((val >> 8) & 0xff);
			*tp++ = (unsigned char)(val & 0xff);
			saw_xdigit = 0;
			count_xdigit = 0;
			val = 0;
			dbloct_count++;
			continue;
		}
		if (ch == '.' && ((tp + INADDRSZ) <= endp) &&
				inet_pton_ipv4(curtok, tp) > 0) {
			tp += INADDRSZ;
			saw_xdigit = 0;
			dbloct_count += 2;
			break;	/* '\0' was seen by inet_pton4(). */
		}
		return 0;
	}
	if (saw_xdigit) {
		if (tp + sizeof(int16_t) > endp)
			return 0;
		*tp++ = (unsigned char)((val >> 8) & 0xff);
		*tp++ = (unsigned char)(val & 0xff);
		dbloct_count++;
	}
	if (colonp != NULL) {
		/* if we already have 8 double octets, having a colon means error */
		if (dbloct_count == 8)
			return 0;

		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = tp - colonp;
		int i;

		for (i = 1; i <= n; i++) {
			endp[-i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return 0;
	memcpy(dst, tmp, IN6ADDRSZ);
	return 1;
}

static int arp_parse_args(struct pipeline_params *params)
{
	uint32_t arp_route_tbl_present = 0;
	uint32_t nd_route_tbl_present = 0;
	uint32_t numArg;
	uint32_t n_vnf_threads_present = 0;

	uint32_t pktq_in_prv_present = 0;
	uint32_t prv_to_pub_map_present = 0;

	uint8_t n_prv_in_port = 0;
	int i;
	for (i = 0; i < PIPELINE_MAX_PORT_IN; i++) {
		in_port_dir_a[i] = 0;	//make all RX ports ingress initially
		prv_to_pub_map[i] = 0xff;
		pub_to_prv_map[i] = 0xff;
	}

	RTE_SET_USED(nd_route_tbl_present);
	RTE_SET_USED(arp_route_tbl_present);
	for (numArg = 0; numArg < params->n_args; numArg++) {
		char *arg_name = params->args_name[numArg];
		char *arg_value = params->args_value[numArg];

		/* arp timer expiry */
		if (strcmp(arg_name, "arp_timer_expiry") == 0) {
			arp_timeout = atoi(arg_value);
		}

		/* pktq_in_prv */
		if (strcmp(arg_name, "pktq_in_prv") == 0) {
			if (pktq_in_prv_present) {
				printf
						("Duplicate pktq_in_prv ... parse failed..\n\n");
				return -1;
			}
			pktq_in_prv_present = 1;

			int rxport = 0, j = 0;
			char phy_port_num[5];
			char *token = strtok(arg_value, "RXQ");
			while (token) {
				j = 0;
				while ((j < 4) && (token[j] != '.')) {
					phy_port_num[j] = token[j];
					j++;
				}
				phy_port_num[j] = '\0';
				rxport = atoi(phy_port_num);
				prv_in_port_a[n_prv_in_port++] = rxport;
				if (rxport < 0)
					rxport = 0;
				printf
						("token: %s, phy_port_str: %s, phy_port_num %d\n",
						 token, phy_port_num, rxport);
				prv_in_port_a[n_prv_in_port++] = rxport;
				if(rxport < PIPELINE_MAX_PORT_IN)
				in_port_dir_a[rxport] = 1;	// set rxport egress
				token = strtok(NULL, "RXQ");
			}

			if (n_prv_in_port == 0) {
				printf
						("VNF common parse error - no prv RX phy port\n");
				return -1;
			}
			continue;
		}

		if (strcmp(arg_name, "arp_buf") == 0) {
			arp_buffer = atoi(arg_value);
			continue;
		}

		if (strcmp(arg_name, "nd_buf") == 0) {
			nd_buffer = atoi(arg_value);
			continue;
		}

		/* prv_to_pub_map */
		if (strcmp(arg_name, "prv_to_pub_map") == 0) {
			if (prv_to_pub_map_present) {
				printf
						("Duplicated prv_to_pub_map ... parse failed ...\n");
				return -1;
			}
			prv_to_pub_map_present = 1;

			int rxport = 0, txport = 0, j = 0, k = 0;
			char rx_phy_port_num[5];
			char tx_phy_port_num[5];
			char *token = strtok(arg_value, "(");
			while (token) {
				j = 0;
				while ((j < 4) && (token[j] != ',')) {
					rx_phy_port_num[j] = token[j];
					j++;
				}
				rx_phy_port_num[j] = '\0';
				rxport = atoi(rx_phy_port_num);
				if (rxport < 0)
					rxport = 0;

				j++;
				k = 0;
				while ((k < 4) && (token[j + k] != ')')) {
					tx_phy_port_num[k] = token[j + k];
					k++;
				}
				tx_phy_port_num[k] = '\0';
				txport = atoi(tx_phy_port_num);
				if (txport < 0)
					txport = 0;

				RTE_LOG(INFO, LIBARP, "token: %s,"
					"rx_phy_port_str: %s, phy_port_num %d,"
					"tx_phy_port_str: %s, tx_phy_port_num %d\n",
					token, rx_phy_port_num, rxport,
					tx_phy_port_num, txport);

				if ((rxport >= PIPELINE_MAX_PORT_IN) ||
						(txport >= PIPELINE_MAX_PORT_IN) ||
						(in_port_dir_a[rxport] != 1)) {
					printf
							("CG-NAPT parse error - incorrect prv-pub translation. Rx %d, Tx %d, Rx Dir %d\n",
							 rxport, txport,
							 in_port_dir_a[rxport]);
					return -1;
				}

				prv_to_pub_map[rxport] = txport;
				pub_to_prv_map[txport] = rxport;
				token = strtok(NULL, "(");
			}

			continue;
		}
		//n_vnf_threads = 3
		if (strcmp(arg_name, "n_vnf_threads") == 0) {
			if (n_vnf_threads_present)
				return -1;
			n_vnf_threads_present = 1;
			trim(arg_value);
			num_vnf_threads = atoi(arg_value);
			if (num_vnf_threads <= 0) {
				RTE_LOG(INFO, LIBARP,
					"n_vnf_threads is invalid\n");
				return -1;
			}
			RTE_LOG(INFO, LIBARP, "n_vnf_threads: 0x%x\n",
				num_vnf_threads);
		}

		/* lib_arp_debug */
		if (strcmp(arg_name, "lib_arp_debug") == 0) {
			ARPICMP_DEBUG = atoi(arg_value);

			continue;
		}

		/* arp_route_tbl */
		if (strcmp(arg_name, "arp_route_tbl") == 0) {
			arp_route_tbl_present = 1;

			uint32_t dest_ip = 0, mask = 0, tx_port = 0, nh_ip =
					0, i = 0, j = 0, k = 0, l = 0;
			uint32_t arp_route_tbl_str_max_len = 10;
			char dest_ip_str[arp_route_tbl_str_max_len];
			char mask_str[arp_route_tbl_str_max_len];
			char tx_port_str[arp_route_tbl_str_max_len];
			char nh_ip_str[arp_route_tbl_str_max_len];
			char *token = strtok(arg_value, "(");
			while (token) {
				i = 0;
				while ((i < (arp_route_tbl_str_max_len - 1))
							 && (token[i] != ',')) {
					dest_ip_str[i] = token[i];
					i++;
				}
				dest_ip_str[i] = '\0';
				dest_ip = strtoul(dest_ip_str, NULL, 16);

				i++;
				j = 0;
				while ((j < (arp_route_tbl_str_max_len - 1))
							 && (token[i + j] != ',')) {
					mask_str[j] = token[i + j];
					j++;
				}
				mask_str[j] = '\0';
				mask = strtoul(mask_str, NULL, 16);

				j++;
				k = 0;
				while ((k < (arp_route_tbl_str_max_len - 1))
							 && (token[i + j + k] != ',')) {
					tx_port_str[k] = token[i + j + k];
					k++;
				}
				tx_port_str[k] = '\0';
				tx_port = strtoul(tx_port_str, NULL, 16);	//atoi(tx_port_str);

				k++;
				l = 0;
				while ((l < (arp_route_tbl_str_max_len - 1))
							 && (token[i + j + k + l] != ')')) {
					nh_ip_str[l] = token[i + j + k + l];
					l++;
				}
				nh_ip_str[l] = '\0';
				nh_ip = strtoul(nh_ip_str, NULL, 16);	//atoi(nh_ip_str);

				if (1) {
					RTE_LOG(INFO, LIBARP, "token: %s, "
						"dest_ip_str: %s, dest_ip %u, "
						"mask_str: %s, mask %u, "
						"tx_port_str: %s, tx_port %u, "
						"nh_ip_str: %s, nh_ip %u\n",
						token, dest_ip_str, dest_ip,
						mask_str, mask, tx_port_str,
						tx_port, nh_ip_str, nh_ip);
				}

				/*  if (tx_port >= params->n_ports_out)
					 {
					 RTE_LOG(INFO, LIBARP,"ARP-ICMP parse error - incorrect tx_port %d, max %d\n",
					 tx_port, params->n_ports_out);
					 return -1;
					 }
				 */
				//Populate the static arp_route_table
			        struct lib_arp_route_table_entry *lentry =
		                &p_arp_data->lib_arp_route_table
				[p_arp_data->lib_arp_route_ent_cnt];
				lentry->ip = dest_ip;
				lentry->mask = mask;
				lentry->port = tx_port;
				lentry->nh = nh_ip;
				lentry->nh_mask = nh_ip & mask;
				p_arp_data->lib_arp_route_ent_cnt++;
				token = strtok(NULL, "(");
			}

			continue;
		}
		/*ND IPv6 */
		/* nd_route_tbl */
		if (strcmp(arg_name, "nd_route_tbl") == 0) {
			nd_route_tbl_present = 1;

			uint8_t dest_ipv6[16], depth = 0, tx_port =
					0, nh_ipv6[16], i = 0, j = 0, k = 0, l = 0;
			uint8_t nd_route_tbl_str_max_len = 128;	//64;
			char dest_ipv6_str[nd_route_tbl_str_max_len];
			char depth_str[nd_route_tbl_str_max_len];
			char tx_port_str[nd_route_tbl_str_max_len];
			char nh_ipv6_str[nd_route_tbl_str_max_len];
			char *token = strtok(arg_value, "(");
			while (token) {
				i = 0;
				while ((i < (nd_route_tbl_str_max_len - 1))
							 && (token[i] != ',')) {
					dest_ipv6_str[i] = token[i];
					i++;
				}
				dest_ipv6_str[i] = '\0';
				my_inet_pton_ipv6(AF_INET6, dest_ipv6_str,
							&dest_ipv6);

				i++;
				j = 0;
				while ((j < (nd_route_tbl_str_max_len - 1))
							 && (token[i + j] != ',')) {
					depth_str[j] = token[i + j];
					j++;
				}
				depth_str[j] = '\0';
				//converting string char to integer
				int s;
				for (s = 0; depth_str[s] != '\0'; ++s)
					depth = depth * 10 + depth_str[s] - '0';

				j++;
				k = 0;
				while ((k < (nd_route_tbl_str_max_len - 1))
							 && (token[i + j + k] != ',')) {
					tx_port_str[k] = token[i + j + k];
					k++;
				}
				tx_port_str[k] = '\0';
				tx_port = strtoul(tx_port_str, NULL, 16);	//atoi(tx_port_str);

				k++;
				l = 0;
				while ((l < (nd_route_tbl_str_max_len - 1))
							 && (token[i + j + k + l] != ')')) {
					nh_ipv6_str[l] = token[i + j + k + l];
					l++;
				}
				nh_ipv6_str[l] = '\0';
				my_inet_pton_ipv6(AF_INET6, nh_ipv6_str,
							&nh_ipv6);

				//Populate the static arp_route_table
				for (i = 0; i < 16; i++) {
					lib_nd_route_table
							[nd_route_tbl_index].ipv6[i] =
							dest_ipv6[i];
					lib_nd_route_table
							[nd_route_tbl_index].nhipv6[i] =
							nh_ipv6[i];
				}
				lib_nd_route_table[nd_route_tbl_index].depth =
						depth;
				lib_nd_route_table[nd_route_tbl_index].port =
						tx_port;

				nd_route_tbl_index++;
				token = strtok(NULL, "(");
			}

			continue;
		}
		/* any other */
		//return -1;
	}
	/* Check that mandatory arguments are present */
	/*
		 if ((arp_route_tbl_present == 0) || (ports_mac_list_present == 0)) {
		 RTE_LOG(INFO, LIBARP,"VNF common not all mandatory arguments are present\n");
		 RTE_LOG(INFO, LIBARP,"%d, %d \n",
		 arp_route_tbl_present, ports_mac_list_present);
		 return -1;
		 }
	 */

	return 0;
}

static void local_arp_cache_init(void)
{
        int i, j, k;
        for (i=0; i<MAX_PORTS;i++) {
                for (j=0; j<MAX_LOCAL_MAC_ADDRESS;j++) {
                        p_arp_data->arp_local_cache[i].nhip[j] = 0;
                        for (k=0;k<6;k++)
                                p_arp_data->arp_local_cache[i].link_hw_laddr[j].addr_bytes[k] = 0;
                        p_arp_data->arp_local_cache[i].num_nhip = 0;
                }
        }
}

struct ether_addr *get_nd_local_link_hw_addr(uint8_t out_port, uint8_t nhip[])
{
        int i, j, limit;
        struct ether_addr *x = NULL;
        limit = p_arp_data->nd_local_cache[out_port].num_nhip;

        for (i=0; i < limit; i++) {
		for (j=0;j<16;j++) {
			if (p_arp_data->nd_local_cache[out_port].nhip[i][j] != nhip[j])
				continue;
		}

                x = &p_arp_data->nd_local_cache[out_port].link_hw_laddr[i];
		return x;
        }

	return x;
}

struct ether_addr *get_local_link_hw_addr(uint8_t out_port, uint32_t nhip)
{
        int i, limit;
	uint32_t tmp;
        struct ether_addr *x = NULL;
        limit = p_arp_data->arp_local_cache[out_port].num_nhip;
        for (i=0; i < limit; i++) {
                tmp = p_arp_data->arp_local_cache[out_port].nhip[i];
                if (tmp == nhip) {
			x = &p_arp_data->arp_local_cache[out_port].link_hw_laddr[i];
                        return x;
		}
        }
	return x;
}

void lib_arp_init(struct pipeline_params *params,
			__rte_unused struct app_params *app)
{

	int i;
	uint32_t size;
	struct pipeline_cgnapt *p;

	RTE_LOG(INFO, LIBARP, "ARP initialization ...\n");

	/* create arp data for table entries */
        size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct arp_data));
        p = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
        p_arp_data = (struct arp_data *)p;

	/* Parse arguments */
	if (arp_parse_args(params)) {
		RTE_LOG(INFO, LIBARP, "arp_parse_args failed ...\n");
		return;
	}

	/* acquire the mac addresses */
	struct ether_addr hw_addr;
	uint8_t nb_ports = rte_eth_dev_count();

	for (i = 0; i < nb_ports; i++) {
		rte_eth_macaddr_get(i, &hw_addr);
		ether_addr_copy(&hw_addr, &p_arp_data->link_hw_addr[i]);
		p_arp_data->link_hw_addr_array_idx++;
	}

	/* create a lock for arp/nd hash */
	rte_rwlock_init(&arp_hash_handle_lock);
	rte_rwlock_init(&nd_hash_handle_lock);

	/* create the arp_icmp mbuf rx pool */
	lib_arp_pktmbuf_tx_pool =
			rte_pktmbuf_pool_create("lib_arp_mbuf_tx_pool", NB_ARPICMP_MBUF, 32,
						0, RTE_MBUF_DEFAULT_BUF_SIZE,
						rte_socket_id());

	if (lib_arp_pktmbuf_tx_pool == NULL) {
		RTE_LOG(INFO, LIBARP, "ARP mbuf pool create failed.\n");
		return;
	}

	for (i=0; i<MAX_PORTS; i++) {
		lib_arp_pkt[i] = rte_pktmbuf_alloc(lib_arp_pktmbuf_tx_pool);
		if (lib_arp_pkt[i] == NULL) {
			RTE_LOG(INFO, LIBARP, "ARP lib_arp_pkt alloc failed.\n");
			return;
		}
	}

	/* create the nd icmp mbuf rx pool */
	lib_nd_pktmbuf_tx_pool =
			rte_pktmbuf_pool_create("lib_nd_mbuf_tx_pool", NB_ARPICMP_MBUF, 32,
						0, RTE_MBUF_DEFAULT_BUF_SIZE,
						rte_socket_id());

	if (lib_nd_pktmbuf_tx_pool == NULL) {
		RTE_LOG(INFO, LIBARP, "ND mbuf pool create failed.\n");
		return;
	}

	for (i=0; i<MAX_PORTS; i++) {
		lib_nd_pkt[i] = rte_pktmbuf_alloc(lib_nd_pktmbuf_tx_pool);
		if (lib_nd_pkt[i] == NULL) {
			RTE_LOG(INFO, LIBARP, "ND lib_nd_pkt alloc failed.\n");
			return;
		}
	}

	/* create the arp_icmp mbuf rx pool */
	arp_icmp_pktmbuf_tx_pool = rte_pktmbuf_pool_create("arp_icmp_mbuf_tx_pool",
					NB_ARPICMP_MBUF, MAX_POOL, 0,
					RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (arp_icmp_pktmbuf_tx_pool == NULL) {
		RTE_LOG(INFO, LIBARP, "icmp_pktmbuf pool creation failed\n");
		return;
	}

	arp_hash_params.socket_id = rte_socket_id();
	arp_hash_params.entries = MAX_NUM_ARP_ENTRIES;
	arp_hash_params.key_len = sizeof(struct arp_key_ipv4);
	arp_hash_handle = rte_hash_create(&arp_hash_params);

	if (arp_hash_handle == NULL) {
		RTE_LOG(INFO, LIBARP,
			"ARP rte_hash_create failed. socket %d ... \n",
			arp_hash_params.socket_id);
	} else {
		RTE_LOG(INFO, LIBARP, "arp_hash_handle %p\n\n",
			(void *)arp_hash_handle);
	}

	/* Create port alloc buffer */

	timer_mempool_arp = rte_mempool_create("timer_mempool_arp",
								 timer_objs_mempool_count,
								 sizeof(struct rte_timer),
								 0, 0,
								 NULL, NULL,
								 NULL, NULL, rte_socket_id(), 0);
	if (timer_mempool_arp == NULL) {
		rte_panic("timer_mempool create error\n");
	}
	rte_timer_subsystem_init();
	list_add_type(ETHER_TYPE_ARP, process_arpicmp_pkt_parse);

	/* ND IPv6 */
	nd_hash_params.socket_id = rte_socket_id();
	nd_hash_params.entries = MAX_NUM_ND_ENTRIES;
	nd_hash_params.key_len = sizeof(struct nd_key_ipv6);
	nd_hash_handle = rte_hash_create(&nd_hash_params);
	if (nd_hash_handle == NULL) {
		RTE_LOG(INFO, LIBARP,
			"ND rte_hash_create failed. socket %d ... \n",
			nd_hash_params.socket_id);
	} else {
		RTE_LOG(INFO, LIBARP, "nd_hash_handle %p\n\n",
			(void *)nd_hash_handle);
	}

        /* Initialize the local arp cache */
        local_arp_cache_init();

	return;
}

void arp_timer_callback(struct rte_timer *timer, void *arg)
{
	struct arp_timer_key *timer_key = (struct arp_timer_key *)arg;
        struct arp_key_ipv4 arp_key;
        arp_key.port_id = timer_key->port_id;
        arp_key.ip = timer_key->ip;
        arp_key.filler1 = 0;
        arp_key.filler2 = 0;
        arp_key.filler3 = 0;

	struct arp_entry_data *ret_arp_data = NULL;
	uint64_t now;
	if (ARPICMP_DEBUG) {
		RTE_LOG(INFO, LIBARP, "arp_timer_callback ip %x, port %d\n",
		arp_key.ip, arp_key.port_id);
	}

	int ret = rte_hash_lookup_data(arp_hash_handle, &arp_key,
					 (void **)&ret_arp_data);
	now = rte_rdtsc();

	if (ARPICMP_DEBUG)
		RTE_LOG(INFO, LIBARP, "ARP TIMER callback : expire :%d now:%ld\n",
			(int)timer->expire, now);
	if (ret < 0) {
		printf("Should not have come here\n");
		return;
	} else {
		if (ret_arp_data->mode == DYNAMIC_ARP) {
			rte_rwlock_write_lock(&ret_arp_data->queue_lock);
			if (ret_arp_data->status == PROBE ||
				ret_arp_data->status == INCOMPLETE) {
				if (ret_arp_data->retry_count == 3) {
					remove_arp_entry(ret_arp_data, arg);
				} else {
					ret_arp_data->retry_count++;

					if (ARPICMP_DEBUG) {
						RTE_LOG(INFO, LIBARP,
						"RETRY ARP..retry count : %u\n",
						ret_arp_data->retry_count);

						RTE_LOG(INFO, LIBARP,
						"TIMER STARTED FOR %u seconds\n",
							ARP_TIMER_EXPIRY);
					}

					if (ifm_chk_port_ipv4_enabled
						(ret_arp_data->port) != IFM_FAILURE) {
						request_arp(ret_arp_data->port,
								ret_arp_data->ip);
					} else {
						if (ARPICMP_DEBUG)
							RTE_LOG(INFO, LIBARP,
							"%s: IP is not enabled on port %u"
							", not sending GARP\n\r",
							__FUNCTION__,
							ret_arp_data->port);
					}

					if (rte_timer_reset(ret_arp_data->timer,
								(PROBE_TIME *
								 rte_get_tsc_hz()/ 1000),
								SINGLE,
								timer_lcore,
								arp_timer_callback,
								arg) < 0)
					if (ARPICMP_DEBUG)
						RTE_LOG(INFO, LIBARP,
							"Err : Timer already running\n");

				}
			} else if (ret_arp_data->status == COMPLETE) {
				if (now <= (ret_arp_data->n_confirmed +
					 (arp_timeout * rte_get_tsc_hz()))) {
					if (rte_timer_reset(ret_arp_data->timer,
								(arp_timeout *
								 rte_get_tsc_hz()), SINGLE,
								timer_lcore,
								arp_timer_callback,
								arg) < 0)
					if (ARPICMP_DEBUG)
						RTE_LOG(INFO, LIBARP,
							"Err : Timer already running\n");
				} else if (now <= (p_arp_data->update_tsc[ret_arp_data->port] + (USED_TIME * rte_get_tsc_hz()))) {
					if (rte_timer_reset(ret_arp_data->timer,
								(arp_timeout *
								 rte_get_tsc_hz()), SINGLE,
								timer_lcore,
								arp_timer_callback,
								arg) < 0)
					if (ARPICMP_DEBUG)
						RTE_LOG(INFO, LIBARP,
							"Err : Timer already running\n");
				} else {
					ret_arp_data->status = STALE;
					p_arp_data->arp_cache_hw_laddr_valid[ret_arp_data->port] = 0;
				}
			}
			rte_rwlock_write_unlock(&ret_arp_data->queue_lock);
		} else {
			rte_hash_del_key(arp_hash_handle, &arp_key);
		}
	}
	return;
}

void nd_timer_callback(struct rte_timer *timer, void *arg)
{
	struct nd_timer_key *timer_key = (struct nd_timer_key *)arg;
        struct nd_key_ipv6 nd_key;
	int j;
	struct nd_entry_data *ret_nd_data = NULL;
	uint64_t now;

        nd_key.port_id = timer_key->port_id;
        nd_key.filler1 = 0;
        nd_key.filler2 = 0;
        nd_key.filler3 = 0;

	rte_mov16(&nd_key.ipv6[0], timer_key->ipv6);

	if (ARPICMP_DEBUG) {
		RTE_LOG(INFO, LIBARP, "nd_timer_callback port %d\n",
		nd_key.port_id);
	}

	int ret = rte_hash_lookup_data(nd_hash_handle, &nd_key,
					 (void **)&ret_nd_data);
	now = rte_rdtsc();

	if (ARPICMP_DEBUG)
		RTE_LOG(INFO, LIBARP, "ND TIMER callback : expire :%d now:%ld\n",
			(int)timer->expire, now);
	if (ret < 0) {
		printf("Should not have come here \n");
		for (j = 0; j < 16; j++)
			printf("*%d ", nd_key.ipv6[j]);
		printf("*%d ", nd_key.port_id);
		return;
	} else {
		if (ret_nd_data->mode == DYNAMIC_ARP) {
			rte_rwlock_write_lock(&ret_nd_data->queue_lock);
			if (ret_nd_data->status == PROBE ||
				ret_nd_data->status == INCOMPLETE) {
				if (ret_nd_data->retry_count == 3) {
					remove_nd_entry_ipv6(ret_nd_data, arg);
				} else {
					ret_nd_data->retry_count++;

					if (ARPICMP_DEBUG) {
						RTE_LOG(INFO, LIBARP,
						"RETRY ND..retry count : %u\n",
						ret_nd_data->retry_count);

						RTE_LOG(INFO, LIBARP,
						"TIMER STARTED FOR %u seconds\n",
							ARP_TIMER_EXPIRY);
					}

					request_nd(ret_nd_data->ipv6,
						 ifm_get_port(ret_nd_data->port));
					if (rte_timer_reset(ret_nd_data->timer,
								(PROBE_TIME *
								 rte_get_tsc_hz()/ 1000),
								SINGLE,
								timer_lcore,
								nd_timer_callback,
								arg) < 0)
					if (ARPICMP_DEBUG)
						RTE_LOG(INFO, LIBARP,
							"Err : Timer already running\n");

				}
			} else if (ret_nd_data->status == COMPLETE) {
				if (now <= (ret_nd_data->n_confirmed +
				 (arp_timeout * rte_get_tsc_hz()))) {
					if (rte_timer_reset(ret_nd_data->timer,
								(arp_timeout *
								 rte_get_tsc_hz()), SINGLE,
								timer_lcore,
								nd_timer_callback,
								arg) < 0)
					if (ARPICMP_DEBUG)
						RTE_LOG(INFO, LIBARP,
							"Err : Timer already running\n");
				} else if (now <= (p_arp_data->update_tsc[ret_nd_data->port] + (USED_TIME * rte_get_tsc_hz()))) {
					if (rte_timer_reset(ret_nd_data->timer,
								(arp_timeout *
								 rte_get_tsc_hz()), SINGLE,
								timer_lcore,
								nd_timer_callback,
								arg) < 0)
					if (ARPICMP_DEBUG)
						RTE_LOG(INFO, LIBARP,
							"Err : Timer already running\n");
				} else {
					printf("making it stale\n");
					ret_nd_data->status = STALE;
					p_arp_data->nd_cache_hw_laddr_valid[ret_nd_data->port] = 0;
				}
			}
			rte_rwlock_write_unlock(&ret_nd_data->queue_lock);
		} else {
			rte_hash_del_key(nd_hash_handle, &nd_key);
		}
	}
	return;
}

void create_arp_table(void)
{

	int i;
	for (i = 0; i < MAX_ARP_DATA_ENTRY_TABLE; i++) {
		populate_arp_entry((const struct ether_addr *)
					 &arp_entry_data_table[i].eth_addr,
					 arp_entry_data_table[i].ip,
					 (uint8_t) arp_entry_data_table[i].port,
					 STATIC_ARP);
	}
	print_arp_table();

	return;
}

void create_nd_table(void)
{

	int i;
	for (i = 0; i < MAX_ND_DATA_ENTRY_TABLE; i++) {
		populate_nd_entry((const struct ether_addr *)
					nd_entry_data_table[i].eth_addr,
					nd_entry_data_table[i].ipv6,
					(uint8_t) nd_entry_data_table[i].port,
					STATIC_ND);
	}
	print_nd_table();
	return;
}

void send_gratuitous_arp(l2_phy_interface_t *port)
{
	struct ether_hdr *eth_h;
	struct arp_hdr *arp_h;

	struct rte_mbuf *arp_pkt = lib_arp_pkt[port->pmdid];

	if (port == NULL) {
		RTE_LOG(INFO, LIBARP, "PORT ID DOWN.. %s\n", __FUNCTION__);
		return;

	}

	if (arp_pkt == NULL) {
		if (ARPICMP_DEBUG)
			RTE_LOG(INFO, LIBARP,
				"Error allocating arp_pkt rte_mbuf\n");
		return;
	}

	eth_h = rte_pktmbuf_mtod(arp_pkt, struct ether_hdr *);

	ether_addr_copy(&broadcast_ether_addr, &eth_h->d_addr);
	ether_addr_copy((struct ether_addr *)
			&port->macaddr[0], &eth_h->s_addr);
	eth_h->ether_type = CHECK_ENDIAN_16(ETHER_TYPE_ARP);

	arp_h = (struct arp_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	arp_h->arp_hrd = CHECK_ENDIAN_16(ARP_HRD_ETHER);
	arp_h->arp_pro = CHECK_ENDIAN_16(ETHER_TYPE_IPv4);
	arp_h->arp_hln = ETHER_ADDR_LEN;
	arp_h->arp_pln = sizeof(uint32_t);
	arp_h->arp_op = CHECK_ENDIAN_16(ARP_OP_REQUEST);

	ether_addr_copy((struct ether_addr *)
			&port->macaddr[0], &arp_h->arp_data.arp_sha);
	if (port->ipv4_list == NULL) {
		if (ARPICMP_DEBUG)
			RTE_LOG(INFO, LIBARP, "port->ipv4_list is NULL.. %s\n",
				__FUNCTION__);
		return;
	}
	arp_h->arp_data.arp_sip = (((ipv4list_t *) (port->ipv4_list))->ipaddr);
	ether_addr_copy(&null_ether_addr, &arp_h->arp_data.arp_tha);
	//arp_h->arp_data.arp_tip = rte_cpu_to_be_32(ip);
	arp_h->arp_data.arp_tip = 0;	//(((ipv4list_t *) (port->ipv4_list))->ipaddr);
	//  RTE_LOG(INFO, LIBARP,"arp tip:%x arp sip :%x\n", arp_h->arp_data.arp_tip,
	//arp_h->arp_data.arp_sip);
	// mmcd changed length from 60 to 42 - real length of arp request, no padding on ethernet needed - looks now like linux arp
	arp_pkt->pkt_len = 42;
	arp_pkt->data_len = 42;

	if (ARPICMP_DEBUG) {
		RTE_LOG(INFO, LIBARP, "SENDING GRATUITOUS ARP REQUEST\n");
		print_mbuf("TX", port->pmdid, arp_pkt, __LINE__);
	}
	port->transmit_single_pkt(port, arp_pkt);
}

void set_arpdebug(int flag)
{
	if (flag) {
		RTE_LOG(INFO, LIBARP, "Debugs turned on\n\r");
		ARPICMP_DEBUG = 1;
		NDIPV6_DEBUG = 1;

	} else {
		RTE_LOG(INFO, LIBARP, "Debugs turned off\n\r");
		ARPICMP_DEBUG = 0;
		NDIPV6_DEBUG = 0;
	}
}

void set_arptimeout(uint32_t timeout_val)
{
	if (timeout_val == 0) {
		RTE_LOG(INFO, LIBARP, "Cannot be zero...\n\r");
		return;
	}
	if (ARPICMP_DEBUG)
		RTE_LOG(INFO, LIBARP,
			"set_arptimeout: arp_timeout %u, timeout_val %u\n\r",
			arp_timeout, timeout_val);
	arp_timeout = timeout_val;
	if (ARPICMP_DEBUG)
		RTE_LOG(INFO, LIBARP, "set_arptimeout: arp_timeout %u\n\r",
			arp_timeout);
}
