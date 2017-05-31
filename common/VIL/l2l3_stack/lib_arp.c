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

#define is_multicast_ipv4_addr(ipv4_addr) \
	(((rte_be_to_cpu_32((ipv4_addr)) >> 24) & 0x000000FF) == 0xE0)

extern uint8_t prv_in_port_a[PIPELINE_MAX_PORT_IN];
extern uint32_t timer_lcore;
uint32_t arp_timeout = ARP_TIMER_EXPIRY;

/*ND IPV6 */
#define INADDRSZ 4
#define IN6ADDRSZ 16
static int my_inet_pton_ipv6(int af, const char *src, void *dst);
static int inet_pton_ipv6(const char *src, unsigned char *dst);
static int inet_pton_ipv4(const char *src, unsigned char *dst);
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

struct rte_mbuf *lib_arp_pkt;
struct rte_mbuf *lib_nd_pkt;

uint8_t default_ether_addr[6] = { 0, 0, 0, 0, 1, 1 };
uint8_t default_ip[4] = { 0, 0, 1, 1 };

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

uint32_t get_nh(uint32_t, uint32_t *);
void get_nh_ipv6(uint8_t ipv6[], uint32_t *port, uint8_t nhipv6[]);

#define MAX_ARP_DATA_ENTRY_TABLE 7

struct table_arp_entry_data arp_entry_data_table[MAX_ARP_DATA_ENTRY_TABLE] = {
	{{0, 0, 0, 0, 0, 1}, 1, INCOMPLETE, IPv4(192, 168, 0, 2)},
	{{0, 0, 0, 0, 0, 2}, 0, INCOMPLETE, IPv4(192, 168, 0, 3)},
	{{0, 0, 0, 0, 0, 1}, 1, INCOMPLETE, IPv4(30, 40, 50, 60)},
	{{0, 0, 0, 0, 0, 1}, 1, INCOMPLETE, IPv4(120, 0, 0, 2)},
	{{0, 0, 0, 0, 0, 4}, 3, INCOMPLETE, IPv4(1, 1, 1, 4)},
	{{0, 0, 0, 0, 0, 5}, 4, INCOMPLETE, IPv4(1, 1, 1, 5)},
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
	 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} }
};

struct lib_arp_route_table_entry lib_arp_route_table[MAX_ARP_RT_ENTRY] = {
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0},
	{0, 0, 0, 0}
};

void print_trace(void);

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

uint32_t get_nh(uint32_t ip, uint32_t *port)
{
	int i = 0;
	for (i = 0; i < MAX_ARP_RT_ENTRY; i++) {
		if (((lib_arp_route_table[i].
					ip & lib_arp_route_table[i].mask) ==
				 (ip & lib_arp_route_table[i].mask))) {

			*port = lib_arp_route_table[i].port;
			lib_arp_nh_found++;
			return lib_arp_route_table[i].nh;
		}
		if (ARPICMP_DEBUG)
			printf("No nh match ip 0x%x, port %u, t_ip "
						 "0x%x, t_port %u, mask 0x%x, r1 %x, r2 %x\n",
						 ip, *port, lib_arp_route_table[i].ip,
						 lib_arp_route_table[i].port,
						 lib_arp_route_table[i].mask,
						 (lib_arp_route_table[i].ip &
				lib_arp_route_table[i].mask),
						 (ip & lib_arp_route_table[i].mask));
	}
	if (ARPICMP_DEBUG)
		printf("No NH - ip 0x%x, port %u\n", ip, *port);
	lib_arp_no_nh_found++;
	return 0;
}

/*ND IPv6 */
void get_nh_ipv6(uint8_t ipv6[], uint32_t *port, uint8_t nhipv6[])
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

			return;
		}

		if (NDIPV6_DEBUG)
			printf("No nh match\n");
		depthflags = 0;
		depthflags1 = 0;
	}
	if (NDIPV6_DEBUG)
		printf("No NH - ip 0x%x, port %u\n", ipv6[0], *port);
	lib_nd_no_nh_found++;
}

/* Added for Multiport changes*/
int get_dest_mac_addr_port(const uint32_t ipaddr,
				 uint32_t *phy_port, struct ether_addr *hw_addr)
{
	lib_arp_get_mac_req++;
	uint32_t nhip = 0;

	nhip = get_nh(ipaddr, phy_port);
	if (nhip == 0) {
		if (ARPICMP_DEBUG)
			printf("ARPICMP no nh found for ip %x, port %d\n",
						 ipaddr, *phy_port);
		//return 0;
		return NH_NOT_FOUND;
	}

	struct arp_entry_data *ret_arp_data = NULL;
	struct arp_key_ipv4 tmp_arp_key;
	tmp_arp_key.port_id = *phy_port;	/* Changed for Multi Port */
	tmp_arp_key.ip = nhip;

	if (ARPICMP_DEBUG)
		printf("%s: nhip: %x, phyport: %d\n", __FUNCTION__, nhip,
					 *phy_port);

	ret_arp_data = retrieve_arp_entry(tmp_arp_key);
	if (ret_arp_data == NULL) {
		if (ARPICMP_DEBUG) {
			printf
					("ARPICMP no arp entry found for ip %x, port %d\n",
					 ipaddr, *phy_port);
			print_arp_table();
		}
		if (nhip != 0) {
			if (ARPICMP_DEBUG)
				printf("CG-NAPT requesting ARP for ip %x, "
							 "port %d\n", nhip, *phy_port);
			request_arp(*phy_port, nhip);	//Changed for Multiport

		}
		lib_arp_no_arp_entry_found++;
		return ARP_NOT_FOUND;
	}
	ether_addr_copy(&ret_arp_data->eth_addr, hw_addr);
	lib_arp_arp_entry_found++;
	if (ARPICMP_DEBUG)
		printf("%s: ARPICMP hwaddr found\n", __FUNCTION__);
	return ARP_FOUND;
}

int get_dest_mac_address(const uint32_t ipaddr, uint32_t *phy_port,
			 struct ether_addr *hw_addr, uint32_t *nhip)
{
	lib_arp_get_mac_req++;

	*nhip = get_nh(ipaddr, phy_port);
	if (*nhip == 0) {
		if (ARPICMP_DEBUG && ipaddr)
			RTE_LOG(INFO, LIBARP,
				"ARPICMP no nh found for ip %x, port %d\n",
				ipaddr, *phy_port);
		return 0;
	}

	struct arp_entry_data *ret_arp_data = NULL;
	struct arp_key_ipv4 tmp_arp_key;
	tmp_arp_key.port_id = *phy_port;
	tmp_arp_key.ip = *nhip;

	ret_arp_data = retrieve_arp_entry(tmp_arp_key);
	if (ret_arp_data == NULL) {
		if (ARPICMP_DEBUG && ipaddr) {
			RTE_LOG(INFO, LIBARP,
				"ARPICMP no arp entry found for ip %x, port %d\n",
				ipaddr, *phy_port);
			print_arp_table();
		}
		lib_arp_no_arp_entry_found++;
		return 0;
	}
	ether_addr_copy(&ret_arp_data->eth_addr, hw_addr);
	lib_arp_arp_entry_found++;
	return 1;

}

int get_dest_mac_addr(const uint32_t ipaddr,
					uint32_t *phy_port, struct ether_addr *hw_addr)
{
	lib_arp_get_mac_req++;
	uint32_t nhip = 0;

	nhip = get_nh(ipaddr, phy_port);
	if (nhip == 0) {
		if (ARPICMP_DEBUG && ipaddr)
			RTE_LOG(INFO, LIBARP,
				"ARPICMP no nh found for ip %x, port %d\n",
				ipaddr, *phy_port);
		return 0;
	}

	struct arp_entry_data *ret_arp_data = NULL;
	struct arp_key_ipv4 tmp_arp_key;
	tmp_arp_key.port_id = *phy_port;
	tmp_arp_key.ip = nhip;

	ret_arp_data = retrieve_arp_entry(tmp_arp_key);
	if (ret_arp_data == NULL) {
		if (ARPICMP_DEBUG && ipaddr) {
			printf
					("ARPICMP no arp entry found for ip %x, port %d\n",
					 ipaddr, *phy_port);
			print_arp_table();
		}

		if (nhip != 0) {
			if (ARPICMP_DEBUG > 4)
				printf
						("CG-NAPT requesting ARP for ip %x, port %d\n",
						 nhip, *phy_port);
			if (ifm_chk_port_ipv4_enabled(*phy_port)) {
				request_arp(*phy_port, nhip);
			} else {
				if (ARPICMP_DEBUG)
					RTE_LOG(INFO, LIBARP,
						"%s: IP is not enabled on port %u, not sending ARP REQ\n\r",
						__FUNCTION__, *phy_port);
			}

		}
		lib_arp_no_arp_entry_found++;
		return 0;
	}
	ether_addr_copy(&ret_arp_data->eth_addr, hw_addr);
	lib_arp_arp_entry_found++;
	return 1;
}

int get_dest_mac_address_ipv6_port(uint8_t ipv6addr[], uint32_t *phy_port,
					 struct ether_addr *hw_addr, uint8_t nhipv6[])
{
	int i = 0, j = 0, flag = 0;
	lib_nd_get_mac_req++;

	get_nh_ipv6(ipv6addr, phy_port, nhipv6);
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

	for (i = 0; i < 16; i++)
		tmp_nd_key.ipv6[i] = nhipv6[i];

	ret_nd_data = retrieve_nd_entry(tmp_nd_key);
	if (ret_nd_data == NULL) {
		if (NDIPV6_DEBUG) {
			printf("NDIPV6 no nd entry found for ip %x, port %d\n",
						 ipv6addr[0], *phy_port);
		}
		lib_nd_no_arp_entry_found++;
		return 0;
	}
	ether_addr_copy(&ret_nd_data->eth_addr, hw_addr);
	lib_nd_nd_entry_found++;
	return 1;
}

int get_dest_mac_address_ipv6(uint8_t ipv6addr[], uint32_t *phy_port,
						struct ether_addr *hw_addr, uint8_t nhipv6[])
{
	int i = 0, j = 0, flag = 0;
	lib_nd_get_mac_req++;

	get_nh_ipv6(ipv6addr, phy_port, nhipv6);
	for (j = 0; j < 16; j++) {
		if (nhipv6[j]) {
			flag++;
		}
	}
	if (flag == 0) {
		if (NDIPV6_DEBUG && ipv6addr)
			RTE_LOG(INFO, LIBARP,
				"NDIPV6 no nh found for ipv6 %x, port %d\n",
				ipv6addr[0], *phy_port);
		return 0;
	}

	struct nd_entry_data *ret_nd_data = NULL;
	struct nd_key_ipv6 tmp_nd_key;
	tmp_nd_key.port_id = *phy_port;

	for (i = 0; i < 16; i++) {
		tmp_nd_key.ipv6[i] = nhipv6[i];
	}

	ret_nd_data = retrieve_nd_entry(tmp_nd_key);
	if (ret_nd_data == NULL) {
		if (NDIPV6_DEBUG && ipv6addr) {
			RTE_LOG(INFO, LIBARP,
				"NDIPV6 no nd entry found for ip %x, port %d\n",
				ipv6addr[0], *phy_port);
		}
		if (flag != 0) {
			if (ARPICMP_DEBUG > 4)
				printf
						("Requesting ARP for ipv6 addr and port %d\n",
						 *phy_port);
			request_nd(&nhipv6[0], ifm_get_port(*phy_port));

		}

		lib_nd_no_arp_entry_found++;
		return 0;
	}
	ether_addr_copy(&ret_nd_data->eth_addr, hw_addr);
	lib_nd_nd_entry_found++;
	return 1;
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

struct arp_entry_data *retrieve_arp_entry(struct arp_key_ipv4 arp_key)
{
	struct arp_entry_data *ret_arp_data = NULL;
	arp_key.filler1 = 0;
	arp_key.filler2 = 0;
	arp_key.filler3 = 0;

	int ret = rte_hash_lookup_data(arp_hash_handle, &arp_key,
							 (void **)&ret_arp_data);
	if (ret < 0) {
		//      RTE_LOG(INFO, LIBARP,"arp-hash lookup failed ret %d, EINVAL %d, ENOENT %d\n", ret, EINVAL, ENOENT);
	} else {

		if (ret_arp_data->mode == DYNAMIC_ARP) {
			struct arp_timer_key callback_key;
			callback_key.port_id = ret_arp_data->port;
			callback_key.ip = ret_arp_data->ip;
			/*lcore need to check which parameter need to be put */
			if (rte_timer_reset(ret_arp_data->timer,
							(arp_timeout * rte_get_tsc_hz()),
							SINGLE, timer_lcore,
							arp_timer_callback,
							&callback_key) < 0)
				if (ARPICMP_DEBUG)
					RTE_LOG(INFO, LIBARP,
						"Err : Timer already running\n");
		}

		return ret_arp_data;
	}

	return NULL;
}

struct nd_entry_data *retrieve_nd_entry(struct nd_key_ipv6 nd_key)
{
	struct nd_entry_data *ret_nd_data = NULL;
	nd_key.filler1 = 0;
	nd_key.filler2 = 0;
	nd_key.filler3 = 0;
	int i = 0;

	/*Find a nd IPv6 key-data pair in the hash table for ND IPv6 */
	int ret = rte_hash_lookup_data(nd_hash_handle, &nd_key,
							 (void **)&ret_nd_data);
	if (ret < 0) {
/*		RTE_LOG(INFO, LIBARP,"nd-hash: no lookup Entry Found - ret %d, EINVAL %d, ENOENT %d\n",
				ret, EINVAL, ENOENT);*/
	} else {
		if (ret_nd_data->mode == DYNAMIC_ND) {
			struct nd_timer_key callback_key;
			callback_key.port_id = ret_nd_data->port;

			for (i = 0; i < ND_IPV6_ADDR_SIZE; i++) {
				callback_key.ipv6[i] = ret_nd_data->ipv6[i];

			}

			if (rte_timer_reset
					(ret_nd_data->timer,
					 (arp_timeout * rte_get_tsc_hz()), SINGLE,
					 timer_lcore, nd_timer_callback, &callback_key) < 0)
				if (ARPICMP_DEBUG)
					RTE_LOG(INFO, LIBARP,
						"Err : Timer already running\n");
		}
		return ret_nd_data;
	}

	return NULL;
}

void print_arp_table(void)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;

	printf
			("------------------------ ARP CACHE -----------------------------------------\n");
	printf
			("----------------------------------------------------------------------------\n");
	printf("\tport  hw addr            status     ip addr\n");
	printf
			("----------------------------------------------------------------------------\n");

	while (rte_hash_iterate(arp_hash_handle, &next_key, &next_data, &iter)
				 >= 0) {

		struct arp_entry_data *tmp_arp_data =
				(struct arp_entry_data *)next_data;
		struct arp_key_ipv4 tmp_arp_key;
		memcpy(&tmp_arp_key, next_key, sizeof(struct arp_key_ipv4));
		printf
				("\t%4d  %02X:%02X:%02X:%02X:%02X:%02X  %10s %d.%d.%d.%d\n",
				 tmp_arp_data->port, tmp_arp_data->eth_addr.addr_bytes[0],
				 tmp_arp_data->eth_addr.addr_bytes[1],
				 tmp_arp_data->eth_addr.addr_bytes[2],
				 tmp_arp_data->eth_addr.addr_bytes[3],
				 tmp_arp_data->eth_addr.addr_bytes[4],
				 tmp_arp_data->eth_addr.addr_bytes[5],
				 tmp_arp_data->status ==
				 COMPLETE ? "COMPLETE" : "INCOMPLETE",
				 (tmp_arp_data->ip >> 24),
				 ((tmp_arp_data->ip & 0x00ff0000) >> 16),
				 ((tmp_arp_data->ip & 0x0000ff00) >> 8),
				 ((tmp_arp_data->ip & 0x000000ff)));
	}

	uint32_t i = 0;
	printf("\nARP routing table has %d entries\n", arp_route_tbl_index);
	printf("\nIP_Address    Mask          Port    NH_IP_Address\n");
	for (i = 0; i < arp_route_tbl_index; i++) {
		printf("0x%x    0x%x    %d       0x%x\n",
					 lib_arp_route_table[i].ip,
					 lib_arp_route_table[i].mask,
					 lib_arp_route_table[i].port, lib_arp_route_table[i].nh);
	}

	printf
			("\nARP Stats: Total Queries %u, ok_NH %u, no_NH %u, ok_Entry %u, no_Entry %u, PopulateCall %u, Del %u, Dup %u\n",
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
	printf
			("------------------------------------------------------------------------------------------------------\n");
	printf("\tport  hw addr            status         ip addr\n");

	printf
			("------------------------------------------------------------------------------------------------------\n");
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
					 tmp_nd_data->status ==
					 COMPLETE ? "COMPLETE" : "INCOMPLETE");
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
	printf
			("\nIP_Address						Depth          Port				NH_IP_Address\n");
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
	printf
			("\nND IPV6 Stats: \nTotal Queries %u, ok_NH %u, no_NH %u, ok_Entry %u, no_Entry %u, PopulateCall %u, Del %u, Dup %u\n",
			 lib_nd_get_mac_req, lib_nd_nh_found, lib_nd_no_nh_found,
			 lib_nd_nd_entry_found, lib_nd_no_arp_entry_found,
			 lib_nd_populate_called, lib_nd_delete_called,
			 lib_nd_duplicate_found);
	printf("ND table key len is %lu\n\n", sizeof(struct nd_key_ipv6));
}

void remove_arp_entry(uint32_t ipaddr, uint8_t portid, void *arg)
{

	struct arp_key_ipv4 arp_key;
	arp_key.port_id = portid;
	arp_key.ip = ipaddr;
	arp_key.filler1 = 0;
	arp_key.filler2 = 0;
	arp_key.filler3 = 0;

	lib_arp_delete_called++;

	struct arp_entry_data *ret_arp_data = NULL;

	int ret = rte_hash_lookup_data(arp_hash_handle, &arp_key,
							 (void **)&ret_arp_data);
	if (ret < 0) {
//              RTE_LOG(INFO, LIBARP,"arp-hash lookup failed ret %d, EINVAL %d, ENOENT %d\n", ret, EINVAL, ENOENT);
		return;
	} else {
		if (ret_arp_data->mode == DYNAMIC_ARP) {
			if (ret_arp_data->retry_count == 3) {
				rte_timer_stop(ret_arp_data->timer);
				rte_free(ret_arp_data->timer_key);
				if (ARPICMP_DEBUG) {
					RTE_LOG(INFO, LIBARP,
						"ARP Entry Deleted for IP :%d.%d.%d.%d , port %d\n",
						(arp_key.ip >> 24),
						((arp_key.ip & 0x00ff0000) >>
						 16),
						((arp_key.ip & 0x0000ff00) >>
						 8),
						((arp_key.ip & 0x000000ff)),
						arp_key.port_id);
				}
				rte_hash_del_key(arp_hash_handle, &arp_key);
				//print_arp_table();
			} else {
				ret_arp_data->retry_count++;
				if (ARPICMP_DEBUG)
					RTE_LOG(INFO, LIBARP,
						"RETRY ARP..retry count : %u\n",
						ret_arp_data->retry_count);
				//print_arp_table();
				if (ARPICMP_DEBUG)
					RTE_LOG(INFO, LIBARP,
						"TIMER STARTED FOR %u seconds\n",
						ARP_TIMER_EXPIRY);
				if (ifm_chk_port_ipv4_enabled
						(ret_arp_data->port)) {
					request_arp(ret_arp_data->port,
								ret_arp_data->ip);
				} else {
					if (ARPICMP_DEBUG)
						RTE_LOG(INFO, LIBARP,
							"%s: IP is not enabled on port %u, not sending GARP\n\r",
							__FUNCTION__,
							ret_arp_data->port);
				}
				if (rte_timer_reset(ret_arp_data->timer,
								(arp_timeout *
								 rte_get_tsc_hz()), SINGLE,
								timer_lcore,
								arp_timer_callback,
								arg) < 0)
					if (ARPICMP_DEBUG)
						RTE_LOG(INFO, LIBARP,
							"Err : Timer already running\n");

			}
		} else {
			rte_hash_del_key(arp_hash_handle, &arp_key);
		}
	}
}

/* ND IPv6 */
void remove_nd_entry_ipv6(uint8_t ipv6addr[], uint8_t portid)
{
	int i = 0;
	struct nd_entry_data *ret_nd_data = NULL;
	struct nd_key_ipv6 nd_key;
	nd_key.port_id = portid;

	for (i = 0; i < ND_IPV6_ADDR_SIZE; i++) {
		nd_key.ipv6[i] = ipv6addr[i];
	}

	nd_key.filler1 = 0;
	nd_key.filler2 = 0;
	nd_key.filler3 = 0;

	lib_nd_delete_called++;

	if (NDIPV6_DEBUG) {
		RTE_LOG(INFO, LIBARP,
			"Deletes rte hash table nd entry for port %d ipv6=",
			nd_key.port_id);
		for (i = 0; i < ND_IPV6_ADDR_SIZE; i += 2) {
			RTE_LOG(INFO, LIBARP, "%02X%02X ", nd_key.ipv6[i],
				nd_key.ipv6[i + 1]);
		}
	}
	struct nd_timer_key callback_key;
	callback_key.port_id = portid;

	for (i = 0; i < ND_IPV6_ADDR_SIZE; i++) {
		callback_key.ipv6[i] = ipv6addr[i];

	}
	int ret = rte_hash_lookup_data(arp_hash_handle, &callback_key,
							 (void **)&ret_nd_data);
	if (ret < 0) {
//              RTE_LOG(INFO, LIBARP,"arp-hash lookup failed ret %d, EINVAL %d, ENOENT %d\n", ret, EINVAL, ENOENT);
	} else {
		if (ret_nd_data->mode == DYNAMIC_ND) {
			rte_timer_stop(ret_nd_data->timer);
			rte_free(ret_nd_data->timer);
		}
	}
	rte_hash_del_key(nd_hash_handle, &nd_key);
}

void
populate_arp_entry(const struct ether_addr *hw_addr, uint32_t ipaddr,
			 uint8_t portid, uint8_t mode)
{
	struct arp_key_ipv4 arp_key;
	arp_key.port_id = portid;
	arp_key.ip = ipaddr;
	arp_key.filler1 = 0;
	arp_key.filler2 = 0;
	arp_key.filler3 = 0;

	lib_arp_populate_called++;

	if (ARPICMP_DEBUG)
		RTE_LOG(INFO, LIBARP, "populate_arp_entry ip %x, port %d\n",
			arp_key.ip, arp_key.port_id);

	struct arp_entry_data *new_arp_data = retrieve_arp_entry(arp_key);
	if (new_arp_data && ((new_arp_data->mode == STATIC_ARP
                && mode == DYNAMIC_ARP) || (new_arp_data->mode == DYNAMIC_ARP
                && mode == STATIC_ARP))) {
                if (ARPICMP_DEBUG)
                        RTE_LOG(INFO, LIBARP,"populate_arp_entry: ARP entry already exists(%d %d)\n",
				new_arp_data->mode, mode);

                return;
        }

	if (mode == DYNAMIC_ARP) {
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
			new_arp_data->retry_count = 0;	// Reset
			if (rte_timer_reset(new_arp_data->timer,
							(arp_timeout * rte_get_tsc_hz()),
							SINGLE, timer_lcore,
							arp_timer_callback,
							new_arp_data->timer_key) < 0)
				if (ARPICMP_DEBUG)
					RTE_LOG(INFO, LIBARP,
						"Err : Timer already running\n");
			return;
		}

		uint32_t size =
				RTE_CACHE_LINE_ROUNDUP(sizeof(struct arp_entry_data));
		new_arp_data = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
		new_arp_data->eth_addr = *hw_addr;
		new_arp_data->status = COMPLETE;
		new_arp_data->port = portid;
		new_arp_data->ip = ipaddr;
		new_arp_data->mode = mode;
		if (rte_mempool_get
				(timer_mempool_arp, (void **)&(new_arp_data->timer)) < 0) {
			RTE_LOG(INFO, LIBARP,
				"TIMER - Error in getting timer alloc buffer\n");
			return;
		}

		rte_hash_add_key_data(arp_hash_handle, &arp_key, new_arp_data);
		if (ARPICMP_DEBUG) {
			RTE_LOG(INFO, LIBARP,
				"arp_entry exists ip :%d.%d.%d.%d , port %d\n",
				(arp_key.ip >> 24),
				((arp_key.ip & 0x00ff0000) >> 16),
				((arp_key.ip & 0x0000ff00) >> 8),
				((arp_key.ip & 0x000000ff)), arp_key.port_id);
		}
		// Call l3fwd module for resolving 2_adj structure.
		resolve_l2_adj(ipaddr, portid, hw_addr);

		rte_timer_init(new_arp_data->timer);
		struct arp_timer_key *callback_key =
				(struct arp_timer_key *)rte_malloc(NULL,
									 sizeof(struct
										arp_timer_key *),
									 RTE_CACHE_LINE_SIZE);
		callback_key->port_id = portid;
		callback_key->ip = ipaddr;

		if (ARPICMP_DEBUG)
			RTE_LOG(INFO, LIBARP, "TIMER STARTED FOR %u seconds\n",
				ARP_TIMER_EXPIRY);
		if (rte_timer_reset
				(new_arp_data->timer, (arp_timeout * rte_get_tsc_hz()),
				 SINGLE, timer_lcore, arp_timer_callback, callback_key) < 0)
			if (ARPICMP_DEBUG)
				RTE_LOG(INFO, LIBARP,
					"Err : Timer already running\n");

		new_arp_data->timer_key = callback_key;
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

			rte_hash_add_key_data(arp_hash_handle, &arp_key,
								new_arp_data);
			if (ARPICMP_DEBUG) {
				RTE_LOG(INFO, LIBARP,
					"arp_entry exists ip :%d.%d.%d.%d , port %d\n",
					(arp_key.ip >> 24),
					((arp_key.ip & 0x00ff0000) >> 16),
					((arp_key.ip & 0x0000ff00) >> 8),
					((arp_key.ip & 0x000000ff)),
					arp_key.port_id);
			}
			// Call l3fwd module for resolving 2_adj structure.
			resolve_l2_adj(ipaddr, portid, hw_addr);
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
	uint8_t i;
	struct nd_key_ipv6 nd_key;
	nd_key.port_id = portid;

	for (i = 0; i < ND_IPV6_ADDR_SIZE; i++)
		nd_key.ipv6[i] = ipv6[i];

//      RTE_LOG(INFO, LIBARP,"\n");
	nd_key.filler1 = 0;
	nd_key.filler2 = 0;
	nd_key.filler3 = 0;

	lib_nd_populate_called++;

	/* Validate if key-value pair already exists in the hash table for ND IPv6 */
	struct nd_entry_data *new_nd_data = retrieve_nd_entry(nd_key);

	if (mode == DYNAMIC_ND) {
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
			RTE_LOG(INFO, LIBARP, "nd_entry exists\n");
			return;
		}
		uint32_t size =
				RTE_CACHE_LINE_ROUNDUP(sizeof(struct nd_entry_data));
		new_nd_data = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);

		//new_nd_data = (struct nd_entry_data *)rte_malloc(NULL, sizeof(struct nd_entry_data *),RTE_CACHE_LINE_SIZE);
		new_nd_data->eth_addr = *hw_addr;
		new_nd_data->status = COMPLETE;
		new_nd_data->port = portid;
		new_nd_data->mode = mode;
		if (rte_mempool_get
				(timer_mempool_arp, (void **)&(new_nd_data->timer)) < 0) {
			RTE_LOG(INFO, LIBARP,
				"TIMER - Error in getting timer alloc buffer\n");
			return;
		}

		if (NDIPV6_DEBUG)
			RTE_LOG(INFO, LIBARP, "populate_nd_entry ipv6=");

		for (i = 0; i < ND_IPV6_ADDR_SIZE; i++) {
			new_nd_data->ipv6[i] = ipv6[i];
		}

		if (NDIPV6_DEBUG) {
			for (i = 0; i < ND_IPV6_ADDR_SIZE; i += 2) {

				RTE_LOG(INFO, LIBARP, "%02X%02X ",
					new_nd_data->ipv6[i],
					new_nd_data->ipv6[i + 1]);
			}
		}

		/*Add a key-data pair at hash table for ND IPv6 static routing */
		rte_hash_add_key_data(nd_hash_handle, &nd_key, new_nd_data);
		/* need to check the return value of the hash add */

		/* after the hash is created then time is started */
		rte_timer_init(new_nd_data->timer);
		struct nd_timer_key *callback_key =
				(struct nd_timer_key *)rte_malloc(NULL,
									sizeof(struct nd_timer_key
									 *),
									RTE_CACHE_LINE_SIZE);
		callback_key->port_id = portid;

		for (i = 0; i < ND_IPV6_ADDR_SIZE; i++) {
			callback_key->ipv6[i] = ipv6[i];
		}
		if (rte_timer_reset
				(new_nd_data->timer, (arp_timeout * rte_get_tsc_hz()),
				 SINGLE, timer_lcore, nd_timer_callback, callback_key) < 0)
			RTE_LOG(INFO, LIBARP, "Err : Timer already running\n");
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

			//new_nd_data = (struct nd_entry_data *)rte_malloc(NULL, sizeof(struct nd_entry_data *),RTE_CACHE_LINE_SIZE);
			new_nd_data->eth_addr = *hw_addr;
			new_nd_data->status = COMPLETE;
			new_nd_data->port = portid;
			new_nd_data->mode = mode;
			for (i = 0; i < ND_IPV6_ADDR_SIZE; i++) {
				new_nd_data->ipv6[i] = ipv6[i];
			}

			/*Add a key-data pair at hash table for ND IPv6 static routing */
			rte_hash_add_key_data(nd_hash_handle, &nd_key,
								new_nd_data);
			/* need to check the return value of the hash add */
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
			RTE_LOG(INFO, LIBARP, "%02x ", rd[(20 * i) + j]);
		RTE_LOG(INFO, LIBARP, "\n");
	}
}

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
	return &link_hw_addr[out_port];
}

void request_arp(uint8_t port_id, uint32_t ip)
{

	struct ether_hdr *eth_h;
	struct arp_hdr *arp_h;

	l2_phy_interface_t *link;
	link = ifm_get_port(port_id);
	struct rte_mbuf *arp_pkt = lib_arp_pkt;

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

	ether_addr_copy((struct ether_addr *)
			&link->macaddr[0], &arp_h->arp_data.arp_sha);
	if (link && link->ipv4_list) {
		arp_h->arp_data.arp_sip =
				(((ipv4list_t *) (link->ipv4_list))->ipaddr);
	}
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
}

struct rte_mbuf *request_echo(uint32_t port_id, uint32_t ip)
{
	struct ether_hdr *eth_h;
	struct ipv4_hdr *ip_h;
	struct icmp_hdr *icmp_h;
	l2_phy_interface_t *port = ifm_get_port(port_id);

	struct rte_mbuf *icmp_pkt = lib_arp_pkt;
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

#if 0
/**
 * Function to send ICMP dest unreachable msg
 *
 */
struct rte_mbuf *send_icmp_dest_unreachable_msg(uint32_t src_ip,
						uint32_t dest_ip)
{
	struct ether_hdr *eth_h;
	struct ipv4_hdr *ip_h;
	struct icmp_hdr *icmp_h;
	struct rte_mbuf *icmp_pkt = lib_arp_pkt;

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
	ip_h->next_proto_id = 1;

	ip_h->dst_addr = rte_bswap32(dest_ip);
	ip_h->src_addr = rte_bswap32(src_ip);

	ip_h->hdr_checksum = 0;
	ip_h->hdr_checksum = rte_ipv4_cksum(ip_h);

	icmp_h->icmp_type = 3;	/* Destination Unreachable */
	icmp_h->icmp_code = 13;	/* Communication administratively prohibited */

	icmp_h->icmp_cksum = ~rte_raw_cksum(icmp_h, sizeof(struct icmp_hdr));

	icmp_pkt->pkt_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
			sizeof(struct icmp_hdr);
	icmp_pkt->data_len = icmp_pkt->pkt_len;

	return icmp_pkt;
}
#endif
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
					populate_arp_entry(
							(struct ether_addr *)&arp_h->arp_data.arp_sha,
							rte_cpu_to_be_32(arp_h->arp_data.arp_sip),
							in_port_id,
							DYNAMIC_ARP);

				} else {
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
							retrieve_arp_entry(arp_key);
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
static int my_inet_pton_ipv6(int af, const char *src, void *dst)
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
	uint32_t ports_mac_list_present = 0;
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

	RTE_SET_USED(ports_mac_list_present);
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

		/* ports_mac_list */
		if (strcmp(arg_name, "ports_mac_list") == 0) {
			ports_mac_list_present = 1;

			uint32_t i = 0, j = 0, k = 0, MAC_NUM_BYTES = 6;

			char byteStr[MAC_NUM_BYTES][3];
			uint32_t byte[MAC_NUM_BYTES];

			char *token = strtok(arg_value, " ");
			while (token) {
				k = 0;
				for (i = 0; i < MAC_NUM_BYTES; i++) {
					for (j = 0; j < 2; j++) {
						byteStr[i][j] = token[k++];
					}
					byteStr[i][j] = '\0';
					k++;
				}

				for (i = 0; i < MAC_NUM_BYTES; i++) {
					byte[i] = strtoul(byteStr[i], NULL, 16);
				}

				if (ARPICMP_DEBUG) {
					RTE_LOG(INFO, LIBARP, "token: %s",
						token);
					for (i = 0; i < MAC_NUM_BYTES; i++)
						RTE_LOG(INFO, LIBARP,
							", byte[%u] %u", i,
							byte[i]);
					RTE_LOG(INFO, LIBARP, "\n");
				}
				//Populate the static arp_route_table
				for (i = 0; i < MAC_NUM_BYTES; i++)
					link_hw_addr
							[link_hw_addr_array_idx].addr_bytes
							[i] = byte[i];

				link_hw_addr_array_idx++;
				token = strtok(NULL, " ");
			}

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
				lib_arp_route_table[arp_route_tbl_index].ip =
						dest_ip;
				lib_arp_route_table[arp_route_tbl_index].mask =
						mask;
				lib_arp_route_table[arp_route_tbl_index].port =
						tx_port;
				lib_arp_route_table[arp_route_tbl_index].nh =
						nh_ip;
				arp_route_tbl_index++;
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

void lib_arp_init(struct pipeline_params *params,
			__rte_unused struct app_params *app)
{

	RTE_LOG(INFO, LIBARP, "ARP initialization ...\n");

	/* Parse arguments */
	if (arp_parse_args(params)) {
		RTE_LOG(INFO, LIBARP, "arp_parse_args failed ...\n");
		return;
	}

	/* create the arp_icmp mbuf rx pool */
	lib_arp_pktmbuf_tx_pool =
			rte_pktmbuf_pool_create("lib_arp_mbuf_tx_pool", NB_ARPICMP_MBUF, 32,
						0, RTE_MBUF_DEFAULT_BUF_SIZE,
						rte_socket_id());

	if (lib_arp_pktmbuf_tx_pool == NULL) {
		RTE_LOG(INFO, LIBARP, "ARP mbuf pool create failed.\n");
		return;
	}

	lib_arp_pkt = rte_pktmbuf_alloc(lib_arp_pktmbuf_tx_pool);
	if (lib_arp_pkt == NULL) {
		RTE_LOG(INFO, LIBARP, "ARP lib_arp_pkt alloc failed.\n");
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

	return;
}

void arp_timer_callback(struct rte_timer *timer, void *arg)
{
	struct arp_timer_key *remove_key = (struct arp_timer_key *)arg;
	if (ARPICMP_DEBUG)
		RTE_LOG(INFO, LIBARP, "ARP TIMER callback : expire :%d\n",
			(int)timer->expire);
	if (ARPICMP_DEBUG)
		RTE_LOG(INFO, LIBARP,
			"Remove ARP Entry for IP :%d.%d.%d.%d , port %d\n",
			(remove_key->ip >> 24),
			((remove_key->ip & 0x00ff0000) >> 16),
			((remove_key->ip & 0x0000ff00) >> 8),
			((remove_key->ip & 0x000000ff)), remove_key->port_id);
	remove_arp_entry((uint32_t) remove_key->ip,
			 (uint8_t) remove_key->port_id, arg);
	return;
}

void nd_timer_callback(struct rte_timer *timer, void *arg)
{
	struct nd_timer_key *remove_key = (struct nd_timer_key *)arg;
	if (ARPICMP_DEBUG)
		RTE_LOG(INFO, LIBARP, "nd  time callback : expire :%d\n",
			(int)timer->expire);
	remove_nd_entry_ipv6(remove_key->ipv6, remove_key->port_id);
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

	struct rte_mbuf *arp_pkt = lib_arp_pkt;

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
