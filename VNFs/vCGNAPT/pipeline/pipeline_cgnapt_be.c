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
 * Pipeline CG-NAPT BE Implementation.
 *
 * Implementation of Pipeline CG-NAPT Back End (BE).
 * Provides NAPT service on dataplane packets.
 * Runs on a core as defined in the config file.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_hash.h>
#include <rte_byteorder.h>
#include <rte_table_lpm.h>
#include <rte_table_hash.h>
#include <rte_table_stub.h>
#include <rte_ring.h>
#include <rte_mempool.h>

#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_pipeline.h>
#include <rte_timer.h>
#include <rte_config.h>
#include <rte_prefetch.h>
#include <rte_hexdump.h>

#include "pipeline_cgnapt_be.h"
#include "pipeline_cgnapt_common.h"
#include "pipeline_actions_common.h"
#include "hash_func.h"
#include "pipeline_arpicmp_be.h"
#include "vnf_common.h"
#include "app.h"
#include "pipeline_common_be.h"
#include "vnf_common.h"
#include "lib_sip_alg.h"
#include "lib_icmpv6.h"

#include "pipeline_common_fe.h"
#ifdef CT_CGNAT
#include "rte_ct_tcp.h"
#include "rte_cnxn_tracking.h"
#endif
#ifdef FTP_ALG
#include "lib_ftp_alg.h"
#endif
#ifdef PCP_ENABLE
#include "cgnapt_pcp_be.h"
#endif

/* To maintain all cgnapt pipeline pointers used for all stats */
struct pipeline_cgnapt *all_pipeline_cgnapt[128];
uint8_t n_cgnapt_pipeline;
struct pipeline_cgnapt *global_pnat;

uint64_t arp_pkts_mask;

/* To know egress or ingress port */
static uint8_t cgnapt_in_port_egress_prv[PIPELINE_MAX_PORT_IN];
static uint8_t cgnapt_prv_que_port_index[PIPELINE_MAX_PORT_IN];

/* Max port per client declarations */

struct rte_hash_parameters max_port_per_client_hash_params = {
	.name = "MAX_PORT_PER_CLIENT",
	.entries = MAX_DYN_ENTRY,
	.key_len = sizeof(struct max_port_per_client_key),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
};
#ifdef CT_CGNAT
struct rte_ct_cnxn_tracker *cgnat_cnxn_tracker;
#endif

/***** Common Port Allocation declarations *****/

struct rte_ring *port_alloc_ring[MAX_CGNAPT_SETS] = { NULL, NULL, NULL, NULL,
						NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                                                NULL, NULL, NULL, NULL};
const char *napt_port_alloc_ring_name[MAX_CGNAPT_SETS] = {
	"NAPT_PORT_ALLOC_0 ",
	"NAPT_PORT_ALLOC_1 ",
	"NAPT_PORT_ALLOC_2 ",
	"NAPT_PORT_ALLOC_3 ",
	"NAPT_PORT_ALLOC_4 ",
	"NAPT_PORT_ALLOC_5 ",
	"NAPT_PORT_ALLOC_6 ",
	"NAPT_PORT_ALLOC_7 ",
	"NAPT_PORT_ALLOC_8 ",
	"NAPT_PORT_ALLOC_9 ",
	"NAPT_PORT_ALLOC_10 ",
	"NAPT_PORT_ALLOC_11 ",
	"NAPT_PORT_ALLOC_12 ",
	"NAPT_PORT_ALLOC_13 ",
	"NAPT_PORT_ALLOC_14 ",
	"NAPT_PORT_ALLOC_16 "
};

int vnf_set_count = -1;

struct app_params *myApp;

/***** Common Port Allocation declarations *****/
int napt_port_alloc_elem_count;

/***** Common Table declarations *****/
struct rte_hash_parameters napt_common_table_hash_params = {
	.name = "NAPT_COM_TBL",
	.entries = MAX_NAPT_ENTRIES,
	.key_len = sizeof(struct pipeline_cgnapt_entry_key),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
	.extra_flag = 1,
};

/***** ARP local cache *****/

uint8_t link_hw_laddr_valid[MAX_NUM_LOCAL_MAC_ADDRESS] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0
};

struct ether_addr link_hw_laddr[MAX_NUM_LOCAL_MAC_ADDRESS] = {
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} }
};

/****** NAT64 declarations *****/

uint8_t well_known_prefix[16] = {
	0x00, 0x64, 0xff, 0x9b,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
};

static uint32_t local_get_nh_ipv4(
	uint32_t ip,
	uint32_t *port,
	uint32_t *nhip,
	struct pipeline_cgnapt *p_nat);
static void do_local_nh_ipv4_cache(
	uint32_t dest_if,
	struct pipeline_cgnapt *p_nat);

static uint32_t local_get_nh_ipv6(
	uint8_t *ip,
	uint32_t *port,
	uint8_t nhip[],
	struct pipeline_cgnapt *p_nat);

static void do_local_nh_ipv6_cache(
	uint32_t dest_if,
	struct pipeline_cgnapt *p_nat);

static uint8_t check_arp_icmp(
	struct rte_mbuf *pkt,
	uint64_t pkt_mask,
	struct pipeline_cgnapt *p_nat);

/* Finds next power of two for n. If n itself
 * is a power of two then returns n
 *
 * @param n
 *	Value usually 32-bit value
 *
 * @return
 *	Value after roundup to power of 2
*/
uint64_t nextPowerOf2(uint64_t n)
{
	n--;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;
	n |= n >> 32;
	n++;
	return n;
}

void remove_local_cache(uint8_t port)
{
	link_hw_laddr_valid[port] = 0;
}

/**
 * Function to get MAC addr of local link
 *
 * @params out_port
 *  Physical port number
 *
 * @return
 *  Outport Link MAC addr
 */

//struct ether_addr *get_local_link_hw_addr(uint8_t out_port)
//{
//	return &link_hw_laddr[out_port];
//}

/**
 * Function to get MAC addr from array instead of hash table
 *
 * @params out_port
 *  Physical port number
 *
 * @return
 *  Outport Link MAC addr
 */

uint8_t local_dest_mac_present(uint8_t out_port)
{
	return link_hw_laddr_valid[out_port];
}

/**
 * Function to get IPv4-IP NH from thread local array
 *
 * @params ip
 *  IPv4 - IP
 * @params port
 *  NH port number
 * @params nhip
 *  NHIP of IPv4 type
 * @params p_nat
 *  CGNAPT pipeline ptr
 *
 * @return
 *  1 on success, 0 for failure
 */

static uint32_t local_get_nh_ipv4(
	uint32_t ip,
	uint32_t *port,
	uint32_t *nhip,
	struct pipeline_cgnapt *p_nat)
{
	int i;
	for (i = 0; i < p_nat->local_lib_arp_route_ent_cnt; i++) {
		if (((p_nat->local_lib_arp_route_table[i].ip &
			p_nat->local_lib_arp_route_table[i].mask) ==
			(ip & p_nat->local_lib_arp_route_table[i].mask))) {
			*port = p_nat->local_lib_arp_route_table[i].port;

			*nhip = p_nat->local_lib_arp_route_table[i].nh;
			return 1;
		}
	}
	return 0;
}

/**
 * Function to make local copy for NH of type IPv4
 *
 * @params dest_if
 *  Physical port number
 * @params p_nat
 *  CGNAPT pipeline ptr
 *
 */

static void do_local_nh_ipv4_cache(
	uint32_t dest_if,
	struct pipeline_cgnapt *p_nat)
{

	/* Search for the entry and do local copy */
	int i;

	for (i = 0; i < MAX_ARP_RT_ENTRY; i++) {
		if (lib_arp_route_table[i].port == dest_if) {

			struct lib_arp_route_table_entry *lentry =
				&p_nat->local_lib_arp_route_table
					[p_nat->local_lib_arp_route_ent_cnt];

			lentry->ip   = lib_arp_route_table[i].ip;
			lentry->mask = lib_arp_route_table[i].mask;
			lentry->port = lib_arp_route_table[i].port;
			lentry->nh   = lib_arp_route_table[i].nh;

			p_nat->local_lib_arp_route_ent_cnt++;
						break;
		}
	}
}


/**
 * Function to get IPv6-IP NH from thread local array
 *
 * @params ip
 *  Pointer to starting addr of IPv6
 * @params port
 *  NH port number
 * @params nhip
 *  NHIP of IPv6 type
 * @params p_nat
 *  CGNAPT pipeline ptr
 *
 * @return
 *  1 on success, 0 for failure
 */

static uint32_t local_get_nh_ipv6(
	uint8_t *ip,
	uint32_t *port,
	uint8_t nhip[],
	struct pipeline_cgnapt *p_nat)
{
	int i = 0;
	uint8_t netmask_ipv6[16];
	uint8_t k = 0, l = 0, depthflags = 0, depthflags1 = 0;

	for (i = 0; i < p_nat->local_lib_nd_route_ent_cnt; i++) {

		convert_prefixlen_to_netmask_ipv6(
			p_nat->local_lib_nd_route_table[i].depth,
			netmask_ipv6);

		for (k = 0; k < 16; k++)
			if (p_nat->local_lib_nd_route_table[i].ipv6[k] &
					netmask_ipv6[k])
				depthflags++;

		for (l = 0; l < 16; l++)
			if (ip[l] & netmask_ipv6[l])
				depthflags1++;

		int j = 0;
		if (depthflags == depthflags1) {
			*port = p_nat->local_lib_nd_route_table[i].port;

			for (j = 0; j < 16; j++)
				nhip[j] = p_nat->local_lib_nd_route_table[i].
						nhipv6[j];
			return 1;
		}

		depthflags = 0;
		depthflags1 = 0;
			}
			return 0;
}


/**
 * Function to make local copy for NH of type IPv6
 *
 * @params dest_if
 *  Physical port number
 * @params p_nat
 *  CGNAPT pipeline ptr
 *
 */

static void do_local_nh_ipv6_cache(
	uint32_t dest_if,
	struct pipeline_cgnapt *p_nat)
{
		/* Search for the entry and do local copy */
	int i, l;
	for (i = 0; i < MAX_ND_RT_ENTRY; i++) {

		if (lib_nd_route_table[i].port == dest_if) {

			struct lib_nd_route_table_entry *lentry =
				&p_nat->local_lib_nd_route_table
					[p_nat->local_lib_nd_route_ent_cnt];

			for (l = 0; l < 16; l++) {
				lentry->ipv6[l]   =
					lib_nd_route_table[i].ipv6[l];
				lentry->nhipv6[l] =
					lib_nd_route_table[i].nhipv6[l];
			}
			lentry->depth = lib_nd_route_table[i].depth;
			lentry->port  = lib_nd_route_table[i].port;

			p_nat->local_lib_nd_route_ent_cnt++;
			break;
			} //if
		} //for
}

#ifdef SIP_ALG
/* Commented code may be required for future usage, Please keep it*/
#if 0
static int retrieve_cgnapt_entry_alg(
	struct pipeline_cgnapt_entry_key *key,
	struct cgnapt_table_entry **entry_ptr1,
	struct cgnapt_table_entry **entry_ptr2)
{
	#ifdef CGNAPT_DBG_PRNT
	printf("retrieve_cgnapt_entry key detail Entry:"
		"0x%x, %d, %d\n", key->ip, key->port,
		key->pid);
	#endif

	int position = rte_hash_lookup(napt_common_table, key);
	if (position < 0) {
		printf("Invalid cgnapt entry position(first_key): %d\n",
			position);
		return 0;
	}

	*entry_ptr1 = &napt_hash_tbl_entries[position];

	uint32_t prv_ip = (*entry_ptr1)->data.prv_ip;
	uint32_t prv_port = (*entry_ptr1)->data.prv_port;
	uint32_t prv_phy_port = (*entry_ptr1)->data.prv_phy_port;

	struct pipeline_cgnapt_entry_key second_key;
	second_key.ip = prv_ip;
	second_key.port = prv_port;
	second_key.pid = prv_phy_port;

	position = rte_hash_lookup(napt_common_table, &second_key);
	if (position < 0) {
		printf("Invalid cgnapt entry position(second_key): %d\n",
			position);
		return 0;
	}

	*entry_ptr2 = &napt_hash_tbl_entries[position];

	return 1;
}
#endif

int add_dynamic_cgnapt_entry_alg(
	struct pipeline *p,
	struct pipeline_cgnapt_entry_key *key,
	struct cgnapt_table_entry **entry_ptr1,
	struct cgnapt_table_entry **entry_ptr2)
{
	int port_num = 0, ret;

	struct pipeline_cgnapt *p_nat = (struct pipeline_cgnapt *)p;

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG >= 1) {
		printf("Th%d add_dynamic_cgnapt_entry key detail Entry:"
		"0x%x, %d, %d\n", p_nat->pipeline_num, key->ip, key->port,
		key->pid);
	}
	#endif

	int32_t position = rte_hash_lookup(napt_common_table, key);
	if (position >= 0) {
		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG >= 1) {
			printf("%s: cgnapt entry exists in "
			"position(first_key): %d\n", __func__, position);
		}
		#endif
		*entry_ptr1 = &napt_hash_tbl_entries[position];
		/* not required, as it is not used in the caller */
		*entry_ptr2 = NULL;
		return 1;
	}


	ret = increment_max_port_counter(key->ip, key->pid, p_nat);
	if (ret == MAX_PORT_INC_ERROR) {

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG > 1)
			printf("add_dynamic_cgnapt_entry:"
			"increment_max_port_counter-1 failed\n");
		#endif

		return 0;
	}

	if (ret == MAX_PORT_INC_REACHED) {

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG > 1)
			printf("add_dynamic_cgnapt_entry:"
			"increment_max_port_counter-2 failed\n");
		#endif

		return 0;
	}

	uint32_t public_ip;
	port_num = get_free_iport(p_nat, &public_ip);

	if (port_num == -1) {

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG > 2) {
			printf("add_dynamic_cgnapt_entry: %d\n", port_num);
			printf("add_dynamic_cgnapt_entry key detail:0x%x, "
			"%d, %d\n", key->ip, key->port, key->pid);
		}
		#endif

		return 0;
	}

	/* check for max_clients_per_ip */
	if (rte_atomic16_read
		(&all_public_ip
		 [rte_jhash(&public_ip, 4, 0) % 16].count) ==
		p_nat->max_clients_per_ip) {
		/* For now just bail out
		* In future we can think about
		* retrying getting a new iport
		*/
		release_iport(port_num, public_ip, p_nat);

		return 0;
	}

	rte_atomic16_inc(&all_public_ip
			 [rte_jhash(&public_ip, 4, 0) %
				16].count);

	#ifdef CGNAPT_DBG_PRNT
		if ((rte_jhash(&public_ip, 4, 0) % 16) == 8)
			printf("pub ip:%x coutn:%d\n", public_ip,
			rte_atomic16_read(&all_public_ip
			[rte_jhash(&public_ip, 4, 0) % 16].count));
	#endif

	#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG > 0) {
			printf("add_dynamic_cgnapt_entry: %d\n",
				port_num);
			printf("add_dynamic_cgnapt_entry key detail: "
			"0x%x, %d, %d\n", key->ip, key->port, key->pid);
	}
	#endif

	struct cgnapt_table_entry entry = {
		.head = {
		 .action = RTE_PIPELINE_ACTION_PORT,
		/* made it configurable below */
		 {.port_id = p->port_out_id[0]},
		 },

		.data = {
			.prv_port = key->port,
			.pub_ip = public_ip,
			.pub_port = port_num,
			.prv_phy_port = key->pid,
			.pub_phy_port = get_pub_to_prv_port(
					&public_ip,
					IP_VERSION_4),
			.ttl = 0,
			/* if(timeout == -1) : static entry
			*  if(timeout == 0 ) : dynamic entry
			*  if(timeout >  0 ) : PCP requested entry
			*/
			.timeout = 0,
			#ifdef PCP_ENABLE
			.timer = NULL,
			#endif
		}
	};

	entry.data.u.prv_ip = key->ip;
	entry.data.type = CGNAPT_ENTRY_IPV4;

	entry.head.port_id = entry.data.pub_phy_port; /* outgoing port info */

	struct pipeline_cgnapt_entry_key second_key;
	/* Need to add a second ingress entry */
	second_key.ip = public_ip;
	second_key.port = port_num;
	second_key.pid = 0xffff;

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 2)
		printf("add_dynamic_cgnapt_entry second key detail:"
		"0x%x, %d, %d\n", second_key.ip, second_key.port,
		second_key.pid);
	#endif

	int32_t position1 = rte_hash_add_key(napt_common_table, (void *)key);

	if (position1 < 0) {
		printf("CG-NAPT entry add failed ...returning "
		"without adding ... %d\n", position1);
		return 0;
	}


	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG) {
		printf("add_dynamic_cgnapt_entry:");
		print_key(key);
		print_cgnapt_entry(&entry);
	}
	#endif

	memcpy(&napt_hash_tbl_entries[position1], &entry,
			 sizeof(struct cgnapt_table_entry));

	/* this pointer is returned to pkt miss function */
	*entry_ptr1 = &napt_hash_tbl_entries[position1];

	p_nat->n_cgnapt_entry_added++;
	p_nat->dynCgnaptCount++;

	/* Now modify the forward port for reverse entry */

	/* outgoing port info */
	entry.head.port_id = entry.data.prv_phy_port;

	int32_t position2 = rte_hash_add_key(napt_common_table, &second_key);

	if (position2 < 0) {
		printf("CG-NAPT entry reverse bulk add failed ..."
		"returning with fwd add ...%d\n",
			 position2);
		return 0;
	}

	memcpy(&napt_hash_tbl_entries[position2], &entry,
			 sizeof(struct cgnapt_table_entry));

	*entry_ptr2 = &napt_hash_tbl_entries[position2];

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG >= 1) {
		printf("add_dynamic_cgnapt_entry position: %d, %d\n",
			position1, position2);
		printf("add_dynamic_cgnapt_entry: entry_ptr1: %p, "
		"entry_ptr2: %p\n", *entry_ptr1, *entry_ptr2);
	}
	#endif

	timer_thread_enqueue(key, &second_key, *entry_ptr1,
		*entry_ptr2, (struct pipeline *)p_nat);

	p_nat->n_cgnapt_entry_added++;
	p_nat->dynCgnaptCount++;

	return 1;
}

#endif

void hw_checksum(struct rte_mbuf *pkt, enum PKT_TYPE ver)
{
	struct tcp_hdr *tcp = NULL;
	struct udp_hdr *udp = NULL;
	struct icmp_hdr *icmp = NULL;
	uint8_t *protocol;
	void *ip_header = NULL;
	uint16_t prot_offset = 0;
	uint32_t pkt_type_is_ipv4 = 1;
	int temp = 0;
	pkt->ol_flags |= PKT_TX_IP_CKSUM;
	pkt->l2_len = ETH_HDR_SIZE;



	switch (ver) {
	case PKT_TYPE_IPV4to6:
		temp = -20;
	case PKT_TYPE_IPV6:

		ip_header = RTE_MBUF_METADATA_UINT32_PTR(pkt,
				MBUF_HDR_ROOM + ETH_HDR_SIZE + temp);

		pkt_type_is_ipv4 = 0;
		pkt->ol_flags |= PKT_TX_IPV6;
		pkt->l3_len =
			sizeof(struct ipv6_hdr);
		tcp = (struct tcp_hdr *)
			((unsigned char *)ip_header +
			 sizeof(struct ipv6_hdr));
		udp = (struct udp_hdr *)
			((unsigned char *)ip_header +
			 sizeof(struct ipv6_hdr));
		icmp = (struct icmp_hdr *)
			((unsigned char *)ip_header +
			 sizeof(struct ipv6_hdr));

		prot_offset = PROT_OFST_IP6 + temp;
		break;
	case PKT_TYPE_IPV6to4:
		temp = 20;
	case PKT_TYPE_IPV4:

		ip_header = RTE_MBUF_METADATA_UINT32_PTR(pkt,
				MBUF_HDR_ROOM + ETH_HDR_SIZE + temp);

		pkt->ol_flags |= PKT_TX_IPV4;
		pkt->l3_len =
			sizeof(struct ipv4_hdr);
		tcp = (struct tcp_hdr *)
			((unsigned char *)ip_header +
			 sizeof(struct ipv4_hdr));
		udp = (struct udp_hdr *)
			((unsigned char *)ip_header +
			 sizeof(struct ipv4_hdr));
		icmp = (struct icmp_hdr *)
			((unsigned char *)ip_header +
			 sizeof(struct ipv4_hdr));
		struct ipv4_hdr *ip_hdr =
			(struct ipv4_hdr *)ip_header;
		ip_hdr->hdr_checksum = 0;

		prot_offset = PROT_OFST_IP4 + temp;
		break;
	default:
		printf("hw_checksum: pkt version is invalid\n");
	}
	protocol = (uint8_t *) RTE_MBUF_METADATA_UINT8_PTR(pkt,
			 prot_offset);

	switch (*protocol) {
	case IP_PROTOCOL_TCP:   /* 6 */
		tcp->cksum = 0;
		pkt->ol_flags |= PKT_TX_TCP_CKSUM;
		if (pkt_type_is_ipv4) {
			tcp->cksum = rte_ipv4_phdr_cksum(
				(struct ipv4_hdr *)ip_header,
				pkt->ol_flags);
		} else {
			tcp->cksum = rte_ipv6_phdr_cksum(
				(struct ipv6_hdr *)ip_header,
				pkt->ol_flags);
		}
		break;
	case IP_PROTOCOL_UDP:   /* 17 */
		udp->dgram_cksum = 0;
		pkt->ol_flags |= PKT_TX_UDP_CKSUM;
		if (pkt_type_is_ipv4) {
			udp->dgram_cksum =
				rte_ipv4_phdr_cksum(
				(struct ipv4_hdr *)ip_header,
				pkt->ol_flags);
		} else {
			udp->dgram_cksum =
				rte_ipv6_phdr_cksum(
				(struct ipv6_hdr *)ip_header,
				pkt->ol_flags);
		}
		break;
	case IP_PROTOCOL_ICMP:  /* 1 */
		if (pkt_type_is_ipv4) {
			/* ICMP checksum code */
			struct ipv4_hdr *ip_hdr =
				(struct ipv4_hdr *)ip_header;
			int size = rte_bswap16(ip_hdr->total_length) - 20;
			icmp->icmp_cksum = 0;
			icmp->icmp_cksum =
				~rte_raw_cksum(icmp,
							size);
		}
		break;

	default:
		printf("hw_checksum() : Neither TCP or UDP pkt\n");
		break;
	}
}


void sw_checksum(struct rte_mbuf *pkt, enum PKT_TYPE ver)
{
	struct tcp_hdr *tcp = NULL;
	struct udp_hdr *udp = NULL;
	struct icmp_hdr *icmp = NULL;
	uint8_t *protocol;
	void *ip_header = NULL;
	uint16_t prot_offset = 0;
	uint32_t pkt_type_is_ipv4 = 1;
	int temp = 0;

	switch (ver) {
	case PKT_TYPE_IPV4to6:
		temp = -20;
	case PKT_TYPE_IPV6:

		ip_header = RTE_MBUF_METADATA_UINT32_PTR(pkt,
				MBUF_HDR_ROOM + ETH_HDR_SIZE + temp);

		pkt_type_is_ipv4 = 0;
		tcp = (struct tcp_hdr *)
			((unsigned char *)ip_header +
			 sizeof(struct ipv6_hdr));
		udp = (struct udp_hdr *)
			((unsigned char *)ip_header +
			 sizeof(struct ipv6_hdr));
		icmp = (struct icmp_hdr *)
			((unsigned char *)ip_header +
			 sizeof(struct ipv6_hdr));

		prot_offset = PROT_OFST_IP6 + temp;
		break;
	case PKT_TYPE_IPV6to4:
		temp = 20;
	case PKT_TYPE_IPV4:

		ip_header = RTE_MBUF_METADATA_UINT32_PTR(pkt,
				MBUF_HDR_ROOM + ETH_HDR_SIZE + temp);

		tcp = (struct tcp_hdr *)
			((unsigned char *)ip_header +
			 sizeof(struct ipv4_hdr));
		udp = (struct udp_hdr *)
			((unsigned char *)ip_header +
			 sizeof(struct ipv4_hdr));
		icmp = (struct icmp_hdr *)
			((unsigned char *)ip_header +
			 sizeof(struct ipv4_hdr));

		prot_offset = PROT_OFST_IP4 + temp;
		break;
	default:
		printf("sw_checksum: pkt version is invalid\n");
	}
	protocol = (uint8_t *) RTE_MBUF_METADATA_UINT8_PTR(pkt,
			 prot_offset);

	switch (*protocol) {
	case IP_PROTOCOL_TCP:   /* 6 */
		tcp->cksum = 0;
		if (pkt_type_is_ipv4) {
			struct ipv4_hdr *ip_hdr =
				(struct ipv4_hdr *)ip_header;
			tcp->cksum = rte_ipv4_udptcp_cksum(ip_hdr,
					(void *)tcp);
			ip_hdr->hdr_checksum = 0;
			ip_hdr->hdr_checksum = rte_ipv4_cksum(
						(struct ipv4_hdr *)ip_hdr);
		} else {
			tcp->cksum = rte_ipv6_udptcp_cksum(
					(struct ipv6_hdr *)
					ip_header, (void *)tcp);
		}
		break;
	case IP_PROTOCOL_UDP:   /* 17 */
		udp->dgram_cksum = 0;
		if (pkt_type_is_ipv4) {
			struct ipv4_hdr *ip_hdr =
				(struct ipv4_hdr *)ip_header;
			udp->dgram_cksum = rte_ipv4_udptcp_cksum(
						ip_hdr, (void *)udp);
			ip_hdr->hdr_checksum = 0;
			ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
		} else {
			udp->dgram_cksum = rte_ipv6_udptcp_cksum(
					(struct ipv6_hdr *)
					ip_header, (void *)udp);
		}
		break;
	case IP_PROTOCOL_ICMP:  /* 1 */
		if (pkt_type_is_ipv4) {
			/* ICMP checksum code */
			struct ipv4_hdr *ip_hdr =
				(struct ipv4_hdr *)ip_header;
			int size = rte_bswap16(ip_hdr->total_length) - 20;
			icmp->icmp_cksum = 0;
			icmp->icmp_cksum =
				~rte_raw_cksum(icmp,
							size);
			ip_hdr->hdr_checksum = 0;
			ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
		}
		break;

	default:
		printf("sw_checksum() : Neither TCP or UDP pkt\n");
		break;
	}
}

void print_pkt_info(uint8_t *eth_dest, struct ether_addr *hw_addr, 
		uint32_t dest_address, uint32_t port_id, struct rte_mbuf *pkt)
{

if (CGNAPT_DEBUG > 2) {
	printf("MAC Found ip 0x%x, port %d - %02x:%02x:%02x:%02x:%02x:%02x  \n",
	dest_address, port_id, hw_addr->addr_bytes[0], hw_addr->addr_bytes[1],
	hw_addr->addr_bytes[2], hw_addr->addr_bytes[3], hw_addr->addr_bytes[4],
	hw_addr->addr_bytes[5]);

	printf("Dest MAC before - %02x:%02x:%02x:%02x:%02x:%02x      \n",
		eth_dest[0], eth_dest[1], eth_dest[2], eth_dest[3], eth_dest[4],
		eth_dest[5]);
}

if (CGNAPT_DEBUG > 2) {
	printf("Dest MAC after - "
		"%02x:%02x:%02x:%02x:%02x:%02x      \n",
		eth_dest[0], eth_dest[1],
		eth_dest[2], eth_dest[3],
		eth_dest[4], eth_dest[5]);
}

if (CGNAPT_DEBUG > 4)
	print_pkt(pkt);
}

static uint8_t check_arp_icmp(
	struct rte_mbuf *pkt,
	uint64_t pkt_mask,
	struct pipeline_cgnapt *p_nat)
{
	uint32_t eth_proto_offset = MBUF_HDR_ROOM + 12;
	uint16_t *eth_proto = RTE_MBUF_METADATA_UINT16_PTR(
				pkt, eth_proto_offset);
	struct app_link_params *link;
	uint8_t solicited_node_multicast_addr[16] = {
		0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00};

	/* ARP outport number */
	uint16_t out_port = p_nat->p.n_ports_out - 1;
	printf("check_arp_icmp called*****\n");
	uint8_t *protocol;
	uint32_t prot_offset;

	link = &myApp->link_params[pkt->port];


	switch (rte_be_to_cpu_16(*eth_proto)) {

	case ETH_TYPE_ARP:

		rte_pipeline_port_out_packet_insert(
			p_nat->p.p,
			out_port,
			pkt);

		/*
		* Pkt mask should be changed, and not changing the
		* drop mask
		*/
		p_nat->invalid_packets |= pkt_mask;
		p_nat->arpicmpPktCount++;

		return 0;
	break;
	case ETH_TYPE_IPV4: {
		/* header room + eth hdr size +
		* src_aadr offset in ip header
		*/
		uint32_t dst_addr_offset = MBUF_HDR_ROOM +
			ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST;
		uint32_t *dst_addr =
			RTE_MBUF_METADATA_UINT32_PTR(pkt,
			dst_addr_offset);
		prot_offset = MBUF_HDR_ROOM + ETH_HDR_SIZE +
			IP_HDR_PROTOCOL_OFST;
		protocol = RTE_MBUF_METADATA_UINT8_PTR(pkt,
			prot_offset);
		if ((*protocol == IP_PROTOCOL_ICMP) &&
			link->ip == rte_be_to_cpu_32(*dst_addr)) {

			if (is_phy_port_privte(pkt->port)) {

				rte_pipeline_port_out_packet_insert(
					p_nat->p.p, out_port, pkt);

				/*
				* Pkt mask should be changed,
				* and not changing the drop mask
				*/

				p_nat->invalid_packets |= pkt_mask;
				p_nat->arpicmpPktCount++;

				return 0;
			}
		}
		return 1;
	}
	break;

	#ifdef IPV6
	case ETH_TYPE_IPV6:
	if (dual_stack_enable) {

		/* Commented code may be required for future usage,
		* Please keep it
		*/
		//uint32_t dst_addr_offset = MBUF_HDR_ROOM +
		//	ETH_HDR_SIZE + IPV6_HDR_DST_ADR_OFST;
		//uint32_t *dst_addr =
		//	RTE_MBUF_METADATA_UINT32_PTR(pkt,
		//	dst_addr_offset);
		uint32_t prot_offset_ipv6 = MBUF_HDR_ROOM +
			ETH_HDR_SIZE + IPV6_HDR_PROTOCOL_OFST;
		struct ipv6_hdr *ipv6_h;

		ipv6_h = (struct ipv6_hdr *) MBUF_HDR_ROOM +
			ETH_HDR_SIZE;
		protocol = RTE_MBUF_METADATA_UINT8_PTR(pkt,
			prot_offset_ipv6);

		if (ipv6_h->proto == ICMPV6_PROTOCOL_ID) {
			if (!memcmp(ipv6_h->dst_addr, link->ipv6, 16)
				|| !memcmp(ipv6_h->dst_addr,
				solicited_node_multicast_addr, 13)) {
				rte_pipeline_port_out_packet_insert(
					p_nat->p.p, out_port, pkt);
				/*
				* Pkt mask should be changed,
				* and not changing the drop mask
				*/
				p_nat->invalid_packets |= pkt_mask;
				p_nat->arpicmpPktCount++;
			} else {
				p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;

			#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount1++;
			#endif
			}
			return 0;
		}
	}
	break;
	#endif
	default:
		return 1;
	}
	return 1;
}

/**
 * Function to create common NAPT table
 * Called during pipeline initialization
 * Creates the common NAPT table
 * If it is not already created and stores its pointer
 * in global napt_common_table pointer.
 *
 * @params nFlows
 *  Max number of NAPT flows. This parameter is configurable via config file.
 *
 * @return
 *  0 on success, negative on error.
 */
int create_napt_common_table(uint32_t nFlows)
{
	if (napt_common_table != NULL) {
		printf("napt_common_table already exists.\n");
		return -1;
	}

	napt_common_table = rte_hash_create(&napt_common_table_hash_params);

	if (napt_common_table == NULL) {
		printf("napt_common_table creation failed.\n");
		return -2;
	}

	uint32_t number_of_entries = nFlows;

	uint32_t size =
		RTE_CACHE_LINE_ROUNDUP(sizeof(struct cgnapt_table_entry) *
					 number_of_entries);
	napt_hash_tbl_entries = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);

	if (napt_hash_tbl_entries == NULL) {
		printf("napt_hash_tbl_entries creation failed. %d, %d\n",
				 nFlows, (int)sizeof(struct cgnapt_table_entry));
		return -3;
	}

	return 0;
}

/**
 * Function to initialize bulk port allocation data structures
 * Called during pipeline initialization.
 *
 * Creates the port alloc ring for the VNF_set this pipeline belongs
 *
 * Creates global port allocation buffer pool
 *
 * Initializes the port alloc ring according to config data
 *
 * @param p_nat
 *  A pointer to struct pipeline_cgnapt
 *
 * @return
 *  0 on success, negative on error.
 */
int napt_port_alloc_init(struct pipeline_cgnapt *p_nat)
{
	p_nat->allocated_ports = NULL;
	p_nat->free_ports = NULL;

	uint32_t vnf_set_num = p_nat->vnf_set;
	/*uint32_t vnf_set_num = get_vnf_set_num(p_nat->pipeline_num); */

	printf("VNF set number for CGNAPT %d is %d.\n", p_nat->pipeline_num,
			 vnf_set_num);
	if (vnf_set_num == 0xFF) {
		printf("VNF set number for CGNAPT %d is invalid %d.\n",
				 p_nat->pipeline_num, vnf_set_num);
		return -1;
	}

	p_nat->port_alloc_ring = port_alloc_ring[vnf_set_num];
	if (p_nat->port_alloc_ring != NULL) {
		printf("CGNAPT%d port_alloc_ring already exists.\n",
				 p_nat->pipeline_num);
		return 1;
	}

	printf("napt_port_alloc_elem_count :%d\n",
		napt_port_alloc_elem_count);
	napt_port_alloc_elem_count += 1;
	napt_port_alloc_elem_count =
		nextPowerOf2(napt_port_alloc_elem_count);
	printf("Next power of napt_port_alloc_elem_count: %d\n",
		napt_port_alloc_elem_count);

	port_alloc_ring[vnf_set_num] =
		 rte_ring_create(napt_port_alloc_ring_name[vnf_set_num],
			napt_port_alloc_elem_count, rte_socket_id(), 0);
	p_nat->port_alloc_ring = port_alloc_ring[vnf_set_num];
	if (p_nat->port_alloc_ring == NULL) {
		printf("CGNAPT%d -  Failed to create port_alloc_ring\n",
					p_nat->pipeline_num);
		return -1;
	}

	/* Create port alloc buffer */
	/* Only one pool is enough for all vnf sets */
	if (napt_port_pool == NULL) {

		napt_port_pool = rte_mempool_create(
				"napt_port_pool",
				napt_port_alloc_elem_count,
				sizeof(struct napt_port_alloc_elem),
				0, 0, NULL, NULL, NULL,
				NULL, rte_socket_id(), 0);
	}

	if (napt_port_pool == NULL) {
		printf("CGNAPT - Create port pool failed\n");
		return -1;
	}

	/* Add all available public IP addresses and ports to the ring */
	uint32_t i, j = 0;

#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag) {
		printf("******* pub_ip_range_count:%d ***********\n",
				 p_nat->pub_ip_range_count);
		/* Initialize all public IP's addresses  */
		int if_addrs;
		uint32_t max_ips_remain;

		for (if_addrs = 0; if_addrs < p_nat->pub_ip_range_count;
			 if_addrs++) {
			/* Add all available addresses to the ring */

			for (i = p_nat->pub_ip_range[if_addrs].start_ip;
				 i <= p_nat->pub_ip_range[if_addrs].end_ip;) {
			/* 1. Get a port alloc buffer from napt_port_pool */
				void *portsBuf;

				if (j == 0) {
			/* get new  napt_port_alloc_elem from pool */
				if (rte_mempool_get(napt_port_pool,
						&portsBuf) < 0) {
				printf("CGNAPT - Error in getting port "
				"alloc buffer\n");
						return -1;
					}
				}

			/* 2. Populate it with available ports and ip addr */
				struct napt_port_alloc_elem *pb =
					(struct napt_port_alloc_elem *)portsBuf;

			int temp;
			temp = p_nat->pub_ip_range[if_addrs].end_ip -
				i + 1;

			/* Check if remaining port count is greater
			*  than or equals to bulk count, if not give
			*  remaining count ports than giving bulk count
			*/
			if (temp < NUM_NAPT_PORT_BULK_ALLOC)
				max_ips_remain = temp;
			else
				max_ips_remain =
					NUM_NAPT_PORT_BULK_ALLOC;

				for (j = 0; j < max_ips_remain; j++) {
					pb->count = j + 1;
					pb->ip_addr[j] = i + j;
					pb->ports[j] = 0;
					if ((i + j) ==
						p_nat->pub_ip_range[if_addrs].
						end_ip)
						break;
				}

				/* 3. add the port alloc buffer to ring */
				if (rte_ring_enqueue(p_nat->port_alloc_ring,
				portsBuf) != 0) {
				printf("CGNAPT%d - Enqueue error - i %d,",
						 p_nat->pipeline_num, i);
					printf("j %d, if_addrs %d, pb %p\n",
						j, if_addrs, pb);
					rte_ring_dump(stdout,
						p_nat->port_alloc_ring);
					rte_mempool_put(napt_port_pool,
							portsBuf);
					return -1;
				}

				/* reset j and advance i */
				j = 0;
				i += max_ips_remain;
			}
		}

		return 1;
	}
#endif

	printf("******* p_nat->pub_ip_count:%d ***********\n",
			 p_nat->pub_ip_count);
	/* Initialize all public IP's ports  */
	int if_ports;
	uint32_t max_ports_remain;

	for (if_ports = 0; if_ports < p_nat->pub_ip_count; if_ports++) {
		/* Add all available ports to the ring */

		for (i = p_nat->pub_ip_port_set[if_ports].start_port;
			 i <= p_nat->pub_ip_port_set[if_ports].end_port;) {
			/* 1. Get a port alloc buffer from napt_port_pool */
			void *portsBuf;

			if (j == 0) {
				/* get new  napt_port_alloc_elem from pool */
				if (rte_mempool_get(napt_port_pool, &portsBuf) <
					0) {
					printf("CGNAPT - Error in getting "
					"port alloc buffer\n");
					return -1;
				}
			}

			/* 2. Populate it with available ports and ip addr */
			struct napt_port_alloc_elem *pb =
				(struct napt_port_alloc_elem *)portsBuf;

			int temp;
			temp = p_nat->pub_ip_port_set[if_ports].end_port -
				i + 1;
			/* Check if remaining port count is greater
			*  than or equals to bulk count, if not give
			*  remaining count ports than giving bulk count
			*/
			if (temp < NUM_NAPT_PORT_BULK_ALLOC)
				max_ports_remain = temp;
			else
				max_ports_remain =
					NUM_NAPT_PORT_BULK_ALLOC;

			for (j = 0; j < max_ports_remain; j++) {
				pb->count = j + 1;
				pb->ip_addr[j] =
					p_nat->pub_ip_port_set[if_ports].ip;
				pb->ports[j] = i + j;
				if ((i + j) == p_nat->pub_ip_port_set
						[if_ports].end_port)
					break;
			}

			/* 3. add the port alloc buffer to ring */
			if (rte_ring_enqueue(p_nat->port_alloc_ring,
				portsBuf) != 0) {
				printf("CGNAPT%d - Enqueue error - i %d, j %d, "
				" if_ports %d, pb %p\n", p_nat->pipeline_num,
				i, j, if_ports, pb);

				rte_ring_dump(stdout, p_nat->port_alloc_ring);
				rte_mempool_put(napt_port_pool, portsBuf);
				return -1;
			}

			/* reset j and advance i */
			j = 0;
			i += max_ports_remain;
		}
	}

	return 1;
}

static pipeline_msg_req_handler handlers[] = {
	[PIPELINE_MSG_REQ_PING] =
		pipeline_msg_req_ping_handler,
	[PIPELINE_MSG_REQ_STATS_PORT_IN] =
		pipeline_msg_req_stats_port_in_handler,
	[PIPELINE_MSG_REQ_STATS_PORT_OUT] =
		pipeline_msg_req_stats_port_out_handler,
	[PIPELINE_MSG_REQ_STATS_TABLE] = pipeline_msg_req_stats_table_handler,
	[PIPELINE_MSG_REQ_PORT_IN_ENABLE] =
		pipeline_msg_req_port_in_enable_handler,
	[PIPELINE_MSG_REQ_PORT_IN_DISABLE] =
		pipeline_msg_req_port_in_disable_handler,
	[PIPELINE_MSG_REQ_CUSTOM] =
		pipeline_cgnapt_msg_req_custom_handler,
};

static pipeline_msg_req_handler custom_handlers[] = {
	[PIPELINE_CGNAPT_MSG_REQ_ENTRY_ADD] =
		pipeline_cgnapt_msg_req_entry_add_handler,
	[PIPELINE_CGNAPT_MSG_REQ_ENTRY_DEL] =
		pipeline_cgnapt_msg_req_entry_del_handler,
	[PIPELINE_CGNAPT_MSG_REQ_ENTRY_SYNC] =
		pipeline_cgnapt_msg_req_entry_sync_handler,
	[PIPELINE_CGNAPT_MSG_REQ_ENTRY_DBG] =
		pipeline_cgnapt_msg_req_entry_dbg_handler,
	[PIPELINE_CGNAPT_MSG_REQ_ENTRY_ADDM] =
		pipeline_cgnapt_msg_req_entry_addm_handler,
	[PIPELINE_CGNAPT_MSG_REQ_VER] =
		pipeline_cgnapt_msg_req_ver_handler,
	[PIPELINE_CGNAPT_MSG_REQ_NSP_ADD] =
		pipeline_cgnapt_msg_req_nsp_add_handler,
	[PIPELINE_CGNAPT_MSG_REQ_NSP_DEL] =
		pipeline_cgnapt_msg_req_nsp_del_handler,

	#ifdef PCP_ENABLE
	[PIPELINE_CGNAPT_MSG_REQ_PCP] =
		pipeline_cgnapt_msg_req_pcp_handler,
	#endif
};

/**
 * Function to convert an IPv6 packet to IPv4 packet
 *
 * @param pkt
 *  A pointer to packet mbuf
 * @param in_ipv6_hdr
 *  A pointer to IPv6 header in the given pkt
 *
 */
static void
convert_ipv6_to_ipv4(struct rte_mbuf *pkt, struct ipv6_hdr *in_ipv6_hdr)
{
	uint32_t ip_hdr_offset = MBUF_HDR_ROOM + ETH_HDR_SIZE;

	uint8_t *eth_hdr_p = RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
	uint8_t *ipv6_hdr_p = RTE_MBUF_METADATA_UINT8_PTR(pkt, ip_hdr_offset);

	struct ether_hdr eth_hdr;
	struct ipv4_hdr *ipv4_hdr_p;
	uint16_t frag_off = 0x4000;
	struct cgnapt_nsp_node *ll = nsp_ll;
	uint8_t ipv4_dest[4];
	int nsp = 0;

	memcpy(&eth_hdr, eth_hdr_p, sizeof(struct ether_hdr));
	memcpy(in_ipv6_hdr, ipv6_hdr_p, sizeof(struct ipv6_hdr));

	eth_hdr.ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

	char *data_area_p = rte_pktmbuf_adj(pkt, 20);
	if (data_area_p == NULL) {
		printf("convert_ipv6_to_ipv4:data_area_p is NULL\n");
		return;
	}
	ipv4_hdr_p = (struct ipv4_hdr *)(data_area_p + ETH_HDR_SIZE);
	memset(ipv4_hdr_p, 0, sizeof(struct ipv4_hdr));

	memcpy(data_area_p, &eth_hdr, sizeof(struct ether_hdr));

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG == 1)
		printf("convert_ipv6_to_ipv4: eth_hdr_p(%p), data_area_p(%p), "
		"ipv4_hdr_p(%p)\n", eth_hdr_p, data_area_p, ipv4_hdr_p);
	#endif

	ipv4_hdr_p->version_ihl = 0x4 << 4 | 0x5;
	ipv4_hdr_p->type_of_service =
		rte_be_to_cpu_32(in_ipv6_hdr->vtc_flow) & 0x0ff00000 >> 20;
	ipv4_hdr_p->total_length =
		rte_cpu_to_be_16(rte_be_to_cpu_16(
				in_ipv6_hdr->payload_len) + 20);
	ipv4_hdr_p->packet_id = 0;
	ipv4_hdr_p->fragment_offset = rte_cpu_to_be_16(frag_off);
	ipv4_hdr_p->time_to_live = in_ipv6_hdr->hop_limits;
	ipv4_hdr_p->next_proto_id = in_ipv6_hdr->proto;
	ipv4_hdr_p->hdr_checksum = 0;
	ipv4_hdr_p->src_addr = 0;

	while (ll != NULL) {
		if (!memcmp
			(&in_ipv6_hdr->dst_addr[0], &ll->nsp.prefix[0],
			 ll->nsp.depth / 8)) {
			if (ll->nsp.depth == 32)
				memcpy(&ipv4_dest[0], &in_ipv6_hdr->dst_addr[4],
						 4);
			else if (ll->nsp.depth == 40) {
				ipv4_dest[0] = in_ipv6_hdr->dst_addr[5];
				ipv4_dest[1] = in_ipv6_hdr->dst_addr[6];
				ipv4_dest[2] = in_ipv6_hdr->dst_addr[7];
				ipv4_dest[3] = in_ipv6_hdr->dst_addr[9];
			} else if (ll->nsp.depth == 48) {
				ipv4_dest[0] = in_ipv6_hdr->dst_addr[6];
				ipv4_dest[1] = in_ipv6_hdr->dst_addr[7];
				ipv4_dest[2] = in_ipv6_hdr->dst_addr[9];
				ipv4_dest[3] = in_ipv6_hdr->dst_addr[10];
			} else if (ll->nsp.depth == 56) {
				ipv4_dest[0] = in_ipv6_hdr->dst_addr[7];
				ipv4_dest[1] = in_ipv6_hdr->dst_addr[9];
				ipv4_dest[2] = in_ipv6_hdr->dst_addr[10];
				ipv4_dest[3] = in_ipv6_hdr->dst_addr[11];
			} else if (ll->nsp.depth == 64) {
				ipv4_dest[0] = in_ipv6_hdr->dst_addr[9];
				ipv4_dest[1] = in_ipv6_hdr->dst_addr[10];
				ipv4_dest[2] = in_ipv6_hdr->dst_addr[11];
				ipv4_dest[3] = in_ipv6_hdr->dst_addr[12];
			} else if (ll->nsp.depth == 96) {
				ipv4_dest[0] = in_ipv6_hdr->dst_addr[12];
				ipv4_dest[1] = in_ipv6_hdr->dst_addr[13];
				ipv4_dest[2] = in_ipv6_hdr->dst_addr[14];
				ipv4_dest[3] = in_ipv6_hdr->dst_addr[15];
			}

			nsp = 1;
			break;
		}

		ll = ll->next;
	}

	if (nsp)
		memcpy(&ipv4_hdr_p->dst_addr, &ipv4_dest[0], 4);
	else
		memcpy(&ipv4_hdr_p->dst_addr, &in_ipv6_hdr->dst_addr[12], 4);

}

/**
 * Function to convert an IPv4 packet to IPv6 packet
 *
 * @param pkt
 *  A pointer to packet mbuf
 * @param in_ipv4_hdr
 *  A pointer to IPv4 header in the given pkt
 *
 */
static void
convert_ipv4_to_ipv6(struct rte_mbuf *pkt, struct ipv4_hdr *in_ipv4_hdr)
{
	uint32_t ip_hdr_offset = MBUF_HDR_ROOM + ETH_HDR_SIZE;

	uint8_t *eth_hdr_p = RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
	uint8_t *ipv4_hdr_p = RTE_MBUF_METADATA_UINT8_PTR(pkt, ip_hdr_offset);

	struct ether_hdr eth_hdr;
	struct ipv6_hdr *ipv6_hdr_p;

	memcpy(&eth_hdr, eth_hdr_p, sizeof(struct ether_hdr));
	memcpy(in_ipv4_hdr, ipv4_hdr_p, sizeof(struct ipv4_hdr));

	eth_hdr.ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);

	char *data_area_p = rte_pktmbuf_prepend(pkt, 20);
	if (data_area_p == NULL) {
		printf("convert_ipv4_to_ipv6:data_area_p is NULL\n");
		return;
	}
	ipv6_hdr_p = (struct ipv6_hdr *)(data_area_p + ETH_HDR_SIZE);
	memset(ipv6_hdr_p, 0, sizeof(struct ipv6_hdr));

	memcpy(data_area_p, &eth_hdr, sizeof(struct ether_hdr));

	ipv6_hdr_p->vtc_flow =
		rte_cpu_to_be_32((0x6 << 28) |
				 (in_ipv4_hdr->type_of_service << 20));
	ipv6_hdr_p->payload_len =
		rte_cpu_to_be_16(rte_be_to_cpu_16(
			in_ipv4_hdr->total_length) - 20);
	ipv6_hdr_p->proto = in_ipv4_hdr->next_proto_id;
	ipv6_hdr_p->hop_limits = in_ipv4_hdr->time_to_live;

	ipv6_hdr_p->src_addr[0] = 0x00;
	ipv6_hdr_p->src_addr[1] = 0x64;
	ipv6_hdr_p->src_addr[2] = 0xff;
	ipv6_hdr_p->src_addr[3] = 0x9b;
	ipv6_hdr_p->src_addr[4] = 0x00;
	ipv6_hdr_p->src_addr[5] = 0x00;
	ipv6_hdr_p->src_addr[6] = 0x00;
	ipv6_hdr_p->src_addr[7] = 0x00;
	ipv6_hdr_p->src_addr[8] = 0x00;
	ipv6_hdr_p->src_addr[9] = 0x00;
	ipv6_hdr_p->src_addr[10] = 0x00;
	ipv6_hdr_p->src_addr[11] = 0x00;
	memcpy(&ipv6_hdr_p->src_addr[12], &in_ipv4_hdr->src_addr, 4);

	memset(&ipv6_hdr_p->dst_addr, 0, 16);

	return;

}

/**
 * Output port handler
 *
 * @param pkt
 *  A pointer to packet mbuf
 * @param arg
 *  Unused void pointer
 *
 */
#ifdef PIPELINE_CGNAPT_INSTRUMENTATION
static void
pkt_work_cgnapt_out(__rte_unused struct rte_mbuf *pkt, __rte_unused void *arg)
{
#ifdef PIPELINE_CGNAPT_INSTRUMENTATION
	if ((cgnapt_num_func_to_inst == 5)
		&& (cgnapt_inst_index < INST_ARRAY_SIZE)) {
		if (cgnapt_inst5_flag == 0) {
			uint8_t *inst5_sig =
				RTE_MBUF_METADATA_UINT8_PTR(pkt,
					CGNAPT_INST5_OFST);
			if (*inst5_sig == CGNAPT_INST5_SIG) {
				cgnapt_inst5_flag = 1;
				inst_end_time[cgnapt_inst_index] =
					rte_get_tsc_cycles();
				cgnapt_inst_index++;
			}
		}
	}
#endif

	/* cgnapt_pkt_out_count++; */
	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG)
		print_pkt(pkt);
	#endif
}
#endif

/**
 * Output port handler to handle 4 pkts
 *
 * @param pkt
 *  A pointer to packet mbuf
 * @param arg
 *  Inport handler argument pointer
 *
 */
#ifdef PIPELINE_CGNAPT_INSTRUMENTATION
static void pkt4_work_cgnapt_out(struct rte_mbuf **pkt, void *arg)
{
	(void)pkt;
	(void)arg;
/* TO BE IMPLEMENTED IF REQUIRED */
}
#endif

#ifdef PIPELINE_CGNAPT_INSTRUMENTATION
PIPELINE_CGNAPT_PORT_OUT_AH(port_out_ah_cgnapt,
				pkt_work_cgnapt_out, pkt4_work_cgnapt_out);

PIPELINE_CGNAPT_PORT_OUT_BAH(port_out_ah_cgnapt_bulk,
				 pkt_work_cgnapt_out, pkt4_work_cgnapt_out);
#endif

/**
 * Function to validate the packet and return version
 *
 * @param pkt
 *  A pointer to packet mbuf
 *
 * @return
 *  IP version of the valid pkt, -1 if invalid pkt
 */
int rte_get_pkt_ver(struct rte_mbuf *pkt)
{
	uint32_t eth_proto_offset = MBUF_HDR_ROOM + 12;
	uint16_t *eth_proto =
		RTE_MBUF_METADATA_UINT16_PTR(pkt, eth_proto_offset);

	if (*eth_proto == rte_be_to_cpu_16(ETHER_TYPE_IPv4))
		return IP_VERSION_4;

	if (dual_stack_enable
		&& (*eth_proto == rte_be_to_cpu_16(ETHER_TYPE_IPv6)))
		return IP_VERSION_6;

	/* Check the protocol first, if not UDP or TCP return */

	return -1;
}

/**
 * A method to print the NAPT entry
 *
 * @param ent
 *  A pointer to struct cgnapt_table_entry
 */
void my_print_entry(struct cgnapt_table_entry *ent)
{
	printf("CGNAPT key:\n");
	printf("entry_type :%d\n", ent->data.type);
	printf("prv_ip: %x %x %x %x\n", ent->data.u.u32_prv_ipv6[0],
			 ent->data.u.u32_prv_ipv6[1], ent->data.u.u32_prv_ipv6[2],
			 ent->data.u.u32_prv_ipv6[3]);
	printf("prv_port:%d\n", ent->data.prv_port);

	printf("pub_ip:%x\n", ent->data.pub_ip);
	printf("prv_phy_port:%d\n", ent->data.prv_phy_port);
	printf("pub_phy_port:%d\n", ent->data.pub_phy_port);
}

/**
 * Function to print common CGNAPT table entries
 *
 */
void print_common_table(void)
{
	uint32_t count = 0;
	const void *key;
	void *data;
	uint32_t next = 0;
	int32_t index = 0;
	do {
		index = rte_hash_iterate(napt_common_table,
				&key, &data, &next);

		if ((index != -EINVAL) && (index != -ENOENT)) {
			printf("\n%04d  ", count);
			//print_key((struct pipeline_cgnapt_entry_key *)key);
			rte_hexdump(stdout, "KEY", key,
				sizeof(struct pipeline_cgnapt_entry_key));
			int32_t position = rte_hash_lookup(
					napt_common_table, key);
			print_cgnapt_entry(&napt_hash_tbl_entries[position]);
		}

		count++;
	} while (index != -ENOENT);
}

/**
 * Input port handler for mixed traffic
 * This is the main method in this file when running in mixed traffic mode.
 * Starting from the packet burst it filters unwanted packets,
 * calculates keys, does lookup and then based on the lookup
 * updates NAPT table and does packet NAPT translation.
 *
 * @param rte_p
 *  A pointer to struct rte_pipeline
 * @param pkts
 *  A pointer to array of packets mbuf
 * @param n_pkts
 *  Number of packets in the burst
 * @param arg
 *  Void pointer
 *
 * @return
 *  int that is not checked by caller
 */
static int cgnapt_in_port_ah_mix(struct rte_pipeline *rte_p,
				 struct rte_mbuf **pkts,
				 uint32_t n_pkts, void *arg)
{
/*
*	Code flow
*
* 1. Read packet version, if invalid drop the packet
* 2. Check protocol, if not UDP or TCP drop the packet
* 3. Bring all valid packets together - useful for bulk lookup
*	and calculate key for all packets
*	a. If IPv4 : calculate key with full IP
*	b. If IPv6 : calculate key with last 32-bit of IP
* 4. Do bulk lookup with rte_hash_lookup_bulk(), if something went wrong
*	drop all packets
* 5. For lookup hit packets, read entry from table
* 6. For lookup miss packets, add dynamic entry to table
* 7. If pkt is IPv6
*	a. If egress pkt, convert to IPv4 and NAPT it
*	b. If ingress, drop the pkt
* 8. If pkt is IPv4
*	a. If egress pkt, NAPT it. Get MAC
*	b. If first ingress pkt (with no egress entry), drop the pkt
*		 If not first ingress pkt
*		I.  If IPv6 converted packet, convert back to IPv6,
			NAPT it & get MAC
*		II. If IPv4 packet, NAPT it & get MAC
* 9. Send all packets out to corresponding ports
*/
	struct pipeline_cgnapt_in_port_h_arg *ap = arg;
	struct pipeline_cgnapt *p_nat = ap->p;
	uint8_t compacting_map[RTE_HASH_LOOKUP_BULK_MAX];
	uint32_t packets_for_lookup = 0;
	uint32_t i;

	p_nat->valid_packets = 0;
	p_nat->invalid_packets = 0;

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 1)
		printf("cgnapt_key hit fn: %" PRIu32 "\n", n_pkts);
	#endif

	p_nat->pkt_burst_cnt = 0;	/* for dynamic napt */

	uint16_t phy_port = 0;
	uint16_t *src_port = NULL;
	uint16_t *dst_port = NULL;
	uint32_t *src_addr = NULL;
	uint32_t *dst_addr = NULL;
	uint8_t *protocol = NULL;
	uint8_t *eth_dest = NULL;
	uint8_t *eth_src = NULL;
	uint16_t src_port_offset = 0;
	uint16_t dst_port_offset = 0;
	uint16_t src_addr_offset = 0;
	uint16_t dst_addr_offset = 0;
	uint16_t prot_offset = 0;
	uint16_t eth_offset = 0;
	int ver = 0;

	enum PKT_TYPE pkt_type = PKT_TYPE_IPV4;

	src_port_offset = SRC_PRT_OFST_IP4_TCP;
	dst_port_offset = DST_PRT_OFST_IP4_TCP;

	for (i = 0; i < n_pkts; i++) {
		p_nat->receivedPktCount++;

		/* bitmask representing only this packet */
		uint64_t pkt_mask = 1LLU << i;

		/* remember this pkt as valid pkt */
		p_nat->valid_packets |= pkt_mask;

		struct rte_mbuf *pkt = pkts[i];

		if (enable_hwlb)
			if (!check_arp_icmp(pkt, pkt_mask, p_nat))
				continue;

		int ver = rte_get_pkt_ver(pkt);

		#ifdef CGNAPT_DBG_PRNT
		printf("ver no. of the pkt:%d\n", ver);
		#endif

		if (unlikely(ver < 0)) {
			/* Not a valid pkt , ignore. */
			/* remember invalid packets to be dropped */
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;

		#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount1++;
		#endif
			continue;
		}
		if (ver == 4)
			prot_offset = PROT_OFST_IP4;
		else
			prot_offset = PROT_OFST_IP6;
		protocol =
			(uint8_t *) RTE_MBUF_METADATA_UINT32_PTR(pkt,
					prot_offset);
		if (!
			(*protocol == IP_PROTOCOL_TCP
			 || *protocol == IP_PROTOCOL_UDP
			 || *protocol == IP_PROTOCOL_ICMP)) {
		/* remember invalid packets to be dropped */
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;

		#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount2++;
		#endif
			continue;
		}

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG > 4)
			print_pkt(pkt);
		#endif

		#ifdef PCP_ENABLE
		/* Handling PCP
		* 1. Handel PCP for egress traffic
		* 2. If PCP, then give response (send pkt) from the same port
		* 3. Drop the PCP packet, should not be added in the NAPT table
		*/
		if (pcp_enable) {
		if (*protocol == IP_PROTOCOL_UDP) {
			struct udp_hdr *udp;
			if (ver == 4)
				udp = (struct udp_hdr *)
					RTE_MBUF_METADATA_UINT8_PTR(pkt,
						IPV4_UDP_OFST);
			else
				udp = (struct udp_hdr *)
					RTE_MBUF_METADATA_UINT8_PTR(pkt,
						IPV6_UDP_OFST);

			if (rte_bswap16(udp->dst_port) ==
				PCP_SERVER_PORT) {
				handle_pcp_req(pkt, ver, p_nat);
				p_nat->invalid_packets |= pkt_mask;
				continue;
			}
		}
		}
		#endif

		if (ver == 4) {

			src_addr =
				RTE_MBUF_METADATA_UINT32_PTR(pkt,
					SRC_ADR_OFST_IP4);
			dst_addr =
				RTE_MBUF_METADATA_UINT32_PTR(pkt,
					DST_ADR_OFST_IP4);

			if ((*protocol == IP_PROTOCOL_TCP)
				|| (*protocol == IP_PROTOCOL_UDP)) {

				src_port_offset = SRC_PRT_OFST_IP4_TCP;
				dst_port_offset = DST_PRT_OFST_IP4_TCP;

			} else if (*protocol == IP_PROTOCOL_ICMP) {
				/* Identifier */
				src_port_offset = IDEN_OFST_IP4_ICMP;
				/* Sequence number */
				dst_port_offset = SEQN_OFST_IP4_ICMP;
			}

			src_port =
				RTE_MBUF_METADATA_UINT16_PTR(pkt,
					src_port_offset);
			dst_port =
				RTE_MBUF_METADATA_UINT16_PTR(pkt,
					dst_port_offset);
		} else {

			src_addr =
				RTE_MBUF_METADATA_UINT32_PTR(pkt,
					SRC_ADR_OFST_IP6);
			dst_addr =
				RTE_MBUF_METADATA_UINT32_PTR(pkt,
					DST_ADR_OFST_IP6);
			src_port =
				RTE_MBUF_METADATA_UINT16_PTR(pkt,
					SRC_PRT_OFST_IP6);
			dst_port =
				RTE_MBUF_METADATA_UINT16_PTR(pkt,
					DST_PRT_OFST_IP6);
		}
		/* need to create compacted table of pointers to
		* pass to bulk lookup
		*/

		compacting_map[packets_for_lookup] = i;

		//phy_port = RTE_MBUF_METADATA_UINT16_PTR(pkt, phyport_offset);
		phy_port = pkt->port;

		struct pipeline_cgnapt_entry_key key;

		memset(&key, 0, sizeof(struct pipeline_cgnapt_entry_key));

		key.pid = phy_port;
		if (get_in_port_dir(phy_port)) {
			/* Egress */
			if (ver == 4)
				key.ip = rte_bswap32(*src_addr);
			else
				key.ip = rte_bswap32(src_addr[3]);
			key.port = rte_bswap16(*src_port);

		#ifdef NAT_ONLY_CONFIG_REQ
			if (nat_only_config_flag)
				key.port = 0xffff;
		#endif
		} else {
			/* Ingress */
			key.ip = rte_bswap32(*dst_addr);

			if (*protocol == IP_PROTOCOL_ICMP) {
			/* common table lookupkey preparation from
			* incoming ICMP Packet- Indentifier field
			*/
				key.port = rte_bswap16(*src_port);
			} else {
				key.port = rte_bswap16(*dst_port);
			}

		#ifdef NAT_ONLY_CONFIG_REQ
			if (nat_only_config_flag)
				key.port = 0xffff;
		#endif

			key.pid = 0xffff;
		}

		memcpy(&(p_nat->keys[packets_for_lookup]), &key,
				 sizeof(struct pipeline_cgnapt_entry_key));
		p_nat->key_ptrs[packets_for_lookup] =
			&(p_nat->keys[packets_for_lookup]);
		packets_for_lookup++;
	}

	if (unlikely(packets_for_lookup == 0)) {
		/* no suitable packet for lookup */
		rte_pipeline_ah_packet_drop(rte_p, p_nat->valid_packets);
		return p_nat->valid_packets;
	}

	/* lookup entries in the common napt table */

	int lookup_result = rte_hash_lookup_bulk(napt_common_table,
						 (const void **)
						 &p_nat->key_ptrs,
						 packets_for_lookup,
						 &p_nat->lkup_indx[0]);

	if (unlikely(lookup_result < 0)) {
		/* unknown error, just discard all packets */
		printf("Unexpected hash lookup error %d, discarding all "
			"packets", lookup_result);
		rte_pipeline_ah_packet_drop(rte_p, p_nat->valid_packets);
		return 0;
	}
	//struct rte_pipeline_table_entry *entries[64];
	/* Now one by one check the result of our bulk lookup */

	for (i = 0; i < packets_for_lookup; i++) {
		/* index into hash table entries */
		int hash_table_entry = p_nat->lkup_indx[i];
		/* index into packet table of this packet */
		uint8_t pkt_index = compacting_map[i];
		/*bitmask representing only this packet */
		uint64_t pkt_mask = 1LLU << pkt_index;

		struct cgnapt_table_entry *entry = NULL;
		if (hash_table_entry < 0) {

			/* try to add new entry */
			struct rte_pipeline_table_entry *table_entry = NULL;

			uint64_t dropmask =
				pkt_miss_cgnapt(p_nat->key_ptrs[i],
						pkts[pkt_index],
						&table_entry,
						&p_nat->valid_packets,
						pkt_index,
						(void *)p_nat);

			if (!table_entry) {
		/* ICMP Error message generation for
		* Destination Host unreachable
		*/
				if (*protocol == IP_PROTOCOL_ICMP) {
					cgnapt_icmp_pkt = pkts[pkt_index];
					send_icmp_dest_unreachable_msg();
				}

				/* Drop packet by adding to invalid pkt mask */

				p_nat->invalid_packets |= dropmask;
				#ifdef CGNAPT_DEBUGGING
				if (p_nat->kpc2++ < 5) {
					printf("in_ah Th: %d",
							 p_nat->pipeline_num);
					print_key(p_nat->key_ptrs[i]);
				}
				#endif

				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount3++;
				#endif
				continue;
			}

			entry = (struct cgnapt_table_entry *)table_entry;
		} else {
			/* entry found for this packet */
			entry = &napt_hash_tbl_entries[hash_table_entry];
		}

		/*  apply napt and mac changes */

		p_nat->entries[pkt_index] = &(entry->head);

		phy_port = pkts[pkt_index]->port;

		struct ipv6_hdr ipv6_hdr;
		struct ipv4_hdr ipv4_hdr;

		ver = rte_get_pkt_ver(pkts[pkt_index]);
		#ifdef CGNAPT_DEBUGGING
		if (CGNAPT_DEBUG >= 1) {
			printf("ver:%d\n", ver);
			printf("entry->data.type:%d\n", entry->data.type);
		}
		#endif
		if ((ver == 6) && (entry->data.type == CGNAPT_ENTRY_IPV6)
			&& is_phy_port_privte(phy_port)) {
			convert_ipv6_to_ipv4(pkts[pkt_index], &ipv6_hdr);

			pkt_type = PKT_TYPE_IPV6to4;

			#ifdef CGNAPT_DBG_PRNT
			if (CGNAPT_DEBUG >= 1)
				printf("pkt_work_cganpt: "
				"convert_ipv6_to_ipv4\n");
			#endif

			struct cgnapt_nsp_node *ll = nsp_ll;
			int nsp = 0;
			while (ll != NULL) {
				if (!memcmp(&ipv6_hdr.dst_addr[0],
					&ll->nsp.prefix[0],
					 ll->nsp.depth / 8)) {
					nsp = 1;
					break;
				}
				ll = ll->next;
			}

			if (!nsp
				&& !memcmp(&ipv6_hdr.dst_addr[0],
						 &well_known_prefix[0], 12)) {
				nsp = 1;
			}

			if (!nsp) {
				p_nat->invalid_packets |= 1LLU << pkt_index;
				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount5++;
				#endif
				continue;
			}

		}

		/* As packet is already converted into IPv4 we must not operate
		* IPv6 offsets on packet
		* Only perform IPv4 operations
		*/

		if (ver == 6) {

			src_port_offset = SRC_PRT_OFST_IP6t4;
			dst_port_offset = DST_PRT_OFST_IP6t4;
			src_addr_offset = SRC_ADR_OFST_IP6t4;
			dst_addr_offset = DST_ADR_OFST_IP6t4;
			prot_offset = PROT_OFST_IP6t4;
			eth_offset = ETH_OFST_IP6t4;

		} else {

			if ((*protocol == IP_PROTOCOL_TCP)
				|| (*protocol == IP_PROTOCOL_UDP)) {
				src_port_offset = SRC_PRT_OFST_IP4_TCP;
				dst_port_offset = DST_PRT_OFST_IP4_TCP;
			} else if (*protocol == IP_PROTOCOL_ICMP) {
				/* Identifier */
				src_port_offset = IDEN_OFST_IP4_ICMP;
				/* Sequence number */
				dst_port_offset = SEQN_OFST_IP4_ICMP;
			}

			src_addr_offset = SRC_ADR_OFST_IP4;
			dst_addr_offset = DST_ADR_OFST_IP4;
			prot_offset = PROT_OFST_IP4;
			eth_offset = MBUF_HDR_ROOM;

		}

		src_addr =
			RTE_MBUF_METADATA_UINT32_PTR(pkts[pkt_index],
						 src_addr_offset);
		dst_addr =
			RTE_MBUF_METADATA_UINT32_PTR(pkts[pkt_index],
						 dst_addr_offset);
		src_port =
			RTE_MBUF_METADATA_UINT16_PTR(pkts[pkt_index],
						 src_port_offset);
		dst_port =
			RTE_MBUF_METADATA_UINT16_PTR(pkts[pkt_index],
						 dst_port_offset);
		protocol =
			RTE_MBUF_METADATA_UINT8_PTR(pkts[pkt_index],
				prot_offset);

		eth_dest =
			RTE_MBUF_METADATA_UINT8_PTR(pkts[pkt_index],
				eth_offset);
		eth_src =
			RTE_MBUF_METADATA_UINT8_PTR(pkts[pkt_index],
						eth_offset + 6);

		if (entry->data.ttl == NAPT_ENTRY_STALE)
			entry->data.ttl = NAPT_ENTRY_VALID;

		struct ether_addr hw_addr;
		uint32_t dest_address = 0;
		uint8_t nh_ipv6[16];
		uint32_t nhip = 0;

		uint32_t dest_if = 0xff;
		uint32_t ret;

		uint16_t *outport_id =
			RTE_MBUF_METADATA_UINT16_PTR(pkts[pkt_index],
						 cgnapt_meta_offset);

		if (is_phy_port_privte(phy_port)) {

			if (*protocol == IP_PROTOCOL_UDP
			&& rte_be_to_cpu_16(*dst_port) == 53) {
			p_nat->invalid_packets |= 1LLU << pkt_index;
			p_nat->naptDroppedPktCount++;
			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount6++;
			#endif
			continue;
			}

			dest_address = rte_bswap32(*dst_addr);
			ret = local_get_nh_ipv4(dest_address, &dest_if,
					&nhip, p_nat);
			if (!ret) {
				dest_if = get_prv_to_pub_port(&dest_address,
						IP_VERSION_4);
				if (dest_if == INVALID_DESTIF) {
					p_nat->invalid_packets |=
						1LLU << pkt_index;
					p_nat->naptDroppedPktCount++;
					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount6++;
					#endif
					continue;
				}
				do_local_nh_ipv4_cache(dest_if, p_nat);
			}

			*outport_id = p_nat->outport_id[dest_if];
			struct arp_entry_data *ret_arp_data;
			ret_arp_data = get_dest_mac_addr_port(dest_address,
				&dest_if, (struct ether_addr *)eth_dest);

			if (unlikely(ret_arp_data == NULL)) {

				printf("%s: NHIP Not Found, nhip: %x, "
				"outport_id: %d\n", __func__, nhip,
				*outport_id);

				/* Drop the pkt */
				p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount4++;
				#endif
				continue;
			}

			if (ret_arp_data->status == COMPLETE) {
				
				if (ret_arp_data->num_pkts) {
					p_nat->naptedPktCount += ret_arp_data->num_pkts;
					arp_send_buffered_pkts(ret_arp_data,
						 &hw_addr, *outport_id);
				}

				memcpy(eth_dest, &hw_addr,
					sizeof(struct ether_addr));
				memcpy(eth_src, get_link_hw_addr(dest_if),
					sizeof(struct ether_addr));
				#ifdef CGNAPT_DBG_PRNT
				if (CGNAPT_DEBUG > 2) {
				printf("MAC found for ip 0x%x, port %d - "
					"%02x:%02x:%02x:%02x:%02x:%02x\n",
					dest_address, *outport_id,
				hw_addr.addr_bytes[0], hw_addr.addr_bytes[1],
				hw_addr.addr_bytes[2], hw_addr.addr_bytes[3],
				hw_addr.addr_bytes[4], hw_addr.addr_bytes[5]);

				printf("Dest MAC before - "
					"%02x:%02x:%02x:%02x:%02x:%02x\n",
					 eth_dest[0], eth_dest[1], eth_dest[2],
					 eth_dest[3], eth_dest[4], eth_dest[5]);
				}
				#endif

				#ifdef CGNAPT_DBG_PRNT
				if (CGNAPT_DEBUG > 2) {
				printf("Dest MAC after - "
				"%02x:%02x:%02x:%02x:%02x:%02x\n",
				eth_dest[0], eth_dest[1], eth_dest[2],
				eth_dest[3], eth_dest[4], eth_dest[5]);
				}
				#endif

				#ifdef CGNAPT_DBG_PRNT
				if (CGNAPT_DEBUG > 4)
					print_pkt(pkts[pkt_index]);
				#endif

			} else if (ret_arp_data->status == INCOMPLETE ||
				ret_arp_data->status == PROBE) {
				if (ret_arp_data->num_pkts >= NUM_DESC) {
					/* Drop the pkt */
					p_nat->invalid_packets |= pkt_mask;
					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					continue;
				} else {
					arp_queue_unresolved_packet(ret_arp_data,
						pkts[pkt_index]);
					continue;
				}
			}

			#ifdef CGNAPT_DBG_PRNT
			if (CGNAPT_DEBUG > 2)
				printf("Egress: \tphy_port:%d\t "
				"get_prv_to_pub():%d \tout_port:%d\n",
				phy_port, dest_if,
				*outport_id);
			#endif

			/* Egress */
			*src_addr = rte_bswap32(entry->data.pub_ip);

			#ifdef NAT_ONLY_CONFIG_REQ
			if (!nat_only_config_flag) {
			#endif
				*src_port = rte_bswap16(entry->data.pub_port);
			#ifdef NAT_ONLY_CONFIG_REQ
			}
			#endif

			p_nat->enaptedPktCount++;
		} else {
			/* Ingress */
			if (*protocol == IP_PROTOCOL_UDP
				&& rte_be_to_cpu_16(*src_port) == 53) {
				p_nat->invalid_packets |= 1LLU << pkt_index;
				p_nat->naptDroppedPktCount++;
				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount6++;
				#endif
				continue;
			}

			#ifdef CGNAPT_DBG_PRNT
			if (CGNAPT_DEBUG > 2)
				printf("Ingress: \tphy_port:%d\t "
				"get_pub_to_prv():%d \tout_port%d\n",
				 phy_port, dest_if,
				 *outport_id);
			#endif

			if (entry->data.type == CGNAPT_ENTRY_IPV6) {
				convert_ipv4_to_ipv6(pkts[pkt_index],
							 &ipv4_hdr);
				pkt_type = PKT_TYPE_IPV4to6;
				/* Ethernet MTU check */
			if ((rte_pktmbuf_data_len(pkts[pkt_index]) -
					 14) > 1500) {
				p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;
				continue;
			}

			eth_dest = eth_dest - 20;
			eth_src = eth_src - 20;

			dst_port_offset = DST_PRT_OFST_IP4t6;
			dst_addr_offset = DST_ADR_OFST_IP4t6;
			dst_addr =
				RTE_MBUF_METADATA_UINT32_PTR(
					pkts[pkt_index],
					dst_addr_offset);
			dst_port =
				RTE_MBUF_METADATA_UINT16_PTR(
					pkts[pkt_index],
					dst_port_offset);

			memcpy((uint8_t *) &dst_addr[0],
					 &entry->data.u.prv_ipv6[0], 16);
			memset(nh_ipv6, 0, 16);
#if 0
			ret = local_get_nh_ipv6((uint8_t *)&dst_addr[0],
				&dest_if, &nh_ipv6[0], p_nat);

			if (!ret) {
				dest_if = get_prv_to_pub_port(
						&dst_addr[0],
						IP_VERSION_6);
				if (dest_if == INVALID_DESTIF) {
					p_nat->invalid_packets |=
						1LLU << pkt_index;
					p_nat->naptDroppedPktCount++;
					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount6++;
					#endif
					continue;
				}
				do_local_nh_ipv6_cache(dest_if, p_nat);
			}
			*outport_id = p_nat->outport_id[dest_if];
#endif
			struct nd_entry_data *ret_nd_data = NULL;
			ret_nd_data = get_dest_mac_address_ipv6_port((uint8_t *)
                                &dst_addr[0], &dest_if,
                                &hw_addr, &nh_ipv6[0]);
			*outport_id = p_nat->outport_id[dest_if];

			if (nd_cache_dest_mac_present(dest_if)) {
				ether_addr_copy(get_link_hw_addr(dest_if),
					(struct ether_addr *)eth_src);
				nd_data_ptr[dest_if]->n_last_update = time(NULL);

				if (unlikely(ret_nd_data && ret_nd_data->num_pkts)) {
					printf("sending buffered packets\n");
					p_nat->naptedPktCount += ret_nd_data->num_pkts;
					nd_send_buffered_pkts(ret_nd_data,
						 (struct ether_addr *)eth_dest, *outport_id);
				}
			} else {
				if (unlikely(ret_nd_data == NULL)) {

					printf("%s: NHIP Not Found, "
					"outport_id: %d\n", __func__,
					*outport_id);

					/* Drop the pkt */
					p_nat->invalid_packets |= pkt_mask;
					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					continue;
				}

				if (ret_nd_data->status == INCOMPLETE ||
					ret_nd_data->status == PROBE) {
					if (ret_nd_data->num_pkts >= NUM_DESC) {
						/* Drop the pkt */
						p_nat->invalid_packets |= pkt_mask;
						p_nat->naptDroppedPktCount++;

						#ifdef CGNAPT_DEBUGGING
						p_nat->naptDroppedPktCount4++;
						#endif
						continue;
					} else {
						arp_pkts_mask |= pkt_mask;
						nd_queue_unresolved_packet(ret_nd_data, pkts[pkt_index]);
						continue;
					}
				}

			}

			#ifdef NAT_ONLY_CONFIG_REQ
				if (!nat_only_config_flag) {
			#endif
				*dst_port =
					rte_bswap16(entry->data.prv_port);
			#ifdef NAT_ONLY_CONFIG_REQ
				}
			#endif

			} else {
				*dst_addr = rte_bswap32(entry->data.u.prv_ip);
				dest_address = entry->data.u.prv_ip;
				ret = local_get_nh_ipv4(dest_address, &dest_if,
					&nhip, p_nat);
				if (!ret) {
					dest_if = get_pub_to_prv_port(
						&dest_address, IP_VERSION_4);
				if (dest_if == INVALID_DESTIF) {
					p_nat->invalid_packets |=
						1LLU << pkt_index;
					p_nat->naptDroppedPktCount++;
					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount6++;
					#endif
					continue;
				}
					do_local_nh_ipv4_cache(dest_if, p_nat);
				};

				*outport_id = p_nat->outport_id[dest_if];
				struct arp_entry_data *ret_arp_data;
				ret_arp_data = get_dest_mac_addr_port(dest_address,
					&dest_if, (struct ether_addr *)eth_dest);

				if (unlikely(ret_arp_data == NULL)) {

					printf("%s: NHIP Not Found, nhip: %x, "
					"outport_id: %d\n", __func__, nhip,
					*outport_id);

					/* Drop the pkt */
					p_nat->invalid_packets |= pkt_mask;
					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					continue;
				}

				if (ret_arp_data->status == COMPLETE) {

					if (ret_arp_data->num_pkts) {
						p_nat->naptedPktCount +=
							 ret_arp_data->num_pkts;
						arp_send_buffered_pkts(ret_arp_data,
							 &hw_addr, *outport_id);
					}

					memcpy(eth_dest, &hw_addr,
						sizeof(struct ether_addr));
					memcpy(eth_src, get_link_hw_addr(
						dest_if),
						sizeof(struct ether_addr));
					#ifdef CGNAPT_DBG_PRNT
					if (CGNAPT_DEBUG > 2) {
					printf("MAC found for ip 0x%x, port %d - "
					"%02x:%02x:%02x:%02x:%02x:%02x\n",
					dest_address, *outport_id,
				 	hw_addr.addr_bytes[0], hw_addr.addr_bytes[1],
				 	hw_addr.addr_bytes[2], hw_addr.addr_bytes[3],
				 	hw_addr.addr_bytes[4], hw_addr.addr_bytes[5]);

					printf("Dest MAC before - "
					"%02x:%02x:%02x:%02x:%02x:%02x\n",
					 eth_dest[0], eth_dest[1], eth_dest[2],
					 eth_dest[3], eth_dest[4], eth_dest[5]);
					}
					#endif

					#ifdef CGNAPT_DBG_PRNT
					if (CGNAPT_DEBUG > 2) {
					printf("Dest MAC after - "
					"%02x:%02x:%02x:%02x:%02x:%02x\n",
					 eth_dest[0], eth_dest[1], eth_dest[2],
					 eth_dest[3], eth_dest[4], eth_dest[5]);
					}
					#endif

					#ifdef CGNAPT_DBG_PRNT
					if (CGNAPT_DEBUG > 4)
						print_pkt(pkts[pkt_index]);
					#endif

				} else if (ret_arp_data->status == INCOMPLETE ||
					ret_arp_data->status == PROBE) {
					arp_queue_unresolved_packet(ret_arp_data,
						pkts[pkt_index]);
					continue;
				}

			if (*protocol == IP_PROTOCOL_ICMP) {
				// Query ID reverse translation done here
				*src_port =
					rte_bswap16(entry->data.prv_port);
				} else {
					#ifdef NAT_ONLY_CONFIG_REQ
					if (!nat_only_config_flag) {
					#endif
						*dst_port =
							rte_bswap16(entry->
								data.prv_port);
					#ifdef NAT_ONLY_CONFIG_REQ
					}
					#endif
				}
			}

			p_nat->inaptedPktCount++;
		}

		p_nat->naptedPktCount++;

		#ifdef CHECKSUM_REQ
			if (p_nat->hw_checksum_reqd)
				hw_checksum(pkts[pkt_index], pkt_type);
			else
				sw_checksum(pkts[pkt_index], pkt_type);
		#endif
	}

	if (p_nat->invalid_packets) {
		/* get rid of invalid packets */
		rte_pipeline_ah_packet_drop(rte_p, p_nat->invalid_packets);

		p_nat->valid_packets &= ~(p_nat->invalid_packets);

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG > 1) {
			printf("valid_packets:0x%jx\n", p_nat->valid_packets);
			printf("rte_valid_packets :0x%jx\n", rte_p->pkts_mask);
			printf("invalid_packets:0x%jx\n",
					 p_nat->invalid_packets);
			printf("rte_invalid_packets :0x%jx\n",
					 rte_p->pkts_drop_mask);
			printf("Total pkts dropped :0x%jx\n",
					 rte_p->n_pkts_ah_drop);
		}
		#endif
	}

	return p_nat->valid_packets;
}

/**
 * Input port handler for IPv4 private traffic
 * Starting from the packet burst it filters unwanted packets,
 * calculates keys, does lookup and then based on the lookup
 * updates NAPT table and does packet NAPT translation.
 *
 * @param rte_p
 *  A pointer to struct rte_pipeline
 * @param pkts
 *  A pointer to array of packets mbuf
 * @param n_pkts
 *  Number of packets in the burst
 * @param arg
 *  Void pointer
 *
 * @return
 *  int that is not checked by caller
 */

static int cgnapt_in_port_ah_ipv4_prv(struct rte_pipeline *rte_p,
						struct rte_mbuf **pkts,
						uint32_t n_pkts, void *arg)
{
	uint32_t i, j;
	struct pipeline_cgnapt_in_port_h_arg *ap = arg;
	struct pipeline_cgnapt *p_nat = ap->p;

	#ifdef CGNAPT_TIMING_INST
	uint64_t entry_timestamp = 0, exit_timestamp;

	if (p_nat->time_measurements_on) {
		entry_timestamp = rte_get_tsc_cycles();
	/* check since exit ts not valid first time through */
		if (likely(p_nat->in_port_exit_timestamp))
			p_nat->external_time_sum +=
				entry_timestamp - p_nat->in_port_exit_timestamp;
	}
	#endif

	p_nat->pkt_burst_cnt = 0;	/* for dynamic napt */
	p_nat->valid_packets = rte_p->pkts_mask;	/*n_pkts; */
	p_nat->invalid_packets = 0;
	arp_pkts_mask = 0;
	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 1)
		printf("cgnapt_key hit fn: %" PRIu32 "\n", n_pkts);
	#endif

	/* prefetching for mbufs should be done here */
	for (j = 0; j < n_pkts; j++)
		rte_prefetch0(pkts[j]);

	for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)
		pkt4_work_cgnapt_key_ipv4_prv(&pkts[i], i, arg, p_nat);

	for (; i < n_pkts; i++)
		pkt_work_cgnapt_key_ipv4_prv(pkts[i], i, arg, p_nat);

	p_nat->valid_packets &= ~(p_nat->invalid_packets);

	if (unlikely(p_nat->valid_packets == 0)) {
		/* no suitable packet for lookup */
		printf("no suitable valid packets\n");
		rte_pipeline_ah_packet_drop(rte_p, p_nat->invalid_packets);
		return p_nat->valid_packets;
	}

	/* lookup entries in the common napt table */

	int lookup_result = rte_hash_lookup_bulk(
				napt_common_table,
				(const void **)&p_nat->key_ptrs,
				/* should be minus num invalid pkts */
				n_pkts,
				/*new pipeline data member */
				&p_nat->lkup_indx[0]);

	if (unlikely(lookup_result < 0)) {
		/* unknown error, just discard all packets */
		printf("Unexpected hash lookup error %d, discarding "
			"all packets", lookup_result);
		rte_pipeline_ah_packet_drop(rte_p, p_nat->valid_packets);
		return 0;
	}

	/* Now call second stage of pipeline to one by one
	* check the result of our bulk lookup
	*/

	/* prefetching for table entries should be done here */
	for (j = 0; j < n_pkts; j++) {
		if (p_nat->lkup_indx[j] >= 0)
			rte_prefetch0(&napt_hash_tbl_entries
						[p_nat->lkup_indx[j]]);
	}

	//prefetch();


	for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)
		pkt4_work_cgnapt_ipv4_prv(pkts, i, arg, p_nat);

	for (; i < n_pkts; i++)
		pkt_work_cgnapt_ipv4_prv(pkts, i, arg, p_nat);

	if (arp_pkts_mask) {
		p_nat->valid_packets &= ~(arp_pkts_mask);
		rte_pipeline_ah_packet_hijack(rte_p, arp_pkts_mask);
	}

	if (p_nat->invalid_packets) {
		/* get rid of invalid packets */
		rte_pipeline_ah_packet_drop(rte_p, p_nat->invalid_packets);

		p_nat->valid_packets &= ~(p_nat->invalid_packets);

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 1) {
		printf("valid_packets:0x%jx\n", p_nat->valid_packets);
		printf("rte_valid_packets :0x%jx\n", rte_p->pkts_mask);
		printf("invalid_packets:0x%jx\n",
				 p_nat->invalid_packets);
		printf("rte_invalid_packets :0x%jx\n",
				 rte_p->pkts_drop_mask);
		printf("Total pkts dropped :0x%jx\n",
				 rte_p->n_pkts_ah_drop);
	}
	#endif
	}

	#ifdef CGNAPT_TIMING_INST
	if (p_nat->time_measurements_on) {
		exit_timestamp = rte_get_tsc_cycles();
		p_nat->in_port_exit_timestamp = exit_timestamp;
		p_nat->internal_time_sum += exit_timestamp - entry_timestamp;
		p_nat->time_measurements++;
		if (p_nat->time_measurements == p_nat->max_time_mesurements)
			p_nat->time_measurements_on = 0;
	}
	#endif

	return p_nat->valid_packets;
}

/**
 * Input port handler for IPv4 public traffic
 * Starting from the packet burst it filters unwanted packets,
 * calculates keys, does lookup and then based on the lookup
 * updates NAPT table and does packet NAPT translation.
 *
 * @param rte_p
 *  A pointer to struct rte_pipeline
 * @param pkts
 *  A pointer to array of packets mbuf
 * @param n_pkts
 *  Number of packets in the burst
 * @param arg
 *  Void pointer
 *
 * @return
 *  int that is not checked by caller
 */
static int cgnapt_in_port_ah_ipv4_pub(struct rte_pipeline *rte_p,
						struct rte_mbuf **pkts,
						uint32_t n_pkts, void *arg)
{
	uint32_t i, j;
	struct pipeline_cgnapt_in_port_h_arg *ap = arg;
	struct pipeline_cgnapt *p_nat = ap->p;

	#ifdef CGNAPT_TIMING_INST
	uint64_t entry_timestamp = 0, exit_timestamp;

	if (p_nat->time_measurements_on) {
		entry_timestamp = rte_get_tsc_cycles();

		/* check since exit ts not valid first time through */
		if (likely(p_nat->in_port_exit_timestamp))
			p_nat->external_time_sum +=
				entry_timestamp - p_nat->in_port_exit_timestamp;
	}
	#endif

	p_nat->pkt_burst_cnt = 0;	/* for dynamic napt */
	p_nat->valid_packets = rte_p->pkts_mask;	/*n_pkts; */
	p_nat->invalid_packets = 0;
	arp_pkts_mask = 0;
	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 1)
		printf("cgnapt_key hit fn: %" PRIu32 "\n", n_pkts);
	#endif

	/* prefetching for mbufs should be done here */
	for (j = 0; j < n_pkts; j++)
		rte_prefetch0(pkts[j]);

	for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)
		pkt4_work_cgnapt_key_ipv4_pub(&pkts[i], i, arg, p_nat);

	for (; i < n_pkts; i++)
		pkt_work_cgnapt_key_ipv4_pub(pkts[i], i, arg, p_nat);

	p_nat->valid_packets &= ~(p_nat->invalid_packets);

	if (unlikely(p_nat->valid_packets == 0)) {
		printf("no valid packets in pub\n");
		/* no suitable packet for lookup */
		rte_pipeline_ah_packet_drop(rte_p, p_nat->invalid_packets);
		return p_nat->valid_packets;
	}

	/* lookup entries in the common napt table */

	int lookup_result = rte_hash_lookup_bulk(
				napt_common_table,
				(const void **)&p_nat->key_ptrs,
				/* should be minus num invalid pkts */
				n_pkts,
				/*new pipeline data member */
				&p_nat->lkup_indx[0]);

	if (unlikely(lookup_result < 0)) {
		/* unknown error, just discard all packets */
		printf("Unexpected hash lookup error %d, discarding "
			"all packets", lookup_result);
		rte_pipeline_ah_packet_drop(rte_p, p_nat->valid_packets);
		return 0;
	}

	/* Now call second stage of pipeline to one by one
	* check the result of our bulk lookup
	*/

	/* prefetching for table entries should be done here */
	for (j = 0; j < n_pkts; j++) {
		if (p_nat->lkup_indx[j] >= 0)
			rte_prefetch0(&napt_hash_tbl_entries
						[p_nat->lkup_indx[j]]);
	}

	for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)
		pkt4_work_cgnapt_ipv4_pub(pkts, i, arg, p_nat);

	for (; i < n_pkts; i++)
		pkt_work_cgnapt_ipv4_pub(pkts, i, arg, p_nat);

	if (arp_pkts_mask) {
		rte_pipeline_ah_packet_hijack(rte_p, arp_pkts_mask);
		p_nat->valid_packets &= ~(arp_pkts_mask);
	}

	if (p_nat->invalid_packets) {
		/* get rid of invalid packets */
		rte_pipeline_ah_packet_drop(rte_p, p_nat->invalid_packets);

		p_nat->valid_packets &= ~(p_nat->invalid_packets);

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 1) {
		printf("valid_packets:0x%jx\n", p_nat->valid_packets);
		printf("rte_valid_packets :0x%jx\n", rte_p->pkts_mask);
		printf("invalid_packets:0x%jx\n",
				 p_nat->invalid_packets);
		printf("rte_invalid_packets :0x%jx\n",
				 rte_p->pkts_drop_mask);
		printf("Total pkts dropped :0x%jx\n",
				 rte_p->n_pkts_ah_drop);
		}
	#endif
	}

	#ifdef CGNAPT_TIMING_INST
	if (p_nat->time_measurements_on) {
		exit_timestamp = rte_get_tsc_cycles();
		p_nat->in_port_exit_timestamp = exit_timestamp;

		p_nat->internal_time_sum += exit_timestamp - entry_timestamp;
		p_nat->time_measurements++;
		if (p_nat->time_measurements == p_nat->max_time_mesurements)
			p_nat->time_measurements_on = 0;
	}
	#endif

	return p_nat->valid_packets;
}

/**
 * NAPT key calculation function for IPv4 private traffic
 * which handles 4 pkts
 *
 * @param pkt
 *  A pointer to array of packets mbuf
 * @param in_pkt_num
 *  Starting pkt number of pkts
 * @param arg
 *  Void pointer
 * @param p_nat
 *  A pointer to main CGNAPT structure
 *
 */
void
pkt4_work_cgnapt_key_ipv4_prv(
	struct rte_mbuf **pkt,
	uint32_t pkt_num,
	__rte_unused void *arg,
	struct pipeline_cgnapt *p_nat)
{
	p_nat->receivedPktCount += 4;
	/* bitmask representing only this packet */
	uint64_t pkt_mask0 = 1LLU << pkt_num;
	uint64_t pkt_mask1 = 1LLU << (pkt_num + 1);
	uint64_t pkt_mask2 = 1LLU << (pkt_num + 2);
	uint64_t pkt_mask3 = 1LLU << (pkt_num + 3);

	uint8_t protocol0 = RTE_MBUF_METADATA_UINT8(pkt[0],
				PROT_OFST_IP4);
	uint8_t protocol1 = RTE_MBUF_METADATA_UINT8(pkt[1],
				PROT_OFST_IP4);
	uint8_t protocol2 = RTE_MBUF_METADATA_UINT8(pkt[2],
				PROT_OFST_IP4);
	uint8_t protocol3 = RTE_MBUF_METADATA_UINT8(pkt[3],
				PROT_OFST_IP4);

	uint32_t src_addr0 = RTE_MBUF_METADATA_UINT32(pkt[0],
				SRC_ADR_OFST_IP4);
	uint32_t src_addr1 = RTE_MBUF_METADATA_UINT32(pkt[1],
				SRC_ADR_OFST_IP4);
	uint32_t src_addr2 = RTE_MBUF_METADATA_UINT32(pkt[2],
				SRC_ADR_OFST_IP4);
	uint32_t src_addr3 = RTE_MBUF_METADATA_UINT32(pkt[3],
				SRC_ADR_OFST_IP4);

	uint16_t src_port_offset0;
	uint16_t src_port_offset1;
	uint16_t src_port_offset2;
	uint16_t src_port_offset3;

	uint16_t src_port0;
	uint16_t src_port1;
	uint16_t src_port2;
	uint16_t src_port3;

	uint16_t phy_port0 = pkt[0]->port;
	uint16_t phy_port1 = pkt[1]->port;
	uint16_t phy_port2 = pkt[2]->port;
	uint16_t phy_port3 = pkt[3]->port;

	struct pipeline_cgnapt_entry_key key0;
	struct pipeline_cgnapt_entry_key key1;
	struct pipeline_cgnapt_entry_key key2;
	struct pipeline_cgnapt_entry_key key3;

	memset(&key0, 0, sizeof(struct pipeline_cgnapt_entry_key));
	memset(&key1, 0, sizeof(struct pipeline_cgnapt_entry_key));
	memset(&key2, 0, sizeof(struct pipeline_cgnapt_entry_key));
	memset(&key3, 0, sizeof(struct pipeline_cgnapt_entry_key));

/* --0-- */
	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt[0]);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt[0], pkt_mask0, p_nat))
			goto PKT1;
	}

	switch (protocol0) {
	case IP_PROTOCOL_UDP:
	{
		#ifdef PCP_ENABLE
		if (pcp_enable) {
		struct udp_hdr *udp;

		udp = (struct udp_hdr *)
			RTE_MBUF_METADATA_UINT8_PTR(pkt[0],
						IPV4_UDP_OFST);

		if (rte_bswap16(udp->dst_port) ==
			PCP_SERVER_PORT) {
			handle_pcp_req(pkt[0], IPV4_SZ, p_nat);
			p_nat->invalid_packets |= pkt_mask0;
			goto PKT1;
		}
		}
		#endif
	}
	case IP_PROTOCOL_TCP:

		src_port_offset0 = SRC_PRT_OFST_IP4_TCP;
		src_port0 = RTE_MBUF_METADATA_UINT16(pkt[0],
				src_port_offset0);

	break;

	case IP_PROTOCOL_ICMP:
		 /* Identifier */
		 src_port_offset0 = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					 IP_HDR_SIZE + 4;
		 src_port0 = RTE_MBUF_METADATA_UINT16(pkt[0],
				src_port_offset0);

	break;

	default:
		 /* remember invalid packets to be dropped */
		 p_nat->invalid_packets |= pkt_mask0;
		 p_nat->naptDroppedPktCount++;

		 #ifdef CGNAPT_DEBUGGING
		 p_nat->naptDroppedPktCount2++;
		 #endif
		goto PKT1;
	}

	key0.pid = phy_port0;
	key0.ip = rte_bswap32(src_addr0);
	key0.port = rte_bswap16(src_port0);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key0.port = 0xffff;
	#endif

	 memcpy(&p_nat->keys[pkt_num], &key0,
				sizeof(struct pipeline_cgnapt_entry_key));
	p_nat->key_ptrs[pkt_num] = &p_nat->keys[pkt_num];

/* --1-- */
PKT1:

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt[1]);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt[1], pkt_mask1, p_nat))
			goto PKT2;
	}
	switch (protocol1) {
	case IP_PROTOCOL_UDP:
	{
		#ifdef PCP_ENABLE
		if (pcp_enable) {
		struct udp_hdr *udp;

		udp = (struct udp_hdr *)
			RTE_MBUF_METADATA_UINT8_PTR(pkt[1],
						IPV4_UDP_OFST);

		if (rte_bswap16(udp->dst_port) ==
			PCP_SERVER_PORT) {
			handle_pcp_req(pkt[1], IPV4_SZ, p_nat);
			p_nat->invalid_packets |= pkt_mask1;
			goto PKT2;
		}
		}
		#endif
	}
	case IP_PROTOCOL_TCP:

		src_port_offset1 = SRC_PRT_OFST_IP4_TCP;
		src_port1 = RTE_MBUF_METADATA_UINT16(pkt[1],
				src_port_offset1);

	break;

	case IP_PROTOCOL_ICMP:
		 /* Identifier */
		 src_port_offset1 = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					 IP_HDR_SIZE + 4;
		 src_port1 = RTE_MBUF_METADATA_UINT16(pkt[1],
				src_port_offset1);

	break;

	default:
		 /* remember invalid packets to be dropped */
		 p_nat->invalid_packets |= pkt_mask1;
		 p_nat->naptDroppedPktCount++;

		 #ifdef CGNAPT_DEBUGGING
		 p_nat->naptDroppedPktCount2++;
		 #endif
		goto PKT2;
	}

	key1.pid = phy_port1;
	key1.ip = rte_bswap32(src_addr1);
	key1.port = rte_bswap16(src_port1);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key1.port = 0xffff;
	#endif

	 memcpy(&p_nat->keys[pkt_num + 1], &key1,
				sizeof(struct pipeline_cgnapt_entry_key));
	p_nat->key_ptrs[pkt_num + 1] = &p_nat->keys[pkt_num + 1];

/* --2-- */
PKT2:
	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt[2]);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt[2], pkt_mask2, p_nat))
			goto PKT3;
	}

	switch (protocol2) {
	case IP_PROTOCOL_UDP:
	{
		#ifdef PCP_ENABLE
		if (pcp_enable) {
		struct udp_hdr *udp;

		udp = (struct udp_hdr *)
			RTE_MBUF_METADATA_UINT8_PTR(pkt[2],
						IPV4_UDP_OFST);

		if (rte_bswap16(udp->dst_port) ==
			PCP_SERVER_PORT) {
			handle_pcp_req(pkt[2], IPV4_SZ, p_nat);
			p_nat->invalid_packets |= pkt_mask2;
			goto PKT3;
		}
		}
		#endif
	}
	case IP_PROTOCOL_TCP:

		src_port_offset2 = SRC_PRT_OFST_IP4_TCP;
		src_port2 = RTE_MBUF_METADATA_UINT16(pkt[2],
				src_port_offset2);

	break;

	case IP_PROTOCOL_ICMP:
		 /* Identifier */
		 src_port_offset2 = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					 IP_HDR_SIZE + 4;
		 src_port2 = RTE_MBUF_METADATA_UINT16(pkt[2],
				src_port_offset2);

	break;

	default:
		 /* remember invalid packets to be dropped */
		 p_nat->invalid_packets |= pkt_mask2;
		 p_nat->naptDroppedPktCount++;

		 #ifdef CGNAPT_DEBUGGING
		 p_nat->naptDroppedPktCount2++;
		 #endif
		goto PKT3;
	}

	key2.pid = phy_port2;
	key2.ip = rte_bswap32(src_addr2);
	key2.port = rte_bswap16(src_port2);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key2.port = 0xffff;
	#endif

	 memcpy(&p_nat->keys[pkt_num + 2], &key2,
				sizeof(struct pipeline_cgnapt_entry_key));
	p_nat->key_ptrs[pkt_num + 2] = &p_nat->keys[pkt_num + 2];

/* --3-- */
PKT3:
	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt[3]);
	#endif
	if (enable_hwlb) {
		if (!check_arp_icmp(pkt[3], pkt_mask3, p_nat))
			return;
	}

	switch (protocol3) {
	case IP_PROTOCOL_UDP:
	{
		#ifdef PCP_ENABLE
		if (pcp_enable) {
		struct udp_hdr *udp;

		udp = (struct udp_hdr *)
			RTE_MBUF_METADATA_UINT8_PTR(pkt[3],
						IPV4_UDP_OFST);

		if (rte_bswap16(udp->dst_port) ==
			PCP_SERVER_PORT) {
			handle_pcp_req(pkt[3], IPV4_SZ, p_nat);
			p_nat->invalid_packets |= pkt_mask3;
			return;
		}
		}
		#endif
	}
	case IP_PROTOCOL_TCP:

		src_port_offset3 = SRC_PRT_OFST_IP4_TCP;
		src_port3 = RTE_MBUF_METADATA_UINT16(pkt[3],
				src_port_offset3);

	break;

	case IP_PROTOCOL_ICMP:
		 /* Identifier */
		 src_port_offset3 = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					 IP_HDR_SIZE + 4;
		 src_port3 = RTE_MBUF_METADATA_UINT16(pkt[3],
				src_port_offset3);

	break;

	default:
		 /* remember invalid packets to be dropped */
		 p_nat->invalid_packets |= pkt_mask3;
		 p_nat->naptDroppedPktCount++;

		 #ifdef CGNAPT_DEBUGGING
		 p_nat->naptDroppedPktCount2++;
		 #endif
		return;
	}

	key3.pid = phy_port3;
	key3.ip = rte_bswap32(src_addr3);
	key3.port = rte_bswap16(src_port3);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key3.port = 0xffff;
	#endif

	 memcpy(&p_nat->keys[pkt_num + 3], &key3,
				sizeof(struct pipeline_cgnapt_entry_key));
	p_nat->key_ptrs[pkt_num + 3] = &p_nat->keys[pkt_num + 3];
}

/**
 * NAPT key calculation function for IPv4 public traffic
 * which handles 4 pkts
 *
 * @param pkt
 *  A pointer to array of packets mbuf
 * @param in_pkt_num
 *  Starting pkt number of pkts
 * @param arg
 *  Void pointer
 * @param p_nat
 *  A pointer to main CGNAPT structure
 *
 */
void
pkt4_work_cgnapt_key_ipv4_pub(
	struct rte_mbuf **pkt,
	uint32_t pkt_num,
	__rte_unused void *arg,
	struct pipeline_cgnapt *p_nat)
{
	p_nat->receivedPktCount += 4;
	/* bitmask representing only this packet */
	uint64_t pkt_mask0 = 1LLU << pkt_num;
	uint64_t pkt_mask1 = 1LLU << (pkt_num + 1);
	uint64_t pkt_mask2 = 1LLU << (pkt_num + 2);
	uint64_t pkt_mask3 = 1LLU << (pkt_num + 3);

	uint8_t protocol0 = RTE_MBUF_METADATA_UINT8(pkt[0],
				PROT_OFST_IP4);
	uint8_t protocol1 = RTE_MBUF_METADATA_UINT8(pkt[1],
				PROT_OFST_IP4);
	uint8_t protocol2 = RTE_MBUF_METADATA_UINT8(pkt[2],
				PROT_OFST_IP4);
	uint8_t protocol3 = RTE_MBUF_METADATA_UINT8(pkt[3],
				PROT_OFST_IP4);

	uint32_t dst_addr0 = RTE_MBUF_METADATA_UINT32(pkt[0],
				DST_ADR_OFST_IP4);
	uint32_t dst_addr1 = RTE_MBUF_METADATA_UINT32(pkt[1],
				DST_ADR_OFST_IP4);
	uint32_t dst_addr2 = RTE_MBUF_METADATA_UINT32(pkt[2],
				DST_ADR_OFST_IP4);
	uint32_t dst_addr3 = RTE_MBUF_METADATA_UINT32(pkt[3],
				DST_ADR_OFST_IP4);

	uint16_t src_port_offset0;
	uint16_t src_port_offset1;
	uint16_t src_port_offset2;
	uint16_t src_port_offset3;

	uint16_t dst_port_offset0;
	uint16_t dst_port_offset1;
	uint16_t dst_port_offset2;
	uint16_t dst_port_offset3;

	uint16_t src_port0;
	uint16_t src_port1;
	uint16_t src_port2;
	uint16_t src_port3;

	uint16_t dst_port0;
	uint16_t dst_port1;
	uint16_t dst_port2;
	uint16_t dst_port3;

	struct pipeline_cgnapt_entry_key key0;
	struct pipeline_cgnapt_entry_key key1;
	struct pipeline_cgnapt_entry_key key2;
	struct pipeline_cgnapt_entry_key key3;

	memset(&key0, 0, sizeof(struct pipeline_cgnapt_entry_key));
	memset(&key1, 0, sizeof(struct pipeline_cgnapt_entry_key));
	memset(&key2, 0, sizeof(struct pipeline_cgnapt_entry_key));
	memset(&key3, 0, sizeof(struct pipeline_cgnapt_entry_key));

/* --0-- */
	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt[0]);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt[0], pkt_mask0, p_nat))
			goto PKT1;
	}

	switch (protocol0) {
	case IP_PROTOCOL_UDP:
	case IP_PROTOCOL_TCP:

		src_port_offset0 = SRC_PRT_OFST_IP4_TCP;
		dst_port_offset0 = DST_PRT_OFST_IP4_TCP;

		src_port0 = RTE_MBUF_METADATA_UINT16(pkt[0],
				src_port_offset0);
		dst_port0 = RTE_MBUF_METADATA_UINT16(pkt[0],
				dst_port_offset0);

		key0.port = rte_bswap16(dst_port0);

	break;

	case IP_PROTOCOL_ICMP:
		 /* Identifier */
		src_port_offset0 = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					 IP_HDR_SIZE + 4;
		/*Sequence number */
		dst_port_offset0 = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					 IP_HDR_SIZE + 6;

		src_port0 = RTE_MBUF_METADATA_UINT16(pkt[0],
				src_port_offset0);
		dst_port0 = RTE_MBUF_METADATA_UINT16(pkt[0],
				dst_port_offset0);

		key0.port = rte_bswap16(src_port0);

	break;

	default:
		 /* remember invalid packets to be dropped */
		 p_nat->invalid_packets |= pkt_mask0;
		 p_nat->naptDroppedPktCount++;

		 #ifdef CGNAPT_DEBUGGING
		 p_nat->naptDroppedPktCount2++;
		 #endif
		goto PKT1;
	}

	key0.pid = 0xffff;
	key0.ip = rte_bswap32(dst_addr0);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key0.port = 0xffff;
	#endif

	 memcpy(&p_nat->keys[pkt_num], &key0,
				sizeof(struct pipeline_cgnapt_entry_key));
	p_nat->key_ptrs[pkt_num] = &p_nat->keys[pkt_num];

/* --1-- */
PKT1:

	 #ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt[1]);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt[1], pkt_mask1, p_nat))
			goto PKT2;
	}

	switch (protocol1) {
	case IP_PROTOCOL_UDP:
	case IP_PROTOCOL_TCP:

		src_port_offset1 = SRC_PRT_OFST_IP4_TCP;
		dst_port_offset1 = DST_PRT_OFST_IP4_TCP;

		src_port1 = RTE_MBUF_METADATA_UINT16(pkt[1],
				src_port_offset1);
		dst_port1 = RTE_MBUF_METADATA_UINT16(pkt[1],
				dst_port_offset1);

		key1.port = rte_bswap16(dst_port1);

	break;

	case IP_PROTOCOL_ICMP:
		 /* Identifier */
		 src_port_offset1 = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					 IP_HDR_SIZE + 4;
		 /*Sequence number */
		 dst_port_offset1 = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					 IP_HDR_SIZE + 6;

		 src_port1 = RTE_MBUF_METADATA_UINT16(pkt[1],
				src_port_offset1);
		 dst_port1 = RTE_MBUF_METADATA_UINT16(pkt[1],
				dst_port_offset1);

		key1.port = rte_bswap16(src_port1);
	break;

	default:
		 /* remember invalid packets to be dropped */
		 p_nat->invalid_packets |= pkt_mask1;
		 p_nat->naptDroppedPktCount++;

		 #ifdef CGNAPT_DEBUGGING
		 p_nat->naptDroppedPktCount2++;
		 #endif
		goto PKT2;
	}

	key1.pid = 0xffff;
	key1.ip = rte_bswap32(dst_addr1);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key1.port = 0xffff;
	#endif

	 memcpy(&p_nat->keys[pkt_num + 1], &key1,
				sizeof(struct pipeline_cgnapt_entry_key));
	p_nat->key_ptrs[pkt_num + 1] = &p_nat->keys[pkt_num + 1];

/* --2-- */
PKT2:
	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt[2]);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt[2], pkt_mask2, p_nat))
			goto PKT3;
	}

	switch (protocol2) {
	case IP_PROTOCOL_UDP:
	case IP_PROTOCOL_TCP:

		src_port_offset2 = SRC_PRT_OFST_IP4_TCP;
		dst_port_offset2 = DST_PRT_OFST_IP4_TCP;

		src_port2 = RTE_MBUF_METADATA_UINT16(pkt[2],
				src_port_offset2);
		dst_port2 = RTE_MBUF_METADATA_UINT16(pkt[2],
				dst_port_offset2);

		key2.port = rte_bswap16(dst_port2);

	break;

	case IP_PROTOCOL_ICMP:
		 /* Identifier */
		 src_port_offset2 = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					 IP_HDR_SIZE + 4;
		 /*Sequence number */
		 dst_port_offset2 = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					 IP_HDR_SIZE + 6;

		 src_port2 = RTE_MBUF_METADATA_UINT16(pkt[2],
				src_port_offset2);
		 dst_port2 = RTE_MBUF_METADATA_UINT16(pkt[2],
				dst_port_offset2);

		key2.port = rte_bswap16(src_port2);

	break;

	default:
		 /* remember invalid packets to be dropped */
		 p_nat->invalid_packets |= pkt_mask2;
		 p_nat->naptDroppedPktCount++;

		 #ifdef CGNAPT_DEBUGGING
		 p_nat->naptDroppedPktCount2++;
		 #endif
		goto PKT3;
	}

	key2.pid = 0xffff;
	key2.ip = rte_bswap32(dst_addr2);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key2.port = 0xffff;
	#endif

	 memcpy(&p_nat->keys[pkt_num + 2], &key2,
				sizeof(struct pipeline_cgnapt_entry_key));
	p_nat->key_ptrs[pkt_num + 2] = &p_nat->keys[pkt_num + 2];

/* --3-- */
PKT3:
	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt[3]);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt[3], pkt_mask3, p_nat))
			return;
	}

	switch (protocol3) {
	case IP_PROTOCOL_UDP:
	case IP_PROTOCOL_TCP:

		src_port_offset3 = SRC_PRT_OFST_IP4_TCP;
		dst_port_offset3 = DST_PRT_OFST_IP4_TCP;

		src_port3 = RTE_MBUF_METADATA_UINT16(pkt[3],
				src_port_offset3);
		dst_port3 = RTE_MBUF_METADATA_UINT16(pkt[3],
				dst_port_offset3);

		key3.port = rte_bswap16(dst_port3);

	break;

	case IP_PROTOCOL_ICMP:
		 /* Identifier */
		 src_port_offset3 = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					 IP_HDR_SIZE + 4;
		 /*Sequence number */
		 dst_port_offset3 = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					 IP_HDR_SIZE + 6;

		 src_port3 = RTE_MBUF_METADATA_UINT16(pkt[3],
				src_port_offset3);
		 dst_port3 = RTE_MBUF_METADATA_UINT16(pkt[3],
				dst_port_offset3);

		key3.port = rte_bswap16(src_port3);

	break;

	default:
		 /* remember invalid packets to be dropped */
		 p_nat->invalid_packets |= pkt_mask3;
		 p_nat->naptDroppedPktCount++;

		 #ifdef CGNAPT_DEBUGGING
		 p_nat->naptDroppedPktCount2++;
		 #endif
		return;
	}

	key3.pid = 0xffff;
	key3.ip = rte_bswap32(dst_addr3);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key3.port = 0xffff;
	#endif

	 memcpy(&p_nat->keys[pkt_num + 3], &key3,
				sizeof(struct pipeline_cgnapt_entry_key));
	p_nat->key_ptrs[pkt_num + 3] = &p_nat->keys[pkt_num + 3];
}

/**
 * NAPT key calculation function for IPv4 private traffic
 * which handles 1 pkt
 *
 * @param pkt
 *  A pointer to array of packets mbuf
 * @param in_pkt_num
 *  Pkt number of pkts
 * @param arg
 *  Void pointer
 * @param p_nat
 *  A pointer to main CGNAPT structure
 *
 */
void
pkt_work_cgnapt_key_ipv4_prv(
	struct rte_mbuf *pkt,
	uint32_t pkt_num,
	__rte_unused void *arg,
	struct pipeline_cgnapt *p_nat)
{
	/* Egress */
	p_nat->receivedPktCount++;

	/* bitmask representing only this packet */
	uint64_t pkt_mask = 1LLU << pkt_num;
	uint8_t protocol = RTE_MBUF_METADATA_UINT8(pkt, PROT_OFST_IP4);

	uint32_t src_addr = RTE_MBUF_METADATA_UINT32(pkt, SRC_ADR_OFST_IP4);

	uint16_t src_port_offset;

	uint16_t src_port;

	uint16_t phy_port = pkt->port;
	struct pipeline_cgnapt_entry_key key;

	memset(&key, 0, sizeof(struct pipeline_cgnapt_entry_key));


	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt, pkt_mask, p_nat))
			return;
	}

	switch (protocol) {
	case IP_PROTOCOL_UDP:
	{
		#ifdef PCP_ENABLE
		if (pcp_enable) {
		struct udp_hdr *udp;

		udp = (struct udp_hdr *)
			RTE_MBUF_METADATA_UINT8_PTR(pkt,
						IPV4_UDP_OFST);

		if (rte_bswap16(udp->dst_port) ==
			PCP_SERVER_PORT) {
			handle_pcp_req(pkt, IPV4_SZ, p_nat);
			p_nat->invalid_packets |= pkt_mask;
			return;
		}
		}
		#endif
	}
	case IP_PROTOCOL_TCP:

		src_port_offset = SRC_PRT_OFST_IP4_TCP;
		src_port = RTE_MBUF_METADATA_UINT16(pkt, src_port_offset);

		key.port = rte_bswap16(src_port);

	break;
	case IP_PROTOCOL_ICMP:
		/* Identifier */
		src_port_offset = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					IP_HDR_SIZE + 4;
		src_port = RTE_MBUF_METADATA_UINT16(pkt, src_port_offset);

		key.port = rte_bswap16(src_port);

	break;
	default:
		/* remember invalid packets to be dropped */
		p_nat->invalid_packets |= pkt_mask;
		p_nat->naptDroppedPktCount++;

		#ifdef CGNAPT_DEBUGGING
		p_nat->naptDroppedPktCount2++;
		#endif
		return;
	}

	key.pid = phy_port;
	key.ip = rte_bswap32(src_addr);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key.port = 0xffff;
	#endif

	memcpy(&p_nat->keys[pkt_num], &key,
			 sizeof(struct pipeline_cgnapt_entry_key));
	p_nat->key_ptrs[pkt_num] = &p_nat->keys[pkt_num];
}

/**
 * NAPT key calculation function for IPv4 public traffic
 * which handles 1 pkt
 *
 * @param pkt
 *  A pointer to array of packets mbuf
 * @param in_pkt_num
 *  Pkt number of pkts
 * @param arg
 *  Void pointer
 * @param p_nat
 *  A pointer to main CGNAPT structure
 *
 */
void
pkt_work_cgnapt_key_ipv4_pub(
	struct rte_mbuf *pkt,
	uint32_t pkt_num,
	__rte_unused void *arg,
	struct pipeline_cgnapt *p_nat)
{
	p_nat->receivedPktCount++;

	/* bitmask representing only this packet */
	uint64_t pkt_mask = 1LLU << pkt_num;
	uint8_t protocol = RTE_MBUF_METADATA_UINT8(pkt, PROT_OFST_IP4);
	uint32_t dst_addr = RTE_MBUF_METADATA_UINT32(pkt, DST_ADR_OFST_IP4);
	uint16_t src_port_offset;
	uint16_t dst_port_offset;
	uint16_t src_port;
	uint16_t dst_port;
	struct pipeline_cgnapt_entry_key key;
	memset(&key, 0, sizeof(struct pipeline_cgnapt_entry_key));

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt, pkt_mask, p_nat))
			return;
	}

	switch (protocol) {
	case IP_PROTOCOL_UDP:
	case IP_PROTOCOL_TCP:
		src_port_offset = SRC_PRT_OFST_IP4_TCP;
		dst_port_offset = DST_PRT_OFST_IP4_TCP;

		src_port = RTE_MBUF_METADATA_UINT16(pkt, src_port_offset);
		dst_port = RTE_MBUF_METADATA_UINT16(pkt, dst_port_offset);

		key.port = rte_bswap16(dst_port);
	break;
	case IP_PROTOCOL_ICMP:
		/* Identifier */
		src_port_offset = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					IP_HDR_SIZE + 4;
		dst_port_offset = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					IP_HDR_SIZE + 6;

		src_port = RTE_MBUF_METADATA_UINT16(pkt, src_port_offset);
		dst_port = RTE_MBUF_METADATA_UINT16(pkt, dst_port_offset);

		/* common table lookupkey preparation from incoming
		* ICMP Packet- Indentifier field
		*/
		key.port = rte_bswap16(src_port);
	break;
	default:
		/* remember invalid packets to be dropped */
		p_nat->invalid_packets |= pkt_mask;
		p_nat->naptDroppedPktCount++;

		#ifdef CGNAPT_DEBUGGING
		p_nat->naptDroppedPktCount2++;
		#endif
		return;
	}

	key.ip = rte_bswap32(dst_addr);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key.port = 0xffff;
	#endif

	key.pid = 0xffff;

	memcpy(&p_nat->keys[pkt_num], &key,
			 sizeof(struct pipeline_cgnapt_entry_key));
	p_nat->key_ptrs[pkt_num] = &p_nat->keys[pkt_num];
}


/**
 * NAPT function for IPv4 private traffic which handles 1 pkt
 *
 * @param pkts
 *  A pointer to array of packet mbuf
 * @param in_pkt_num
 *  Pkt number of pkt
 * @param arg
 *  Void pointer
 * @param p_nat
 *  A pointer to main CGNAPT structure
 *
 */
uint64_t last_update;
void
pkt_work_cgnapt_ipv4_prv(
	struct rte_mbuf **pkts,
	uint32_t pkt_num,
	__rte_unused void *arg,
	struct pipeline_cgnapt *p_nat)
{
	#ifdef CT_CGNAT
	struct rte_CT_helper ct_helper;
	memset(&ct_helper, 0, sizeof(struct rte_CT_helper));
	#endif

	/* index into hash table entries */
	int hash_table_entry = p_nat->lkup_indx[pkt_num];
	/*bitmask representing only this packet */
	uint64_t pkt_mask = 1LLU << pkt_num;
	struct rte_mbuf *pkt = pkts[pkt_num];

	uint8_t protocol = RTE_MBUF_METADATA_UINT8(pkt, PROT_OFST_IP4);

	uint32_t dest_if = 0xff;	/* Added for Multiport */
	uint16_t *outport_id =
		RTE_MBUF_METADATA_UINT16_PTR(pkt, cgnapt_meta_offset);

	struct cgnapt_table_entry *entry = NULL;

	enum PKT_TYPE pkt_type = PKT_TYPE_IPV4;

	if (hash_table_entry < 0) {

		/* try to add new entry */
		struct rte_pipeline_table_entry *table_entry = NULL;

		uint64_t dropmask = pkt_miss_cgnapt(p_nat->key_ptrs[pkt_num],
					pkt, &table_entry,
					&p_nat->valid_packets, pkt_num,
					(void *)p_nat);

		if (!table_entry) {
			/* ICMP Error message generation for Destination
			 * Host unreachable
			 */
			if (protocol == IP_PROTOCOL_ICMP) {
				cgnapt_icmp_pkt = pkt;
				send_icmp_dest_unreachable_msg();
			}

			/* Drop packet by adding to invalid pkt mask */

			p_nat->invalid_packets |= dropmask;
			#ifdef CGNAPT_DEBUGGING
			if (p_nat->kpc2++ < 5) {
				printf("in_ah Th: %d", p_nat->pipeline_num);
				print_key(p_nat->key_ptrs[pkt_num]);
			}
			#endif

			p_nat->naptDroppedPktCount++;

			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount3++;
			#endif
			return;
		}

		entry = (struct cgnapt_table_entry *)table_entry;
	} else {
		/* entry found for this packet */
		entry = &napt_hash_tbl_entries[hash_table_entry];
	}

	/*  apply napt and mac changes */

	p_nat->entries[pkt_num] = &(entry->head);

	uint32_t *src_addr =
		RTE_MBUF_METADATA_UINT32_PTR(pkt, SRC_ADR_OFST_IP4);
	uint32_t *dst_addr =
		RTE_MBUF_METADATA_UINT32_PTR(pkt, DST_ADR_OFST_IP4);
	uint16_t src_port_offset = 0;
	uint16_t dst_port_offset = 0;
	uint16_t *src_port;
	uint16_t *dst_port;

	switch (protocol) {
	case IP_PROTOCOL_TCP:
		src_port_offset = SRC_PRT_OFST_IP4_TCP;
		dst_port_offset = DST_PRT_OFST_IP4_TCP;
		src_port = RTE_MBUF_METADATA_UINT16_PTR(pkt, src_port_offset);
		dst_port = RTE_MBUF_METADATA_UINT16_PTR(pkt, dst_port_offset);

		#ifdef CT_CGNAT
		if ((rte_be_to_cpu_16(*src_port) == 21) ||
			rte_be_to_cpu_16(*dst_port) == 21) {

			#ifdef ALGDBG
			printf("cgnapt_ct_process: pkt_mask: % "PRIu64", "
				"pkt_num: %d\n", pkt_mask, pkt_num);
			#endif

			pkt_mask =  cgnapt_ct_process(cgnat_cnxn_tracker, pkts,
				pkt_mask, &ct_helper);
		}
		#endif
	break;
	case IP_PROTOCOL_UDP:
		src_port_offset = SRC_PRT_OFST_IP4_TCP;
		dst_port_offset = DST_PRT_OFST_IP4_TCP;
		src_port = RTE_MBUF_METADATA_UINT16_PTR(pkt, src_port_offset);
		dst_port = RTE_MBUF_METADATA_UINT16_PTR(pkt, dst_port_offset);
	break;
	case IP_PROTOCOL_ICMP:
		/* Identifier */
		src_port_offset = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					IP_HDR_SIZE + 4;
		/*Sequence number */
		dst_port_offset = MBUF_HDR_ROOM + ETH_HDR_SIZE +
					IP_HDR_SIZE + 6;
		src_port = RTE_MBUF_METADATA_UINT16_PTR(pkt, src_port_offset);
		dst_port = RTE_MBUF_METADATA_UINT16_PTR(pkt, dst_port_offset);
	break;
	}

	uint8_t *eth_dest = RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
	uint8_t *eth_src = RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM + 6);

	if (entry->data.ttl == NAPT_ENTRY_STALE)
		entry->data.ttl = NAPT_ENTRY_VALID;

	struct ether_addr hw_addr;
	uint32_t dest_address = 0;

	/* Egress */
	if (unlikely(protocol == IP_PROTOCOL_UDP
				&& rte_be_to_cpu_16(*dst_port) == 53)) {
		p_nat->invalid_packets |= pkt_mask;
		p_nat->naptDroppedPktCount++;

		#ifdef CGNAPT_DEBUGGING
		p_nat->naptDroppedPktCount6++;
		#endif
		return;
	}
	last_update = rte_rdtsc();
	dest_address = rte_bswap32(*dst_addr);
	uint32_t nhip = 0;
	struct arp_entry_data *ret_arp_data = NULL;
	ret_arp_data = get_dest_mac_addr_port(dest_address, &dest_if, (struct ether_addr *)eth_dest);
	*outport_id = p_nat->outport_id[dest_if];

	if (arp_cache_dest_mac_present(dest_if)) {
		ether_addr_copy(get_link_hw_addr(dest_if),(struct ether_addr *)eth_src);
		arp_data_ptr[dest_if]->n_last_update = time(NULL);

		if (unlikely(ret_arp_data && ret_arp_data->num_pkts)) {
			printf("sending buffered packets\n");
			p_nat->naptedPktCount += ret_arp_data->num_pkts;
			arp_send_buffered_pkts(ret_arp_data,
				 (struct ether_addr *)eth_dest, *outport_id);

		}
	} else {

		if (unlikely(ret_arp_data == NULL)) {

			printf("%s: NHIP Not Found, nhip:%x , "
			"outport_id: %d\n", __func__, nhip,
			*outport_id);

			/* Drop the pkt */
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;

			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount4++;
			#endif
			return;
		}

		if (ret_arp_data->status == INCOMPLETE ||
			   ret_arp_data->status == PROBE) {
				if (ret_arp_data->num_pkts >= NUM_DESC) {
					/* Drop the pkt */
					p_nat->invalid_packets |= pkt_mask;
					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					return;
				} else {
					arp_pkts_mask |= pkt_mask;
					arp_queue_unresolved_packet(ret_arp_data, pkt);
					return;
				}
		}

	}

	{
		/* Egress */
		*src_addr = rte_bswap32(entry->data.pub_ip);


		#ifdef NAT_ONLY_CONFIG_REQ
		if (!nat_only_config_flag) {
		#endif
			*src_port = rte_bswap16(entry->data.pub_port);
		#ifdef NAT_ONLY_CONFIG_REQ
		}
		#endif

		#ifdef SIP_ALG
		uint16_t rtp_port = 0, rtcp_port = 0;
		struct cgnapt_table_entry *entry_ptr1 = NULL,
		*entry_ptr2 = NULL, *entry_ptr3 = NULL,
		*entry_ptr4 = NULL;

		if (unlikely(protocol == IP_PROTOCOL_UDP
				&& (rte_be_to_cpu_16(*dst_port) == 5060
				|| rte_be_to_cpu_16(*src_port) == 5060))) {

			int ret = natSipAlgGetAudioPorts(pkt, &rtp_port,
					&rtcp_port);
			/* Commented code may be required for debug
			* and future use, Please keep it*/
			#if 0
			if (ret < 0) {
				printf("%s: Wrong SIP ALG packet1\n",
					__func__);
				p_nat->invalid_packets |= pkt_mask;

				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount4++;
				#endif
				return;
			}
			#endif

			if (ret >= 0 && rtp_port != 0) {
				struct pipeline_cgnapt_entry_key rtp_key;
				rtp_key.ip = entry->data.u.prv_ip;
				rtp_key.port = rtp_port;
				rtp_key.pid = entry->data.prv_phy_port;

				if (add_dynamic_cgnapt_entry_alg(
				(struct pipeline *)p_nat, &rtp_key,
				&entry_ptr1, &entry_ptr2) == 0) {
					printf("%s: Wrong SIP ALG packet2\n",
						__func__);
					p_nat->invalid_packets |= pkt_mask;

					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					return;
				}
			}

			if (ret >= 0 && rtcp_port != 0) {
				struct pipeline_cgnapt_entry_key rtcp_key;
				rtcp_key.ip = entry->data.u.prv_ip;
				rtcp_key.port = rtcp_port;
				rtcp_key.pid = entry->data.prv_phy_port;

				if (add_dynamic_cgnapt_entry_alg(
				(struct pipeline *)p_nat, &rtcp_key,
				&entry_ptr3, &entry_ptr4) == 0) {
					printf("%s: Wrong SIP ALG packet3\n",
						__func__);
					p_nat->invalid_packets |= pkt_mask;

					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					return;
				}

			}
			//if(entry_ptr1 != NULL  && entry_ptr3 != NULL)
			if (sip_alg_dpi(pkt, PRIVATE, entry->data.pub_ip,
				entry->data.pub_port, entry->data.u.prv_ip,
				entry->data.prv_port, (rtp_port == 0) ? 0 :
				entry_ptr1->data.pub_port,
				(rtcp_port == 0) ? 0 :
				entry_ptr3->data.pub_port) == 0) {

				printf("%s: Wrong SIP ALG packet4\n",
						__func__);
				p_nat->invalid_packets |= pkt_mask;

				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount4++;
				#endif
				return;
			}
		}
		#endif /* SIP_ALG */

		#ifdef FTP_ALG

		#ifdef ALGDBG
		printf("@CGNAT-pktwork ct_position :%d, pkt_num %d pkt_mask= "
			"%" PRIu64 "\n", ct_position, pkt_num, pkt_mask);
		#endif

		if ((rte_be_to_cpu_16(*src_port) == 21) ||
			rte_be_to_cpu_16(*dst_port) == 21) {

		int32_t ct_position = cgnat_cnxn_tracker->positions[pkt_num];
		if (ct_position < 0){
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;
			return;
		}
			/* Commented code may be required for future usage,
			 * Please keep it
			 */
			//if (cgnat_cnxn_tracker->hash_table_entries
			//	[ct_position].alg_bypass_flag != BYPASS)
			{
			struct pipeline_cgnapt_entry_key data_channel_entry_key;

			data_channel_entry_key.ip = entry->data.pub_ip;
			data_channel_entry_key.port = entry->data.pub_port;
			data_channel_entry_key.pid = pkt->port;
			ftp_alg_dpi(p_nat, &data_channel_entry_key, pkt,
			cgnat_cnxn_tracker, ct_position, PRIVATE);
			}
		}
		#endif /* FTP_ALG */

		p_nat->enaptedPktCount++;
	}

	p_nat->naptedPktCount++;

	#ifdef CHECKSUM_REQ
		if (p_nat->hw_checksum_reqd)
			hw_checksum(pkt, pkt_type);
		else
			sw_checksum(pkt, pkt_type);
	#endif

}


/**
 * NAPT function for IPv4 public traffic which handles 1 pkt
 *
 * @param pkts
 *  A pointer to array of packet mbuf
 * @param in_pkt_num
 *  Pkt number of pkt
 * @param arg
 *  Void pointer
 * @param p_nat
 *  A pointer to main CGNAPT structure
 *
 */
void
pkt_work_cgnapt_ipv4_pub(
	struct rte_mbuf **pkts,
	uint32_t pkt_num,
	__rte_unused void *arg,
	struct pipeline_cgnapt *p_nat)
{

	#ifdef CT_CGNAT
	struct rte_CT_helper ct_helper;
	memset(&ct_helper, 0, sizeof(struct rte_CT_helper));
	#endif

	/* index into hash table entries */
	int hash_table_entry = p_nat->lkup_indx[pkt_num];
	/*bitmask representing only this packet */
	uint64_t pkt_mask = 1LLU << pkt_num;
	struct rte_mbuf *pkt = pkts[pkt_num];

	uint8_t protocol = RTE_MBUF_METADATA_UINT8(pkt, PROT_OFST_IP4);

	uint32_t dest_if = 0xff;	/* Added for Multiport */
	uint16_t *outport_id =
		RTE_MBUF_METADATA_UINT16_PTR(pkt, cgnapt_meta_offset);

	struct cgnapt_table_entry *entry = NULL;

	enum PKT_TYPE pkt_type = PKT_TYPE_IPV4;

	if (hash_table_entry < 0) {

		/* try to add new entry */
		struct rte_pipeline_table_entry *table_entry = NULL;

		uint64_t dropmask = pkt_miss_cgnapt(p_nat->key_ptrs[pkt_num],
					pkt, &table_entry,
					&p_nat->valid_packets, pkt_num,
					(void *)p_nat);

		if (!table_entry) {
			/* ICMP Error message generation for
			* Destination Host unreachable
			*/
			if (protocol == IP_PROTOCOL_ICMP) {
				cgnapt_icmp_pkt = pkt;
				send_icmp_dest_unreachable_msg();
			}

			/* Drop packet by adding to invalid pkt mask */

			p_nat->invalid_packets |= dropmask;
			#ifdef CGNAPT_DEBUGGING
			if (p_nat->kpc2++ < 5) {
				printf("in_ah Th: %d", p_nat->pipeline_num);
				print_key(p_nat->key_ptrs[pkt_num]);
			}
			#endif

			p_nat->naptDroppedPktCount++;

			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount3++;
			#endif
			return;
		}

		entry = (struct cgnapt_table_entry *)table_entry;
	} else {
		/* entry found for this packet */
		entry = &napt_hash_tbl_entries[hash_table_entry];
	}

	/*  apply napt and mac changes */

	p_nat->entries[pkt_num] = &(entry->head);

	uint32_t *dst_addr =
		RTE_MBUF_METADATA_UINT32_PTR(pkt, DST_ADR_OFST_IP4);
	uint16_t src_port_offset = 0;
	uint16_t dst_port_offset = 0;

	if ((protocol == IP_PROTOCOL_TCP) || (protocol == IP_PROTOCOL_UDP)) {
		src_port_offset = SRC_PRT_OFST_IP4_TCP;
		dst_port_offset = DST_PRT_OFST_IP4_TCP;
	} else if (protocol == IP_PROTOCOL_ICMP) {
		/* Identifier */
		src_port_offset = MBUF_HDR_ROOM +
					ETH_HDR_SIZE +
					IP_HDR_SIZE + 4;
		/*Sequence number */
		dst_port_offset = MBUF_HDR_ROOM +
					ETH_HDR_SIZE +
					IP_HDR_SIZE + 6;
	}

	uint16_t *src_port = RTE_MBUF_METADATA_UINT16_PTR(pkt, src_port_offset);
	uint16_t *dst_port = RTE_MBUF_METADATA_UINT16_PTR(pkt, dst_port_offset);

	uint8_t *eth_dest = RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
	uint8_t *eth_src = RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM + 6);

	if (entry->data.ttl == NAPT_ENTRY_STALE)
		entry->data.ttl = NAPT_ENTRY_VALID;

	struct ether_addr hw_addr;
	uint32_t dest_address = 0;

	/* Multiport Changes */
	uint32_t nhip = 0;
	uint32_t ret;

	{
		/* Ingress */
		if (unlikely(protocol == IP_PROTOCOL_UDP
				 && rte_be_to_cpu_16(*src_port) == 53)) {
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;
			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount6++;
			#endif
			return;
		}
	}

	dest_address = entry->data.u.prv_ip;
	struct arp_entry_data *ret_arp_data = NULL;
	ret_arp_data = get_dest_mac_addr_port(dest_address, &dest_if, (struct ether_addr *)eth_dest);
	*outport_id = p_nat->outport_id[dest_if];

	if (arp_cache_dest_mac_present(dest_if)) {
		ether_addr_copy(get_link_hw_addr(dest_if), (struct ether_addr *)eth_src);
		arp_data_ptr[dest_if]->n_last_update = time(NULL);

		if (ret_arp_data && ret_arp_data->num_pkts) {
			printf("sending buffered packets\n");
			p_nat->naptedPktCount += ret_arp_data->num_pkts;
			arp_send_buffered_pkts(ret_arp_data,
				 (struct ether_addr *)eth_dest, *outport_id);
		}

	} else {

		if (unlikely(ret_arp_data == NULL)) {

			/* Commented code may be required for debug
			 * and future use, Please keep it */
			printf("%s: NHIP Not Found, nhip: %x, "
			"outport_id: %d\n", __func__, nhip,
			*outport_id);

			/* Drop the pkt */
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;

			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount4++;
			#endif
			return;

		}

		if (ret_arp_data->status == INCOMPLETE ||
			ret_arp_data->status == PROBE) {
			if (ret_arp_data->num_pkts >= NUM_DESC) {
				/* Drop the pkt */
				p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount4++;
				#endif
				return;
			} else {
				arp_pkts_mask |= pkt_mask;
				arp_queue_unresolved_packet(ret_arp_data, pkt);
				return;
			}
		}
	}

	{
		/* Ingress */

		*dst_addr = rte_bswap32(entry->data.u.prv_ip);
		if (protocol == IP_PROTOCOL_ICMP) {
			/* Query ID reverse translation done here */
			/* dont care sequence num */
			*src_port = rte_bswap16(entry->data.prv_port);
		} else {

		#ifdef NAT_ONLY_CONFIG_REQ
			if (!nat_only_config_flag) {
		#endif
				*dst_port = rte_bswap16(entry->data.prv_port);

		#ifdef NAT_ONLY_CONFIG_REQ
			}
		#endif
		#ifdef CT_CGNAT
		if ((rte_be_to_cpu_16(*src_port) == 21) ||
			rte_be_to_cpu_16(*dst_port) == 21) {
			pkt_mask = cgnapt_ct_process(cgnat_cnxn_tracker, pkts,
				pkt_mask, &ct_helper);
		}
		#endif
		}

		#ifdef SIP_ALG
		uint16_t rtp_port = 0, rtcp_port = 0;
		struct cgnapt_table_entry *entry_ptr1 = NULL,
			*entry_ptr3 = NULL;

		/* Commented code may be required for debug
		 * and future use, Please keep it */
		#if 0
		struct cgnapt_table_entry *entry_ptr2 = NULL,
				*entry_ptr4 = NULL;
		#endif

		if (unlikely(protocol == IP_PROTOCOL_UDP
				&& (rte_be_to_cpu_16(*dst_port) == 5060
				|| rte_be_to_cpu_16(*src_port) == 5060))) {
			/* Commented code may be required for future usage,
			 * Please keep it
			 */
			#if 0
			int ret = natSipAlgGetAudioPorts(pkt, &rtp_port,
					&rtcp_port);
			if (ret < 0) {
				printf("%s: Wrong SIP ALG packet1\n",
					__func__);
				p_nat->invalid_packets |= pkt_mask;

				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount4++;
				#endif
				return;
			}
			if (rtp_port != 0) {
				struct pipeline_cgnapt_entry_key rtp_key;
				rtp_key.ip = entry->data.pub_ip;
				rtp_key.port = rtp_port;
				rtp_key.pid = 0xffff;

				if (retrieve_cgnapt_entry_alg(&rtp_key,
					&entry_ptr1, &entry_ptr2) == 0) {
					printf("%s: Wrong SIP ALG packet2\n",
						__func__);
					p_nat->invalid_packets |= pkt_mask;

					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					return;
				}
			}

			if (rtcp_port != 0) {
				struct pipeline_cgnapt_entry_key rtcp_key;
				rtcp_key.ip = entry->data.pub_ip;
				rtcp_key.port = rtcp_port;
				rtcp_key.pid = 0xffff;

				if (retrieve_cgnapt_entry_alg(&rtcp_key,
					&entry_ptr3, &entry_ptr4) == 0) {
					printf("%s: Wrong SIP ALG packet3\n",
						__func__);
					p_nat->invalid_packets |= pkt_mask;

					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					return;
				}

			}
			#endif

			if (sip_alg_dpi(pkt, PUBLIC, entry->data.u.prv_ip,
				entry->data.prv_port, entry->data.pub_ip,
				entry->data.pub_port, (rtp_port == 0) ? 0 :
				entry_ptr1->data.prv_port,
				(rtcp_port == 0) ? 0 :
				entry_ptr3->data.prv_port) == 0) {

				printf("%s: Wrong SIP ALG packet4\n",
						__func__);
				p_nat->invalid_packets |= pkt_mask;

				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount4++;
				#endif
				return;

			}
		}
		#endif /* SIP_ALG */

		#ifdef FTP_ALG
		if ((rte_be_to_cpu_16(*src_port) == 21) ||
			rte_be_to_cpu_16(*dst_port) == 21) {
			int32_t ct_position = cgnat_cnxn_tracker->
						positions[pkt_num];
		if (ct_position < 0){
			p_nat->invalid_packets |= pkt_mask;

			p_nat->naptDroppedPktCount++;
			return;
		}
			#ifdef ALGDBG
			rte_hexdump(stdout, "CT Entry", &cgnat_cnxn_tracker->
			hash_table_entries[ct_position].key, 40);
			#endif

			/* Commented code may be required for debug
			* and future use, Please keep it*/
			//if (cgnat_cnxn_tracker->hash_table_entries
			//	[ct_position].alg_bypass_flag != BYPASS)
			{
			/*enable ALG DPI */
			struct pipeline_cgnapt_entry_key
				data_channel_entry_key;

			data_channel_entry_key.ip = entry->data.pub_ip;
			data_channel_entry_key.port = entry->data.pub_port;
			data_channel_entry_key.pid = 0xffff;
			//printf("pkt_work_pub ftp_alg_dpi\n");
			ftp_alg_dpi(p_nat, &data_channel_entry_key,  pkt,
				cgnat_cnxn_tracker, ct_position, PUBLIC);

			}
		}
		#endif

		p_nat->inaptedPktCount++;
	}

	p_nat->naptedPktCount++;

	#ifdef CHECKSUM_REQ
		if (p_nat->hw_checksum_reqd)
			hw_checksum(pkt, pkt_type);
		else
			sw_checksum(pkt, pkt_type);
	#endif
}


/**
 * NAPT function for IPv4 private traffic which handles 4 pkts
 *
 * @param pkts
 *  A pointer to array of packets mbuf
 * @param in_pkt_num
 *  Starting pkt number of pkts
 * @param arg
 *  Void pointer
 * @param p_nat
 *  A pointer to main CGNAPT structure
 *
 */
void
pkt4_work_cgnapt_ipv4_prv(
	struct rte_mbuf **pkts,
	uint32_t in_pkt_num,
	__rte_unused void *arg,
	struct pipeline_cgnapt *p_nat)
{
	uint32_t dest_if = 0xff;	/* Added for Multiport */
	struct rte_mbuf *pkt;
	uint8_t i;
	uint8_t pkt_num;
	enum PKT_TYPE pkt_type = PKT_TYPE_IPV4;

	#ifdef CT_CGNAT
	struct rte_CT_helper ct_helper;
	memset(&ct_helper, 0, sizeof(struct rte_CT_helper));
	#endif

	for (i = 0; i < 4; i++) {
		pkt_num = in_pkt_num + i;
		pkt = pkts[pkt_num];

		/* index into hash table entries */
		int hash_table_entry = p_nat->lkup_indx[pkt_num];
		/*bitmask representing only this packet */
		uint64_t pkt_mask = 1LLU << pkt_num;

		uint8_t protocol = RTE_MBUF_METADATA_UINT8(pkt, PROT_OFST_IP4);

		uint16_t *outport_id =
			RTE_MBUF_METADATA_UINT16_PTR(pkt, cgnapt_meta_offset);

		struct cgnapt_table_entry *entry = NULL;

		if (hash_table_entry < 0) {

			/* try to add new entry */
			struct rte_pipeline_table_entry *table_entry = NULL;

			uint64_t dropmask =
				pkt_miss_cgnapt(p_nat->key_ptrs[pkt_num], pkt,
						&table_entry,
						&p_nat->valid_packets, pkt_num,
						(void *)p_nat);

			if (!table_entry) {
				/* ICMP Error message generation for
				* Destination Host unreachable
				*/
				if (protocol == IP_PROTOCOL_ICMP) {
					cgnapt_icmp_pkt = pkt;
					send_icmp_dest_unreachable_msg();
				}

				/* Drop packet by adding to invalid pkt mask */

				p_nat->invalid_packets |= dropmask;

				#ifdef CGNAPT_DEBUGGING
				if (p_nat->kpc2++ < 5) {
					printf("in_ah Th: %d",
							 p_nat->pipeline_num);
					print_key(p_nat->key_ptrs[pkt_num]);
				}
				#endif

				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount3++;
				#endif
				continue;
			}

			entry = (struct cgnapt_table_entry *)table_entry;
		} else {
			/* entry found for this packet */
			entry = &napt_hash_tbl_entries[hash_table_entry];
		}

		/*  apply napt and mac changes */

		p_nat->entries[pkt_num] = &(entry->head);

		uint32_t *src_addr =
			RTE_MBUF_METADATA_UINT32_PTR(pkt, SRC_ADR_OFST_IP4);
		uint32_t *dst_addr =
			RTE_MBUF_METADATA_UINT32_PTR(pkt, DST_ADR_OFST_IP4);
		uint16_t src_port_offset = 0;
		uint16_t dst_port_offset = 0;
		uint16_t *src_port;
		uint16_t *dst_port;

		#if 0
		if ((protocol == IP_PROTOCOL_TCP)
			|| (protocol == IP_PROTOCOL_UDP)) {
			src_port_offset = SRC_PRT_OFST_IP4_TCP;
			dst_port_offset = DST_PRT_OFST_IP4_TCP;
		} else if (protocol == IP_PROTOCOL_ICMP) {
			/* Identifier */
			src_port_offset = MBUF_HDR_ROOM +
						ETH_HDR_SIZE +
						IP_HDR_SIZE + 4;
			/*Sequence number */
			dst_port_offset = MBUF_HDR_ROOM +
						ETH_HDR_SIZE +
						IP_HDR_SIZE + 6;
		}
		#endif

		switch (protocol) {
		case IP_PROTOCOL_TCP:
			src_port_offset = SRC_PRT_OFST_IP4_TCP;
			dst_port_offset = DST_PRT_OFST_IP4_TCP;
			src_port = RTE_MBUF_METADATA_UINT16_PTR(pkt,
						src_port_offset);
			dst_port = RTE_MBUF_METADATA_UINT16_PTR(pkt,
						dst_port_offset);

			#ifdef CT_CGNAT
			if ((rte_be_to_cpu_16(*src_port) == 21) ||
				rte_be_to_cpu_16(*dst_port) == 21) {

				//To process CT , pkt_mask does it need
				//to be complemented ??
				#ifdef ALGDBG
				printf("cgnapt_ct_process: pkt_mask: "
					"% "PRIu64", pkt_num: %d\n",
					pkt_mask, pkt_num);
				#endif

				pkt_mask =  cgnapt_ct_process(
						cgnat_cnxn_tracker, pkts,
						pkt_mask, &ct_helper);
			}
			#endif
		break;
		case IP_PROTOCOL_UDP:
			src_port_offset = SRC_PRT_OFST_IP4_TCP;
			dst_port_offset = DST_PRT_OFST_IP4_TCP;
			src_port = RTE_MBUF_METADATA_UINT16_PTR(pkt,
					src_port_offset);
			dst_port = RTE_MBUF_METADATA_UINT16_PTR(pkt,
					dst_port_offset);
		break;
		case IP_PROTOCOL_ICMP:
			/* Identifier */
			src_port_offset = MBUF_HDR_ROOM + ETH_HDR_SIZE +
						IP_HDR_SIZE + 4;
			/*Sequence number */
			dst_port_offset = MBUF_HDR_ROOM + ETH_HDR_SIZE +
						IP_HDR_SIZE + 6;
			src_port = RTE_MBUF_METADATA_UINT16_PTR(pkt,
					src_port_offset);
			dst_port = RTE_MBUF_METADATA_UINT16_PTR(pkt,
					dst_port_offset);
		break;
		}


		uint8_t *eth_dest =
			RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
		uint8_t *eth_src =
			RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM + 6);

		if (entry->data.ttl == NAPT_ENTRY_STALE)
			entry->data.ttl = NAPT_ENTRY_VALID;

		struct ether_addr hw_addr;
		uint32_t dest_address = 0;
		/*Multiport Changes */
		uint32_t nhip = 0;
		uint32_t ret;

		{

			/* Egress */
			if (unlikely(protocol == IP_PROTOCOL_UDP
				&& rte_be_to_cpu_16(*dst_port) == 53)) {
				p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount6++;
				#endif
				continue;
			}
		}

		dest_address = rte_bswap32(*dst_addr);
		struct arp_entry_data *ret_arp_data = NULL;
		uint64_t start, end;
		ret_arp_data = get_dest_mac_addr_port(dest_address, &dest_if, (struct ether_addr *)eth_dest);
		*outport_id = p_nat->outport_id[dest_if];
		if (arp_cache_dest_mac_present(dest_if)) {
			ether_addr_copy(get_link_hw_addr(dest_if), (struct ether_addr *)eth_src);
			arp_data_ptr[dest_if]->n_last_update = time(NULL);
		
			if (ret_arp_data && ret_arp_data->num_pkts) {
				printf("sending buffered packets\n");
				p_nat->naptedPktCount += ret_arp_data->num_pkts;
				arp_send_buffered_pkts(ret_arp_data,
					 (struct ether_addr *)eth_dest, *outport_id);
			}

		} else {

			if (unlikely(ret_arp_data == NULL)) {

				printf("%s: ARP Not Found, nhip: %x, "
				"outport_id: %d\n", __func__, nhip,
				*outport_id);

				/* Drop the pkt */
				p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount4++;
				#endif
				continue;

			}

			if (ret_arp_data->status == INCOMPLETE ||
				ret_arp_data->status == PROBE) {
				if (ret_arp_data->num_pkts >= NUM_DESC) {
					/* Drop the pkt */
					p_nat->invalid_packets |= pkt_mask;
					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					continue;
				} else {
					arp_pkts_mask |= pkt_mask;
					arp_queue_unresolved_packet(ret_arp_data, pkt);
					continue;
				}
			}
		}

		{
			/* Egress */
			*src_addr = rte_bswap32(entry->data.pub_ip);

			#ifdef NAT_ONLY_CONFIG_REQ
			if (!nat_only_config_flag) {
			#endif
				*src_port = rte_bswap16(entry->data.pub_port);
			#ifdef NAT_ONLY_CONFIG_REQ
			}
			#endif

			#ifdef SIP_ALG
			uint16_t rtp_port = 0, rtcp_port = 0;
			struct cgnapt_table_entry *entry_ptr1 = NULL,
				*entry_ptr2 = NULL, *entry_ptr3 = NULL,
				*entry_ptr4 = NULL;

			if (unlikely(protocol == IP_PROTOCOL_UDP
				&& (rte_be_to_cpu_16(*dst_port) == 5060
				|| rte_be_to_cpu_16(*src_port) == 5060))) {

				int ret = natSipAlgGetAudioPorts(pkt,
						&rtp_port, &rtcp_port);
			/* Commented code may be required for future usage,
			 * Please keep it
			 */
				#if 0
				if (ret < 0) {
					printf("%s: Wrong SIP ALG packet1\n",
						__func__);
					p_nat->invalid_packets |= pkt_mask;

					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					continue;
				}
				#endif

				if (ret >= 0 && rtp_port != 0) {
				struct pipeline_cgnapt_entry_key rtp_key;
				rtp_key.ip = entry->data.u.prv_ip;
				rtp_key.port = rtp_port;
				rtp_key.pid = entry->data.prv_phy_port;

				if (add_dynamic_cgnapt_entry_alg(
				(struct pipeline *)p_nat, &rtp_key,
				&entry_ptr1, &entry_ptr2) == 0) {
					printf("%s: Wrong SIP ALG packet2\n",
						__func__);
					p_nat->invalid_packets |= pkt_mask;

					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					continue;
					}
				}

				if (ret >= 0 && rtcp_port != 0) {
				struct pipeline_cgnapt_entry_key rtcp_key;
				rtcp_key.ip = entry->data.u.prv_ip;
				rtcp_key.port = rtcp_port;
				rtcp_key.pid = entry->data.prv_phy_port;

				if (add_dynamic_cgnapt_entry_alg(
				(struct pipeline *)p_nat, &rtcp_key,
				&entry_ptr3, &entry_ptr4) == 0) {

					printf("%s: Wrong SIP ALG packet3\n",
						__func__);
					p_nat->invalid_packets |= pkt_mask;

					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					continue;
				}

				}
				//if(entry_ptr1 != NULL && entry_ptr3 != NULL)
				if (sip_alg_dpi(pkt, PRIVATE,
					entry->data.pub_ip,
					entry->data.pub_port,
					entry->data.u.prv_ip,
					entry->data.prv_port,
					(rtp_port == 0) ? 0 :
					entry_ptr1->data.pub_port,
					(rtcp_port == 0) ? 0 :
					entry_ptr3->data.pub_port) == 0) {

					printf("%s: Wrong SIP ALG packet4\n",
						__func__);
					p_nat->invalid_packets |= pkt_mask;

					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					continue;
				}
			}
			#endif /* SIP_ALG */

		#ifdef FTP_ALG
		if ((rte_be_to_cpu_16(*src_port) == 21) ||
			rte_be_to_cpu_16(*dst_port) == 21) {

			int32_t ct_position =
				cgnat_cnxn_tracker->positions[pkt_num];
			#ifdef ALGDBG
			printf("@CGNAT-pkt4work ct_position :%d, pkt_num %d "
			"pkt_mask = %" PRIu64 "\n", ct_position,
			pkt_num, pkt_mask);
			#endif

		if (ct_position < 0){
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;
			continue;
		}
			if (cgnat_cnxn_tracker->hash_table_entries[ct_position].
				alg_bypass_flag != BYPASS){

				struct pipeline_cgnapt_entry_key
					data_channel_entry_key;
				/*enable ALG DPI */
				data_channel_entry_key.ip =
					entry->data.pub_ip;
				data_channel_entry_key.port =
					entry->data.pub_port;
				data_channel_entry_key.pid = 0xffff;

				ftp_alg_dpi(p_nat, &data_channel_entry_key,
					pkt, cgnat_cnxn_tracker, ct_position,
					PRIVATE);

			}
		}
		#endif
		p_nat->enaptedPktCount++;
		}

		p_nat->naptedPktCount++;

		#ifdef CHECKSUM_REQ
			if (p_nat->hw_checksum_reqd)
				hw_checksum(pkt, pkt_type);
			else
				sw_checksum(pkt, pkt_type);
		#endif
	}
}

/**
 * NAPT function for IPv4 public traffic which handles 4 pkts
 *
 * @param pkts
 *  A pointer to array of packets mbuf
 * @param in_pkt_num
 *  Starting pkt number of pkts
 * @param arg
 *  Void pointer
 * @param p_nat
 *  A pointer to main CGNAPT structure
 *
 */
void
pkt4_work_cgnapt_ipv4_pub(
	struct rte_mbuf **pkts,
	uint32_t in_pkt_num,
	__rte_unused void *arg,
	struct pipeline_cgnapt *p_nat)
{
	#ifdef CT_CGNAT
	struct rte_CT_helper ct_helper;
	memset(&ct_helper, 0, sizeof(struct rte_CT_helper));
	#endif
	struct rte_mbuf *pkt;
	uint8_t i;
	uint8_t pkt_num;
	enum PKT_TYPE pkt_type = PKT_TYPE_IPV4;

	for (i = 0; i < 4; i++) {
		pkt_num = in_pkt_num + i;
		pkt = pkts[pkt_num];

		/* index into hash table entries */
		int hash_table_entry = p_nat->lkup_indx[pkt_num];
		/*bitmask representing only this packet */
		uint64_t pkt_mask = 1LLU << pkt_num;

		uint8_t protocol = RTE_MBUF_METADATA_UINT8(pkt, PROT_OFST_IP4);

		uint32_t dest_if = 0xff;	/* Added for Multiport */
		uint16_t *outport_id =
			RTE_MBUF_METADATA_UINT16_PTR(pkt, cgnapt_meta_offset);

		struct cgnapt_table_entry *entry = NULL;

		if (hash_table_entry < 0) {

			/* try to add new entry */
			struct rte_pipeline_table_entry *table_entry = NULL;

			uint64_t dropmask =
				pkt_miss_cgnapt(p_nat->key_ptrs[pkt_num], pkt,
						&table_entry,
						&p_nat->valid_packets, pkt_num,
						(void *)p_nat);

			if (!table_entry) {
				/* ICMP Error message generation for
				* Destination Host unreachable
				*/
				if (protocol == IP_PROTOCOL_ICMP) {
					cgnapt_icmp_pkt = pkt;
					send_icmp_dest_unreachable_msg();
				}

				/* Drop packet by adding to invalid pkt mask */

				p_nat->invalid_packets |= dropmask;

				#ifdef CGNAPT_DEBUGGING
				if (p_nat->kpc2++ < 5) {
					printf("in_ah Th: %d",
							 p_nat->pipeline_num);
					print_key(p_nat->key_ptrs[pkt_num]);
				}
				#endif

				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount3++;
				#endif
				printf("causing p_nat->naptDroppedPktCount3\n");
				continue;
			}

			entry = (struct cgnapt_table_entry *)table_entry;
		} else {
			/* entry found for this packet */
			entry = &napt_hash_tbl_entries[hash_table_entry];
		}

		/*  apply napt and mac changes */

		p_nat->entries[pkt_num] = &(entry->head);

		uint32_t *dst_addr =
			RTE_MBUF_METADATA_UINT32_PTR(pkt, DST_ADR_OFST_IP4);
		uint16_t src_port_offset = 0;
		uint16_t dst_port_offset = 0;

		if ((protocol == IP_PROTOCOL_TCP)
			|| (protocol == IP_PROTOCOL_UDP)) {
			src_port_offset = SRC_PRT_OFST_IP4_TCP;
			dst_port_offset = DST_PRT_OFST_IP4_TCP;
		} else if (protocol == IP_PROTOCOL_ICMP) {
			/* Identifier */
			src_port_offset = MBUF_HDR_ROOM +
						ETH_HDR_SIZE +
						IP_HDR_SIZE + 4;
			/*Sequence number */
			dst_port_offset = MBUF_HDR_ROOM +
						ETH_HDR_SIZE +
						IP_HDR_SIZE + 6;
		}

		uint16_t *src_port =
			RTE_MBUF_METADATA_UINT16_PTR(pkt, src_port_offset);
		uint16_t *dst_port =
			RTE_MBUF_METADATA_UINT16_PTR(pkt, dst_port_offset);

		uint8_t *eth_dest =
			RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
		uint8_t *eth_src =
			RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM + 6);

		if (entry->data.ttl == NAPT_ENTRY_STALE)
			entry->data.ttl = NAPT_ENTRY_VALID;

		struct ether_addr hw_addr;
		uint32_t dest_address = 0;
		/* Multiport Changes */
		uint32_t nhip = 0;
		uint32_t ret;

		/* Ingress */
		{
			if (unlikely(protocol == IP_PROTOCOL_UDP
				&& rte_be_to_cpu_16(*src_port) == 53)) {
				p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;
				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount6++;
				#endif
				continue;
			}
		}
		dest_address = entry->data.u.prv_ip;
		struct arp_entry_data *ret_arp_data = NULL;
		ret_arp_data = get_dest_mac_addr_port(dest_address, &dest_if, (struct ether_addr *)eth_dest);
		*outport_id = p_nat->outport_id[dest_if];

	if (arp_cache_dest_mac_present(dest_if)) {
		ether_addr_copy(get_link_hw_addr(dest_if), (struct ether_addr *)eth_src);
		arp_data_ptr[dest_if]->n_last_update = time(NULL);
		
		if (ret_arp_data && ret_arp_data->num_pkts) {
			printf("sending buffered packets\n");
			p_nat->naptedPktCount += ret_arp_data->num_pkts;
			arp_send_buffered_pkts(ret_arp_data,
				 (struct ether_addr *)eth_dest, *outport_id);
		}

	} else {

		if (unlikely(ret_arp_data == NULL)) {

			printf("%s: NHIP Not Found, nhip: %x, "
			"outport_id: %d\n", __func__, nhip,
			*outport_id);

			/* Drop the pkt */
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;

			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount4++;
			#endif
			continue;
		}

		if (ret_arp_data->status == INCOMPLETE ||
			ret_arp_data->status == PROBE) {
			if (ret_arp_data->num_pkts >= NUM_DESC) {
				/* Drop the pkt */
				p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount4++;
				#endif
				continue;
			} else {
				arp_pkts_mask |= pkt_mask;
				arp_queue_unresolved_packet(ret_arp_data, pkt);
				continue;
			}
		}
	}

		{
			/* Ingress */

			*dst_addr = rte_bswap32(entry->data.u.prv_ip);
			if (protocol == IP_PROTOCOL_ICMP) {
				/* Query ID reverse translation done here */
				*src_port = rte_bswap16(entry->data.prv_port);
				/* dont care sequence num */
			} else {
			#ifdef NAT_ONLY_CONFIG_REQ
				if (!nat_only_config_flag) {
			#endif
					*dst_port =
					rte_bswap16(entry->data.prv_port);
			#ifdef NAT_ONLY_CONFIG_REQ
				}
				#endif

			#ifdef CT_CGNAT
			if ((rte_be_to_cpu_16(*src_port) == 21) ||
				rte_be_to_cpu_16(*dst_port) == 21) {
				pkt_mask = cgnapt_ct_process(
					cgnat_cnxn_tracker, pkts,
				pkt_mask, &ct_helper);
			}
			#endif
			}

			#ifdef SIP_ALG
			uint16_t rtp_port = 0, rtcp_port = 0;
			struct cgnapt_table_entry *entry_ptr1 = NULL,
				*entry_ptr3 = NULL;
			/* Commented code may be required for future usage,
			 * Please keep it
			 */
			#if 0
			struct cgnapt_table_entry *entry_ptr2 = NULL,
					*entry_ptr4 = NULL;
			#endif

			if (unlikely(protocol == IP_PROTOCOL_UDP
				&& (rte_be_to_cpu_16(*dst_port) == 5060
				|| rte_be_to_cpu_16(*src_port) == 5060))) {
			/* Commented code may be required for future usage,
			 * Please keep it
			 */
			#if 0
				int ret = natSipAlgGetAudioPorts(pkt,
					&rtp_port, &rtcp_port);
				if (ret < 0) {
					printf("%s: Wrong SIP ALG packet1\n",
						__func__);
					p_nat->invalid_packets |= pkt_mask;

					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					return;
				}

				if (rtp_port != 0) {
				struct pipeline_cgnapt_entry_key rtp_key;
				rtp_key.ip = entry->data.pub_ip;
				rtp_key.port = rtp_port;
				rtp_key.pid = 0xffff;

				if (retrieve_cgnapt_entry_alg(&rtp_key,
					&entry_ptr1, &entry_ptr2) == 0) {
					printf("%s: Wrong SIP ALG packet2\n",
					__func__);
					p_nat->invalid_packets |= pkt_mask;

					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					return;
					}
				}

				if (rtcp_port != 0) {
				struct pipeline_cgnapt_entry_key rtcp_key;
				rtcp_key.ip = entry->data.pub_ip;
				rtcp_key.port = rtcp_port;
				rtcp_key.pid = 0xffff;

				if (retrieve_cgnapt_entry_alg(&rtcp_key,
					&entry_ptr3, &entry_ptr4) == 0) {
					printf("%s: Wrong SIP ALG packet3\n",
						__func__);
					p_nat->invalid_packets |= pkt_mask;
					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					return;
				}

				}
			#endif
				if (sip_alg_dpi(pkt, PUBLIC,
					entry->data.u.prv_ip,
					entry->data.prv_port,
					entry->data.pub_ip,
					entry->data.pub_port,
					(rtp_port == 0) ? 0 :
					entry_ptr1->data.prv_port,
					(rtcp_port == 0) ? 0 :
					entry_ptr3->data.prv_port) == 0) {

					printf("%s: Wrong SIP ALG packet4\n",
						__func__);
					p_nat->invalid_packets |= pkt_mask;

					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					continue;
				}
			}
			#endif /* SIP_ALG */

		#ifdef FTP_ALG
		if ((rte_be_to_cpu_16(*src_port) == 21) ||
			rte_be_to_cpu_16(*dst_port) == 21) {

			int32_t ct_position =
				cgnat_cnxn_tracker->positions[pkt_num];
		if (ct_position < 0){
			p_nat->invalid_packets |= pkt_mask;

			p_nat->naptDroppedPktCount++;
			continue;
		}
			if (cgnat_cnxn_tracker->hash_table_entries
				[ct_position].alg_bypass_flag != BYPASS){

				struct pipeline_cgnapt_entry_key
					data_channel_entry_key;

				/*enable ALG DPI */
				data_channel_entry_key.ip =
					entry->data.pub_ip;
				data_channel_entry_key.port =
					entry->data.pub_port;
				data_channel_entry_key.pid = 0xffff;

				ftp_alg_dpi(p_nat, &data_channel_entry_key,
						pkt, cgnat_cnxn_tracker,
						ct_position, PUBLIC);

			}
		}
		#endif
			p_nat->inaptedPktCount++;
		}

		p_nat->naptedPktCount++;

		#ifdef CHECKSUM_REQ
			if (p_nat->hw_checksum_reqd)
				hw_checksum(pkt, pkt_type);
			else
				sw_checksum(pkt, pkt_type);
		#endif
	}
}

/**
 * NAPT key calculation function for IPv6 private traffic
 * which handles 1 pkt
 *
 * @param pkt
 *  A pointer to array of packets mbuf
 * @param in_pkt_num
 *  Pkt number of pkts
 * @param arg
 *  Void pointer
 * @param p_nat
 *  A pointer to main CGNAPT structure
 *
 */
void
pkt_work_cgnapt_key_ipv6_prv(
	struct rte_mbuf *pkt,
	uint32_t pkt_num,
	__rte_unused void *arg,
	struct pipeline_cgnapt *p_nat)
{
	/* Egress */
	p_nat->receivedPktCount++;

	/* bitmask representing only this packet */
	uint64_t pkt_mask = 1LLU << pkt_num;

	uint8_t protocol = RTE_MBUF_METADATA_UINT8(pkt, PROT_OFST_IP6);
	uint32_t *src_addr = RTE_MBUF_METADATA_UINT32_PTR(pkt,
				SRC_ADR_OFST_IP6);
	uint16_t src_port = RTE_MBUF_METADATA_UINT16(pkt, SRC_PRT_OFST_IP6);

	uint16_t phy_port = pkt->port;
	struct pipeline_cgnapt_entry_key key;

	memset(&key, 0, sizeof(struct pipeline_cgnapt_entry_key));

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt, pkt_mask, p_nat))
			return;
	}

	switch (protocol) {
	case IP_PROTOCOL_UDP:
	{
		#ifdef PCP_ENABLE
		if (pcp_enable) {
		struct udp_hdr *udp;

		udp = (struct udp_hdr *)
			RTE_MBUF_METADATA_UINT8_PTR(pkt,
						IPV6_UDP_OFST);

		if (rte_bswap16(udp->dst_port) ==
			PCP_SERVER_PORT) {
			handle_pcp_req(pkt, IPV6_SZ, p_nat);
			p_nat->invalid_packets |= pkt_mask;
			return;
		}
		}
		#endif
	}
	case IP_PROTOCOL_TCP:
	case IP_PROTOCOL_ICMP:
		/*we don't need icmp check in ipv6 */
	break;

	default:
		printf("wrong protocol: %d\n", protocol);
		/* remember invalid packets to be dropped */
		p_nat->invalid_packets |= pkt_mask;
		p_nat->naptDroppedPktCount++;

		#ifdef CGNAPT_DEBUGGING
		p_nat->naptDroppedPktCount2++;
		#endif
		return;
	}

	key.pid = phy_port;
	key.ip = rte_bswap32(src_addr[3]);
	key.port = rte_bswap16(src_port);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key.port = 0xffff;
	#endif

	memcpy(&p_nat->keys[pkt_num], &key,
			 sizeof(struct pipeline_cgnapt_entry_key));
	p_nat->key_ptrs[pkt_num] = &p_nat->keys[pkt_num];
}

/**
 * NAPT key calculation function for IPv6 public traffic
 * which handles 1 pkt
 *
 * @param pkt
 *  A pointer to array of packets mbuf
 * @param in_pkt_num
 *  Pkt number of pkts
 * @param arg
 *  Void pointer
 * @param p_nat
 *  A pointer to main CGNAPT structure
 *
 */
void
pkt_work_cgnapt_key_ipv6_pub(
	struct rte_mbuf *pkt,
	uint32_t pkt_num,
	__rte_unused void *arg,
	struct pipeline_cgnapt *p_nat)
{

	/* Ingress */
	p_nat->receivedPktCount++;

	/* bitmask representing only this packet */
	uint64_t pkt_mask = 1LLU << pkt_num;

	uint8_t protocol = RTE_MBUF_METADATA_UINT8(pkt, PROT_OFST_IP4);

	uint32_t *dst_addr = RTE_MBUF_METADATA_UINT32_PTR(pkt,
				DST_ADR_OFST_IP4);
	uint16_t dst_port = RTE_MBUF_METADATA_UINT16(pkt,
				DST_PRT_OFST_IP4_TCP);

	struct pipeline_cgnapt_entry_key key;

	memset(&key, 0, sizeof(struct pipeline_cgnapt_entry_key));

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt, pkt_mask, p_nat))
			return;
	}

	switch (protocol) {

	case IP_PROTOCOL_UDP:
	case IP_PROTOCOL_TCP:
	case IP_PROTOCOL_ICMP:
		/*we don't need icmp check in ipv6 */
	break;

	default:
		/* remember invalid packets to be dropped */
		p_nat->invalid_packets |= pkt_mask;
		p_nat->naptDroppedPktCount++;

		#ifdef CGNAPT_DEBUGGING
		p_nat->naptDroppedPktCount2++;
		#endif
		return;
	}

	key.pid = 0xffff;
	key.ip = rte_bswap32(dst_addr[0]);
	key.port = rte_bswap16(dst_port);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key.port = 0xffff;
	#endif

	memcpy(&p_nat->keys[pkt_num], &key,
			 sizeof(struct pipeline_cgnapt_entry_key));
	p_nat->key_ptrs[pkt_num] = &p_nat->keys[pkt_num];
}

/**
 * NAPT key calculation function for IPv6 private traffic
 * which handles 4 pkts
 *
 * @param pkt
 *  A pointer to array of packets mbuf
 * @param in_pkt_num
 *  Starting pkt number of pkts
 * @param arg
 *  Void pointer
 * @param p_nat
 *  A pointer to main CGNAPT structure
 *
 */
void
pkt4_work_cgnapt_key_ipv6_prv(
	struct rte_mbuf **pkt,
	uint32_t pkt_num,
	__rte_unused void *arg,
	struct pipeline_cgnapt *p_nat)
{
	p_nat->receivedPktCount += 4;

	/* bitmask representing only this packet */
	uint64_t pkt_mask0 = 1LLU << pkt_num;
	uint64_t pkt_mask1 = 1LLU << (pkt_num + 1);
	uint64_t pkt_mask2 = 1LLU << (pkt_num + 2);
	uint64_t pkt_mask3 = 1LLU << (pkt_num + 3);

	uint8_t protocol0 = RTE_MBUF_METADATA_UINT8(pkt[0],
				PROT_OFST_IP6);
	uint8_t protocol1 = RTE_MBUF_METADATA_UINT8(pkt[1],
				PROT_OFST_IP6);
	uint8_t protocol2 = RTE_MBUF_METADATA_UINT8(pkt[2],
				PROT_OFST_IP6);
	uint8_t protocol3 = RTE_MBUF_METADATA_UINT8(pkt[3],
				PROT_OFST_IP6);

	uint32_t *src_addr0 = RTE_MBUF_METADATA_UINT32_PTR(pkt[0],
				SRC_ADR_OFST_IP6);
	uint32_t *src_addr1 = RTE_MBUF_METADATA_UINT32_PTR(pkt[1],
				SRC_ADR_OFST_IP6);
	uint32_t *src_addr2 = RTE_MBUF_METADATA_UINT32_PTR(pkt[2],
				SRC_ADR_OFST_IP6);
	uint32_t *src_addr3 = RTE_MBUF_METADATA_UINT32_PTR(pkt[3],
				SRC_ADR_OFST_IP6);

	uint16_t src_port0 = RTE_MBUF_METADATA_UINT16(pkt[0],
				SRC_PRT_OFST_IP6);
	uint16_t src_port1 = RTE_MBUF_METADATA_UINT16(pkt[1],
				SRC_PRT_OFST_IP6);
	uint16_t src_port2 = RTE_MBUF_METADATA_UINT16(pkt[2],
				SRC_PRT_OFST_IP6);
	uint16_t src_port3 = RTE_MBUF_METADATA_UINT16(pkt[3],
				SRC_PRT_OFST_IP6);

	uint16_t phy_port0 = pkt[0]->port;
	uint16_t phy_port1 = pkt[1]->port;
	uint16_t phy_port2 = pkt[2]->port;
	uint16_t phy_port3 = pkt[3]->port;

	struct pipeline_cgnapt_entry_key key0;
	struct pipeline_cgnapt_entry_key key1;
	struct pipeline_cgnapt_entry_key key2;
	struct pipeline_cgnapt_entry_key key3;

	memset(&key0, 0, sizeof(struct pipeline_cgnapt_entry_key));
	memset(&key1, 0, sizeof(struct pipeline_cgnapt_entry_key));
	memset(&key2, 0, sizeof(struct pipeline_cgnapt_entry_key));
	memset(&key3, 0, sizeof(struct pipeline_cgnapt_entry_key));



	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt[0]);
	 #endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt[0], pkt_mask0, p_nat))
			goto PKT1;
	}

	switch (protocol0) {

	case IP_PROTOCOL_UDP:
	{
		#ifdef PCP_ENABLE
		if (pcp_enable) {
		struct udp_hdr *udp;

		udp = (struct udp_hdr *)
			RTE_MBUF_METADATA_UINT8_PTR(pkt[0],
						IPV6_UDP_OFST);

		if (rte_bswap16(udp->dst_port) ==
			PCP_SERVER_PORT) {
			handle_pcp_req(pkt[0], IPV6_SZ, p_nat);
			p_nat->invalid_packets |= pkt_mask0;
			goto PKT1;
		}
		}
		#endif
	}
	case IP_PROTOCOL_TCP:
	case IP_PROTOCOL_ICMP:
		 /*we don't need icmp check in ipv6 */
	break;

	default:
		 /* remember invalid packets to be dropped */
		 p_nat->invalid_packets |= pkt_mask0;
		 p_nat->naptDroppedPktCount++;

		 #ifdef CGNAPT_DEBUGGING
		 p_nat->naptDroppedPktCount2++;
		 #endif

		goto PKT1;
	}


	 key0.pid = phy_port0;
	 key0.ip = rte_bswap32(src_addr0[3]);
	 key0.port = rte_bswap16(src_port0);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key0.port = 0xffff;
	#endif

	 memcpy(&p_nat->keys[pkt_num], &key0,
				sizeof(struct pipeline_cgnapt_entry_key));
	 p_nat->key_ptrs[pkt_num] = &p_nat->keys[pkt_num];

 PKT1:
	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt[1]);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt[1], pkt_mask1, p_nat))
			goto PKT2;
	}

	switch (protocol1) {
	case IP_PROTOCOL_UDP:
	{
		#ifdef PCP_ENABLE
		if (pcp_enable) {
		struct udp_hdr *udp;

		udp = (struct udp_hdr *)
			RTE_MBUF_METADATA_UINT8_PTR(pkt[1],
						IPV6_UDP_OFST);

		if (rte_bswap16(udp->dst_port) ==
			PCP_SERVER_PORT) {
			handle_pcp_req(pkt[1], IPV6_SZ, p_nat);
			p_nat->invalid_packets |= pkt_mask1;
			goto PKT2;
		}
		}
		#endif
	}
	case IP_PROTOCOL_TCP:
	case IP_PROTOCOL_ICMP:
		 /*we don't need icmp check in ipv6 */
	break;

	default:
		 /* remember invalid packets to be dropped */
		 p_nat->invalid_packets |= pkt_mask1;
		 p_nat->naptDroppedPktCount++;

		 #ifdef CGNAPT_DEBUGGING
		 p_nat->naptDroppedPktCount2++;
		 #endif

		goto PKT2;
	}

	 key1.pid = phy_port1;
	 key1.ip = rte_bswap32(src_addr1[3]);
	 key1.port = rte_bswap16(src_port1);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key1.port = 0xffff;
	#endif

	 memcpy(&p_nat->keys[pkt_num + 1], &key1,
				sizeof(struct pipeline_cgnapt_entry_key));
	 p_nat->key_ptrs[pkt_num + 1] = &p_nat->keys[pkt_num + 1];

 PKT2:
	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt[2]);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt[2], pkt_mask2, p_nat))
			goto PKT3;
	}

	switch (protocol2) {
	case IP_PROTOCOL_UDP:
	{
		#ifdef PCP_ENABLE
		if (pcp_enable) {
		struct udp_hdr *udp;

		udp = (struct udp_hdr *)
			RTE_MBUF_METADATA_UINT8_PTR(pkt[2],
						IPV6_UDP_OFST);

		if (rte_bswap16(udp->dst_port) ==
			PCP_SERVER_PORT) {
			handle_pcp_req(pkt[2], IPV6_SZ, p_nat);
			p_nat->invalid_packets |= pkt_mask2;
			goto PKT3;
		}
		}
		#endif
	}
	case IP_PROTOCOL_TCP:
	case IP_PROTOCOL_ICMP:
		 /*we don't need icmp check in ipv6 */
	break;

	default:
		 /* remember invalid packets to be dropped */
		 p_nat->invalid_packets |= pkt_mask2;
		 p_nat->naptDroppedPktCount++;

		 #ifdef CGNAPT_DEBUGGING
		 p_nat->naptDroppedPktCount2++;
		 #endif

		goto PKT3;
	}

	 key2.pid = phy_port2;
	 key2.ip = rte_bswap32(src_addr2[3]);
	 key2.port = rte_bswap16(src_port2);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key2.port = 0xffff;
	#endif

	 memcpy(&p_nat->keys[pkt_num + 2], &key2,
				sizeof(struct pipeline_cgnapt_entry_key));
	 p_nat->key_ptrs[pkt_num + 2] = &p_nat->keys[pkt_num + 2];

 PKT3:
	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt[3]);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt[3], pkt_mask3, p_nat))
			return;
	}

	switch (protocol3) {
	case IP_PROTOCOL_UDP:
	{
		#ifdef PCP_ENABLE
		if (pcp_enable) {
		struct udp_hdr *udp;

		udp = (struct udp_hdr *)
			RTE_MBUF_METADATA_UINT8_PTR(pkt[3],
						IPV6_UDP_OFST);

		if (rte_bswap16(udp->dst_port) ==
			PCP_SERVER_PORT) {
			handle_pcp_req(pkt[3], IPV6_SZ, p_nat);
			p_nat->invalid_packets |= pkt_mask3;
			return;
		}
		}
		#endif
	}
	case IP_PROTOCOL_TCP:
	case IP_PROTOCOL_ICMP:
		 /*we don't need icmp check in ipv6 */
	break;

	default:
		 /* remember invalid packets to be dropped */
		 p_nat->invalid_packets |= pkt_mask2;
		 p_nat->naptDroppedPktCount++;

		 #ifdef CGNAPT_DEBUGGING
		 p_nat->naptDroppedPktCount2++;
		 #endif

		return;
	}

	 key3.pid = phy_port3;
	 key3.ip = rte_bswap32(src_addr3[3]);
	 key3.port = rte_bswap16(src_port3);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key3.port = 0xffff;
	#endif

	 memcpy(&p_nat->keys[pkt_num + 3], &key3,
				sizeof(struct pipeline_cgnapt_entry_key));
	 p_nat->key_ptrs[pkt_num + 3] = &p_nat->keys[pkt_num + 3];


}

/**
 * NAPT key calculation function for IPv4 public traffic
 * which handles 4 pkts
 *
 * @param pkt
 *  A pointer to array of packets mbuf
 * @param in_pkt_num
 *  Starting pkt number of pkts
 * @param arg
 *  Void pointer
 * @param p_nat
 *  A pointer to main CGNAPT structure
 *
 */
void
pkt4_work_cgnapt_key_ipv6_pub(
	struct rte_mbuf **pkt,
	uint32_t pkt_num,
	__rte_unused void *arg,
	struct pipeline_cgnapt *p_nat)
{
	p_nat->receivedPktCount += 4;

	/* bitmask representing only this packet */
	uint64_t pkt_mask0 = 1LLU << pkt_num;
	uint64_t pkt_mask1 = 1LLU << (pkt_num + 1);
	uint64_t pkt_mask2 = 1LLU << (pkt_num + 2);
	uint64_t pkt_mask3 = 1LLU << (pkt_num + 3);

	uint8_t protocol0 = RTE_MBUF_METADATA_UINT8(pkt[0],
				PROT_OFST_IP4);
	uint8_t protocol1 = RTE_MBUF_METADATA_UINT8(pkt[1],
				PROT_OFST_IP4);
	uint8_t protocol2 = RTE_MBUF_METADATA_UINT8(pkt[2],
				PROT_OFST_IP4);
	uint8_t protocol3 = RTE_MBUF_METADATA_UINT8(pkt[3],
				PROT_OFST_IP4);

	uint32_t *dst_addr0 = RTE_MBUF_METADATA_UINT32_PTR(pkt[0],
				DST_ADR_OFST_IP4);
	uint32_t *dst_addr1 = RTE_MBUF_METADATA_UINT32_PTR(pkt[1],
				DST_ADR_OFST_IP4);
	uint32_t *dst_addr2 = RTE_MBUF_METADATA_UINT32_PTR(pkt[2],
				DST_ADR_OFST_IP4);
	uint32_t *dst_addr3 = RTE_MBUF_METADATA_UINT32_PTR(pkt[3],
				DST_ADR_OFST_IP4);

	uint16_t dst_port0 = RTE_MBUF_METADATA_UINT16(pkt[0],
				DST_PRT_OFST_IP4_TCP);
	uint16_t dst_port1 = RTE_MBUF_METADATA_UINT16(pkt[1],
				DST_PRT_OFST_IP4_TCP);
	uint16_t dst_port2 = RTE_MBUF_METADATA_UINT16(pkt[2],
				DST_PRT_OFST_IP4_TCP);
	uint16_t dst_port3 = RTE_MBUF_METADATA_UINT16(pkt[3],
				DST_PRT_OFST_IP4_TCP);

	struct pipeline_cgnapt_entry_key key0;
	struct pipeline_cgnapt_entry_key key1;
	struct pipeline_cgnapt_entry_key key2;
	struct pipeline_cgnapt_entry_key key3;

	memset(&key0, 0, sizeof(struct pipeline_cgnapt_entry_key));
	memset(&key1, 0, sizeof(struct pipeline_cgnapt_entry_key));
	memset(&key2, 0, sizeof(struct pipeline_cgnapt_entry_key));
	memset(&key3, 0, sizeof(struct pipeline_cgnapt_entry_key));

/* --0-- */

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt[0]);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt[0], pkt_mask0, p_nat))
			goto PKT1;
	}

	switch (protocol0) {

	case IP_PROTOCOL_TCP:
	case IP_PROTOCOL_UDP:
	case IP_PROTOCOL_ICMP:
		/*we don't need icmp check in ipv6 */
	break;

	default:
		/* remember invalid packets to be dropped */
		p_nat->invalid_packets |= pkt_mask0;
		p_nat->naptDroppedPktCount++;

		#ifdef CGNAPT_DEBUGGING
		p_nat->naptDroppedPktCount2++;
		#endif
		goto PKT1;
	}

	key0.pid = 0xffff;
	key0.ip = rte_bswap32(dst_addr0[0]);
	key0.port = rte_bswap16(dst_port0);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key0.port = 0xffff;
	#endif

	memcpy(&p_nat->keys[pkt_num], &key0,
			 sizeof(struct pipeline_cgnapt_entry_key));
	p_nat->key_ptrs[pkt_num] = &p_nat->keys[pkt_num];


/* --1-- */

PKT1:
	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt[1]);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt[1], pkt_mask1, p_nat))
			goto PKT2;
	}

	switch (protocol1) {

	case IP_PROTOCOL_TCP:
	case IP_PROTOCOL_UDP:
	case IP_PROTOCOL_ICMP:
		/*we don't need icmp check in ipv6 */
	break;

	default:
		/* remember invalid packets to be dropped */
		p_nat->invalid_packets |= pkt_mask1;
		p_nat->naptDroppedPktCount++;

		#ifdef CGNAPT_DEBUGGING
		p_nat->naptDroppedPktCount2++;
		#endif
		goto PKT2;
	}

	key1.pid = 0xffff;
	key1.ip = rte_bswap32(dst_addr1[0]);
	key1.port = rte_bswap16(dst_port1);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key1.port = 0xffff;
	#endif

	memcpy(&p_nat->keys[pkt_num + 1], &key1,
			 sizeof(struct pipeline_cgnapt_entry_key));
	p_nat->key_ptrs[pkt_num + 1] = &p_nat->keys[pkt_num + 1];


/* --2-- */

PKT2:
	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt[2]);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt[2], pkt_mask2, p_nat))
			goto PKT3;
	}

	switch (protocol2) {

	case IP_PROTOCOL_TCP:
	case IP_PROTOCOL_UDP:
	case IP_PROTOCOL_ICMP:
		/*we don't need icmp check in ipv6 */
	break;

	default:
		/* remember invalid packets to be dropped */
		p_nat->invalid_packets |= pkt_mask2;
		p_nat->naptDroppedPktCount++;

		#ifdef CGNAPT_DEBUGGING
		p_nat->naptDroppedPktCount2++;
		#endif
		goto PKT3;
	}

	key2.pid = 0xffff;
	key2.ip = rte_bswap32(dst_addr2[0]);
	key2.port = rte_bswap16(dst_port2);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key2.port = 0xffff;
	#endif

	memcpy(&p_nat->keys[pkt_num + 2], &key2,
			 sizeof(struct pipeline_cgnapt_entry_key));

	p_nat->key_ptrs[pkt_num + 2] = &p_nat->keys[pkt_num + 2];


/* --3-- */

PKT3:
	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 4)
		print_pkt(pkt[3]);
	#endif

	if (enable_hwlb) {
		if (!check_arp_icmp(pkt[3], pkt_mask3, p_nat))
			return;
	}

	switch (protocol3) {

	case IP_PROTOCOL_TCP:
	case IP_PROTOCOL_UDP:
	case IP_PROTOCOL_ICMP:
		/*we don't need icmp check in ipv6 */
	break;

	default:
		/* remember invalid packets to be dropped */
		p_nat->invalid_packets |= pkt_mask3;
		p_nat->naptDroppedPktCount++;

		#ifdef CGNAPT_DEBUGGING
		p_nat->naptDroppedPktCount2++;
		#endif
		return;
	}

	key3.pid = 0xffff;
	key3.ip = rte_bswap32(dst_addr3[0]);
	key3.port = rte_bswap16(dst_port3);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		key3.port = 0xffff;
	#endif

	memcpy(&p_nat->keys[pkt_num + 3], &key3,
			 sizeof(struct pipeline_cgnapt_entry_key));

	p_nat->key_ptrs[pkt_num + 3] = &p_nat->keys[pkt_num + 3];
}

/**
 * NAPT function for IPv6 private traffic which handles 1 pkt
 *
 * @param pkts
 *  A pointer to array of packet mbuf
 * @param in_pkt_num
 *  Pkt number of pkt
 * @param arg
 *  Void pointer
 * @param p_nat
 *  A pointer to main CGNAPT structure
 *
 */
void
pkt_work_cgnapt_ipv6_prv(
	struct rte_mbuf *pkt,
	uint32_t pkt_num,
	__rte_unused void *arg,
	struct pipeline_cgnapt *p_nat)
{
	/* index into hash table entries */
	int hash_table_entry = p_nat->lkup_indx[pkt_num];

	/*bitmask representing only this packet */
	uint64_t pkt_mask = 1LLU << pkt_num;

	uint8_t protocol = RTE_MBUF_METADATA_UINT8(pkt, PROT_OFST_IP6);

	/* Added for Multiport */
	uint32_t dest_if = INVALID_DESTIF;
	uint16_t *outport_id = RTE_MBUF_METADATA_UINT16_PTR(pkt,
				cgnapt_meta_offset);

	struct cgnapt_table_entry *entry = NULL;
	enum PKT_TYPE pkt_type = PKT_TYPE_IPV6to4;

	if (hash_table_entry < 0) {

		/* try to add new entry */
		struct rte_pipeline_table_entry *table_entry = NULL;

		uint64_t dropmask = pkt_miss_cgnapt(p_nat->key_ptrs[pkt_num],
					pkt, &table_entry,
					&p_nat->valid_packets, pkt_num,
					(void *)p_nat);

		if (!table_entry) {
			/* ICMP Error message generation for
			* Destination Host unreachable
			*/
			/* Do we need this check for ipv6? */
			if (protocol == IP_PROTOCOL_ICMP) {
				cgnapt_icmp_pkt = pkt;
				send_icmp_dest_unreachable_msg();
			}

			/* Drop packet by adding to invalid pkt mask */

			p_nat->invalid_packets |= dropmask;

			#ifdef CGNAPT_DEBUGGING
			if (p_nat->kpc2++ < 5) {
				printf("in_ah Th: %d", p_nat->pipeline_num);
				print_key(p_nat->key_ptrs[pkt_num]);
			}
			#endif

			p_nat->naptDroppedPktCount++;

			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount3++;
			#endif

			return;
		}

		entry = (struct cgnapt_table_entry *)table_entry;
	} else {
		/* entry found for this packet */
		entry = &napt_hash_tbl_entries[hash_table_entry];
	}

	/*  apply napt and mac changes */

	p_nat->entries[pkt_num] = &(entry->head);

	struct ipv6_hdr ipv6_hdr;

	struct ether_addr hw_addr;
	uint32_t dest_address = 0;
	uint32_t nhip = 0;
	/* Egress */
	{

		convert_ipv6_to_ipv4(pkt, &ipv6_hdr);

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG == 1)
			printf("pkt_work_cganpt: convert_ipv6_to_ipv4\n");
		#endif

		struct cgnapt_nsp_node *ll = nsp_ll;
		int nsp = 0;

		while (ll != NULL) {
			if (!memcmp
				(&ipv6_hdr.dst_addr[0], &ll->nsp.prefix[0],
				 ll->nsp.depth / 8)) {
				nsp = 1;
				break;
			}
			ll = ll->next;
		}

		if (!nsp
			&& !memcmp(&ipv6_hdr.dst_addr[0], &well_known_prefix[0],
					 12)) {
			nsp = 1;
		}

		if (!nsp) {
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;

			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount5++;
			#endif

			return;
		}

	}

	/* As packet is already converted into IPv4 we must not
	* operate IPv6 offsets on packet
	* Only perform IPv4 operations
	*/

	uint32_t *src_addr =
		RTE_MBUF_METADATA_UINT32_PTR(pkt, SRC_ADR_OFST_IP6t4);
	uint32_t *dst_addr =
		RTE_MBUF_METADATA_UINT32_PTR(pkt, DST_ADR_OFST_IP6t4);
	uint16_t *src_port =
		RTE_MBUF_METADATA_UINT16_PTR(pkt, SRC_PRT_OFST_IP6t4);
	uint16_t *dst_port =
		RTE_MBUF_METADATA_UINT16_PTR(pkt, DST_PRT_OFST_IP6t4);

	uint8_t *eth_dest = RTE_MBUF_METADATA_UINT8_PTR(pkt,
				ETH_OFST_IP6t4);
	uint8_t *eth_src = RTE_MBUF_METADATA_UINT8_PTR(pkt,
				ETH_OFST_IP6t4 + 6);

	if (entry->data.ttl == NAPT_ENTRY_STALE)
		entry->data.ttl = NAPT_ENTRY_VALID;
	{
		/* Egress */
		if (unlikely(protocol == IP_PROTOCOL_UDP
				 && rte_be_to_cpu_16(*dst_port) == 53)) {
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;

			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount6++;
			#endif

			return;
		}

		dest_address = rte_bswap32(*dst_addr);
		/*Multiport Changes */
	uint32_t nhip = 0;
#if 0
	uint32_t ret;
	ret = local_get_nh_ipv4(dest_address, &dest_if, &nhip, p_nat);
	if (!ret) {
		dest_if = get_prv_to_pub_port(&dest_address, IP_VERSION_4);

		if (dest_if == INVALID_DESTIF) {
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;
			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount6++;
			#endif
			return;
		}

		do_local_nh_ipv4_cache(dest_if, p_nat);
	}
#endif
	//	*outport_id = p_nat->outport_id[dest_if];

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG > 2)
			printf("Egress: \tphy_port:%d\t get_prv_to_pub():%d "
			"\tout_port:%d\n", pkt->port,
			dest_if, *outport_id);
		#endif
	}

	#ifdef CGNAPT_DBG_PRNT
	static int static_count;

	if (static_count++ < 10) {
		print_pkt(pkt);
		my_print_entry(entry);
		printf("dest-offset:%d\n", DST_ADR_OFST_IP4);
		printf("dest_add:%x\n", entry->data.u.prv_ip);
		printf("dest_add:%x\n", *dst_addr);
		printf("DST_ADR_OFST_IP6:%d\n", DST_ADR_OFST_IP6);
	}
	#endif

	struct arp_entry_data *ret_arp_data;
	ret_arp_data = get_dest_mac_addr_port(dest_address, &dest_if, (struct ether_addr *)eth_dest);
	*outport_id = p_nat->outport_id[dest_if];
	if (arp_cache_dest_mac_present(dest_if)) {
		ether_addr_copy(get_link_hw_addr(dest_if),
			(struct ether_addr *)eth_src);
		arp_data_ptr[dest_if]->n_last_update = time(NULL);

		if (unlikely(ret_arp_data && ret_arp_data->num_pkts)) {
			printf("sending buffered packets\n");
			p_nat->naptedPktCount += ret_arp_data->num_pkts;
			arp_send_buffered_pkts(ret_arp_data,
				 (struct ether_addr *)eth_dest, *outport_id);

		}
	} else {

		if (unlikely(ret_arp_data == NULL)) {

			printf("%s: NHIP Not Found, nhip:%x , "
			"outport_id: %d\n", __func__, nhip,
			*outport_id);

			/* Drop the pkt */
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;

			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount4++;
			#endif
			return;
		}

		if (ret_arp_data->status == INCOMPLETE ||
			   ret_arp_data->status == PROBE) {
			if (ret_arp_data->num_pkts >= NUM_DESC) {
				/* Drop the pkt */
				p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount4++;
				#endif
				return;
			} else {
				arp_pkts_mask |= pkt_mask;
				arp_queue_unresolved_packet(ret_arp_data, pkt);
				return;
			}
		}
	}

	{
		/* Egress */
		*src_addr = rte_bswap32(entry->data.pub_ip);

		#ifdef NAT_ONLY_CONFIG_REQ
		if (!nat_only_config_flag) {
		#endif
			*src_port = rte_bswap16(entry->data.pub_port);

		#ifdef NAT_ONLY_CONFIG_REQ
		}
		#endif

		p_nat->enaptedPktCount++;
	}

	p_nat->naptedPktCount++;

		#ifdef CHECKSUM_REQ
			if (p_nat->hw_checksum_reqd)
				hw_checksum(pkt, pkt_type);
			else
				sw_checksum(pkt, pkt_type);
		#endif
}


/**
 * NAPT function for IPv6 public traffic which handles 1 pkt
 *
 * @param pkts
 *  A pointer to array of packet mbuf
 * @param in_pkt_num
 *  Pkt number of pkt
 * @param arg
 *  Void pointer
 * @param p_nat
 *  A pointer to main CGNAPT structure
 *
 */
void
pkt_work_cgnapt_ipv6_pub(
	struct rte_mbuf *pkt,
	uint32_t pkt_num,
	__rte_unused void *arg,
	struct pipeline_cgnapt *p_nat)
{

	/* index into hash table entries */
	int hash_table_entry = p_nat->lkup_indx[pkt_num];
	/*bitmask representing only this packet */
	uint64_t pkt_mask = 1LLU << pkt_num;

	uint8_t protocol = RTE_MBUF_METADATA_UINT8(pkt, PROT_OFST_IP4);

	uint32_t dest_if = INVALID_DESTIF;	/* Added for Multiport */
	uint16_t *outport_id =
		RTE_MBUF_METADATA_UINT16_PTR(pkt, cgnapt_meta_offset);
	struct cgnapt_table_entry *entry = NULL;

	enum PKT_TYPE pkt_type = PKT_TYPE_IPV4to6;

	if (hash_table_entry < 0) {

		/* Drop ingress initial traffic */

		p_nat->invalid_packets |= pkt_mask;
		p_nat->naptDroppedPktCount++;

		#ifdef CGNAPT_DEBUGGING
		p_nat->naptDroppedPktCount3++;
		if (p_nat->kpc2++ < 5) {
			printf("in_ah Th: %d", p_nat->pipeline_num);
			print_key(p_nat->key_ptrs[pkt_num]);
		}
		#endif

		return;

	} else {
		/* entry found for this packet */
		entry = &napt_hash_tbl_entries[hash_table_entry];
	}

	/*  apply napt and mac changes */

	p_nat->entries[pkt_num] = &(entry->head);
	if (entry->data.type != CGNAPT_ENTRY_IPV6) {
		p_nat->invalid_packets |= pkt_mask;
		p_nat->naptDroppedPktCount++;
		return;
	}

	struct ipv4_hdr ipv4_hdr;
	uint16_t *src_port =
		RTE_MBUF_METADATA_UINT16_PTR(pkt, SRC_PRT_OFST_IP4_TCP);

	uint8_t *eth_dest = RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
	uint8_t *eth_src = RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM + 6);

	if (entry->data.ttl == NAPT_ENTRY_STALE)
		entry->data.ttl = NAPT_ENTRY_VALID;

	struct ether_addr hw_addr;
	uint8_t dest_addr_ipv6[16];
	uint8_t nh_ipv6[16];

	/* Ingress */
	{

		if (unlikely(protocol == IP_PROTOCOL_UDP
				 && rte_be_to_cpu_16(*src_port) == 53)) {
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;
			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount6++;
			#endif
			return;
		}
	}
		memcpy(&dest_addr_ipv6[0], &entry->data.u.prv_ipv6[0], 16);
		uint8_t nhipv6[16];
#if 0
		int ret;
		ret = local_get_nh_ipv6(&dest_addr_ipv6[0], &dest_if,
				&nhipv6[0], p_nat);
		if (!ret) {
			dest_if = get_prv_to_pub_port((uint32_t *)
					&dest_addr_ipv6[0],
					IP_VERSION_6);

		if (dest_if == INVALID_DESTIF) {
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;
			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount6++;
			#endif
			return;
		}

			do_local_nh_ipv6_cache(dest_if, p_nat);
		}
		*outport_id = p_nat->outport_id[dest_if];
	}

	#ifdef CGNAPT_DEBUGGING
	static int static_count;

	if (static_count++ < 10) {
		print_pkt(pkt);
		my_print_entry(entry);
		printf("dest-offset:%d\n", DST_ADR_OFST_IP4);
		printf("dest_add:%x\n", entry->data.u.prv_ip);
		printf("DST_ADR_OFST_IP6:%d\n", DST_ADR_OFST_IP6);
	}
	#endif
#endif
	memset(nh_ipv6, 0, 16);
	struct nd_entry_data *ret_nd_data = NULL;
	ret_nd_data = get_dest_mac_address_ipv6_port(
                &dest_addr_ipv6[0],
                &dest_if,
                (struct ether_addr *)eth_dest,
                &nh_ipv6[0]);

	*outport_id = p_nat->outport_id[dest_if];

	if (nd_cache_dest_mac_present(dest_if)) {
		ether_addr_copy(get_link_hw_addr(dest_if),
			(struct ether_addr *)eth_src);
		nd_data_ptr[dest_if]->n_last_update = time(NULL);

		if (unlikely(ret_nd_data && ret_nd_data->num_pkts)) {
			printf("sending buffered packets\n");
			p_nat->naptedPktCount += ret_nd_data->num_pkts;
			nd_send_buffered_pkts(ret_nd_data,
				 (struct ether_addr *)eth_dest, *outport_id);

		}
	} else {
		if (unlikely(ret_nd_data == NULL)) {

			printf("%s: NHIP Not Found, "
			"outport_id: %d\n", __func__,
			*outport_id);

			/* Drop the pkt */
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;

			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount4++;
			#endif
			return;
		}

		if (ret_nd_data->status == INCOMPLETE ||
			   ret_nd_data->status == PROBE) {
			if (ret_nd_data->num_pkts >= NUM_DESC) {
				/* Drop the pkt */
				p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount4++;
				#endif
				return;
			} else {
				arp_pkts_mask |= pkt_mask;
				nd_queue_unresolved_packet(ret_nd_data, pkt);
				return;
			}
		}

	}

	/* Ingress */
	{

		convert_ipv4_to_ipv6(pkt, &ipv4_hdr);

		/* Ethernet MTU check */
		if ((rte_pktmbuf_data_len(pkt) - 14) > 1500) {
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;
			return;
		}
		uint32_t *dst_addr =
			RTE_MBUF_METADATA_UINT32_PTR(pkt, DST_ADR_OFST_IP4t6);
		uint16_t *dst_port =
			RTE_MBUF_METADATA_UINT16_PTR(pkt, DST_PRT_OFST_IP4t6);

		memcpy((uint8_t *) &dst_addr[0], &entry->data.u.prv_ipv6[0],
				 16);

		#ifdef NAT_ONLY_CONFIG_REQ
		if (!nat_only_config_flag) {
		#endif
			*dst_port = rte_bswap16(entry->data.prv_port);

		#ifdef NAT_ONLY_CONFIG_REQ
		}
		#endif

		p_nat->inaptedPktCount++;
	}

	p_nat->naptedPktCount++;

		#ifdef CHECKSUM_REQ
			if (p_nat->hw_checksum_reqd)
				hw_checksum(pkt, pkt_type);
			else
				sw_checksum(pkt, pkt_type);
		#endif
}


/**
 * NAPT function for IPv6 private traffic which handles 4 pkts
 *
 * @param pkts
 *  A pointer to array of packets mbuf
 * @param in_pkt_num
 *  Starting pkt number of pkts
 * @param arg
 *  Void pointer
 * @param p_nat
 *  A pointer to main CGNAPT structure
 *
 */
void
pkt4_work_cgnapt_ipv6_prv(
	struct rte_mbuf **pkts,
	uint32_t in_pkt_num,
	__rte_unused void *arg,
	struct pipeline_cgnapt *p_nat)
{
	struct rte_mbuf *pkt;
	uint8_t i;
	uint8_t pkt_num;

	enum PKT_TYPE pkt_type = PKT_TYPE_IPV6to4;

	for (i = 0; i < 4; i++) {
		pkt_num = in_pkt_num + i;
		pkt = pkts[i];

		/* index into hash table entries */
		int hash_table_entry = p_nat->lkup_indx[pkt_num];
		/*bitmask representing only this packet */
		uint64_t pkt_mask = 1LLU << pkt_num;

		uint8_t protocol = RTE_MBUF_METADATA_UINT8(pkt, PROT_OFST_IP6);
		uint32_t dest_if = INVALID_DESTIF;
		uint16_t *outport_id =
			RTE_MBUF_METADATA_UINT16_PTR(pkt, cgnapt_meta_offset);
		struct cgnapt_table_entry *entry = NULL;

		if (hash_table_entry < 0) {

			/* try to add new entry */
			struct rte_pipeline_table_entry *table_entry = NULL;

			uint64_t dropmask =
				pkt_miss_cgnapt(p_nat->key_ptrs[pkt_num], pkt,
						&table_entry,
						&p_nat->valid_packets, pkt_num,
						(void *)p_nat);

			if (!table_entry) {
				/* ICMP Error message generation for
				* Destination Host unreachable
				*/
				/* Do we need this check for ipv6? */
				if (protocol == IP_PROTOCOL_ICMP) {
					cgnapt_icmp_pkt = pkt;
					send_icmp_dest_unreachable_msg();
				}

				/* Drop packet by adding to invalid pkt mask */

				p_nat->invalid_packets |= dropmask;

				#ifdef CGNAPT_DEBUGGING
				if (p_nat->kpc2++ < 5) {
					printf("in_ah Th: %d",
							 p_nat->pipeline_num);
					print_key(p_nat->key_ptrs[pkt_num]);
				}
				#endif

				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount3++;
				#endif

				continue;
			}

			entry = (struct cgnapt_table_entry *)table_entry;
		} else {
			/* entry found for this packet */
			entry = &napt_hash_tbl_entries[hash_table_entry];
		}

		/*  apply napt and mac changes */

		p_nat->entries[pkt_num] = &(entry->head);

		struct ipv6_hdr ipv6_hdr;
		struct ether_addr hw_addr;
		uint32_t dest_address = 0;
		uint8_t nh_ipv6[16];
		uint32_t nhip = 0;

		/* Egress */
		{
			convert_ipv6_to_ipv4(pkt, &ipv6_hdr);

			#ifdef CGNAPT_DBG_PRNT
			if (CGNAPT_DEBUG >= 1)
				printf("pkt_work_cganpt: "
				"convert_ipv6_to_ipv4\n");
			#endif

			struct cgnapt_nsp_node *ll = nsp_ll;
			int nsp = 0;

			while (ll != NULL) {
				if (!memcmp(&ipv6_hdr.dst_addr[0],
					&ll->nsp.prefix[0],
					 ll->nsp.depth / 8)) {
					nsp = 1;
					break;
				}
				ll = ll->next;
			}

			if (!nsp
				&& !memcmp(&ipv6_hdr.dst_addr[0],
						 &well_known_prefix[0], 12)) {
				nsp = 1;
			}

			if (!nsp) {
				p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount5++;
				#endif
				continue;
			}

		}

		/* As packet is already converted into IPv4 we must not
		* operate IPv6 offsets on packet only perform IPv4 operations
		*/

		uint32_t *src_addr =
			RTE_MBUF_METADATA_UINT32_PTR(pkt, SRC_ADR_OFST_IP6t4);
		uint32_t *dst_addr =
			RTE_MBUF_METADATA_UINT32_PTR(pkt, DST_ADR_OFST_IP6t4);
		uint16_t *src_port =
			RTE_MBUF_METADATA_UINT16_PTR(pkt, SRC_PRT_OFST_IP6t4);
		uint16_t *dst_port =
			RTE_MBUF_METADATA_UINT16_PTR(pkt, DST_PRT_OFST_IP6t4);

		uint8_t *eth_dest =
			RTE_MBUF_METADATA_UINT8_PTR(pkt, ETH_OFST_IP6t4);
		uint8_t *eth_src =
			RTE_MBUF_METADATA_UINT8_PTR(pkt, ETH_OFST_IP6t4 + 6);

		if (entry->data.ttl == NAPT_ENTRY_STALE)
			entry->data.ttl = NAPT_ENTRY_VALID;

		/* Egress */
		{

			if (unlikely(protocol == IP_PROTOCOL_UDP
				&& rte_be_to_cpu_16(*dst_port) == 53)) {
				p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount6++;
				#endif
				continue;
			}

			dest_address = rte_bswap32(*dst_addr);
	uint32_t nhip;
	uint32_t ret;
#if 0
	ret = local_get_nh_ipv4(dest_address, &dest_if, &nhip, p_nat);
	if (!ret) {
		dest_if = get_prv_to_pub_port(&dest_address, IP_VERSION_4);

		if (dest_if == INVALID_DESTIF) {
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;
			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount6++;
			#endif
			continue;
		}

		do_local_nh_ipv4_cache(dest_if, p_nat);
	}
		*outport_id = p_nat->outport_id[dest_if];
#endif
		#ifdef CGNAPT_DBG_PRNT
			if (CGNAPT_DEBUG > 2)
				printf("Egress: \tphy_port:%d\t"
				"get_prv_to_pub():%d \tout_port:%d\n",
				pkt->port, dest_if, *outport_id);
		#endif
		}

		#ifdef CGNAPT_DEBUGGING
		static int static_count;

		if (static_count++ < 10) {
			print_pkt(pkt);
			my_print_entry(entry);
			printf("dest-offset:%d\n", DST_ADR_OFST_IP4);
			printf("dest_add:%x\n", entry->data.u.prv_ip);
			printf("dest_add:%x\n", *dst_addr);
			printf("DST_ADR_OFST_IP6:%d\n", DST_ADR_OFST_IP6);
		}
		#endif

		memset(nh_ipv6, 0, 16);

	{
		struct arp_entry_data *ret_arp_data;
		ret_arp_data = get_dest_mac_addr_port(dest_address, &dest_if, (struct ether_addr *)eth_dest);
		*outport_id = p_nat->outport_id[dest_if];

		if (arp_cache_dest_mac_present(dest_if)) {
			ether_addr_copy(get_link_hw_addr(dest_if),
				(struct ether_addr *)eth_src);
			arp_data_ptr[dest_if]->n_last_update = time(NULL);

			if (unlikely(ret_arp_data && ret_arp_data->num_pkts)) {
				printf("sending buffered packets\n");
				p_nat->naptedPktCount += ret_arp_data->num_pkts;
				arp_send_buffered_pkts(ret_arp_data,
					 (struct ether_addr *)eth_dest, *outport_id);

			}
		} else {

			if (unlikely(ret_arp_data == NULL)) {

				printf("%s: NHIP Not Found, nhip:%x , "
				"outport_id: %d\n", __func__, nhip,
				*outport_id);

				/* Drop the pkt */
				p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount4++;
				#endif
				return;
			}

			if (ret_arp_data->status == INCOMPLETE ||
			   ret_arp_data->status == PROBE) {
				if (ret_arp_data->num_pkts >= NUM_DESC) {
					/* Drop the pkt */
					p_nat->invalid_packets |= pkt_mask;
					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					return;
				} else {
					arp_pkts_mask |= pkt_mask;
					arp_queue_unresolved_packet(ret_arp_data, pkt);
					return;
				}
			}

		}
	}

		{
			/* Egress */
			*src_addr = rte_bswap32(entry->data.pub_ip);

			#ifdef NAT_ONLY_CONFIG_REQ
			if (!nat_only_config_flag) {
			#endif
				*src_port = rte_bswap16(entry->data.pub_port);

			#ifdef NAT_ONLY_CONFIG_REQ
			}
			#endif

			p_nat->enaptedPktCount++;
		}

		p_nat->naptedPktCount++;

		#ifdef CHECKSUM_REQ
			if (p_nat->hw_checksum_reqd)
				hw_checksum(pkt, pkt_type);
			else
				sw_checksum(pkt, pkt_type);
		#endif
	}
}

/**
 * NAPT function for IPv6 public traffic which handles 4 pkts
 *
 * @param pkts
 *  A pointer to array of packets mbuf
 * @param in_pkt_num
 *  Starting pkt number of pkts
 * @param arg
 *  Void pointer
 * @param p_nat
 *  A pointer to main CGNAPT structure
 *
 */
void
pkt4_work_cgnapt_ipv6_pub(
	struct rte_mbuf **pkts,
	uint32_t in_pkt_num,
	__rte_unused void *arg,
	struct pipeline_cgnapt *p_nat)
{
	struct rte_mbuf *pkt;
	uint8_t i;
	uint8_t pkt_num;

	enum PKT_TYPE pkt_type = PKT_TYPE_IPV4to6;

	for (i = 0; i < 4; i++) {
		pkt_num = in_pkt_num + i;
		pkt = pkts[i];

		/* index into hash table entries */
		int hash_table_entry = p_nat->lkup_indx[pkt_num];
		/*bitmask representing only this packet */
		uint64_t pkt_mask = 1LLU << pkt_num;

		uint8_t protocol = RTE_MBUF_METADATA_UINT8(pkt, PROT_OFST_IP4);
		uint16_t *outport_id =
			RTE_MBUF_METADATA_UINT16_PTR(pkt, cgnapt_meta_offset);
		struct cgnapt_table_entry *entry = NULL;

		if (hash_table_entry < 0) {

			/* Drop ingress initial traffic */

			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;
			#ifdef CGNAPT_DEBUGGING
			p_nat->naptDroppedPktCount3++;
			if (p_nat->kpc2++ < 5) {
				printf("in_ah Th: %d", p_nat->pipeline_num);
				print_key(p_nat->key_ptrs[pkt_num]);
			}
			#endif

			continue;

		} else {
			/* entry found for this packet */
			entry = &napt_hash_tbl_entries[hash_table_entry];
		}

		/*  apply napt and mac changes */

		p_nat->entries[pkt_num] = &(entry->head);
		if (entry->data.type != CGNAPT_ENTRY_IPV6) {
			p_nat->invalid_packets |= pkt_mask;
			p_nat->naptDroppedPktCount++;
			continue;
		}

		struct ipv4_hdr ipv4_hdr;

		uint16_t *src_port =
			RTE_MBUF_METADATA_UINT16_PTR(pkt, SRC_PRT_OFST_IP4_TCP);

		uint8_t *eth_dest =
			RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
		uint8_t *eth_src =
			RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM + 6);

		if (entry->data.ttl == NAPT_ENTRY_STALE)
			entry->data.ttl = NAPT_ENTRY_VALID;

		struct ether_addr hw_addr;
		uint8_t dest_addr_ipv6[16];
		uint8_t nh_ipv6[16];
		uint32_t dest_if = INVALID_DESTIF;
		{ /*start of Ingress */

			if (unlikely(protocol == IP_PROTOCOL_UDP
				&& rte_be_to_cpu_16(*src_port) == 53)) {
				p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;
				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount6++;
				#endif
				continue;
			}

			memcpy(&dest_addr_ipv6[0], &entry->data.u.prv_ipv6[0],
					 16);
			uint8_t nhipv6[16];
#if 0
			int ret;
			ret = local_get_nh_ipv6(&dest_addr_ipv6[0], &dest_if,
				&nhipv6[0], p_nat);
			if (!ret) {
				dest_if = get_prv_to_pub_port((uint32_t *)
					&dest_addr_ipv6[0], IP_VERSION_6);

				if (dest_if == INVALID_DESTIF) {
					p_nat->invalid_packets |= pkt_mask;
					p_nat->naptDroppedPktCount++;
					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount6++;
					#endif
					return;
				}

				do_local_nh_ipv6_cache(dest_if, p_nat);
			}

			*outport_id = p_nat->outport_id[dest_if];
#endif
		}/* end of ingress */

		#ifdef CGNAPT_DEBUGGING
		static int static_count;

		if (static_count++ < 10) {
			print_pkt(pkt);
			my_print_entry(entry);
			printf("dest-offset:%d\n", DST_ADR_OFST_IP4);
			printf("dest_add:%x\n", entry->data.u.prv_ip);
			printf("DST_ADR_OFST_IP6:%d\n", DST_ADR_OFST_IP6);
		}
		#endif

		memset(nh_ipv6, 0, 16);
		struct nd_entry_data *ret_nd_data = NULL;
		ret_nd_data = get_dest_mac_address_ipv6_port
				(&dest_addr_ipv6[0], &dest_if,
				(struct ether_addr *)eth_dest, &nh_ipv6[0]);

		*outport_id = p_nat->outport_id[dest_if];

		if (nd_cache_dest_mac_present(dest_if)) {
			ether_addr_copy(get_link_hw_addr(dest_if),
				(struct ether_addr *)eth_src);
			nd_data_ptr[dest_if]->n_last_update = time(NULL);

			if (unlikely(ret_nd_data && ret_nd_data->num_pkts)) {
				printf("sending buffered packets\n");
				p_nat->naptedPktCount += ret_nd_data->num_pkts;
				nd_send_buffered_pkts(ret_nd_data,
				 (struct ether_addr *)eth_dest, *outport_id);
			}
		} else {
			if (unlikely(ret_nd_data == NULL)) {

				printf("%s: NHIP Not Found "
				"outport_id: %d\n", __func__,
				*outport_id);

				/* Drop the pkt */
				p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount4++;
				#endif
				continue;
			}

			if (ret_nd_data->status == INCOMPLETE ||
				   ret_nd_data->status == PROBE) {

				if (ret_nd_data->num_pkts >= NUM_DESC) {
					/* Drop the pkt */
					p_nat->invalid_packets |= pkt_mask;
					p_nat->naptDroppedPktCount++;

					#ifdef CGNAPT_DEBUGGING
					p_nat->naptDroppedPktCount4++;
					#endif
					continue;
				} else {
					arp_pkts_mask |= pkt_mask;
					nd_queue_unresolved_packet(ret_nd_data, pkt);
					continue;
				}
			}

		}

		{
		/* start of Ingress */

			convert_ipv4_to_ipv6(pkt, &ipv4_hdr);

			/* Ethernet MTU check */
			if ((rte_pktmbuf_data_len(pkt) - 14) > 1500) {
				p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;
				continue;
			}
			uint32_t *dst_addr = RTE_MBUF_METADATA_UINT32_PTR(pkt,
							DST_ADR_OFST_IP4t6);
			uint16_t *dst_port = RTE_MBUF_METADATA_UINT16_PTR(pkt,
							DST_PRT_OFST_IP4t6);

			memcpy((uint8_t *) &dst_addr[0],
					 &entry->data.u.prv_ipv6[0], 16);

			#ifdef NAT_ONLY_CONFIG_REQ
			if (!nat_only_config_flag) {
			#endif
				*dst_port = rte_bswap16(entry->data.prv_port);

			#ifdef NAT_ONLY_CONFIG_REQ
			}
			#endif

			p_nat->inaptedPktCount++;
		} /* end of ingress */

		p_nat->naptedPktCount++;

		#ifdef CHECKSUM_REQ
			if (p_nat->hw_checksum_reqd)
				hw_checksum(pkt, pkt_type);
			else
				sw_checksum(pkt, pkt_type);
		#endif
	} /* end of for loop */
}

/**
 * Input port handler for IPv6 private traffic
 * Starting from the packet burst it filters unwanted packets,
 * calculates keys, does lookup and then based on the lookup
 * updates NAPT table and does packet NAPT translation.
 *
 * @param rte_p
 *  A pointer to struct rte_pipeline
 * @param pkts
 *  A pointer to array of packets mbuf
 * @param n_pkts
 *  Number of packets in the burst
 * @param arg
 *  Void pointer
 *
 * @return
 *  int that is not checked by caller
 */
static int cgnapt_in_port_ah_ipv6_prv(struct rte_pipeline *rte_p,
						struct rte_mbuf **pkts,
						uint32_t n_pkts, void *arg)
{
	uint32_t i, j;
	struct pipeline_cgnapt_in_port_h_arg *ap = arg;
	struct pipeline_cgnapt *p_nat = ap->p;

	p_nat->pkt_burst_cnt = 0;	/* for dynamic napt */
	p_nat->valid_packets = rte_p->pkts_mask;	/*n_pkts; */
	p_nat->invalid_packets = 0;
	arp_pkts_mask = 0;

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 1)
		printf("cgnapt_key hit fn: %" PRIu32 "\n", n_pkts);
	#endif

	/* prefetching for mbufs should be done here */
	for (j = 0; j < n_pkts; j++)
		rte_prefetch0(pkts[j]);

	for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)
		pkt4_work_cgnapt_key_ipv6_prv(&pkts[i], i, arg, p_nat);

	for (; i < n_pkts; i++)
		pkt_work_cgnapt_key_ipv6_prv(pkts[i], i, arg, p_nat);

	p_nat->valid_packets &= ~(p_nat->invalid_packets);

	if (arp_pkts_mask) {
		p_nat->valid_packets &= ~(arp_pkts_mask);
		rte_pipeline_ah_packet_hijack(rte_p, arp_pkts_mask);
	}

	if (unlikely(p_nat->valid_packets == 0)) {
		/* no suitable packet for lookup */
		rte_pipeline_ah_packet_drop(rte_p, p_nat->invalid_packets);
		return p_nat->valid_packets;
	}

	/* lookup entries in the common napt table */

	int lookup_result = rte_hash_lookup_bulk(
				napt_common_table,
				(const void **) &p_nat->key_ptrs,
				/* should be minus num invalid pkts */
				n_pkts,
				/*new pipeline data member */
				&p_nat->lkup_indx[0]);

	if (unlikely(lookup_result < 0)) {
		/* unknown error, just discard all packets */
		printf("Unexpected hash lookup error %d, "
			"discarding all packets",
			 lookup_result);
		rte_pipeline_ah_packet_drop(rte_p, p_nat->valid_packets);
		return 0;
	}

	/* Now call second stage of pipeline to one by one
	* check the result of our bulk lookup
	*/

	/* prefetching for table entries should be done here */
	for (j = 0; j < n_pkts; j++) {
		if (p_nat->lkup_indx[j] >= 0)
			rte_prefetch0(&napt_hash_tbl_entries
						[p_nat->lkup_indx[j]]);
	}

	for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)
		pkt4_work_cgnapt_ipv6_prv(&pkts[i], i, arg, p_nat);

	for (; i < n_pkts; i++)
		pkt_work_cgnapt_ipv6_prv(pkts[i], i, arg, p_nat);

	if (p_nat->invalid_packets) {
		/* get rid of invalid packets */
		rte_pipeline_ah_packet_drop(rte_p, p_nat->invalid_packets);

		p_nat->valid_packets &= ~(p_nat->invalid_packets);

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG > 1) {
			printf("valid_packets:0x%jx\n", p_nat->valid_packets);
			printf("rte_valid_packets :0x%jx\n", rte_p->pkts_mask);
			printf("invalid_packets:0x%jx\n",
					 p_nat->invalid_packets);
			printf("rte_invalid_packets :0x%jx\n",
					 rte_p->pkts_drop_mask);
			printf("Total pkts dropped :0x%jx\n",
					 rte_p->n_pkts_ah_drop);
		}
		#endif
	}

	return p_nat->valid_packets;
}


/**
 * Input port handler for IPv6 public traffic
 * Starting from the packet burst it filters unwanted packets,
 * calculates keys, does lookup and then based on the lookup
 * updates NAPT table and does packet NAPT translation.
 *
 * @param rte_p
 *  A pointer to struct rte_pipeline
 * @param pkts
 *  A pointer to array of packets mbuf
 * @param n_pkts
 *  Number of packets in the burst
 * @param arg
 *  Void pointer
 *
 * @return
 *  int that is not checked by caller
 */
static int cgnapt_in_port_ah_ipv6_pub(struct rte_pipeline *rte_p,
						struct rte_mbuf **pkts,
						uint32_t n_pkts, void *arg)
{
	uint32_t i, j;
	struct pipeline_cgnapt_in_port_h_arg *ap = arg;
	struct pipeline_cgnapt *p_nat = ap->p;

	p_nat->pkt_burst_cnt = 0;	/* for dynamic napt */
	p_nat->valid_packets = rte_p->pkts_mask;	/*n_pkts; */
	p_nat->invalid_packets = 0;
	arp_pkts_mask = 0;

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 1)
		printf("cgnapt_key hit fn: %" PRIu32 "\n", n_pkts);
	#endif

	/* prefetching for mbufs should be done here */
	for (j = 0; j < n_pkts; j++)
		rte_prefetch0(pkts[j]);

	for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)
		pkt4_work_cgnapt_key_ipv6_pub(&pkts[i], i, arg, p_nat);

	for (; i < n_pkts; i++)
		pkt_work_cgnapt_key_ipv6_pub(pkts[i], i, arg, p_nat);

	p_nat->valid_packets &= ~(p_nat->invalid_packets);

	if (arp_pkts_mask) {
		p_nat->valid_packets &= ~(arp_pkts_mask);
		rte_pipeline_ah_packet_hijack(rte_p, arp_pkts_mask);
	}

	if (unlikely(p_nat->valid_packets == 0)) {
		/* no suitable packet for lookup */
		rte_pipeline_ah_packet_drop(rte_p, p_nat->invalid_packets);
		return p_nat->valid_packets;
	}

	/* lookup entries in the common napt table */

	int lookup_result = rte_hash_lookup_bulk(
				napt_common_table,
				(const void **) &p_nat->key_ptrs,
				/* should be minus num invalid pkts */
				 n_pkts,
				/*new pipeline data member */
				 &p_nat->lkup_indx[0]);

	if (unlikely(lookup_result < 0)) {
		/* unknown error, just discard all packets */
		printf("Unexpected hash lookup error %d, "
			"discarding all packets",
			 lookup_result);
		rte_pipeline_ah_packet_drop(rte_p, p_nat->valid_packets);
		return 0;
	}

	/* Now call second stage of pipeline to one by one
	* check the result of our bulk lookup
	*/

	/* prefetching for table entries should be done here */
	for (j = 0; j < n_pkts; j++) {
		if (p_nat->lkup_indx[j] >= 0)
			rte_prefetch0(&napt_hash_tbl_entries
						[p_nat->lkup_indx[j]]);
	}

	for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)
		pkt4_work_cgnapt_ipv6_pub(&pkts[i], i, arg, p_nat);

	for (; i < n_pkts; i++)
		pkt_work_cgnapt_ipv6_pub(pkts[i], i, arg, p_nat);

	if (p_nat->invalid_packets) {
		/* get rid of invalid packets */
		rte_pipeline_ah_packet_drop(rte_p, p_nat->invalid_packets);

		p_nat->valid_packets &= ~(p_nat->invalid_packets);

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG > 1) {
			printf("valid_packets:0x%jx\n", p_nat->valid_packets);
			printf("rte_valid_packets :0x%jx\n", rte_p->pkts_mask);
			printf("invalid_packets:0x%jx\n",
					 p_nat->invalid_packets);
			printf("rte_invalid_packets :0x%jx\n",
					 rte_p->pkts_drop_mask);
			printf("Total pkts dropped :0x%jx\n",
					 rte_p->n_pkts_ah_drop);
		}
		#endif
	}

	return p_nat->valid_packets;
}

/**
 * Function to send ICMP dest unreachable msg
 *
 */
void send_icmp_dest_unreachable_msg(void)
{

	struct ether_hdr *eth_h;
	struct ipv4_hdr *ip_h;
	struct icmp_hdr *icmp_h;
	struct rte_mbuf *icmp_pkt = cgnapt_icmp_pkt;

	if (icmp_pkt == NULL) {
		if (ARPICMP_DEBUG)
			printf("Error allocating icmp_pkt rte_mbuf\n");
		return;
	}
	uint16_t port_id;
	port_id = icmp_pkt->port;

	struct app_link_params *link;
	link = &mylink[port_id];
	eth_h = rte_pktmbuf_mtod(icmp_pkt, struct ether_hdr *);
	ip_h = (struct ipv4_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	icmp_h = (struct icmp_hdr *)((char *)ip_h + sizeof(struct ipv4_hdr));

	struct ether_addr gw_addr;
	struct ether_addr dst_addr;
	ether_addr_copy(&eth_h->s_addr, &dst_addr);
	rte_eth_macaddr_get(port_id, &gw_addr);
	ether_addr_copy(&gw_addr, &eth_h->s_addr);
	ether_addr_copy(&dst_addr, &eth_h->d_addr);

	eth_h->ether_type = CHECK_ENDIAN_16(ETHER_TYPE_IPv4);
	ip_h->version_ihl = IP_VHL_DEF;
	ip_h->type_of_service = 0;
	ip_h->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr) +
				sizeof(struct icmp_hdr));
	ip_h->packet_id = 0xaabb;
	ip_h->fragment_offset = 0x0000;
	ip_h->time_to_live = 64;
	ip_h->next_proto_id = 1;

	uint32_t *src_addr;
	uint32_t src_addr_offset =
		MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_SRC_ADR_OFST;
	src_addr =
		RTE_MBUF_METADATA_UINT32_PTR(cgnapt_icmp_pkt, src_addr_offset);

	ip_h->dst_addr = *src_addr;
	ip_h->src_addr = rte_bswap32(link->ip);

	ip_h->dst_addr = *src_addr;
	ip_h->src_addr = rte_bswap32(link->ip);

	ip_h->hdr_checksum = 0;
	ip_h->hdr_checksum = rte_ipv4_cksum(ip_h);
	icmp_h->icmp_type = 3;	/* Destination Unreachable */
	icmp_h->icmp_code = 13;	/* Communication administratively prohibited */

	icmp_h->icmp_cksum = ~rte_raw_cksum(icmp_h, sizeof(struct icmp_hdr));

	icmp_pkt->pkt_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
		sizeof(struct icmp_hdr);
	icmp_pkt->data_len = icmp_pkt->pkt_len;
	if (ARPICMP_DEBUG) {
		printf("Sending ICMP error message - "
			"Destination Unreachable\n");
	}
	rte_pipeline_port_out_packet_insert(myP, port_id, icmp_pkt);
}

/**
 * Function to add a dynamic NAPT entry pair
 *
 * @param p
 *  A pointer to struct pipeline
 * @param key
 *  A pointer to struct pipeline_cgnapt_entry_key
 * @param time_out
 *  expairy time of an dynamic or PCP req entry
 * @param src_addr
 *  uint8_t pointer of source address
 *
 * @return
 *  A pointer to struct cgnapt_table_entry for added entry
 */

struct cgnapt_table_entry *add_dynamic_cgnapt_entry(
	struct pipeline *p,
	struct pipeline_cgnapt_entry_key *key,
	uint32_t timeout,
	uint8_t pkt_type,
	uint8_t *src_addr,
	uint8_t *err)
{
	int port_num = 0;
	void *entry_ptr, *ret_ptr;
	int ret = 0, i;

	struct pipeline_cgnapt *p_nat = (struct pipeline_cgnapt *)p;

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG >= 1) {
		printf("Th%d add_dynamic_cgnapt_entry key detail Entry:"
		"0x%x, %d, %d\n", p_nat->pipeline_num, key->ip, key->port,
		key->pid);
	}
	#endif

	for (i = 0; i < RTE_PORT_IN_BURST_SIZE_MAX && i < p_nat->pkt_burst_cnt;
		 i++) {
		if (p_nat->cgnapt_dyn_ent_table[i].ip == key->ip
			&& p_nat->cgnapt_dyn_ent_table[i].port == key->port
			&& p_nat->cgnapt_dyn_ent_table[i].pid == key->pid) {

			#ifdef CGNAPT_DBG_PRNT
			if (CGNAPT_DEBUG > 1)
				printf("add_dynamic_cgnapt_entry:pkt_burst "
				"array key matched!!!\n");
			#endif

			return &napt_hash_tbl_entries
				[p_nat->cgnapt_dyn_ent_index[i]];
		}
	}

	#ifdef NAT_ONLY_CONFIG_REQ
	if (!nat_only_config_flag) {
	#endif

	ret = increment_max_port_counter(key->ip, key->pid, p_nat);
	if (ret == MAX_PORT_INC_ERROR) {

		#ifdef CGNAPT_DEBUGGING
		p_nat->missedpktcount5++;
		#endif

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG > 1)
			printf("add_dynamic_cgnapt_entry:"
			"increment_max_port_counter-1 failed\n");
		#endif

		*err = 1;
		return NULL;
	}

	if (ret == MAX_PORT_INC_REACHED) {

		#ifdef CGNAPT_DEBUGGING
		p_nat->missedpktcount6++;
		#endif

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG > 1)
			printf("add_dynamic_cgnapt_entry:"
			"increment_max_port_counter-2 failed\n");
		#endif

		*err = 1;
		return NULL;
	}

	#ifdef NAT_ONLY_CONFIG_REQ
	}
	#endif

	uint32_t public_ip;
	port_num = get_free_iport(p_nat, &public_ip);

	if (port_num == -1) {

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG > 2) {
			printf("add_dynamic_cgnapt_entry: %d\n", port_num);
			printf("add_dynamic_cgnapt_entry key detail:0x%x, "
			"%d, %d\n", key->ip, key->port, key->pid);
		}
		#endif

		#ifdef CGNAPT_DEBUGGING
		p_nat->missedpktcount7++;
		#endif

		*err = 1;
		return NULL;
	}

	#ifdef NAT_ONLY_CONFIG_REQ
	if (!nat_only_config_flag) {
	#endif

	if (ret == 2) {	//MPPC_NEW_ENTRY

		/* check for max_clients_per_ip */
		if (rte_atomic16_read
			(&all_public_ip
			[rte_jhash(&public_ip, 4, 0) %
			CGNAPT_MAX_PUB_IP].count) ==
			p_nat->max_clients_per_ip) {

		/* For now just bail out
		* In future we can think about
		* retrying getting a new iport
		*/

		release_iport(port_num, public_ip, p_nat);

		#ifdef CGNAPT_DEBUGGING
				p_nat->missedpktcount10++;
		#endif
				*err = 1;
				return NULL;
			}

			rte_atomic16_inc(&all_public_ip
					 [rte_jhash(&public_ip, 4, 0) %
						CGNAPT_MAX_PUB_IP].count);

		#ifdef CGNAPT_DBG_PRNT
			if ((rte_jhash(&public_ip, 4, 0) %
				CGNAPT_MAX_PUB_IP) == 8)
				printf("pub ip:%x coutn:%d\n", public_ip,
				rte_atomic16_read(&all_public_ip
				[rte_jhash(&public_ip, 4, 0) %
				CGNAPT_MAX_PUB_IP].count));
		#endif

		}
		#ifdef NAT_ONLY_CONFIG_REQ
		}
		#endif

		#ifdef CGNAPT_DBG_PRNT
			if (CGNAPT_DEBUG > 0) {
				printf("add_dynamic_cgnapt_entry: %d\n",
					port_num);
				printf("add_dynamic_cgnapt_entry key detail: "
				"0x%x, %d, %d\n", key->ip, key->port, key->pid);
		}
		#endif

		struct cgnapt_table_entry entry = {
			.head = {
			 .action = RTE_PIPELINE_ACTION_PORT,
			/* made it configurable below */
			 {.port_id = p->port_out_id[0]},
			 },

			.data = {
				.prv_port = key->port,
				.pub_ip = public_ip,
				.pub_port = port_num,
				.prv_phy_port = key->pid,
				.pub_phy_port = get_pub_to_prv_port(
						&public_ip,
						IP_VERSION_4),
				.ttl = 0,
				/* if(timeout == -1) : static entry
				*  if(timeout == 0 ) : dynamic entry
				*  if(timeout >  0 ) : PCP requested entry
				*/
				.timeout = timeout > 0 ? timeout : 0,
				#ifdef PCP_ENABLE
				.timer = NULL,
				#endif
			}
		};

	#ifdef NAT_ONLY_CONFIG_REQ
		if (nat_only_config_flag) {
			entry.data.prv_port = 0xffff;
			entry.data.pub_port = 0xffff;
		}
	#endif

	if (pkt_type == CGNAPT_ENTRY_IPV6) {
		entry.data.type = CGNAPT_ENTRY_IPV6;
		memcpy(&entry.data.u.prv_ipv6[0], src_addr, 16);
	} else {
		entry.data.u.prv_ip = key->ip;
		entry.data.type = CGNAPT_ENTRY_IPV4;
	}

	//entry.head.port_id = CGNAPT_PUB_PORT_ID; /* outgoing port info */
	entry.head.port_id = entry.data.pub_phy_port; /* outgoing port info */

	struct pipeline_cgnapt_entry_key second_key;
	/* Need to add a second ingress entry */
	second_key.ip = public_ip;
	second_key.port = port_num;
	second_key.pid = 0xffff;

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		second_key.port = 0xffff;
	#endif

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 2)
		printf("add_dynamic_cgnapt_entry second key detail:"
		"0x%x, %d, %d\n", second_key.ip, second_key.port,
		second_key.pid);
	#endif

	int32_t position = rte_hash_add_key(napt_common_table, (void *)key);

	if (position < 0) {
		#ifdef CGNAPT_DEBUGGING
		p_nat->missedpktcount8++;
		#endif

		printf("CG-NAPT entry add failed ...returning "
		"without adding ... %d\n", position);
		*err = 1;
		return NULL;
	}

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG) {
		printf("add_dynamic_cgnapt_entry\n");
		print_key(key);
		print_cgnapt_entry(&entry);
	}
	#endif

	memcpy(&napt_hash_tbl_entries[position], &entry,
			 sizeof(struct cgnapt_table_entry));

	/* this pointer is returned to pkt miss function */
	ret_ptr = &napt_hash_tbl_entries[position];

	p_nat->n_cgnapt_entry_added++;
	p_nat->dynCgnaptCount++;

	/* Now modify the forward port for reverse entry */

	/* outgoing port info */
	//entry.head.port_id = CGNAPT_PRV_PORT_ID;
	/* outgoing port info */
	entry.head.port_id = entry.data.prv_phy_port;

	int32_t position2 = rte_hash_add_key(napt_common_table, &second_key);

	if (position2 < 0) {
		#ifdef CGNAPT_DEBUGGING
		p_nat->missedpktcount9++;
		#endif
		printf("CG-NAPT entry reverse bulk add failed ..."
		"returning with fwd add ...%d\n",
			 position2);
		*err = 1;
		return NULL;
	}

	memcpy(&napt_hash_tbl_entries[position2], &entry,
			 sizeof(struct cgnapt_table_entry));

	entry_ptr = &napt_hash_tbl_entries[position2];

	timer_thread_enqueue(key, &second_key, ret_ptr,
		entry_ptr, (struct pipeline *)p_nat);

	p_nat->n_cgnapt_entry_added++;
	p_nat->dynCgnaptCount++;

	if (p_nat->pkt_burst_cnt < RTE_PORT_IN_BURST_SIZE_MAX) {
		memcpy(&p_nat->cgnapt_dyn_ent_table[p_nat->pkt_burst_cnt], key,
				 sizeof(struct pipeline_cgnapt_entry_key));
		p_nat->cgnapt_dyn_ent_index[p_nat->pkt_burst_cnt] = position;
		p_nat->pkt_burst_cnt++;
	}
	return ret_ptr;
}

int pkt_miss_cgnapt_count;
/**
 * Function handle a missed NAPT entry lookup
 * Will attempt to add a dynamic entry pair.
 *
 * @param p
 *  A pointer to struct pipeline
 * @param key
 *  A pointer to struct pipeline_cgnapt_entry_key
 * @param pkt
 *  A pointer to pkt struct rte_mbuf
 * @param pkt_mask
 *  uint64_t pointer to pkt mask
 * @param table_entry
 *  A pointer to struct rte_pipeline_table_entry to be created and returned
 * @param pkt_num
 *  number of this pkt in current burst
 *
 * @return
 *  A uint64_t mask for drop packets
 */
uint64_t
pkt_miss_cgnapt(struct pipeline_cgnapt_entry_key *key,
		struct rte_mbuf *pkt,
		struct rte_pipeline_table_entry **table_entry,
		__rte_unused uint64_t *pkts_mask,
		uint32_t pkt_num, void *arg)
{

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 0)
		printf("\n pkt_miss_cgnapt\n");
	#endif
	/*  In egress case
	*   get src address
	*   see if get_port passes for this src address
	*   if passed add a new egress entry and a
	*  corresponding new ingress entry
	*   return the fwd entry to calling function using input pointer
	*   else if get_port fails drop packet
	*/

	struct pipeline_cgnapt *p_nat = (struct pipeline_cgnapt *)arg;

	uint32_t eth_proto_offset = MBUF_HDR_ROOM + 12;
	uint32_t src_addr_offset_ipv6 =
		MBUF_HDR_ROOM + ETH_HDR_SIZE + IPV6_HDR_SRC_ADR_OFST;
	uint16_t phy_port = pkt->port;

	uint16_t *eth_proto =
		RTE_MBUF_METADATA_UINT16_PTR(pkt, eth_proto_offset);

	uint8_t *src_addr = NULL;
	uint8_t src_addr_ipv6[16];
	uint8_t pkt_type = CGNAPT_ENTRY_IPV4;
	/* To drop the packet */
	uint64_t drop_mask = 0;

	if (p_nat->is_static_cgnapt) {
		drop_mask |= 1LLU << pkt_num;
		p_nat->missedPktCount++;

		#ifdef CGNAPT_DEBUGGING
		p_nat->missedpktcount1++;
		#endif
		return drop_mask;
	}

	if (rte_be_to_cpu_16(*eth_proto) == ETHER_TYPE_IPv6) {
		src_addr =
			RTE_MBUF_METADATA_UINT8_PTR(pkt, src_addr_offset_ipv6);
		pkt_type = CGNAPT_ENTRY_IPV6;
		memcpy(src_addr_ipv6, src_addr, 16);
	}

	uint8_t err = 0;

	/* some validation first */
	if (is_phy_port_privte(phy_port)) {
		/* dynamic NAPT entry creation */
		*table_entry = (struct rte_pipeline_table_entry *)
			add_dynamic_cgnapt_entry(
				(struct pipeline *)&p_nat->p,
				key,
				DYNAMIC_CGNAPT_TIMEOUT,
				pkt_type,
				src_addr_ipv6, &err);

		if (!(*table_entry)) {
			if (err) {
				drop_mask |= 1LLU << pkt_num;
				p_nat->missedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->missedpktcount2++;
				#endif

				#ifdef CGNAPT_DBG_PRNT
				if (CGNAPT_DEBUG > 1)
					printf("Add Dynamic NAT entry failed "
					"in pkt!!!\n");
				#endif
			} else {
				#ifdef CGNAPT_DEBUGGING
				p_nat->missedpktcount11++;
				#endif
			}
		}

	} else if (!is_phy_port_privte(phy_port)) {

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG >= 2) {
			printf("Initial Ingress entry creation NOT ALLOWED "
			"%d\n", phy_port);
		}
		#endif

		drop_mask |= 1LLU << pkt_num;
		p_nat->missedPktCount++;

		#ifdef CGNAPT_DEBUGGING
		p_nat->missedpktcount3++;
		#endif
	} else {

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG > 1)
			printf("NOT a PRIVATE or PUBLIC port!!!!!\n");
		#endif

		drop_mask |= 1LLU << pkt_num;
		p_nat->missedPktCount++;

		#ifdef CGNAPT_DEBUGGING
		p_nat->missedpktcount4++;
		#endif
	}

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG > 5)
		print_pkt(pkt);
	#endif

	return drop_mask;
}

int numprints;

/**
 * Function to print the contents of a packet
 *
 * @param pkt
 *  A pointer to pkt struct rte_mbuf
 */
void print_pkt(struct rte_mbuf *pkt)
{
	int i = 0, j = 0;

	printf("\nPacket Contents:\n");

	uint8_t *rd = RTE_MBUF_METADATA_UINT8_PTR(pkt, 0);

	for (i = 0; i < 20; i++) {
		for (j = 0; j < 20; j++)
			printf("%02x ", rd[(20 * i) + j]);

		printf("\n");
	}
}

rte_table_hash_op_hash cgnapt_hash_func[] = {
	hash_default_key8,
	hash_default_key16,
	hash_default_key24,
	hash_default_key32,
	hash_default_key40,
	hash_default_key48,
	hash_default_key56,
	hash_default_key64
};

/**
 * Function to parse incoming pipeline arguments
 * Called during pipeline initialization
 *
 * @param p
 *  A pointer to struct pipeline_cgnapt
 * @param params
 *  A pointer to struct pipeline_params
 *
 * @return
 *  0 if success, negative if failure
 */
static int
pipeline_cgnapt_parse_args(struct pipeline_cgnapt *p,
				 struct pipeline_params *params)
{
	uint32_t n_flows_present = 0;
	uint32_t key_offset_present = 0;
	uint32_t key_size_present = 0;
	uint32_t hash_offset_present = 0;
	uint32_t n_entries_present = 0;
	uint32_t max_port_present = 0;
	uint32_t max_client_present = 0;
	uint32_t public_ip_range_present = 0;
	uint32_t public_ip_port_range_present = 0;
	uint32_t i;
	uint8_t public_ip_count = 0;
	uint8_t public_ip_range_count = 0;
	uint8_t dest_if_offset_present = 0;
	uint8_t cgnapt_meta_offset_present = 0;
	uint8_t prv_que_handler_present = 0;
	uint8_t n_prv_in_port = 0;

	if (CGNAPT_DEBUG > 2) {
		printf("CGNAPT pipeline_cgnapt_parse_args params->n_args: %d\n",
				 params->n_args);
	}
	for (i = 0; i < params->n_args; i++) {
		char *arg_name = params->args_name[i];
		char *arg_value = params->args_value[i];

		if (CGNAPT_DEBUG > 2) {
			printf("CGNAPT args[%d]: %s %d, %s\n", i, arg_name,
					 atoi(arg_value), arg_value);
		}
		if (strcmp(arg_name, "prv_que_handler") == 0) {

			if (prv_que_handler_present) {
				printf("Duplicate pktq_in_prv ..\n\n");
				return -1;
			}
			prv_que_handler_present = 1;
			n_prv_in_port = 0;

			char *token;
			int rxport = 0;
			/* get the first token */
			token = strtok(arg_value, "(");
			token = strtok(token, ")");
			token = strtok(token, ",");
			printf("***** prv_que_handler *****\n");

			if (token == NULL) {
				printf("string is null\n");
				printf("invalid prv_que_handler value/n");
				return -1;
			}
			printf("string is :%s\n", token);

			/* walk through other tokens */
			while (token != NULL) {
				printf(" %s\n", token);
				rxport =  atoi(token);
				cgnapt_prv_que_port_index[n_prv_in_port++] =
							rxport;
				if (rxport < PIPELINE_MAX_PORT_IN)
				cgnapt_in_port_egress_prv[rxport] = 1;
				token = strtok(NULL, ",");
			}

			if (n_prv_in_port == 0) {
				printf("VNF common parse err - "
				"no prv RX phy port\n");
				return -1;
			}
		continue;
		}

		if (strcmp(arg_name, "cgnapt_meta_offset") == 0) {
			if (cgnapt_meta_offset_present) {
				printf("CG-NAPT parse error:");
				printf("cgnapt_meta_offset initizlized "
				"mulitple times\n");
				return -1;
			}
			cgnapt_meta_offset_present = 1;
			int temp;
			temp = atoi(arg_value);

			if (temp > 256) {
				printf("cgnapt_meta_offset is invalid :");
				printf("Not be more than metadata size\n");
				return -1;
			}
			cgnapt_meta_offset = (uint16_t) temp;
		}
		if (strcmp(arg_name, "vnf_set") == 0)
			vnf_set_count++;

		if (strcmp(arg_name, "public_ip_range") == 0) {
			public_ip_range_present = 1;
			if (public_ip_port_range_present) {
				printf("CG-NAPT parse error:");
				printf("public_ip_range with "
				"public_ip_port_range_present\n");
				return -1;
			}

			p->pub_ip_range = rte_realloc(p->pub_ip_range,
								sizeof(struct
								 pub_ip_range),
								RTE_CACHE_LINE_SIZE);

			if (!p->pub_ip_range) {
				printf("Memory allocation failed for "
				"pub_ip_range\n");
				return -1;
			}

			uint32_t sip = 0, eip = 0;

			if (sscanf(arg_value, "(%x,%x)", &sip, &eip) != 2) {
				printf("public_ip_range is invalid\n");
				return -1;
			}

			if (sip <= 0 || eip <= 0 || sip >= eip) {
				printf("public_ip_range is invalid %x-%x\n",
						 sip, eip);
				return -1;
			}

			printf("public_ip_range: %d-%d\n",
					 p->pub_ip_range[public_ip_range_count].
					start_ip = sip,
					 p->pub_ip_range[public_ip_range_count].
					end_ip = eip);

			p->pub_ip_range_count = ++public_ip_range_count;
			continue;
		}

		if (strcmp(arg_name, "public_ip_port_range") == 0) {
			public_ip_port_range_present = 1;
			if (nat_only_config_flag || public_ip_range_present) {

			printf("CG-NAPT parse error:");
			printf("nat_only_config_flag OR ");
			printf("public_ip_range_present with "
			"public_ip_port_range_present\n");
				return -1;
			}

			p->pub_ip_port_set = rte_realloc(
						p->pub_ip_port_set,
						sizeof(struct pub_ip_port_set),
						RTE_CACHE_LINE_SIZE);

			if (!p->pub_ip_port_set) {
				printf("Memory allocation failed for "
				"public IP\n");
				return -1;
			}

			uint32_t ip = 0;
			int sp = 0, ep = 0;

			if (sscanf(arg_value, "%x:(%d,%d)",
					&ip, &sp, &ep) != 3) {
				printf("Public IP or Port-range is invalid\n");
				return -1;
			}

			if (ip <= 0 || sp <= 0 || ep <= 0 || sp > ep) {
				printf("Public IP or Port-range is invalid "
				"%x:%d-%d\n", ip, sp, ep);
				return -1;
			}

			printf("public_ip: 0x%x Range:%d-%d\n",
			p->pub_ip_port_set[public_ip_count].ip = ip,
			p->pub_ip_port_set[public_ip_count].start_port = sp,
			p->pub_ip_port_set[public_ip_count].end_port = ep);

			napt_port_alloc_elem_count += (ep - sp + 1);
			printf("parse - napt_port_alloc_elem_count :%d\n",
				napt_port_alloc_elem_count);

		/* Store all public IPs of all CGNAPT threads
		* in the global variable
		*/
		 /* to revisit indexing */
			all_public_ip[rte_jhash(&ip, 4, 0) %
				CGNAPT_MAX_PUB_IP].ip = ip;
			p->pub_ip_count = ++public_ip_count;
			printf("public_ip_count:%d hash:%d\n", public_ip_count,
					 rte_jhash(&ip, 4, 0) % CGNAPT_MAX_PUB_IP);
			continue;
		}

		/* hw_checksum_reqd */
		if (strcmp(arg_name, "hw_checksum_reqd") == 0) {
			int temp;
			temp = atoi(arg_value);
			if ((temp != 0) && (temp != 1)) {
				printf("hw_checksum_reqd is invalid\n");
				return -1;
			}
			p->hw_checksum_reqd = temp;
			continue;
		}

		/* nat_only_config_flag */
		if (strcmp(arg_name, "nat_only_config_flag") == 0) {
			nat_only_config_flag = 1;
			if (public_ip_port_range_present) {

			printf("CG-NAPT parse error:");
			printf("nat_only_config_flag with "
			"public_ip_port_range_present\n");
				return -1;
			}
			continue;
		}

		/*  max_port_per_client */
		if (strcmp(arg_name, "max_port_per_client") == 0) {
			if (max_port_present) {
				printf("CG-NAPT Parse Error: "
				"duplicate max_port_per_client\n");
				return -1;
			}
			max_port_present = 1;

			int max = 0;
			max = atoi(arg_value);
			if (max <= 0) {
				printf("max_port_per_client is invalid !!!\n");
				return -1;
			}

			p->max_port_per_client = (uint16_t) max;

			if (p->max_port_per_client <= 0) {
				printf("max port per client is invalid\n");
				return -1;
			}

			printf("max_port_per_client comp: %d\n",
					 p->max_port_per_client);
			continue;
		}

		/*  max_clients_per_ip */
		if (strcmp(arg_name, "max_clients_per_ip") == 0) {
			if (max_client_present) {
				printf("CG-NAPT parse Error: duplicate "
				"max_clients_per_ip\n");
				return -1;
			}
			max_client_present = 1;

			if (nat_only_config_flag) {
				printf("CG-NAPT parse error:");
				printf("nat_only_config_flag with "
				"max_clients_per_ip\n");
				return -1;
			}

			int max = 0;
			max = atoi(arg_value);
			if (max <= 0) {
				printf("max_clients_per_ip is invalid !!!\n");
				return -1;
			}

			p->max_clients_per_ip = (uint16_t) max;

			if (p->max_clients_per_ip <= 0) {
				printf("max_clients_per_ip is invalid\n");
				return -1;
			}

			printf("max_clients_per_ip: %d\n",
					 p->max_clients_per_ip);
			continue;
		}

		/* n_entries */
		if (strcmp(arg_name, "n_entries") == 0) {
			if (n_entries_present)
				return -1;
			n_entries_present = 1;

			p->n_entries = atoi(arg_value);
			if (p->n_entries == 0)
				return -1;

			continue;
		}

		/* n_flows */
		if (strcmp(arg_name, "n_flows") == 0) {
			if (n_flows_present)
				return -1;
			n_flows_present = 1;

			p->n_flows = atoi(arg_value);
			if (p->n_flows == 0)
				return -1;

			napt_common_table_hash_params.entries = p->n_flows;
			continue;
		}
		/* dest_if_offset Multiport Changes */
		if (strcmp(arg_name, "dest_if_offset") == 0) {
			if (dest_if_offset_present)
				return -1;
			//dest_if_offset_present = 1;

			dest_if_offset = atoi(arg_value);

			continue;
		}

		/* key_offset */
		if (strcmp(arg_name, "key_offset") == 0) {
			if (key_offset_present)
				return -1;
			key_offset_present = 1;

			p->key_offset = atoi(arg_value);

			continue;
		}

		/* key_size */
		if (strcmp(arg_name, "key_size") == 0) {
			if (key_size_present)
				return -1;
			key_size_present = 1;

			p->key_size = atoi(arg_value);
			if ((p->key_size == 0) ||
				(p->key_size > PIPELINE_CGNAPT_KEY_MAX_SIZE) ||
				(p->key_size % 8))
				return -1;

			continue;
		}

		/* hash_offset */
		if (strcmp(arg_name, "hash_offset") == 0) {
			if (hash_offset_present)
				return -1;
			hash_offset_present = 1;

			p->hash_offset = atoi(arg_value);

			continue;
		}

		/* traffic_type */
		if (strcmp(arg_name, "pkt_type") == 0) {
			if (strcmp(arg_value, "ipv4") == 0) {
				p->traffic_type = TRAFFIC_TYPE_IPV4;
				printf("Traffic is set to IPv4\n");
			} else if (strcmp(arg_value, "ipv6") == 0) {
				p->traffic_type = TRAFFIC_TYPE_IPV6;
				printf("Traffic is set to IPv6\n");
			}
			continue;
		}

		/* cgnapt_debug */
		if (strcmp(arg_name, "cgnapt_debug") == 0) {
			CGNAPT_DEBUG = atoi(arg_value);

			continue;
		}

		/* any other  Unknown argument return -1 */
	}

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag) {
		if (!public_ip_range_count) {
			printf("No public_ip_range %d for NAT only config.\n",
					 public_ip_range_count);
			printf("Running static NAT only configuration\n");
			p->is_static_cgnapt = 1;
		}
	}
	#else

	if (!p->max_port_per_client)
		p->is_static_cgnapt = 1;
	#endif

	/* Check that mandatory arguments are present */
	if ((n_flows_present == 0) ||
		(cgnapt_meta_offset_present == 0))
		return -1;

	return 0;

}
/**
 * Function to initialize the pipeline
 *
 * @param params
 *  A pointer to struct pipeline_params
 * @param arg
 *  Void pointer - points to app params
 *
 * @return
 *  void pointer to the pipeline, NULL 0 if failure
 */
static void *pipeline_cgnapt_init(struct pipeline_params *params, void *arg)
	/* (struct app_params *app) save it for use in port in handler */
{
	struct pipeline *p;
	struct pipeline_cgnapt *p_nat;
	uint32_t size, i, in_ports_arg_size;

	/* Check input arguments */
	if ((params == NULL) ||
		(params->n_ports_in == 0) || (params->n_ports_out == 0))
		return NULL;

	/* Memory allocation */
	size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct pipeline_cgnapt));
	p = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
	p_nat = (struct pipeline_cgnapt *)p;
	global_pnat = p_nat;
	if (p == NULL)
		return NULL;

	all_pipeline_cgnapt[n_cgnapt_pipeline++] = p_nat;

	strcpy(p->name, params->name);
	p->log_level = params->log_level;

	PLOG(p, HIGH, "CG-NAPT");
	/* Initialize all counters and arrays */

	p_nat->n_cgnapt_entry_deleted = 0;
	p_nat->n_cgnapt_entry_added = 0;
	p_nat->naptedPktCount = 0;
	p_nat->naptDroppedPktCount = 0;
	p_nat->inaptedPktCount = 0;
	p_nat->enaptedPktCount = 0;
	p_nat->receivedPktCount = 0;
	p_nat->missedPktCount = 0;
	p_nat->dynCgnaptCount = 0;
	p_nat->arpicmpPktCount = 0;

	p_nat->app_params_addr = (uint64_t) arg;
	for (i = 0; i < PIPELINE_MAX_PORT_IN; i++) {
		p_nat->links_map[i] = 0xff;
		p_nat->outport_id[i] = 0xff;
		cgnapt_in_port_egress_prv[i] = 0;
		cgnapt_prv_que_port_index[i] = 0;
	}
	p_nat->pipeline_num = 0xff;
	p_nat->hw_checksum_reqd = 0;
	p_nat->pub_ip_port_set = NULL;
	p_nat->pub_ip_count = 0;
	p_nat->traffic_type = TRAFFIC_TYPE_MIX;
	p_nat->vnf_set = 0xff;

	/* For every init it should be reset */
	napt_port_alloc_elem_count = 0;

	#ifdef CGNAPT_TIMING_INST
	p_nat->in_port_exit_timestamp = 0;
	p_nat->external_time_sum = 0;
	p_nat->internal_time_sum = 0;
	p_nat->time_measurements = 0;
	p_nat->max_time_mesurements = 10000;
	p_nat->time_measurements_on = 0;
	#endif

	#ifdef CGNAPT_DEBUGGING

	p_nat->naptDebugCount = 0;

	p_nat->naptDroppedPktCount1 = 0;
	p_nat->naptDroppedPktCount2 = 0;
	p_nat->naptDroppedPktCount3 = 0;
	p_nat->naptDroppedPktCount4 = 0;
	p_nat->naptDroppedPktCount5 = 0;
	p_nat->naptDroppedPktCount6 = 0;

	p_nat->missedpktcount1 = 0;
	p_nat->missedpktcount2 = 0;
	p_nat->missedpktcount3 = 0;
	p_nat->missedpktcount4 = 0;
	p_nat->missedpktcount5 = 0;
	p_nat->missedpktcount6 = 0;
	p_nat->missedpktcount7 = 0;
	p_nat->missedpktcount8 = 0;
	p_nat->missedpktcount9 = 0;
	p_nat->missedpktcount10 = 0;
	p_nat->missedpktcount11 = 0;
	p_nat->missedpktcount12 = 0;

	p_nat->max_port_dec_err1 = 0;
	p_nat->max_port_dec_err2 = 0;
	p_nat->max_port_dec_err3 = 0;
	p_nat->max_port_dec_success = 0;

	p_nat->pfb_err = 0;
	p_nat->pfb_ret = 0;
	p_nat->pfb_get = 0;
	p_nat->pfb_suc = 0;
	p_nat->gfp_suc = 0;
	p_nat->gfp_get = 0;
	p_nat->gfp_ret = 0;
	p_nat->gfp_err = 0;

	p_nat->kpc2 = 0;
	p_nat->kpc1 = 0;
	#endif

	#ifdef SIP_ALG
	static int sip_enabled;
	if (!sip_enabled)
		lib_sip_alg_init();
	sip_enabled = 1;
	#endif /* SIP_ALG */

	/*struct rte_pipeline_table_entry *entries[RTE_HASH_LOOKUP_BULK_MAX];*/
	/* bitmap of valid packets */
	p_nat->valid_packets = 0;
	/* bitmap of invalid packets to be dropped */
	p_nat->invalid_packets = 0;

	for (i = 0; i < RTE_HASH_LOOKUP_BULK_MAX; i++)
		p_nat->key_ptrs[i] = &(p_nat->keys[i]);

	p_nat->port_alloc_ring = NULL;

	/* Parse arguments */
	if (pipeline_cgnapt_parse_args(p_nat, params))
		return NULL;

	p_nat->vnf_set = vnf_set_count;

	/* Pipeline */
	{
		struct rte_pipeline_params pipeline_params = {
			.name = params->name,
			.socket_id = params->socket_id,
			.offset_port_id = cgnapt_meta_offset,
		};

		p->p = rte_pipeline_create(&pipeline_params);
		if (p->p == NULL) {
			rte_free(p);
			return NULL;
		}
		myP = p->p;
	}

	#ifdef PIPELINE_CGNAPT_INSTRUMENTATION

	uint32_t instr_size =
		RTE_CACHE_LINE_ROUNDUP((sizeof(uint64_t)) *
			(INST_ARRAY_SIZE));
	inst_start_time =
		(uint64_t *) rte_zmalloc(NULL, instr_size,
		RTE_CACHE_LINE_SIZE);
	inst_end_time =
		(uint64_t *) rte_zmalloc(NULL, instr_size,
			RTE_CACHE_LINE_SIZE);
	inst_diff_time =
		(uint32_t *) rte_zmalloc(NULL, instr_size / 2,
			RTE_CACHE_LINE_SIZE);
	if ((inst_start_time == NULL) || (inst_end_time == NULL)
		|| (inst_diff_time == NULL)) {
		printf("Inst array alloc failed .... ");
		return NULL;
	}
	#endif

	/* Memory allocation for in_port_h_arg */
	in_ports_arg_size = RTE_CACHE_LINE_ROUNDUP(
			(sizeof(struct pipeline_cgnapt_in_port_h_arg)) *
					 (params->n_ports_in));
	struct pipeline_cgnapt_in_port_h_arg *ap =
		(struct pipeline_cgnapt_in_port_h_arg *)
			rte_zmalloc(NULL,
				in_ports_arg_size,
				RTE_CACHE_LINE_SIZE);
	if (ap == NULL)
		return NULL;

	myApp = (struct app_params *) arg;

	/* Input ports */
	p->n_ports_in = params->n_ports_in;
	for (i = 0; i < p->n_ports_in; i++) {
		/* passing our cgnapt pipeline in call back arg */
		(ap[i]).p = p_nat;
		(ap[i]).in_port_id = i;

		struct rte_pipeline_port_in_params port_params = {
			.ops =
				pipeline_port_in_params_get_ops(&params->port_in
								[i]),
			.arg_create =
				pipeline_port_in_params_convert(&params->port_in
								[i]),
			.f_action = cgnapt_in_port_ah_mix,
			.arg_ah = &(ap[i]),
			.burst_size = params->port_in[i].burst_size,
		};

		#ifdef PIPELINE_CGNAPT_INSTRUMENTATION
		if (i == 0)
			instrumentation_port_in_arg = &(ap[i]);
		#endif

		if (p_nat->traffic_type == TRAFFIC_TYPE_IPV4) {
			/* Private in-port handler */
			/* Multiport changes */
			if (cgnapt_in_port_egress_prv[i]) {
				port_params.f_action =
					cgnapt_in_port_ah_ipv4_prv;
				printf("CGNAPT port %d is IPv4 Prv\n", i);
			} else{
				port_params.f_action =
					cgnapt_in_port_ah_ipv4_pub;
				printf("CGNAPT port %d is IPv4 Pub\n", i);
			}
		}

		if (p_nat->traffic_type == TRAFFIC_TYPE_IPV6) {
			if (cgnapt_in_port_egress_prv[i]) {
				port_params.f_action =
					cgnapt_in_port_ah_ipv6_prv;
				printf("CGNAPT port %d is IPv6 Prv\n", i);
			} else{
				port_params.f_action =
					cgnapt_in_port_ah_ipv6_pub;
				printf("CGNAPT port %d is IPv6 Pub\n", i);
			}
		}

		int status = rte_pipeline_port_in_create(p->p,
							 &port_params,
							 &p->port_in_id[i]);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}

	}

	/* Output ports */
	p->n_ports_out = params->n_ports_out;
	for (i = 0; i < p->n_ports_out; i++) {
		struct rte_pipeline_port_out_params port_params = {
			.ops = pipeline_port_out_params_get_ops(
						&params->port_out[i]),
			.arg_create = pipeline_port_out_params_convert(
					&params->port_out[i]),
			#ifdef PIPELINE_CGNAPT_INSTRUMENTATION
			.f_action = port_out_ah_cgnapt,
			#else
			.f_action = NULL,
			#endif
			.arg_ah = NULL,
		};

		int status = rte_pipeline_port_out_create(p->p,
								&port_params,
								&p->port_out_id[i]);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}
	}

	int pipeline_num = 0;
	int ignore;
	ignore = sscanf(params->name, "PIPELINE%d", &pipeline_num);
	if (ignore != 1) {
		printf("Not able to read pipeline number\n");
		return NULL;
	}
		p_nat->pipeline_num = (uint8_t) pipeline_num;
	register_pipeline_Qs(p_nat->pipeline_num, p);
	set_link_map(p_nat->pipeline_num, p, p_nat->links_map);
	set_outport_id(p_nat->pipeline_num, p, p_nat->outport_id);

	/* Tables */
	p->n_tables = 1;
	{

		if (napt_common_table == NULL) {
			if (create_napt_common_table(p_nat->n_flows)) {
				PLOG(p, HIGH,
				"CG-NAPT create_napt_common_table failed.");
				return NULL;
			}
		}

		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_stub_ops,
			.arg_create = NULL,
			.f_action_hit = NULL,
			.f_action_miss = NULL,
			.arg_ah = NULL,
			.action_data_size = 0,
		};

		int status = rte_pipeline_table_create(p->p,
								 &table_params,
								 &p->table_id[0]);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}
		struct rte_pipeline_table_entry default_entry = {
			.action = RTE_PIPELINE_ACTION_PORT_META
		};
		struct rte_pipeline_table_entry *default_entry_ptr;
		status = rte_pipeline_table_default_entry_add(
				p->p,
				p->table_id[0],
				&default_entry,
				&default_entry_ptr);
		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}
	}

	/* Connecting input ports to tables */
	for (i = 0; i < p->n_ports_in; i++) {
		int status = rte_pipeline_port_in_connect_to_table(p->p,
									 p->port_in_id
									 [i],
									 p->table_id
									 [0]);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}
	}

	/* Enable input ports */
	for (i = 0; i < p->n_ports_in; i++) {
		int status = rte_pipeline_port_in_enable(p->p,
							 p->port_in_id[i]);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}
	}

	/* Check pipeline consistency */
	if (rte_pipeline_check(p->p) < 0) {
		rte_pipeline_free(p->p);
		rte_free(p);
		return NULL;
	}

	/* Message queues */
	p->n_msgq = params->n_msgq;
	for (i = 0; i < p->n_msgq; i++)
		p->msgq_in[i] = params->msgq_in[i];
	for (i = 0; i < p->n_msgq; i++)
		p->msgq_out[i] = params->msgq_out[i];

	/* Message handlers */
	memcpy(p->handlers, handlers, sizeof(p->handlers));
	memcpy(p_nat->custom_handlers,
			 custom_handlers, sizeof(p_nat->custom_handlers));

	if (!p_nat->is_static_cgnapt) {
		printf("Initializing dyn napt components ... %d\n",
				 p_nat->pipeline_num);
		if (napt_port_alloc_init(p_nat) == -1) {
			printf("Error - napt_port_alloc_init failed - %d\n",
					 p_nat->pipeline_num);
			return NULL;
		}
		int rc = 0;

		if (max_port_per_client_hash == NULL) {
			rc = init_max_port_per_client(p_nat);
			if (rc < 0) {
				printf("CGNAPT Error - "
				"init_max_port_per_client failed %d", rc);
				return NULL;
			}
		}

	}

	if (!icmp_pool_init) {
		icmp_pool_init = 1;
		/* create the arp_icmp mbuf rx pool */
		cgnapt_icmp_pktmbuf_tx_pool =
			rte_pktmbuf_pool_create("icmp_mbuf_tx_pool", 63, 32, 0,
						RTE_MBUF_DEFAULT_BUF_SIZE,
						rte_socket_id());
		if (cgnapt_icmp_pktmbuf_tx_pool == NULL) {
			PLOG(p, HIGH, "ICMP mbuf pool create failed.");
			return NULL;
		}

		cgnapt_icmp_pkt =
			rte_pktmbuf_alloc(cgnapt_icmp_pktmbuf_tx_pool);

		if (cgnapt_icmp_pkt == NULL) {
			printf("Failed to allocate cgnapt_icmp_pkt\n");
			return NULL;
		}
	}

	#ifdef CT_CGNAT

	cgnat_cnxn_tracker =  rte_zmalloc(NULL, rte_ct_get_cnxn_tracker_size(),
				RTE_CACHE_LINE_SIZE);

	if (cgnat_cnxn_tracker == NULL) {
		printf("CGNAPT CT memory not allocated\n");
		return NULL;
	}
	rte_ct_initialize_default_timeouts(cgnat_cnxn_tracker);

	printf("CGNAPT CT Flows %d\n", p_nat->n_flows);
	int ret;
	ret = rte_ct_initialize_cnxn_tracker(cgnat_cnxn_tracker,
							p_nat->n_flows,
							"CGNAT_CT_COMMON_TABLE");
	if (ret == -1)
		return NULL;
	#endif

	#ifdef FTP_ALG
	lib_ftp_alg_init();
	#endif

	#ifdef PCP_ENABLE
	if (pcp_init() == PCP_INIT_SUCCESS)
		printf("PCP contents are initialized successfully\n");
	else
		printf("Error in initializing PCP contents\n");
	#endif

	return p;
}

/**
 * Function for pipeline cleanup
 *
 * @param pipeline
 *  A void pointer to pipeline
 *
 * @return
 *  0
 */
static int pipeline_cgnapt_free(void *pipeline)
{
	struct pipeline *p = (struct pipeline *)pipeline;

	/* Check input arguments */
	if (p == NULL)
		return -1;

	/* Free resources */
	rte_pipeline_free(p->p);
	rte_free(p);
	return 0;
}

static int
pipeline_cgnapt_track(void *pipeline, __rte_unused uint32_t port_in,
				uint32_t *port_out)
{
	struct pipeline *p = (struct pipeline *)pipeline;

	/* Check input arguments */
	if ((p == NULL) || (port_in >= p->n_ports_in) || (port_out == NULL))
		return -1;

	if (p->n_ports_in == 1) {
		*port_out = 0;
		return 0;
	}

	return -1;
}

/**
 * Function for pipeline timers
 *
 * @param pipeline
 *  A void pointer to pipeline
 *
 * @return
 *  0
 */
static int pipeline_cgnapt_timer(void *pipeline)
{
	struct pipeline_cgnapt *p_nat = (struct pipeline_cgnapt *)pipeline;

	pipeline_msg_req_handle(&p_nat->p);

	rte_pipeline_flush(((struct pipeline *)p_nat)->p);

	return 0;
}

/**
 * Function for pipeline custom handlers
 *
 * @param pipeline
 *  A void pointer to pipeline
 * @param msg
 *  void pointer for incoming data
 *
 * @return
 *  void pointer of response
 */
void *pipeline_cgnapt_msg_req_custom_handler(struct pipeline *p, void *msg)
{
	struct pipeline_cgnapt *p_nat = (struct pipeline_cgnapt *)p;
	struct pipeline_custom_msg_req *req = msg;
	pipeline_msg_req_handler f_handle;

	f_handle = (req->subtype < PIPELINE_CGNAPT_MSG_REQS) ?
		p_nat->custom_handlers[req->subtype] :
		pipeline_msg_req_invalid_handler;

	if (f_handle == NULL)
		f_handle = pipeline_msg_req_invalid_handler;

	return f_handle(p, req);
}

/**
 * Function for adding NSP data
 *
 * @param pipeline
 *  A void pointer to pipeline
 * @param msg
 *  void pointer for incoming data
 *
 * @return
 *  void pointer of response
 */
void *pipeline_cgnapt_msg_req_nsp_add_handler(
	__rte_unused struct pipeline *p,
	void *msg)
{
	struct pipeline_cgnapt_nsp_add_msg_req *req = msg;
	struct pipeline_cgnapt_nsp_add_msg_rsp *rsp = msg;
	int size = 0;
	struct cgnapt_nsp_node *node = NULL, *ll = nsp_ll;

	if (!
		(req->nsp.depth == 32 || req->nsp.depth == 40
		 || req->nsp.depth == 48 || req->nsp.depth == 56
		 || req->nsp.depth == 64 || req->nsp.depth == 96)) {
		rsp->status = 0xE;
		rsp->key_found = 0;
		return rsp;
	}

	printf("be initial cond\n");
	if (nsp_ll == NULL) {
		size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct cgnapt_nsp_node));
		node = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
		if (node == NULL) {
			printf("be 1st cond\n");
			rsp->status = 0xE;
			rsp->key_found = 0;
			return rsp;
		}

		memcpy(&node->nsp, &req->nsp,
				 sizeof(struct pipeline_cgnapt_nsp_t));
		node->next = NULL;
		nsp_ll = node;
	} else {
		while (ll != NULL) {
			if (!memcmp(ll->nsp.prefix, req->nsp.prefix, 16)
				&& ll->nsp.depth == req->nsp.depth) {
				printf("be 2st cond\n");
				rsp->status = 0xE;
				rsp->key_found = 1;
				return rsp;
			}
			ll = ll->next;
		}

		size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct cgnapt_nsp_node));
		node = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
		if (node == NULL) {
			printf("be 3st cond\n");
			rsp->status = 0xE;
			rsp->key_found = 0;
			return rsp;
		}

		memcpy(&node->nsp, &req->nsp,
				 sizeof(struct pipeline_cgnapt_nsp_t));
		node->next = nsp_ll;
		nsp_ll = node;
	}

	rsp->status = 0;
	rsp->key_found = 0;

	printf("be 4st cond\n");
	return rsp;
}

/**
 * Function for deleting NSP data
 *
 * @param pipeline
 *  A void pointer to pipeline
 * @param msg
 *  void pointer for incoming data
 *
 * @return
 *  void pointer of response
 */
void *pipeline_cgnapt_msg_req_nsp_del_handler(
	__rte_unused struct pipeline *p,
	void *msg)
{
	struct pipeline_cgnapt_nsp_del_msg_req *req = msg;
	struct pipeline_cgnapt_nsp_del_msg_rsp *rsp = msg;
	struct cgnapt_nsp_node *prev = NULL, *ll = nsp_ll;

	while (ll != NULL) {
		if (!memcmp(ll->nsp.prefix, req->nsp.prefix, 16)
			&& ll->nsp.depth == req->nsp.depth) {
			if (prev != NULL)
				prev->next = ll->next;
			else
				nsp_ll = NULL;

			rte_free(ll);

			rsp->status = 0;
			rsp->key_found = 1;

			return rsp;
		}

		prev = ll;
		ll = ll->next;
	}

	rsp->status = 0xE;
	rsp->key_found = 0;

	return rsp;
}

/**
 * Function for adding NAPT entry
 *
 * @param pipeline
 *  A void pointer to pipeline
 * @param msg
 *  void pointer for incoming data
 *
 * @return
 *  void pointer of response
 */
void *pipeline_cgnapt_msg_req_entry_add_handler(struct pipeline *p, void *msg)
{
	struct pipeline_cgnapt_entry_add_msg_req *req = msg;
	struct pipeline_cgnapt *p_nat = (struct pipeline_cgnapt *)p;
	uint8_t type = req->data.type;
	uint32_t src_ip = (type == CGNAPT_ENTRY_IPV4) ?
			req->data.u.prv_ip :
			rte_bswap32(req->data.u.u32_prv_ipv6[3]);

	uint8_t src_ipv6[16];

	uint32_t dest_ip = req->data.pub_ip;
	uint16_t src_port = req->data.prv_port;
	uint16_t dest_port = req->data.pub_port;
	uint16_t rx_port = req->data.prv_phy_port;
	uint32_t ttl = req->data.ttl;

	if (type == CGNAPT_ENTRY_IPV6)
		memcpy(src_ipv6, req->data.u.prv_ipv6, 16);

	printf("CG-NAPT addm - PrvIP %x, PrvPort %d,", src_ip, src_port);
	printf("PubIP %x, PubPort %d,", dest_ip, dest_port);

	 printf("PhyPort %d, ttl %u,", rx_port, ttl);
	 printf("entry_type %d\n", type);

	 #ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag) {
		if (!p_nat->is_static_cgnapt) {
			int i;

		for (i = 0; i < p_nat->pub_ip_range_count; i++) {
			if (((dest_ip >= p_nat->pub_ip_range[i].start_ip)
			&& (dest_ip <= p_nat->pub_ip_range[i].end_ip))) {
			printf("Error - static port cannot be in Dynamic "
				"port range");
			printf("%x-%x\n", p_nat->pub_ip_range[i].start_ip,
				p_nat->pub_ip_range[i].end_ip);
				return msg;
			}
		}
	}

		if (pipeline_cgnapt_msg_req_entry_addm_pair(p, msg,
			src_ip, src_port,
			dest_ip, dest_port,
			rx_port, ttl,
			type, src_ipv6)) {
			printf("Error - ");
			printf("pipeline_cgnapt_msg_req_entry_addm_handler\n");
				return msg;
		}

		printf("Success - pipeline_cgnapt_msg_req_entry_addm_handler");
		printf("added %d rule pairs.\n", count);

		return msg;
	}
	 #endif

	if (!p_nat->is_static_cgnapt) {
		int i;

	for (i = 0; i < p_nat->pub_ip_count; i++) {
			 /* Check port range if same Public-IP */
		if (dest_ip != p_nat->pub_ip_port_set[i].ip)
			continue;
		if (((dest_port >= p_nat->pub_ip_port_set[i].start_port) &&
			(dest_port <= p_nat->pub_ip_port_set[i].end_port))) {
			printf("Error - port cannot be in Dynamic "
			"port range %d-%d\n",
			p_nat->pub_ip_port_set[i].start_port,
			p_nat->pub_ip_port_set[i].end_port);
				return msg;
		}
	}
	}

	if (pipeline_cgnapt_msg_req_entry_addm_pair
		(p, msg, src_ip, src_port, dest_ip, dest_port, rx_port,
		ttl, type, src_ipv6)) {
		printf("Error - pipeline_cgnapt_msg_req_entry_add_handler\n");
			return msg;
	}


	 printf("\nSuccess - pipeline_cgnapt_msg_req_entry_add_handler "
		"added\n");

	return msg;
}

/**
 * Function for adding a NAPT entry pair
 *
 * @param pipeline
 *  A void pointer to pipeline
 * @param msg
 *  void pointer for incoming data
 * @param src_ip
 *  source ip address
 * @param src_port
 *  source port
 * @param dest_ip
 *  destination ip address
 * @param dest_port
 *  destination port
 * @param rx_port
 *  Physical receive port
 * @param ttl
 * time to live value
 * @param type
 *  type of entry IPv4 vs IPv6
 * @param src_ipv6[]
 *  uint8_t array of IPv6 address
 *
 * @return
 *  0 if success, negative if fails
 */
int
pipeline_cgnapt_msg_req_entry_addm_pair(
	struct pipeline *p, __rte_unused void *msg,
	uint32_t src_ip, uint16_t src_port,
	uint32_t dest_ip, uint16_t dest_port,
	uint16_t rx_port, uint32_t ttl,
	uint8_t type, uint8_t src_ipv6[16])
{

	struct pipeline_cgnapt_entry_key key;
	struct pipeline_cgnapt *p_nat = (struct pipeline_cgnapt *)p;

	key.ip = src_ip;
	key.port = src_port;
	key.pid = rx_port;

	struct cgnapt_table_entry entry = {
		.head = {
			 .action = RTE_PIPELINE_ACTION_PORT,
			 .port_id = CGNAPT_PUB_PORT_ID,
			 },

		.data = {
			 /*.prv_ip = src_ip, */
			 .prv_port = src_port,
			 .pub_ip = dest_ip,
			 .pub_port = dest_port,
			 .prv_phy_port = rx_port,
			 .pub_phy_port = get_prv_to_pub_port(&dest_ip,
						IP_VERSION_4),
			 .ttl = ttl,
			 .timeout = STATIC_CGNAPT_TIMEOUT,
			 #ifdef PCP_ENABLE
			 .timer = NULL,
			 #endif
			}
	};

	if (type == CGNAPT_ENTRY_IPV4) {
		entry.data.type = CGNAPT_ENTRY_IPV4;
		entry.data.u.prv_ip = src_ip;
	} else {
		entry.data.type = CGNAPT_ENTRY_IPV6;
		memcpy(entry.data.u.prv_ipv6, src_ipv6, 16);
	}

	/* Also need to add a paired entry on our own */
	/*
	* Need to change key
	* Need to change entry header
	* Will keep the same entry and take care
	* of translation in table hit handler
	*/
	struct pipeline_cgnapt_entry_key second_key;

	/* Need to add a second ingress entry */
	second_key.ip = dest_ip;
	second_key.port = dest_port;
	second_key.pid = 0xffff;

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag) {
		key.port = 0xffff;
		entry.data.pub_port = 0xffff;
		second_key.port = 0xffff;
	}
	#endif

	//if (CGNAPT_DEBUG > 2)
		//printf("key.ip %x, key.port %d", key.ip, key.port);
		//printf("key.pid %d, in_type %d,", key.pid, type);
		//printf("entry_type %d\n", entry.data.type);

	int32_t position = rte_hash_add_key(napt_common_table, &key);

	if (position < 0) {
		printf("CG-NAPT entry bulk add failed");
		printf(" ... returning without adding ...\n");
		return -1;
	}

	memcpy(&napt_hash_tbl_entries[position], &entry,
			 sizeof(struct cgnapt_table_entry));

	#ifdef CGNAPT_DEBUGGING
	if (p_nat->kpc1++ < 5)
		print_key(&key);
	#endif

	p_nat->n_cgnapt_entry_added++;

	/* Now modify the forward port for reverse entry */
	entry.head.port_id = CGNAPT_PRV_PORT_ID;

	position = rte_hash_add_key(napt_common_table, &second_key);

	if (position < 0) {
		printf("CG-NAPT entry reverse bulk add failed");
		printf(" ... returning with fwd add ...%d\n", position);
		return 2;
	}

	memcpy(&napt_hash_tbl_entries[position], &entry,
			 sizeof(struct cgnapt_table_entry));

	#ifdef CGNAPT_DEBUGGING
	if (p_nat->kpc1 < 5)
		print_key(&second_key);
	#endif

	p_nat->n_cgnapt_entry_added++;
	return 0;
}

/**
 * Function for adding multiple NAPT entries
 *
 * @param pipeline
 *  A void pointer to pipeline
 * @param msg
 *  void pointer for incoming data
 *
 * @return
 *  void pointer of response
 */
void *pipeline_cgnapt_msg_req_entry_addm_handler(struct pipeline *p, void *msg)
{
	struct pipeline_cgnapt_entry_addm_msg_req *req = msg;
	struct pipeline_cgnapt *p_nat = (struct pipeline_cgnapt *)p;
	uint32_t uenum = 0;
	uint32_t max_ue = req->data.num_ue;
	uint8_t type = req->data.type;
	uint32_t src_ip = (type == CGNAPT_ENTRY_IPV4) ?
			req->data.u.prv_ip :
			rte_bswap32(req->data.u.u32_prv_ipv6[3]);

	uint8_t src_ipv6[16];

	uint32_t dest_ip = req->data.pub_ip;
	uint16_t src_port = req->data.prv_port;
	uint16_t dest_port = req->data.pub_port;
	uint16_t rx_port = req->data.prv_phy_port;
	uint32_t ttl = req->data.ttl;
	uint16_t max_src_port = req->data.prv_port_max;
	uint16_t max_dest_port = req->data.pub_port_max;
	uint32_t count = 0;
	uint16_t src_port_start = src_port;
	uint16_t dest_port_start = dest_port;
	uint32_t src_ip_temp;

	if (type == CGNAPT_ENTRY_IPV6)
		memcpy(src_ipv6, req->data.u.prv_ipv6, 16);

	printf("CG-NAPT addm - PrvIP %x, PrvPort %d,", src_ip, src_port);
	printf("PubIP %x, PubPort %d,", dest_ip, dest_port);
	printf("PhyPort %d, ttl %u, NumUe %d,", rx_port, ttl, max_ue);
	printf("mPrvPort %d, mPubPort %d,", max_src_port, max_dest_port);
	printf("entry_type %d\n", type);

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag) {
		if (!p_nat->is_static_cgnapt) {
			int i;

		for (i = 0; i < p_nat->pub_ip_range_count; i++) {
			if (((dest_ip >= p_nat->pub_ip_range[i].start_ip)
			&& (dest_ip <= p_nat->pub_ip_range[i].end_ip)) ||
			(((dest_ip + max_ue) >=
						p_nat->pub_ip_range[i].start_ip) &&
			((dest_ip + max_ue) <=
					 p_nat->pub_ip_range[i].end_ip))) {
			printf("Error - static port cannot be in Dynamic "
				"port range");
			printf("%x-%x\n", p_nat->pub_ip_range[i].start_ip,
				p_nat->pub_ip_range[i].end_ip);

				return msg;
				}
			}
		}

		for (uenum = 0; uenum < max_ue; uenum++) {

		if (pipeline_cgnapt_msg_req_entry_addm_pair(p, msg,
			src_ip, src_port,
			dest_ip, dest_port,
			rx_port, ttl,
			type, src_ipv6)) {
			printf("Error - ");
			printf("pipeline_cgnapt_msg_req_entry_addm_handler\n");
				return msg;
			}

			count++;

			src_ip++;
			dest_ip++;
		}

		printf("Success - pipeline_cgnapt_msg_req_entry_addm_handler");
		printf("added %d rule pairs.\n", count);

		return msg;
	}
	#endif

	if (!p_nat->is_static_cgnapt) {
		int i;

	for (i = 0; i < p_nat->pub_ip_count; i++) {
			/* Check port range if same Public-IP */
		if (dest_ip != p_nat->pub_ip_port_set[i].ip)
			continue;
		if (((dest_port >= p_nat->pub_ip_port_set[i].start_port) &&
			(dest_port <= p_nat->pub_ip_port_set[i].end_port)) ||
		((max_dest_port >= p_nat->pub_ip_port_set[i].start_port)
		&& max_dest_port <= p_nat->pub_ip_port_set[i].end_port)) {
		printf("Error - port cannot be in Dynamic port range %d-%d\n",
			p_nat->pub_ip_port_set[i].start_port,
			p_nat->pub_ip_port_set[i].end_port);
				return msg;
		}
	}
	}

	for (uenum = 0; uenum < max_ue; uenum++) {
		if (pipeline_cgnapt_msg_req_entry_addm_pair
			(p, msg, src_ip, src_port, dest_ip, dest_port, rx_port,
			 ttl, type, src_ipv6)) {
		printf("Error - pipeline_cgnapt_msg_req_entry_addm_handler\n");
			return msg;
		}

		count++;

		src_port++;
		if (src_port > max_src_port) {
			src_port = src_port_start;
			src_ip++;
			if (req->data.type == CGNAPT_ENTRY_IPV6) {
				src_ip_temp = rte_bswap32(src_ip);
				memcpy(&src_ipv6[12], &src_ip_temp, 4);
			}
		}
		dest_port++;
		if (dest_port > max_dest_port) {
			dest_port = dest_port_start;
			dest_ip++;
		}
	}

	printf("\nSuccess - pipeline_cgnapt_msg_req_entry_addm_handler added");
	printf("%d rule pairs.\n", count);

	return msg;
}

/**
 * Function for deleting NAPT entry
 *
 * @param pipeline
 *  A void pointer to pipeline
 * @param msg
 *  void pointer for incoming data
 *
 * @return
 *  void pointer of response
 */
void *pipeline_cgnapt_msg_req_entry_del_handler(struct pipeline *p, void *msg)
{
	struct pipeline_cgnapt_entry_delete_msg_req *req = msg;
	struct pipeline_cgnapt_entry_delete_msg_rsp *rsp = msg;
	struct pipeline_cgnapt *p_nat = (struct pipeline_cgnapt *)p;

	if (CGNAPT_DEBUG) {
		uint8_t *KeyP = (void *)(&req->key);
		int i = 0;

		printf("pipeline_cgnapt_msg_req_entry_del_handler - Key: ");
		for (i = 0; i < (int)sizeof(struct pipeline_cgnapt_entry_key);
			 i++)
			printf(" %02x", KeyP[i]);
		printf(" ,KeySize %u\n",
				 (int)sizeof(struct pipeline_cgnapt_entry_key));
	}

	struct cgnapt_table_entry entry;

	/* If ingress key */
	if (!is_phy_port_privte(req->key.pid))
		req->key.pid = 0xffff;

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		req->key.port = 0xffff;
	#endif

	int32_t position;
	position = rte_hash_lookup(napt_common_table, &req->key);
	if (position == -ENOENT) {
		printf("Entry not found\n");
		return NULL;
	}
	memcpy(&entry, &napt_hash_tbl_entries[position],
		sizeof(struct cgnapt_table_entry));
	position = rte_hash_del_key(napt_common_table, &req->key);
	p_nat->n_cgnapt_entry_deleted++;

	struct pipeline_cgnapt_entry_key second_key;

	if (is_phy_port_privte(req->key.pid)) {
		/* key is for egress - make second key for ingress */
		second_key.ip = entry.data.pub_ip;
		second_key.port = entry.data.pub_port;
		second_key.pid = 0xffff;

	} else {
		/* key is for ingress - make second key for egress */
		second_key.ip = entry.data.u.prv_ip;
		second_key.port = entry.data.prv_port;
		second_key.pid = entry.data.prv_phy_port;
	}

	#ifdef NAT_ONLY_CONFIG_REQ
	if (nat_only_config_flag)
		second_key.port = 0xffff;
	#endif

	position = rte_hash_del_key(napt_common_table, &second_key);
	p_nat->n_cgnapt_entry_deleted++;

	return rsp;
}

void *pipeline_cgnapt_msg_req_entry_sync_handler(struct pipeline *p, void *msg)
{
	struct pipeline_cgnapt_entry_delete_msg_req *req = msg;
	struct pipeline_cgnapt_entry_delete_msg_rsp *rsp = msg;

	rsp->status = rte_pipeline_table_entry_delete(
				p->p,
				p->table_id[0],
				&req->key,
				&rsp->key_found, NULL);

	return rsp;
}

/**
 * Function to print the NAPT key
 *
 * @param key
 *  A pointer to struct pipeline_cgnapt_entry_key
 */
void print_key(struct pipeline_cgnapt_entry_key *key)
{
	uint8_t *KeyP = (void *)(key);
	int i = 0;

	printf("\nKey: ");
	for (i = 0; i < (int)sizeof(struct pipeline_cgnapt_entry_key); i++)
		printf(" %02x", KeyP[i]);
}

/**
 * Function to print the table entry
 *
 * @param entry
 *  A pointer to struct rte_pipeline_table_entry
 */
void print_entry1(struct rte_pipeline_table_entry *entry)
{
	uint8_t *entryP = (void *)(entry);
	int i = 0;

	printf("Entry: ");
	for (i = 0; i < (int)sizeof(struct rte_pipeline_table_entry); i++)
		printf(" %02x", entryP[i]);
}

/**
 * Function to print the NAPT table entry
 *
 * @param entry
 *  A pointer to struct cgnapt_table_entry
 */
void print_cgnapt_entry(struct cgnapt_table_entry *entry)
{
	uint8_t *entryP = (void *)(entry);
	int i = 0;

	printf("CGNAPT Entry: ");
	for (i = 0; i < (int)sizeof(struct cgnapt_table_entry); i++)
		printf(" %02x", entryP[i]);
	printf(" size:%d\n", (int)sizeof(struct cgnapt_table_entry));
}

/**
 * Function to get a free port
 *
 * @param p_nat
 *  A pointer to struct pipeline_cgnapt
 * @param public_ip
 *  A uint32_t pointer to return corresponding ip address
 *
 * @return
 *  free port number, 0 if error
 */
int get_free_iport(struct pipeline_cgnapt *p_nat, uint32_t *public_ip)
{
	int port = -1;
	/* If we don't have a valid napt_port_alloc_elem get one from
	* port_alloc_ring
	*/
	if (p_nat->allocated_ports == NULL) {
		void *ports;
		int ret;

		ret = rte_ring_dequeue(p_nat->port_alloc_ring, &ports);
		if (ret == 0) {
			p_nat->allocated_ports =
				(struct napt_port_alloc_elem *)ports;

			#ifdef CGNAPT_DEBUGGING
			p_nat->gfp_get++;
			#endif

			#ifdef CGNAPT_DBG_PRNT
			if (CGNAPT_DEBUG > 3)
				printf("p_nat->allocated_ports %p\n",
						 p_nat->allocated_ports);
			#endif
		} else {
			printf("CGNAPT Err - get_free_iport rte_ring_dequeue "
			"failed");
			printf("%d, %d, %d\n", rte_ring_count(
			p_nat->port_alloc_ring), rte_ring_free_count(
			p_nat->port_alloc_ring), ret);

			#ifdef CGNAPT_DEBUGGING
			#ifdef CGNAPT_DBG_PRNT
			printf("Th%d GFP:: %" PRIu64 ", %" PRIu64 ", "
			"%" PRIu64", %" PRIu64 ",\n", p_nat->pipeline_num,
			p_nat->gfp_get, p_nat->gfp_ret, p_nat->gfp_suc,
			p_nat->gfp_err);

			p_nat->gfp_err++;
			#endif
			#endif
			return port;
		}
	}

	/* get the port from index count-1 and decrease count */
	port = p_nat->allocated_ports->ports
			[p_nat->allocated_ports->count - 1];
	*public_ip = p_nat->allocated_ports->ip_addr
			[p_nat->allocated_ports->count - 1];

	p_nat->allocated_ports->count -= 1;

	/* if count is zero, return buffer to mem pool */
	if (p_nat->allocated_ports->count == 0) {
		rte_mempool_put(napt_port_pool, p_nat->allocated_ports);

		#ifdef CGNAPT_DEBUGGING
		p_nat->gfp_ret++;
		#ifdef CGNAPT_DBG_PRNT
		printf("Th%d Returned to pool p_nat->allocated_ports %p,",
				 p_nat->pipeline_num, p_nat->allocated_ports);
		printf("%" PRIu64 ", %" PRIu64 ",",
			p_nat->gfp_get, p_nat->gfp_ret);
		printf("%" PRIu64 ", %" PRIu64 ",\n",
			p_nat->gfp_suc, p_nat->gfp_err);
		#endif
		#endif

		p_nat->allocated_ports = NULL;
	}

	#ifdef CGNAPT_DEBUGGING
	p_nat->gfp_suc++;
	#endif

	return port;
}

/**
 * Function to free a port
 *
 * @param port_num
 *  Port number to free
 * @param public_ip
 *  Corresponding ip address
 * @param p_nat
 *  A pointer to struct pipeline_cgnapt
 *
 */
void release_iport(uint16_t port_num, uint32_t public_ip,
			 struct pipeline_cgnapt *p_nat)
{
	/* If we don't have a valid napt_port_alloc_elem get one
	* from mem pool
	*/
	if (p_nat->free_ports == NULL) {
		void *ports;

		#ifdef CGNAPT_DEBUGGING
		p_nat->pfb_get++;
		#endif

		if (rte_mempool_get(napt_port_pool, &ports) < 0) {
			#ifdef CGNAPT_DEBUGGING
			p_nat->pfb_err++;
			#endif
			printf("CGNAPT release_iport error in getting "
			"port alloc buffer\n");
			return;
		}

		p_nat->free_ports = (struct napt_port_alloc_elem *)ports;
		p_nat->free_ports->count = 0;
	}

	/* put the port at index count and increase count */
	p_nat->free_ports->ip_addr[p_nat->free_ports->count] = public_ip;
	p_nat->free_ports->ports[p_nat->free_ports->count] = port_num;
	p_nat->free_ports->count += 1;

	/* if napt_port_alloc_elem is full add it to ring */
	{

	#ifdef CGNAPT_DEBUGGING
	p_nat->pfb_ret++;
	#endif

	#ifdef CGNAPT_DBG_PRNT
	if (CGNAPT_DEBUG >= 2) {
		printf("CGNAPT port_alloc_ring before EnQ Cnt %d, Free %d\n",
				 rte_ring_count(p_nat->port_alloc_ring),
				 rte_ring_free_count(p_nat->port_alloc_ring));
		}
	#endif

	if (rte_ring_enqueue(p_nat->port_alloc_ring,
		(void *)p_nat->free_ports) != 0) {
		printf("CGNAPT release_iport  Enqueue error %p\n",
			p_nat->free_ports);

		#ifdef CGNAPT_DEBUGGING
		p_nat->pfb_err++;
		#endif
		}

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG >= 2) {
			printf("CGNAPT port_alloc_ring after EnQ Cnt %d",
				rte_ring_count(p_nat->port_alloc_ring));
			printf("Free %d\n",
				rte_ring_free_count(p_nat->port_alloc_ring));
		}
		#endif

		p_nat->free_ports = NULL;
	}

	#ifdef CGNAPT_DEBUGGING
	p_nat->pfb_suc++;
	#endif
}

/**
 * Function to initialize max ports per client data structures
 * Called during dynamic NAPT initialization.
 *
 * @param p_nat
 *  A pointer to struct pipeline_cgnapt
 *
 * @return
 *  0 if success, negative if error
 */
int init_max_port_per_client(
	__rte_unused struct pipeline_cgnapt *p_nat)
{
	if (max_port_per_client_hash)
		return -1;

	/*MPPC_ALREADY_EXISTS */

	int i = 0;

	max_port_per_client_hash =
		rte_hash_create(&max_port_per_client_hash_params);
	if (!max_port_per_client_hash)
		return -2;

	/*MPPC_HASH_CREATE_ERROR */

	max_port_per_client_array =
		rte_zmalloc(NULL,
			sizeof(struct max_port_per_client) * MAX_DYN_ENTRY,
			RTE_CACHE_LINE_SIZE);
	if (!max_port_per_client_array)
		return -3;

	/*MPPC_ARRAY_CREATE_ERROR */

	for (i = 0; i < MAX_DYN_ENTRY; i++) {
		max_port_per_client_array[i].prv_ip = 0;
		max_port_per_client_array[i].prv_phy_port = 0;
		max_port_per_client_array[i].max_port_cnt = 0;
	}

	return 0;
	/*MPPC_SUCCESS */
}

/**
 * Function to check if max ports for a client is reached
 *
 * @param prv_ip_param
 *  A uint32_t ip address of client
 * @param prv_phy_port_param
 *  A uint32_t physical port id of the client
 * @param p_nat
 *  A pointer to struct pipeline_cgnapt
 *
 * @return
 *  0 if max port not reached, 1 if reached, -1 if error
 */
int is_max_port_per_client_reached(uint32_t prv_ip_param,
					 uint32_t prv_phy_port_param,
					 struct pipeline_cgnapt *p_nat)
{
	int index = MAX_PORT_INVALID_KEY;

	struct max_port_per_client_key key = {
		.prv_ip = prv_ip_param,
		.prv_phy_port = prv_phy_port_param,
	};

	index = rte_hash_lookup(max_port_per_client_hash, (const void *)&key);

	if (index < 0)
		return MAX_PORT_INVALID_KEY;

	if (max_port_per_client_array[index].max_port_cnt >=
		p_nat->max_port_per_client)
		return MAX_PORT_REACHED;

	return MAX_PORT_NOT_REACHED;
}

/**
 * Function to increase max ports for a client
 *
 * @param prv_ip_param
 *  A uint32_t ip address of client
 * @param prv_phy_port_param
 *  A uint32_t physical port id of the client
 * @param p_nat
 *  A pointer to struct pipeline_cgnapt
 *
 * @return
 *  0 if max port reached, 1 if success, 2 if new entry, -1 if error
 */
int increment_max_port_counter(uint32_t prv_ip_param,
					 uint32_t prv_phy_port_param,
					 struct pipeline_cgnapt *p_nat)
{
	int index = MAX_PORT_INC_ERROR;

	struct max_port_per_client_key key = {
		.prv_ip = prv_ip_param,
		.prv_phy_port = prv_phy_port_param,
	};

	index = rte_hash_lookup(max_port_per_client_hash, (const void *)&key);

	if (index == -EINVAL)
		return MAX_PORT_INC_ERROR;

	if (index == -ENOENT) {
		if (max_port_per_client_add_entry(prv_ip_param,
							prv_phy_port_param,
							p_nat) <= 0)
			return MAX_PORT_INC_ERROR;

		return 2;	/*return MAX_PORT_NEW_ENTRY; */
	}

	if (CGNAPT_DEBUG > 2)
		printf("%s: max_port_cnt(%d), p_nat_max(%d)\n", __func__,
			max_port_per_client_array[index].max_port_cnt,
			p_nat->max_port_per_client);

	if (max_port_per_client_array[index].max_port_cnt <
		p_nat->max_port_per_client) {
		max_port_per_client_array[index].max_port_cnt++;
		return MAX_PORT_INC_SUCCESS;
	}

	return MAX_PORT_INC_REACHED;
}

/**
 * Function to decrease max ports for a client
 *
 * @param prv_ip_param
 *  A uint32_t ip address of client
 * @param prv_phy_port_param
 *  A uint32_t physical port id of the client
 * @param p_nat
 *  A pointer to struct pipeline_cgnapt
 *
 * @return
 *  0 if count already 0, 1 if success, -1 if error
 */
int decrement_max_port_counter(uint32_t prv_ip_param,
					 uint32_t prv_phy_port_param,
					 struct pipeline_cgnapt *p_nat)
{
	int index = MAX_PORT_DEC_ERROR;

	struct max_port_per_client_key key = {
		.prv_ip = prv_ip_param,
		.prv_phy_port = prv_phy_port_param,
	};

	index = rte_hash_lookup(max_port_per_client_hash, (const void *)&key);
	if (index < 0) {

		#ifdef CGNAPT_DEBUGGING
		p_nat->max_port_dec_err1++;
		#endif
		return MAX_PORT_DEC_ERROR;

	}

	if (max_port_per_client_array[index].max_port_cnt > 0) {
		/* If it is the last port,ret this info which is used for
		*  max_cli_per_pub_ip
		*/

		max_port_per_client_array[index].max_port_cnt--;
		/* Count should be atomic but we are good as we have only
		* one task handling this counter at a time (core affinity)
		*/
	}

	if (max_port_per_client_array[index].max_port_cnt <= 0) {
		if (max_port_per_client_del_entry
			(prv_ip_param, prv_phy_port_param, p_nat) <= 0) {

			#ifdef CGNAPT_DEBUGGING
			p_nat->max_port_dec_err2++;
			#endif
			return MAX_PORT_DEC_ERROR;
		}

		#ifdef CGNAPT_DEBUGGING
		p_nat->max_port_dec_err3++;
		#endif

		return MAX_PORT_DEC_REACHED;
	}

	#ifdef CGNAPT_DEBUGGING
	p_nat->max_port_dec_success++;
	#endif

	return MAX_PORT_DEC_SUCCESS;
}

/**
 * Function to add a max ports per client entry
 *
 * @param prv_ip_param
 *  A uint32_t ip address of client
 * @param prv_phy_port_param
 *  A uint32_t physical port id of the client
 * @param p_nat
 *  A pointer to struct pipeline_cgnapt
 *
 * @return
 *  0 no success, 1 if success, -1 if error
 */
int max_port_per_client_add_entry(
	uint32_t prv_ip_param,
	uint32_t prv_phy_port_param,
	__rte_unused struct pipeline_cgnapt *p_nat)
{
	int index = MAX_PORT_ADD_ERROR;

	struct max_port_per_client_key key = {
		.prv_ip = prv_ip_param,
		.prv_phy_port = prv_phy_port_param,
	};

	index = rte_hash_lookup(max_port_per_client_hash, (const void *)&key);
	if (index == -EINVAL)
		return MAX_PORT_ADD_ERROR;

	if (index >= 0)
		return MAX_PORT_ADD_UNSUCCESS;

	if (index == -ENOENT) {

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG > 2)
			printf("max_port_per_client_add_entry fn: "
			"Entry does not exist\n");
		#endif

		index =
			rte_hash_add_key(max_port_per_client_hash,
					 (const void *)&key);
		if (index == -ENOSPC)
			return MAX_PORT_ADD_UNSUCCESS;

		#ifdef CGNAPT_DBG_PRNT
		if (CGNAPT_DEBUG > 2)
			printf("max_port_per_client_add_entry fn:"
			"Add entry index(%d)\n", index);
		#endif

		max_port_per_client_array[index].prv_ip = prv_ip_param;
		max_port_per_client_array[index].prv_phy_port =
			prv_phy_port_param;
	}

	max_port_per_client_array[index].max_port_cnt++;
	return MAX_PORT_ADD_SUCCESS;
}

/**
 * Function to delete a max ports per client entry
 *
 * @param prv_ip_param
 *  A uint32_t ip address of client
 * @param prv_phy_port_param
 *  A uint32_t physical port id of the client
 * @param p_nat
 *  A pointer to struct pipeline_cgnapt
 *
 * @return
 *  0 no success, 1 if success, -1 if error
 */
int max_port_per_client_del_entry(
	uint32_t prv_ip_param,
	uint32_t prv_phy_port_param,
	__rte_unused struct pipeline_cgnapt *p_nat)
{
	int index = MAX_PORT_DEL_ERROR;

	struct max_port_per_client_key key = {
		.prv_ip = prv_ip_param,
		.prv_phy_port = prv_phy_port_param,
	};

	index = rte_hash_lookup(max_port_per_client_hash, (const void *)&key);

	if (index == -EINVAL)
		return MAX_PORT_DEL_ERROR;

	if (index == -ENOENT)
		return MAX_PORT_DEL_UNSUCCESS;

	index = rte_hash_del_key(max_port_per_client_hash, (const void *)&key);
	max_port_per_client_array[index].prv_ip = 0;
	max_port_per_client_array[index].prv_phy_port = 0;
	max_port_per_client_array[index].max_port_cnt = 0;

	return MAX_PORT_DEL_SUCCESS;
}

/**
 * Function to execute debug commands
 *
 * @param p
 *  A pointer to struct pipeline
 * @param msg
 *  void pointer to incoming arguments
 */
void *pipeline_cgnapt_msg_req_entry_dbg_handler(struct pipeline *p, void *msg)
{
	struct pipeline_cgnapt_entry_delete_msg_rsp *rsp = msg;
	uint8_t *Msg = msg;
	struct pipeline_cgnapt *p_nat = (struct pipeline_cgnapt *)p;

	rsp->status = 0;

	if (Msg[CGNAPT_DBG_CMD_OFST] == CGNAPT_DBG_CMD_STATS_SHOW) {
		printf("\nCG-NAPT Packet Stats:\n");
		printf("Received %" PRIu64 ",", p_nat->receivedPktCount);
		printf("Missed %" PRIu64 ",", p_nat->missedPktCount);
		printf("Dropped %" PRIu64 ",",  p_nat->naptDroppedPktCount);
		printf("Translated %" PRIu64 ",", p_nat->naptedPktCount);
		printf("ingress %" PRIu64 ",",  p_nat->inaptedPktCount);
		printf("egress %" PRIu64 "\n", p_nat->enaptedPktCount);
		printf("arp pkts %" PRIu64 "\n", p_nat->arpicmpPktCount);

		#ifdef CGNAPT_DEBUGGING
		printf("\n Drop detail 1:%" PRIu64 ",",
				p_nat->naptDroppedPktCount1);
		printf("\n Drop detail 2:%" PRIu64 ",",
				p_nat->naptDroppedPktCount2);
		printf("\n Drop detail 3:%" PRIu64 ",",
				p_nat->naptDroppedPktCount3);
		printf("\n Drop detail 4:%" PRIu64 ",",
				p_nat->naptDroppedPktCount4);
		printf("\n Drop detail 5:%" PRIu64 ",",
				p_nat->naptDroppedPktCount5);
		printf("\n Drop detail 6:%" PRIu64 "",
				p_nat->naptDroppedPktCount6);

		printf("\nPkt_miss: %" PRIu64 " %" PRIu64 "",
				p_nat->missedpktcount1,
				p_nat->missedpktcount2);
		printf("\nPkt_miss: %" PRIu64 " %" PRIu64 "",
				p_nat->missedpktcount3,
				p_nat->missedpktcount4);
		printf("\nPkt_miss: %" PRIu64 " %" PRIu64 "",
				p_nat->missedpktcount5,
				p_nat->missedpktcount6);
		printf("\nPkt_miss: %" PRIu64 " %" PRIu64 "",
				p_nat->missedpktcount7,
				p_nat->missedpktcount8);
		printf("\nPkt_miss: %" PRIu64 " %" PRIu64 "",
				p_nat->missedpktcount9,
				p_nat->missedpktcount10);

		#endif

		return rsp;
	}

	if (Msg[CGNAPT_DBG_CMD_OFST] == CGNAPT_DBG_CMD_STATS_CLEAR) {
		printf("\nCG-NAPT Packet Stats:\n");
		printf("Received %" PRIu64 ",", p_nat->receivedPktCount);
		printf("Missed %" PRIu64 ",", p_nat->missedPktCount);
		printf("Dropped %" PRIu64 ",",  p_nat->naptDroppedPktCount);
		printf("Translated %" PRIu64 ",", p_nat->naptedPktCount);
		printf("ingress %" PRIu64 ",",  p_nat->inaptedPktCount);
		printf("egress %" PRIu64 "\n", p_nat->enaptedPktCount);
		printf("arp pkts %" PRIu64 "\n", p_nat->arpicmpPktCount);

		p_nat->naptedPktCount = 0;
		p_nat->naptDroppedPktCount = 0;
		p_nat->inaptedPktCount = 0;
		p_nat->enaptedPktCount = 0;
		p_nat->receivedPktCount = 0;
		p_nat->missedPktCount = 0;
		p_nat->arpicmpPktCount = 0;
		printf("CG-NAPT Packet Stats cleared\n");
		return rsp;
	}

	if (Msg[CGNAPT_DBG_CMD_OFST] == CGNAPT_DBG_CMD_DBG_LEVEL) {
		CGNAPT_DEBUG = Msg[CGNAPT_DBG_CMD_OFST + 1];
		printf("CG-NAPT debug level set to %d\n", CGNAPT_DEBUG);
		return rsp;
	}

	if (Msg[CGNAPT_DBG_CMD_OFST] == CGNAPT_DBG_CMD_DBG_SHOW) {

		printf("\nNAPT entries - added %" PRIu64 ",",
				p_nat->n_cgnapt_entry_added);
		printf("deleted %" PRIu64 ",", p_nat->n_cgnapt_entry_deleted);
		printf("current %" PRIu64 "", p_nat->n_cgnapt_entry_added -
				p_nat->n_cgnapt_entry_deleted);

		printf("\nCG-NAPT Packet Stats:\n");
		printf("Received %" PRIu64 ",", p_nat->receivedPktCount);
		printf("Missed %" PRIu64 ",", p_nat->missedPktCount);
		printf("Dropped %" PRIu64 ",",  p_nat->naptDroppedPktCount);
		printf("Translated %" PRIu64 ",", p_nat->naptedPktCount);
		printf("ingress %" PRIu64 ",",  p_nat->inaptedPktCount);
		printf("egress %" PRIu64 "\n", p_nat->enaptedPktCount);
		printf("arp pkts %" PRIu64 "\n", p_nat->arpicmpPktCount);

		return rsp;
	}
	#ifdef PIPELINE_CGNAPT_INSTRUMENTATION
	if (Msg[CGNAPT_DBG_CMD_OFST] == CGNAPT_DBG_CMD_INSTRUMENTATION) {
		if (Msg[CGNAPT_DBG_CMD_OFST1] ==
			CGNAPT_CMD_INSTRUMENTATION_SUB0) {

		int index = 0;
		uint32_t diff_sum = 0;

		printf("CG-NAPT Instrumentation ...\n");
		printf("Instrumentation data collected for fn# %d\n",
			cgnapt_num_func_to_inst);
		printf("Current collection index %d\n",
		cgnapt_inst_index);

	if (Msg[CGNAPT_DBG_CMD_OFST + 2] == 2) {
		printf("Timer Start:\n");

		for (index = 0; index < INST_ARRAY_SIZE; index++) {
			if ((index % 5) == 0)
				printf("\n");
			printf(" 0x%jx", inst_start_time[index]);
		}
		printf("\n\nTimer End:\n");

		for (index = 0; index < INST_ARRAY_SIZE; index++) {
			if ((index % 5) == 0)
				printf("\n");
			printf(" 0x%jx", inst_end_time[index]);
		}
	}

	for (index = 0; index < INST_ARRAY_SIZE; index++) {
		inst_diff_time[index] = (uint32_t) (inst_end_time[index] -
						inst_start_time[index]);
	}

	if (Msg[CGNAPT_DBG_CMD_OFST + 2] ==
		CGNAPT_CMD_INSTRUMENTATION_SUB1) {
		printf("\n\nTimer Diff:\n");

	for (index = 0; index < INST_ARRAY_SIZE; index++) {
		if (Msg[CGNAPT_DBG_CMD_OFST + 2] ==
			CGNAPT_CMD_INSTRUMENTATION_SUB1) {
			if ((index % 5) == 0)
				printf("\n");
			printf(" 0x%08x", inst_diff_time[index]);
		}

		diff_sum += inst_diff_time[index];
	}

	printf("\ndiff_sum %u, INST_ARRAY_SIZE %d, Ave Time %u\n",
		diff_sum, INST_ARRAY_SIZE, (diff_sum / INST_ARRAY_SIZE));
	} else if (Msg[CGNAPT_DBG_CMD_OFST + 1] ==
		CGNAPT_CMD_INSTRUMENTATION_SUB1) {
		/* p plid entry dbg 7 1 0
		*  p plid entry dbg 7 1 1 <--- pkt_work_cgnapt
		*  p plid entry dbg 7 1 2 <--- pkt4_work_cgnapt
		*  p plid entry dbg 7 1 3 <--- pkt_work_cgnapt_key
		*  p plid entry dbg 7 1 4 <--- pkt4_work_cgnapt_key
		*  p plid entry dbg 7 1 5 <--- in port ah to out port ah
		*				- pkt life in the system
		*  p plid entry dbg 7 1 6 <--- how long this instrumentation
		*				itself is taking
		*/
		cgnapt_inst_index = 0;
		cgnapt_num_func_to_inst = Msg[CGNAPT_DBG_CMD_OFST + 2];
		printf("Instrumentation data collection started for fn# %d\n",
				 cgnapt_num_func_to_inst);
	} else if (Msg[CGNAPT_DBG_CMD_OFST + 1] ==
			CGNAPT_CMD_INSTRUMENTATION_SUB2) {
		/*  p plid entry dbg 7 2 0
		*   Test all major functions by calling them multiple times
		*   pkt_work_cgnapt, pkt4_work_cgnapt, pkt_work_cgnapt_key,
		*   pkt4_work_cgnapt_key
		*/
		if (cgnapt_test_pktmbuf_pool == NULL) {
			cgnapt_test_pktmbuf_pool = rte_pktmbuf_pool_create(
				"cgnapt_test_pktmbuf_pool", 63, 32, 0,
				RTE_MBUF_DEFAULT_BUF_SIZE,
				rte_socket_id());
		}

		if (cgnapt_test_pktmbuf_pool == NULL)
			printf("CGNAPT test mbuf pool create failed.\n");

			struct rte_mbuf *cgnapt_test_pkt0 =
				rte_pktmbuf_alloc(cgnapt_test_pktmbuf_pool);
			if (cgnapt_test_pkt0 == NULL)
				printf("CGNAPT test pkt 0 alloc failed.");
			struct rte_mbuf *cgnapt_test_pkt1 =
				rte_pktmbuf_alloc(cgnapt_test_pktmbuf_pool);
			if (cgnapt_test_pkt1 == NULL)
				printf("CGNAPT test pkt 1 alloc failed.");
			struct rte_mbuf *cgnapt_test_pkt2 =
				rte_pktmbuf_alloc(cgnapt_test_pktmbuf_pool);
			if (cgnapt_test_pkt2 == NULL)
				printf("CGNAPT test pkt 2 alloc failed.");
			struct rte_mbuf *cgnapt_test_pkt3 =
				rte_pktmbuf_alloc(cgnapt_test_pktmbuf_pool);
			if (cgnapt_test_pkt3 == NULL)
				printf("CGNAPT test pkt 3 alloc failed.");

			struct rte_mbuf *cgnapt_test_pkts[4];

			cgnapt_test_pkts[0] = cgnapt_test_pkt0;
			cgnapt_test_pkts[1] = cgnapt_test_pkt1;
			cgnapt_test_pkts[2] = cgnapt_test_pkt2;
			cgnapt_test_pkts[3] = cgnapt_test_pkt3;

		uint32_t src_addr_offset =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_SRC_ADR_OFST;
		/* header room + eth hdr size +
		* src_aadr offset in ip header
		*/
		uint32_t dst_addr_offset =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST;
		/* header room + eth hdr size +
		* dst_aadr offset in ip header
		*/
		uint32_t prot_offset =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_PROTOCOL_OFST;
		/* header room + eth hdr size +
		* srprotocol char offset in ip header
		*/
		int pktCnt = 0, entCnt = 0, exCnt = 0;

		for (pktCnt = 0; pktCnt < 4; pktCnt++) {
			uint32_t *src_addr =
				RTE_MBUF_METADATA_UINT32_PTR
				(cgnapt_test_pkts[pktCnt], src_addr_offset);
			uint32_t *dst_addr =
				RTE_MBUF_METADATA_UINT32_PTR
				(cgnapt_test_pkts[pktCnt], dst_addr_offset);
			uint8_t *protocol =
				RTE_MBUF_METADATA_UINT8_PTR(cgnapt_test_pkts
							[pktCnt],
							prot_offset);
			uint8_t *phy_port =
				RTE_MBUF_METADATA_UINT8_PTR(cgnapt_test_pkts
							[pktCnt], 70);
			uint8_t *eth_dest =
				RTE_MBUF_METADATA_UINT8_PTR(cgnapt_test_pkts
							[pktCnt],
							MBUF_HDR_ROOM);
			uint8_t *eth_src =
				RTE_MBUF_METADATA_UINT8_PTR(
					cgnapt_test_pkts[pktCnt],
							MBUF_HDR_ROOM +
							6);
			uint16_t *src_port =
				RTE_MBUF_METADATA_UINT16_PTR
				(cgnapt_test_pkts[pktCnt],
				 MBUF_HDR_ROOM + ETH_HDR_SIZE +
				 IP_HDR_SIZE);
			uint16_t *dst_port =
				RTE_MBUF_METADATA_UINT16_PTR
				(cgnapt_test_pkts[pktCnt],
				 MBUF_HDR_ROOM + ETH_HDR_SIZE +
				 IP_HDR_SIZE + 2);
			*src_addr = 0xc0a80001;
			*dst_addr = 0x90418634;
			*protocol = 0x6;
			*phy_port = 0;
			*src_port = 1234;
			*dst_port = 4000;
			eth_src[0] = 0xAB;
			eth_src[1] = 0xAB;
			eth_src[2] = 0xAB;
			eth_src[3] = 0xAB;
			eth_src[4] = 0xAB;
			eth_src[5] = 0xAB;
			eth_dest[0] = 0x90;
			eth_dest[1] = 0xE2;
			eth_dest[2] = 0xba;
			eth_dest[3] = 0x54;
			eth_dest[4] = 0x67;
			eth_dest[5] = 0xc8;
		}
		struct rte_pipeline_table_entry *table_entries[4];
		struct cgnapt_table_entry ctable_entries[4];
			table_entries[0] = (struct rte_pipeline_table_entry *)
			&ctable_entries[0];
		table_entries[1] = (struct rte_pipeline_table_entry *)
			&ctable_entries[1];
		table_entries[2] = (struct rte_pipeline_table_entry *)
			&ctable_entries[2];
		table_entries[3] = (struct rte_pipeline_table_entry *)
			&ctable_entries[3];
		for (entCnt = 0; entCnt < 4; entCnt++) {
			ctable_entries[entCnt].head.action =
				RTE_PIPELINE_ACTION_PORT;
			ctable_entries[entCnt].head.port_id = 0;

			ctable_entries[entCnt].data.prv_ip = 0x01020304;
			ctable_entries[entCnt].data.prv_port = 1234;
			ctable_entries[entCnt].data.pub_ip = 0x0a0b0c0d;
			ctable_entries[entCnt].data.pub_port = 4000;
			ctable_entries[entCnt].data.prv_phy_port = 0;
			ctable_entries[entCnt].data.pub_phy_port = 1;
			ctable_entries[entCnt].data.ttl = 500;
		}

		uint64_t time1 = rte_get_tsc_cycles();

		for (exCnt = 0; exCnt < 1000; exCnt++) {
			pkt_work_cgnapt_key(cgnapt_test_pkts[0],
					instrumentation_port_in_arg);
		}
			uint64_t time2 = rte_get_tsc_cycles();

			printf("times for %d times execution of "
				"pkt_work_cgnapt_key 0x%jx",
				exCnt, time1);
			printf(", 0x%jx, diff %" PRIu64 "\n", time2,
				time2 - time1);

			time1 = rte_get_tsc_cycles();
			for (exCnt = 0; exCnt < 1000000; exCnt++) {
				pkt_work_cgnapt_key(cgnapt_test_pkts[0],
					instrumentation_port_in_arg);
			}
			time2 = rte_get_tsc_cycles();
			printf("times for %d times execution of "
				"pkt_work_cgnapt_key 0x%jx", exCnt, time1);
			printf("0x%jx, diff %" PRIu64 "\n", time2,
				time2 - time1);

			time1 = rte_get_tsc_cycles();
			for (exCnt = 0; exCnt < 1000; exCnt++) {
				pkt4_work_cgnapt_key(cgnapt_test_pkts,
					instrumentation_port_in_arg);
			}
			time2 = rte_get_tsc_cycles();
			printf("times for %d times execution of "
				"pkt4_work_cgnapt_key 0x%jx",
				exCnt, time1);
			printf(" 0x%jx, diff %" PRIu64 "\n", time2,
				time2 - time1);

			time1 = rte_get_tsc_cycles();
			for (exCnt = 0; exCnt < 1000000; exCnt++) {
				pkt4_work_cgnapt_key(cgnapt_test_pkts,
					instrumentation_port_in_arg);
			}
			time2 = rte_get_tsc_cycles();
			printf("times for %d times execution of "
				"pkt4_work_cgnapt_key 0x%jx",
				exCnt, time1);
			printf("0x%jx, diff %" PRIu64 "\n", time2,
				time2 - time1);

			uint64_t mask = 0xff;

			time1 = rte_get_tsc_cycles();
			for (exCnt = 0; exCnt < 1000; exCnt++) {
				pkt_work_cgnapt(cgnapt_test_pkts[0],
						table_entries[0], 3, &mask,
						NULL);
			}
			time2 = rte_get_tsc_cycles();
			printf("times for %d times execution of "
				"pkt_work_cgnapt 0x%jx",
				exCnt, time1);
			printf("0x%jx, diff %" PRIu64 "\n", time2,
				time2 - time1);

			time1 = rte_get_tsc_cycles();
			for (exCnt = 0; exCnt < 1000000; exCnt++) {
				pkt_work_cgnapt(cgnapt_test_pkts[0],
						table_entries[0], 3, &mask,
						NULL);
			}
			time2 = rte_get_tsc_cycles();
			printf("times for %d times execution of "
				"pkt_work_cgnapt 0x%jx",
				exCnt, time1);
			printf("0x%jx, diff %" PRIu64 "\n", time2,
				time2 - time1);

			time1 = rte_get_tsc_cycles();
			for (exCnt = 0; exCnt < 1000; exCnt++) {
				pkt4_work_cgnapt(cgnapt_test_pkts,
						 table_entries, 0, &mask, NULL);
			}
			time2 = rte_get_tsc_cycles();
			printf("times for %d times execution of "
				"pkt4_work_cgnapt 0x%jx",
				exCnt, time1);
			printf("0x%jx, diff % " PRIu64 "\n", time2,
				time2 - time1);

			int idummy = ctable_entries[0].data.prv_port;

			idummy++;

		}
	}
		return rsp;
	}
	#endif

	if (Msg[CGNAPT_DBG_CMD_OFST] == CGNAPT_DBG_CMD_LS_ENTRY) {
		printf("CG-NAPT be entries are:\n");
		printf("Pipeline pointer %p\n", p);
		return rsp;
	}

	if (Msg[CGNAPT_DBG_CMD_OFST] == CGNAPT_DBG_CMD_DYN) {
		printf("Total Number of dynamic napt entries: %" PRIu64 "\n",
				 p_nat->dynCgnaptCount);

		#ifdef CGNAPT_DEBUGGING
		printf("MAX PORT PER CLIENT:");
		printf("%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
				 p_nat->max_port_dec_err1, p_nat->max_port_dec_err2,
				 p_nat->max_port_dec_err3);
		printf("MPPC success : %" PRIu64 "\n",
				 p_nat->max_port_dec_success);

		printf("Release port:err:%" PRIu64 ",ret::%" PRIu64 ",get::%"
				 PRIu64 ",suc::%" PRIu64 "\n", p_nat->pfb_err,
				 p_nat->pfb_ret, p_nat->pfb_get, p_nat->pfb_suc);
		printf("Get port::err:%" PRIu64 ",ret::%" PRIu64 ",get::%"
				 PRIu64 ",suc::%" PRIu64 "\n", p_nat->gfp_err,
				 p_nat->gfp_ret, p_nat->gfp_get, p_nat->gfp_suc);
		printf("Ring Info:\n");
		rte_ring_dump(stdout, p_nat->port_alloc_ring);
		#endif
		return rsp;
	}
	if (Msg[CGNAPT_DBG_CMD_OFST] == CGNAPT_DBG_CMD_IPV6) {
		dual_stack_enable = Msg[CGNAPT_DBG_CMD_OFST + 1];
		printf("Dual Stack option set: %x\n", dual_stack_enable);
		return rsp;
	}

	if (Msg[CGNAPT_DBG_CMD_OFST] == CGNAPT_DBG_CMD_MAPS_INFO) {
		pipelines_port_info();
		pipelines_map_info();
		return rsp;
	}

	if (Msg[CGNAPT_DBG_CMD_OFST] == CGNAPT_DBG_CMD_ITER_COM_TBL) {
		uint32_t count = 0;
		const void *key;
		void *data;
		uint32_t next = 0;
		int32_t index = 0;

		do {
			index =
				rte_hash_iterate(napt_common_table, &key, &data,
						 &next);

			if ((index != -EINVAL) && (index != -ENOENT)) {
				printf("\n%04d  ", count);
				rte_hexdump(stdout, "KEY", key,
					sizeof(struct
						pipeline_cgnapt_entry_key));

				//print_key((struct pipeline_cgnapt_entry_key *)
				//		key);
				int32_t position =
					rte_hash_lookup(napt_common_table,
						key);
				print_cgnapt_entry(&napt_hash_tbl_entries
							 [position]);
			}

			count++;
		} while (index != -ENOENT);
		return rsp;
	}

	if (Msg[CGNAPT_DBG_CMD_OFST] == CGNAPT_DBG_CMD_IF_STATS) {

		struct app_params *app =
			(struct app_params *)p_nat->app_params_addr;
		uint8_t cmd[2];

		cmd[0] = Msg[CGNAPT_DBG_CMD_OFST + 1];
		cmd[1] = Msg[CGNAPT_DBG_CMD_OFST + 2];
		switch (cmd[0]) {
		case CGNAPT_IF_STATS_HWQ:
			printf("n_pktq_hwq_int :%d\n", app->n_pktq_hwq_in);
			printf("n_pktq_hwq_out :%d\n", app->n_pktq_hwq_out);
			printf("\n");
			uint8_t i, j;

			for (i = 0; i < app->n_pktq_hwq_in; i++) {
				struct rte_eth_stats stats;

				rte_eth_stats_get(p_nat->links_map[i], &stats);

				if (is_phy_port_privte(i))
					printf("Private Port Stats %d\n", i);
				else
					printf("Public Port Stats  %d\n", i);

				printf("\n\tipackets : %" PRIu64 "",
						 stats.ipackets);
				printf("\n\topackets : %" PRIu64 "",
						 stats.opackets);
				printf("\n\tierrors  : %" PRIu64 "",
						 stats.ierrors);
				printf("\n\toerrors  : %" PRIu64 "",
						 stats.oerrors);
				printf("\n\trx_nombuf: %" PRIu64 "",
						 stats.rx_nombuf);
				printf("\n");
				if (is_phy_port_privte(i))
					printf("Private Q:");
				else
					printf("Public  Q:");
				for (j = 0; j < RTE_ETHDEV_QUEUE_STAT_CNTRS;
					 j++)
					printf(" %" PRIu64 ", %" PRIu64 "|",
							 stats.q_ipackets[j],
							 stats.q_opackets[j]);

				printf("\n\n");

			}

			return rsp;

		case CGNAPT_IF_STATS_SWQ:

			printf("n_pktq_swq :%d\n", app->n_pktq_swq);

			if (cmd[1] < app->n_pktq_swq) {
				rte_ring_dump(stdout, app->swq[cmd[1]]);
				return rsp;
			}
			printf("SWQ number is invalid\n");
			return rsp;

		case CGNAPT_IF_STATS_OTH:
			printf("\n");
			printf("config_file:%s\n", app->config_file);
			printf("script_file:%s\n", app->script_file);
			printf("parser_file:%s\n", app->parser_file);
			printf("output_file:%s\n", app->output_file);
			printf("n_msgq :%d\n", app->n_msgq);
			printf("n_pktq_tm :%d\n", app->n_pktq_tm);
			printf("n_pktq_source :%d\n", app->n_pktq_source);
			printf("n_pktq_sink :%d\n", app->n_pktq_sink);
			printf("n_pipelines :%d\n", app->n_pipelines);
			printf("\n");
			return rsp;
		default:
			printf("Command does not match\n\n");
			return rsp;

		}		/* switch */

		return rsp;
	}

	if (Msg[CGNAPT_DBG_CMD_OFST] == CGNAPT_DBG_MAX_CLI_PER_PUB_IP) {
		if (nat_only_config_flag) {
			printf("Command not supported for NAT only config.\n");
			return rsp;
		}
		uint16_t ii;

		printf("\tPublic IP:	Num Clients\n");
		for (ii = 0; ii < CGNAPT_MAX_PUB_IP; ii++)
			printf("\t%x : %7d\n", all_public_ip[ii].ip,
					 rte_atomic16_read(&all_public_ip[ii].count));
		return rsp;
	}

	if (Msg[CGNAPT_DBG_CMD_OFST] == CGNAPT_DBG_PUB_IP_LIST) {

		int i;
		for (i = 0; i < p_nat->pub_ip_count; i++)
			printf("%x : (%d,%d)\n", p_nat->pub_ip_port_set[i].ip,
					 p_nat->pub_ip_port_set[i].start_port,
					 p_nat->pub_ip_port_set[i].end_port);
		return rsp;
	}

	#ifdef CGNAPT_TIMING_INST
	if (Msg[CGNAPT_DBG_CMD_OFST] == CGNAPT_DBG_TIMING_INST) {
		if (Msg[CGNAPT_DBG_CMD_OFST + 1] == 0) {
			p_nat->time_measurements_on = 1;
			p_nat->time_measurements = 0;
			printf("CGNAPT timing instrumentation turned on.\n");
			printf("Max samples %d\n", p_nat->max_time_mesurements);
		}
		if (Msg[CGNAPT_DBG_CMD_OFST + 1] == 1) {
			p_nat->time_measurements_on = 0;
			printf("CGNAPT timing instrumentation turned off.\n");
			printf("Cur Samples %d\n", p_nat->time_measurements);
		}
		if (Msg[CGNAPT_DBG_CMD_OFST + 1] == 2) {
			uint64_t sum = p_nat->external_time_sum +
					p_nat->internal_time_sum;
			uint64_t isump = (p_nat->internal_time_sum * 100) / sum;
			uint64_t esump = (p_nat->external_time_sum * 100) / sum;
			printf("CGNAPT timing instrumentation status ...\n");
			printf("Max Count %d, Cur Count %d, Status %d (1=ON)\n",
					 p_nat->max_time_mesurements,
					 p_nat->time_measurements,
					 p_nat->time_measurements_on);
			printf("Internal Time Sum %" PRIu64 " , Ave %" PRIu64
					 ", percent %" PRIu64 "\n",
					 p_nat->internal_time_sum,
					 (p_nat->internal_time_sum /
				p_nat->time_measurements), isump);
			printf("External Time Sum %" PRIu64 " , Ave %" PRIu64
					 ", percent %" PRIu64 "\n",
					 p_nat->external_time_sum,
					 (p_nat->external_time_sum /
				p_nat->time_measurements), esump);
		}

		return rsp;
	}
	#endif

	if (Msg[CGNAPT_DBG_CMD_OFST] == CGNAPT_DBG_CMD_PRINT_NSP) {
		struct cgnapt_nsp_node *ll = nsp_ll;

		while (ll != NULL) {
			fprintf(stderr, "NSP Prefix/Depth=>%x%x:%x%x:%x%x: "
				"%x%x:%x%x:%x%x:%x%x:%x%x/%d",
				ll->nsp.prefix[0], ll->nsp.prefix[1],
				ll->nsp.prefix[2], ll->nsp.prefix[3],
				ll->nsp.prefix[4], ll->nsp.prefix[5],
				ll->nsp.prefix[6], ll->nsp.prefix[7],
				ll->nsp.prefix[8], ll->nsp.prefix[9],
				ll->nsp.prefix[10], ll->nsp.prefix[11],
				ll->nsp.prefix[12], ll->nsp.prefix[13],
				ll->nsp.prefix[14], ll->nsp.prefix[15],
				ll->nsp.depth);

			ll = ll->next;
		}

		return rsp;
	}

	printf("CG-NAPT debug handler called with wrong args %x %x\n", Msg[0],
			 Msg[1]);
	int i = 0;

	for (i = 0; i < 20; i++)
		printf("%02x ", Msg[i]);
	printf("\n");
	return rsp;
}

/**
 * Function to print num of clients per IP address
 *
 */
void print_num_ip_clients(void)
{
	if (nat_only_config_flag) {
		printf("Command not supported for NAT only config.\n");
		return;
	}

	uint16_t ii;
	printf("\tPublic IP:    Num Clients\n");
	for (ii = 0; ii < CGNAPT_MAX_PUB_IP; ii++)
		printf("\t%08x : %7d\n", all_public_ip[ii].ip,
				 rte_atomic16_read(&all_public_ip[ii].count));
}

/**
 * Function to print CGNAPT version info
 *
 * @param p
 *  An unused pointer to struct pipeline
 * @param msg
 *  void pointer to incoming arguments
 */
void *pipeline_cgnapt_msg_req_ver_handler(__rte_unused struct pipeline *p,
						void *msg)
{
	struct pipeline_cgnapt_entry_delete_msg_rsp *rsp = msg;
	uint8_t *Msg = msg;

	rsp->status = 0;

	printf("CG-NAPT debug handler called with args %x %x, offset %d\n",
			 Msg[CGNAPT_VER_CMD_OFST], Msg[CGNAPT_VER_CMD_OFST + 1],
			 CGNAPT_VER_CMD_OFST);

	if (Msg[CGNAPT_VER_CMD_OFST] == CGNAPT_VER_CMD_VER) {
		printf("CGNAPT Version %s\n", CGNAPT_VERSION);
		return rsp;
	}
	printf("CG-NAPT Version handler called with wrong args %x %x\n",
			 Msg[0], Msg[1]);
	int i = 0;

	for (i = 0; i < 20; i++)
		printf("%02x ", Msg[i]);
	printf("\n");
	return rsp;
}

/**
 * Function to show CGNAPT stats
 *
 */
void all_cgnapt_stats(void)
{
	int i;
	struct pipeline_cgnapt *p_nat;
	uint64_t receivedPktCount = 0;
	uint64_t missedPktCount = 0;
	uint64_t naptDroppedPktCount = 0;
	uint64_t naptedPktCount = 0;
	uint64_t inaptedPktCount = 0;
	uint64_t enaptedPktCount = 0;
	uint64_t arpicmpPktCount = 0;

	printf("\nCG-NAPT Packet Stats:\n");
	for (i = 0; i < n_cgnapt_pipeline; i++) {
		p_nat = all_pipeline_cgnapt[i];

		receivedPktCount	+= p_nat->receivedPktCount;
		missedPktCount		+= p_nat->missedPktCount;
		naptDroppedPktCount	+= p_nat->naptDroppedPktCount;
		naptedPktCount		+= p_nat->naptedPktCount;
		inaptedPktCount		+= p_nat->inaptedPktCount;
		enaptedPktCount		+= p_nat->enaptedPktCount;
		arpicmpPktCount		+= p_nat->arpicmpPktCount;

		printf("pipeline %d stats:\n", p_nat->pipeline_num);
		printf("Received %" PRIu64 ",", p_nat->receivedPktCount);
		printf("Missed %" PRIu64 ",", p_nat->missedPktCount);
		printf("Dropped %" PRIu64 ",",  p_nat->naptDroppedPktCount);
		printf("Translated %" PRIu64 ",", p_nat->naptedPktCount);
		printf("ingress %" PRIu64 ",",  p_nat->inaptedPktCount);
		printf("egress %" PRIu64 "\n", p_nat->enaptedPktCount);
		printf("arpicmp pkts %" PRIu64 "\n", p_nat->arpicmpPktCount);


		#ifdef CGNAPT_DEBUGGING
		printf("\n Drop detail 1:%" PRIu64 ",",
				p_nat->naptDroppedPktCount1);
		printf("\n Drop detail 2:%" PRIu64 ",",
				p_nat->naptDroppedPktCount2);
		printf("\n Drop detail 3:%" PRIu64 ",",
				p_nat->naptDroppedPktCount3);
		printf("\n Drop detail 4:%" PRIu64 ",",
				p_nat->naptDroppedPktCount4);
		printf("\n Drop detail 5:%" PRIu64 ",",
				p_nat->naptDroppedPktCount5);
		printf("\n Drop detail 6:%" PRIu64 "",
				p_nat->naptDroppedPktCount6);

		printf("\nPkt_miss: %" PRIu64 " %" PRIu64 "",
				p_nat->missedpktcount1,
				p_nat->missedpktcount2);
		printf("\nPkt_miss: %" PRIu64 " %" PRIu64 "",
				p_nat->missedpktcount3,
				p_nat->missedpktcount4);
		printf("\nPkt_miss: %" PRIu64 " %" PRIu64 "",
				p_nat->missedpktcount5,
				p_nat->missedpktcount6);
		printf("\nPkt_miss: %" PRIu64 " %" PRIu64 "",
				p_nat->missedpktcount7,
				p_nat->missedpktcount8);
		printf("\nPkt_miss: %" PRIu64 " %" PRIu64 "",
				p_nat->missedpktcount9,
				p_nat->missedpktcount10);

		#endif

	}

	printf("\nTotal pipeline stats:\n");
	printf("Received %" PRIu64 ",", receivedPktCount);
	printf("Missed %" PRIu64 ",", missedPktCount);
	printf("Dropped %" PRIu64 ",",  naptDroppedPktCount);
	printf("Translated %" PRIu64 ",", naptedPktCount);
	printf("ingress %" PRIu64 ",",  inaptedPktCount);
	printf("egress %" PRIu64 "\n", enaptedPktCount);
	printf("arpicmp pkts %" PRIu64 "\n", arpicmpPktCount);
}

void all_cgnapt_clear_stats(void)
{
	int i;
	struct pipeline_cgnapt *p_nat;
		printf("\nCG-NAPT Packet Stats:\n");
	for (i = 0; i < n_cgnapt_pipeline; i++) {
		p_nat = all_pipeline_cgnapt[i];

		printf("pipeline %d stats:\n", p_nat->pipeline_num);
		printf("Received %" PRIu64 ",", p_nat->receivedPktCount);
		printf("Missed %" PRIu64 ",", p_nat->missedPktCount);
		printf("Dropped %" PRIu64 ",",  p_nat->naptDroppedPktCount);
		printf("Translated %" PRIu64 ",", p_nat->naptedPktCount);
		printf("ingress %" PRIu64 ",",  p_nat->inaptedPktCount);
		printf("egress %" PRIu64 "\n", p_nat->enaptedPktCount);
		printf("arpicmp pkts %" PRIu64 "\n", p_nat->arpicmpPktCount);

		p_nat->receivedPktCount = 0;
		p_nat->missedPktCount = 0;
		p_nat->naptDroppedPktCount = 0;
		p_nat->naptedPktCount = 0;
		p_nat->inaptedPktCount = 0;
		p_nat->enaptedPktCount = 0;
		p_nat->arpicmpPktCount = 0;

		#ifdef CGNAPT_DEBUGGING
		printf("\n Drop detail 1:%" PRIu64 ",",
				p_nat->naptDroppedPktCount1);
		printf("\n Drop detail 2:%" PRIu64 ",",
				p_nat->naptDroppedPktCount2);
		printf("\n Drop detail 3:%" PRIu64 ",",
				p_nat->naptDroppedPktCount3);
		printf("\n Drop detail 4:%" PRIu64 ",",
				p_nat->naptDroppedPktCount4);
		printf("\n Drop detail 5:%" PRIu64 ",",
				p_nat->naptDroppedPktCount5);
		printf("\n Drop detail 6:%" PRIu64 "",
				p_nat->naptDroppedPktCount6);

		printf("\nPkt_miss: %" PRIu64 " %" PRIu64 "",
				p_nat->missedpktcount1,
				p_nat->missedpktcount2);
		printf("\nPkt_miss: %" PRIu64 " %" PRIu64 "",
				p_nat->missedpktcount3,
				p_nat->missedpktcount4);
		printf("\nPkt_miss: %" PRIu64 " %" PRIu64 "",
				p_nat->missedpktcount5,
				p_nat->missedpktcount6);
		printf("\nPkt_miss: %" PRIu64 " %" PRIu64 "",
				p_nat->missedpktcount7,
				p_nat->missedpktcount8);
		printf("\nPkt_miss: %" PRIu64 " %" PRIu64 "",
				p_nat->missedpktcount9,
				p_nat->missedpktcount10);

		#endif

	}
}

/**
 * Function to print common CGNAPT table entries
 *
 */
void print_static_cgnapt_entries(void)
{
	uint32_t count = 0;
	const void *key;
	void *data;
	uint32_t next = 0;
	int32_t index = 0;
	struct cgnapt_table_entry *entry;
	do {
		index = rte_hash_iterate(napt_common_table,
				&key, &data, &next);

		if ((index != -EINVAL) && (index != -ENOENT)) {
			printf("\n%04d  ", count);
			rte_hexdump(stdout, "KEY", key,
				sizeof(struct pipeline_cgnapt_entry_key));
			int32_t position = rte_hash_lookup(
					napt_common_table, key);
			entry = &napt_hash_tbl_entries[position];

			if (entry->data.timeout == STATIC_CGNAPT_TIMEOUT)
				rte_hexdump(stdout, "Entry",
					(const void *)entry,
					sizeof(struct cgnapt_table_entry));
		}

		count++;
	} while (index != -ENOENT);
}

/**
 * Function to show CGNAPT stats
 *
 */

struct pipeline_be_ops pipeline_cgnapt_be_ops = {
	.f_init = pipeline_cgnapt_init,
	.f_free = pipeline_cgnapt_free,
	.f_run = NULL,
	.f_timer = pipeline_cgnapt_timer,
	.f_track = pipeline_cgnapt_track,
};
