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

#include "l3fwd_common.h"
#include "interface.h"
#include "l2_proto.h"
#include "l3fwd_lpm4.h"
#include "l3fwd_lpm6.h"
#include "lib_arp.h"
#include "lib_icmpv6.h"
#include <inttypes.h>
#include "vnf_common.h"

/* Declare Global variables */

/* Global for IPV6 */
void *lpm4_table; /**< lpm4_table handler */

/*Hash table for L2 adjacency */
struct rte_hash *l2_adj_hash_handle;  /**< l2 adjacency hash table handler */
struct rte_hash *fib_path_hash_handle;  /**< fib path hash table handler */

l3_stats_t stats; /**< L3 statistics */

/* Global load balancing hash table for ECMP*/
uint8_t nh_links[MAX_SUPPORTED_FIB_PATHS][HASH_BUCKET_SIZE] = /**< Round Robin Hash entries for ECMP only*/
{
	/* 1 path, No Load balancing is required */
	{0},

	/* 2 path */
	{0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
	 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
	 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
	 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1},

	/* 3 path */
	{0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0,
	 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1,
	 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2,
	 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0},

	/* 4 path */
	{0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
	 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
	 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
	 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3},

	/* 5 path */
	{0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0,
	 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1,
	 2, 3, 4, 0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1, 2,
	 3, 4, 0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1, 2, 3},

	/* 6 path */
	{0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3,
	 4, 5, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5, 0, 1,
	 2, 3, 4, 5, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5,
	 0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3},

	/* 7 path */
	{0, 1, 2, 3, 4, 5, 6, 0, 1, 2, 3, 4, 5, 6, 0, 1,
	 2, 3, 4, 5, 6, 0, 1, 2, 3, 4, 5, 6, 0, 1, 2, 3,
	 4, 5, 6, 0, 1, 2, 3, 4, 5, 6, 0, 1, 2, 3, 4, 5,
	 6, 0, 1, 2, 3, 4, 5, 6, 0, 1, 2, 3, 4, 5, 6, 0},

	/* 8 path */
	{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,
	 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,
	 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,
	 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
};

#if 0
#define META_DATA_OFFSET 128

#define RTE_PKTMBUF_HEADROOM 128	/* where is this defined ? */
#define ETHERNET_START (META_DATA_OFFSET + RTE_PKTMBUF_HEADROOM)
#define ETH_HDR_SIZE 14
#define IP_START (ETHERNET_START + ETH_HDR_SIZE)
#define TCP_START (IP_START + 20)

static void print_pkt(struct rte_mbuf *pkt)
{
	int i;
	int size = 14;
	uint8_t *rd = RTE_MBUF_METADATA_UINT8_PTR(pkt, ETHERNET_START);

	printf("Meta-data:\n");
	for (i = 0; i < size; i++) {
		printf("%02x ", rd[i]);
		if ((i & 3) == 3)
			printf("\n");
	}
	printf("\n");
	printf("IP and TCP/UDP headers:\n");
	rd = RTE_MBUF_METADATA_UINT8_PTR(pkt, IP_START);
	for (i = 0; i < 40; i++) {
		printf("%02x ", rd[i]);
		if ((i & 3) == 3)
			printf("\n");
	}

}
#endif
static struct ip_protocol_type *proto_type[2];
int lpm_init(void)
{

	/* Initiliaze LPMv4 params */
	struct rte_table_lpm_params lpm_params = {
		.name = "LPMv4",
		.n_rules = IPV4_L3FWD_LPM_MAX_RULES,
		.number_tbl8s = IPV4_L3FWD_LPM_NUMBER_TBL8S,
		.flags = 0,
		.entry_unique_size = sizeof(struct fib_info),
		.offset = 128,
	};

	/* Create LPMv4 tables */
	lpm4_table =
			rte_table_lpm_ops.f_create(&lpm_params, app_get_socket_id(),
							 sizeof(struct fib_info));
	if (lpm4_table == NULL) {
		printf("Failed to create LPM IPV4 table\n");
		return 0;
	}

	/*Initialize L2 ADJ hash params  */
	struct rte_hash_parameters l2_adj_ipv4_params = {
		.name = "l2_ADJ_HASH",
		.entries = 64,
		.key_len = sizeof(struct l2_adj_key_ipv4),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
	};

	/* Create IPv4 L2 Adj Hash tables */
	l2_adj_hash_handle = rte_hash_create(&l2_adj_ipv4_params);

	if (l2_adj_hash_handle == NULL) {
		printf("L2 ADJ rte_hash_create failed\n");
		return 0;
	} else {
		printf("l2_adj_hash_handle %p\n\n", (void *)l2_adj_hash_handle);
	}

	/*Initialize Fib PAth hassh params  */
	struct rte_hash_parameters fib_path_ipv4_params = {
		.name = "FIB_PATH_HASH",
		.entries = 64,
		.key_len = sizeof(struct fib_path_key_ipv4),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
	};

	/* Create FIB PATH Hash tables */
	fib_path_hash_handle = rte_hash_create(&fib_path_ipv4_params);

	if (fib_path_hash_handle == NULL) {
		printf("FIB path rte_hash_create failed\n");
		return 0;
	}
	return 1;
}

int lpm4_table_route_add(struct routing_info *data)
{

	struct routing_info *fib = data;
	struct rte_table_lpm_key lpm_key = {
		.ip = fib->dst_ip_addr,
		.depth = fib->depth,
	};
	uint8_t i;
	static int Total_route_count;
	struct fib_info entry;
	entry.dst_ip_addr = rte_bswap32(fib->dst_ip_addr);
	entry.depth = fib->depth;
	entry.fib_nh_size = fib->fib_nh_size;			/**< For Single Path, greater then 1 for Multipath(ECMP)*/

#if MULTIPATH_FEAT
	if (entry.fib_nh_size == 0 || entry.fib_nh_size > MAX_FIB_PATHS)
#else
	if (entry.fib_nh_size != 1)	/**< For Single FIB_PATH */
#endif
	{
		printf("Route can't be configured!!, entry.fib_nh_size = %d\n",
					 entry.fib_nh_size);
		return 0;
	}
	/* Populate L2 adj and precomputes l2 encap string */
#if MULTIPATH_FEAT
	for (i = 0; i < entry.fib_nh_size; i++)
#else
	for (i = 0; i < 1; i++)
#endif
	{
		struct fib_path *fib_path_addr = NULL;

		fib_path_addr =
				populate_fib_path(fib->nh_ip_addr[i], fib->out_port[i]);
		if (fib_path_addr) {

			entry.path[i] = fib_path_addr;
			printf("Fib info for the Dest IP");
			printf(" : %" PRIu32 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32
						 "/%" PRIu8
						 " => fib_path Addr: %p, l2_adj Addr: %p\n",
						 (fib->dst_ip_addr & 0xFF000000) >> 24,
						 (fib->dst_ip_addr & 0x00FF0000) >> 16,
						 (fib->dst_ip_addr & 0x0000FF00) >> 8,
						 (fib->dst_ip_addr & 0x000000FF), fib->depth,
						 fib_path_addr,
						 (void *)entry.path[i]->l2_adj_ptr);
		} else {
			printf("Fib info for the Dest IP :\
					%" PRIu32 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32 "/%" PRIu8 " => fib_path Addr: NULL \n", (fib->dst_ip_addr & 0xFF000000) >> 24, (fib->dst_ip_addr & 0x00FF0000) >> 16, (fib->dst_ip_addr & 0x0000FF00) >> 8, (fib->dst_ip_addr & 0x000000FF), fib->depth);
			entry.path[i] = NULL;				 /**< setting all other fib_paths to NULL */
		}
	}

	int key_found, ret;
	void *entry_ptr;
	ret =
			rte_table_lpm_ops.f_add(lpm4_table, (void *)&lpm_key, &entry,
						&key_found, &entry_ptr);

	if (ret != 0) {
		printf("Failed to Add IP route\n");
		return 0;
	}
	Total_route_count++;
	printf("Total Routed Added : %u, Key_found: %d\n", Total_route_count,
				 key_found);
	printf("Adding Route to LPM table...\n");

	printf("Iterate with Cuckoo Hash table\n");
	iterate_cuckoo_hash_table();
	return 1;
}

int lpm4_table_route_delete(uint32_t dst_ip, uint8_t depth)
{

	struct rte_table_lpm_key lpm_key = {
		.ip = dst_ip,
		.depth = depth,
	};

	int key_found, ret;
	void *entry = NULL;

	entry = rte_zmalloc(NULL, 512, RTE_CACHE_LINE_SIZE);

	/* Deleting a IP route from LPMv4 table */
	ret =
			rte_table_lpm_ops.f_delete(lpm4_table, &lpm_key, &key_found, entry);

	if (ret) {
		printf("Failed to Delete IP route from LPMv4 table\n");
		return 0;
	}

	printf("Deleted route from LPM table (IPv4 Address = %"
				 PRIu32 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32
				 "/%u , key_found = %d\n", (lpm_key.ip & 0xFF000000) >> 24,
				 (lpm_key.ip & 0x00FF0000) >> 16, (lpm_key.ip & 0x0000FF00) >> 8,
				 (lpm_key.ip & 0x000000FF), lpm_key.depth, key_found);

	/* Deleting a L2 Adj entry if refcount is 1, Else decrement Refcount */
	remove_fib_l2_adj_entry(entry);
	rte_free(entry);
	printf("Iterate with Cuckoo Hash table\n");
	iterate_cuckoo_hash_table();
	return 1;
}

int
lpm4_table_lookup(struct rte_mbuf **pkts_burst, uint16_t nb_pkts,
			uint64_t pkts_mask,
			l2_phy_interface_t *port_ptr[RTE_PORT_IN_BURST_SIZE_MAX],
			uint64_t *hit_mask)
{

	struct routing_table_entry *ipv4_entries[RTE_PORT_IN_BURST_SIZE_MAX];
	uint64_t lookup_hit_mask_ipv4 = 0;
	int status;
	uint64_t pkts_key_mask = pkts_mask;
	uint64_t lookup_miss_mask_ipv4 = pkts_mask;

	static uint64_t sent_count;
	static uint64_t rcvd_count;
	rcvd_count += nb_pkts;
	if (L3FWD_DEBUG) {
		printf
				(" Received IPv4 nb_pkts: %u, Rcvd_count: %lu\n, pkts_mask: %p\n",
				 nb_pkts, rcvd_count, (void *)pkts_mask);
	}
	uint32_t dst_addr_offset =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST;

	for (; pkts_key_mask;) {
/**< Populate key offset in META DATA for all valid pkts */
		uint8_t pos = (uint8_t) __builtin_ctzll(pkts_key_mask);
		uint64_t pkt_mask = 1LLU << pos;
		pkts_key_mask &= ~pkt_mask;
		struct rte_mbuf *mbuf = pkts_burst[pos];
		uint32_t *lpm_key = NULL;
		uint32_t *dst_addr = NULL;
		lpm_key = (uint32_t *) RTE_MBUF_METADATA_UINT8_PTR(mbuf, 128);
		dst_addr =
				(uint32_t *) RTE_MBUF_METADATA_UINT8_PTR(mbuf,
									 dst_addr_offset);
		*lpm_key = *dst_addr;
		if (L3FWD_DEBUG) {

			printf("Rcvd Pakt (IPv4 Address = %"
						 PRIu32 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32 ")\n",
						 (rte_cpu_to_be_32(*lpm_key) & 0xFF000000) >> 24,
						 (rte_cpu_to_be_32(*lpm_key) & 0x00FF0000) >> 16,
						 (rte_cpu_to_be_32(*lpm_key) & 0x0000FF00) >> 8,
						 (rte_cpu_to_be_32(*lpm_key) & 0x000000FF));
		}
	}

	/* Lookup for IP route in LPM table */
	if (L3FWD_DEBUG)
		printf("\nIPV4 Lookup Mask Before = %p\n",
					 (void *)lookup_hit_mask_ipv4);
	status =
			rte_table_lpm_ops.f_lookup(lpm4_table, pkts_burst, pkts_mask,
							 &lookup_hit_mask_ipv4,
							 (void **)ipv4_entries);

	if (status) {
		printf("LPM Lookup failed for IP route\n");
		return 0;
	}

	lookup_miss_mask_ipv4 = lookup_miss_mask_ipv4 & (~lookup_hit_mask_ipv4);
	if (L3FWD_DEBUG) {
		printf
				("AFTER lookup_hit_mask_ipv4 = %p, lookup_miss_mask_ipv4 =%p\n",
				 (void *)lookup_hit_mask_ipv4,
				 (void *)lookup_miss_mask_ipv4);
	}

	for (; lookup_miss_mask_ipv4;) {
/**< Drop packets for lookup_miss_mask */
		uint8_t pos = (uint8_t) __builtin_ctzll(lookup_miss_mask_ipv4);
		uint64_t pkt_mask = 1LLU << pos;
		lookup_miss_mask_ipv4 &= ~pkt_mask;
		rte_pktmbuf_free(pkts_burst[pos]);
		pkts_burst[pos] = NULL;
		stats.nb_l3_drop_pkt++;	 /**< Peg the L3 Drop counter */
		if (L3FWD_DEBUG)
			printf("\n DROP PKT IPV4 Lookup_miss_Mask  = %p\n",
						 (void *)lookup_miss_mask_ipv4);
	}

	*hit_mask = lookup_hit_mask_ipv4;
	for (; lookup_hit_mask_ipv4;) {
/**< Process the packets for lookup_hit_mask*/
		uint8_t pos = (uint8_t) __builtin_ctzll(lookup_hit_mask_ipv4);
		uint64_t pkt_mask = 1LLU << pos;
		lookup_hit_mask_ipv4 &= ~pkt_mask;
		struct rte_mbuf *pkt = pkts_burst[pos];

		struct fib_info *entry = (struct fib_info *)ipv4_entries[pos];

#if MULTIPATH_FEAT

		uint8_t ecmp_path = 0;
		ecmp_path = ip_hash_load_balance(pkts_burst[pos]);
		uint8_t selected_path = 0;
		struct fib_path *fib_path = NULL;
		if (((entry->fib_nh_size != 0)
				 && (entry->fib_nh_size - 1) < MAX_SUPPORTED_FIB_PATHS)
				&& ((ecmp_path != 0) && (ecmp_path - 1) < HASH_BUCKET_SIZE))
			selected_path =
					nh_links[entry->fib_nh_size - 1][ecmp_path - 1];
		if (selected_path < MAX_FIB_PATHS)
			fib_path = entry->path[selected_path];
		if (L3FWD_DEBUG) {
			printf
					("Total supported Path :%u, Hashed ECMP Key : %u, selected Fib_path: %u\n",
					 entry->fib_nh_size, ecmp_path, selected_path);
		}
#else
		struct fib_path *fib_path = entry->path[0];
#endif

		if (fib_path == NULL) {
			rte_pktmbuf_free(pkt);
			pkts_burst[pos] = NULL;
			stats.nb_l3_drop_pkt++;	 /**< Peg the L3 Drop counter */
			*hit_mask &= ~pkt_mask;	/**< Remove this pkt from port Mask */
			if (L3FWD_DEBUG)
				printf
						("Fib_path is NULL, ARP has not resolved, DROPPED UNKNOWN PKT\n");
			continue;
		}

		if (fib_path->l2_adj_ptr->flags == L2_ADJ_UNRESOLVED) {
			if (fib_path->l2_adj_ptr->phy_port->ipv4_list != NULL)
				request_arp(fib_path->l2_adj_ptr->phy_port->
							pmdid, fib_path->nh_ip);

			rte_pktmbuf_free(pkts_burst[pos]);
			pkts_burst[pos] = NULL;
			*hit_mask &= ~pkt_mask;	/**< Remove this pkt from port Mask */
			if (L3FWD_DEBUG)
				printf
						("L2_ADJ_UNRESOLVED, DROPPED UNKNOWN PKT\n");
			continue;
		}

		/* extract ip headers and MAC */
		uint8_t *eth_dest =
				RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
		uint8_t *eth_src =
				RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM + 6);
		if (L3FWD_DEBUG) {
			printf
					("MAC BEFORE- DST MAC %02x:%02x:%02x:%02x:%02x:%02x, \
					SRC MAC %02x:%02x:%02x:%02x:%02x:%02x \n",
					 eth_dest[0], eth_dest[1], eth_dest[2], eth_dest[3], eth_dest[4], eth_dest[5], eth_src[0], eth_src[1],
					 eth_src[2], eth_src[3], eth_src[4], eth_src[5]);
		}
		/* Rewrite the packet with L2 string  */
		memcpy(eth_dest, fib_path->l2_adj_ptr->l2_string, sizeof(struct ether_addr) * 2);	// For MAC
		if (L3FWD_DEBUG) {
			int k = 0;
			for (k = 0; k < 14; k++) {
				printf("%02x ",
							 fib_path->l2_adj_ptr->l2_string[k]);
				printf("\n");
			}
			printf
					("MAC AFTER DST MAC %02x:%02x:%02x:%02x:%02x:%02x, \
					SRC MAC %02x:%02x:%02x:%02x:%02x:%02x\n", eth_dest[0], eth_dest[1], eth_dest[2], eth_dest[3], eth_dest[4], eth_dest[5], eth_src[0], eth_src[1], eth_src[2], eth_src[3], eth_src[4], eth_src[5]);
		}
		port_ptr[pos] = fib_path->l2_adj_ptr->phy_port;
		if (L3FWD_DEBUG) {
			printf("l3fwd_lookup API!!!!\n");
			//print_pkt(pkt);
		}

		sent_count++;
		stats.nb_tx_l3_pkt++;
		if (L3FWD_DEBUG)
			printf
					("Successfully sent to port %u, sent_count : %lu\n\r",
					 fib_path->out_port, sent_count);
	}
	return 1;
}

int is_valid_ipv4_pkt(struct ipv4_hdr *pkt, uint32_t link_len)
{
	if (link_len < sizeof(struct ipv4_hdr))
		return -1;
	if (((pkt->version_ihl) >> 4) != 4)
		return -1;
	if ((pkt->version_ihl & 0xf) < 5)
		return -1;
	if (rte_cpu_to_be_16(pkt->total_length) < sizeof(struct ipv4_hdr))
		return -1;
	return 0;
}

int
get_dest_mac_for_nexthop(uint32_t next_hop_ip,
			 uint8_t out_phy_port, struct ether_addr *hw_addr)
{
	struct arp_entry_data *arp_data = NULL;
	struct arp_key_ipv4 arp_key;
	arp_key.port_id = out_phy_port;
	arp_key.ip = next_hop_ip;

	arp_data = retrieve_arp_entry(arp_key);
	if (arp_data == NULL) {
		printf("ARP entry is not found for ip %x, port %d\n",
					 next_hop_ip, out_phy_port);
		return 0;
	}
	ether_addr_copy(&arp_data->eth_addr, hw_addr);
	return 1;
}

struct l2_adj_entry *retrieve_l2_adj_entry(struct l2_adj_key_ipv4 l2_adj_key)
{
	struct l2_adj_entry *ret_l2_adj_data = NULL;
	l2_adj_key.filler1 = 0;
	l2_adj_key.filler2 = 0;
	l2_adj_key.filler3 = 0;

	int ret =
			rte_hash_lookup_data(l2_adj_hash_handle, &l2_adj_key,
				 (void **)&ret_l2_adj_data);
	if (ret < 0) {
		#ifdef L2L3_DEBUG
		printf
				("L2 Adj hash lookup failed ret %d, EINVAL %d, ENOENT %d\n",
				 ret, EINVAL, ENOENT);
		#endif
		return NULL;
	} else {
		#ifdef L2L3_DEBUG
		printf
				("L2 Adj hash lookup Success, Entry Already Exist ret %d, EINVAL %d, ENOENT %d\n",
				 ret, EINVAL, ENOENT);
		#endif
		return ret_l2_adj_data;
	}
}

void remove_fib_l2_adj_entry(void *entry)
{
	struct fib_info entry1;
	memcpy(&entry1, entry, sizeof(struct fib_info));

	struct fib_path *fib_path_addr = entry1.path[0];  /**< For Single path */
	if (fib_path_addr->refcount > 1) {
		printf
				(" BEFORE fib_path entry, nh_ip %x, port %d, refcount %d\n",
				 fib_path_addr->nh_ip, fib_path_addr->out_port,
				 fib_path_addr->refcount);
		fib_path_addr->refcount--;		 /**< Just decrement the refcount this entry is still referred*/
		printf("AFTER fib_path entry, nh_ip %x, port %d, refcount %d\n",
					 fib_path_addr->nh_ip, fib_path_addr->out_port,
					 fib_path_addr->refcount);
	} else {
/**< Refcount is 1 so delete both fib_path and l2_adj_entry */

		struct l2_adj_entry *adj_addr = NULL;
		adj_addr = fib_path_addr->l2_adj_ptr;

		if (adj_addr != NULL) {
/** < l2_adj_entry is has some entry in hash table*/
			struct l2_adj_key_ipv4 l2_adj_key = {
				.Next_hop_ip = fib_path_addr->nh_ip,
				.out_port_id = fib_path_addr->out_port,
			};
			#ifdef L3FWD_DEBUG
			printf
					(" l2_adj_entry is removed for ip %x, port %d, refcount %d\n",
					 l2_adj_key.Next_hop_ip, l2_adj_key.out_port_id,
					 adj_addr->refcount);
			#endif

			rte_hash_del_key(l2_adj_hash_handle, &l2_adj_key);
			rte_free(adj_addr); /**< free the memory which was allocated for Hash entry */
			adj_addr = NULL;
		}

		struct fib_path_key_ipv4 path_key = {
			.nh_ip = fib_path_addr->nh_ip,
			.out_port = fib_path_addr->out_port,
		};

		printf
				("fib_path entry is removed for ip %x, port %d, refcount %d\n",
				 fib_path_addr->nh_ip, fib_path_addr->out_port,
				 fib_path_addr->refcount);
		rte_hash_del_key(fib_path_hash_handle, &path_key);
		rte_free(fib_path_addr); /**< Free the memory which was allocated for Hash entry*/
		fib_path_addr = NULL;
	}
}

struct l2_adj_entry *populate_l2_adj(uint32_t ipaddr, uint8_t portid)
{

	struct l2_adj_key_ipv4 l2_adj_key;
	l2_adj_key.out_port_id = portid;
	l2_adj_key.Next_hop_ip = ipaddr;
	l2_adj_key.filler1 = 0;
	l2_adj_key.filler2 = 0;
	l2_adj_key.filler3 = 0;

	struct ether_addr eth_dst;
	struct l2_adj_entry *adj_data = NULL;

	/* Populate L2 adj if the MAC Address is already present in L2 Adj HAsh Table */
	adj_data = retrieve_l2_adj_entry(l2_adj_key);

	if (adj_data) {	 /**< L2 Adj Entry Exists*/

		printf
				("l2_adj_entry exists ip%x, port %d, Refcnt :%u Address :%p\n",
				 l2_adj_key.Next_hop_ip, l2_adj_key.out_port_id,
				 adj_data->refcount, adj_data);
		ether_addr_copy(&adj_data->eth_addr, &eth_dst);
		adj_data->refcount++;
		printf
				("l2_adj_entry UPDATED Refcount for NH ip%x, port %d, Refcnt :%u Address :%p\n",
				 l2_adj_key.Next_hop_ip, l2_adj_key.out_port_id,
				 adj_data->refcount, adj_data);
		return adj_data;
	}

	struct ether_addr eth_src;
	l2_phy_interface_t *port;
	//uint16_t ether_type = 0x0800;
	port = ifm_get_port(portid);

	if (port != NULL) {
		memcpy(&eth_src, &port->macaddr, sizeof(struct ether_addr));
		unsigned char *p = (unsigned char *)eth_src.addr_bytes;
		printf("S-MAC %x:%x:%x:%x:%x:%x\n\r", p[0], p[1], p[2], p[3],
					 p[4], p[5]);

		uint32_t size =
				RTE_CACHE_LINE_ROUNDUP(sizeof(struct l2_adj_entry));
		adj_data = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
		if (adj_data == NULL) {
			printf("L2 Adjacency memory allocation failed !\n");
			return NULL;
		}

		adj_data->out_port_id = portid;
		adj_data->Next_hop_ip = ipaddr;
		adj_data->refcount++;

		adj_data->phy_port = port;
		memset(&adj_data->eth_addr, 0, sizeof(struct ether_addr));
		memset(&adj_data->l2_string, 0, 256);

		/**< Store the received MAC Address in L2 Adj HAsh Table */
		rte_hash_add_key_data(l2_adj_hash_handle, &l2_adj_key,
							adj_data);
		#ifdef L2L3_DEBUG
		printf
				("L2 adj data stored in l2_adj_entry hash table,Addr:%p\n",
				 adj_data);
		#endif
	} else {
		#ifdef L2L3_DEBUG
		printf("\n PORT %u IS DOWN...\n", portid);
		#endif
		return NULL;
	}
	/* Query ARP to get L2 Adj */
	if (get_dest_mac_for_nexthop(ipaddr, portid, &eth_dst)) {
		unsigned char *p = (unsigned char *)eth_dst.addr_bytes;
		printf
				("ARP resolution success and stored in l2_adj_entry hash table:D-MAC %x:%x:%x:%x:%x:%x\n\r",
				 p[0], p[1], p[2], p[3], p[4], p[5]);

		memcpy(adj_data->l2_string, &eth_dst, sizeof(struct ether_addr));	//** < Precompute the L2 String encap*/
		memcpy(&adj_data->l2_string[6], &eth_src,
					 sizeof(struct ether_addr));
		//memcpy(&adj_data->l2_string[12], &ether_type, 2);

		ether_addr_copy(&eth_dst, &adj_data->eth_addr);
		adj_data->flags = L2_ADJ_RESOLVED;
	} else {
		adj_data->flags = L2_ADJ_UNRESOLVED;
		printf
				(" ARP resolution Failed !! , unable to write in l2_adj_entry\n");
	}
	return adj_data;
}

struct fib_path *populate_fib_path(uint32_t nh_ip, uint8_t portid)
{

	struct fib_path_key_ipv4 path_key;
	path_key.out_port = portid;
	path_key.nh_ip = nh_ip;
	path_key.filler1 = 0;
	path_key.filler2 = 0;
	path_key.filler3 = 0;

	struct fib_path *fib_data = NULL;

	/* Populate fib_path */
	fib_data = retrieve_fib_path_entry(path_key);

	if (fib_data) {/**< fib_path entry already exists */

		/* Already present in FIB_PATH cuckoo HAsh Table */
		printf
				("fib_path_entry already exists for NextHop ip: %x, port %d\n, Refcount %u Addr:%p\n",
				 fib_data->nh_ip, fib_data->out_port, fib_data->refcount,
				 fib_data);
		fib_data->refcount++;
		fib_data->l2_adj_ptr->refcount++;
		printf
				("fib_path Refcount Updated NextHop :%x , port %u, Refcount %u\n\r",
				 fib_data->nh_ip, fib_data->out_port, fib_data->refcount);
		return fib_data;
	} else {
		printf("fib_path entry Doesn't Exists.......\n");
	}

	fib_data = NULL;
	struct l2_adj_entry *l2_adj_ptr = NULL;
	l2_adj_ptr = populate_l2_adj(nh_ip, portid);

	if (l2_adj_ptr) {

		uint32_t size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct fib_path));
		fib_data = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);

		fib_data->out_port = portid;
		fib_data->nh_ip = nh_ip;
		fib_data->refcount++;
		fib_data->l2_adj_ptr = l2_adj_ptr;

		printf("%s: get port details %u %d\n\r", __FUNCTION__, portid,
					 __LINE__);
		/* Store the received MAC Address in L2 Adj HAsh Table */
		int status;
		status =
				rte_hash_add_key_data(fib_path_hash_handle, &path_key,
						fib_data);
		if (status) {
			printf
					("fib_path entry addition to hash table FAILED!! NextHop :%x , port %u, Refcount %u\n\r",
					 fib_data->nh_ip, fib_data->out_port,
					 fib_data->refcount);

			rte_free(fib_data);
		} else {
			printf
					("fib_path entry Added into hash table for the NextHop :%x , port %u, Refcount %u\n\r",
					 fib_data->nh_ip, fib_data->out_port,
					 fib_data->refcount);
			printf
					(" l2_adj_entry Addr: %p, Fib_path Addr: %p, FibPath->l2ADJ Addr:%p \n",
					 l2_adj_ptr, fib_data, fib_data->l2_adj_ptr);
			printf
					(" ARP resolution success l2_adj_entry Addr: %p, Fib_path Addr: %p \n",
					 l2_adj_ptr, fib_data);
			return fib_data;
		}
	} else {
		printf
				(" ARP resolution failed and unable to write fib path in fib_path cuckoo hash\n");
	}
	return NULL;
}

struct fib_path *retrieve_fib_path_entry(struct fib_path_key_ipv4 path_key)
{
	printf("FIB PATH for NExtHOP IP : %x, port :%u\n", path_key.nh_ip,
				 path_key.out_port);

	struct fib_path *ret_fib_path_data = NULL;
	int ret =
			rte_hash_lookup_data(fib_path_hash_handle, &path_key,
				 (void **)&ret_fib_path_data);
	if (ret < 0) {
		printf
				("FIB PATH hash lookup Failed!! ret %d, EINVAL %d, ENOENT %d\n",
				 ret, EINVAL, ENOENT);
		return NULL;
	} else {
		printf("FIB PATH ALREADY Exists for NExtHOP IP: %x, port: %u\n",
					 path_key.nh_ip, path_key.out_port);
		return ret_fib_path_data;
	}
}

void iterate_cuckoo_hash_table(void)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;

	printf("\n\t\t\t FIB_path Cache table....");
	printf
			("\n----------------------------------------------------------------");
	printf("\n\tNextHop IP    Port   Refcount   l2_adj_ptr_addrress\n");
	printf
			("\n----------------------------------------------------------------\n");

	while (rte_hash_iterate
				 (fib_path_hash_handle, &next_key, &next_data, &iter) >= 0) {
		struct fib_path *tmp_data = (struct fib_path *)next_data;
		struct fib_path_key_ipv4 tmp_key;
		memcpy(&tmp_key, next_key, sizeof(tmp_key));
		printf("\t %" PRIu32 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32
					 " \t %u \t %u \t %p\n",
					 (tmp_data->nh_ip & 0xFF000000) >> 24,
					 (tmp_data->nh_ip & 0x00FF0000) >> 16,
					 (tmp_data->nh_ip & 0x0000FF00) >> 8,
					 (tmp_data->nh_ip & 0x000000FF), tmp_data->out_port,
					 tmp_data->refcount, tmp_data->l2_adj_ptr);

	}
	iter = 0;

	printf("\n\t\t\t L2 ADJ Cache table.....");
	printf
			("\n------------------------------------------------------------------------------------");
	printf
			("\n\tNextHop IP    Port  \t l2 Encap string \t l2_Phy_interface\n");
	printf
			("\n------------------------------------------------------------------------------------\n");

	while (rte_hash_iterate
				 (l2_adj_hash_handle, &next_key, &next_data, &iter) >= 0) {
		struct l2_adj_entry *l2_data = (struct l2_adj_entry *)next_data;
		struct l2_adj_key_ipv4 l2_key;
		memcpy(&l2_key, next_key, sizeof(l2_key));
		printf("\t %" PRIu32 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32
					 "\t %u \t%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x\t%p\n",
					 (l2_data->Next_hop_ip & 0xFF000000) >> 24,
					 (l2_data->Next_hop_ip & 0x00FF0000) >> 16,
					 (l2_data->Next_hop_ip & 0x0000FF00) >> 8,
					 (l2_data->Next_hop_ip & 0x000000FF),
					 l2_data->out_port_id, l2_data->l2_string[0],
					 l2_data->l2_string[1], l2_data->l2_string[2],
					 l2_data->l2_string[3], l2_data->l2_string[4],
					 l2_data->l2_string[5], l2_data->l2_string[6],
					 l2_data->l2_string[7], l2_data->l2_string[8],
					 l2_data->l2_string[9], l2_data->l2_string[10],
					 l2_data->l2_string[11], l2_data->phy_port);
	}
}

void print_l3_stats(void)
{
	printf("==============================================\n");
	printf("\t\t L3 STATISTICS \t\n");
	printf("==============================================\n");
	printf(" Num of Received L3 Pkts     : %lu\n", stats.nb_rx_l3_pkt);
	printf(" Num of Dropped L3 Pkts      : %lu\n", stats.nb_l3_drop_pkt);
	printf(" Num of Transmitted L3 Pkts  : %lu\n", stats.nb_tx_l3_pkt);
	printf(" Num of ICMP Pkts Rcvd at L3 : %lu\n", stats.nb_rx_l3_icmp_pkt);
	printf(" Num of ICMP Pkts Tx to ICMP : %lu\n", stats.nb_tx_l3_icmp_pkt);
	stats.total_nb_rx_l3_pkt = stats.nb_rx_l3_icmp_pkt + stats.nb_rx_l3_pkt;
	stats.total_nb_tx_l3_pkt = stats.nb_tx_l3_icmp_pkt + stats.nb_tx_l3_pkt;
	printf(" Total Num of Rcvd pkts at L3: %lu\n",
				 stats.total_nb_rx_l3_pkt);
	printf(" Total Num of Sent pkts at L3: %lu\n",
				 stats.total_nb_tx_l3_pkt);
}

void
ip_local_packets_process(struct rte_mbuf **pkt_burst, uint16_t nb_rx,
			 uint64_t icmp_pkt_mask, l2_phy_interface_t *port)
{
	process_arpicmp_pkt_parse(pkt_burst, nb_rx, icmp_pkt_mask, port);
}

void
ip_forward_deliver(struct rte_mbuf **pkt_burst, uint16_t nb_pkts,
			 uint64_t ipv4_forward_pkts_mask, l2_phy_interface_t *port)
{
	if (L3FWD_DEBUG) {
		printf
				("ip_forward_deliver BEFORE DROP: nb_pkts: %u\n from in_port %u",
				 nb_pkts, port->pmdid);
	}
	uint64_t pkts_for_process = ipv4_forward_pkts_mask;

	struct ipv4_hdr *ipv4_hdr;
	l2_phy_interface_t *port_ptr[RTE_PORT_IN_BURST_SIZE_MAX];
	uint64_t hit_mask = 0;

	for (; pkts_for_process;) {
/**< process only valid packets.*/
		uint8_t pos = (uint8_t) __builtin_ctzll(pkts_for_process);
		uint64_t pkt_mask = 1LLU << pos;   /**< bitmask representing only this packet */
		pkts_for_process &= ~pkt_mask;		 /**< remove this packet from the mask */
		ipv4_hdr =
				rte_pktmbuf_mtod_offset(pkt_burst[pos], struct ipv4_hdr *,
							sizeof(struct ether_hdr));
		/* Make sure the IPv4 packet is valid  */
		if (is_valid_ipv4_pkt(ipv4_hdr, pkt_burst[pos]->pkt_len) < 0) {
			rte_pktmbuf_free(pkt_burst[pos]);   /**< Drop the Unknown IPv4 Packet */
			pkt_burst[pos] = NULL;
			ipv4_forward_pkts_mask &= ~(1LLU << pos);  /**< That will clear bit of that position*/
			nb_pkts--;
			stats.nb_l3_drop_pkt++;
		}
	}

	if (L3FWD_DEBUG) {
		printf
				("\nl3fwd_rx_ipv4_packets_received AFTER DROP: nb_pkts: %u, valid_Pkts_mask :%lu\n",
				 nb_pkts, ipv4_forward_pkts_mask);
	}

	/* Lookup for IP destination in LPMv4 table */
	lpm4_table_lookup(pkt_burst, nb_pkts, ipv4_forward_pkts_mask, port_ptr,
				&hit_mask);

	for (; hit_mask;) {
/**< process only valid packets.*/
		uint8_t pos = (uint8_t) __builtin_ctzll(hit_mask);
		uint64_t pkt_mask = 1LLU << pos;   /**< bitmask representing only this packet */
		hit_mask &= ~pkt_mask;		 /**< remove this packet from the mask */

		port_ptr[pos]->transmit_single_pkt(port_ptr[pos],
							 pkt_burst[pos]);
	}

}

void
l3_protocol_type_add(uint8_t protocol_type,
				 void (*func) (struct rte_mbuf **, uint16_t, uint64_t,
					 l2_phy_interface_t *port))
{
	switch (protocol_type) {
	case IPPROTO_ICMP:
		proto_type[IP_LOCAL] =
				rte_malloc(NULL, sizeof(struct ip_protocol_type),
						 RTE_CACHE_LINE_SIZE);
		proto_type[IP_LOCAL]->protocol_type = protocol_type;
		proto_type[IP_LOCAL]->func = func;
		break;

	case IPPROTO_TCP:	// Time being treared as Remote forwarding
	case IPPROTO_UDP:
		proto_type[IP_REMOTE] =
				rte_malloc(NULL, sizeof(struct ip_protocol_type),
						 RTE_CACHE_LINE_SIZE);
		proto_type[IP_REMOTE]->protocol_type = protocol_type;
		proto_type[IP_REMOTE]->func = func;
		break;

	}

}

void l3fwd_rx_ipv4_packets(struct rte_mbuf **m, uint16_t nb_pkts,
				 uint64_t valid_pkts_mask, l2_phy_interface_t *port)
{
	if (L3FWD_DEBUG) {
		printf
				("l3fwd_rx_ipv4_packets_received BEFORE DROP: nb_pkts: %u\n from in_port %u",
				 nb_pkts, port->pmdid);
	}
	uint64_t pkts_for_process = valid_pkts_mask;

	struct ipv4_hdr *ipv4_hdr;
	uint32_t configure_port_ip = 0;
	uint64_t icmp_pkts_mask = RTE_LEN2MASK(nb_pkts, uint64_t);
	uint64_t ipv4_forward_pkts_mask = RTE_LEN2MASK(nb_pkts, uint64_t);
	uint16_t nb_icmp_pkt = 0;
	uint16_t nb_l3_pkt = 0;

	if (port->ipv4_list != NULL)
		configure_port_ip =
				(uint32_t) (((ipv4list_t *) (port->ipv4_list))->ipaddr);

	for (; pkts_for_process;) {
/**< process only valid packets.*/
		uint8_t pos = (uint8_t) __builtin_ctzll(pkts_for_process);
		uint64_t pkt_mask = 1LLU << pos;   /**< bitmask representing only this packet */
		pkts_for_process &= ~pkt_mask;		 /**< remove this packet from the mask */
		ipv4_hdr =
				rte_pktmbuf_mtod_offset(m[pos], struct ipv4_hdr *,
							sizeof(struct ether_hdr));

		if ((ipv4_hdr->next_proto_id == IPPROTO_ICMP)
				&& (ipv4_hdr->dst_addr == configure_port_ip)) {
			ipv4_forward_pkts_mask &= ~pkt_mask; /**< Its  ICMP, remove this packet from the ipv4_forward_pkts_mask*/
			stats.nb_rx_l3_icmp_pkt++;  /**< Increment stats for ICMP PKT */
			nb_icmp_pkt++;
		} else{		// Forward the packet
			icmp_pkts_mask &= ~pkt_mask;  /**< Not ICMP, remove this packet from the icmp_pkts_mask*/
			stats.nb_rx_l3_pkt++;
			nb_l3_pkt++;	/**< Increment stats for L3 PKT */
		}
	}

	if (icmp_pkts_mask) {
		if (L3FWD_DEBUG)
			printf
					("\n RECEiVED LOCAL ICMP PKT at L3...\n PROCESSING ICMP LOCAL PKT...\n");
		proto_type[IP_LOCAL]->func(m, nb_icmp_pkt, icmp_pkts_mask,
						 port);
	}

	if (ipv4_forward_pkts_mask) {
		if (L3FWD_DEBUG)
			printf
					("\n RECEIVED L3 PKT, \n\n FORWARDING L3 PKT....\n");
		proto_type[IP_REMOTE]->func(m, nb_l3_pkt,
							ipv4_forward_pkts_mask, port);
	}
}

void
resolve_l2_adj(uint32_t nexthop_ip, uint8_t out_port_id,
				 const struct ether_addr *hw_addr)
{
	struct l2_adj_key_ipv4 l2_adj_key = {
		.Next_hop_ip = nexthop_ip,
		.out_port_id = out_port_id,
	};
	//uint16_t ether_type = 0x0800;

	struct l2_adj_entry *adj_data = retrieve_l2_adj_entry(l2_adj_key);

	if (adj_data) {	 /**< L2 Adj Entry Exists*/

		printf
				("l2_adj_entry exists ip%x, port %d, Refcnt :%u Address :%p\n",
				 l2_adj_key.Next_hop_ip, l2_adj_key.out_port_id,
				 adj_data->refcount, adj_data);

		if (adj_data->flags == L2_ADJ_UNRESOLVED
				|| memcmp(hw_addr, &adj_data->eth_addr,
						sizeof(struct ether_addr))) {
			memcpy(adj_data->l2_string, hw_addr, sizeof(struct ether_addr));	//** < Precompute the L2 String encap*/
			memcpy(&adj_data->l2_string[6],
						 &adj_data->phy_port->macaddr,
						 sizeof(struct ether_addr));
			//memcpy(&adj_data->l2_string[12], &ether_type, 2);

			ether_addr_copy(hw_addr, &adj_data->eth_addr);
			adj_data->flags = L2_ADJ_RESOLVED;
		}

		return;
	}

	l2_phy_interface_t *port;
	port = ifm_get_port(out_port_id);
	if (port != NULL) {

		uint32_t size =
				RTE_CACHE_LINE_ROUNDUP(sizeof(struct l2_adj_entry));
		adj_data = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
		if (adj_data == NULL) {
			printf("L2 Adjacency memory allocation failed !\n");
			return;
		}

		adj_data->out_port_id = out_port_id;
		adj_data->Next_hop_ip = nexthop_ip;
		adj_data->phy_port = port;

		memcpy(adj_data->l2_string, hw_addr, sizeof(struct ether_addr));	//** < Precompute the L2 String encap*/
		memcpy(&adj_data->l2_string[6], &adj_data->phy_port->macaddr,
					 sizeof(struct ether_addr));
		//memcpy(&adj_data->l2_string[12], &ether_type, 2);

		ether_addr_copy(hw_addr, &adj_data->eth_addr);
		adj_data->flags = L2_ADJ_RESOLVED;

		rte_hash_add_key_data(l2_adj_hash_handle, &l2_adj_key,
							adj_data);
		printf
				("L2 adj data stored in l2_adj_entry hash table,Addr:%p\n",
				 adj_data);
	} else
		printf("PORT:%u IS DOWN...\n", out_port_id);

	return;
}

uint8_t ip_hash_load_balance(struct rte_mbuf *mbuf)
{
	uint32_t src_addr_offset =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_SRC_ADR_OFST;
	uint32_t dst_addr_offset =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST;
	uint32_t *dst_addr = NULL;
	uint32_t *src_addr = NULL;
	src_addr =
			(uint32_t *) RTE_MBUF_METADATA_UINT8_PTR(mbuf, src_addr_offset);
	dst_addr =
			(uint32_t *) RTE_MBUF_METADATA_UINT8_PTR(mbuf, dst_addr_offset);

	uint32_t hash_key1 = *src_addr;	/* STORE SRC IP in key1 variable */
	uint32_t hash_key2 = *dst_addr;	/* STORE DST IP in key variable */

	hash_key1 = hash_key1 ^ hash_key2;	/* XOR With SRC and DST IP, Result is hask_key1 */
	hash_key2 = hash_key1;	/* MOVE The result to hask_key2 */

	hash_key1 = rotr32(hash_key1, 16);	/* Circular Rotate to 16 bit */
	hash_key1 = hash_key1 ^ hash_key2;	/* XOR With Key1 with Key2 */

	hash_key2 = hash_key1;	/* MOVE The result to hask_key2 */

	hash_key1 = rotr32(hash_key1, 8);	/* Circular Rotate to 8 bit */
	hash_key1 = hash_key1 ^ hash_key2;	/* XOR With Key1 with Key2 */

	hash_key1 = hash_key1 & (HASH_BUCKET_SIZE - 1);	/* MASK the KEY with BUCKET SIZE */
	if (L3FWD_DEBUG)
		printf("Hash Result_key: %d, \n", hash_key1);
	return hash_key1;
}

uint32_t rotr32(uint32_t value, unsigned int count)
{
	const unsigned int mask = (CHAR_BIT * sizeof(value) - 1);
	count &= mask;
	return (value >> count) | (value << ((-count) & mask));
}

void
ip_local_out_deliver(struct rte_mbuf **pkt_burst, uint16_t nb_rx,
				 uint64_t ipv4_pkts_mask, l2_phy_interface_t *port)
{
	ip_forward_deliver(pkt_burst, nb_rx, ipv4_pkts_mask, port);
}
