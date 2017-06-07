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
#include "l3fwd_lpm4.h"
#include "l3fwd_lpm6.h"
#include "l3fwd_common.h"
#include "interface.h"
#include "l2_proto.h"
#include "lib_arp.h"
#include "lib_icmpv6.h"

/* Declare Global variables */

/* Global for IPV6 */
void *lpm6_table; /**< lpm6 table handler */
struct rte_hash *l2_adj_ipv6_hash_handle;  /**< IPv6 l2 adjacency table handler */
struct rte_hash *fib_path_ipv6_hash_handle;  /**< IPv6 fib path hash table handler */
extern uint8_t nh_links[MAX_SUPPORTED_FIB_PATHS][HASH_BUCKET_SIZE];
extern l3_stats_t stats; /**< L3 statistics */

static struct ipv6_protocol_type *proto_type[2];

int lpm6_init(void)
{

	/* Initiliaze LPMv6 params */

	struct rte_table_lpm_ipv6_params lpm6_params = {
		.name = "LPMv6",
		.n_rules = IPV6_L3FWD_LPM_MAX_RULES,
		.number_tbl8s = IPV6_L3FWD_LPM_NUMBER_TBL8S,
		.entry_unique_size = sizeof(struct ipv6_fib_info),
		.offset = 128,
	};

	/* Create LPMv6 tables */
	lpm6_table =
			rte_table_lpm_ipv6_ops.f_create(&lpm6_params, rte_socket_id(),
							sizeof(struct ipv6_fib_info));
	if (lpm6_table == NULL) {
		printf("Failed to create LPM IPV6 table\n");
		return 0;
	}

	/*Initialize IPv6 params for l2 Adj  */
	struct rte_hash_parameters l2_adj_ipv6_params = {
		.name = "l2_ADJ_IPV6_HASH",
		.entries = 64,
		.key_len = sizeof(struct l2_adj_key_ipv6),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
	};

	l2_adj_ipv6_hash_handle = rte_hash_create(&l2_adj_ipv6_params);
	if (l2_adj_ipv6_hash_handle == NULL) {
		printf("ND for IPV6 rte_hash_create failed.\n");
		return 0;
	} else {
		printf("ND IPV6_hash_handle %p\n\n",
					 (void *)l2_adj_ipv6_hash_handle);
	}

	/*Initialize Fib PAth hassh params  */
	struct rte_hash_parameters fib_path_ipv6_params = {
		.name = "FIB_PATH_IPV6_HASH",
		.entries = 64,
		.key_len = sizeof(struct fib_path_key_ipv6),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.extra_flag = 1,
	};

	/* Create FIB PATH Hash tables */
	fib_path_ipv6_hash_handle = rte_hash_create(&fib_path_ipv6_params);

	if (fib_path_ipv6_hash_handle == NULL) {
		printf("FIB path rte_hash_create failed\n");
		return 0;
	}
	return 1;
}

int lpm6_table_route_add(struct ipv6_routing_info *data)
{

	struct ipv6_routing_info *fib = data;
	/* Populate the Key */
	struct rte_table_lpm_ipv6_key lpm6_key;
	uint8_t i;
	for (i = 0; i < 16; i++) {
		lpm6_key.ip[i] = fib->dst_ipv6[i];
	}
	lpm6_key.depth = fib->depth;

	static int Total_route_count;
	struct ipv6_fib_info entry;
	for (i = 0; i < 16; i++) {
		entry.dst_ipv6[i] = fib->dst_ipv6[i];
	}
	entry.depth = fib->depth;
	entry.fib_nh_size = fib->fib_nh_size;

#if MULTIPATH_FEAT
	if (entry.fib_nh_size == 0 || entry.fib_nh_size > MAX_FIB_PATHS)
#else
	if (entry.fib_nh_size != 1)	/**< For Single FIB_PATH */
#endif
	{
		printf
				("Route's can't be configured!!, entry.fib_nh_size = %d\n",
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
		struct ipv6_fib_path *ipv6_fib_path_addr = NULL;
		ipv6_fib_path_addr =
				populate_ipv6_fib_path(fib->nh_ipv6[i], fib->out_port[i]);

		if (ipv6_fib_path_addr) {
			entry.path[i] = ipv6_fib_path_addr;
			printf("Fib path for IPv6 destination = "
						 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:"
						 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x/%u) ==> fib_path Addr :%p, L2_adj Addr ;%p\n",
						 lpm6_key.ip[0], lpm6_key.ip[1], lpm6_key.ip[2],
						 lpm6_key.ip[3], lpm6_key.ip[4], lpm6_key.ip[5],
						 lpm6_key.ip[6], lpm6_key.ip[7], lpm6_key.ip[8],
						 lpm6_key.ip[9], lpm6_key.ip[10], lpm6_key.ip[11],
						 lpm6_key.ip[12], lpm6_key.ip[13],
						 lpm6_key.ip[14], lpm6_key.ip[15], fib->depth,
						 ipv6_fib_path_addr,
						 (void *)entry.path[i]->l2_adj_ipv6_ptr);
		} else {
			printf("Fib path for IPv6 destination = "
						 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:"
						 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x/%u) ==> fib_path Addr : NULL\n",
						 lpm6_key.ip[0], lpm6_key.ip[1], lpm6_key.ip[2],
						 lpm6_key.ip[3], lpm6_key.ip[4], lpm6_key.ip[5],
						 lpm6_key.ip[6], lpm6_key.ip[7], lpm6_key.ip[8],
						 lpm6_key.ip[9], lpm6_key.ip[10], lpm6_key.ip[11],
						 lpm6_key.ip[12], lpm6_key.ip[13],
						 lpm6_key.ip[14], lpm6_key.ip[15], fib->depth);
			entry.path[i] = NULL;	/**< setting all other fib_paths to NULL */
		}
	}

	int key_found, ret;
	void *entry_ptr;

	/* Adding a IP route in LPMv6 table */
	printf("%s, Line %u \n", __FUNCTION__, __LINE__);

	ret =
			rte_table_lpm_ipv6_ops.f_add(lpm6_table, (void *)&lpm6_key, &entry,
					 &key_found, &entry_ptr);
	printf("%s, Line %u \n", __FUNCTION__, __LINE__);

	if (ret) {
		printf("Failed to Add IP route in LPMv6\n");
		return 0;
	}
	printf("Added route to IPv6 LPM table (IPv6 destination = "
				 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:"
				 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x/%u)\n",
				 lpm6_key.ip[0], lpm6_key.ip[1], lpm6_key.ip[2], lpm6_key.ip[3],
				 lpm6_key.ip[4], lpm6_key.ip[5], lpm6_key.ip[6], lpm6_key.ip[7],
				 lpm6_key.ip[8], lpm6_key.ip[9], lpm6_key.ip[10], lpm6_key.ip[11],
				 lpm6_key.ip[12], lpm6_key.ip[13], lpm6_key.ip[14],
				 lpm6_key.ip[15], fib->depth);

	Total_route_count++;
	printf("Total Routed Added : %u, Key_found: %d\n", Total_route_count,
				 key_found);

	if (Total_route_count == 2)
		ipv6_iterate__hash_table();

	return 1;
}

int
lpm6_table_route_delete(uint8_t dst_ipv6[RTE_LPM_IPV6_ADDR_SIZE], uint8_t depth)
{

	/* Populate the Key */
	struct rte_table_lpm_ipv6_key lpm6_key;
	memcpy(&lpm6_key.ip, &dst_ipv6, sizeof(RTE_LPM_IPV6_ADDR_SIZE));
	lpm6_key.depth = depth;
	int key_found, ret;
	char *entry = NULL;
	entry = rte_zmalloc(NULL, 512, RTE_CACHE_LINE_SIZE);
	/* Delete a IP route in LPMv6 table */
	ret =
			rte_table_lpm_ipv6_ops.f_delete(lpm6_table, &lpm6_key, &key_found,
							entry);

	if (ret) {
		printf("Failed to Delete IP route from LPMv6 table\n");
		return 0;
	}

	printf("Deleted route from IPv6 LPM table (IPv6 destination = "
				 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:"
				 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x/%u, key_found = %d\n",
				 lpm6_key.ip[0], lpm6_key.ip[1], lpm6_key.ip[2], lpm6_key.ip[3],
				 lpm6_key.ip[4], lpm6_key.ip[5], lpm6_key.ip[6], lpm6_key.ip[7],
				 lpm6_key.ip[8], lpm6_key.ip[9], lpm6_key.ip[10], lpm6_key.ip[11],
				 lpm6_key.ip[12], lpm6_key.ip[13], lpm6_key.ip[14],
				 lpm6_key.ip[15], lpm6_key.depth, key_found);

	/* Deleting a L2 Adj entry if refcount is 1, Else decrement Refcount */
	remove_ipv6_fib_l2_adj_entry(entry);
	rte_free(entry);	// free memory
	return 1;
}

int
lpm6_table_lookup(struct rte_mbuf **pkts_burst,
			uint16_t nb_pkts,
			uint64_t pkts_mask,
			l2_phy_interface_t *port_ptr[RTE_PORT_IN_BURST_SIZE_MAX],
			uint64_t *hit_mask)
{
	struct ipv6_routing_table_entry
			*ipv6_entries[RTE_PORT_IN_BURST_SIZE_MAX];
	uint64_t lookup_hit_mask_ipv6 = 0;
	int status;
	uint64_t lookup_miss_mask = pkts_mask;
	/*Populate the key offset in META DATA */
	uint32_t dst_addr_offset =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST_IPV6;
	uint64_t pkts_key_mask = pkts_mask;

	//for(i = 0; i < RTE_PORT_IN_BURST_SIZE_MAX; i++)
	for (; pkts_key_mask;) {
/**< Populate key offset in META DATA for all valid pkts */
		uint8_t pos = (uint8_t) __builtin_ctzll(pkts_key_mask);
		uint64_t pkt_mask = 1LLU << pos;
		pkts_key_mask &= ~pkt_mask;

		uint8_t *lpm6_key;
		uint8_t dst_addr[RTE_LPM_IPV6_ADDR_SIZE];
		memcpy(dst_addr,
					 (uint8_t *) RTE_MBUF_METADATA_UINT32_PTR(pkts_burst[pos],
								dst_addr_offset),
					 RTE_LPM_IPV6_ADDR_SIZE);
		lpm6_key =
				(uint8_t *) RTE_MBUF_METADATA_UINT8_PTR(pkts_burst[pos],
									128);
		memcpy(lpm6_key, dst_addr, RTE_LPM_IPV6_ADDR_SIZE);
	}
	/* Lookup for IP route in LPM6 table */
	printf(" IPV6 Lookup Mask Before = %p, nb_pkts :%u\n",
				 (void *)pkts_mask, nb_pkts);
	status =
			rte_table_lpm_ops.f_lookup(lpm6_table, pkts_burst, pkts_mask,
							 &lookup_hit_mask_ipv6,
							 (void **)ipv6_entries);
	if (status) {
		printf("LPM Lookup failed for IP route\n");
		return 0;
	}
	printf(" IPV6 Lookup Mask After = %p\n", (void *)lookup_hit_mask_ipv6);
	lookup_miss_mask = lookup_miss_mask & (~lookup_hit_mask_ipv6);
	if (L3FWD_DEBUG) {
		printf("AFTER lookup_hit_mask = %p, lookup_miss_mask =%p\n",
					 (void *)lookup_hit_mask_ipv6, (void *)lookup_miss_mask);
	}

	for (; lookup_miss_mask;) {
/**< Drop packets for lookup_miss_mask */
		uint8_t pos = (uint8_t) __builtin_ctzll(lookup_miss_mask);
		uint64_t pkt_mask = 1LLU << pos;
		lookup_miss_mask &= ~pkt_mask;
		rte_pktmbuf_free(pkts_burst[pos]);
		pkts_burst[pos] = NULL;
		if (L3FWD_DEBUG)
			printf("\n DROP PKT IPV4 Lookup_miss_Mask  = %p\n",
						 (void *)lookup_miss_mask);

	}
	*hit_mask = lookup_hit_mask_ipv6;
	for (; lookup_hit_mask_ipv6;) {
		uint8_t pos = (uint8_t) __builtin_ctzll(lookup_hit_mask_ipv6);
		uint64_t pkt_mask = 1LLU << pos;
		lookup_hit_mask_ipv6 &= ~pkt_mask;
		struct rte_mbuf *pkt = pkts_burst[pos];

		struct ipv6_fib_info *entry =
				(struct ipv6_fib_info *)ipv6_entries[pos];

#if MULTIPATH_FEAT

		uint8_t ecmp_path = ipv6_hash_load_balance(pkts_burst[pos]);
		uint8_t selected_path = 0;
		struct ipv6_fib_path *fib_path = NULL;
		if (((entry->fib_nh_size != 0)
				 && (entry->fib_nh_size - 1) < MAX_SUPPORTED_FIB_PATHS)
				&& ((ecmp_path != 0) && (ecmp_path - 1) < HASH_BUCKET_SIZE))
			selected_path =
					nh_links[entry->fib_nh_size - 1][ecmp_path - 1];
		if (selected_path < MAX_FIB_PATHS)
			fib_path = entry->path[selected_path];
		printf
				("Total supported Path :%u, Hashed ECMP Key : %u, selected Fib_path: %u\n",
				 entry->fib_nh_size, ecmp_path, selected_path);
#else
		struct ipv6_fib_path *fib_path = entry->path[0];
#endif
		if (fib_path == NULL) {
			printf("Fib_path is NULL, ND has not resolved\n");
			rte_pktmbuf_free(pkt);
			pkts_burst[pos] = NULL;
			stats.nb_l3_drop_pkt++;	 /**< Peg the L3 Drop counter */
			*hit_mask &= ~pkt_mask;	/**< Remove this pkt from port Mask */
			printf
					("Fib_path is NULL, ND has not resolved, DROPPED UNKNOWN PKT\n");
			continue;
		}

		if (fib_path->l2_adj_ipv6_ptr->flags == L2_ADJ_UNRESOLVED) {
			rte_pktmbuf_free(pkts_burst[pos]);
			pkts_burst[pos] = NULL;
			*hit_mask &= ~pkt_mask;	/**< Remove this pkt from port Mask */
			if (L3FWD_DEBUG)
				printf
						("L2_ADJ_UNRESOLVED, DROPPED UNKNOWN PKT\n");
			continue;
		}

		uint8_t *eth_dest =
				RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
		uint8_t *eth_src =
				RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM + 6);
		if (L3FWD_DEBUG) {
			printf
				("MAC BEFORE- DST MAC %02x:%02x:%02x:%02x"
				 ":%02x:%02x, "
				 "SRC MAC %02x:%02x:%02x:%02x:"
				 "%02x:%02x \n",
				 eth_dest[0], eth_dest[1], eth_dest[2],
				 eth_dest[3],
				 eth_dest[4], eth_dest[5], eth_src[0],
				 eth_src[1],
				 eth_src[2], eth_src[3],
				 eth_src[4], eth_src[5]);
		}

		/* Rewrite the packet with L2 string  */
		memcpy(eth_dest, fib_path->l2_adj_ipv6_ptr->l2_string,
					 sizeof(struct ether_addr) * 2 + 2);

		if (L3FWD_DEBUG) {
			printf
				("MAC AFTER DST MAC %02x:%02x:%02x:%02x:%02x:%02x,"
				 "SRC MAC %02x:%02x:%02x:%02x:"
				 "%02x:%02x\n", eth_dest[0],
				 eth_dest[1], eth_dest[2], eth_dest[3],
				 eth_dest[4],
				 eth_dest[5], eth_src[0], eth_src[1],
				 eth_src[2],
				 eth_src[3], eth_src[4], eth_src[5]);
		}
		port_ptr[pos] = fib_path->l2_adj_ipv6_ptr->phy_port;

		//fib_path->l2_adj_ipv6_ptr->phy_port->transmit_single_pkt(fib_path->l2_adj_ipv6_ptr->phy_port, pkt);
		if (L3FWD_DEBUG)
			printf("Successfully sent to port %u \n\r",
						 fib_path->out_port);
	}
	return 1;
}

void l3fwd_rx_ipv6_packets(struct rte_mbuf **m, uint16_t nb_pkts,
				 uint64_t valid_pkts_mask, l2_phy_interface_t *port)
{
	if (!port)
		return;
	if (L3FWD_DEBUG) {
		printf
				("l3fwd_rx_ipv6_packets_received BEFORE DROP: nb_pkts: %u, from in_port %u, valid_pkts_mask:%"
				 PRIu64 "\n", nb_pkts, port->pmdid, valid_pkts_mask);
	}
	uint64_t pkts_for_process = valid_pkts_mask;

	struct ipv6_hdr *ipv6_hdr;
	//struct ether_hdr *eth_h;
	uint64_t icmp_pkts_mask = valid_pkts_mask;
	uint64_t ipv6_forward_pkts_mask = valid_pkts_mask;
	uint16_t nb_icmpv6_pkt = 0;
	uint16_t nb_l3_pkt = 0;

	uint8_t configured_port_ipv6[RTE_LPM_IPV6_ADDR_SIZE] = { 0 };
	int8_t solicited_node_multicast_addr[RTE_LPM_IPV6_ADDR_SIZE] = {
		0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0xff, 0x00, 0x00, 0x00 };
	uint8_t dest_ipv6_addr[RTE_LPM_IPV6_ADDR_SIZE];

	memset(dest_ipv6_addr, 0, RTE_LPM_IPV6_ADDR_SIZE);

	printf("\n%s : LINE # %u\n", __FUNCTION__, __LINE__);
	int ii;
	if (port->ipv6_list != NULL) {
		for (ii = 0; ii < 16; ii += 1) {
			configured_port_ipv6[ii] =
					((ipv6list_t *) (port->ipv6_list))->ipaddr[ii];
		}
	}
	//      memcpy(&configured_port_ipv6, &(((ipv6list_t*)(port->ipv6_list))->ipaddr), RTE_LPM_IPV6_ADDR_SIZE);

	for (ii = 0; ii < 16; ii += 2) {
		if (port && port->ipv6_list)
			printf("%02X%02X ",
						 ((ipv6list_t *) (port->ipv6_list))->ipaddr[ii],
						 ((ipv6list_t *) (port->ipv6_list))->ipaddr[ii +
										1]);
	}

	printf("\n%s : LINE # %u\n", __FUNCTION__, __LINE__);
	for (ii = 0; ii < 16; ii += 2) {
		printf("%02X%02X ", configured_port_ipv6[ii],
					 configured_port_ipv6[ii + 1]);
	}

	for (; pkts_for_process;) {
/**< process only valid packets.*/
		printf("\n%s : LINE # %u\n", __FUNCTION__, __LINE__);
		uint8_t pos = (uint8_t) __builtin_ctzll(pkts_for_process);
		uint64_t pkt_mask = 1LLU << pos;    /**< bitmask representing only this packet */
		pkts_for_process &= ~pkt_mask;			/**< remove this packet from the mask */
		//printf("\n%s : LINE # %u\n", __FUNCTION__, __LINE__);
		//eth_h = rte_pktmbuf_mtod(m[pos], struct ether_hdr *);
		printf("\n%s : LINE #%u,  POS%u\n", __FUNCTION__, __LINE__,
					 pos);
		//ipv6_hdr = (struct ipv6_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
		if (m[pos] == NULL) {
			printf("\n%s : M_POS IS NULLLLLLL, LINE: %u\n",
						 __FUNCTION__, __LINE__);
			return;
		}
		ipv6_hdr =
				rte_pktmbuf_mtod_offset(m[pos], struct ipv6_hdr *,
							sizeof(struct ether_hdr));
		printf("\n%s : LINE # %u\n", __FUNCTION__, __LINE__);
		for (ii = 0; ii < 13; ii += 1) {
			dest_ipv6_addr[ii] = ipv6_hdr->dst_addr[ii];
		}

		printf("\n");
		printf("\n%s : LINE # %u\n", __FUNCTION__, __LINE__);
		for (ii = 0; ii < 16; ii += 2) {
			printf("%02X%02X ", ipv6_hdr->dst_addr[ii],
						 ipv6_hdr->dst_addr[ii + 1]);
		}
		printf("\n");
		printf("\n%s : LINE # %u\n", __FUNCTION__, __LINE__);
		for (ii = 0; ii < 16; ii += 2) {
			printf("%02X%02X ", dest_ipv6_addr[ii],
						 dest_ipv6_addr[ii + 1]);
		}

		printf("\n%s : LINE # %u", __FUNCTION__, __LINE__);
		if ((ipv6_hdr->proto == IPPROTO_ICMPV6) &&
				(!memcmp
				 (&ipv6_hdr->dst_addr, &configured_port_ipv6[0],
					RTE_LPM_IPV6_ADDR_SIZE)
				 || !memcmp(&dest_ipv6_addr[0],
				&solicited_node_multicast_addr[0],
				RTE_LPM_IPV6_ADDR_SIZE))) {
			ipv6_forward_pkts_mask &= ~pkt_mask;  /**< Its  ICMP, remove this packet from the ipv6_forward_pkts_mask*/
			stats.nb_rx_l3_icmp_pkt++;   /**< Increment stats for ICMP PKT */
			nb_icmpv6_pkt++;
		} else{		// Forward the packet
			icmp_pkts_mask &= ~pkt_mask;   /**< Not ICMP, remove this packet from the icmp_pkts_mask*/
			stats.nb_rx_l3_pkt++;
			nb_l3_pkt++;	 /**< Increment stats for L3 PKT */
		}
	}

	if (icmp_pkts_mask) {
		if (L3FWD_DEBUG)
			printf
					("\n RECEiVED LOCAL ICMP PKT at L3...\n PROCESSING ICMP LOCAL PKT...\n");
		proto_type[IP_LOCAL]->func(m, nb_icmpv6_pkt, icmp_pkts_mask,
						 port);
	}

	if (ipv6_forward_pkts_mask) {
		if (L3FWD_DEBUG)
			printf
					("\n RECEIVED L3 PKT, \n\n FORWARDING L3 PKT....\n");
		proto_type[IP_REMOTE]->func(m, nb_l3_pkt,
							ipv6_forward_pkts_mask, port);
	}
}

struct ipv6_fib_path *populate_ipv6_fib_path(uint8_t
							 nh_ipv6[RTE_LPM_IPV6_ADDR_SIZE],
							 uint8_t portid)
{

	struct fib_path_key_ipv6 path_key;
	uint8_t i;
	for (i = 0; i < 16; i++) {
		path_key.nh_ipv6[i] = nh_ipv6[i];
	}
	path_key.out_port = portid;
	path_key.filler1 = 0;
	path_key.filler2 = 0;
	path_key.filler3 = 0;

	struct ipv6_fib_path *fib_data = NULL;
	/* Populate fib_path if it is present in FIB_PATH cuckoo HAsh Table */
	fib_data = retrieve_ipv6_fib_path_entry(path_key);

	if (fib_data) {

		printf(" Fib path entry exists for IPv6 destination = "
					 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:"
					 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x and out port :%u\n",
					 nh_ipv6[0], nh_ipv6[1], nh_ipv6[2], nh_ipv6[3],
					 nh_ipv6[4], nh_ipv6[5], nh_ipv6[6], nh_ipv6[7],
					 nh_ipv6[8], nh_ipv6[9], nh_ipv6[10], nh_ipv6[11],
					 nh_ipv6[12], nh_ipv6[13], nh_ipv6[14], nh_ipv6[15],
					 portid);

		fib_data->refcount++;
		return fib_data;	// Entry Exists. Return True (1)
	} else {
		printf("IPv6 fib_path entry Doesn't Exists.......\n");
	}

	/* populate L2 Adj */
	fib_data = NULL;
	struct l2_adj_ipv6_entry *l2_adj_ptr = NULL;
	l2_adj_ptr = populate_ipv6_l2_adj(nh_ipv6, portid);

	if (l2_adj_ptr) {

		uint32_t size =
				RTE_CACHE_LINE_ROUNDUP(sizeof(struct ipv6_fib_path));
		fib_data = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);

		for (i = 0; i < 16; i++) {
			fib_data->nh_ipv6[i] = nh_ipv6[i];
		}
		fib_data->out_port = portid;
		//memcpy(fib_data->nh_ipv6, &nh_ipv6, RTE_LPM_IPV6_ADDR_SIZE);

		fib_data->refcount++;
		fib_data->l2_adj_ipv6_ptr = l2_adj_ptr;

		/* Store the received MAC Address in L2 Adj HAsh Table */
		rte_hash_add_key_data(fib_path_ipv6_hash_handle, &path_key,
							fib_data);
		printf
				(" ND resolution success l2_adj_entry %p\n, ipv6_fib_path_addr %p",
				 l2_adj_ptr, fib_data);
		return fib_data;
	} else {
		printf
				("ND resolution failed and unable to write fib path in fib_path cuckoo hash\n");
	}
	return NULL;

}

struct l2_adj_ipv6_entry *populate_ipv6_l2_adj(uint8_t
								 nh_ipv6[RTE_LPM_IPV6_ADDR_SIZE],
								 uint8_t portid)
{

	struct l2_adj_key_ipv6 l2_adj_key;
	uint8_t i;
	for (i = 0; i < 16; i++) {
		l2_adj_key.nh_ipv6[i] = nh_ipv6[i];
	}
	l2_adj_key.out_port_id = portid;
	l2_adj_key.filler1 = 0;
	l2_adj_key.filler2 = 0;
	l2_adj_key.filler3 = 0;

	struct l2_adj_ipv6_entry *adj_data = NULL;
	struct ether_addr eth_dst;
	/* Populate L2 adj if the MAC Address is present in L2 Adj HAsh Table */
	adj_data = retrieve_ipv6_l2_adj_entry(l2_adj_key);

	if (adj_data) {

		printf("ipv6_l2_adj_entry exists for Next Hop IPv6 = "
					 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:"
					 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x and out port :%u\n",
					 nh_ipv6[0], nh_ipv6[1], nh_ipv6[2], nh_ipv6[3],
					 nh_ipv6[4], nh_ipv6[5], nh_ipv6[6], nh_ipv6[7],
					 nh_ipv6[8], nh_ipv6[9], nh_ipv6[10], nh_ipv6[11],
					 nh_ipv6[12], nh_ipv6[13], nh_ipv6[14], nh_ipv6[15],
					 portid);

		ether_addr_copy(&adj_data->eth_addr, &eth_dst);
		adj_data->refcount++;
		return adj_data;	// Entry Exists. Return True (1)
	}

	struct ether_addr eth_src;
	uint16_t ether_type = 0x086DD;
	l2_phy_interface_t *port;
	port = ifm_get_port(portid);
	if (port == NULL) {
		printf("PORT %u IS DOWN.. Unable to process !\n", portid);
		return NULL;
	}

	memcpy(&eth_src, &port->macaddr, sizeof(struct ether_addr));
	uint32_t size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct l2_adj_entry));
	adj_data = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
	if (adj_data == NULL) {
		printf("L2 Adjacency memory allocation failed !\n");
		return NULL;
	}

	adj_data->out_port_id = portid;
	//memcpy(adj_data->nh_ipv6, &nh_ipv6, RTE_LPM_IPV6_ADDR_SIZE);
	for (i = 0; i < 16; i++) {
		adj_data->nh_ipv6[i] = nh_ipv6[i];
	}
	adj_data->refcount++;
	adj_data->phy_port = port;

	rte_hash_add_key_data(l2_adj_ipv6_hash_handle, &l2_adj_key, adj_data);

	/* Query ND to get L2 Adj */
	if (get_dest_mac_for_nexthop_ipv6(nh_ipv6, portid, &eth_dst)) {
		/* Store the received MAC Address in L2 Adj HAsh Table */
		ether_addr_copy(&eth_dst, &adj_data->eth_addr);

		/* Precompute the L2 string encapsulation */
		memcpy(&adj_data->l2_string, &eth_dst,
					 sizeof(struct ether_addr));
		memcpy(&adj_data->l2_string[6], &eth_src,
					 sizeof(struct ether_addr));
		memcpy(&adj_data->l2_string[12], &ether_type, 2);

		adj_data->flags = L2_ADJ_RESOLVED;
		printf
				(" ND resolution successful and stored in ipv6_l2_adj_entry %p\n",
				 adj_data);

		return adj_data;
	} else {
		adj_data->flags = L2_ADJ_UNRESOLVED;
		printf
				("ND resolution failed and unable to write in ipv6_l2_adj_entry\n");
	}
	return NULL;
}

struct l2_adj_ipv6_entry *retrieve_ipv6_l2_adj_entry(struct l2_adj_key_ipv6
								 l2_adj_key)
{
	struct l2_adj_ipv6_entry *ret_l2_adj_data = NULL;

	int ret =
			rte_hash_lookup_data(l2_adj_ipv6_hash_handle, &l2_adj_key,
				 (void **)&ret_l2_adj_data);
	if (ret < 0) {
		printf
				("L2 Adj hash lookup failed ret %d, EINVAL %d, ENOENT %d\n",
				 ret, EINVAL, ENOENT);
	} else {
		printf("L2 Adj hash lookup Successful..!!!\n");
		return ret_l2_adj_data;
	}
	return NULL;
}

int get_dest_mac_for_nexthop_ipv6(uint8_t nh_ipv6[RTE_LPM_IPV6_ADDR_SIZE],
					uint32_t out_phy_port,
					struct ether_addr *hw_addr)
{
	struct nd_entry_data *nd_data = NULL;
	struct nd_key_ipv6 tmp_nd_key;
	uint8_t i;
	for (i = 0; i < 16; i++) {
		tmp_nd_key.ipv6[i] = nh_ipv6[i];
	}
	tmp_nd_key.port_id = out_phy_port;

	nd_data = retrieve_nd_entry(tmp_nd_key, DYNAMIC_ND);
	if (nd_data == NULL) {
		printf("ND entry is not found\n");
		return 0;
	}
	ether_addr_copy(&nd_data->eth_addr, hw_addr);

	return 1;
}

struct ipv6_fib_path *retrieve_ipv6_fib_path_entry(struct fib_path_key_ipv6
							 path_key)
{

	struct ipv6_fib_path *ret_fib_path_data = NULL;
	int ret =
			rte_hash_lookup_data(fib_path_ipv6_hash_handle, &path_key,
				 (void **)&ret_fib_path_data);
	if (ret < 0) {
		printf
				("FIB Path Adj hash lookup failed ret %d, EINVAL %d, ENOENT %d\n",
				 ret, EINVAL, ENOENT);
		return NULL;
	} else {
		return ret_fib_path_data;
	}
}

void remove_ipv6_fib_l2_adj_entry(void *entry)
{
	struct ipv6_fib_info entry1;
	memcpy(&entry1, entry, sizeof(struct ipv6_fib_info));

	struct ipv6_fib_path *fib_path_addr = entry1.path[0];	//fib_info->path[0];
	if (fib_path_addr->refcount > 1) {
		printf("BEFORE fib_path entry is not Removed! nh_iPv6 = "
					 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:"
					 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x and out port :%u, refcount :%d\n",
					 fib_path_addr->nh_ipv6[0], fib_path_addr->nh_ipv6[1],
					 fib_path_addr->nh_ipv6[2], fib_path_addr->nh_ipv6[3],
					 fib_path_addr->nh_ipv6[4], fib_path_addr->nh_ipv6[5],
					 fib_path_addr->nh_ipv6[6], fib_path_addr->nh_ipv6[7],
					 fib_path_addr->nh_ipv6[8], fib_path_addr->nh_ipv6[9],
					 fib_path_addr->nh_ipv6[10], fib_path_addr->nh_ipv6[11],
					 fib_path_addr->nh_ipv6[12], fib_path_addr->nh_ipv6[13],
					 fib_path_addr->nh_ipv6[14], fib_path_addr->nh_ipv6[15],
					 fib_path_addr->out_port, fib_path_addr->refcount);
		fib_path_addr->refcount--;	// Just decrement the refcount this entry is still referred
		printf("AFTER fib_path entry is not Removed! nh_iPv6 = "
					 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:"
					 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x and out port :%u, refcount :%d\n",
					 fib_path_addr->nh_ipv6[0], fib_path_addr->nh_ipv6[1],
					 fib_path_addr->nh_ipv6[2], fib_path_addr->nh_ipv6[3],
					 fib_path_addr->nh_ipv6[4], fib_path_addr->nh_ipv6[5],
					 fib_path_addr->nh_ipv6[6], fib_path_addr->nh_ipv6[7],
					 fib_path_addr->nh_ipv6[8], fib_path_addr->nh_ipv6[9],
					 fib_path_addr->nh_ipv6[10], fib_path_addr->nh_ipv6[11],
					 fib_path_addr->nh_ipv6[12], fib_path_addr->nh_ipv6[13],
					 fib_path_addr->nh_ipv6[14], fib_path_addr->nh_ipv6[15],
					 fib_path_addr->out_port, fib_path_addr->refcount);
	} else {			// Refcount is 1 so delete both fib_path and l2_adj_entry

		struct l2_adj_ipv6_entry *adj_addr = NULL;
		adj_addr = fib_path_addr->l2_adj_ipv6_ptr;

		if (adj_addr != NULL) {	//l2_adj_entry is has some entry in hash table
			printf("%s: CHECK   %d\n\r", __FUNCTION__, __LINE__);
			struct l2_adj_key_ipv6 l2_adj_key;
			memcpy(&l2_adj_key.nh_ipv6, fib_path_addr->nh_ipv6,
						 RTE_LPM_IPV6_ADDR_SIZE);
			l2_adj_key.out_port_id =
					fib_path_addr->out_port,
					rte_hash_del_key(l2_adj_ipv6_hash_handle,
							 &l2_adj_key);
			rte_free(adj_addr);	// free memory
			adj_addr = NULL;
		}

		struct fib_path_key_ipv6 path_key;
		memcpy(&path_key.nh_ipv6, fib_path_addr->nh_ipv6,
					 RTE_LPM_IPV6_ADDR_SIZE);
		path_key.out_port = fib_path_addr->out_port;
		rte_hash_del_key(fib_path_ipv6_hash_handle, &path_key);
		rte_free(fib_path_addr);	//Free the memory
		fib_path_addr = NULL;
	}
}

int is_valid_ipv6_pkt(struct ipv6_hdr *pkt, uint32_t link_len)
{
	if (link_len < sizeof(struct ipv4_hdr))
		return -1;
	if (rte_cpu_to_be_16(pkt->payload_len) < sizeof(struct ipv6_hdr))
		return -1;

	return 0;
}

void
ipv6_l3_protocol_type_add(uint8_t protocol_type,
				void (*func) (struct rte_mbuf **, uint16_t, uint64_t,
					l2_phy_interface_t *))
{
	switch (protocol_type) {
	case IPPROTO_ICMPV6:
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

void
ipv6_local_deliver(struct rte_mbuf **pkt_burst, __rte_unused uint16_t nb_rx,
			 uint64_t icmp_pkt_mask, l2_phy_interface_t *port)
{
	for (; icmp_pkt_mask;) {
/**< process only valid packets.*/
		uint8_t pos = (uint8_t) __builtin_ctzll(icmp_pkt_mask);
		uint64_t pkt_mask = 1LLU << pos;   /**< bitmask representing only this packet */
		icmp_pkt_mask &= ~pkt_mask;	/**< remove this packet from the mask */

		process_icmpv6_pkt(pkt_burst[pos], port);
	}
}

void
ipv6_forward_deliver(struct rte_mbuf **pkt_burst, uint16_t nb_pkts,
				 uint64_t ipv6_forward_pkts_mask, l2_phy_interface_t *port)
{
	if (L3FWD_DEBUG) {
		printf
				("ip_forward_deliver BEFORE DROP: nb_pkts: %u\n from in_port %u",
				 nb_pkts, port->pmdid);
	}
	uint64_t pkts_for_process = ipv6_forward_pkts_mask;

	struct ipv6_hdr *ipv6_hdr;
	l2_phy_interface_t *port_ptr[RTE_PORT_IN_BURST_SIZE_MAX];
	uint64_t hit_mask = 0;

	for (; pkts_for_process;) {
/**< process only valid packets.*/
		uint8_t pos = (uint8_t) __builtin_ctzll(pkts_for_process);
		uint64_t pkt_mask = 1LLU << pos;   /**< bitmask representing only this packet */
		pkts_for_process &= ~pkt_mask;		 /**< remove this packet from the mask */
		ipv6_hdr =
				rte_pktmbuf_mtod_offset(pkt_burst[pos], struct ipv6_hdr *,
							sizeof(struct ether_hdr));
		/* Make sure the IPv4 packet is valid  */

		if (is_valid_ipv6_pkt(ipv6_hdr, pkt_burst[pos]->pkt_len) < 0) {
			rte_pktmbuf_free(pkt_burst[pos]);   /**< Drop the Unknown IPv4 Packet */
			pkt_burst[pos] = NULL;
			ipv6_forward_pkts_mask &= ~(1LLU << pos);  /**< That will clear bit of that position*/
			nb_pkts--;
			stats.nb_l3_drop_pkt++;
		}
	}

	if (L3FWD_DEBUG) {
		printf
				("\nl3fwd_rx_ipv4_packets_received AFTER DROP: nb_pkts: %u, valid_Pkts_mask :%lu\n",
				 nb_pkts, ipv6_forward_pkts_mask);
	}

	/* Lookup for IP destination in LPMv4 table */
	lpm6_table_lookup(pkt_burst, nb_pkts, ipv6_forward_pkts_mask, port_ptr,
				&hit_mask);
}

uint8_t ipv6_hash_load_balance(struct rte_mbuf *mbuf)
{
	uint32_t src_addr_offset =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_SRC_ADR_OFST_IPV6;
	uint32_t dst_addr_offset =
			MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST_IPV6;
	uint8_t src_addr[RTE_LPM_IPV6_ADDR_SIZE];
	uint8_t dst_addr[RTE_LPM_IPV6_ADDR_SIZE];

	memcpy(&src_addr,
				 (uint8_t *) RTE_MBUF_METADATA_UINT32_PTR(mbuf, src_addr_offset),
				 RTE_LPM_IPV6_ADDR_SIZE);
	memcpy(&dst_addr,
				 (uint8_t *) RTE_MBUF_METADATA_UINT32_PTR(mbuf, dst_addr_offset),
				 RTE_LPM_IPV6_ADDR_SIZE);
	uint32_t hash_key1 = 0;	/* STORE Accumulated value of SRC IP in key1 variable */
	uint32_t hash_key2 = 0;	/* STORE Accumulated value of DST IP in key2 variable */
	uint8_t i;
	for (i = 0; i < RTE_LPM_IPV6_ADDR_SIZE; i++) {
		hash_key1 += src_addr[i];	/* Accumulate */
		hash_key2 += dst_addr[i];	/* Accumulate */
	}
	hash_key1 = hash_key1 ^ hash_key2;	/* XOR With SRC and DST IP, Result is hask_key1 */
	hash_key2 = hash_key1;	/* MOVE The result to hask_key2 */
	hash_key1 = rotr32(hash_key1, RTE_LPM_IPV6_ADDR_SIZE);	/* Circular Rotate to 16 bit */
	hash_key1 = hash_key1 ^ hash_key2;	/* XOR With Key1 with Key2 */

	hash_key2 = hash_key1;	/* MOVE The result to hask_key2 */

	hash_key1 = rotr32(hash_key1, 8);	/* Circular Rotate to 8 bit */
	hash_key1 = hash_key1 ^ hash_key2;	/* XOR With Key1 with Key2 */

	hash_key1 = hash_key1 & (HASH_BUCKET_SIZE - 1);	/* MASK the KEY with BUCKET SIZE */
	if (L3FWD_DEBUG)
		printf("Hash Result_key: %d, \n", hash_key1);
	return hash_key1;
}

void
resolve_ipv6_l2_adj(uint8_t nh_ipv6[RTE_LPM_IPV6_ADDR_SIZE], uint8_t portid,
				struct ether_addr *hw_addr)
{
	struct l2_adj_ipv6_entry *adj_data = NULL;
	struct ether_addr eth_dst;
	uint16_t ether_type = 0x086DD;

	struct l2_adj_key_ipv6 l2_adj_key;
	memcpy(&l2_adj_key.nh_ipv6, &nh_ipv6, RTE_LPM_IPV6_ADDR_SIZE);
	l2_adj_key.out_port_id = portid;

	adj_data = retrieve_ipv6_l2_adj_entry(l2_adj_key);
	if (adj_data) {
		if (adj_data->flags == L2_ADJ_UNRESOLVED
				|| memcmp(&adj_data->eth_addr, hw_addr, 6)) {
			ether_addr_copy(hw_addr, &adj_data->eth_addr);

			/* Precompute the L2 string encapsulation */
			memcpy(&adj_data->l2_string, hw_addr,
						 sizeof(struct ether_addr));
			memcpy(&adj_data->l2_string[6],
						 &adj_data->phy_port->macaddr,
						 sizeof(struct ether_addr));
			memcpy(&adj_data->l2_string[12], &ether_type, 2);

			adj_data->flags = L2_ADJ_RESOLVED;
		}

		return;
	}

	l2_phy_interface_t *port;
	port = ifm_get_port(portid);
	if (port == NULL) {
		printf("PORT %u IS DOWN..! Unable to Process\n", portid);
		return;
	}
	uint32_t size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct l2_adj_entry));
	adj_data = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
	if (adj_data == NULL) {
		printf("L2 Adjacency memory allocation failed !\n");
		return;
	}

	adj_data->out_port_id = portid;
	memcpy(adj_data->nh_ipv6, &nh_ipv6, RTE_LPM_IPV6_ADDR_SIZE);

	adj_data->phy_port = port;

	ether_addr_copy(&eth_dst, &adj_data->eth_addr);

	/* Precompute the L2 string encapsulation */
	memcpy(&adj_data->l2_string, hw_addr, sizeof(struct ether_addr));
	memcpy(&adj_data->l2_string[6], &port->macaddr,
				 sizeof(struct ether_addr));
	memcpy(&adj_data->l2_string[12], &ether_type, 2);

	adj_data->flags = L2_ADJ_RESOLVED;

	/* Store the received MAC Address in L2 Adj HAsh Table */
	rte_hash_add_key_data(l2_adj_ipv6_hash_handle, &l2_adj_key, adj_data);

	printf(" ND resolution successful and stored in ipv6_l2_adj_entry %p\n",
				 adj_data);
}

void ipv6_iterate__hash_table(void)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;
	uint8_t ii;
	printf("\n\t\t\t IPv6 FIB_path Cache table....");
	printf
			("\n------------------------------------------------------------------------------");
	printf
			("\n\tNextHop IP \t\t\t\t Port   Refcount   l2_adj_ptr_addrress\n\n");
	printf
			("--------------------------------------------------------------------------------\n");

	while (rte_hash_iterate
				 (fib_path_ipv6_hash_handle, &next_key, &next_data, &iter) >= 0) {
		struct ipv6_fib_path *tmp_data =
				(struct ipv6_fib_path *)next_data;
		struct fib_path_key_ipv6 tmp_key;
		memcpy(&tmp_key, next_key, sizeof(tmp_key));
		for (ii = 0; ii < 16; ii += 2) {
			printf("%02X%02X ", tmp_data->nh_ipv6[ii],
						 tmp_data->nh_ipv6[ii + 1]);
		}
		printf(" \t %u \t %u \t %p\n", tmp_data->out_port,
					 tmp_data->refcount, tmp_data->l2_adj_ipv6_ptr);

	}

	iter = 0;

	printf("\n\t\t\t L2 ADJ Cache table.....");
	printf
			("\n----------------------------------------------------------------------------------\n");
	printf
			("\tNextHop IP  \t\t\t\t Port \t  l2 Encap string \t l2_Phy_interface\n");
	printf
			("\n------------------------------------------------------------------------------------\n");
	while (rte_hash_iterate
				 (l2_adj_ipv6_hash_handle, &next_key, &next_data, &iter) >= 0) {
		struct l2_adj_ipv6_entry *l2_data =
				(struct l2_adj_ipv6_entry *)next_data;
		struct l2_adj_key_ipv6 l2_key;
		memcpy(&l2_key, next_key, sizeof(l2_key));
		for (ii = 0; ii < 16; ii += 2) {
			printf("%02X%02X ", l2_data->nh_ipv6[ii],
						 l2_data->nh_ipv6[ii + 1]);
		}
		printf(" \t%u\t%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x\t%p\n",
					 l2_data->out_port_id,
					 l2_data->l2_string[0],
					 l2_data->l2_string[1],
					 l2_data->l2_string[2],
					 l2_data->l2_string[3],
					 l2_data->l2_string[4],
					 l2_data->l2_string[5],
					 l2_data->l2_string[6],
					 l2_data->l2_string[7],
					 l2_data->l2_string[8],
					 l2_data->l2_string[9],
					 l2_data->l2_string[10],
					 l2_data->l2_string[11], l2_data->phy_port);
	}
}
