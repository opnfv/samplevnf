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
 * Pipeline ACL BE Implementation.
 *
 * Implementation of Pipeline ACL Back End (BE).
 * Responsible for packet processing.
 *
 */

#include <string.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_byteorder.h>
#include <rte_table_acl.h>
#include <rte_table_stub.h>
#include "pipeline_arpicmp_be.h"
#include "vnf_common.h"
#include "pipeline_common_be.h"
#include <rte_pipeline.h>
#include <rte_hash.h>

#include <rte_timer.h>
#include <rte_cycles.h>

#include "pipeline_acl.h"
#include "pipeline_acl_be.h"
#include "rte_cnxn_tracking.h"
#include "pipeline_actions_common.h"
#include "lib_arp.h"
#include "lib_icmpv6.h"
static uint8_t acl_prv_que_port_index[PIPELINE_MAX_PORT_IN];
extern void convert_prefixlen_to_netmask_ipv6(uint32_t depth,
                                              uint8_t netmask_ipv6[]);
enum {
	ACL_PUB_PORT_ID,
	ACL_PRV_PORT_ID,
};

/**
 * A structure defining the ACL pipeline per thread data.
 */
struct pipeline_acl {
	struct pipeline p;
	pipeline_msg_req_handler custom_handlers[PIPELINE_ACL_MSG_REQS];

	uint32_t n_rules;
	uint32_t n_rule_fields;
	struct rte_acl_field_def *field_format;
	uint32_t field_format_size;

	/* Connection Tracker */
	struct rte_ct_cnxn_tracker *cnxn_tracker;
	struct rte_ACL_counter_block *counters;
	int action_counter_index;
	/* timestamp retrieved during in-port computations */
	uint64_t in_port_time_stamp;
	uint32_t n_flows;

	uint8_t pipeline_num;
	uint8_t traffic_type;
	uint8_t links_map[PIPELINE_MAX_PORT_IN];
	uint8_t port_out_id[PIPELINE_MAX_PORT_IN];
	uint64_t arpPktCount;
	struct acl_table_entry *acl_entries_ipv4[RTE_PORT_IN_BURST_SIZE_MAX];
	struct acl_table_entry *acl_entries_ipv6[RTE_PORT_IN_BURST_SIZE_MAX];

	/* Local ARP & ND Tables */
	struct lib_arp_route_table_entry
	 local_lib_arp_route_table[MAX_ARP_RT_ENTRY];
	uint8_t local_lib_arp_route_ent_cnt;
	struct lib_nd_route_table_entry
	 local_lib_nd_route_table[MAX_ND_RT_ENTRY];
	uint8_t local_lib_nd_route_ent_cnt;

} __rte_cache_aligned;

/**
 * A structure defining the mbuf meta data for ACL.
 */
struct mbuf_acl_meta_data {
	/* output port stored for RTE_PIPELINE_ACTION_PORT_META */
	uint32_t output_port;
	/* next hop ip address used by ARP code */
	uint8_t nhip[16];
} __rte_cache_aligned;

#define META_DATA_OFFSET 128

struct rte_ACL_counter_block rte_acl_counter_table[MAX_ACL_INSTANCES]
	__rte_cache_aligned;
int rte_ACL_hi_counter_block_in_use = -1;

/* a spin lock used during acl initialization only */
rte_spinlock_t rte_ACL_init_lock = RTE_SPINLOCK_INITIALIZER;

/* Action Array */
struct pipeline_action_key *action_array_a;
struct pipeline_action_key *action_array_b;
struct pipeline_action_key *action_array_active;
struct pipeline_action_key *action_array_standby;
uint32_t action_array_size;

struct action_counter_block
	action_counter_table[MAX_ACL_INSTANCES][action_array_max]
	__rte_cache_aligned;

static void *pipeline_acl_msg_req_custom_handler(struct pipeline *p, void *msg);

static pipeline_msg_req_handler handlers[] = {
	[PIPELINE_MSG_REQ_PING] = pipeline_msg_req_ping_handler,
	[PIPELINE_MSG_REQ_STATS_PORT_IN] =
	    pipeline_msg_req_stats_port_in_handler,
	[PIPELINE_MSG_REQ_STATS_PORT_OUT] =
	    pipeline_msg_req_stats_port_out_handler,
	[PIPELINE_MSG_REQ_STATS_TABLE] = pipeline_msg_req_stats_table_handler,
	[PIPELINE_MSG_REQ_PORT_IN_ENABLE] =
	    pipeline_msg_req_port_in_enable_handler,
	[PIPELINE_MSG_REQ_PORT_IN_DISABLE] =
	    pipeline_msg_req_port_in_disable_handler,
	[PIPELINE_MSG_REQ_CUSTOM] = pipeline_acl_msg_req_custom_handler,
};

static void *pipeline_acl_msg_req_dbg_handler(struct pipeline *p, void *msg);

static pipeline_msg_req_handler custom_handlers[] = {
	[PIPELINE_ACL_MSG_REQ_DBG] = pipeline_acl_msg_req_dbg_handler,
};

uint8_t ACL_DEBUG;
uint32_t local_get_nh_ipv4(uint32_t ip,
			   uint32_t *port,
			   uint32_t *nhip, struct pipeline_acl *p_acl)
{
	int i;

	for (i = 0; i < p_acl->local_lib_arp_route_ent_cnt; i++) {
		if (((p_acl->local_lib_arp_route_table[i].ip &
		      p_acl->local_lib_arp_route_table[i].mask) ==
		     (ip & p_acl->local_lib_arp_route_table[i].mask))) {
			*port = p_acl->local_lib_arp_route_table[i].port;

			*nhip = p_acl->local_lib_arp_route_table[i].nh;
			return 1;
		}
	}
	return 0;
}

static void do_local_nh_ipv4_cache(uint32_t dest_if, struct pipeline_acl *p_acl)
{

	/* Search for the entry and do local copy */
	int i;

	for (i = 0; i < MAX_ARP_RT_ENTRY; i++) {
		if (lib_arp_route_table[i].port == dest_if) {

			struct lib_arp_route_table_entry *lentry =
			    &p_acl->local_lib_arp_route_table
			    [p_acl->local_lib_arp_route_ent_cnt];

			lentry->ip = lib_arp_route_table[i].ip;
			lentry->mask = lib_arp_route_table[i].mask;
			lentry->port = lib_arp_route_table[i].port;
			lentry->nh = lib_arp_route_table[i].nh;

			p_acl->local_lib_arp_route_ent_cnt++;
			break;
		}
	}
}

static uint32_t local_get_nh_ipv6(uint8_t *ip,
				  uint32_t *port,
				  uint8_t nhip[], struct pipeline_acl *p_acl)
{
	int i = 0;
        uint8_t netmask_ipv6[16],netip_nd[16],netip_in[16];
        uint8_t k = 0, l = 0, depthflags = 0, depthflags1 = 0;
        memset (netmask_ipv6, 0, sizeof(netmask_ipv6));
        memset (netip_nd, 0, sizeof(netip_nd));
        memset (netip_in, 0, sizeof(netip_in));

        for (i = 0; i < p_acl->local_lib_nd_route_ent_cnt; i++) {

                convert_prefixlen_to_netmask_ipv6
                    (p_acl->local_lib_nd_route_table[i].depth, netmask_ipv6);

                for (k = 0; k < 16; k++)
                        if (p_acl->local_lib_nd_route_table[i].ipv6[k] &
                            netmask_ipv6[k]) {
                                depthflags++;
                                netip_nd[k] = p_acl->
                                local_lib_nd_route_table[i].ipv6[k];
                        }


                for (l = 0; l < 16; l++)
                        if (ip[l] & netmask_ipv6[l]) {
                                depthflags1++;
                                netip_in[l] = ip[l];
                        }

                int j = 0;

                if ((depthflags == depthflags1) && (memcmp(netip_nd, netip_in,
                                                        sizeof(netip_nd)) == 0)){
                        *port = p_acl->local_lib_nd_route_table[i].port;

                        for (j = 0; j < 16; j++)
                                nhip[j] =
                                    p_acl->local_lib_nd_route_table[i].
                                    nhipv6[j];
                        return 1;
                }

                depthflags = 0;
                depthflags1 = 0;
        }
        return 0;
}
void do_local_nh_ipv6_cache(uint32_t dest_if, struct pipeline_acl *p_acl)
{
	/* Search for the entry and do local copy */
	int i, l;

	for (i = 0; i < MAX_ND_RT_ENTRY; i++) {

		if (lib_nd_route_table[i].port == dest_if) {

			struct lib_nd_route_table_entry *lentry =
			    &p_acl->local_lib_nd_route_table
			    [p_acl->local_lib_nd_route_ent_cnt];

			for (l = 0; l < 16; l++) {
				lentry->ipv6[l] = lib_nd_route_table[i].ipv6[l];
				lentry->nhipv6[l] =
				    lib_nd_route_table[i].nhipv6[l];
			}
			lentry->depth = lib_nd_route_table[i].depth;
			lentry->port = lib_nd_route_table[i].port;

			p_acl->local_lib_nd_route_ent_cnt++;
			break;
		}		/* if */
	}			/* for */
}

static uint8_t check_arp_icmp(struct rte_mbuf *pkt,
			      uint64_t pkt_mask, struct pipeline_acl *p_acl)
{
	uint32_t eth_proto_offset = MBUF_HDR_ROOM + 12;
	struct ipv6_hdr *ipv6_h;
	uint16_t *eth_proto =
	    RTE_MBUF_METADATA_UINT16_PTR(pkt, eth_proto_offset);
	struct app_link_params *link;

	//uint32_t *port_out_id = RTE_MBUF_METADATA_UINT32_PTR(pk
	//                      offsetof(struct mbuf_acl_meta_dat

	/* ARP outport number */
	uint16_t out_port = p_acl->p.n_ports_out - 1;

	uint8_t *protocol;
	uint32_t prot_offset;

	link = &myApp->link_params[pkt->port];

	switch (rte_be_to_cpu_16(*eth_proto)) {

	case ETH_TYPE_ARP:
		rte_pipeline_port_out_packet_insert(p_acl->p.p, out_port, pkt);

		/*
		 * Pkt mask should be changed, and not changing the
		 * drop mask
		 */
		p_acl->arpPktCount++;

		return 0;
/*		break;*/
	case ETH_TYPE_IPV4:{
			/* header room + eth hdr size +
			 * src_aadr offset in ip header
			 */
			uint32_t dst_addr_offset = MBUF_HDR_ROOM +
			    ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST;
			uint32_t *dst_addr = RTE_MBUF_METADATA_UINT32_PTR(pkt,
							  dst_addr_offset);
			prot_offset = MBUF_HDR_ROOM + ETH_HDR_SIZE +
			    IP_HDR_PROTOCOL_OFST;
			protocol = RTE_MBUF_METADATA_UINT8_PTR(pkt,
							       prot_offset);
			if ((*protocol == IP_PROTOCOL_ICMP) &&
			    link->ip == rte_be_to_cpu_32(*dst_addr)) {

				if (is_phy_port_privte(pkt->port)) {

					rte_pipeline_port_out_packet_insert
					    (p_acl->p.p, out_port, pkt);
					/*
					 * Pkt mask should be changed,
					 * and not changing the drop mask
					 */
					p_acl->arpPktCount++;

					return 0;
				}
			}
			return 1;
		}
		break;
#if 0
#ifdef IPV6
	case ETH_TYPE_IPV6:{

			uint32_t dst_addr_offset = MBUF_HDR_ROOM +
			    ETH_HDR_SIZE + IPV6_HDR_DST_ADR_OFST;
			uint32_t *dst_addr = RTE_MBUF_METADATA_UINT32_PTR(pkt,
							  dst_addr_offset);

			uint32_t prot_offset_ipv6 = MBUF_HDR_ROOM +
			    ETH_HDR_SIZE + IPV6_HDR_PROTOCOL_OFST;
			struct ipv6_hdr *ipv6_h;

			ipv6_h = (struct ipv6_hdr *)MBUF_HDR_ROOM +
			    ETH_HDR_SIZE;
			protocol = RTE_MBUF_METADATA_UINT8_PTR(pkt,
						       prot_offset_ipv6);

			if ((ipv6_h->proto == ICMPV6_PROTOCOL_ID) &&
			    (link->ip == rte_be_to_cpu_32(dst_addr[3]))) {

				if (is_phy_port_privte(pkt->port)) {

					rte_pipeline_port_out_packet_insert
					    (p_acl->p.p, out_port, pkt);
					/*
					 * Pkt mask should be changed,
					 * and not changing the drop mask
					 */
					p_acl->arpPktCount++;

					return 0;
				}
			}
			return 1;
		}
		break;
#endif
#endif
#define IP_START (MBUF_HDR_ROOM + ETH_HDR_SIZE)
#ifdef IPV6
        case ETH_TYPE_IPV6:
                ipv6_h = (struct ipv6_hdr *)
                        RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);

                if ((ipv6_h->proto == ICMPV6_PROTOCOL_ID) &&
                                (link->ip ==
                         rte_be_to_cpu_32(ipv6_h->dst_addr[3]))) {

                        if (is_phy_port_privte(pkt->port)) {
                                rte_pipeline_port_out_packet_insert(
                                                p_acl->p.p,
                                                out_port,
                                                pkt);

                        p_acl->arpPktCount++;

                                return 0;
                        }
                }
                break;
#endif
	default:
		break;
		return 1;
	}
	return 1;
}

/**
 * Print packet for debugging.
 *
 * @param pkt
 *  A pointer to the packet.
 *
 */
void print_pkt_acl(struct rte_mbuf *pkt)
{
	int i = 0, j = 0;

	printf("Packet Contents:\n");
	uint8_t *rd = RTE_MBUF_METADATA_UINT8_PTR(pkt, 0);

	for (i = 0; i < 20; i++) {
		for (j = 0; j < 20; j++)
			printf("%02x ", rd[(20 * i) + j]);
		printf("\n");
	}
}

/**
 * Main packet processing function.
 * 64 packet bit mask are used to identify which packets to forward.
 * Performs the following:
 *  - Burst lookup packets in the IPv4 ACL Rule Table.
 *  - Burst lookup packets in the IPv6 ACL Rule Table.
 *  - Lookup Action Table, perform actions.
 *  - Burst lookup Connection Tracking, if enabled.
 *  - Lookup MAC address.
 *  - Set bit mask.
 *  - Packets with bit mask set are forwarded
 *
 * @param p
 *  A pointer to the pipeline.
 * @param pkts
 *  A pointer to a burst of packets.
 * @param n_pkts
 *  Number of packets to process.
 * @param arg
 *  A pointer to pipeline specific data.
 *
 * @return
 *  0 on success, negative on error.
 */
static int
pkt_work_acl_key(struct rte_pipeline *p,
		 struct rte_mbuf **pkts, uint32_t n_pkts, void *arg)
{

	struct pipeline_acl *p_acl = arg;

	p_acl->counters->pkts_received =
	    p_acl->counters->pkts_received + n_pkts;
	if (ACL_DEBUG)
		printf("pkt_work_acl_key pkts_received: %" PRIu64
		       " n_pkts: %u\n", p_acl->counters->pkts_received, n_pkts);

	uint64_t lookup_hit_mask = 0;
	uint64_t lookup_hit_mask_ipv4 = 0;
	uint64_t lookup_hit_mask_ipv6 = 0;
	uint64_t lookup_miss_mask = 0;
	uint64_t conntrack_mask = 0;
	uint64_t connexist_mask = 0;
	uint32_t dest_address = 0;
	int dest_if = 0;
	int status;
	uint64_t pkts_drop_mask, pkts_mask = RTE_LEN2MASK(n_pkts, uint64_t);
	uint64_t keep_mask = pkts_mask;
	uint16_t port;
	uint32_t ret;

	p_acl->in_port_time_stamp = rte_get_tsc_cycles();

	if (acl_ipv4_enabled) {
		if (ACL_DEBUG)
			printf("ACL IPV4 Lookup Mask Before = %p\n",
			       (void *)pkts_mask);
		status =
		    rte_table_acl_ops.f_lookup(acl_rule_table_ipv4_active, pkts,
					       pkts_mask, &lookup_hit_mask_ipv4,
					       (void **)
					       p_acl->acl_entries_ipv4);
		if (ACL_DEBUG)
			printf("ACL IPV4 Lookup Mask After = %p\n",
			       (void *)lookup_hit_mask_ipv4);
	}

	if (acl_ipv6_enabled) {
		if (ACL_DEBUG)
			printf("ACL IPV6 Lookup Mask Before = %p\n",
			       (void *)pkts_mask);
		status =
		    rte_table_acl_ops.f_lookup(acl_rule_table_ipv6_active, pkts,
					       pkts_mask, &lookup_hit_mask_ipv6,
					       (void **)
					       p_acl->acl_entries_ipv6);
		if (ACL_DEBUG)
			printf("ACL IPV6 Lookup Mask After = %p\n",
			       (void *)lookup_hit_mask_ipv6);
	}

	/* Merge lookup results since we process both IPv4 and IPv6 below */
	lookup_hit_mask = lookup_hit_mask_ipv4 | lookup_hit_mask_ipv6;
	if (ACL_DEBUG)
		printf("ACL Lookup Mask After = %p\n", (void *)lookup_hit_mask);

	lookup_miss_mask = pkts_mask & (~lookup_hit_mask);
	pkts_mask = lookup_hit_mask;
	p_acl->counters->pkts_drop += __builtin_popcountll(lookup_miss_mask);
	if (ACL_DEBUG)
		printf("pkt_work_acl_key pkts_drop: %" PRIu64 " n_pkts: %u\n",
		       p_acl->counters->pkts_drop,
		       __builtin_popcountll(lookup_miss_mask));

	uint64_t pkts_to_process = lookup_hit_mask;
		/* bitmap of packets left to process for ARP */

	for (; pkts_to_process;) {
		uint8_t pos = (uint8_t) __builtin_ctzll(pkts_to_process);
		uint64_t pkt_mask = 1LLU << pos;
		/* bitmask representing only this packet */

		pkts_to_process &= ~pkt_mask;
		/* remove this packet from remaining list */
		struct rte_mbuf *pkt = pkts[pos];

		if (enable_hwlb)
			if (!check_arp_icmp(pkt, pkt_mask, p_acl)) {
				pkts_mask &= ~(1LLU << pos);
				continue;
			}

		uint8_t hdr_chk =
		    RTE_MBUF_METADATA_UINT8(pkt, MBUF_HDR_ROOM + ETH_HDR_SIZE);
		hdr_chk = hdr_chk >> IP_VERSION_CHECK;

		if (hdr_chk == IPv4_HDR_VERSION) {

			struct acl_table_entry *entry =
			    (struct acl_table_entry *)
			    p_acl->acl_entries_ipv4[pos];
			uint16_t phy_port = entry->head.port_id;
			uint32_t action_id = entry->action_id;

			if (ACL_DEBUG)
				printf("action_id = %u\n", action_id);

			uint32_t dscp_offset =
			    MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DSCP_OFST;

			if (action_array_active[action_id].action_bitmap &
			    acl_action_count) {
				action_counter_table
				    [p_acl->action_counter_index]
				    [action_id].packetCount++;
				action_counter_table
				    [p_acl->action_counter_index]
				    [action_id].byteCount +=
				    rte_pktmbuf_pkt_len(pkt);
				if (ACL_DEBUG)
					printf("Action Count   Packet Count: %"
					       PRIu64 "  Byte Count: %" PRIu64
					       "\n",
					       action_counter_table
					       [p_acl->action_counter_index]
					       [action_id].packetCount,
					       action_counter_table
					       [p_acl->action_counter_index]
					       [action_id].byteCount);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_packet_drop) {

				/* Drop packet by changing the mask */
				if (ACL_DEBUG)
					printf("ACL before drop pkt_mask "
							" %lu, pkt_num %d\n",
					     pkts_mask, pos);
				pkts_mask &= ~(1LLU << pos);
				if (ACL_DEBUG)
					printf("ACL after drop pkt_mask  "
							"%lu, pkt_num %d\n",
					     pkts_mask, pos);
				p_acl->counters->pkts_drop++;
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_fwd) {
				phy_port =
				    action_array_active[action_id].fwd_port;
				entry->head.port_id = phy_port;
				if (ACL_DEBUG)
					printf("Action FWD  Port ID: %u\n",
					       phy_port);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_nat) {
				phy_port =
				    action_array_active[action_id].nat_port;
				entry->head.port_id = phy_port;
				if (ACL_DEBUG)
					printf("Action NAT  Port ID: %u\n",
					       phy_port);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_dscp) {

				/* Set DSCP priority */
				uint8_t *dscp = RTE_MBUF_METADATA_UINT8_PTR(pkt,
							    dscp_offset);
				*dscp =
				    action_array_active[action_id].dscp_priority
				    << 2;
				if (ACL_DEBUG)
					printf
					    ("Action DSCP  DSCP Priority: %u\n",
					     *dscp);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_packet_accept) {
				if (ACL_DEBUG)
					printf("Action Accept\n");

				if (action_array_active[action_id].action_bitmap
				    & acl_action_conntrack) {

					/* Set conntrack bit for this pkt */
					conntrack_mask |= pkt_mask;
					if (ACL_DEBUG)
						printf("ACL Conntrack enabled: "
							"%p  pkt_mask: %p\n",
						     (void *)conntrack_mask,
						     (void *)pkt_mask);
				}

				if (action_array_active[action_id].action_bitmap
				    & acl_action_connexist) {

					/* Set conntrack bit for this pkt */
					conntrack_mask |= pkt_mask;

		/* Set connexist bit for this pkt for public -> private */
		/* Private -> public packet will open the connection */
					if (action_array_active
					    [action_id].private_public ==
					    acl_public_private)
						connexist_mask |= pkt_mask;

					if (ACL_DEBUG)
						printf("ACL Connexist enabled  "
				"conntrack: %p  connexist: %p  pkt_mask: %p\n",
						     (void *)conntrack_mask,
						     (void *)connexist_mask,
						     (void *)pkt_mask);
				}
			}
		}

		if (hdr_chk == IPv6_HDR_VERSION) {

			struct acl_table_entry *entry =
			    (struct acl_table_entry *)
			    p_acl->acl_entries_ipv6[pos];
			uint16_t phy_port = entry->head.port_id;
			uint32_t action_id = entry->action_id;

			if (ACL_DEBUG)
				printf("action_id = %u\n", action_id);

			if (action_array_active[action_id].action_bitmap &
			    acl_action_count) {
				action_counter_table
				    [p_acl->action_counter_index]
				    [action_id].packetCount++;
				action_counter_table
				    [p_acl->action_counter_index]
				    [action_id].byteCount +=
				    rte_pktmbuf_pkt_len(pkt);
				if (ACL_DEBUG)
					printf("Action Count   Packet Count: %"
					       PRIu64 "  Byte Count: %" PRIu64
					       "\n",
					       action_counter_table
					       [p_acl->action_counter_index]
					       [action_id].packetCount,
					       action_counter_table
					       [p_acl->action_counter_index]
					       [action_id].byteCount);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_packet_drop) {
				/* Drop packet by changing the mask */
				if (ACL_DEBUG)
					printf("ACL before drop pkt_mask  "
							"%lu, pkt_num %d\n",
					     pkts_mask, pos);
				pkts_mask &= ~(1LLU << pos);
				if (ACL_DEBUG)
					printf("ACL after drop pkt_mask  "
							"%lu, pkt_num %d\n",
					     pkts_mask, pos);
				p_acl->counters->pkts_drop++;

			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_fwd) {
				phy_port =
				    action_array_active[action_id].fwd_port;
				entry->head.port_id = phy_port;
				if (ACL_DEBUG)
					printf("Action FWD  Port ID: %u\n",
					       phy_port);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_nat) {
				phy_port =
				    action_array_active[action_id].nat_port;
				entry->head.port_id = phy_port;
				if (ACL_DEBUG)
					printf("Action NAT  Port ID: %u\n",
					       phy_port);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_dscp) {

				/* Set DSCP priority */
				uint32_t dscp_offset =
				    MBUF_HDR_ROOM + ETH_HDR_SIZE +
				    IP_HDR_DSCP_OFST_IPV6;
				uint16_t *dscp =
				    RTE_MBUF_METADATA_UINT16_PTR(pkt,
								 dscp_offset);
				uint16_t dscp_value =
				    (rte_bswap16
				     (RTE_MBUF_METADATA_UINT16
				      (pkt, dscp_offset)) & 0XF00F);
				uint8_t dscp_store =
				    action_array_active[action_id].dscp_priority
				    << 2;
				uint16_t dscp_temp = dscp_store;

				dscp_temp = dscp_temp << 4;
				*dscp = rte_bswap16(dscp_temp | dscp_value);
				if (ACL_DEBUG)
					printf
					    ("Action DSCP  DSCP Priority: %u\n",
					     *dscp);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_packet_accept) {
				if (ACL_DEBUG)
					printf("Action Accept\n");

				if (action_array_active[action_id].action_bitmap
				    & acl_action_conntrack) {

					/* Set conntrack bit for this pkt */
					conntrack_mask |= pkt_mask;
					if (ACL_DEBUG)
						printf("ACL Conntrack enabled: "
							" %p  pkt_mask: %p\n",
						     (void *)conntrack_mask,
						     (void *)pkt_mask);
				}

				if (action_array_active[action_id].action_bitmap
				    & acl_action_connexist) {

					/* Set conntrack bit for this pkt */
					conntrack_mask |= pkt_mask;

		/* Set connexist bit for this pkt for public -> private */
		/* Private -> public packet will open the connection */
					if (action_array_active
					    [action_id].private_public ==
					    acl_public_private)
						connexist_mask |= pkt_mask;

					if (ACL_DEBUG)
						printf("ACL Connexist enabled  "
				"conntrack: %p  connexist: %p  pkt_mask: %p\n",
						     (void *)conntrack_mask,
						     (void *)connexist_mask,
						     (void *)pkt_mask);
				}
			}
		}
	}

	/* Only call connection tracker if required */
	if (conntrack_mask > 0) {
		if (ACL_DEBUG)
			printf
			    ("ACL Call Conntrack Before = %p  Connexist = %p\n",
			     (void *)conntrack_mask, (void *)connexist_mask);
		conntrack_mask =
		    rte_ct_cnxn_tracker_batch_lookup_with_new_cnxn_control
		    (p_acl->cnxn_tracker, pkts, conntrack_mask, connexist_mask);
		if (ACL_DEBUG)
			printf("ACL Call Conntrack After = %p\n",
			       (void *)conntrack_mask);

		/* Only change pkt mask for pkts that have conntrack enabled */
		/* Need to loop through packets to check if conntrack enabled */
		pkts_to_process = pkts_mask;
		for (; pkts_to_process;) {
			uint32_t action_id = 0;
			uint8_t pos =
			    (uint8_t) __builtin_ctzll(pkts_to_process);
			uint64_t pkt_mask = 1LLU << pos;
		/* bitmask representing only this packet */

			pkts_to_process &= ~pkt_mask;
		/* remove this packet from remaining list */
			struct rte_mbuf *pkt = pkts[pos];

			uint8_t hdr_chk = RTE_MBUF_METADATA_UINT8(pkt,
								  MBUF_HDR_ROOM
								  +
								  ETH_HDR_SIZE);

			hdr_chk = hdr_chk >> IP_VERSION_CHECK;
			if (hdr_chk == IPv4_HDR_VERSION) {
				struct acl_table_entry *entry =
				    (struct acl_table_entry *)
				    p_acl->acl_entries_ipv4[pos];
				action_id = entry->action_id;
			} else {
				struct acl_table_entry *entry =
				    (struct acl_table_entry *)
				    p_acl->acl_entries_ipv6[pos];
				action_id = entry->action_id;
			}

			if ((action_array_active[action_id].action_bitmap &
			     acl_action_conntrack)
			    || (action_array_active[action_id].action_bitmap &
				acl_action_connexist)) {

				if (conntrack_mask & pkt_mask) {
					if (ACL_DEBUG)
						printf("ACL Conntrack Accept  "
								"packet = %p\n",
						     (void *)pkt_mask);
				} else {
					/* Drop packet by changing the mask */
					if (ACL_DEBUG)
						printf("ACL Conntrack Drop  "
								"packet = %p\n",
						     (void *)pkt_mask);
					pkts_mask &= ~pkt_mask;
					p_acl->counters->pkts_drop++;
				}
			}
		}
	}

	pkts_to_process = pkts_mask;
		/* bitmap of packets left to process for ARP */

	for (; pkts_to_process;) {
		uint8_t pos = (uint8_t) __builtin_ctzll(pkts_to_process);
		uint64_t pkt_mask = 1LLU << pos;
		/* bitmask representing only this packet */

		pkts_to_process &= ~pkt_mask;
		/* remove this packet from remaining list */
		struct rte_mbuf *pkt = pkts[pos];

		uint8_t hdr_chk =
		    RTE_MBUF_METADATA_UINT8(pkt, MBUF_HDR_ROOM + ETH_HDR_SIZE);
		hdr_chk = hdr_chk >> IP_VERSION_CHECK;

		if (hdr_chk == IPv4_HDR_VERSION) {

			struct acl_table_entry *entry =
			    (struct acl_table_entry *)
			    p_acl->acl_entries_ipv4[pos];
			uint16_t phy_port = pkt->port;
			uint32_t *port_out_id =
			    RTE_MBUF_METADATA_UINT32_PTR(pkt,
							 META_DATA_OFFSET +
							 offsetof(struct
							  mbuf_acl_meta_data,
								  output_port));
			if (ACL_DEBUG)
				printf
				   ("phy_port = %i, links_map[phy_port] = %i\n",
				     phy_port, p_acl->links_map[phy_port]);

		/* header room + eth hdr size + dst_adr offset in ip header */
			uint32_t dst_addr_offset =
			    MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST;
			uint32_t *dst_addr =
			    RTE_MBUF_METADATA_UINT32_PTR(pkt, dst_addr_offset);
			uint8_t *eth_dest =
			    RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
			uint8_t *eth_src =
			    RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM + 6);
			struct ether_addr hw_addr;
			uint32_t dest_address = rte_bswap32(*dst_addr);
			uint32_t *nhip = RTE_MBUF_METADATA_UINT32_PTR(pkt,
							      META_DATA_OFFSET
								      +
								      offsetof
								      (struct
						       mbuf_acl_meta_data,
								       nhip));
			uint32_t packet_length = rte_pktmbuf_pkt_len(pkt);
			*nhip = 0;
			if (is_phy_port_privte(phy_port)) {
				dest_address = rte_bswap32(*dst_addr);
				ret =
				    local_get_nh_ipv4(dest_address, &dest_if,
						      nhip, p_acl);
				if (!ret) {
					dest_if =
					    get_prv_to_pub_port(&dest_address,
								IP_VERSION_4);
					do_local_nh_ipv4_cache(dest_if, p_acl);
				}
				*port_out_id = p_acl->port_out_id[dest_if];
			} else {
				dest_address = rte_bswap32(*dst_addr);

				ret = local_get_nh_ipv4(dest_address, &dest_if,
							nhip, p_acl);
				if (!ret) {
					dest_if =
					    get_pub_to_prv_port(&dest_address,
								IP_VERSION_4);
					do_local_nh_ipv4_cache(dest_if, p_acl);
				};
				*port_out_id = p_acl->port_out_id[dest_if];
			}
			/* port = ACL_PRV_PORT_ID; */

			int ret_mac = 0;

			ret_mac = get_dest_mac_addr_port
			    (dest_address, &dest_if, &hw_addr);
			if (ret_mac == ARP_FOUND) {
				if (ACL_DEBUG) {
					printf("MAC found for ip 0x%x,  "
				"port %d - %02x:%02x:%02x:%02x:%02x:%02x\n",
					     dest_address, phy_port,
					     hw_addr.addr_bytes[0],
					     hw_addr.addr_bytes[1],
					     hw_addr.addr_bytes[2],
					     hw_addr.addr_bytes[3],
					     hw_addr.addr_bytes[4],
					     hw_addr.addr_bytes[5]);
					printf("Dest MAC before -  "
					"%02x:%02x:%02x:%02x:%02x:%02x\n",
					     eth_dest[0], eth_dest[1],
					     eth_dest[2], eth_dest[3],
					     eth_dest[4], eth_dest[5]);
				}

				memcpy(eth_dest, &hw_addr,
				       sizeof(struct ether_addr));
				if (ACL_DEBUG) {
					printf("PktP %p, dest_macP %p\n", pkt,
					       eth_dest);
					printf("Dest MAC after -  "
					"%02x:%02x:%02x:%02x:%02x:%02x\n",
					     eth_dest[0], eth_dest[1],
					     eth_dest[2], eth_dest[3],
					     eth_dest[4], eth_dest[5]);
				}
				if (is_phy_port_privte(phy_port))
					memcpy(eth_src,
					       get_link_hw_addr(dest_if),
					       sizeof(struct ether_addr));
				else
					memcpy(eth_src,
					       get_link_hw_addr(dest_if),
					       sizeof(struct ether_addr));
				p_acl->counters->tpkts_processed++;
				p_acl->counters->bytes_processed +=
				    packet_length;
			}

			else {
				if (*nhip != 0) {
					if (ACL_DEBUG)
						printf("ACL requesting ARP for "
							"ip %x, port %d\n",
						     dest_address, phy_port);
					if (ret_mac == ARP_NOT_FOUND)
						request_arp(dest_if, *nhip);

		/*      request_arp(p_acl->links_map[phy_port], *nhip); */
				}
				/* Drop packet by changing the mask */
				if (ACL_DEBUG)
					printf("ACL before drop pkt_mask  "
							"%lu, pkt_num %d\n",
					     pkts_mask, pos);
				pkts_mask &= ~(1LLU << pos);
				if (ACL_DEBUG)
					printf("ACL after drop pkt_mask  "
							"%lu, pkt_num %d\n",
					     pkts_mask, pos);
				p_acl->counters->pkts_drop++;
			}
		}

		if (hdr_chk == IPv6_HDR_VERSION) {

			struct acl_table_entry *entry =
			    (struct acl_table_entry *)
			    p_acl->acl_entries_ipv6[pos];
			//uint16_t phy_port = entry->head.port_id;
			uint16_t phy_port = pkt->port;
			uint32_t *port_out_id =
			    RTE_MBUF_METADATA_UINT32_PTR(pkt,
							 META_DATA_OFFSET +
							 offsetof(struct
							  mbuf_acl_meta_data,
								  output_port));
			/*if (is_phy_port_privte(phy_port))
				*port_out_id = ACL_PUB_PORT_ID;
			else
				*port_out_id = ACL_PRV_PORT_ID;*/

			/*      *port_out_id = p_acl->links_map[phy_port]; */
			if (ACL_DEBUG)
				printf("phy_port = %i,  "
					"links_map[phy_port] = %i\n",
				     phy_port, p_acl->links_map[phy_port]);

		/* header room + eth hdr size + dst_adr offset in ip header */
			uint32_t dst_addr_offset =
			    MBUF_HDR_ROOM + ETH_HDR_SIZE +
			    IP_HDR_DST_ADR_OFST_IPV6;
			uint8_t *eth_dest =
			    RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
			uint8_t *eth_src =
			    RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM + 6);
			struct ether_addr hw_addr;
			uint8_t dest_address[16];
			uint8_t nhip[16];

			nhip[0] =
			    RTE_MBUF_METADATA_UINT8(pkt,
						    META_DATA_OFFSET +
						    offsetof(struct
							     mbuf_acl_meta_data,
							     nhip));
			uint8_t *dst_addr[16];
			uint32_t packet_length = rte_pktmbuf_pkt_len(pkt);
			int i = 0;

			for (i = 0; i < 16; i++) {
				dst_addr[i] =
				    RTE_MBUF_METADATA_UINT8_PTR(pkt,
								dst_addr_offset
								+ i);
			}
			memcpy(dest_address, *dst_addr, sizeof(dest_address));
			memset(nhip, 0, sizeof(nhip));
			ret = local_get_nh_ipv6(&dest_address[0], &dest_if,
						&nhip[0], p_acl);

			if (is_phy_port_privte(phy_port)) {
				if (!ret) {
					dest_if = get_prv_to_pub_port((
								       uint32_t
								       *)
					      &dest_address[0], IP_VERSION_6);
					do_local_nh_ipv6_cache(dest_if, p_acl);
					*port_out_id =
					    p_acl->port_out_id[dest_if];
				}
				//              port = ACL_PUB_PORT_ID;

			} else {
				if (!ret) {
					dest_if = get_pub_to_prv_port((
								       uint32_t
								       *)
					      &dest_address[0], IP_VERSION_6);
					do_local_nh_ipv6_cache(dest_if, p_acl);
					*port_out_id =
					    p_acl->port_out_id[dest_if];
				}
//               port = ACL_PRV_PORT_ID;

			}

			if (get_dest_mac_address_ipv6_port
			    (dest_address, &dest_if, &hw_addr, &nhip[0])) {
				if (ACL_DEBUG) {
					printf("MAC found for  port %d - "
					" %02x:%02x:%02x:%02x:%02x:%02x\n",
					     phy_port, hw_addr.addr_bytes[0],
					     hw_addr.addr_bytes[1],
					     hw_addr.addr_bytes[2],
					     hw_addr.addr_bytes[3],
					     hw_addr.addr_bytes[4],
					     hw_addr.addr_bytes[5]);
					printf("Dest MAC before -  "
					"%02x:%02x:%02x:%02x:%02x:%02x\n",
					     eth_dest[0], eth_dest[1],
					     eth_dest[2], eth_dest[3],
					     eth_dest[4], eth_dest[5]);
				}
				memcpy(eth_dest, &hw_addr,
				       sizeof(struct ether_addr));
				if (ACL_DEBUG) {
					printf("PktP %p, dest_macP %p\n", pkt,
					       eth_dest);
					printf("Dest MAC after -  "
				"%02x:%02x:%02x:%02x:%02x:%02x\n",
					     eth_dest[0], eth_dest[1],
					     eth_dest[2], eth_dest[3],
					     eth_dest[4], eth_dest[5]);
				}
				if (is_phy_port_privte(phy_port))
					memcpy(eth_src,
					       get_link_hw_addr(dest_if),
					       sizeof(struct ether_addr));
				else
					memcpy(eth_src,
					       get_link_hw_addr(dest_if),
					       sizeof(struct ether_addr));

/* memcpy(eth_src, get_link_hw_addr(p_acl->links_map[phy_port]), */
/*		   sizeof(struct ether_addr)); */
				p_acl->counters->tpkts_processed++;
				p_acl->counters->bytes_processed +=
				    packet_length;
			}

			else {

#if 0
			/* Request next neighbor for Ipv6 is yet to be done. */
				if (*nhip != 0) {
					if (ACL_DEBUG)
						printf
				    ("ACL requesting ARP for ip %x, port %d\n",
						     dest_address, phy_port);

			/* request_arp(p_acl->links_map[phy_port], *nhip); */
				}
#endif
				/* Drop packet by changing the mask */
				if (ACL_DEBUG)
					printf("ACL before drop pkt_mask  "
							"%lu, pkt_num %d\n",
					     pkts_mask, pos);
				pkts_mask &= ~(1LLU << pos);
				if (ACL_DEBUG)
					printf("ACL after drop pkt_mask  "
							"%lu, pkt_num %d\n",
					     pkts_mask, pos);
				p_acl->counters->pkts_drop++;
			}
		}

	}

	pkts_drop_mask = keep_mask & ~pkts_mask;
	rte_pipeline_ah_packet_drop(p, pkts_drop_mask);
	keep_mask = pkts_mask;

	/* don't bother measuring if traffic very low, might skew stats */
	uint32_t packets_this_iteration = __builtin_popcountll(pkts_mask);

	if (packets_this_iteration > 1) {
		uint64_t latency_this_iteration =
		    rte_get_tsc_cycles() - p_acl->in_port_time_stamp;

		p_acl->counters->sum_latencies += latency_this_iteration;
		p_acl->counters->count_latencies++;
	}

	if (ACL_DEBUG)
		printf("Leaving pkt_work_acl_key pkts_mask = %p\n",
		       (void *)pkts_mask);

	return 0;
}

/**
 * Main packet processing function.
 * 64 packet bit mask are used to identify which packets to forward.
 * Performs the following:
 *  - Burst lookup packets in the IPv4 ACL Rule Table.
 *  - Burst lookup packets in the IPv6 ACL Rule Table.
 *  - Lookup Action Table, perform actions.
 *  - Burst lookup Connection Tracking, if enabled.
 *  - Lookup MAC address.
 *  - Set bit mask.
 *  - Packets with bit mask set are forwarded
 *
 * @param p
 *  A pointer to the pipeline.
 * @param pkts
 *  A pointer to a burst of packets.
 * @param n_pkts
 *  Number of packets to process.
 * @param arg
 *  A pointer to pipeline specific data.
 *
 * @return
 *  0 on success, negative on error.
 */
static int
pkt_work_acl_ipv4_key(struct rte_pipeline *p,
		      struct rte_mbuf **pkts, uint32_t n_pkts, void *arg)
{

	struct pipeline_acl *p_acl = arg;

	p_acl->counters->pkts_received =
	    p_acl->counters->pkts_received + n_pkts;
	if (ACL_DEBUG)
		printf("pkt_work_acl_key pkts_received: %" PRIu64
		       " n_pkts: %u\n", p_acl->counters->pkts_received, n_pkts);

	uint64_t lookup_hit_mask = 0;
	uint64_t lookup_hit_mask_ipv4 = 0;
	uint64_t lookup_hit_mask_ipv6 = 0;
	uint64_t lookup_miss_mask = 0;
	uint64_t conntrack_mask = 0;
	uint64_t connexist_mask = 0;
	uint32_t dest_address = 0;
	int dest_if = 0;
	int status;
	uint64_t pkts_drop_mask, pkts_mask = RTE_LEN2MASK(n_pkts, uint64_t);
	uint64_t keep_mask = pkts_mask;
	uint16_t port;
	uint32_t ret;

	p_acl->in_port_time_stamp = rte_get_tsc_cycles();

	if (acl_ipv4_enabled) {
		if (ACL_DEBUG)
			printf("ACL IPV4 Lookup Mask Before = %p\n",
			       (void *)pkts_mask);
		status =
		    rte_table_acl_ops.f_lookup(acl_rule_table_ipv4_active, pkts,
					       pkts_mask, &lookup_hit_mask_ipv4,
					       (void **)
					       p_acl->acl_entries_ipv4);
		if (ACL_DEBUG)
			printf("ACL IPV4 Lookup Mask After = %p\n",
			       (void *)lookup_hit_mask_ipv4);
	}

	/* Merge lookup results since we process both IPv4 and IPv6 below */
	lookup_hit_mask = lookup_hit_mask_ipv4 | lookup_hit_mask_ipv6;
	if (ACL_DEBUG)
		printf("ACL Lookup Mask After = %p\n", (void *)lookup_hit_mask);

	lookup_miss_mask = pkts_mask & (~lookup_hit_mask);
	pkts_mask = lookup_hit_mask;
	p_acl->counters->pkts_drop += __builtin_popcountll(lookup_miss_mask);
	if (ACL_DEBUG)
		printf("pkt_work_acl_key pkts_drop: %" PRIu64 " n_pkts: %u\n",
		       p_acl->counters->pkts_drop,
		       __builtin_popcountll(lookup_miss_mask));

	uint64_t pkts_to_process = lookup_hit_mask;
		/* bitmap of packets left to process for ARP */

	for (; pkts_to_process;) {
		uint8_t pos = (uint8_t) __builtin_ctzll(pkts_to_process);
		uint64_t pkt_mask = 1LLU << pos;
		/* bitmask representing only this packet */

		pkts_to_process &= ~pkt_mask;
		/* remove this packet from remaining list */
		struct rte_mbuf *pkt = pkts[pos];

		if (enable_hwlb)
			if (!check_arp_icmp(pkt, pkt_mask, p_acl)) {
				pkts_mask &= ~(1LLU << pos);
				continue;
			}

		uint8_t hdr_chk =
		    RTE_MBUF_METADATA_UINT8(pkt, MBUF_HDR_ROOM + ETH_HDR_SIZE);
		hdr_chk = hdr_chk >> IP_VERSION_CHECK;

		if (hdr_chk == IPv4_HDR_VERSION) {
			struct acl_table_entry *entry =
			    (struct acl_table_entry *)
			    p_acl->acl_entries_ipv4[pos];
			uint16_t phy_port = entry->head.port_id;
			uint32_t action_id = entry->action_id;

			if (ACL_DEBUG)
				printf("action_id = %u\n", action_id);

			uint32_t dscp_offset =
			    MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DSCP_OFST;

			if (action_array_active[action_id].action_bitmap &
			    acl_action_count) {
				action_counter_table
				    [p_acl->action_counter_index]
				    [action_id].packetCount++;
				action_counter_table
				    [p_acl->action_counter_index]
				    [action_id].byteCount +=
				    rte_pktmbuf_pkt_len(pkt);
				if (ACL_DEBUG)
					printf("Action Count   Packet Count: %"
					       PRIu64 "  Byte Count: %" PRIu64
					       "\n",
					       action_counter_table
					       [p_acl->action_counter_index]
					       [action_id].packetCount,
					       action_counter_table
					       [p_acl->action_counter_index]
					       [action_id].byteCount);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_packet_drop) {

				/* Drop packet by changing the mask */
				if (ACL_DEBUG)
					printf("ACL before drop pkt_mask  "
							"%lu, pkt_num %d\n",
					     pkts_mask, pos);
				pkts_mask &= ~(1LLU << pos);
				if (ACL_DEBUG)
					printf("ACL after drop pkt_mask "
							" %lu, pkt_num %d\n",
					     pkts_mask, pos);
				p_acl->counters->pkts_drop++;
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_fwd) {
				phy_port =
				    action_array_active[action_id].fwd_port;
				entry->head.port_id = phy_port;
				if (ACL_DEBUG)
					printf("Action FWD  Port ID: %u\n",
					       phy_port);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_nat) {
				phy_port =
				    action_array_active[action_id].nat_port;
				entry->head.port_id = phy_port;
				if (ACL_DEBUG)
					printf("Action NAT  Port ID: %u\n",
					       phy_port);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_dscp) {

				/* Set DSCP priority */
				uint8_t *dscp = RTE_MBUF_METADATA_UINT8_PTR(pkt,
							    dscp_offset);
				*dscp =
				    action_array_active[action_id].dscp_priority
				    << 2;
				if (ACL_DEBUG)
					printf
					    ("Action DSCP  DSCP Priority: %u\n",
					     *dscp);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_packet_accept) {
				if (ACL_DEBUG)
					printf("Action Accept\n");

				if (action_array_active[action_id].action_bitmap
				    & acl_action_conntrack) {

					/* Set conntrack bit for this pkt */
					conntrack_mask |= pkt_mask;
					if (ACL_DEBUG)
						printf("ACL Conntrack  "
						"enabled: %p  pkt_mask: %p\n",
						     (void *)conntrack_mask,
						     (void *)pkt_mask);
				}

				if (action_array_active[action_id].action_bitmap
				    & acl_action_connexist) {

					/* Set conntrack bit for this pkt */
					conntrack_mask |= pkt_mask;

		/* Set connexist bit for this pkt for public -> private */
		/* Private -> public packet will open the connection */
					if (action_array_active
					    [action_id].private_public ==
					    acl_public_private)
						connexist_mask |= pkt_mask;

					if (ACL_DEBUG)
						printf("ACL Connexist  "
			"enabled conntrack: %p  connexist: %p  pkt_mask: %p\n",
						     (void *)conntrack_mask,
						     (void *)connexist_mask,
						     (void *)pkt_mask);
				}
			}
		}
#if 0
		if (hdr_chk == IPv6_HDR_VERSION) {

			struct acl_table_entry *entry =
			    (struct acl_table_entry *)
			    p_acl->acl_entries_ipv6[pos];
			uint16_t phy_port = entry->head.port_id;
			uint32_t action_id = entry->action_id;

			if (ACL_DEBUG)
				printf("action_id = %u\n", action_id);

			if (action_array_active[action_id].action_bitmap &
			    acl_action_count) {
				action_counter_table
				    [p_acl->action_counter_index]
				    [action_id].packetCount++;
				action_counter_table
				    [p_acl->action_counter_index]
				    [action_id].byteCount +=
				    rte_pktmbuf_pkt_len(pkt);
				if (ACL_DEBUG)
					printf("Action Count   Packet Count: %"
					       PRIu64 "  Byte Count: %" PRIu64
					       "\n",
					       action_counter_table
					       [p_acl->action_counter_index]
					       [action_id].packetCount,
					       action_counter_table
					       [p_acl->action_counter_index]
					       [action_id].byteCount);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_packet_drop) {
				/* Drop packet by changing the mask */
				if (ACL_DEBUG)
					printf
			    ("ACL before drop pkt_mask %lu, pkt_num %d\n",
					     pkts_mask, pos);
				pkts_mask &= ~(1LLU << pos);
				if (ACL_DEBUG)
					printf
			 ("ACL after drop pkt_mask %lu, pkt_num %d\n",
					     pkts_mask, pos);
				p_acl->counters->pkts_drop++;

			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_fwd) {
				phy_port =
				    action_array_active[action_id].fwd_port;
				entry->head.port_id = phy_port;
				if (ACL_DEBUG)
					printf("Action FWD  Port ID: %u\n",
					       phy_port);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_nat) {
				phy_port =
				    action_array_active[action_id].nat_port;
				entry->head.port_id = phy_port;
				if (ACL_DEBUG)
					printf("Action NAT  Port ID: %u\n",
					       phy_port);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_dscp) {

				/* Set DSCP priority */
				uint32_t dscp_offset =
				    MBUF_HDR_ROOM + ETH_HDR_SIZE +
				    IP_HDR_DSCP_OFST_IPV6;
				uint16_t *dscp =
				    RTE_MBUF_METADATA_UINT16_PTR(pkt,
								 dscp_offset);
				uint16_t dscp_value =
				    (rte_bswap16
				     (RTE_MBUF_METADATA_UINT16
				      (pkt, dscp_offset)) & 0XF00F);
				uint8_t dscp_store =
				    action_array_active[action_id].dscp_priority
				    << 2;
				uint16_t dscp_temp = dscp_store;

				dscp_temp = dscp_temp << 4;
				*dscp = rte_bswap16(dscp_temp | dscp_value);
				if (ACL_DEBUG)
					printf
				    ("Action DSCP   DSCP Priority: %u\n",
					     *dscp);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_packet_accept) {
				if (ACL_DEBUG)
					printf("Action Accept\n");

				if (action_array_active[action_id].action_bitmap
				    & acl_action_conntrack) {

					/* Set conntrack bit for this pkt */
					conntrack_mask |= pkt_mask;
					if (ACL_DEBUG)
						printf("ACL Conntrack  "
						"enabled: %p  pkt_mask: %p\n",
						     (void *)conntrack_mask,
						     (void *)pkt_mask);
				}

				if (action_array_active[action_id].action_bitmap
				    & acl_action_connexist) {

					/* Set conntrack bit for this pkt */
					conntrack_mask |= pkt_mask;

		/* Set connexist bit for this pkt for public -> private */
		/* Private -> public packet will open the connection */
					if (action_array_active
					    [action_id].private_public ==
					    acl_public_private)
						connexist_mask |= pkt_mask;

					if (ACL_DEBUG)
						printf("ACL Connexist enabled  "
				"conntrack: %p  connexist: %p  pkt_mask: %p\n",
						     (void *)conntrack_mask,
						     (void *)connexist_mask,
						     (void *)pkt_mask);
				}
			}
		}
#endif
	}
	/* Only call connection tracker if required */
	if (conntrack_mask > 0) {
		if (ACL_DEBUG)
			printf
			    ("ACL Call Conntrack Before = %p  Connexist = %p\n",
			     (void *)conntrack_mask, (void *)connexist_mask);
		conntrack_mask =
		    rte_ct_cnxn_tracker_batch_lookup_with_new_cnxn_control
		    (p_acl->cnxn_tracker, pkts, conntrack_mask, connexist_mask);
		if (ACL_DEBUG)
			printf("ACL Call Conntrack After = %p\n",
			       (void *)conntrack_mask);

		/* Only change pkt mask for pkts that have conntrack enabled */
		/* Need to loop through packets to check if conntrack enabled */
		pkts_to_process = pkts_mask;
		for (; pkts_to_process;) {
			uint32_t action_id = 0;
			uint8_t pos =
			    (uint8_t) __builtin_ctzll(pkts_to_process);
			uint64_t pkt_mask = 1LLU << pos;
		/* bitmask representing only this packet */

			pkts_to_process &= ~pkt_mask;
		/* remove this packet from remaining list */
			struct rte_mbuf *pkt = pkts[pos];

			uint8_t hdr_chk = RTE_MBUF_METADATA_UINT8(pkt,
								  MBUF_HDR_ROOM
								  +
								  ETH_HDR_SIZE);
			hdr_chk = hdr_chk >> IP_VERSION_CHECK;
			if (hdr_chk == IPv4_HDR_VERSION) {
				struct acl_table_entry *entry =
				    (struct acl_table_entry *)
				    p_acl->acl_entries_ipv4[pos];
				action_id = entry->action_id;
			} else {
				struct acl_table_entry *entry =
				    (struct acl_table_entry *)
				    p_acl->acl_entries_ipv6[pos];
				action_id = entry->action_id;
			}

			if ((action_array_active[action_id].action_bitmap &
			     acl_action_conntrack)
			    || (action_array_active[action_id].action_bitmap &
				acl_action_connexist)) {

				if (conntrack_mask & pkt_mask) {
					if (ACL_DEBUG)
						printf("ACL Conntrack Accept  "
								"packet = %p\n",
						     (void *)pkt_mask);
				} else {
/* Drop packet by changing the mask */
					if (ACL_DEBUG)
						printf("ACL Conntrack Drop  "
								"packet = %p\n",
						     (void *)pkt_mask);
					pkts_mask &= ~pkt_mask;
					p_acl->counters->pkts_drop++;
				}
			}
		}
	}

	pkts_to_process = pkts_mask;
	/* bitmap of packets left to process for ARP */

	for (; pkts_to_process;) {
		uint8_t pos = (uint8_t) __builtin_ctzll(pkts_to_process);
		uint64_t pkt_mask = 1LLU << pos;
	/* bitmask representing only this packet */

		pkts_to_process &= ~pkt_mask;
	/* remove this packet from remaining list */
		struct rte_mbuf *pkt = pkts[pos];

		uint8_t hdr_chk =
		    RTE_MBUF_METADATA_UINT8(pkt, MBUF_HDR_ROOM + ETH_HDR_SIZE);
		hdr_chk = hdr_chk >> IP_VERSION_CHECK;

		if (hdr_chk == IPv4_HDR_VERSION) {

			struct acl_table_entry *entry =
			    (struct acl_table_entry *)
			    p_acl->acl_entries_ipv4[pos];
			//uint16_t phy_port = entry->head.port_id;
			uint16_t phy_port = pkt->port;
			uint32_t *port_out_id =
			    RTE_MBUF_METADATA_UINT32_PTR(pkt,
							 META_DATA_OFFSET +
							 offsetof(struct
							  mbuf_acl_meta_data,
								  output_port));
			/*  *port_out_id = p_acl->links_map[phy_port]; */
/*			if (is_phy_port_privte(phy_port))
				*port_out_id = ACL_PUB_PORT_ID;
			else
				*port_out_id = ACL_PRV_PORT_ID;*/
			if (ACL_DEBUG)
				printf
				   ("phy_port = %i, links_map[phy_port] = %i\n",
				     phy_port, p_acl->links_map[phy_port]);

	/* header room + eth hdr size + dst_adr offset in ip header */
			uint32_t dst_addr_offset =
			    MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST;
			uint32_t *dst_addr =
			    RTE_MBUF_METADATA_UINT32_PTR(pkt, dst_addr_offset);
			uint8_t *eth_dest =
			    RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
			uint8_t *eth_src =
			    RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM + 6);
			struct ether_addr hw_addr;
			uint32_t dest_address = rte_bswap32(*dst_addr);
			uint32_t *nhip = RTE_MBUF_METADATA_UINT32_PTR(pkt,
							      META_DATA_OFFSET
								      +
								      offsetof
								      (struct
						       mbuf_acl_meta_data,
								       nhip));
			uint32_t packet_length = rte_pktmbuf_pkt_len(pkt);
			*nhip = 0;
			if (is_phy_port_privte(phy_port)) {
				dest_address = rte_bswap32(*dst_addr);
				ret =
				    local_get_nh_ipv4(dest_address, &dest_if,
						      nhip, p_acl);
				if (!ret) {
					dest_if =
					    get_prv_to_pub_port(&dest_address,
								IP_VERSION_4);
					do_local_nh_ipv4_cache(dest_if, p_acl);
				}
				*port_out_id = p_acl->port_out_id[dest_if];
			}
			/* port = ACL_PUB_PORT_ID; */
			else {
				dest_address = rte_bswap32(*dst_addr);

				ret = local_get_nh_ipv4(dest_address, &dest_if,
							nhip, p_acl);
				if (!ret) {
					dest_if =
					    get_pub_to_prv_port(&dest_address,
								IP_VERSION_4);
					do_local_nh_ipv4_cache(dest_if, p_acl);
				};
				*port_out_id = p_acl->port_out_id[dest_if];
			}
			/* port = ACL_PRV_PORT_ID; */
			int ret_mac = 0;

			ret_mac = get_dest_mac_addr_port
			    (dest_address, &dest_if, &hw_addr);

			if (ret_mac == ARP_FOUND) {
				if (ACL_DEBUG) {
					printf("MAC found for ip 0x%x, port  "
					"%d - %02x:%02x:%02x:%02x:%02x:%02x\n",
					     dest_address, phy_port,
					     hw_addr.addr_bytes[0],
					     hw_addr.addr_bytes[1],
					     hw_addr.addr_bytes[2],
					     hw_addr.addr_bytes[3],
					     hw_addr.addr_bytes[4],
					     hw_addr.addr_bytes[5]);
					printf("Dest MAC before -  "
					"%02x:%02x:%02x:%02x:%02x:%02x\n",
					     eth_dest[0], eth_dest[1],
					     eth_dest[2], eth_dest[3],
					     eth_dest[4], eth_dest[5]);
				}

				memcpy(eth_dest, &hw_addr,
				       sizeof(struct ether_addr));
				if (ACL_DEBUG) {
					printf("PktP %p, dest_macP %p\n", pkt,
					       eth_dest);
					printf("Dest MAC after -  "
					"%02x:%02x:%02x:%02x:%02x:%02x\n",
					     eth_dest[0], eth_dest[1],
					     eth_dest[2], eth_dest[3],
					     eth_dest[4], eth_dest[5]);
				}
				if (is_phy_port_privte(phy_port))
					memcpy(eth_src,
					       get_link_hw_addr(dest_if),
					       sizeof(struct ether_addr));
				else
					memcpy(eth_src,
					       get_link_hw_addr(dest_if),
					       sizeof(struct ether_addr));
				p_acl->counters->tpkts_processed++;
				p_acl->counters->bytes_processed +=
				    packet_length;
			}

			else {
				if (*nhip != 0) {
					if (ACL_DEBUG)
						printf("ACL requesting ARP for "
							"ip %x, port %d\n",
						     dest_address, phy_port);
					if (ret_mac == ARP_NOT_FOUND)
						request_arp(dest_if, *nhip);

			/*  request_arp(p_acl->links_map[phy_port], *nhip); */
				}
				/* Drop packet by changing the mask */
				if (ACL_DEBUG)
					printf
					    ("ACL before drop pkt_mask  "
							"%lu, pkt_num %d\n",
					     pkts_mask, pos);
				pkts_mask &= ~(1LLU << pos);
				if (ACL_DEBUG)
					printf("ACL after drop pkt_mask  "
							"%lu, pkt_num %d\n",
					     pkts_mask, pos);
				p_acl->counters->pkts_drop++;
			}
		}
#if 0
		if (hdr_chk == IPv6_HDR_VERSION) {

			struct acl_table_entry *entry =
			    (struct acl_table_entry *)
			    p_acl->acl_entries_ipv6[pos];
			uint16_t phy_port = entry->head.port_id;
			uint32_t *port_out_id =
			    RTE_MBUF_METADATA_UINT32_PTR(pkt,
							 META_DATA_OFFSET +
							 offsetof(struct
							  mbuf_acl_meta_data,
								  output_port));
			if (is_phy_port_privte(phy_port))
				*port_out_id = ACL_PUB_PORT_ID;
			else
				*port_out_id = ACL_PRV_PORT_ID;

			/*  *port_out_id = p_acl->links_map[phy_port]; */
			if (ACL_DEBUG)
				printf
			    ("phy_port = %i, links_map[phy_port] = %i\n",
				     phy_port, p_acl->links_map[phy_port]);

	/* header room + eth hdr size + dst_adr offset in ip header */
			uint32_t dst_addr_offset =
			    MBUF_HDR_ROOM + ETH_HDR_SIZE +
			    IP_HDR_DST_ADR_OFST_IPV6;
			uint8_t *eth_dest =
			    RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
			uint8_t *eth_src =
			    RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM + 6);
			struct ether_addr hw_addr;
			uint8_t dest_address[16];
			uint8_t nhip[16];

			nhip[0] =
			    RTE_MBUF_METADATA_UINT8(pkt,
						    META_DATA_OFFSET +
						    offsetof(struct
							     mbuf_acl_meta_data,
							     nhip));
			uint8_t *dst_addr[16];
			uint32_t packet_length = rte_pktmbuf_pkt_len(pkt);
			int i = 0;

			for (i = 0; i < 16; i++) {
				dst_addr[i] =
				    RTE_MBUF_METADATA_UINT8_PTR(pkt,
								dst_addr_offset
								+ i);
			}
			memcpy(dest_address, *dst_addr, sizeof(dest_address));
			memset(nhip, 0, sizeof(nhip));
			if (is_phy_port_privte(phy_port))
				port = ACL_PUB_PORT_ID;
			else
				port = ACL_PRV_PORT_ID;

			if (get_dest_mac_address_ipv6_port
			    (dest_address, port, &hw_addr, &nhip[0])) {
				if (ACL_DEBUG) {

					printf
	    ("MAC found for  port %d - %02x:%02x:%02x:%02x:%02x:%02x\n",
					     phy_port, hw_addr.addr_bytes[0],
					     hw_addr.addr_bytes[1],
					     hw_addr.addr_bytes[2],
					     hw_addr.addr_bytes[3],
					     hw_addr.addr_bytes[4],
					     hw_addr.addr_bytes[5]);
					printf
		    ("Dest MAC before - %02x:%02x:%02x:%02x:%02x:%02x\n",
					     eth_dest[0], eth_dest[1],
					     eth_dest[2], eth_dest[3],
					     eth_dest[4], eth_dest[5]);
				}
				memcpy(eth_dest, &hw_addr,
				       sizeof(struct ether_addr));
				if (ACL_DEBUG) {
					printf("PktP %p, dest_macP %p\n", pkt,
					       eth_dest);
					printf
			    ("Dest MAC after - %02x:%02x:%02x:%02x:%02x:%02x\n",
					     eth_dest[0], eth_dest[1],
					     eth_dest[2], eth_dest[3],
					     eth_dest[4], eth_dest[5]);
				}
				if (is_phy_port_privte(phy_port))
					memcpy(eth_src,
					       get_link_hw_addr(dest_if),
					       sizeof(struct ether_addr));
				else
					memcpy(eth_src,
					       get_link_hw_addr(dest_if),
					       sizeof(struct ether_addr));

		/*
		 * memcpy(eth_src, get_link_hw_addr(p_acl->links_map[phy_port]),
		 * sizeof(struct ether_addr));
		 */
				p_acl->counters->tpkts_processed++;
				p_acl->counters->bytes_processed +=
				    packet_length;
			}

			else {

#if 0
			/* Request next neighbor for Ipv6 is yet to be done. */
				if (*nhip != 0) {
					if (ACL_DEBUG)
						printf
				    ("ACL requesting ARP for ip %x, port %d\n",
						     dest_address, phy_port);

			/* request_arp(p_acl->links_map[phy_port], *nhip); */
				}
#endif
				/* Drop packet by changing the mask */
				if (ACL_DEBUG)
					printf("ACL before drop pkt_mask "
							" %lu, pkt_num %d\n",
					     pkts_mask, pos);
				pkts_mask &= ~(1LLU << pos);
				if (ACL_DEBUG)
					printf("ACL after drop pkt_mask  "
							"%lu, pkt_num %d\n",
					     pkts_mask, pos);
				p_acl->counters->pkts_drop++;
			}
		}
#endif

	}

	pkts_drop_mask = keep_mask & ~pkts_mask;
	rte_pipeline_ah_packet_drop(p, pkts_drop_mask);
	keep_mask = pkts_mask;

	/* don't bother measuring if traffic very low, might skew stats */
	uint32_t packets_this_iteration = __builtin_popcountll(pkts_mask);

	if (packets_this_iteration > 1) {
		uint64_t latency_this_iteration =
		    rte_get_tsc_cycles() - p_acl->in_port_time_stamp;
		p_acl->counters->sum_latencies += latency_this_iteration;
		p_acl->counters->count_latencies++;
	}
	if (ACL_DEBUG)
		printf("Leaving pkt_work_acl_key pkts_mask = %p\n",
		       (void *)pkts_mask);

	return 0;
}

/**
 * Main packet processing function.
 * 64 packet bit mask are used to identify which packets to forward.
 * Performs the following:
 *  - Burst lookup packets in the IPv4 ACL Rule Table.
 *  - Burst lookup packets in the IPv6 ACL Rule Table.
 *  - Lookup Action Table, perform actions.
 *  - Burst lookup Connection Tracking, if enabled.
 *  - Lookup MAC address.
 *  - Set bit mask.
 *  - Packets with bit mask set are forwarded
 *
 * @param p
 *  A pointer to the pipeline.
 * @param pkts
 *  A pointer to a burst of packets.
 * @param n_pkts
 *  Number of packets to process.
 * @param arg
 *  A pointer to pipeline specific data.
 *
 * @return
 *  0 on success, negative on error.
 */
static int
pkt_work_acl_ipv6_key(struct rte_pipeline *p,
		      struct rte_mbuf **pkts, uint32_t n_pkts, void *arg)
{

	struct pipeline_acl *p_acl = arg;

	p_acl->counters->pkts_received =
	    p_acl->counters->pkts_received + n_pkts;
	if (ACL_DEBUG)
		printf("pkt_work_acl_key pkts_received: %" PRIu64
		       " n_pkts: %u\n", p_acl->counters->pkts_received, n_pkts);

	uint64_t lookup_hit_mask = 0;
	uint64_t lookup_hit_mask_ipv4 = 0;
	uint64_t lookup_hit_mask_ipv6 = 0;
	uint64_t lookup_miss_mask = 0;
	uint64_t conntrack_mask = 0;
	uint64_t connexist_mask = 0;
	uint32_t dest_address = 0;
	int dest_if = 0;
	int status;
	uint64_t pkts_drop_mask, pkts_mask = RTE_LEN2MASK(n_pkts, uint64_t);
	uint64_t keep_mask = pkts_mask;
	uint16_t port;
	uint32_t ret;

	p_acl->in_port_time_stamp = rte_get_tsc_cycles();

	if (acl_ipv6_enabled) {
		if (ACL_DEBUG)
			printf("ACL IPV6 Lookup Mask Before = %p\n",
			       (void *)pkts_mask);
		status =
		    rte_table_acl_ops.f_lookup(acl_rule_table_ipv6_active, pkts,
					       pkts_mask, &lookup_hit_mask_ipv6,
					       (void **)
					       p_acl->acl_entries_ipv6);
		if (ACL_DEBUG)
			printf("ACL IPV6 Lookup Mask After = %p\n",
			       (void *)lookup_hit_mask_ipv6);
	}

	/* Merge lookup results since we process both IPv4 and IPv6 below */
	lookup_hit_mask = lookup_hit_mask_ipv4 | lookup_hit_mask_ipv6;
	if (ACL_DEBUG)
		printf("ACL Lookup Mask After = %p\n", (void *)lookup_hit_mask);

	lookup_miss_mask = pkts_mask & (~lookup_hit_mask);
	pkts_mask = lookup_hit_mask;
	p_acl->counters->pkts_drop += __builtin_popcountll(lookup_miss_mask);
	if (ACL_DEBUG)
		printf("pkt_work_acl_key pkts_drop: %" PRIu64 " n_pkts: %u\n",
		       p_acl->counters->pkts_drop,
		       __builtin_popcountll(lookup_miss_mask));

	uint64_t pkts_to_process = lookup_hit_mask;
		/* bitmap of packets left to process for ARP */

	for (; pkts_to_process;) {
		uint8_t pos = (uint8_t) __builtin_ctzll(pkts_to_process);
		uint64_t pkt_mask = 1LLU << pos;
		/* bitmask representing only this packet */

		pkts_to_process &= ~pkt_mask;
		/* remove this packet from remaining list */
		struct rte_mbuf *pkt = pkts[pos];

		if (enable_hwlb)
			if (!check_arp_icmp(pkt, pkt_mask, p_acl)) {
				pkts_mask &= ~(1LLU << pos);
				continue;
			}
		uint8_t hdr_chk =
		    RTE_MBUF_METADATA_UINT8(pkt, MBUF_HDR_ROOM + ETH_HDR_SIZE);
		hdr_chk = hdr_chk >> IP_VERSION_CHECK;
#if 0
		if (hdr_chk == IPv4_HDR_VERSION) {
			struct acl_table_entry *entry =
			    (struct acl_table_entry *)
			    p_acl->acl_entries_ipv4[pos];
			uint16_t phy_port = entry->head.port_id;
			uint32_t action_id = entry->action_id;

			if (ACL_DEBUG)
				printf("action_id = %u\n", action_id);

			uint32_t dscp_offset =
			    MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DSCP_OFST;

			if (action_array_active[action_id].action_bitmap &
			    acl_action_count) {
				action_counter_table
				    [p_acl->action_counter_index]
				    [action_id].packetCount++;
				action_counter_table
				    [p_acl->action_counter_index]
				    [action_id].byteCount +=
				    rte_pktmbuf_pkt_len(pkt);
				if (ACL_DEBUG)
					printf("Action Count   Packet Count: %"
					       PRIu64 "  Byte Count: %" PRIu64
					       "\n",
					       action_counter_table
					       [p_acl->action_counter_index]
					       [action_id].packetCount,
					       action_counter_table
					       [p_acl->action_counter_index]
					       [action_id].byteCount);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_packet_drop) {

				/* Drop packet by changing the mask */
				if (ACL_DEBUG)
					printf
			    ("ACL before drop pkt_mask %lu, pkt_num %d\n",
					     pkts_mask, pos);
				pkts_mask &= ~(1LLU << pos);
				if (ACL_DEBUG)
					printf
			  ("ACL after drop pkt_mask %lu, pkt_num %d\n",
					     pkts_mask, pos);
				p_acl->counters->pkts_drop++;
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_fwd) {
				phy_port =
				    action_array_active[action_id].fwd_port;
				entry->head.port_id = phy_port;
				if (ACL_DEBUG)
					printf("Action FWD  Port ID: %u\n",
					       phy_port);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_nat) {
				phy_port =
				    action_array_active[action_id].nat_port;
				entry->head.port_id = phy_port;
				if (ACL_DEBUG)
					printf("Action NAT  Port ID: %u\n",
					       phy_port);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_dscp) {

				/* Set DSCP priority */
				uint8_t *dscp = RTE_MBUF_METADATA_UINT8_PTR(pkt,
							    dscp_offset);
				*dscp =
				    action_array_active[action_id].dscp_priority
				    << 2;
				if (ACL_DEBUG)
					printf
					    ("Action DSCP  DSCP Priority: %u\n",
					     *dscp);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_packet_accept) {
				if (ACL_DEBUG)
					printf("Action Accept\n");

				if (action_array_active[action_id].action_bitmap
				    & acl_action_conntrack) {

					/* Set conntrack bit for this pkt */
					conntrack_mask |= pkt_mask;
					if (ACL_DEBUG)
						printf("ACL Conntrack enabled: "
							" %p  pkt_mask: %p\n",
						     (void *)conntrack_mask,
						     (void *)pkt_mask);
				}

				if (action_array_active[action_id].action_bitmap
				    & acl_action_connexist) {

					/* Set conntrack bit for this pkt */
					conntrack_mask |= pkt_mask;

		/* Set connexist bit for this pkt for public -> private */
			/* Private -> public packet will open the connection */
					if (action_array_active
					    [action_id].private_public ==
					    acl_public_private)
						connexist_mask |= pkt_mask;

					if (ACL_DEBUG)
						printf("ACL Connexist enabled  "
				"conntrack: %p  connexist: %p  pkt_mask: %p\n",
						     (void *)conntrack_mask,
						     (void *)connexist_mask,
						     (void *)pkt_mask);
				}
			}
		}
#endif

		if (hdr_chk == IPv6_HDR_VERSION) {

			struct acl_table_entry *entry =
			    (struct acl_table_entry *)
			    p_acl->acl_entries_ipv6[pos];
			uint16_t phy_port = entry->head.port_id;
			uint32_t action_id = entry->action_id;

			if (ACL_DEBUG)
				printf("action_id = %u\n", action_id);

			if (action_array_active[action_id].action_bitmap &
			    acl_action_count) {
				action_counter_table
				    [p_acl->action_counter_index]
				    [action_id].packetCount++;
				action_counter_table
				    [p_acl->action_counter_index]
				    [action_id].byteCount +=
				    rte_pktmbuf_pkt_len(pkt);
				if (ACL_DEBUG)
					printf("Action Count   Packet Count: %"
					       PRIu64 "  Byte Count: %" PRIu64
					       "\n",
					       action_counter_table
					       [p_acl->action_counter_index]
					       [action_id].packetCount,
					       action_counter_table
					       [p_acl->action_counter_index]
					       [action_id].byteCount);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_packet_drop) {
				/* Drop packet by changing the mask */
				if (ACL_DEBUG)
					printf("ACL before drop pkt_mask  "
							"%lu, pkt_num %d\n",
					     pkts_mask, pos);
				pkts_mask &= ~(1LLU << pos);
				if (ACL_DEBUG)
					printf("ACL after drop pkt_mask  "
							"%lu, pkt_num %d\n",
					     pkts_mask, pos);
				p_acl->counters->pkts_drop++;

			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_fwd) {
				phy_port =
				    action_array_active[action_id].fwd_port;
				entry->head.port_id = phy_port;
				if (ACL_DEBUG)
					printf("Action FWD  Port ID: %u\n",
					       phy_port);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_nat) {
				phy_port =
				    action_array_active[action_id].nat_port;
				entry->head.port_id = phy_port;
				if (ACL_DEBUG)
					printf("Action NAT  Port ID: %u\n",
					       phy_port);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_dscp) {

				/* Set DSCP priority */
				uint32_t dscp_offset =
				    MBUF_HDR_ROOM + ETH_HDR_SIZE +
				    IP_HDR_DSCP_OFST_IPV6;
				uint16_t *dscp =
				    RTE_MBUF_METADATA_UINT16_PTR(pkt,
								 dscp_offset);
				uint16_t dscp_value =
				    (rte_bswap16
				     (RTE_MBUF_METADATA_UINT16
				      (pkt, dscp_offset)) & 0XF00F);
				uint8_t dscp_store =
				    action_array_active[action_id].dscp_priority
				    << 2;
				uint16_t dscp_temp = dscp_store;

				dscp_temp = dscp_temp << 4;
				*dscp = rte_bswap16(dscp_temp | dscp_value);
				if (ACL_DEBUG)
					printf
					    ("Action DSCP  DSCP Priority: %u\n",
					     *dscp);
			}

			if (action_array_active[action_id].action_bitmap &
			    acl_action_packet_accept) {
				if (ACL_DEBUG)
					printf("Action Accept\n");

				if (action_array_active[action_id].action_bitmap
				    & acl_action_conntrack) {

					/* Set conntrack bit for this pkt */
					conntrack_mask |= pkt_mask;
					if (ACL_DEBUG)
						printf("ACL Conntrack enabled: "
							" %p  pkt_mask: %p\n",
						     (void *)conntrack_mask,
						     (void *)pkt_mask);
				}

				if (action_array_active[action_id].action_bitmap
				    & acl_action_connexist) {

					/* Set conntrack bit for this pkt */
					conntrack_mask |= pkt_mask;

		/* Set connexist bit for this pkt for public -> private */
			/* Private -> public packet will open the connection */
					if (action_array_active
					    [action_id].private_public ==
					    acl_public_private)
						connexist_mask |= pkt_mask;

					if (ACL_DEBUG)
						printf("ACL Connexist enabled "
				"conntrack: %p  connexist: %p  pkt_mask: %p\n",
						     (void *)conntrack_mask,
						     (void *)connexist_mask,
						     (void *)pkt_mask);
				}
			}
		}
	}
	/* Only call connection tracker if required */
	if (conntrack_mask > 0) {
		if (ACL_DEBUG)
			printf
			    ("ACL Call Conntrack Before = %p  Connexist = %p\n",
			     (void *)conntrack_mask, (void *)connexist_mask);
		conntrack_mask =
		    rte_ct_cnxn_tracker_batch_lookup_with_new_cnxn_control
		    (p_acl->cnxn_tracker, pkts, conntrack_mask, connexist_mask);
		if (ACL_DEBUG)
			printf("ACL Call Conntrack After = %p\n",
			       (void *)conntrack_mask);

		/* Only change pkt mask for pkts that have conntrack enabled */
		/* Need to loop through packets to check if conntrack enabled */
		pkts_to_process = pkts_mask;
		for (; pkts_to_process;) {
			uint32_t action_id = 0;
			uint8_t pos =
			    (uint8_t) __builtin_ctzll(pkts_to_process);
			uint64_t pkt_mask = 1LLU << pos;
		/* bitmask representing only this packet */

			pkts_to_process &= ~pkt_mask;
		/* remove this packet from remaining list */
			struct rte_mbuf *pkt = pkts[pos];

			uint8_t hdr_chk = RTE_MBUF_METADATA_UINT8(pkt,
								  MBUF_HDR_ROOM
								  +
								  ETH_HDR_SIZE);
			hdr_chk = hdr_chk >> IP_VERSION_CHECK;
			if (hdr_chk == IPv4_HDR_VERSION) {
				struct acl_table_entry *entry =
				    (struct acl_table_entry *)
				    p_acl->acl_entries_ipv4[pos];
				action_id = entry->action_id;
			} else {
				struct acl_table_entry *entry =
				    (struct acl_table_entry *)
				    p_acl->acl_entries_ipv6[pos];
				action_id = entry->action_id;
			}

			if ((action_array_active[action_id].action_bitmap &
			     acl_action_conntrack)
			    || (action_array_active[action_id].action_bitmap &
				acl_action_connexist)) {

				if (conntrack_mask & pkt_mask) {
					if (ACL_DEBUG)
						printf("ACL Conntrack Accept  "
							"packet = %p\n",
						     (void *)pkt_mask);
				} else {
/* Drop packet by changing the mask */
					if (ACL_DEBUG)
						printf
					    ("ACL Conntrack Drop packet = %p\n",
						     (void *)pkt_mask);
					pkts_mask &= ~pkt_mask;
					p_acl->counters->pkts_drop++;
				}
			}
		}
	}

	pkts_to_process = pkts_mask;
	/* bitmap of packets left to process for ARP */

	for (; pkts_to_process;) {
		uint8_t pos = (uint8_t) __builtin_ctzll(pkts_to_process);
		uint64_t pkt_mask = 1LLU << pos;
	/* bitmask representing only this packet */

		pkts_to_process &= ~pkt_mask;
	/* remove this packet from remaining list */
		struct rte_mbuf *pkt = pkts[pos];

		uint8_t hdr_chk =
		    RTE_MBUF_METADATA_UINT8(pkt, MBUF_HDR_ROOM + ETH_HDR_SIZE);
		hdr_chk = hdr_chk >> IP_VERSION_CHECK;
#if 0
		if (hdr_chk == IPv4_HDR_VERSION) {

			struct acl_table_entry *entry =
			    (struct acl_table_entry *)
			    p_acl->acl_entries_ipv4[pos];
			uint16_t phy_port = entry->head.port_id;
			uint32_t *port_out_id =
			    RTE_MBUF_METADATA_UINT32_PTR(pkt,
							 META_DATA_OFFSET +
							 offsetof(struct
							  mbuf_acl_meta_data,
								  output_port));
			/*  *port_out_id = p_acl->links_map[phy_port]; */
			if (is_phy_port_privte(phy_port))
				*port_out_id = ACL_PUB_PORT_ID;
			else
				*port_out_id = ACL_PRV_PORT_ID;
			if (ACL_DEBUG)
				printf
				    ("phy_port = %i,links_map[phy_port] = %i\n",
				     phy_port, p_acl->links_map[phy_port]);

	/* header room + eth hdr size + dst_adr offset in ip header */
			uint32_t dst_addr_offset =
			    MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST;
			uint32_t *dst_addr =
			    RTE_MBUF_METADATA_UINT32_PTR(pkt, dst_addr_offset);
			uint8_t *eth_dest =
			    RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
			uint8_t *eth_src =
			    RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM + 6);
			struct ether_addr hw_addr;
			uint32_t dest_address = rte_bswap32(*dst_addr);
			uint32_t *nhip = RTE_MBUF_METADATA_UINT32_PTR(pkt,
							      META_DATA_OFFSET
								      +
								      offsetof
								      (struct
						       mbuf_acl_meta_data,
								       nhip));
			uint32_t packet_length = rte_pktmbuf_pkt_len(pkt);
			*nhip = 0;
			if (is_phy_port_privte(phy_port)) {
				dest_address = rte_bswap32(*dst_addr);
				ret =
				    local_get_nh_ipv4(dest_address, &dest_if,
						      nhip, p_acl);
				if (!ret) {
					dest_if =
					    get_prv_to_pub_port(&dest_address,
								IP_VERSION_4);
					do_local_nh_ipv4_cache(dest_if, p_acl);
				}
				*port_out_id = p_acl->port_out_id[dest_if];
			}
			/* port = ACL_PUB_PORT_ID; */
			else {
				dest_address = rte_bswap32(*dst_addr);

				ret = local_get_nh_ipv4(dest_address, &dest_if,
							nhip, p_acl);
				if (!ret) {
					dest_if =
					    get_pub_to_prv_port(&dest_address,
								IP_VERSION_4);
					do_local_nh_ipv4_cache(dest_if, p_acl);
				};
				*port_out_id = p_acl->port_out_id[dest_if];
			}
			/* port = ACL_PRV_PORT_ID; */

			if (get_dest_mac_addr_port
			    (dest_address, &dest_if, &hw_addr)) {
				if (ACL_DEBUG) {
					printf("MAC found for ip 0x%x, port "
					" %d - %02x:%02x:%02x:%02x:%02x:%02x\n",
					     dest_address, phy_port,
					     hw_addr.addr_bytes[0],
					     hw_addr.addr_bytes[1],
					     hw_addr.addr_bytes[2],
					     hw_addr.addr_bytes[3],
					     hw_addr.addr_bytes[4],
					     hw_addr.addr_bytes[5]);
					printf("Dest MAC before -  "
					"%02x:%02x:%02x:%02x:%02x:%02x\n",
					     eth_dest[0], eth_dest[1],
					     eth_dest[2], eth_dest[3],
					     eth_dest[4], eth_dest[5]);
				}

				memcpy(eth_dest, &hw_addr,
				       sizeof(struct ether_addr));
				if (ACL_DEBUG) {
					printf("PktP %p, dest_macP %p\n", pkt,
					       eth_dest);
					printf("Dest MAC after -  "
					"%02x:%02x:%02x:%02x:%02x:%02x\n",
					     eth_dest[0], eth_dest[1],
					     eth_dest[2], eth_dest[3],
					     eth_dest[4], eth_dest[5]);
				}
				if (is_phy_port_privte(phy_port))
					memcpy(eth_src,
					       get_link_hw_addr(dest_if),
					       sizeof(struct ether_addr));
				else
					memcpy(eth_src,
					       get_link_hw_addr(dest_if),
					       sizeof(struct ether_addr));
				p_acl->counters->tpkts_processed++;
				p_acl->counters->bytes_processed +=
				    packet_length;
			}

			else {
				if (*nhip != 0) {

					if (ACL_DEBUG)

						printf("ACL requesting ARP for "
							" ip %x, port %d\n",
						     dest_address, phy_port);
					if (is_phy_port_privte(phy_port))
						request_arp(dest_if, *nhip);

					else
						request_arp(dest_if, *nhip);

			/*  request_arp(p_acl->links_map[phy_port], *nhip); */
				}
				/* Drop packet by changing the mask */
				if (ACL_DEBUG)
					printf("ACL before drop pkt_mask  "
						"%lu, pkt_num %d\n",
					     pkts_mask, pos);
				pkts_mask &= ~(1LLU << pos);
				if (ACL_DEBUG)
					printf("ACL after drop pkt_mask  "
						"%lu, pkt_num %d\n",
					     pkts_mask, pos);
				p_acl->counters->pkts_drop++;
			}
		}
#endif

		if (hdr_chk == IPv6_HDR_VERSION) {

			struct acl_table_entry *entry =
			    (struct acl_table_entry *)
			    p_acl->acl_entries_ipv6[pos];
			//uint16_t phy_port = entry->head.port_id;
			uint16_t phy_port = pkt->port;
			uint32_t *port_out_id =
			    RTE_MBUF_METADATA_UINT32_PTR(pkt,
							 META_DATA_OFFSET +
							 offsetof(struct
							  mbuf_acl_meta_data,
								  output_port));
		/*	if (is_phy_port_privte(phy_port))
				*port_out_id = ACL_PUB_PORT_ID;
			else
				*port_out_id = ACL_PRV_PORT_ID;*/

			/*  *port_out_id = p_acl->links_map[phy_port]; */
			if (ACL_DEBUG)
				printf
				    ("phy_port = %i,links_map[phy_port] = %i\n",
				     phy_port, p_acl->links_map[phy_port]);

	/* header room + eth hdr size + dst_adr offset in ip header */
			uint32_t dst_addr_offset =
			    MBUF_HDR_ROOM + ETH_HDR_SIZE +
			    IP_HDR_DST_ADR_OFST_IPV6;
			uint8_t *eth_dest =
			    RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);
			uint8_t *eth_src =
			    RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM + 6);
			struct ether_addr hw_addr;
			uint8_t dest_address[16];
			uint8_t nhip[16];

			nhip[0] =
			    RTE_MBUF_METADATA_UINT8(pkt,
						    META_DATA_OFFSET +
						    offsetof(struct
							     mbuf_acl_meta_data,
							     nhip));
			uint8_t *dst_addr[16];
			uint32_t packet_length = rte_pktmbuf_pkt_len(pkt);
			int i = 0;

			for (i = 0; i < 16; i++) {
				dst_addr[i] =
				    RTE_MBUF_METADATA_UINT8_PTR(pkt,
								dst_addr_offset
								+ i);
			}
			memcpy(dest_address, *dst_addr, sizeof(dest_address));
			memset(nhip, 0, sizeof(nhip));
			ret = local_get_nh_ipv6(&dest_address[0], &dest_if,
						&nhip[0], p_acl);

			if (is_phy_port_privte(phy_port)) {
				if (!ret) {
					dest_if = get_prv_to_pub_port((
								       uint32_t
								       *)
					      &dest_address[0], IP_VERSION_6);
					do_local_nh_ipv6_cache(dest_if, p_acl);
				}
				//          port = ACL_PUB_PORT_ID;
					*port_out_id =
					    p_acl->port_out_id[dest_if];

			} else {
				if (!ret) {
					dest_if = get_pub_to_prv_port((
								       uint32_t
								       *)
					      &dest_address[0], IP_VERSION_6);
					do_local_nh_ipv6_cache(dest_if, p_acl);
				}
				//           port = ACL_PRV_PORT_ID;
					*port_out_id =
					    p_acl->port_out_id[dest_if];

			}

			if (get_dest_mac_address_ipv6_port
			    (dest_address, &dest_if, &hw_addr, &nhip[0])) {
				if (ACL_DEBUG) {
					printf("MAC found for  port %d  "
					"- %02x:%02x:%02x:%02x:%02x:%02x\n",
					     phy_port, hw_addr.addr_bytes[0],
					     hw_addr.addr_bytes[1],
					     hw_addr.addr_bytes[2],
					     hw_addr.addr_bytes[3],
					     hw_addr.addr_bytes[4],
					     hw_addr.addr_bytes[5]);
					printf("Dest MAC before - "
					" %02x:%02x:%02x:%02x:%02x:%02x\n",
					     eth_dest[0], eth_dest[1],
					     eth_dest[2], eth_dest[3],
					     eth_dest[4], eth_dest[5]);
				}
				memcpy(eth_dest, &hw_addr,
				       sizeof(struct ether_addr));
				if (ACL_DEBUG) {
					printf("PktP %p, dest_macP %p\n", pkt,
					       eth_dest);
					printf("Dest MAC after - "
					" %02x:%02x:%02x:%02x:%02x:%02x\n",
					     eth_dest[0], eth_dest[1],
					     eth_dest[2], eth_dest[3],
					     eth_dest[4], eth_dest[5]);
				}
				if (is_phy_port_privte(phy_port))
					memcpy(eth_src,
					       get_link_hw_addr(dest_if),
					       sizeof(struct ether_addr));
				else
					memcpy(eth_src,
					       get_link_hw_addr(dest_if),
					       sizeof(struct ether_addr));

		/*
		 * memcpy(eth_src, get_link_hw_addr(p_acl->links_map[phy_port]),
		 * sizeof(struct ether_addr));
		 */
				p_acl->counters->tpkts_processed++;
				p_acl->counters->bytes_processed +=
				    packet_length;
			}

			else {

#if 0
			/* Request next neighbor for Ipv6 is yet to be done. */
			if (*nhip != 0) {
			if (ACL_DEBUG)
				printf
				    ("ACL requesting ARP for ip %x, port %d\n",
						     dest_address, phy_port);

			/* request_arp(p_acl->links_map[phy_port], *nhip); */
				}
#endif
				/* Drop packet by changing the mask */
				if (ACL_DEBUG)
					printf("ACL before drop pkt_mask "
						" %lu, pkt_num %d\n",
					     pkts_mask, pos);
				pkts_mask &= ~(1LLU << pos);
				if (ACL_DEBUG)
					printf("ACL after drop pkt_mask "
						" %lu, pkt_num %d\n",
					     pkts_mask, pos);
				p_acl->counters->pkts_drop++;
			}
		}

	}

	pkts_drop_mask = keep_mask & ~pkts_mask;
	rte_pipeline_ah_packet_drop(p, pkts_drop_mask);
	keep_mask = pkts_mask;

	/* don't bother measuring if traffic very low, might skew stats */
	uint32_t packets_this_iteration = __builtin_popcountll(pkts_mask);

	if (packets_this_iteration > 1) {
		uint64_t latency_this_iteration =
		    rte_get_tsc_cycles() - p_acl->in_port_time_stamp;
		p_acl->counters->sum_latencies += latency_this_iteration;
		p_acl->counters->count_latencies++;
	}
	if (ACL_DEBUG)
		printf("Leaving pkt_work_acl_key pkts_mask = %p\n",
		       (void *)pkts_mask);

	return 0;
}

static struct rte_acl_field_def field_format_ipv4[] = {
	/* Protocol */
	[0] = {
	       .type = RTE_ACL_FIELD_TYPE_BITMASK,
	       .size = sizeof(uint8_t),
	       .field_index = 0,
	       .input_index = 0,
	       .offset = sizeof(struct ether_hdr) +
	       offsetof(struct ipv4_hdr, next_proto_id),
	       },

	/* Source IP address (IPv4) */
	[1] = {
	       .type = RTE_ACL_FIELD_TYPE_MASK,
	       .size = sizeof(uint32_t),
	       .field_index = 1,
	       .input_index = 1,
	       .offset = sizeof(struct ether_hdr) +
	       offsetof(struct ipv4_hdr, src_addr),
	       },

	/* Destination IP address (IPv4) */
	[2] = {
	       .type = RTE_ACL_FIELD_TYPE_MASK,
	       .size = sizeof(uint32_t),
	       .field_index = 2,
	       .input_index = 2,
	       .offset = sizeof(struct ether_hdr) +
	       offsetof(struct ipv4_hdr, dst_addr),
	       },

	/* Source Port */
	[3] = {
	       .type = RTE_ACL_FIELD_TYPE_RANGE,
	       .size = sizeof(uint16_t),
	       .field_index = 3,
	       .input_index = 3,
	       .offset = sizeof(struct ether_hdr) +
	       sizeof(struct ipv4_hdr) + offsetof(struct tcp_hdr, src_port),
	       },

	/* Destination Port */
	[4] = {
	       .type = RTE_ACL_FIELD_TYPE_RANGE,
	       .size = sizeof(uint16_t),
	       .field_index = 4,
	       .input_index = 3,
	       .offset = sizeof(struct ether_hdr) +
	       sizeof(struct ipv4_hdr) + offsetof(struct tcp_hdr, dst_port),
	       },
};

#define SIZEOF_VLAN_HDR                          4

static struct rte_acl_field_def field_format_vlan_ipv4[] = {
	/* Protocol */
	[0] = {
	       .type = RTE_ACL_FIELD_TYPE_BITMASK,
	       .size = sizeof(uint8_t),
	       .field_index = 0,
	       .input_index = 0,
	       .offset = sizeof(struct ether_hdr) +
	       SIZEOF_VLAN_HDR + offsetof(struct ipv4_hdr, next_proto_id),
	       },

	/* Source IP address (IPv4) */
	[1] = {
	       .type = RTE_ACL_FIELD_TYPE_MASK,
	       .size = sizeof(uint32_t),
	       .field_index = 1,
	       .input_index = 1,
	       .offset = sizeof(struct ether_hdr) +
	       SIZEOF_VLAN_HDR + offsetof(struct ipv4_hdr, src_addr),
	       },

	/* Destination IP address (IPv4) */
	[2] = {
	       .type = RTE_ACL_FIELD_TYPE_MASK,
	       .size = sizeof(uint32_t),
	       .field_index = 2,
	       .input_index = 2,
	       .offset = sizeof(struct ether_hdr) +
	       SIZEOF_VLAN_HDR + offsetof(struct ipv4_hdr, dst_addr),
	       },

	/* Source Port */
	[3] = {
	       .type = RTE_ACL_FIELD_TYPE_RANGE,
	       .size = sizeof(uint16_t),
	       .field_index = 3,
	       .input_index = 3,
	       .offset = sizeof(struct ether_hdr) +
	       SIZEOF_VLAN_HDR +
	       sizeof(struct ipv4_hdr) + offsetof(struct tcp_hdr, src_port),
	       },

	/* Destination Port */
	[4] = {
	       .type = RTE_ACL_FIELD_TYPE_RANGE,
	       .size = sizeof(uint16_t),
	       .field_index = 4,
	       .input_index = 4,
	       .offset = sizeof(struct ether_hdr) +
	       SIZEOF_VLAN_HDR +
	       sizeof(struct ipv4_hdr) + offsetof(struct tcp_hdr, dst_port),
	       },
};

#define SIZEOF_QINQ_HEADER                       8

static struct rte_acl_field_def field_format_qinq_ipv4[] = {
	/* Protocol */
	[0] = {
	       .type = RTE_ACL_FIELD_TYPE_BITMASK,
	       .size = sizeof(uint8_t),
	       .field_index = 0,
	       .input_index = 0,
	       .offset = sizeof(struct ether_hdr) +
	       SIZEOF_QINQ_HEADER + offsetof(struct ipv4_hdr, next_proto_id),
	       },

	/* Source IP address (IPv4) */
	[1] = {
	       .type = RTE_ACL_FIELD_TYPE_MASK,
	       .size = sizeof(uint32_t),
	       .field_index = 1,
	       .input_index = 1,
	       .offset = sizeof(struct ether_hdr) +
	       SIZEOF_QINQ_HEADER + offsetof(struct ipv4_hdr, src_addr),
	       },

	/* Destination IP address (IPv4) */
	[2] = {
	       .type = RTE_ACL_FIELD_TYPE_MASK,
	       .size = sizeof(uint32_t),
	       .field_index = 2,
	       .input_index = 2,
	       .offset = sizeof(struct ether_hdr) +
	       SIZEOF_QINQ_HEADER + offsetof(struct ipv4_hdr, dst_addr),
	       },

	/* Source Port */
	[3] = {
	       .type = RTE_ACL_FIELD_TYPE_RANGE,
	       .size = sizeof(uint16_t),
	       .field_index = 3,
	       .input_index = 3,
	       .offset = sizeof(struct ether_hdr) +
	       SIZEOF_QINQ_HEADER +
	       sizeof(struct ipv4_hdr) + offsetof(struct tcp_hdr, src_port),
	       },

	/* Destination Port */
	[4] = {
	       .type = RTE_ACL_FIELD_TYPE_RANGE,
	       .size = sizeof(uint16_t),
	       .field_index = 4,
	       .input_index = 4,
	       .offset = sizeof(struct ether_hdr) +
	       SIZEOF_QINQ_HEADER +
	       sizeof(struct ipv4_hdr) + offsetof(struct tcp_hdr, dst_port),
	       },
};

static struct rte_acl_field_def field_format_ipv6[] = {
	/* Protocol */
	[0] = {
	       .type = RTE_ACL_FIELD_TYPE_BITMASK,
	       .size = sizeof(uint8_t),
	       .field_index = 0,
	       .input_index = 0,
	       .offset = sizeof(struct ether_hdr) +
	       offsetof(struct ipv6_hdr, proto),
	       },

	/* Source IP address (IPv6) */
	[1] = {
	       .type = RTE_ACL_FIELD_TYPE_MASK,
	       .size = sizeof(uint32_t),
	       .field_index = 1,
	       .input_index = 1,
	       .offset = sizeof(struct ether_hdr) +
	       offsetof(struct ipv6_hdr, src_addr),
	       },

	[2] = {
	       .type = RTE_ACL_FIELD_TYPE_MASK,
	       .size = sizeof(uint32_t),
	       .field_index = 2,
	       .input_index = 2,
	       .offset = sizeof(struct ether_hdr) +
	       offsetof(struct ipv6_hdr, src_addr) + sizeof(uint32_t),
	}
	,

	[3] = {
	       .type = RTE_ACL_FIELD_TYPE_MASK,
	       .size = sizeof(uint32_t),
	       .field_index = 3,
	       .input_index = 3,
	       .offset = sizeof(struct ether_hdr) +
	       offsetof(struct ipv6_hdr, src_addr) + 2 * sizeof(uint32_t),
	}
	,

	[4] = {
	       .type = RTE_ACL_FIELD_TYPE_MASK,
	       .size = sizeof(uint32_t),
	       .field_index = 4,
	       .input_index = 4,
	       .offset = sizeof(struct ether_hdr) +
	       offsetof(struct ipv6_hdr, src_addr) + 3 * sizeof(uint32_t),
	}
	,

	/* Destination IP address (IPv6) */
	[5] = {
	       .type = RTE_ACL_FIELD_TYPE_MASK,
	       .size = sizeof(uint32_t),
	       .field_index = 5,
	       .input_index = 5,
	       .offset = sizeof(struct ether_hdr) +
	       offsetof(struct ipv6_hdr, dst_addr),
	       },

	[6] = {
	       .type = RTE_ACL_FIELD_TYPE_MASK,
	       .size = sizeof(uint32_t),
	       .field_index = 6,
	       .input_index = 6,
	       .offset = sizeof(struct ether_hdr) +
	       offsetof(struct ipv6_hdr, dst_addr) + sizeof(uint32_t),
	}
	,

	[7] = {
	       .type = RTE_ACL_FIELD_TYPE_MASK,
	       .size = sizeof(uint32_t),
	       .field_index = 7,
	       .input_index = 7,
	       .offset = sizeof(struct ether_hdr) +
	       offsetof(struct ipv6_hdr, dst_addr) + 2 * sizeof(uint32_t),
	}
	,

	[8] = {
	       .type = RTE_ACL_FIELD_TYPE_MASK,
	       .size = sizeof(uint32_t),
	       .field_index = 8,
	       .input_index = 8,
	       .offset = sizeof(struct ether_hdr) +
	       offsetof(struct ipv6_hdr, dst_addr) + 3 * sizeof(uint32_t),
	}
	,

	/* Source Port */
	[9] = {
	       .type = RTE_ACL_FIELD_TYPE_RANGE,
	       .size = sizeof(uint16_t),
	       .field_index = 9,
	       .input_index = 9,
	       .offset = sizeof(struct ether_hdr) +
	       sizeof(struct ipv6_hdr) + offsetof(struct tcp_hdr, src_port),
	       },

	/* Destination Port */
	[10] = {
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = 10,
		.input_index = 9,
		.offset = sizeof(struct ether_hdr) +
		sizeof(struct ipv6_hdr) + offsetof(struct tcp_hdr, dst_port),
		},
};

/**
 * Parse arguments in config file.
 *
 * @param p
 *  A pointer to the pipeline.
 * @param params
 *  A pointer to pipeline specific parameters.
 *
 * @return
 *  0 on success, negative on error.
 */
static int
pipeline_acl_parse_args(struct pipeline_acl *p, struct pipeline_params *params)
{
	uint32_t n_rules_present = 0;
	uint32_t pkt_type_present = 0;
	uint32_t i;
	uint8_t prv_que_handler_present = 0;
	uint8_t n_prv_in_port = 0;

	/* defaults */
	p->n_rules = 4 * 1024;
	acl_n_rules = 4 * 1024;
	p->n_rule_fields = RTE_DIM(field_format_ipv4);
	p->field_format = field_format_ipv4;
	p->field_format_size = sizeof(field_format_ipv4);

	for (i = 0; i < params->n_args; i++) {
		char *arg_name = params->args_name[i];
		char *arg_value = params->args_value[i];

		if (strcmp(arg_name, "n_rules") == 0) {
			if (n_rules_present)
				return -1;
			n_rules_present = 1;

			p->n_rules = atoi(arg_value);
			acl_n_rules = atoi(arg_value);
			continue;
		}

		if (strcmp(arg_name, "pkt_type") == 0) {
			if (pkt_type_present)
				return -1;
			pkt_type_present = 1;

			/* ipv4 */
			if (strcmp(arg_value, "ipv4") == 0) {
				p->n_rule_fields = RTE_DIM(field_format_ipv4);
				p->field_format = field_format_ipv4;
				p->field_format_size =
				    sizeof(field_format_ipv4);
				continue;
			}

			/* vlan_ipv4 */
			if (strcmp(arg_value, "vlan_ipv4") == 0) {
				p->n_rule_fields =
				    RTE_DIM(field_format_vlan_ipv4);
				p->field_format = field_format_vlan_ipv4;
				p->field_format_size =
				    sizeof(field_format_vlan_ipv4);
				continue;
			}

			/* qinq_ipv4 */
			if (strcmp(arg_value, "qinq_ipv4") == 0) {
				p->n_rule_fields =
				    RTE_DIM(field_format_qinq_ipv4);
				p->field_format = field_format_qinq_ipv4;
				p->field_format_size =
				    sizeof(field_format_qinq_ipv4);
				continue;
			}

			/* ipv6 */
			if (strcmp(arg_value, "ipv6") == 0) {
				p->n_rule_fields = RTE_DIM(field_format_ipv6);
				p->field_format = field_format_ipv6;
				p->field_format_size =
				    sizeof(field_format_ipv6);
				continue;
			}

			/* other */
			return -1;
		}
		/* traffic_type */
		if (strcmp(arg_name, "traffic_type") == 0) {
			int traffic_type = atoi(arg_value);

			if (traffic_type == 0
			    || !(traffic_type == IPv4_HDR_VERSION
				 || traffic_type == IPv6_HDR_VERSION)) {
				printf("not IPVR4/IPVR6");
				return -1;
			}

			p->traffic_type = traffic_type;
			continue;
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

			if (token == NULL){
				printf("string is null\n");
				printf("prv_que_handler is invalid\n");
				return -1;
			}
			printf("string is :%s\n", token);

			while (token != NULL) {
				printf(" %s\n", token);
				rxport = atoi(token);
				acl_prv_que_port_index[n_prv_in_port++] =
				    rxport;
				token = strtok(NULL, ",");
			}

			if (n_prv_in_port == 0) {
			printf("VNF common parse err  - no prv RX phy port\n");
				return -1;
			}
			continue;
		}

		/* n_flows */
		if (strcmp(arg_name, "n_flows") == 0) {
			p->n_flows = atoi(arg_value);
			if (p->n_flows == 0)
				return -1;

			continue;/* needed when multiple parms are checked */
		}

	}

	return 0;
}

/**
 * Create and initialize Pipeline Back End (BE).
 *
 * @param params
 *  A pointer to the pipeline.
 * @param arg
 *  A pointer to pipeline specific data.
 *
 * @return
 *  A pointer to the pipeline create, NULL on error.
 */
static void *pipeline_acl_init(struct pipeline_params *params,
			       __rte_unused void *arg)
{
	struct pipeline *p;
	struct pipeline_acl *p_acl;
	uint32_t size, i;

	/* Check input arguments */
	if ((params == NULL) ||
	    (params->n_ports_in == 0) || (params->n_ports_out == 0))
		return NULL;

	/* Memory allocation */
	size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct pipeline_acl));
	p = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
	p_acl = (struct pipeline_acl *)p;
	if (p == NULL)
		return NULL;

	strcpy(p->name, params->name);
	p->log_level = params->log_level;

	PLOG(p, HIGH, "ACL");

	/*
	 *  p_acl->links_map[0] = 0xff;
	 *  p_acl->links_map[1] = 0xff;]
	 */
	p_acl->traffic_type = MIX;
	for (i = 0; i < PIPELINE_MAX_PORT_IN; i++) {
		p_acl->links_map[i] = 0xff;
		p_acl->port_out_id[i] = 0xff;
		acl_prv_que_port_index[i] = 0;
	}

	p_acl->pipeline_num = 0xff;

	/* if(enable_hwlb || enable_flow_dir) */
//        lib_arp_init(params, arg);

	p_acl->n_flows = 4096;	/* small default value */
	/* Create a single firewall instance and initialize. */
	p_acl->cnxn_tracker =
	    rte_zmalloc(NULL, rte_ct_get_cnxn_tracker_size(),
			RTE_CACHE_LINE_SIZE);

	if (p_acl->cnxn_tracker == NULL)
		return NULL;

	/*
	 * Now allocate a counter block entry.It appears that the initialization
	 * of all instances is serialized on core 0, so no lock is necessary.
	 */
	struct rte_ACL_counter_block *counter_ptr;

	if (rte_ACL_hi_counter_block_in_use == MAX_ACL_INSTANCES) {
		/* error, exceeded table bounds */
		return NULL;
	}

	rte_ACL_hi_counter_block_in_use++;
	counter_ptr = &rte_acl_counter_table[rte_ACL_hi_counter_block_in_use];
	strcpy(counter_ptr->name, params->name);
	p_acl->action_counter_index = rte_ACL_hi_counter_block_in_use;

	p_acl->counters = counter_ptr;

	rte_ct_initialize_default_timeouts(p_acl->cnxn_tracker);
	p_acl->arpPktCount = 0;

	/* Parse arguments */
	if (pipeline_acl_parse_args(p_acl, params))
		return NULL;
	/*n_flows already checked, ignore Klockwork issue */
	if (p_acl->n_flows > 0) {
		rte_ct_initialize_cnxn_tracker(p_acl->cnxn_tracker,
					       p_acl->n_flows, params->name);
		p_acl->counters->ct_counters =
		    rte_ct_get_counter_address(p_acl->cnxn_tracker);
	} else {
		printf("ACL invalid p_acl->n_flows: %u\n", p_acl->n_flows);
		return NULL;
	}

	/* Pipeline */
	{
		struct rte_pipeline_params pipeline_params = {
			.name = params->name,
			.socket_id = params->socket_id,
			.offset_port_id = META_DATA_OFFSET +
			    offsetof(struct mbuf_acl_meta_data, output_port),
		};

		p->p = rte_pipeline_create(&pipeline_params);
		if (p->p == NULL) {
			rte_free(p);
			return NULL;
		}
	}

	/* Input ports */
	p->n_ports_in = params->n_ports_in;
	for (i = 0; i < p->n_ports_in; i++) {
		struct rte_pipeline_port_in_params port_params = {
			.ops =
			    pipeline_port_in_params_get_ops(&params->port_in
							    [i]),
			.arg_create =
			    pipeline_port_in_params_convert(&params->port_in
							    [i]),
			.f_action = pkt_work_acl_key,
			.arg_ah = p_acl,
			.burst_size = params->port_in[i].burst_size,
		};
		if (p_acl->traffic_type == IPv4_HDR_VERSION)
			port_params.f_action = pkt_work_acl_ipv4_key;

		if (p_acl->traffic_type == IPv6_HDR_VERSION)
			port_params.f_action = pkt_work_acl_ipv6_key;

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
			.ops =
			    pipeline_port_out_params_get_ops(&params->port_out
							     [i]),
			.arg_create =
			    pipeline_port_out_params_convert(&params->port_out
							     [i]),
			.f_action = NULL,
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

	int temp = sscanf(params->name, "PIPELINE%d", &pipeline_num);
	p_acl->pipeline_num = (uint8_t) pipeline_num;
/*	set_phy_outport_map(p_acl->pipeline_num, p_acl->links_map);*/
	register_pipeline_Qs(p_acl->pipeline_num, p);
	set_link_map(p_acl->pipeline_num, p, p_acl->links_map);
	set_outport_id(p_acl->pipeline_num, p, p_acl->port_out_id);

	/* If this is the first ACL thread, create common ACL Rule tables */
	if (rte_ACL_hi_counter_block_in_use == 0) {

		printf("Create ACL Tables rte_socket_id(): %i\n",
		       rte_socket_id());

		/* Create IPV4 ACL Rule Tables */
		struct rte_table_acl_params common_ipv4_table_acl_params = {
			.name = "ACLIPV4A",
			.n_rules = acl_n_rules,
			.n_rule_fields = RTE_DIM(field_format_ipv4),
		};

		memcpy(common_ipv4_table_acl_params.field_format,
		       field_format_ipv4, sizeof(field_format_ipv4));

		uint32_t ipv4_entry_size = sizeof(struct acl_table_entry);

		acl_rule_table_ipv4_active =
		    rte_table_acl_ops.f_create(&common_ipv4_table_acl_params,
					       rte_socket_id(),
					       ipv4_entry_size);

		if (acl_rule_table_ipv4_active == NULL) {
			printf
			    ("Failed to create common ACL IPV4A Rule table\n");
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}

		/* Create second IPV4 Table */
		common_ipv4_table_acl_params.name = "ACLIPV4B";
		acl_rule_table_ipv4_standby =
		    rte_table_acl_ops.f_create(&common_ipv4_table_acl_params,
					       rte_socket_id(),
					       ipv4_entry_size);

		if (acl_rule_table_ipv4_standby == NULL) {
			printf
			    ("Failed to create common ACL IPV4B Rule table\n");
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}

		/* Create IPV6 ACL Rule Tables */
		struct rte_table_acl_params common_ipv6_table_acl_params = {
			.name = "ACLIPV6A",
			.n_rules = acl_n_rules,
			.n_rule_fields = RTE_DIM(field_format_ipv6),
		};

		memcpy(common_ipv6_table_acl_params.field_format,
		       field_format_ipv6, sizeof(field_format_ipv6));

		uint32_t ipv6_entry_size = sizeof(struct acl_table_entry);

		acl_rule_table_ipv6_active =
		    rte_table_acl_ops.f_create(&common_ipv6_table_acl_params,
					       rte_socket_id(),
					       ipv6_entry_size);

		if (acl_rule_table_ipv6_active == NULL) {
			printf
			    ("Failed to create common ACL IPV6A Rule table\n");
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}

		/* Create second IPV6 table */
		common_ipv6_table_acl_params.name = "ACLIPV6B";
		acl_rule_table_ipv6_standby =
		    rte_table_acl_ops.f_create(&common_ipv6_table_acl_params,
					       rte_socket_id(),
					       ipv6_entry_size);

		if (acl_rule_table_ipv6_standby == NULL) {
			printf
			    ("Failed to create common ACL IPV6B Rule table\n");
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}
	}

	/* Tables */
	p->n_tables = 1;
	{

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

		status = rte_pipeline_table_default_entry_add(p->p,
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
	memcpy(p_acl->custom_handlers,
	       custom_handlers, sizeof(p_acl->custom_handlers));

	return p;
}

/**
 * Free resources and delete pipeline.
 *
 * @param p
 *  A pointer to the pipeline.
 *
 * @return
 *  0 on success, negative on error.
 */
static int pipeline_acl_free(void *pipeline)
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

/**
 * Callback function to map input/output ports.
 *
 * @param pipeline
 *  A pointer to the pipeline.
 * @param port_in
 *  Input port ID
 * @param port_out
 *  A pointer to the Output port.
 *
 * @return
 *  0 on success, negative on error.
 */
static int
pipeline_acl_track(void *pipeline,
		   __rte_unused uint32_t port_in, uint32_t *port_out)
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
 * Callback function to process timers.
 *
 * @param pipeline
 *  A pointer to the pipeline.
 *
 * @return
 *  0 on success, negative on error.
 */
static int pipeline_acl_timer(void *pipeline)
{

	struct pipeline *p = (struct pipeline *)pipeline;
	struct pipeline_acl *p_acl = (struct pipeline_acl *)pipeline;

	pipeline_msg_req_handle(p);
	rte_pipeline_flush(p->p);

	rte_ct_handle_expired_timers(p_acl->cnxn_tracker);

	return 0;
}

/**
 * Callback function to process CLI commands from FE.
 *
 * @param p
 *  A pointer to the pipeline.
 * @param msg
 *  A pointer to command specific data.
 *
 * @return
 *  A pointer to message handler on success,
 *  pipeline_msg_req_invalid_hander on error.
 */
void *pipeline_acl_msg_req_custom_handler(struct pipeline *p, void *msg)
{
	struct pipeline_acl *p_acl = (struct pipeline_acl *)p;
	struct pipeline_custom_msg_req *req = msg;
	pipeline_msg_req_handler f_handle;

	f_handle = (req->subtype < PIPELINE_ACL_MSG_REQS) ?
	    p_acl->custom_handlers[req->subtype] :
	    pipeline_msg_req_invalid_handler;

	if (f_handle == NULL)
		f_handle = pipeline_msg_req_invalid_handler;

	return f_handle(p, req);
}

/**
 * Handler for DBG CLI command.
 *
 * @param p
 *  A pointer to the pipeline.
 * @param msg
 *  A pointer to command specific data.
 *
 * @return
 *  A pointer to response message.
 *  Response message contains status.
 */
void *pipeline_acl_msg_req_dbg_handler(struct pipeline *p, void *msg)
{
	(void)p;
	struct pipeline_acl_dbg_msg_req *req = msg;
	struct pipeline_acl_dbg_msg_rsp *rsp = msg;

	if (req->dbg == 0) {
		printf("DBG turned OFF\n");
		ACL_DEBUG = 0;
		rsp->status = 0;
	} else if (req->dbg == 1) {
		printf("DBG turned ON\n");
		ACL_DEBUG = 1;
		rsp->status = 0;
	} else {
		printf("Invalid DBG setting\n");
		rsp->status = -1;
	}

	return rsp;
}

struct pipeline_be_ops pipeline_acl_be_ops = {
	.f_init = pipeline_acl_init,
	.f_free = pipeline_acl_free,
	.f_run = NULL,
	.f_timer = pipeline_acl_timer,
	.f_track = pipeline_acl_track,
};
