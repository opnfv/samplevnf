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
 * Pipeline VFW BE Implementation.
 *
 * Implementation of Pipeline VFW Back End (BE).
 * Responsible for packet processing.
 *
 */

#define EN_SWP_ACL 1
//#define EN_SWP_ARP 1

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_byteorder.h>

#include <rte_table_lpm.h>
#include <rte_table_hash.h>
#include <rte_table_array.h>
#include <rte_table_acl.h>
#include <rte_table_stub.h>
#include <rte_timer.h>
#include <rte_cycles.h>
#include <rte_pipeline.h>
#include <rte_spinlock.h>
#include <rte_prefetch.h>
#include "pipeline_actions_common.h"
#include "hash_func.h"
#include "pipeline_vfw.h"
#include "pipeline_vfw_be.h"
#include "rte_cnxn_tracking.h"
#include "pipeline_arpicmp_be.h"
#include "vnf_common.h"
#include "vnf_define.h"

#include "lib_arp.h"
#include "lib_icmpv6.h"
#include "pipeline_common_fe.h"
#include "gateway.h"

uint32_t timer_lcore;

uint8_t firewall_flag = 1;
uint8_t VFW_DEBUG = 0;
uint8_t cnxn_tracking_is_active = 1;
/**
 * A structure defining the VFW pipeline input port per thread data.
 */
struct vfw_ports_in_args {
       struct pipeline *pipe;
       struct rte_ct_cnxn_tracker *cnxn_tracker;
} __rte_cache_aligned;
/**
 * A structure defining the VFW pipeline per thread data.
 */
struct pipeline_vfw {
       struct pipeline pipe;
       pipeline_msg_req_handler custom_handlers[PIPELINE_VFW_MSG_REQS];

       struct rte_ct_cnxn_tracker *cnxn_tracker;
       struct rte_VFW_counter_block *counters;
       struct rte_mbuf *pkt_buffer[PKT_BUFFER_SIZE];
       struct lib_acl *plib_acl;
       /* timestamp retrieved during in-port computations */
       uint32_t n_flows;
       uint8_t pipeline_num;
       uint8_t traffic_type;
       uint8_t links_map[PIPELINE_MAX_PORT_IN];
       uint8_t outport_id[PIPELINE_MAX_PORT_IN];

} __rte_cache_aligned;
/**
 * A structure defining the mbuf meta data for VFW.
 */
struct mbuf_tcp_meta_data {
/* output port stored for RTE_PIPELINE_ACTION_PORT_META */
       uint32_t output_port;
       struct rte_mbuf *next;       /* next pointer for chained buffers */
} __rte_cache_aligned;

#define DONT_CARE_TCP_PACKET 0
#define IS_NOT_TCP_PACKET 0
#define IS_TCP_PACKET 1

#define META_DATA_OFFSET 128

#define RTE_PKTMBUF_HEADROOM 128       /* where is this defined ? */
#define ETHERNET_START (META_DATA_OFFSET + RTE_PKTMBUF_HEADROOM)
#define ETH_HDR_SIZE 14
#define PROTOCOL_START (IP_START + 9)

#define TCP_START (IP_START + 20)
#define RTE_LB_PORT_OFFSET 204       /* TODO: Need definition in LB header */
#define TCP_START_IPV6 (IP_START + 40)
#define PROTOCOL_START_IPV6 (IP_START + 6)
#define IP_HDR_DSCP_OFST 1

#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17

#define DELETE_BUFFERED_PACKETS 0
#define FORWARD_BUFFERED_PACKETS 1
#define DO_ARP 1
#define NO_ARP 0

#define IPv4_HEADER_SIZE 20
#define IPv6_HEADER_SIZE 40

#define IP_VERSION_4 4
#define IP_VERSION_6 6

/* IPv6 */
#define IP_HDR_SIZE_IPV6  40
#define IP_HDR_DSCP_OFST_IPV6 0
#define IP_HDR_LENGTH_OFST_IPV6 4
#define IP_HDR_PROTOCOL_OFST_IPV6 6
#define IP_HDR_DST_ADR_OFST_IPV6 24
#define MAX_NUM_LOCAL_MAC_ADDRESS 16
/** The counter table for VFW pipeline per thread data.*/
struct rte_VFW_counter_block rte_vfw_counter_table[MAX_VFW_INSTANCES]
__rte_cache_aligned;
int rte_VFW_hi_counter_block_in_use = -1;

/* a spin lock used during vfw initialization only */
rte_spinlock_t rte_VFW_init_lock = RTE_SPINLOCK_INITIALIZER;

/* Action Array */
struct pipeline_action_key *action_array_a;
struct pipeline_action_key *action_array_b;
struct pipeline_action_key *action_array_active;
struct pipeline_action_key *action_array_standby;
uint32_t action_array_size;
struct action_counter_block
action_counter_table[MAX_VFW_INSTANCES][action_array_max]
__rte_cache_aligned;
/*
  * Pipeline table strategy for firewall. Unfortunately, there does not seem to
  * be any use for the built-in table lookup of ip_pipeline for the firewall.
  * The main table requirement of the firewall is the hash table to maintain
  * connection info, but that is implemented seperately in the connection
  * tracking library. So a "dummy" table lookup will be performed.
  * TODO: look into "stub" table and see if that can be used
  * to avoid useless table lookup
  */
uint64_t arp_pkts_mask;

/* Start TSC measurement */
/* Prefetch counters and pipe before this function */
static inline void start_tsc_measure(struct pipeline_vfw *vfw_pipe) {
       vfw_pipe->counters->entry_timestamp = rte_get_tsc_cycles();
       if (likely(vfw_pipe->counters->exit_timestamp))
              vfw_pipe->counters->external_time_sum +=
                     vfw_pipe->counters->entry_timestamp -
                     vfw_pipe->counters->exit_timestamp;
}

/* End TSC measurement */
static inline void end_tsc_measure(
       struct pipeline_vfw *vfw_pipe,
       uint8_t n_pkts)
{
       if (likely(n_pkts > 1)) {
              vfw_pipe->counters->exit_timestamp = rte_get_tsc_cycles();
              vfw_pipe->counters->internal_time_sum +=
                     vfw_pipe->counters->exit_timestamp -
                     vfw_pipe->counters->entry_timestamp;
              vfw_pipe->counters->time_measurements++;
       } else {
              /* small counts skew results, ignore */
              vfw_pipe->counters->exit_timestamp = 0;
       }
}

/**
 * Print packet for debugging.
 *
 * @param pkt
 *  A pointer to the packet.
 *
 */
static __rte_unused  void print_pkt(struct rte_mbuf *pkt)
{
       int i;
       int size = (int)sizeof(struct mbuf_tcp_meta_data);
       uint8_t *rd = RTE_MBUF_METADATA_UINT8_PTR(pkt, META_DATA_OFFSET);

       printf("Meta-data:\n");
       for (i = 0; i < size; i++) {
              printf("%02x ", rd[i]);
              if ((i & TWO_BYTE_PRINT) == TWO_BYTE_PRINT)
                     printf("\n");
       }
       printf("\n");
       printf("IP and TCP/UDP headers:\n");
       rd = RTE_MBUF_METADATA_UINT8_PTR(pkt, IP_START);
       for (i = 0; i < IP_HDR_SIZE_IPV6; i++) {
              printf("%02x ", rd[i]);
              if ((i & TWO_BYTE_PRINT) == TWO_BYTE_PRINT)
                     printf("\n");
       }
       printf("\n");
}

/* TODO: are the protocol numbers defined somewhere with meaningful names? */
#define IP_ICMP_PROTOCOL 1
#define IP_TCP_PROTOCOL 6
#define IP_UDP_PROTOCOL 17
#define IPv6_FRAGMENT_HEADER 44

/**
 * Return ethernet header structure form packet.
 *
 * @param pkt
 *  A pointer to the packet.
 *
 */
static inline struct ether_hdr *rte_vfw_get_ether_addr(struct rte_mbuf *pkt)
{
       return (struct ether_hdr *)RTE_MBUF_METADATA_UINT32_PTR(pkt,
                                                        ETHERNET_START);
}

/**
 * Return IPV4 header structure form packet.
 *
 * @param pkt
 *  A pointer to the packet.
 *
 */

static inline struct ipv4_hdr *rte_vfw_get_IPv4_hdr_addr(
              struct rte_mbuf *pkt)
{
       return (struct ipv4_hdr *)RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);
}

static inline int rte_vfw_is_IPv4(struct rte_mbuf *pkt)
{
       /* NOTE: Only supporting IP headers with no options,
        * so header is fixed size */
       uint8_t ip_type = RTE_MBUF_METADATA_UINT8(pkt, IP_START)
              >> VERSION_NO_BYTE;

       return ip_type == IPv4_HDR_VERSION;
}

static inline int rte_vfw_is_IPv6(struct rte_mbuf *pkt)
{
       /* NOTE: Only supporting IP headers with no options,
        * so header is fixed size */
       uint8_t ip_type = RTE_MBUF_METADATA_UINT8(pkt, IP_START)
              >> VERSION_NO_BYTE;

       return ip_type == IPv6_HDR_VERSION;
}

static inline void rte_vfw_incr_drop_ctr(uint64_t *counter)
{
       if (likely(firewall_flag))
              (*counter)++;
}

static uint8_t check_arp_icmp(
              struct rte_mbuf *pkt,
              struct pipeline_vfw *vfw_pipe)
{
       struct ether_hdr *ehdr;
       struct app_link_params *link;
        uint8_t solicited_node_multicast_addr[IPV6_ADD_SIZE] = {
                0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00};

        /* ARP outport number */
       uint16_t out_port = vfw_pipe->pipe.n_ports_out - 1;
       struct ipv4_hdr *ipv4_h;
       struct ipv6_hdr *ipv6_h;
       link = &myApp->link_params[pkt->port];

       ehdr = rte_vfw_get_ether_addr(pkt);
       switch (rte_be_to_cpu_16(ehdr->ether_type)) {

       case ETH_TYPE_ARP:
              rte_pipeline_port_out_packet_insert(
                            vfw_pipe->pipe.p,
                            out_port,
                            pkt);

              vfw_pipe->counters->arpicmpPktCount++;

              return 0;
       case ETH_TYPE_IPV4:
              ipv4_h = (struct ipv4_hdr *)
                     RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);
              if ((ipv4_h->next_proto_id == IP_PROTOCOL_ICMP) &&
                            link->ip ==
                            rte_be_to_cpu_32(ipv4_h->dst_addr)) {
                     if (is_phy_port_privte(pkt->port)) {
                            rte_pipeline_port_out_packet_insert(
                                          vfw_pipe->pipe.p,
                                          out_port,
                                          pkt);

                     vfw_pipe->counters->arpicmpPktCount++;
                            return 0;
                     }
              }
              break;
#ifdef IPV6
        case ETH_TYPE_IPV6:
                ipv6_h = (struct ipv6_hdr *)
                        RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);

                if (ipv6_h->proto == ICMPV6_PROTOCOL_ID) {
                        if (!memcmp(ipv6_h->dst_addr, link->ipv6, IPV6_ADD_SIZE)
                                        || !memcmp(ipv6_h->dst_addr,
                                                solicited_node_multicast_addr,
                                                IPV6_ADD_CMP_MULTI)) {

                                rte_pipeline_port_out_packet_insert(
                                                vfw_pipe->pipe.p,
                                                out_port,
                                                pkt);

                                vfw_pipe->counters->arpicmpPktCount++;

                        } else
                                vfw_pipe->counters->
                                        pkts_drop_unsupported_type++;

                        return 0;
                }
                break;
#endif
       default:
              break;
}
       return 1;
}

/**
 * Performs basic VFW ipv4 packet filtering.
 * @param pkts
 *  A pointer to the packets.
 * @param pkts_mask
 *  packet mask.
 * @param vfw_pipe
 *  A pointer to VFW pipeline.
 */

static uint64_t
rte_vfw_ipv4_packet_filter_and_process(struct rte_mbuf **pkts,
                                 uint64_t pkts_mask,
                                 struct pipeline_vfw *vfw_pipe)
{

       /*
        * Make use of cache prefetch. At beginning of loop, want to prefetch
        * mbuf data for next iteration (not current one).
        * Note that ethernet header (14 bytes) is cache aligned. IPv4 header
        * is 20 bytes (extensions not supported), while the IPv6 header is 40
        * bytes. TCP header is 20 bytes, UDP is 8. One cache line prefetch
        * will cover IPv4 and TCP or UDP, but to get IPv6 and TCP,
        * need two pre-fetches.
        */

       uint8_t pos, next_pos = 0;
       uint64_t pkt_mask;       /* bitmask representing a single packet */
       struct rte_mbuf *pkt;
       struct rte_mbuf *next_pkt = NULL;
       struct ipv4_hdr *ihdr4;
       void *next_iphdr = NULL;

       if (unlikely(pkts_mask == 0))
              return pkts_mask;
       pos = (uint8_t) __builtin_ctzll(pkts_mask);
       pkt_mask = 1LLU << pos;       /* bitmask representing only this packet */
       pkt = pkts[pos];

       uint64_t bytes_processed = 0;
       /* bitmap of packets left to process */
       uint64_t pkts_to_process = pkts_mask;
       /* bitmap of valid packets to return */
       uint64_t valid_packets = pkts_mask;

       rte_prefetch0(pkt);
       /* prefetch counters, updated below. Most likely counters to update
        * at beginnning */
       rte_prefetch0(&vfw_pipe->counters);

       do {                     /* always execute at least once */

              /* remove this packet from remaining list */
              uint64_t next_pkts_to_process = pkts_to_process &= ~pkt_mask;

              if (likely(next_pkts_to_process)) {
                     /* another packet to process after this, prefetch it */

                     next_pos =
                            (uint8_t) __builtin_ctzll(next_pkts_to_process);
                     next_pkt = pkts[next_pos];
                     next_iphdr = RTE_MBUF_METADATA_UINT32_PTR(next_pkt,
                                   IP_START);
                     rte_prefetch0(next_iphdr);
              }

              int discard = 0;
              /* remove this packet from remaining list */
              pkts_to_process &= ~pkt_mask;

	      if (enable_hwlb) {
		      if (!check_arp_icmp(pkt, vfw_pipe)) {
			      /* make next packet data the current */
			      pkts_to_process = next_pkts_to_process;
			      pos = next_pos;
			      pkt = next_pkt;
			      ihdr4 = next_iphdr;
			      pkt_mask = 1LLU << pos;
			      valid_packets &= ~pkt_mask;
			      continue;
		     }
	      }

              uint32_t packet_length = rte_pktmbuf_pkt_len(pkt);

              bytes_processed += packet_length;

              ihdr4 = (struct ipv4_hdr *)
                     RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);

              /* verify that packet size according to mbuf is at least
               * as large as the size according to the IP header.
               */

              uint32_t ip_length = rte_bswap16(ihdr4->total_length);

              if (unlikely
                            (ip_length > (packet_length - ETH_HDR_SIZE))) {
                     discard = 1;
                     vfw_pipe->counters->pkts_drop_bad_size++;
              }

              /*
               * IPv4 fragmented if: MF (more fragments) or Fragment
               * Offset are non-zero. Header in Intel order, so flip
               * constant to compensate. Note that IPv6 uses a header
               * extension for identifying fragments.
               */

              int fragmented = (ihdr4->fragment_offset & 0xff3f) != 0;
              uint8_t ttl = ihdr4->time_to_live;

              if (unlikely(fragmented)) {
                     discard = 1;
                     vfw_pipe->counters->pkts_drop_fragmented++;
              }

              if (unlikely(ttl <= 1)) {
                     /*
                      * about to decrement to zero (or is somehow
                      * already zero), so discard
                      */
                     discard = 1;
                     vfw_pipe->counters->pkts_drop_ttl++;
              }

              /*
               * Dropping the packets other than TCP AND UDP.
               */

              uint8_t proto = ihdr4->next_proto_id;

              if (unlikely(!(proto == IP_TCP_PROTOCOL ||
                                          proto == IP_UDP_PROTOCOL ||
                                          proto == IP_ICMP_PROTOCOL))) {
                     discard = 1;
                     vfw_pipe->counters->
                            pkts_drop_unsupported_type++;
              }

              if (unlikely(discard)) {
                     valid_packets &= ~pkt_mask;
              }

              /* make next packet data the current */
              pkts_to_process = next_pkts_to_process;
              pos = next_pos;
              pkt = next_pkt;
              ihdr4 = next_iphdr;
              pkt_mask = 1LLU << pos;

       } while (pkts_to_process);

       /* finalize counters, etc. */
       vfw_pipe->counters->bytes_processed += bytes_processed;

       if (likely(firewall_flag))
              return valid_packets;
       else
              return pkts_mask;
}
/**
 * Performs basic VFW IPV6 packet filtering.
 * @param pkts
 *  A pointer to the packets.
 * @param pkts_mask
 *  packet mask.
 * @param vfw_pipe
 *  A pointer to VFW pipeline.
 */
       static uint64_t
rte_vfw_ipv6_packet_filter_and_process(struct rte_mbuf **pkts,
              uint64_t pkts_mask,
              struct pipeline_vfw *vfw_pipe)
{

       /*
        * Make use of cache prefetch. At beginning of loop, want to prefetch
        * mbuf data for next iteration (not current one).
        * Note that ethernet header (14 bytes) is cache aligned. IPv4 header
        * is 20 bytes (extensions not supported), while the IPv6 header is 40
        * bytes. TCP header is 20 bytes, UDP is 8. One cache line prefetch
        * will cover IPv4 and TCP or UDP, but to get IPv6 and TCP,
        * need two pre-fetches.
        */

       uint8_t pos, next_pos = 0;
       uint64_t pkt_mask;       /* bitmask representing a single packet */
       struct rte_mbuf *pkt;
       struct rte_mbuf *next_pkt = NULL;
       struct ipv6_hdr *ihdr6;
       void *next_iphdr = NULL;

       if (unlikely(pkts_mask == 0))
              return pkts_mask;
       pos = (uint8_t) __builtin_ctzll(pkts_mask);
       pkt_mask = 1LLU << pos;       /* bitmask representing only this packet */
       pkt = pkts[pos];

       uint64_t bytes_processed = 0;
       /* bitmap of packets left to process */
       uint64_t pkts_to_process = pkts_mask;
       /* bitmap of valid packets to return */
       uint64_t valid_packets = pkts_mask;

       /* prefetch counters, updated below. Most likely counters to update
        * at beginnning */
       rte_prefetch0(&vfw_pipe->counters);

       do {                     /* always execute at least once */

              /* remove this packet from remaining list */
              uint64_t next_pkts_to_process = pkts_to_process &= ~pkt_mask;

              if (likely(next_pkts_to_process)) {
                     /* another packet to process after this, prefetch it */

                     next_pos =
                         (uint8_t) __builtin_ctzll(next_pkts_to_process);
                     next_pkt = pkts[next_pos];
                     next_iphdr =
                         RTE_MBUF_METADATA_UINT32_PTR(next_pkt, IP_START);
                     rte_prefetch0(next_iphdr);
              }

              int discard = 0;
              /* remove this packet from remaining list */
              pkts_to_process &= ~pkt_mask;

              if (enable_hwlb) {
                     if (!check_arp_icmp(pkt, vfw_pipe)) {
			     /* make next packet data the current */
			     pkts_to_process = next_pkts_to_process;
			     pos = next_pos;
			     pkt = next_pkt;
			     ihdr6 = next_iphdr;
			     pkt_mask = 1LLU << pos;
			     valid_packets &= ~pkt_mask;
			     continue;
		     }
	      }

              uint32_t packet_length = rte_pktmbuf_pkt_len(pkt);

              bytes_processed += packet_length;

              ihdr6 = (struct ipv6_hdr *)
                     RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);

              /*
               * verify that packet size according to mbuf is at least
               * as large as the size according to the IP header.
               * For IPv6, note that size includes header extensions
               * but not the base header size
               */

              uint32_t ip_length =
                     rte_bswap16(ihdr6->payload_len) + IPv6_HEADER_SIZE;

              if (unlikely
                            (ip_length > (packet_length - ETH_HDR_SIZE))) {
                     discard = 1;
                     vfw_pipe->counters->pkts_drop_bad_size++;
              }

              /*
               * Dropping the packets other than TCP AND UDP.
               */

              uint8_t proto = ihdr6->proto;

              if (unlikely(!(proto == IP_TCP_PROTOCOL ||
                                          proto == IP_UDP_PROTOCOL ||
                                          proto == IP_ICMP_PROTOCOL))) {
                     discard = 1;
                     if (proto == IPv6_FRAGMENT_HEADER)
                            vfw_pipe->counters->
                                   pkts_drop_fragmented++;
                     else
                            vfw_pipe->counters->
                                   pkts_drop_unsupported_type++;
              }

              /*
               * Behave like a router, and decrement the TTL of an
               * IP packet. If this causes the TTL to become zero,
               * the packet will be discarded. Unlike a router,
               * no ICMP code 11 (Time * Exceeded) message will be
               * sent back to the packet originator.
               */

              if (unlikely(ihdr6->hop_limits <= 1)) {
                     /*
                      * about to decrement to zero (or is somehow
                      * already zero), so discard
                      */
                     discard = 1;
                     vfw_pipe->counters->pkts_drop_ttl++;
              }

              if (unlikely(discard))
                     valid_packets &= ~pkt_mask;
              else
                     ihdr6->hop_limits--;

              /* make next packet data the current */
              pkts_to_process = next_pkts_to_process;
              pos = next_pos;
              pkt = next_pkt;
              ihdr6 = next_iphdr;
              pkt_mask = 1LLU << pos;

       } while (pkts_to_process);

       /* finalize counters, etc. */
       vfw_pipe->counters->bytes_processed += bytes_processed;

       if (likely(firewall_flag))
              return valid_packets;
       else
              return pkts_mask;
}

/**
 * exchange the mac address so source becomes destination and vice versa.
 *
 * @param ehdr
 *  A pointer to the ethernet header.
 *
 */
static inline void rte_sp_exchange_mac_addresses(struct ether_hdr *ehdr)
{
       struct ether_addr saved_copy;

       ether_addr_copy(&ehdr->d_addr, &saved_copy);
       ether_addr_copy(&ehdr->s_addr, &ehdr->d_addr);
       ether_addr_copy(&saved_copy, &ehdr->s_addr);
}
#ifdef EN_SWP_ARP

/**
 * walk every valid mbuf (denoted by pkts_mask) and apply arp to the packet.
 * To support synproxy, some (altered) packets may need to be sent back where
 * they came from. The ip header has already been adjusted, but the ethernet
 * header has not, so this must be performed here.
 * Return an updated pkts_mask, since arp may drop some packets
 *
 * @param pkts
 *  A pointer to the packet array.
 * @param pkt_num
 *  Packet num to start processing
 * @param pkts_mask
 *  Packet mask
 * @param synproxy_reply_mask
 *  Reply Packet mask for Synproxy
 * @param vfw_pipe
 *  A pointer to VFW pipeline.
 */
static void
pkt4_work_vfw_arp_ipv4_packets(struct rte_mbuf **pkts,
              uint16_t pkt_num,
              uint64_t *pkts_mask,
              uint64_t synproxy_reply_mask,
              struct pipeline_vfw *vfw_pipe)
{

       uint8_t i;

       struct mbuf_tcp_meta_data *meta_data_addr;
       struct ether_hdr *ehdr;
       struct rte_mbuf *pkt;

       for (i = 0; i < 4; i++) {
              uint32_t dest_if = INVALID_DESTIF;
              /* bitmask representing only this packet */
              uint64_t pkt_mask = 1LLU << (pkt_num + i);

              pkt = pkts[i];

              if(!(*pkts_mask & pkt_mask))
                     continue;

              int must_reverse = ((synproxy_reply_mask & pkt_mask) != 0);

              meta_data_addr = (struct mbuf_tcp_meta_data *)
                     RTE_MBUF_METADATA_UINT32_PTR(pkt, META_DATA_OFFSET);
              ehdr = rte_vfw_get_ether_addr(pkt);


              struct ipv4_hdr *ihdr = (struct ipv4_hdr *)
                     RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);
              uint32_t nhip = 0;

              uint32_t dest_address = rte_bswap32(ihdr->dst_addr);
              if (must_reverse)
                     rte_sp_exchange_mac_addresses(ehdr);

	struct arp_entry_data *ret_arp_data = NULL;
        ret_arp_data = get_dest_mac_addr_port(dest_address,
                       &dest_if, &ehdr->d_addr);
        meta_data_addr->output_port =  vfw_pipe->outport_id[dest_if];

        if (arp_cache_dest_mac_present(dest_if)) {
                ether_addr_copy(get_link_hw_addr(dest_if), &ehdr->s_addr);
		update_nhip_access(dest_if);
                if (unlikely(ret_arp_data && ret_arp_data->num_pkts)) {
                        arp_send_buffered_pkts(ret_arp_data,
                                 &ehdr->d_addr, vfw_pipe->outport_id[dest_if]);

                            }

                     } else {
                if (unlikely(ret_arp_data == NULL)) {
			if (VFW_DEBUG)
                        printf("%s: NHIP Not Found, nhip:%x , "
                        "outport_id: %d\n", __func__, nhip,
                        vfw_pipe->outport_id[dest_if]);

                        /* Drop the pkt */
                        vfw_pipe->counters->
                                 pkts_drop_without_arp_entry++;
                        continue;
                            }
		if (ret_arp_data->status == INCOMPLETE ||
                           ret_arp_data->status == PROBE) {
                                if (ret_arp_data->num_pkts >= NUM_DESC) {
					/* ICMP req sent, drop packet by
						* changing the mask */
					vfw_pipe->counters->
						pkts_drop_without_arp_entry++;
                                        continue;
                                } else {
                                        //arp_pkts_mask |= pkt_mask;
					*arp_hijack_mask |= pkt_mask;
                                        arp_queue_unresolved_packet(ret_arp_data, pkt);
                                        continue;
                     }
              }
	}
       }
}


/**
 * walk every valid mbuf (denoted by pkts_mask) and apply arp to the packet.
 * To support synproxy, some (altered) packets may need to be sent back where
 * they came from. The ip header has already been adjusted, but the ethernet
 * header has not, so this must be performed here.
 * Return an updated pkts_mask, since arp may drop some packets
 *
 * @param pkts
 *  A pointer to the packet.
 * @param packet_num
 *  Packet number to process
 * @param pkts_mask
 *  Packet mask pointer
 * @param synproxy_reply_mask
 *  Reply Packet mask for Synproxy
 * @param vfw_pipe
 *  A pointer to VFW pipeline.
 */
static void
pkt_work_vfw_arp_ipv4_packets(struct rte_mbuf *pkts,
              uint16_t pkt_num,
              uint64_t *pkts_mask,
              uint64_t synproxy_reply_mask,
              struct pipeline_vfw *vfw_pipe)
{

       uint32_t dest_if = INVALID_DESTIF;

       struct mbuf_tcp_meta_data *meta_data_addr;
       struct ether_hdr *ehdr;
       struct rte_mbuf *pkt;
       uint64_t pkt_mask = 1LLU << pkt_num;

       pkt = pkts;

       if(*pkts_mask & pkt_mask) {

              int must_reverse = ((synproxy_reply_mask & pkt_mask) != 0);

              meta_data_addr = (struct mbuf_tcp_meta_data *)
                     RTE_MBUF_METADATA_UINT32_PTR(pkt, META_DATA_OFFSET);
              ehdr = rte_vfw_get_ether_addr(pkt);


              struct ipv4_hdr *ihdr = (struct ipv4_hdr *)
                     RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);
              uint32_t nhip = 0;

              uint32_t dest_address = rte_bswap32(ihdr->dst_addr);
              if (must_reverse)
                     rte_sp_exchange_mac_addresses(ehdr);

	struct arp_entry_data *ret_arp_data = NULL;
                     ret_arp_data = get_dest_mac_addr_port(dest_address,
                                   &dest_if, &ehdr->d_addr);
			meta_data_addr->output_port =  vfw_pipe->outport_id[dest_if];

        if (arp_cache_dest_mac_present(dest_if)) {

                ether_addr_copy(get_link_hw_addr(dest_if), &ehdr->s_addr);
		update_nhip_access(dest_if);
                if (unlikely(ret_arp_data && ret_arp_data->num_pkts)) {
                        arp_send_buffered_pkts(ret_arp_data,
                                 &ehdr->d_addr, vfw_pipe->outport_id[dest_if]);

                            }
                     } else {
                if (unlikely(ret_arp_data == NULL)) {

			if (VFW_DEBUG)
                        printf("%s: NHIP Not Found, nhip:%x , "
                        "outport_id: %d\n", __func__, nhip,
                        vfw_pipe->outport_id[dest_if]);

                        vfw_pipe->counters->
                                pkts_drop_without_arp_entry++;
                        return;
                            }
		if (ret_arp_data->status == INCOMPLETE ||
                           ret_arp_data->status == PROBE) {
                                if (ret_arp_data->num_pkts >= NUM_DESC) {
					/* ICMP req sent, drop packet by
						* changing the mask */
					vfw_pipe->counters->
						pkts_drop_without_arp_entry++;
                                        return;
                                } else {
                                        arp_pkts_mask |= pkt_mask;
                                        arp_queue_unresolved_packet(ret_arp_data, pkt);
                                        return;
                     }
              }
	}

       }
}


/**
 * walk every valid mbuf (denoted by pkts_mask) and apply arp to the packet.
 * To support synproxy, some (altered) packets may need to be sent back where
 * they came from. The ip header has already been adjusted, but the ethernet
 * header has not, so this must be performed here.
 * Return an updated pkts_mask, since arp may drop some packets
 *
 * @param pkts
 *  A pointer to the packets array.
 * @param pkt_num
 *  Packet number to start processing.
 * @param pkts_mask
 *  Packet mask pointer
 * @param synproxy_reply_mask
 *  Reply Packet mask for Synproxy
 * @param vfw_pipe
 *  A pointer to VFW pipeline.
 */

static void
pkt4_work_vfw_arp_ipv6_packets(struct rte_mbuf **pkts,
              uint16_t pkt_num,
              uint64_t *pkts_mask,
              uint64_t synproxy_reply_mask,
              struct pipeline_vfw *vfw_pipe)
{
       uint8_t nh_ipv6[IPV6_ADD_SIZE];
       struct ether_addr hw_addr;
       struct mbuf_tcp_meta_data *meta_data_addr;
       struct ether_hdr *ehdr;
       struct rte_mbuf *pkt;
       uint8_t i;

       for (i = 0; i < 4; i++) {
              uint32_t dest_if = INVALID_DESTIF;
              /* bitmask representing only this packet */
              uint64_t pkt_mask = 1LLU << (pkt_num + i);

              pkt = pkts[i];

              if(!(*pkts_mask & pkt_mask))
                     continue;
              int must_reverse = ((synproxy_reply_mask & pkt_mask) != 0);

              meta_data_addr = (struct mbuf_tcp_meta_data *)
                     RTE_MBUF_METADATA_UINT32_PTR(pkt, META_DATA_OFFSET);
              ehdr = rte_vfw_get_ether_addr(pkt);

              struct ipv6_hdr *ihdr = (struct ipv6_hdr *)
                     RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);

              uint8_t nhip[IPV6_ADD_SIZE];
              uint8_t dest_address[IPV6_ADD_SIZE];

              memset(nhip, 0, IPV6_ADD_SIZE);
              if (must_reverse)
                     rte_sp_exchange_mac_addresses(ehdr);

              rte_mov16(dest_address, ihdr->dst_addr);
              memset(nh_ipv6, 0, IPV6_ADD_SIZE);
              struct nd_entry_data *ret_nd_data = NULL;
              ret_nd_data = get_dest_mac_address_ipv6_port(
                                   &dest_address[0],
                                   &dest_if,
                                   &hw_addr,
                                   &nh_ipv6[0]);

		meta_data_addr->output_port = vfw_pipe->
                                    outport_id[dest_if];
              if (nd_cache_dest_mac_present(dest_if)) {
                    ether_addr_copy(get_link_hw_addr(dest_if),
                                   &ehdr->s_addr);
		    update_nhip_access(dest_if);

                    if (unlikely(ret_nd_data && ret_nd_data->num_pkts)) {
                        nd_send_buffered_pkts(ret_nd_data,
				&ehdr->d_addr, meta_data_addr->output_port);
                    }
              } else {
                    if (unlikely(ret_nd_data == NULL)) {
                         *pkts_mask &= ~pkt_mask;
			  vfw_pipe->counters->
				pkts_drop_without_arp_entry++;
                          continue;
                    }
		    if (ret_nd_data->status == INCOMPLETE ||
	                  ret_nd_data->status == PROBE) {
			  if (ret_nd_data->num_pkts >= NUM_DESC) {
                                /* Drop the pkt */
                                *pkts_mask &= ~pkt_mask;
                                vfw_pipe->counters->
					pkts_drop_without_arp_entry++;
				continue;
                          } else {
                                arp_pkts_mask |= pkt_mask;
                                nd_queue_unresolved_packet(ret_nd_data, pkt);
                                continue;
                          }
                    }
              }

       }
}


/**
 * walk every valid mbuf (denoted by pkts_mask) and apply arp to the packet.
 * To support synproxy, some (altered) packets may need to be sent back where
 * they came from. The ip header has already been adjusted, but the ethernet
 * header has not, so this must be performed here.
 * Return an updated pkts_mask, since arp may drop some packets
 *
 * @param pkts
 *  A pointer to the packets.
 * @param pkt_num
 *  Packet number to process.
 * @param pkts_mask
 *  Packet mask pointer
 * @param synproxy_reply_mask
 *  Reply Packet mask for Synproxy
 * @param vfw_pipe
 *  A pointer to VFW pipeline.
 */

static void
pkt_work_vfw_arp_ipv6_packets(struct rte_mbuf *pkts,
              uint16_t pkt_num,
              uint64_t *pkts_mask,
              uint64_t synproxy_reply_mask,
              struct pipeline_vfw *vfw_pipe)
{
       uint8_t nh_ipv6[IPV6_ADD_SIZE];
       struct ether_addr hw_addr;
       struct mbuf_tcp_meta_data *meta_data_addr;
       struct ether_hdr *ehdr;
       struct rte_mbuf *pkt;

       uint32_t dest_if = INVALID_DESTIF;
       /* bitmask representing only this packet */
       uint64_t pkt_mask = 1LLU << pkt_num;

       pkt = pkts;

       if(*pkts_mask & pkt_mask) {

              int must_reverse = ((synproxy_reply_mask & pkt_mask) != 0);

              meta_data_addr = (struct mbuf_tcp_meta_data *)
                     RTE_MBUF_METADATA_UINT32_PTR(pkt, META_DATA_OFFSET);
              ehdr = rte_vfw_get_ether_addr(pkt);

              struct ipv6_hdr *ihdr = (struct ipv6_hdr *)
                     RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);

              uint8_t nhip[IPV6_ADD_SIZE];
              uint8_t dest_address[IPV6_ADD_SIZE];

              memset(nhip, 0, IPV6_ADD_SIZE);
              if (must_reverse)
                     rte_sp_exchange_mac_addresses(ehdr);
              rte_mov16(dest_address, ihdr->dst_addr);
              memset(nh_ipv6, 0, IPV6_ADD_SIZE);
              struct nd_entry_data *ret_nd_data = NULL;
              ret_nd_data = get_dest_mac_address_ipv6_port(
                                   &dest_address[0],
                                   &dest_if,
                                   &hw_addr,
                                   &nh_ipv6[0]);
	      meta_data_addr->output_port = vfw_pipe->
                                    outport_id[dest_if];
              if (nd_cache_dest_mac_present(dest_if)) {
                     ether_addr_copy(get_link_hw_addr(dest_if),
                                   &ehdr->s_addr);
		    update_nhip_access(dest_if);

                    if (unlikely(ret_nd_data && ret_nd_data->num_pkts)) {
                        nd_send_buffered_pkts(ret_nd_data,
				&ehdr->d_addr, meta_data_addr->output_port);
                     }
              } else {
                    if (unlikely(ret_nd_data == NULL)) {
                        *pkts_mask &= ~pkt_mask;
			vfw_pipe->counters->
				pkts_drop_without_arp_entry++;
                        return;
                    }
		    if (ret_nd_data->status == INCOMPLETE ||
                          ret_nd_data->status == PROBE) {
                          if (ret_nd_data->num_pkts >= NUM_DESC) {
                                /* Drop the pkt */
                                *pkts_mask &= ~pkt_mask;
                                vfw_pipe->counters->
                                    pkts_drop_without_arp_entry++;
                                return;
                          } else {
                                arp_pkts_mask |= pkt_mask;
                                nd_queue_unresolved_packet(ret_nd_data, pkt);
                                return;
                          }
                    }
              }

       }

}

#else

/**
 * walk every valid mbuf (denoted by pkts_mask) and forward the packet.
 * To support synproxy, some (altered) packets may need to be sent back where
 * they came from. The ip header has already been adjusted, but the ethernet
 * header has not, so this must be performed here.
 * Return an updated pkts_mask and arp_hijack_mask since arp may drop some packets
 *
 * @param pkts
 *  A pointer to the packet array.
 * @param pkts_mask
 *  Packets mask to be processed
 * @param arp_hijack_mask
 *  Packets to be hijacked for arp buffering
 * @param vfw_pipe
 *  A pointer to VFW pipeline.
 */
static void vfw_fwd_pkts_ipv4(struct rte_mbuf **pkts, uint64_t *pkts_mask,
		uint64_t *arp_hijack_mask, struct pipeline_vfw *vfw_pipe)
{
	uint64_t pkts_to_arp = *pkts_mask;

	for (; pkts_to_arp;) {

		struct mbuf_tcp_meta_data *meta_data_addr;
		struct ether_hdr *ehdr;
		struct rte_mbuf *pkt;
		uint32_t src_phy_port;

		uint8_t pos = (uint8_t) __builtin_ctzll(pkts_to_arp);
		/* bitmask representing only this packet */
		uint64_t pkt_mask = 1LLU << pos;
		/* remove this packet from remaining list */
		pkts_to_arp &= ~pkt_mask;
		pkt = pkts[pos];

		if(VFW_DEBUG) {
			printf("----------------\n");
			print_pkt(pkt);
		}

		meta_data_addr = (struct mbuf_tcp_meta_data *)
			RTE_MBUF_METADATA_UINT32_PTR(pkt, META_DATA_OFFSET);

		ehdr = (struct ether_hdr *)
			RTE_MBUF_METADATA_UINT32_PTR(pkt, ETHERNET_START);

		src_phy_port = pkt->port;
		uint32_t dst_phy_port = INVALID_DESTIF;

		if(is_gateway()){
			struct ipv4_hdr *ipv4hdr = (struct ipv4_hdr *)
				RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);

			/* Gateway Proc Starts */

			struct arp_entry_data *ret_arp_data = NULL;
			struct ether_addr dst_mac;
			uint32_t nhip = 0;
			uint32_t dst_ip_addr = rte_bswap32(ipv4hdr->dst_addr);

			gw_get_nh_port_ipv4(dst_ip_addr, &dst_phy_port, &nhip);

			ret_arp_data = get_dest_mac_addr_ipv4(nhip, dst_phy_port, &dst_mac);

			/* Gateway Proc Ends */

			if (arp_cache_dest_mac_present(dst_phy_port)) {

				ether_addr_copy(&dst_mac, &ehdr->d_addr);
				ether_addr_copy(get_link_hw_addr(dst_phy_port), &ehdr->s_addr);

				meta_data_addr->output_port = vfw_pipe->outport_id[dst_phy_port];

				update_nhip_access(dst_phy_port);

				if (unlikely(ret_arp_data && ret_arp_data->num_pkts)) {

					arp_send_buffered_pkts(ret_arp_data, &ehdr->d_addr,
							vfw_pipe->outport_id[dst_phy_port]);
				}

			} else {
				if (unlikely(ret_arp_data == NULL)) {

					printf("NHIP Not Found\n");

					/* Drop the pkt */
					vfw_pipe->counters->
						pkts_drop_without_arp_entry++;
					continue;
				}
				if (ret_arp_data->status == INCOMPLETE ||
						ret_arp_data->status == PROBE) {
					if (ret_arp_data->num_pkts >= NUM_DESC) {
						/* ICMP req sent, drop packet by
						 * changing the mask */
						vfw_pipe->counters->pkts_drop_without_arp_entry++;
						continue;
					} else {
						*arp_hijack_mask |= pkt_mask;
						arp_queue_unresolved_packet(ret_arp_data, pkt);
						continue;
					}
				}
			}
		} else {
			/* IP Pkt forwarding based on  pub/prv mapping */
			if(is_phy_port_privte(src_phy_port))
				dst_phy_port = prv_to_pub_map[src_phy_port];
			else
				dst_phy_port = pub_to_prv_map[src_phy_port];

			meta_data_addr->output_port = vfw_pipe->outport_id[dst_phy_port];

			if(VFW_DEBUG) {
				printf("IP_PKT_FWD: src_phy_port=%d, dst_phy_port=%d\n",
						src_phy_port, dst_phy_port);
			}
		}

		if(VFW_DEBUG)
			print_pkt(pkt);
	}

}

/**
 * walk every valid mbuf (denoted by pkts_mask) and forward the packet.
 * To support synproxy, some (altered) packets may need to be sent back where
 * they came from. The ip header has already been adjusted, but the ethernet
 * header has not, so this must be performed here.
 * Return an updated pkts_mask and arp_hijack_mask since arp may drop some packets
 *
 * @param pkts
 *  A pointer to the packet array.
 * @param pkts_mask
 *  Packets mask to be processed
 * @param arp_hijack_mask
 *  Packets to be hijacked for arp buffering
 * @param vfw_pipe
 *  A pointer to VFW pipeline.
 */
static void vfw_fwd_pkts_ipv6(struct rte_mbuf **pkts, uint64_t *pkts_mask,
			uint64_t *arp_hijack_mask, struct pipeline_vfw *vfw_pipe)
{
	uint64_t pkts_to_arp = *pkts_mask;

	for (; pkts_to_arp;) {

		struct mbuf_tcp_meta_data *meta_data_addr;
		struct ether_hdr *ehdr;
		struct rte_mbuf *pkt;
		uint32_t src_phy_port;

		struct nd_entry_data *ret_nd_data = NULL;

		uint8_t pos = (uint8_t) __builtin_ctzll(pkts_to_arp);
		/* bitmask representing only this packet */
		uint64_t pkt_mask = 1LLU << pos;
		/* remove this packet from remaining list */
		pkts_to_arp &= ~pkt_mask;
		pkt = pkts[pos];

		if(VFW_DEBUG) {
			printf("----------------\n");
			print_pkt(pkt);
		}

		meta_data_addr = (struct mbuf_tcp_meta_data *)
			RTE_MBUF_METADATA_UINT32_PTR(pkt, META_DATA_OFFSET);

		ehdr = (struct ether_hdr *)
			RTE_MBUF_METADATA_UINT32_PTR(pkt, ETHERNET_START);

		src_phy_port = pkt->port;
		uint32_t dst_phy_port = INVALID_DESTIF;

		if(is_gateway()){
			struct ipv6_hdr *ipv6hdr = (struct ipv6_hdr *)
				RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);

			/* Gateway Proc Starts */

			struct ether_addr dst_mac;
			uint32_t dst_phy_port = INVALID_DESTIF;
			uint8_t nhipv6[IPV6_ADD_SIZE];
			uint8_t dest_ipv6_address[IPV6_ADD_SIZE];
			memset(nhipv6, 0, IPV6_ADD_SIZE);
			src_phy_port = pkt->port;
			rte_mov16(dest_ipv6_address, (uint8_t *)ipv6hdr->dst_addr);

			gw_get_nh_port_ipv6(dest_ipv6_address, &dst_phy_port, nhipv6);

			ret_nd_data = get_dest_mac_addr_ipv6(nhipv6, dst_phy_port, &dst_mac);

			/* Gateway Proc Ends */

			if (nd_cache_dest_mac_present(dst_phy_port)) {

				ether_addr_copy(&dst_mac, &ehdr->d_addr);
				ether_addr_copy(get_link_hw_addr(dst_phy_port), &ehdr->s_addr);

				meta_data_addr->output_port = vfw_pipe->outport_id[dst_phy_port];

				update_nhip_access(dst_phy_port);

				if (unlikely(ret_nd_data && ret_nd_data->num_pkts)) {
					nd_send_buffered_pkts(ret_nd_data, &ehdr->d_addr,
							vfw_pipe->outport_id[dst_phy_port]);
				}

			} else {
				if (unlikely(ret_nd_data == NULL)) {

					printf("NHIP Not Found\n");

					/* Drop the pkt */
					vfw_pipe->counters->pkts_drop_without_arp_entry++;
					continue;
				}
				if (ret_nd_data->status == INCOMPLETE ||
						ret_nd_data->status == PROBE) {
					if (ret_nd_data->num_pkts >= NUM_DESC) {
						/* ICMP req sent, drop packet by
						 * changing the mask */
						vfw_pipe->counters->pkts_drop_without_arp_entry++;
						continue;
					} else {
						*arp_hijack_mask |= pkt_mask;
						nd_queue_unresolved_packet(ret_nd_data, pkt);
						continue;
					}
				}
			}

		} else {
			/* IP Pkt forwarding based on  pub/prv mapping */
			if(is_phy_port_privte(src_phy_port))
				dst_phy_port = prv_to_pub_map[src_phy_port];
			else
				dst_phy_port = pub_to_prv_map[src_phy_port];

			meta_data_addr->output_port = vfw_pipe->outport_id[dst_phy_port];

			if(VFW_DEBUG) {
				printf("IP_PKT_FWD: src_phy_port=%d, dst_phy_port=%d\n",
						src_phy_port, dst_phy_port);
			}
		}
		if(VFW_DEBUG)
			print_pkt(pkt);
	}
}

#endif
/**
 * Packets processing for connection tracking.
 *
 * @param vfw_pipe
 *  A pointer to the pipeline.
 * @param ct
 *  A pointer to the connetion tracker .
 * @param pkts
 *  A pointer to a burst of packets.
 * @param packet_mask_in
 *  Input packets Mask.
 */

       static  uint64_t
vfw_process_buffered_pkts(__rte_unused struct pipeline_vfw *vfw_pipe,
              struct rte_ct_cnxn_tracker *ct,
                          struct rte_mbuf **pkts, uint64_t packet_mask_in)
{
       uint64_t keep_mask = packet_mask_in;
       struct rte_synproxy_helper sp_helper;       /* for synproxy */

       keep_mask =
           rte_ct_cnxn_tracker_batch_lookup_with_synproxy(ct, pkts, keep_mask,
                                                    &sp_helper);

       if (unlikely(sp_helper.hijack_mask))
              printf("buffered hijack pkts severe error\n");

       if (unlikely(sp_helper.reply_pkt_mask))
              printf("buffered reply pkts severe error\n");

       return keep_mask;
}

/**
 * Free Packets from mbuf.
 *
 * @param ct
 *  A pointer to the connection tracker to increment drop counter.
 *
 * @param pkt
 *  Packet to be free.
 */
static inline void
vfw_pktmbuf_free(struct rte_ct_cnxn_tracker *ct, struct rte_mbuf *pkt)
{
       ct->counters->pkts_drop++;
       rte_pktmbuf_free(pkt);
}

static void
vfw_output_or_delete_buffered_packets(struct rte_ct_cnxn_tracker *ct,
                                    struct rte_pipeline *p,
                                    struct rte_mbuf **pkts,
                                    int num_pkts, uint64_t pkts_mask)
{
       int i;
       struct mbuf_tcp_meta_data *meta_data_addr;
       uint64_t pkt_mask = 1;

       /* any clear bits in low-order num_pkts bit of
        * pkt_mask must be discarded */

       for (i = 0; i < num_pkts; i++) {
              struct rte_mbuf *pkt = pkts[i];

              if (pkts_mask & pkt_mask) {
                     printf("vfw_output_or_delete_buffered_packets\n");
                     meta_data_addr = (struct mbuf_tcp_meta_data *)
                         RTE_MBUF_METADATA_UINT32_PTR(pkt, META_DATA_OFFSET);
                     rte_pipeline_port_out_packet_insert(
                                   p, meta_data_addr->output_port, pkt);

              } else {
                     vfw_pktmbuf_free(ct, pkt);
              }

              pkt_mask = pkt_mask << 1;
       }
}

/**
 *Packet buffered for synproxy.
 *
 * @param p
 *  A pointer to the pipeline.
 * @param vfw_pipe
 *  A pointer to the vfw pipeline.
 * @param ct
 *  A pointer to the connection tracker.
 * @param forward_pkts
 *  Packet forwarded by synproxy.
 *
 */
static void
vfw_handle_buffered_packets(struct rte_pipeline *p,
                            struct pipeline_vfw *vfw_pipe,
                            struct rte_ct_cnxn_tracker *ct, int forward_pkts)
{
       struct rte_mbuf *pkt_list = rte_ct_get_buffered_synproxy_packets(ct);

       if (likely(pkt_list == NULL))       /* only during proxy setup is != NULL */
              return;

       int pkt_count = 0;
       uint64_t keep_mask = 0;
       struct rte_mbuf **pkts = vfw_pipe->pkt_buffer;
       struct rte_mbuf *pkt;

       while (pkt_list != NULL) {
              struct mbuf_tcp_meta_data *meta_data =
              (struct mbuf_tcp_meta_data *)
              RTE_MBUF_METADATA_UINT32_PTR(pkt_list, META_DATA_OFFSET);

              /* detach head of list and advance list */
              pkt = pkt_list;
              pkt_list = meta_data->next;

              if (forward_pkts) {

                     pkts[pkt_count++] = pkt;

                     if (pkt_count == PKT_BUFFER_SIZE) {
                            /* need to send out packets */
                            /* currently 0, set all bits */
                            keep_mask = ~keep_mask;

                            keep_mask =
                                vfw_process_buffered_pkts(vfw_pipe,
                                                         ct, pkts,
                                                         keep_mask);
                            vfw_output_or_delete_buffered_packets(
                                          ct, p,
                                          pkts,
                                          PKT_BUFFER_SIZE,
                                          keep_mask);
                            pkt_count = 0;
                            keep_mask = 0;
                     }

              } else {
                     vfw_pktmbuf_free(ct, pkt);
              }
       }

       if (pkt_count != 0) {
              /* need to send out packets */
              keep_mask = RTE_LEN2MASK(pkt_count, uint64_t);

              keep_mask =
                     vfw_process_buffered_pkts(vfw_pipe, ct, pkts,
                                   keep_mask);

              vfw_output_or_delete_buffered_packets(ct, p, pkts, pkt_count,
                            keep_mask);

              pkt_count = 0;
              keep_mask = 0;
       }
}
/**
 * The pipeline port-in action is used to do all the firewall and
 * connection tracking work for IPV4 packets.
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
vfw_port_in_action_ipv4(struct rte_pipeline *p,
              struct rte_mbuf **pkts,
              __rte_unused uint32_t n_pkts, __rte_unused void *arg)
{
       struct vfw_ports_in_args *port_in_args =
              (struct vfw_ports_in_args *)arg;
       struct pipeline_vfw *vfw_pipe =
              (struct pipeline_vfw *)port_in_args->pipe;
       struct rte_ct_cnxn_tracker *ct = port_in_args->cnxn_tracker;

       start_tsc_measure(vfw_pipe);

       uint64_t packet_mask_in = RTE_LEN2MASK(n_pkts, uint64_t);
       uint64_t pkts_drop_mask;
       uint64_t synp_hijack_mask = 0;
       uint64_t arp_hijack_mask = 0;
//       uint64_t synproxy_reply_mask;       /* for synproxy */
       uint64_t keep_mask = packet_mask_in;

       uint64_t conntrack_mask = 0, connexist_mask = 0;
       struct rte_CT_helper ct_helper;
       uint8_t j;

       /*
        * This routine uses a bit mask to represent which packets in the
        * "pkts" table are considered valid. Any table entry which exists
        * and is considered valid has the corresponding bit in the mask set.
        * Otherwise, it is cleared. Note that the mask is 64 bits,
        * but the number of packets in the table may be considerably less.
        * Any mask bits which do correspond to actual packets are cleared.
        * Various routines are called which may determine that an existing
        * packet is somehow invalid. The routine will return an altered bit
        * mask, with the bit cleared. At the end of all the checks,
        * packets are dropped if their mask bit is a zero
        */

       rte_prefetch0(& vfw_pipe->counters);

#ifdef EN_SWP_ACL
       /* Pre-fetch all rte_mbuf header */
       for(j = 0; j < n_pkts; j++)
              rte_prefetch0(pkts[j]);
#endif
       memset(&ct_helper, 0, sizeof(struct rte_CT_helper));
#ifdef EN_SWP_ACL
       rte_prefetch0(& vfw_pipe->counters->pkts_drop_ttl);
       rte_prefetch0(& vfw_pipe->counters->sum_latencies);
#endif

       if (unlikely(vfw_debug > 1))
              printf("Enter in-port action IPV4 with %p packet mask\n",
                            (void *)packet_mask_in);
       vfw_pipe->counters->pkts_received =
              vfw_pipe->counters->pkts_received + n_pkts;

       if (unlikely(VFW_DEBUG))
              printf("vfw_port_in_action_ipv4 pkts_received: %" PRIu64
                            " n_pkts: %u\n",
                            vfw_pipe->counters->pkts_received, n_pkts);

       /* first handle handle any previously buffered packets now released */
       vfw_handle_buffered_packets(p, vfw_pipe, ct,
                     FORWARD_BUFFERED_PACKETS);

       /* now handle any new packets on input ports */
       if (likely(firewall_flag)) {
              keep_mask = rte_vfw_ipv4_packet_filter_and_process(pkts,
                            keep_mask, vfw_pipe);
              vfw_pipe->counters->pkts_fw_forwarded +=
                     __builtin_popcountll(keep_mask);
       }
#ifdef ACL_ENABLE
#ifdef EN_SWP_ACL
       rte_prefetch0((void*)vfw_pipe->plib_acl);
       rte_prefetch0((void*)vfw_rule_table_ipv4_active);
#endif /* EN_SWP_ACL */
       keep_mask = lib_acl_ipv4_pkt_work_key(
                     vfw_pipe->plib_acl, pkts, keep_mask,
                     &vfw_pipe->counters->pkts_drop_without_rule,
                     vfw_rule_table_ipv4_active,
                     action_array_active,
                     action_counter_table,
                     &conntrack_mask, &connexist_mask);
       vfw_pipe->counters->pkts_acl_forwarded +=
              __builtin_popcountll(keep_mask);
       if (conntrack_mask > 0) {
              keep_mask = conntrack_mask;
              ct_helper.no_new_cnxn_mask = connexist_mask;
              cnxn_tracking_is_active = 1;
       } else
              cnxn_tracking_is_active = 0;
#endif /* ACL_ENABLE */

       if (likely(cnxn_tracking_is_active)) {
              rte_ct_cnxn_tracker_batch_lookup_type(ct, pkts,
                            &keep_mask, &ct_helper, IPv4_HEADER_SIZE);
//              synproxy_reply_mask = ct_helper.reply_pkt_mask;
              synp_hijack_mask = ct_helper.hijack_mask;

       }

#ifdef EN_SWP_ARP
       for(j = 0; j < (n_pkts & 0x3LLU); j++) {
               rte_prefetch0(RTE_MBUF_METADATA_UINT32_PTR(pkts[j],
                                   META_DATA_OFFSET));
               rte_prefetch0(RTE_MBUF_METADATA_UINT32_PTR(pkts[j],
                                   ETHERNET_START));
       }
       rte_prefetch0((void*)in_port_dir_a);
       rte_prefetch0((void*)prv_to_pub_map);

       uint8_t i;
       for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4) {
              for (j = i+4; ((j < n_pkts) && (j < i+8)); j++) {
                     rte_prefetch0(RTE_MBUF_METADATA_UINT32_PTR(pkts[j],
                                          META_DATA_OFFSET));
                     rte_prefetch0(RTE_MBUF_METADATA_UINT32_PTR(pkts[j],
                                          ETHERNET_START));
              }
              pkt4_work_vfw_arp_ipv4_packets(&pkts[i], i, &keep_mask,
                            synproxy_reply_mask, vfw_pipe);
       }
       for (j = i; j < n_pkts; j++) {
              rte_prefetch0(RTE_MBUF_METADATA_UINT32_PTR(pkts[j],
                                   META_DATA_OFFSET));
              rte_prefetch0(RTE_MBUF_METADATA_UINT32_PTR(pkts[j],
                                   ETHERNET_START));
       }
       for (; i < n_pkts; i++) {
              pkt_work_vfw_arp_ipv4_packets(pkts[i], i, &keep_mask,
                            synproxy_reply_mask, vfw_pipe);
       }
#else
       rte_prefetch0((void*)in_port_dir_a);
       rte_prefetch0((void*)prv_to_pub_map);

	vfw_fwd_pkts_ipv4(pkts, &keep_mask, &arp_hijack_mask, vfw_pipe);

#endif

       if (vfw_debug > 1) {
              printf("  Exit in-port action with %p packet mask\n",
                            (void *)keep_mask);
              if (keep_mask != packet_mask_in)
                     printf("dropped packets, %p in, %p out\n",
                                   (void *)packet_mask_in,
                                   (void *)keep_mask);
       }

	   /* Hijack the Synproxy and ARP buffered packets */

       if (unlikely(arp_hijack_mask || synp_hijack_mask)) {

//                printf("Pkts hijacked arp = %lX, synp = %lX\n",
//			              arp_hijack_mask, synp_hijack_mask);

                rte_pipeline_ah_packet_hijack(p,(arp_hijack_mask | synp_hijack_mask));
        }

       pkts_drop_mask = packet_mask_in & ~keep_mask;

       if (unlikely(pkts_drop_mask != 0)) {
              /* printf("drop %p\n", (void *) pkts_drop_mask); */
              rte_pipeline_ah_packet_drop(p, pkts_drop_mask);
       }

       vfw_pipe->counters->num_batch_pkts_sum += n_pkts;
       vfw_pipe->counters->num_pkts_measurements++;

       end_tsc_measure(vfw_pipe, n_pkts);

       return 0;
}
/**
 * The pipeline port-in action is used to do all the firewall and
 * connection tracking work for IPV6 packet.
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
vfw_port_in_action_ipv6(struct rte_pipeline *p,
              struct rte_mbuf **pkts,
              __rte_unused uint32_t n_pkts, __rte_unused void *arg)
{
       struct vfw_ports_in_args *port_in_args =
              (struct vfw_ports_in_args *)arg;
       struct pipeline_vfw *vfw_pipe =
              (struct pipeline_vfw *)port_in_args->pipe;
       struct rte_ct_cnxn_tracker *ct = port_in_args->cnxn_tracker;

       start_tsc_measure(vfw_pipe);

       uint64_t packet_mask_in = RTE_LEN2MASK(n_pkts, uint64_t);
       uint64_t pkts_drop_mask;
       uint64_t synp_hijack_mask = 0;
       uint64_t arp_hijack_mask = 0;
//       uint64_t hijack_mask = 0;
//       uint64_t synproxy_reply_mask = 0;       /* for synproxy */
       uint64_t keep_mask = packet_mask_in;

       uint64_t conntrack_mask = 0, connexist_mask = 0;
       struct rte_CT_helper ct_helper;
       uint32_t j;

       /*
        * This routine uses a bit mask to represent which packets in the
        * "pkts" table are considered valid. Any table entry which exists
        * and is considered valid has the corresponding bit in the mask set.
        * Otherwise, it is cleared. Note that the mask is 64 bits,
        * but the number of packets in the table may be considerably less.
        * Any mask bits which do correspond to actual packets are cleared.
        * Various routines are called which may determine that an existing
        * packet is somehow invalid. The routine will return an altered bit
        * mask, with the bit cleared. At the end of all the checks,
        * packets are dropped if their mask bit is a zero
        */

       rte_prefetch0(& vfw_pipe->counters);

       /* Pre-fetch all rte_mbuf header */
       for(j = 0; j < n_pkts; j++)
               rte_prefetch0(pkts[j]);

       memset(&ct_helper, 0, sizeof(struct rte_CT_helper));
       rte_prefetch0(& vfw_pipe->counters->pkts_drop_ttl);
       rte_prefetch0(& vfw_pipe->counters->sum_latencies);

       if (vfw_debug > 1)
              printf("Enter in-port action with %p packet mask\n",
                            (void *)packet_mask_in);
       vfw_pipe->counters->pkts_received =
              vfw_pipe->counters->pkts_received + n_pkts;
       if (VFW_DEBUG)
              printf("vfw_port_in_action pkts_received: %" PRIu64
                            " n_pkts: %u\n",
                            vfw_pipe->counters->pkts_received, n_pkts);

       /* first handle handle any previously buffered packets now released */
       vfw_handle_buffered_packets(p, vfw_pipe, ct,
                     FORWARD_BUFFERED_PACKETS);

       /* now handle any new packets on input ports */
       if (likely(firewall_flag)) {
              keep_mask = rte_vfw_ipv6_packet_filter_and_process(pkts,
                            keep_mask, vfw_pipe);
              vfw_pipe->counters->pkts_fw_forwarded +=
                     __builtin_popcountll(keep_mask);
       }
#ifdef ACL_ENABLE

#ifdef EN_SWP_ACL
       rte_prefetch0((void*)vfw_pipe->plib_acl);
       rte_prefetch0((void*)vfw_rule_table_ipv6_active);
#endif /* EN_SWP_ACL */
       keep_mask = lib_acl_ipv6_pkt_work_key(
                     vfw_pipe->plib_acl, pkts, keep_mask,
                     &vfw_pipe->counters->pkts_drop_without_rule,
                     vfw_rule_table_ipv6_active,
                     action_array_active,
                     action_counter_table,
                     &conntrack_mask, &connexist_mask);
       vfw_pipe->counters->pkts_acl_forwarded +=
              __builtin_popcountll(keep_mask);
       if (conntrack_mask > 0) {
              keep_mask = conntrack_mask;
              ct_helper.no_new_cnxn_mask = connexist_mask;
              cnxn_tracking_is_active = 1;
       } else
              cnxn_tracking_is_active = 0;
#endif /* ACL_ENABLE */
       if (likely(cnxn_tracking_is_active)) {
              rte_ct_cnxn_tracker_batch_lookup_type(ct, pkts,
                            &keep_mask, &ct_helper, IPv6_HEADER_SIZE);
//              synproxy_reply_mask = ct_helper.reply_pkt_mask;
              synp_hijack_mask = ct_helper.hijack_mask;

       }

#ifdef EN_SWP_ARP
       for(j = 0; j < (n_pkts & 0x3LLU); j++) {
               rte_prefetch0(RTE_MBUF_METADATA_UINT32_PTR(pkts[j],
                                   META_DATA_OFFSET));
               rte_prefetch0(RTE_MBUF_METADATA_UINT32_PTR(pkts[j],
                                   ETHERNET_START));
       }
       rte_prefetch0((void*)in_port_dir_a);
 //      rte_prefetch0(vfw_pipe->local_lib_nd_route_table);
       uint32_t i;

       for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4) {
              for (j = i+4; ((j < n_pkts) && (j < i+8)); j++) {
                     rte_prefetch0(RTE_MBUF_METADATA_UINT32_PTR(pkts[j],
                                          META_DATA_OFFSET));
                     rte_prefetch0(RTE_MBUF_METADATA_UINT32_PTR(pkts[j],
                                          ETHERNET_START));
              }
              pkt4_work_vfw_arp_ipv6_packets(&pkts[i], i, &keep_mask,
                            synproxy_reply_mask, vfw_pipe);
       }
       for (j = i; j < n_pkts; j++) {
              rte_prefetch0(RTE_MBUF_METADATA_UINT32_PTR(pkts[j],
                                   META_DATA_OFFSET));
              rte_prefetch0(RTE_MBUF_METADATA_UINT32_PTR(pkts[j],
                                   ETHERNET_START));
       }
       for (; i < n_pkts; i++) {
              pkt_work_vfw_arp_ipv6_packets(pkts[i], i, &keep_mask,
                            synproxy_reply_mask, vfw_pipe);
       }
#else
       rte_prefetch0((void*)in_port_dir_a);

	vfw_fwd_pkts_ipv6(pkts, &keep_mask, &arp_hijack_mask, vfw_pipe);

#endif

       if (vfw_debug > 1) {
              printf("  Exit in-port action with %p packet mask\n",
                            (void *)keep_mask);
              if (keep_mask != packet_mask_in)
                     printf("dropped packets, %p in, %p out\n",
                                   (void *)packet_mask_in,
                                   (void *)keep_mask);
       }

	/* Hijack the Synproxy and ARP buffered packets */

        if (unlikely(arp_hijack_mask || synp_hijack_mask)) {

//                printf("Pkts hijacked arp = %lX, synp = %lX\n",
//			              arp_hijack_mask, synp_hijack_mask);

                rte_pipeline_ah_packet_hijack(p,(arp_hijack_mask | synp_hijack_mask));
        }

       /* Update mask before returning, so that bad packets are dropped */

       pkts_drop_mask = packet_mask_in & ~keep_mask;

       if (unlikely(pkts_drop_mask != 0)) {
              /* printf("drop %p\n", (void *) pkts_drop_mask); */
              rte_pipeline_ah_packet_drop(p, pkts_drop_mask);
       }

       vfw_pipe->counters->num_batch_pkts_sum += n_pkts;
       vfw_pipe->counters->num_pkts_measurements++;

       end_tsc_measure(vfw_pipe, n_pkts);

       return 0;
}


/**
 * Parse arguments in config file.
 *
 * @param vfw_pipe
 *  A pointer to the pipeline.
 * @param params
 *  A pointer to pipeline specific parameters.
 *
 * @return
 *  0 on success, negative on error.
 */
static int
pipeline_vfw_parse_args(struct pipeline_vfw *vfw_pipe,
              struct pipeline_params *params)
{
       uint32_t i;
       int status;

       if (vfw_debug)
              printf("VFW pipeline_vfw_parse_args params->n_args: %d\n",
                            params->n_args);

       for (i = 0; i < params->n_args; i++) {
              char *arg_name = params->args_name[i];
              char *arg_value = params->args_value[i];

              printf("VFW args[%d]: %s %d, %s\n", i, arg_name,
                            atoi(arg_value), arg_value);
#ifdef ACL_ENABLE
              status = lib_acl_parse_config(vfw_pipe->plib_acl,
                                   arg_name, arg_value, &vfw_n_rules);
              if (status < 0) {
                     printf("rte_ct_set_configuration_options =%s,%s",
                                   arg_name, arg_value);
                     return -1;
              } else if (status == 0)
                     continue;

#endif              /* traffic_type */
              if (strcmp(arg_name, "traffic_type") == 0) {
                     int traffic_type = atoi(arg_value);

                     if (traffic_type == 0 ||
                                   !(traffic_type == IP_VERSION_4 ||
                                          traffic_type == IP_VERSION_6)) {
                            printf("not IPV4/IPV6");
                            return -1;
                     }

                     vfw_pipe->traffic_type = traffic_type;
                     continue;
              }


              /* n_flows */
              if (strcmp(arg_name, "n_flows") == 0) {
                     int n_flows = atoi(arg_value);

                     if ((n_flows == 0) || (n_flows > 8000000))
                            return -1;

                     /* must be power of 2, round up if not */
                     if (!rte_is_power_of_2(n_flows))
                            n_flows = rte_align32pow2(n_flows);

                     vfw_pipe->n_flows = n_flows;
                     continue;
              }

              /* not firewall option, process as cnxn tracking option */
              status = rte_ct_set_configuration_options(
                            vfw_pipe->cnxn_tracker,
                            arg_name, arg_value);
              if (status < 0) {
                     printf("rte_ct_set_configuration_options =%s,%s",
                                   arg_name, arg_value);
                     return -1;
              } else if (status == 0)
                     continue;

       }

       return 0;
}

static void *pipeline_vfw_msg_req_custom_handler(struct pipeline *p,
                                              void *msg);

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
       [PIPELINE_MSG_REQ_CUSTOM] = pipeline_vfw_msg_req_custom_handler,
};

static void *pipeline_vfw_msg_req_synproxy_flag_handler(struct pipeline *p,
                                                    void *msg);
static pipeline_msg_req_handler custom_handlers[] = {

       [PIPELINE_VFW_MSG_REQ_SYNPROXY_FLAGS] =
           pipeline_vfw_msg_req_synproxy_flag_handler
};

/**
 * Create and initialize Pipeline Back End (BE).
 *
 * @param params
 *  A pointer to the pipeline specific parameters..
 * @param arg
 *  A pointer to pipeline specific data.
 *
 * @return
 *  A pointer to the pipeline create, NULL on error.
 */
static void
*pipeline_vfw_init(struct pipeline_params *params, __rte_unused void *arg)
{
       uint32_t size, i;

       /* Check input arguments */
       if ((params == NULL) ||
                     (params->n_ports_in == 0) || (params->n_ports_out == 0))
              return NULL;

       if (vfw_debug)
              printf("num ports in %d / num ports out %d\n",
                            params->n_ports_in, params->n_ports_out);

       /* Create a single pipeline instance and initialize. */
       struct pipeline_vfw *pipe_vfw;

       size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct pipeline_vfw));
       pipe_vfw = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);

       if (pipe_vfw == NULL)
              return NULL;

       struct pipeline *pipe;

       pipe = &pipe_vfw->pipe;

       strncpy(pipe->name, params->name, sizeof(pipe->name));
       pipe->log_level = params->log_level;
       pipe_vfw->n_flows = 4096;       /* small default value */
       pipe_vfw->traffic_type = IP_VERSION_4;
       pipe_vfw->pipeline_num = 0xff;
       for (i = 0; i < PIPELINE_MAX_PORT_IN; i++) {
              pipe_vfw->links_map[i] = 0xff;
              pipe_vfw->outport_id[i] = 0xff;
       }
       PLOG(pipe, HIGH, "VFW");

       /* Create a firewall instance and initialize. */
       pipe_vfw->cnxn_tracker =
              rte_zmalloc(NULL, rte_ct_get_cnxn_tracker_size(),
                            RTE_CACHE_LINE_SIZE);

       if (pipe_vfw->cnxn_tracker == NULL)
              return NULL;
#ifdef ACL_ENABLE
       /* Create a acl instance and initialize. */
       pipe_vfw->plib_acl =
              rte_zmalloc(NULL, sizeof(struct lib_acl),
                            RTE_CACHE_LINE_SIZE);

       if (pipe_vfw->plib_acl == NULL)
              return NULL;
#endif
       timer_lcore = rte_lcore_id();
       /*
        * Now allocate a counter block entry. It appears that the
        * initialization of all instances is serialized on core 0,
        * so no lock is necessary.
        */
       struct rte_VFW_counter_block *counter_ptr;

       if (rte_VFW_hi_counter_block_in_use == MAX_VFW_INSTANCES)
              /* error, exceeded table bounds */
              return NULL;

       rte_VFW_hi_counter_block_in_use++;
       counter_ptr =
              &rte_vfw_counter_table[rte_VFW_hi_counter_block_in_use];
       strncpy(counter_ptr->name, params->name, sizeof(counter_ptr->name));

       pipe_vfw->counters = counter_ptr;

       rte_ct_initialize_default_timeouts(pipe_vfw->cnxn_tracker);
       /* Parse arguments */
       if (pipeline_vfw_parse_args(pipe_vfw, params))
              return NULL;

       uint16_t pointers_offset =
              META_DATA_OFFSET + offsetof(struct mbuf_tcp_meta_data, next);

       if (pipe_vfw->n_flows > 0)
              rte_ct_initialize_cnxn_tracker_with_synproxy(
                            pipe_vfw->cnxn_tracker,
                            pipe_vfw->n_flows,
                            params->name,
                            pointers_offset);

       pipe_vfw->counters->ct_counters =
              rte_ct_get_counter_address(pipe_vfw->cnxn_tracker);

       /* Pipeline */
       {
              struct rte_pipeline_params pipeline_params = {
                     .name = params->name,
                     .socket_id = params->socket_id,
                     .offset_port_id = META_DATA_OFFSET +
                            offsetof(struct mbuf_tcp_meta_data, output_port)
              };

              pipe->p = rte_pipeline_create(&pipeline_params);
              if (pipe->p == NULL) {
                     rte_free(pipe_vfw);
                     return NULL;
              }
       }

       /* Input ports */

       /*
        * create a different "arg_ah" for each input port.
        * They differ only in the recorded port number. Unfortunately,
        * IP_PIPELINE does not pass port number in to input port handler
        */

       uint32_t in_ports_arg_size =
              RTE_CACHE_LINE_ROUNDUP((sizeof(struct vfw_ports_in_args)) *
                            (params->n_ports_in));
       struct vfw_ports_in_args *port_in_args =
              (struct vfw_ports_in_args *)
              rte_zmalloc(NULL, in_ports_arg_size, RTE_CACHE_LINE_SIZE);

       if (port_in_args == NULL)
              return NULL;

       pipe->n_ports_in = params->n_ports_in;
       for (i = 0; i < pipe->n_ports_in; i++) {

              /* initialize this instance of port_in_args as necessary */
              port_in_args[i].pipe = pipe;
              port_in_args[i].cnxn_tracker = pipe_vfw->cnxn_tracker;

              struct rte_pipeline_port_in_params port_params = {
                     .ops =
                            pipeline_port_in_params_get_ops(&params->port_in
                                          [i]),
                     .arg_create =
                            pipeline_port_in_params_convert(&params->port_in
                                          [i]),
                     .f_action = vfw_port_in_action_ipv4,
                     .arg_ah = &(port_in_args[i]),
                     .burst_size = params->port_in[i].burst_size,
              };
               if (pipe_vfw->traffic_type == IP_VERSION_6)
                     port_params.f_action = vfw_port_in_action_ipv6;
              int status = rte_pipeline_port_in_create(pipe->p, &port_params,
                            &pipe->port_in_id[i]);

              if (status) {
                     rte_pipeline_free(pipe->p);
                     rte_free(pipe_vfw);
                     return NULL;
              }
       }

       /* Output ports */
       pipe->n_ports_out = params->n_ports_out;
       for (i = 0; i < pipe->n_ports_out; i++) {
              struct rte_pipeline_port_out_params port_params = {
                     .ops = pipeline_port_out_params_get_ops(
                                   &params->port_out[i]),
                     .arg_create = pipeline_port_out_params_convert(
                                   &params->port_out[i]),
                     .f_action = NULL,
                     .arg_ah = NULL,
              };

              int status = rte_pipeline_port_out_create(pipe->p, &port_params,
                            &pipe->port_out_id[i]);

              if (status) {
                     rte_pipeline_free(pipe->p);
                     rte_free(pipe_vfw);
                     return NULL;
              }
       }

       int pipeline_num = 0;
       int dont_care = sscanf(params->name, "PIPELINE%d", &pipeline_num);

       if (dont_care < 0)
              printf("sscanf unble to read pipeline id\n");
       pipe_vfw->pipeline_num = (uint8_t) pipeline_num;
       register_pipeline_Qs(pipe_vfw->pipeline_num, pipe);
       set_link_map(pipe_vfw->pipeline_num, pipe, pipe_vfw->links_map);
       set_outport_id(pipe_vfw->pipeline_num, pipe,
                     pipe_vfw->outport_id);
       printf("pipeline_num=%d\n", pipeline_num);
#ifdef ACL_ENABLE
       /*If this is the first VFW thread, create common VFW Rule tables*/
       if (rte_VFW_hi_counter_block_in_use == 0) {
              vfw_rule_table_ipv4_active =
                     lib_acl_create_active_standby_table_ipv4(1,
                                   &vfw_n_rules);
              if (vfw_rule_table_ipv4_active == NULL) {
                     printf("Failed to create active table for IPV4\n");
                     rte_pipeline_free(pipe->p);
                     rte_free(pipe_vfw->cnxn_tracker);
                     rte_free(pipe_vfw->plib_acl);
                     rte_free(pipe_vfw);
                     return NULL;
              }
              vfw_rule_table_ipv4_standby =
                     lib_acl_create_active_standby_table_ipv4(2,
                                   &vfw_n_rules);
              if (vfw_rule_table_ipv4_standby == NULL) {
                     printf("Failed to create standby table for IPV4\n");
                     rte_pipeline_free(pipe->p);
                     rte_free(pipe_vfw->cnxn_tracker);
                     rte_free(pipe_vfw->plib_acl);
                     rte_free(pipe_vfw);
                     return NULL;
              }

              vfw_rule_table_ipv6_active =
                     lib_acl_create_active_standby_table_ipv6(1,
                                   &vfw_n_rules);

              if (vfw_rule_table_ipv6_active == NULL) {
                     printf("Failed to create active table for IPV6\n");
                     rte_pipeline_free(pipe->p);
                     rte_free(pipe_vfw->cnxn_tracker);
                     rte_free(pipe_vfw->plib_acl);
                     rte_free(pipe_vfw);
                     return NULL;
              }
              vfw_rule_table_ipv6_standby =
                     lib_acl_create_active_standby_table_ipv6(2,
                                   &vfw_n_rules);
              if (vfw_rule_table_ipv6_standby == NULL) {
                     printf("Failed to create standby table for IPV6\n");
                     rte_pipeline_free(pipe->p);
                     rte_free(pipe_vfw->cnxn_tracker);
                     rte_free(pipe_vfw->plib_acl);
                     rte_free(pipe_vfw);
                     return NULL;
              }
       }

#endif

       /* Tables */

       pipe->n_tables = 1;

       struct rte_pipeline_table_params table_params = {
              .ops = &rte_table_stub_ops,
              .arg_create = NULL,
              .f_action_hit = NULL,
              .f_action_miss = NULL,
              .arg_ah = NULL,
              .action_data_size = 0,
       };

       int status = rte_pipeline_table_create(pipe->p,
                     &table_params,
                     &pipe->table_id[0]);

       if (status) {
              rte_pipeline_free(pipe->p);
              rte_free(pipe);
              return NULL;
       }

       struct rte_pipeline_table_entry default_entry = {
              .action = RTE_PIPELINE_ACTION_PORT_META
       };

       struct rte_pipeline_table_entry *default_entry_ptr;

       status = rte_pipeline_table_default_entry_add(pipe->p,
                                                pipe->table_id[0],
                                                &default_entry,
                                                &default_entry_ptr);

       if (status) {
              rte_pipeline_free(pipe->p);
              rte_free(pipe);
              return NULL;
       }
       for (i = 0; i < pipe->n_ports_in; i++) {
              int status = rte_pipeline_port_in_connect_to_table(
                            pipe->p,
                            pipe->port_in_id[i],
                            pipe->table_id[0]);

              if (status) {
                     rte_pipeline_free(pipe->p);
                     rte_free(pipe_vfw);
                     return NULL;
              }
       }

       /* Enable input ports */
       for (i = 0; i < pipe->n_ports_in; i++) {
              int status =
                  rte_pipeline_port_in_enable(pipe->p, pipe->port_in_id[i]);

              if (status) {
                     rte_pipeline_free(pipe->p);
                     rte_free(pipe_vfw);
                     return NULL;
              }
       }

       /* Check pipeline consistency */
       if (rte_pipeline_check(pipe->p) < 0) {
              rte_pipeline_free(pipe->p);
              rte_free(pipe_vfw);
              return NULL;
       }

       /* Message queues */
       pipe->n_msgq = params->n_msgq;
       for (i = 0; i < pipe->n_msgq; i++)
              pipe->msgq_in[i] = params->msgq_in[i];

       for (i = 0; i < pipe->n_msgq; i++)
              pipe->msgq_out[i] = params->msgq_out[i];

       /* Message handlers */
       memcpy(pipe->handlers, handlers, sizeof(pipe->handlers));
       memcpy(pipe_vfw->custom_handlers, custom_handlers,
              sizeof(pipe_vfw->custom_handlers));

       return pipe_vfw;
}

/**
 * Free resources and delete pipeline.
 *
 * @param pipeline
 *  A pointer to the pipeline.
 *
 * @return
 *  0 on success, negative on error.
 */
static int pipeline_vfw_free(void *pipeline)
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
pipeline_vfw_track(void *pipeline, __rte_unused uint32_t port_in,
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
 * Callback function to process timers.
 *
 * @param pipeline
 *  A pointer to the pipeline.
 *
 * @return
 *  0 on success, negative on error.
 */
static int pipeline_vfw_timer(void *pipeline)
{
       struct pipeline_vfw *p = (struct pipeline_vfw *)pipeline;

       /*
        * handle any good buffered packets released by synproxy before checking
        * for packets relased by synproxy due to timeout.
        * Don't want packets missed
        */

       vfw_handle_buffered_packets(p->pipe.p, p, p->cnxn_tracker,
                                   FORWARD_BUFFERED_PACKETS);

       pipeline_msg_req_handle(&p->pipe);
       rte_pipeline_flush(p->pipe.p);

       rte_ct_handle_expired_timers(p->cnxn_tracker);

       /* now handle packets released by synproxy due to timeout. */
       vfw_handle_buffered_packets(p->pipe.p, p, p->cnxn_tracker,
                                   DELETE_BUFFERED_PACKETS);

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
void *pipeline_vfw_msg_req_custom_handler(struct pipeline *p, void *msg)
{
       struct pipeline_vfw *pipe_vfw = (struct pipeline_vfw *)p;
       struct pipeline_custom_msg_req *req = msg;
       pipeline_msg_req_handler f_handle;

       f_handle = (req->subtype < PIPELINE_VFW_MSG_REQS) ?
           pipe_vfw->custom_handlers[req->subtype] :
           pipeline_msg_req_invalid_handler;

       if (f_handle == NULL)
              f_handle = pipeline_msg_req_invalid_handler;

       return f_handle(p, req);
}

/**
 * Handler for synproxy ON/OFF CLI command.
 *
 * @param p
 *  A pointer to the pipeline.
 * @param msg
 *  A pointer to command specific data.
 *
 * @return
 *  Response message contains status.
 */

void *pipeline_vfw_msg_req_synproxy_flag_handler(struct pipeline *p,
                                              void *msg)
{
       struct pipeline_vfw *pipe_vfw = (struct pipeline_vfw *)p;
       struct pipeline_vfw_synproxy_flag_msg_req *req = msg;
       struct pipeline_vfw_synproxy_flag_msg_rsp *rsp = msg;

       if (req->synproxy_flag == 0) {
              rte_ct_disable_synproxy(pipe_vfw->cnxn_tracker);
              rsp->status = 0;
              printf("synproxy turned OFF for %s\n", p->name);
       } else if (req->synproxy_flag == 1) {
              rte_ct_enable_synproxy(pipe_vfw->cnxn_tracker);
              rsp->status = 0;
              printf("synproxy turned ON for %s\n", p->name);
       } else {
              printf("Invalid synproxy setting\n");
              rsp->status = -1;
       }

       return rsp;
}

struct pipeline_be_ops pipeline_vfw_be_ops = {
       .f_init = pipeline_vfw_init,
       .f_free = pipeline_vfw_free,
       .f_run = NULL,
       .f_timer = pipeline_vfw_timer,
       .f_track = pipeline_vfw_track,
};
