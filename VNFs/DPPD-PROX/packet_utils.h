/*
// Copyright (c) 2010-2020 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
#ifndef _PACKET_UTILS_H_
#define _PACKET_UTILS_H_

#include "prox_compat.h"
#include "arp.h"
#include "quit.h"
#include "prox_malloc.h"
#include "defaults.h"
#include "prox_cfg.h"
#include "etypes.h"

#define FLAG_DST_MAC_KNOWN	1
#define MAX_ARP_ENTRIES	65536

#define IP4(x) x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, x >> 24
enum {
	SEND_MBUF_AND_ARP_ND,
	SEND_MBUF,
	SEND_ARP_ND,
	DROP_MBUF
};
#define DEFAULT_ARP_TIMEOUT	(1000 * 3600 * 24 * 15)	// ~15 days = disabled by default
#define DEFAULT_ARP_UPDATE_TIME (1000)			// 1 second

struct task_base;
struct task_args;
struct task_master;
struct arp_table {
	uint64_t arp_ndp_retransmit_timeout;
	uint64_t reachable_timeout;
	uint32_t ip;
	prox_rte_ether_addr mac;
	struct ipv6_addr ip6;
};
struct l3_base {
	struct rte_ring *ctrl_plane_ring;
	struct task_base *tmaster;
	uint32_t flags;
	uint32_t n_pkts;
	uint32_t local_ipv4;
	uint8_t reachable_port_id;
	uint8_t core_id;
	uint8_t task_id;
	uint32_t arp_ndp_retransmit_timeout;
	uint32_t reachable_timeout;
	struct arp_table gw;
	struct arp_table optimized_arp_table[4];
	struct rte_hash *ip_hash;
	struct rte_hash *ip6_hash;
	struct arp_table *arp_table;
	struct rte_mempool *arp_nd_pool;
	struct ipv6_addr local_ipv6;
	struct ipv6_addr global_ipv6;
};

void task_init_l3(struct task_base *tbase, struct task_args *targ);
void task_start_l3(struct task_base *tbase, struct task_args *targ);
int write_dst_mac(struct task_base *tbase, struct rte_mbuf *mbuf, uint32_t *ip_dst);
int write_ip6_dst_mac(struct task_base *tbase, struct rte_mbuf *mbuf, struct ipv6_addr *ip_dst);
void task_set_gateway_ip(struct task_base *tbase, uint32_t ip);
void task_set_local_ip(struct task_base *tbase, uint32_t ip);
void handle_ctrl_plane_pkts(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts);
void build_router_advertisement(struct rte_mbuf *mbuf, prox_rte_ether_addr *s_addr, struct ipv6_addr *ipv6_s_addr, struct ipv6_addr *router_prefix);

static inline uint8_t get_port(struct rte_mbuf *mbuf)
{
        return mbuf->port;
}

#endif /* _PACKET_UTILS_H_ */
