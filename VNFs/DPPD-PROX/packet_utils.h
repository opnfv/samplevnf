/*
// Copyright (c) 2010-2017 Intel Corporation
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

#define IP4(x) x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, x >> 24	// From Network (BE)
enum {
	SEND_MBUF_AND_ARP,
	SEND_MBUF,
	SEND_ARP,
	DROP_MBUF
};
#define DEFAULT_ARP_TIMEOUT	(1000 * 3600 * 24 * 15)	// ~15 days = disabled by default
#define DEFAULT_ARP_UPDATE_TIME (1000)			// 1 second

struct task_base;
struct task_args;
struct arp_table {
	uint64_t arp_update_time;
	uint64_t arp_timeout;
	uint32_t ip;
	uint32_t nh;
	prox_rte_ether_addr mac;
};
struct l3_base {
	struct rte_ring *ctrl_plane_ring;
	struct task_base *tmaster;
	uint32_t flags;
	uint32_t n_pkts;
	uint8_t reachable_port_id;
	uint8_t core_id;
	uint8_t task_id;
	uint32_t arp_timeout;
	uint32_t arp_update_time;
	uint seed;
	prox_next_hop_index_type nb_gws;
	struct arp_table gw;
	struct arp_table optimized_arp_table[4];
	struct rte_hash *ip_hash;
	struct arp_table *arp_table;
	struct rte_mempool *arp_pool;
	struct rte_lpm *ipv4_lpm;
	struct arp_table *next_hops;
};

void task_init_l3(struct task_base *tbase, struct task_args *targ);
void task_start_l3(struct task_base *tbase, struct task_args *targ);
int write_dst_mac(struct task_base *tbase, struct rte_mbuf *mbuf, uint32_t *ip_dst, uint64_t **time);
void task_set_gateway_ip(struct task_base *tbase, uint32_t ip);
void task_set_local_ip(struct task_base *tbase, uint32_t ip);
void handle_ctrl_plane_pkts(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts);

static inline void update_arp_update_time(struct l3_base *l3, uint64_t *ptr, uint32_t base)
{
	// randomize timers - from 0.5 to 1.5 * configured time
	const uint64_t hz = rte_get_tsc_hz();
	uint64_t tsc = rte_rdtsc();
	uint64_t rand = 500 + (1000L * rand_r(&l3->seed)) / RAND_MAX;
	*ptr = tsc + (base * rand / 1000) * hz / 1000;
}
#endif /* _PACKET_UTILS_H_ */
