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

#include <poll.h>
#include "task_base.h"
#include "task_init.h"

enum arp_actions {
	MAC_INFO_FROM_MASTER,
	MAC_INFO_FROM_MASTER_FOR_IPV6,
	IPV6_INFO_FROM_MASTER,
	ROUTE_ADD_FROM_MASTER,
	ROUTE_DEL_FROM_MASTER,
	SEND_ARP_REQUEST_FROM_MASTER,
	SEND_ARP_REPLY_FROM_MASTER,
	SEND_NDP_FROM_MASTER,
	SEND_ICMP_FROM_MASTER,
	SEND_BGP_FROM_MASTER,
	ARP_PKT_FROM_NET_TO_MASTER,
	NDP_PKT_FROM_NET_TO_MASTER,
	ICMP_TO_MASTER,
	BGP_TO_MASTER,
	IP4_REQ_MAC_TO_MASTER,
	IP6_REQ_MAC_TO_MASTER,
	PKT_FROM_TAP,
	MAX_ACTIONS
};

#define PROX_MAX_ARP_REQUESTS	32	// Maximum number of tasks requesting the same MAC address

#define HANDLE_RANDOM_IP_FLAG		1
#define HANDLE_RANDOM_LOCAL_IP_FLAG	2
#define HANDLE_RANDOM_GLOBAL_IP_FLAG	4
#define IPV6_ROUTER			8
#define RANDOM_IP		0xffffffff

#define PROX_PSEUDO_PKT_PORT 0xdead

struct port_table {
	prox_rte_ether_addr 	mac;
	struct rte_ring 	*ring;
	uint32_t 		ip;
	uint8_t			port;
	uint8_t 		flags;
	struct ipv6_addr	local_ipv6_addr;
	struct ipv6_addr	global_ipv6_addr;
	struct ipv6_addr	router_prefix;
	uint64_t last_echo_req_rcvd_tsc;
	uint64_t last_echo_rep_rcvd_tsc;
	uint32_t n_echo_req;
	uint32_t n_echo_rep;
};

struct ip_table {
	prox_rte_ether_addr 	mac;
	struct rte_ring 	*ring;
};

struct external_ip_table {
	prox_rte_ether_addr 	mac;
	struct rte_ring 	*rings[PROX_MAX_ARP_REQUESTS];
	uint16_t 		nb_requests;
};

struct vdev {
	int port_id;
	struct rte_ring *ring;
};

struct task_master {
        struct task_base base;
	struct rte_ring *ctrl_rx_ring;
	struct rte_ring **ctrl_tx_rings;
	struct ip_table *internal_ip_table;	// Store mac address from our IP
	struct external_ip_table *external_ip_table;	// Store mac address from external systems
	struct ip_table *internal_ip6_table;	// Store mac address from our IP
	struct external_ip_table *external_ip6_table;	// Store mac address from external systems
	struct rte_hash  *external_ip_hash;
	struct rte_hash  *external_ip6_hash;
	struct rte_hash  *internal_ip_hash;
	struct rte_hash  *internal_ip6_hash;
	struct port_table internal_port_table[PROX_MAX_PORTS];
	struct vdev all_vdev[PROX_MAX_PORTS];
	int max_vdev_id;
	struct pollfd arp_fds;
	struct pollfd route_fds;
};

const char *actions_string[MAX_ACTIONS];

void init_ctrl_plane(struct task_base *tbase);

int (*handle_ctrl_plane)(struct task_base *tbase, struct rte_mbuf **mbuf, uint16_t n_pkts);

static inline void tx_drop(struct rte_mbuf *mbuf)
{
	rte_pktmbuf_free(mbuf);
}

void register_ip_to_ctrl_plane(struct task_base *task, uint32_t ip, uint8_t port_id, uint8_t core_id, uint8_t task_id);
void master_init_vdev(struct task_base *task, uint8_t port_id, uint8_t core_id, uint8_t task_id);
void register_router_to_ctrl_plane(struct task_base *tbase, uint8_t port_id, uint8_t core_id, uint8_t task_id, struct ipv6_addr *local_ipv6_addr, struct ipv6_addr *global_ipv6_addr, struct ipv6_addr *router_prefix);
void register_node_to_ctrl_plane(struct task_base *tbase, struct ipv6_addr *local_ipv6_addr, struct ipv6_addr *global_ipv6_addr, uint8_t port_id, uint8_t core_id, uint8_t task_id);
