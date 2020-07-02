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

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ether.h>
#include <rte_icmp.h>

#include "prox_cfg.h"
#include "prox_globals.h"
#include "rx_pkt.h"
#include "arp.h"
#include "handle_master.h"
#include "log.h"
#include "mbuf_utils.h"
#include "etypes.h"
#include "defaults.h"
#include "prox_malloc.h"
#include "quit.h"
#include "task_init.h"
#include "prox_port_cfg.h"
#include "main.h"
#include "lconf.h"
#include "input.h"
#include "tx_pkt.h"
#include "defines.h"
#include "prox_ipv6.h"
#include "packet_utils.h"

#define PROX_MAX_ARP_REQUESTS	32	// Maximum number of tasks requesting the same MAC address
#define NETLINK_BUF_SIZE	16384

static char netlink_buf[NETLINK_BUF_SIZE];

const char *actions_string[] = {
	"MAC_INFO_FROM_MASTER",		// Controlplane sending a MAC update to dataplane
	"MAC_INFO_FROM_MASTER_FOR_IPV6",// Controlplane sending a MAC update to dataplane
	"IPV6_INFO_FROM_MASTER",	// Controlplane IPv6 Global IP info to dataplane
	"ROUTE_ADD_FROM_MASTER",	// Controlplane sending a new route to dataplane
	"ROUTE_DEL_FROM_MASTER",	// Controlplane deleting a new route from dataplane
	"SEND_ARP_REQUEST_FROM_MASTER",	// Controlplane requesting dataplane to send ARP request
	"SEND_ARP_REPLY_FROM_MASTER",	// Controlplane requesting dataplane to send ARP reply
	"SEND_NDP_FROM_MASTER",		// Controlplane requesting dataplane to send NDP
	"SEND_ICMP_FROM_MASTER",	// Controlplane requesting dataplane to send ICMP message
	"SEND_BGP_FROM_MASTER",		// Controlplane requesting dataplane to send BGP message
	"ARP_PKT_FROM_NET_TO_MASTER",	// ARP sent by datplane to Controlpane for handling
	"NDP_PKT_FROM_NET_TO_MASTER,"	// NDP sent by datplane to Controlpane for handling
	"ICMP_TO_MASTER",		// ICMP sent by datplane to Controlpane for handling
	"BGP_TO_MASTER"			// BGP sent by datplane to Controlpane for handling
	"IP4_REQ_MAC_TO_MASTER",	// Dataplane requesting MAC resolution to Controlplane
	"IP6_REQ_MAC_TO_MASTER",	// Dataplane requesting MAC resolution to Controlplane
	"PKT_FROM_TAP"			// Packet received by Controlplane from kernel and forwarded to dataplane for sending

};

static struct my_arp_t arp_reply = {
	.htype = 0x100,
	.ptype = 8,
	.hlen = 6,
	.plen = 4,
	.oper = 0x200
};
static struct my_arp_t arp_request = {
	.htype = 0x100,
	.ptype = 8,
	.hlen = 6,
	.plen = 4,
	.oper = 0x100
};

struct ip_port {
	uint32_t ip;
	uint8_t port;
} __attribute__((packed));

struct ip6_port {
	struct ipv6_addr ip6;
	uint8_t port;
} __attribute__((packed));

void register_router_to_ctrl_plane(struct task_base *tbase, uint8_t port_id, uint8_t core_id, uint8_t task_id, struct ipv6_addr *local_ipv6_addr, struct ipv6_addr *global_ipv6_addr, struct ipv6_addr *router_prefix)
{
	struct task_master *task = (struct task_master *)tbase;
	task->internal_port_table[port_id].flags |= IPV6_ROUTER;
	memcpy(&task->internal_port_table[port_id].router_prefix, router_prefix, sizeof(struct ipv6_addr));
	register_node_to_ctrl_plane(tbase, local_ipv6_addr, global_ipv6_addr, port_id, core_id, task_id);
}

void register_node_to_ctrl_plane(struct task_base *tbase, struct ipv6_addr *local_ipv6_addr, struct ipv6_addr *global_ipv6_addr, uint8_t port_id, uint8_t core_id, uint8_t task_id)
{
	struct task_master *task = (struct task_master *)tbase;
	if (task->internal_port_table[port_id].flags & IPV6_ROUTER)
		plogx_dbg("\tregistering router with port %d core %d and task %d\n", port_id, core_id, task_id);
	else
		plogx_dbg("\tregistering node with port %d core %d and task %d\n", port_id, core_id, task_id);

	if (port_id >= PROX_MAX_PORTS) {
		plog_err("Unable to register router, port %d\n", port_id);
		return;
	}
	task->internal_port_table[port_id].ring = task->ctrl_tx_rings[core_id * MAX_TASKS_PER_CORE + task_id];
	memcpy(&task->internal_port_table[port_id].mac, &prox_port_cfg[port_id].eth_addr, sizeof(prox_rte_ether_addr));
	memcpy(&task->internal_port_table[port_id].local_ipv6_addr, local_ipv6_addr, sizeof(struct ipv6_addr));
	if (memcmp(local_ipv6_addr, &prox_cfg.random_ip, sizeof(struct ipv6_addr)) == 0) {
		task->internal_port_table[port_id].flags |= HANDLE_RANDOM_LOCAL_IP_FLAG;
		return;
	}
	memcpy(&task->internal_port_table[port_id].global_ipv6_addr, global_ipv6_addr, sizeof(struct ipv6_addr));
	if (memcmp(global_ipv6_addr, &prox_cfg.random_ip, sizeof(struct ipv6_addr)) == 0) {
		task->internal_port_table[port_id].flags |= HANDLE_RANDOM_GLOBAL_IP_FLAG;
		return;
	}
	struct ip6_port key;
	memcpy(&key.ip6, local_ipv6_addr, sizeof(struct ipv6_addr));
	key.port = port_id;
	int ret = rte_hash_add_key(task->internal_ip6_hash, (const void *)&key);
	if (unlikely(ret < 0)) {
		plog_err("Unable to register ip "IPv6_BYTES_FMT"\n", IPv6_BYTES(local_ipv6_addr->bytes));
		return;
	}
	memcpy(&key.ip6, global_ipv6_addr, sizeof(struct ipv6_addr));
	ret = rte_hash_add_key(task->internal_ip6_hash, (const void *)&key);
	if (unlikely(ret < 0)) {
		plog_err("Unable to register ip "IPv6_BYTES_FMT"\n", IPv6_BYTES(global_ipv6_addr->bytes));
		return;
	}
	memcpy(&task->internal_ip6_table[ret].mac, &prox_port_cfg[port_id].eth_addr, sizeof(prox_rte_ether_addr));
	task->internal_ip6_table[ret].ring = task->ctrl_tx_rings[core_id * MAX_TASKS_PER_CORE + task_id];
}

void master_init_vdev(struct task_base *tbase, uint8_t port_id, uint8_t core_id, uint8_t task_id)
{
	struct task_master *task = (struct task_master *)tbase;
	uint8_t vdev_port = prox_port_cfg[port_id].dpdk_mapping;
	int rc, i;
	if (vdev_port != NO_VDEV_PORT) {
		for (i = 0; i < task->max_vdev_id; i++) {
			if (task->all_vdev[i].port_id == vdev_port)
				break;
		}
		if (i <  task->max_vdev_id) {
			// Already initialized (e.g. by another core handling the same port).
			return;
		}
		task->all_vdev[task->max_vdev_id].port_id = vdev_port;
	 	task->all_vdev[task->max_vdev_id].ring = task->ctrl_tx_rings[core_id * MAX_TASKS_PER_CORE + task_id];

		struct sockaddr_in dst, src;
		src.sin_family = AF_INET;
		src.sin_addr.s_addr = prox_port_cfg[vdev_port].ip;
		src.sin_port = rte_cpu_to_be_16(PROX_PSEUDO_PKT_PORT);

		int fd = socket(AF_INET,  SOCK_DGRAM, 0);
		PROX_PANIC(fd < 0, "Failed to open socket(AF_INET,  SOCK_DGRAM, 0)\n");
		prox_port_cfg[vdev_port].fd = fd;
		rc = bind(fd,(struct sockaddr *)&src, sizeof(struct sockaddr_in));
		PROX_PANIC(rc, "Failed to bind("IPv4_BYTES_FMT":%d): errno = %d (%s)\n", IPv4_BYTES(((uint8_t*)&src.sin_addr.s_addr)), src.sin_port, errno, strerror(errno));
		plog_info("DPDK port %d bound("IPv4_BYTES_FMT":%d) to fd %d\n", port_id, IPv4_BYTES(((uint8_t*)&src.sin_addr.s_addr)), src.sin_port, fd);
		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
		task->max_vdev_id++;
	}
}

void register_ip_to_ctrl_plane(struct task_base *tbase, uint32_t ip, uint8_t port_id, uint8_t core_id, uint8_t task_id)
{
	struct task_master *task = (struct task_master *)tbase;
	struct ip_port key;
	plogx_info("\tregistering IP "IPv4_BYTES_FMT" with port %d core %d and task %d\n", IP4(ip), port_id, core_id, task_id);

	if (port_id >= PROX_MAX_PORTS) {
		plog_err("Unable to register ip "IPv4_BYTES_FMT", port %d\n", IP4(ip), port_id);
		return;
	}

	/* TODO - store multiple rings if multiple cores able to handle IP
	   Remove them when such cores are stopped and de-register IP
	*/
	task->internal_port_table[port_id].ring = task->ctrl_tx_rings[core_id * MAX_TASKS_PER_CORE + task_id];
	memcpy(&task->internal_port_table[port_id].mac, &prox_port_cfg[port_id].eth_addr, sizeof(prox_rte_ether_addr));
	task->internal_port_table[port_id].ip = ip;

	if (ip == RANDOM_IP) {
		task->internal_port_table[port_id].flags |= HANDLE_RANDOM_IP_FLAG;
		return;
	}

	key.ip = ip;
	key.port = port_id;
	int ret = rte_hash_add_key(task->internal_ip_hash, (const void *)&key);
	if (unlikely(ret < 0)) {
		plog_err("Unable to register ip "IPv4_BYTES_FMT"\n", IP4(ip));
		return;
	}
	memcpy(&task->internal_ip_table[ret].mac, &prox_port_cfg[port_id].eth_addr, sizeof(prox_rte_ether_addr));
	task->internal_ip_table[ret].ring = task->ctrl_tx_rings[core_id * MAX_TASKS_PER_CORE + task_id];
}

static inline void handle_arp_reply(struct task_base *tbase, struct rte_mbuf *mbuf, struct my_arp_t *arp)
{
	struct task_master *task = (struct task_master *)tbase;
	int i, ret;
	uint32_t key = arp->data.spa;
	plogx_dbg("\tMaster handling ARP reply for ip "IPv4_BYTES_FMT"\n", IP4(key));

	ret = rte_hash_lookup(task->external_ip_hash, (const void *)&key);
	if (unlikely(ret < 0)) {
		// entry not found for this IP: we did not ask a request, delete the reply
		tx_drop(mbuf);
	} else {
		// entry found for this IP
		uint16_t nb_requests = task->external_ip_table[ret].nb_requests;
		// If we receive a request from multiple task for the same IP, then we update all tasks
		if (task->external_ip_table[ret].nb_requests) {
			rte_mbuf_refcnt_set(mbuf, nb_requests);
			for (int i = 0; i < nb_requests; i++) {
				struct rte_ring *ring = task->external_ip_table[ret].rings[i];
				tx_ring_ip(tbase, ring, MAC_INFO_FROM_MASTER, mbuf, key);
			}
			task->external_ip_table[ret].nb_requests = 0;
		} else {
			tx_drop(mbuf);
		}
	}
}

static inline void handle_arp_request(struct task_base *tbase, struct rte_mbuf *mbuf, struct my_arp_t *arp)
{
	struct task_master *task = (struct task_master *)tbase;
	prox_rte_ether_hdr *ether_hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
	int i, ret;
	uint8_t port = get_port(mbuf);

	struct ip_port key;
	key.ip = arp->data.tpa;
	key.port = port;
	if (task->internal_port_table[port].flags & HANDLE_RANDOM_IP_FLAG) {
		prox_rte_ether_addr mac;
		plogx_dbg("\tMaster handling ARP request for ip "IPv4_BYTES_FMT" on port %d which supports random ip\n", IP4(key.ip), key.port);
		struct rte_ring *ring = task->internal_port_table[port].ring;
		create_mac(arp, &mac);
		mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);
		build_arp_reply(ether_hdr, &mac, arp);
		tx_ring(tbase, ring, SEND_ARP_REPLY_FROM_MASTER, mbuf);
		return;
	}

	plogx_dbg("\tMaster handling ARP request for ip "IPv4_BYTES_FMT"\n", IP4(key.ip));

	ret = rte_hash_lookup(task->internal_ip_hash, (const void *)&key);
	if (unlikely(ret < 0)) {
		// entry not found for this IP.
		plogx_dbg("Master ignoring ARP REQUEST received on un-registered IP "IPv4_BYTES_FMT" on port %d\n", IP4(arp->data.tpa), port);
		tx_drop(mbuf);
	} else {
		struct rte_ring *ring = task->internal_ip_table[ret].ring;
		mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);
		build_arp_reply(ether_hdr, &task->internal_ip_table[ret].mac, arp);
		tx_ring(tbase, ring, SEND_ARP_REPLY_FROM_MASTER, mbuf);
	}
}

static inline int record_request(struct task_base *tbase, uint32_t ip_dst, uint8_t port, struct rte_ring *ring)
{
	struct task_master *task = (struct task_master *)tbase;
	int ret = rte_hash_add_key(task->external_ip_hash, (const void *)&ip_dst);
	int i;

	if (unlikely(ret < 0)) {
		plogx_dbg("Unable to add IP "IPv4_BYTES_FMT" in external_ip_hash\n", IP4(ip_dst));
		return -1;
	}

	// If multiple tasks requesting the same info, we will need to send a reply to all of them
	// However if one task sends multiple requests to the same IP (e.g. because it is not answering)
	// then we should not send multiple replies to the same task
	if (task->external_ip_table[ret].nb_requests >= PROX_MAX_ARP_REQUESTS) {
		// This can only happen if really many tasks requests the same IP
		plogx_dbg("Unable to add request for IP "IPv4_BYTES_FMT" in external_ip_table\n", IP4(ip_dst));
		return -1;
	}
	for (i = 0; i < task->external_ip_table[ret].nb_requests; i++) {
		if (task->external_ip_table[ret].rings[i] == ring)
			break;
	}
	if (i >= task->external_ip_table[ret].nb_requests) {
		// If this is a new request i.e. a new task requesting a new IP
		task->external_ip_table[ret].rings[task->external_ip_table[ret].nb_requests] = ring;
		task->external_ip_table[ret].nb_requests++;
	}
	return 0;
}

static inline void handle_unknown_ip(struct task_base *tbase, struct rte_mbuf *mbuf)
{
	struct task_master *task = (struct task_master *)tbase;
	struct ether_hdr_arp *hdr_arp = rte_pktmbuf_mtod(mbuf, struct ether_hdr_arp *);
	uint8_t port = get_port(mbuf);
	uint32_t ip_dst = get_ip(mbuf);
	uint16_t vlan = ctrl_ring_get_vlan(mbuf);

	plogx_dbg("\tMaster handling unknown ip "IPv4_BYTES_FMT" for port %d\n", IP4(ip_dst), port);
	if (unlikely(port >= PROX_MAX_PORTS)) {
		plogx_dbg("Port %d not found", port);
		tx_drop(mbuf);
		return;
	}
	uint32_t ip_src = task->internal_port_table[port].ip;
	struct rte_ring *ring = task->ctrl_tx_rings[get_core(mbuf) * MAX_TASKS_PER_CORE + get_task(mbuf)];

	if (ring == NULL) {
		plogx_dbg("Port %d not registered", port);
		tx_drop(mbuf);
		return;
	}

	if (record_request(tbase, ip_dst, port, ring) < 0) {
		tx_drop(mbuf);
		return;
	}
	// We send an ARP request even if one was just sent (and not yet answered) by another task
	mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);
	build_arp_request(mbuf, &task->internal_port_table[port].mac, ip_dst, ip_src, vlan);
	tx_ring(tbase, ring, SEND_ARP_REQUEST_FROM_MASTER, mbuf);
}

static inline void build_icmp_reply_message(struct task_base *tbase, struct rte_mbuf *mbuf)
{
	struct task_master *task = (struct task_master *)tbase;
	struct ip_port key;
	key.port = mbuf->port;
	prox_rte_ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
	prox_rte_ether_addr dst_mac;
	prox_rte_ether_addr_copy(&hdr->s_addr, &dst_mac);
	prox_rte_ether_addr_copy(&hdr->d_addr, &hdr->s_addr);
	prox_rte_ether_addr_copy(&dst_mac, &hdr->d_addr);
	prox_rte_ipv4_hdr *ip_hdr = (prox_rte_ipv4_hdr *)(hdr + 1);
	key.ip = ip_hdr->dst_addr;
	ip_hdr->dst_addr = ip_hdr->src_addr;
	ip_hdr->src_addr = key.ip;
	prox_rte_icmp_hdr *picmp = (prox_rte_icmp_hdr *)(ip_hdr + 1);
	picmp->icmp_type = PROX_RTE_IP_ICMP_ECHO_REPLY;

	int ret = rte_hash_lookup(task->internal_ip_hash, (const void *)&key);
	if (unlikely(ret < 0)) {
		// entry not found for this IP.
		plogx_dbg("Master ignoring ICMP received on un-registered IP "IPv4_BYTES_FMT" on port %d\n", IP4(key.ip), mbuf->port);
		tx_drop(mbuf);
	} else {
		struct rte_ring *ring = task->internal_ip_table[ret].ring;
		mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);
		tx_ring(tbase, ring, SEND_ICMP_FROM_MASTER, mbuf);
	}
}

static inline void handle_icmp(struct task_base *tbase, struct rte_mbuf *mbuf)
{
	struct task_master *task = (struct task_master *)tbase;
	uint8_t port_id = mbuf->port;
	struct port_table *port = &task->internal_port_table[port_id];
	prox_rte_ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
	if (hdr->ether_type != ETYPE_IPv4) {
		tx_drop(mbuf);
		return;
	}
	prox_rte_ipv4_hdr *ip_hdr = (prox_rte_ipv4_hdr *)(hdr + 1);
	if (ip_hdr->next_proto_id != IPPROTO_ICMP) {
		tx_drop(mbuf);
		return;
	}
	if (ip_hdr->dst_addr != port->ip) {
		tx_drop(mbuf);
		return;
	}

	prox_rte_icmp_hdr *picmp = (prox_rte_icmp_hdr *)(ip_hdr + 1);
	uint8_t type = picmp->icmp_type;
	if (type == PROX_RTE_IP_ICMP_ECHO_REQUEST) {
		port->n_echo_req++;
		if (rte_rdtsc() - port->last_echo_req_rcvd_tsc > rte_get_tsc_hz()) {
			plog_dbg("Received %u Echo Request on IP "IPv4_BYTES_FMT" (last received from IP "IPv4_BYTES_FMT")\n", port->n_echo_req, IPv4_BYTES(((uint8_t*)&ip_hdr->dst_addr)), IPv4_BYTES(((uint8_t*)&ip_hdr->src_addr)));
			port->n_echo_req = 0;
			port->last_echo_req_rcvd_tsc = rte_rdtsc();
		}
		build_icmp_reply_message(tbase, mbuf);
	} else if (type == PROX_RTE_IP_ICMP_ECHO_REPLY) {
		port->n_echo_rep++;
		if (rte_rdtsc() - port->last_echo_rep_rcvd_tsc > rte_get_tsc_hz()) {
			plog_info("Received %u Echo Reply on IP "IPv4_BYTES_FMT" (last received from IP "IPv4_BYTES_FMT")\n", port->n_echo_rep, IPv4_BYTES(((uint8_t*)&ip_hdr->dst_addr)), IPv4_BYTES(((uint8_t*)&ip_hdr->src_addr)));
			port->n_echo_rep = 0;
			port->last_echo_rep_rcvd_tsc = rte_rdtsc();
		}
	}
	tx_drop(mbuf);
	return;
}

static inline void handle_unknown_ip6(struct task_base *tbase, struct rte_mbuf *mbuf)
{
	struct task_master *task = (struct task_master *)tbase;
	struct ether_hdr_arp *hdr_arp = rte_pktmbuf_mtod(mbuf, struct ether_hdr_arp *);
	uint8_t port = get_port(mbuf);
	struct ipv6_addr *ip_dst = ctrl_ring_get_ipv6_addr(mbuf);
	int ret1, ret2, i;

	plogx_dbg("\tMaster trying to find MAC of external IP "IPv6_BYTES_FMT" for port %d\n", IPv6_BYTES(ip_dst->bytes), port);
	if (unlikely(port >= PROX_MAX_PORTS)) {
		plogx_dbg("Port %d not found", port);
		tx_drop(mbuf);
		return;
	}
	struct ipv6_addr *local_ip_src = &task->internal_port_table[port].local_ipv6_addr;
	struct ipv6_addr *global_ip_src = &task->internal_port_table[port].global_ipv6_addr;
	struct ipv6_addr *ip_src;
	if (memcmp(local_ip_src, ip_dst, 8) == 0)
		ip_src = local_ip_src;
	else if (memcmp(global_ip_src,  &null_addr, 16))
		ip_src = global_ip_src;
	else {
		plogx_dbg("Unable to find a src ip for dst ip "IPv6_BYTES_FMT"\n", IPv6_BYTES(ip_dst->bytes));
		tx_drop(mbuf);
		return;
	}
	struct rte_ring *ring = task->ctrl_tx_rings[get_core(mbuf) * MAX_TASKS_PER_CORE + get_task(mbuf)];

	if (ring == NULL) {
		plogx_dbg("Port %d not registered", port);
		tx_drop(mbuf);
		return;
	}

	ret2 = rte_hash_add_key(task->external_ip6_hash, (const void *)ip_dst);
	if (unlikely(ret2 < 0)) {
		plogx_dbg("Unable to add IP "IPv6_BYTES_FMT" in external_ip6_hash\n", IPv6_BYTES(ip_dst->bytes));
		tx_drop(mbuf);
		return;
	}

	// If multiple tasks requesting the same info, we will need to send a reply to all of them
	// However if one task sends multiple requests to the same IP (e.g. because it is not answering)
	// then we should not send multiple replies to the same task
	if (task->external_ip6_table[ret2].nb_requests >= PROX_MAX_ARP_REQUESTS) {
		// This can only happen if really many tasks requests the same IP
		plogx_dbg("Unable to add request for IP "IPv6_BYTES_FMT" in external_ip6_table\n", IPv6_BYTES(ip_dst->bytes));
		tx_drop(mbuf);
		return;
	}
	for (i = 0; i < task->external_ip6_table[ret2].nb_requests; i++) {
		if (task->external_ip6_table[ret2].rings[i] == ring)
			break;
	}
	if (i >= task->external_ip6_table[ret2].nb_requests) {
		// If this is a new request i.e. a new task requesting a new IP
		task->external_ip6_table[ret2].rings[task->external_ip6_table[ret2].nb_requests] = ring;
		task->external_ip6_table[ret2].nb_requests++;
		// Only needed for first request - but avoid test and copy the same 6 bytes
		// In most cases we will only have one request per IP.
		//memcpy(&task->external_ip6_table[ret2].mac, &task->internal_port_table[port].mac, sizeof(prox_rte_ether_addr));
	}

	// As timers are not handled by master, we might send an NS request even if one was just sent
	// (and not yet answered) by another task
	build_neighbour_sollicitation(mbuf, &task->internal_port_table[port].mac, ip_dst, ip_src);
	tx_ring(tbase, ring, SEND_NDP_FROM_MASTER, mbuf);
}

static inline void handle_rs(struct task_base *tbase, struct rte_mbuf *mbuf)
{
	struct task_master *task = (struct task_master *)tbase;
	prox_rte_ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
	prox_rte_ipv6_hdr *ipv6_hdr = (prox_rte_ipv6_hdr *)(hdr + 1);
	int i, ret;
	uint8_t port = get_port(mbuf);

	if (task->internal_port_table[port].flags & IPV6_ROUTER) {
		plogx_dbg("\tMaster handling Router Solicitation from ip "IPv6_BYTES_FMT" on port %d\n", IPv6_BYTES(ipv6_hdr->src_addr), port);
		struct rte_ring *ring = task->internal_port_table[port].ring;
		build_router_advertisement(mbuf, &prox_port_cfg[port].eth_addr, &task->internal_port_table[port].local_ipv6_addr, &task->internal_port_table[port].router_prefix);
		tx_ring(tbase, ring, SEND_NDP_FROM_MASTER, mbuf);
		return;
	}
}

static inline void handle_ra(struct task_base *tbase, struct rte_mbuf *mbuf)
{
	struct task_master *task = (struct task_master *)tbase;
	prox_rte_ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
	prox_rte_ipv6_hdr *ipv6_hdr = (prox_rte_ipv6_hdr *)(hdr + 1);
	int i, ret, send = 0;
	uint8_t port = get_port(mbuf);
	struct rte_ring *ring = task->internal_port_table[port].ring;

	plog_dbg("Master handling Router Advertisement from ip "IPv6_BYTES_FMT" on port %d - len = %d; payload_len = %d\n", IPv6_BYTES(ipv6_hdr->src_addr), port, rte_pktmbuf_pkt_len(mbuf), rte_be_to_cpu_16(ipv6_hdr->payload_len));
	if (rte_be_to_cpu_16(ipv6_hdr->payload_len) + sizeof(prox_rte_ipv6_hdr) + sizeof(prox_rte_ether_hdr) > rte_pktmbuf_pkt_len(mbuf)) {
		plog_err("Unexpected length received: pkt_len = %d, ipv6 hdr length = %ld, ipv6 payload len = %d\n", rte_pktmbuf_pkt_len(mbuf), sizeof(prox_rte_ipv6_hdr), rte_be_to_cpu_16(ipv6_hdr->payload_len));
		tx_drop(mbuf);
		return;
	}
	if (ring == NULL) {
		plog_info("TX side not initialized yet => dropping\n");
		tx_drop(mbuf);
		return;
	}
	int16_t option_len = rte_be_to_cpu_16(ipv6_hdr->payload_len) - sizeof(struct icmpv6_RA) + sizeof(struct icmpv6_option);
	struct icmpv6_RA *router_advertisement = (struct icmpv6_RA *)(ipv6_hdr + 1);
	struct icmpv6_option *option = (struct icmpv6_option *)&router_advertisement->options;
	struct icmpv6_prefix_option *prefix_option;
	while(option_len > 0) {
		uint8_t   type = option->type;
		switch(type) {
			case ICMPv6_source_link_layer_address:
				plog_dbg("\tOption %d = Source Link Layer Address\n", type);
				break;
			case ICMPv6_prefix_information:
				prefix_option = (struct icmpv6_prefix_option *)option;
				plog_dbg("\tOption %d = Prefix Information = %s\n", type, IP6_Canonical(&prefix_option->prefix));
				send = 1;
				break;
			case ICMPv6_mtu:
				plog_dbg("\tOption %d = MTU\n", type);
				break;
			default:
				plog_dbg("\tOption %d = Unknown Option\n", type);
				break;
		}
		if ((option->length == 0) || (option->length *8 > option_len)) {
			plog_err("Unexpected option length (%d) received in option %d: %d\n", option->length, option->type, option->length);
			send = 0;
			break;
		}
		option_len -=option->length * 8;
		option = (struct icmpv6_option *)(((uint8_t *)option) + option->length * 8);
	}
	if (send) {
		struct ipv6_addr global_ipv6;
		memcpy(&global_ipv6, &prefix_option->prefix, sizeof(struct ipv6_addr));
		set_EUI(&global_ipv6, &task->internal_port_table[port].mac);
		tx_ring_ip6(tbase, ring, IPV6_INFO_FROM_MASTER, mbuf, &global_ipv6);
	} else
		tx_drop(mbuf);
}

static inline void handle_ns(struct task_base *tbase, struct rte_mbuf *mbuf)
{
	struct task_master *task = (struct task_master *)tbase;
	prox_rte_ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
	prox_rte_ipv6_hdr *ipv6_hdr = (prox_rte_ipv6_hdr *)(hdr + 1);
	struct icmpv6_NS *neighbour_sollicitation = (struct icmpv6_NS *)(ipv6_hdr + 1);
	int i, ret;
	uint8_t port = get_port(mbuf);
	struct rte_ring *ring = task->internal_port_table[port].ring;

	plog_dbg("Master handling Neighbour Sollicitation for ip "IPv6_BYTES_FMT" on port %d - len = %d; payload_len = %d\n", IPv6_BYTES(neighbour_sollicitation->target_address.bytes), port, rte_pktmbuf_pkt_len(mbuf), rte_be_to_cpu_16(ipv6_hdr->payload_len));
	if (rte_be_to_cpu_16(ipv6_hdr->payload_len) + sizeof(prox_rte_ipv6_hdr) + sizeof(prox_rte_ether_hdr) > rte_pktmbuf_pkt_len(mbuf)) {
		plog_err("Unexpected length received: pkt_len = %d, ipv6 hdr length = %ld, ipv6 payload len = %d\n", rte_pktmbuf_pkt_len(mbuf), sizeof(prox_rte_ipv6_hdr), rte_be_to_cpu_16(ipv6_hdr->payload_len));
		tx_drop(mbuf);
		return;
	}
	int16_t option_len = rte_be_to_cpu_16(ipv6_hdr->payload_len) - sizeof(struct icmpv6_NS) + sizeof(struct icmpv6_option);
	struct icmpv6_option *option = (struct icmpv6_option *)&neighbour_sollicitation->options;
	while(option_len > 0) {
		uint8_t   type = option->type;
		switch(type) {
			case ICMPv6_source_link_layer_address:
				plog_dbg("Option %d = Source Link Layer Address\n", type);
				break;
			default:
				plog_dbg("Option %d = Unknown Option\n", type);
				break;
		}
		if ((option->length == 0) || (option->length *8 > option_len)) {
			plog_err("Unexpected option length (%d) received in option %d: %d\n", option->length, option->type, option->length);
			tx_drop(mbuf);
			return;
		}
		option_len -=option->length * 8;
		option = (struct icmpv6_option *)(((uint8_t *)option) + option->length * 8);
	}
	struct ip6_port key;
	memcpy(&key.ip6, &neighbour_sollicitation->target_address, sizeof(struct ipv6_addr));
	key.port = port;

	if (memcmp(&neighbour_sollicitation->target_address, &task->internal_port_table[port].local_ipv6_addr, 8) == 0) {
		// Local IP
		if (task->internal_port_table[port].flags & HANDLE_RANDOM_LOCAL_IP_FLAG) {
			prox_rte_ether_addr mac;
			plogx_dbg("\tMaster handling NS request for ip "IPv6_BYTES_FMT" on port %d which supports random ip\n", IPv6_BYTES(key.ip6.bytes), key.port);
			struct rte_ring *ring = task->internal_port_table[port].ring;
			create_mac_from_EUI(&key.ip6, &mac);
			build_neighbour_advertisement(tbase, mbuf, &mac, &task->internal_port_table[port].local_ipv6_addr, PROX_SOLLICITED);
			tx_ring(tbase, ring, SEND_NDP_FROM_MASTER, mbuf);
			return;
		}
	} else {
		if (task->internal_port_table[port].flags & HANDLE_RANDOM_GLOBAL_IP_FLAG) {
			prox_rte_ether_addr mac;
			plogx_dbg("\tMaster handling NS request for ip "IPv6_BYTES_FMT" on port %d which supports random ip\n", IPv6_BYTES(key.ip6.bytes), key.port);
			struct rte_ring *ring = task->internal_port_table[port].ring;
			create_mac_from_EUI(&key.ip6, &mac);
			build_neighbour_advertisement(tbase, mbuf, &mac, &task->internal_port_table[port].global_ipv6_addr, PROX_SOLLICITED);
			tx_ring(tbase, ring, SEND_NDP_FROM_MASTER, mbuf);
			return;
		}
	}

	ret = rte_hash_lookup(task->internal_ip6_hash, (const void *)&key);
	if (unlikely(ret < 0)) {
		// entry not found for this IP.
		plogx_dbg("Master ignoring Neighbour Sollicitation received on un-registered IP "IPv6_BYTES_FMT" on port %d\n", IPv6_BYTES(key.ip6.bytes), port);
		tx_drop(mbuf);
	} else {
		struct rte_ring *ring = task->internal_ip6_table[ret].ring;
		build_neighbour_advertisement(tbase, mbuf, &task->internal_ip6_table[ret].mac, &key.ip6, PROX_SOLLICITED);
		tx_ring(tbase, ring, SEND_NDP_FROM_MASTER, mbuf);
	}
}

static inline void handle_na(struct task_base *tbase, struct rte_mbuf *mbuf)
{
	struct task_master *task = (struct task_master *)tbase;
	prox_rte_ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
	prox_rte_ipv6_hdr *ipv6_hdr = (prox_rte_ipv6_hdr *)(hdr + 1);
	struct icmpv6_NA *neighbour_advertisement = (struct icmpv6_NA *)(ipv6_hdr + 1);
	int i, ret;
	uint8_t port = get_port(mbuf);
	struct rte_ring *ring = task->internal_port_table[port].ring;

	plog_dbg("Master handling Neighbour Advertisement for ip "IPv6_BYTES_FMT" on port %d - len = %d; payload_len = %d\n", IPv6_BYTES(neighbour_advertisement->destination_address.bytes), port, rte_pktmbuf_pkt_len(mbuf), rte_be_to_cpu_16(ipv6_hdr->payload_len));
	if (rte_be_to_cpu_16(ipv6_hdr->payload_len) + sizeof(prox_rte_ipv6_hdr) + sizeof(prox_rte_ether_hdr) > rte_pktmbuf_pkt_len(mbuf)) {
		plog_err("Unexpected length received: pkt_len = %d, ipv6 hdr length = %ld, ipv6 payload len = %d\n", rte_pktmbuf_pkt_len(mbuf), sizeof(prox_rte_ipv6_hdr), rte_be_to_cpu_16(ipv6_hdr->payload_len));
		tx_drop(mbuf);
		return;
	}
	int16_t option_len = rte_be_to_cpu_16(ipv6_hdr->payload_len) - sizeof(struct icmpv6_NA) + sizeof(struct icmpv6_option);
	struct icmpv6_option *option = (struct icmpv6_option *)&neighbour_advertisement->options;
	uint8_t *target_address = NULL;
	while(option_len > 0) {
		uint8_t   type = option->type;
		switch(type) {
			case ICMPv6_source_link_layer_address:
				plog_dbg("Option %d = Source Link Layer Address\n", type);
				break;
			case ICMPv6_target_link_layer_address:
				if (option->length != 1) {
					plog_err("Unexpected option length = %u for Target Link Layer Address\n", option->length);
					break;
				}
				target_address = option->data;
				plog_dbg("Option %d = Target Link Layer Address = "MAC_BYTES_FMT"\n", type, MAC_BYTES(target_address));
				break;
			default:
				plog_dbg("Option %d = Unknown Option\n", type);
				break;
		}
		if ((option->length == 0) || (option->length *8 > option_len)) {
			plog_err("Unexpected option length (%d) received in option %d: %d\n", option->length, option->type, option->length);
			tx_drop(mbuf);
			return;
		}
		option_len -=option->length * 8;
		option = (struct icmpv6_option *)(((uint8_t *)option) + option->length * 8);
	}

	if (target_address == NULL) {
		tx_drop(mbuf);
	}
	struct ether_hdr_arp *hdr_arp = rte_pktmbuf_mtod(mbuf, struct ether_hdr_arp *);
	struct ipv6_addr *key = &neighbour_advertisement->destination_address;

	ret = rte_hash_lookup(task->external_ip6_hash, (const void *)key);
	if (unlikely(ret < 0)) {
		// entry not found for this IP: we did not ask a request, delete the reply
		tx_drop(mbuf);
	} else {
		// entry found for this IP
		uint16_t nb_requests = task->external_ip6_table[ret].nb_requests;
		//memcpy(&hdr->d_addr.addr_bytes, &task->external_ip6_table[ret].mac, sizeof(prox_rte_ether_addr));
		// If we receive a request from multiple task for the same IP, then we update all tasks
		if (task->external_ip6_table[ret].nb_requests) {
			rte_mbuf_refcnt_set(mbuf, nb_requests);
			for (int i = 0; i < nb_requests; i++) {
				struct rte_ring *ring = task->external_ip6_table[ret].rings[i];
				tx_ring_ip6_data(tbase, ring, MAC_INFO_FROM_MASTER_FOR_IPV6, mbuf, &neighbour_advertisement->destination_address, *(uint64_t *)target_address);
			}
			task->external_ip6_table[ret].nb_requests = 0;
		} else {
			tx_drop(mbuf);
		}
	}
}

static inline void handle_message(struct task_base *tbase, struct rte_mbuf *mbuf, int ring_id)
{
	struct task_master *task = (struct task_master *)tbase;
	prox_rte_ether_hdr *ether_hdr;
	struct icmpv6 *icmpv6;
	int command = get_command(mbuf);
	uint8_t port = get_port(mbuf);
	uint32_t ip;
	uint16_t vlan, ether_type;
	uint8_t vdev_port = prox_port_cfg[port].dpdk_mapping;
	plogx_dbg("\tMaster received %s (%x) from mbuf %p\n", actions_string[command], command, mbuf);
	struct my_arp_t *arp;

	switch(command) {
	case BGP_TO_MASTER:
		if (vdev_port != NO_VDEV_PORT) {
			// If a virtual (net_tap) device is attached, send the (BGP) packet to this device
			// The kernel will receive and handle it.
			plogx_dbg("\tMaster forwarding BGP packet to TAP\n");
			int n = rte_eth_tx_burst(prox_port_cfg[port].dpdk_mapping, 0, &mbuf, 1);
			return;
		}
		tx_drop(mbuf);
		break;
	case ICMP_TO_MASTER:
		if (vdev_port != NO_VDEV_PORT) {
			// If a virtual (net_tap) device is attached, send the (PING) packet to this device
			// The kernel will receive and handle it.
			plogx_dbg("\tMaster forwarding packet to TAP\n");
			int n = rte_eth_tx_burst(prox_port_cfg[port].dpdk_mapping, 0, &mbuf, 1);
			return;
		}
		handle_icmp(tbase, mbuf);
		break;
	case ARP_PKT_FROM_NET_TO_MASTER:
		if (vdev_port != NO_VDEV_PORT) {
			// If a virtual (net_tap) device is attached, send the (ARP) packet to this device
			// The kernel will receive and handle it.
			plogx_dbg("\tMaster forwarding packet to TAP\n");
			int n = rte_eth_tx_burst(prox_port_cfg[port].dpdk_mapping, 0, &mbuf, 1);
			return;
		}
		ether_hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
		ether_type = ether_hdr->ether_type;
		if (ether_type == ETYPE_VLAN) {
			prox_rte_vlan_hdr *vlan_hdr = (prox_rte_vlan_hdr *)(ether_hdr + 1);
			arp = (struct my_arp_t *)(vlan_hdr + 1);
			ether_type = vlan_hdr->eth_proto;
		}  else {
			arp = (struct my_arp_t *)(ether_hdr + 1);
		}

		if (ether_type != ETYPE_ARP) {
			plog_err("\tUnexpected message received: ARP_PKT_FROM_NET_TO_MASTER with ether_type %x\n", ether_type);
			tx_drop(mbuf);
			return;
		}
		if (arp_is_gratuitous(arp)) {
			plog_info("\tReceived gratuitous packet \n");
			tx_drop(mbuf);
			return;
		} else if (memcmp(arp, &arp_reply, 8) == 0) {
			// uint32_t ip = arp->data.spa;
			handle_arp_reply(tbase, mbuf, arp);
		} else if (memcmp(arp, &arp_request, 8) == 0) {
			handle_arp_request(tbase, mbuf, arp);
		} else {
			plog_info("\tReceived unexpected ARP operation %d\n", arp->oper);
			tx_drop(mbuf);
			return;
		}
		break;
	case IP4_REQ_MAC_TO_MASTER:
		if (vdev_port != NO_VDEV_PORT) {
			// We send a packet to the kernel with the proper destnation IP address and our src IP address
			// This means that if a generator sends packets from many sources all ARP will still
			// be sent from the same IP src. This might be a limitation.
			// This prevent to have to open as many sockets as there are sources MAC addresses
			// We also always use the same UDP ports - as the packet will finally not leave the system anyhow

			struct ether_hdr_arp *hdr_arp = rte_pktmbuf_mtod(mbuf, struct ether_hdr_arp *);
			uint32_t ip = get_ip(mbuf);
			struct rte_ring *ring = task->ctrl_tx_rings[get_core(mbuf) * MAX_TASKS_PER_CORE + get_task(mbuf)];

			// First check whether MAC address is not already in kernel MAC table.
			// If present in our hash with a non-null MAC, then present in kernel. A null MAC
			// might just mean that we sent a request.
			// If MAC present in kernel, do not send a packet towards the kernel to try to generate
			// an ARP request, as the kernel would not generate it.
			int ret = rte_hash_lookup(task->external_ip_hash, (const void *)&ip);
			if ((ret >= 0) && (!prox_rte_is_zero_ether_addr(&task->external_ip_table[ret].mac))) {
				memcpy(&hdr_arp->arp.data.sha, &task->external_ip_table[ret].mac, sizeof(prox_rte_ether_addr));
				plogx_dbg("\tMaster ready to send MAC_INFO_FROM_MASTER ip "IPv4_BYTES_FMT" with mac "MAC_BYTES_FMT"\n",
					IP4(ip), MAC_BYTES(hdr_arp->arp.data.sha.addr_bytes));
				tx_ring_ip(tbase, ring, MAC_INFO_FROM_MASTER, mbuf, ip);
				return;
			}

			struct sockaddr_in dst;
			dst.sin_family = AF_INET;
			dst.sin_addr.s_addr = ip;
			dst.sin_port = rte_cpu_to_be_16(PROX_PSEUDO_PKT_PORT);
			// TODO VLAN: find the right fd based on the VLAN
			int n = sendto(prox_port_cfg[vdev_port].fd, (char*)(&ip), 0, MSG_DONTROUTE,  (struct sockaddr *)&dst, sizeof(struct sockaddr_in));
			if (n < 0) {
				plogx_info("\tFailed to send to TAP IP "IPv4_BYTES_FMT" using fd %d, error = %d (%s)\n", IPv4_BYTES(((uint8_t*)&ip)), prox_port_cfg[vdev_port].fd, errno, strerror(errno));
			} else
				plogx_dbg("\tSent %d bytes to TAP IP "IPv4_BYTES_FMT" using fd %d\n", n, IPv4_BYTES(((uint8_t*)&ip)), prox_port_cfg[vdev_port].fd);

			record_request(tbase, ip, port, ring);
			tx_drop(mbuf);
			break;
		}
		handle_unknown_ip(tbase, mbuf);
		break;
	case IP6_REQ_MAC_TO_MASTER:
		handle_unknown_ip6(tbase, mbuf);
		break;
	case NDP_PKT_FROM_NET_TO_MASTER:
		ether_hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
		prox_rte_ipv6_hdr *ipv6_hdr = (prox_rte_ipv6_hdr *)(ether_hdr + 1);
		if (unlikely((ether_hdr->ether_type != ETYPE_IPv6) || (ipv6_hdr->proto != ICMPv6))) {
			// Should not happen
			if (ether_hdr->ether_type != ETYPE_IPv6)
				plog_err("\tUnexpected message received: NDP_PKT_FROM_NET_TO_MASTER with ether_type %x\n", ether_hdr->ether_type);
			else
				plog_err("\tUnexpected message received: NDP_PKT_FROM_NET_TO_MASTER with ether_type %x and proto %x\n", ether_hdr->ether_type, ipv6_hdr->proto);
			tx_drop(mbuf);
			return;
		}
		icmpv6 = (struct icmpv6 *)(ipv6_hdr + 1);
		switch (icmpv6->type) {
		case ICMPv6_DU:
			plog_err("IPV6 ICMPV6 Destination Unreachable\n");
			tx_drop(mbuf);
			break;
		case ICMPv6_PTB:
			plog_err("IPV6 ICMPV6 packet too big\n");
			tx_drop(mbuf);
			break;
		case ICMPv6_TE:
			plog_err("IPV6 ICMPV6 Time Exceeded\n");
			tx_drop(mbuf);
			break;
		case ICMPv6_PaPr:
			plog_err("IPV6 ICMPV6 Parameter Problem\n");
			tx_drop(mbuf);
			break;
		case ICMPv6_RS:
			handle_rs(tbase, mbuf);
			break;
		case ICMPv6_RA:
			handle_ra(tbase, mbuf);
			break;
		case ICMPv6_NS:
			handle_ns(tbase, mbuf);
			break;
		case ICMPv6_NA:
			handle_na(tbase, mbuf);
			break;
		case ICMPv6_RE:
			plog_err("IPV6 ICMPV6 Redirect not handled\n");
			tx_drop(mbuf);
			break;
		default:
			plog_err("Unexpected type %d in IPV6 ICMPV6\n", icmpv6->type);
			tx_drop(mbuf);
			break;
		}
		break;
	default:
		plogx_dbg("\tMaster received unexpected message\n");
		tx_drop(mbuf);
		break;
	}
}

void init_ctrl_plane(struct task_base *tbase)
{
	struct task_master *task = (struct task_master *)tbase;
	int socket_id = rte_lcore_to_socket_id(prox_cfg.master);
	uint32_t n_entries = MAX_ARP_ENTRIES * 4;
	static char hash_name[30];

	sprintf(hash_name, "A%03d_hash_arp_table", prox_cfg.master);
	struct rte_hash_parameters hash_params = {
		.name = hash_name,
		.entries = n_entries,
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
	};
	if (prox_cfg.flags & DSF_L3_ENABLED) {
		hash_params.key_len = sizeof(uint32_t);
		task->external_ip_hash = rte_hash_create(&hash_params);
		PROX_PANIC(task->external_ip_hash == NULL, "Failed to set up external ip hash\n");
		plog_info("\texternal ip hash table allocated, with %d entries of size %d\n", hash_params.entries, hash_params.key_len);
		hash_name[0]++;

		task->external_ip_table = (struct external_ip_table *)prox_zmalloc(n_entries * sizeof(struct external_ip_table), socket_id);
		PROX_PANIC(task->external_ip_table == NULL, "Failed to allocate memory for %u entries in external ip table\n", n_entries);
		plog_info("\texternal ip table, with %d entries of size %ld\n", n_entries, sizeof(struct external_ip_table));

		hash_params.key_len = sizeof(struct ip_port);
		task->internal_ip_hash = rte_hash_create(&hash_params);
		PROX_PANIC(task->internal_ip_hash == NULL, "Failed to set up internal ip hash\n");
		plog_info("\tinternal ip hash table allocated, with %d entries of size %d\n", hash_params.entries, hash_params.key_len);
		hash_name[0]++;

		task->internal_ip_table = (struct ip_table *)prox_zmalloc(n_entries * sizeof(struct ip_table), socket_id);
		PROX_PANIC(task->internal_ip_table == NULL, "Failed to allocate memory for %u entries in internal ip table\n", n_entries);
		plog_info("\tinternal ip table, with %d entries of size %ld\n", n_entries, sizeof(struct ip_table));
	}

	if (prox_cfg.flags & DSF_NDP_ENABLED) {
		hash_params.key_len = sizeof(struct ipv6_addr);
		task->external_ip6_hash = rte_hash_create(&hash_params);
		PROX_PANIC(task->external_ip6_hash == NULL, "Failed to set up external ip6 hash\n");
		plog_info("\texternal ip6 hash table allocated, with %d entries of size %d\n", hash_params.entries, hash_params.key_len);
		hash_name[0]++;

		task->external_ip6_table = (struct external_ip_table *)prox_zmalloc(n_entries * sizeof(struct external_ip_table), socket_id);
		PROX_PANIC(task->external_ip6_table == NULL, "Failed to allocate memory for %u entries in external ip6 table\n", n_entries);
		plog_info("\texternal ip6_table, with %d entries of size %ld\n", n_entries, sizeof(struct external_ip_table));

		hash_params.key_len = sizeof(struct ip6_port);
		task->internal_ip6_hash = rte_hash_create(&hash_params);
		PROX_PANIC(task->internal_ip6_hash == NULL, "Failed to set up internal ip6 hash\n");
		plog_info("\tinternal ip6 hash table allocated, with %d entries of size %d\n", hash_params.entries, hash_params.key_len);
		hash_name[0]++;

		task->internal_ip6_table = (struct ip_table *)prox_zmalloc(n_entries * sizeof(struct ip_table), socket_id);
		PROX_PANIC(task->internal_ip6_table == NULL, "Failed to allocate memory for %u entries in internal ip6 table\n", n_entries);
		plog_info("\tinternal ip6 table, with %d entries of size %ld\n", n_entries, sizeof(struct ip_table));
	}

	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	PROX_PANIC(fd < 0, "Failed to open netlink socket: %d\n", errno);
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

	struct sockaddr_nl sockaddr;
	memset(&sockaddr, 0, sizeof(struct sockaddr_nl));
	sockaddr.nl_family = AF_NETLINK;
	sockaddr.nl_groups = RTMGRP_NEIGH | RTMGRP_NOTIFY;
	int rc = bind(fd, (struct sockaddr *)&sockaddr, sizeof(struct sockaddr_nl));
	PROX_PANIC(rc < 0, "Failed to bind to RTMGRP_NEIGH netlink group\n");
	task->arp_fds.fd = fd;
	task->arp_fds.events = POLL_IN;
	plog_info("\tRTMGRP_NEIGH netlink group bound; fd = %d\n", fd);

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	PROX_PANIC(fd < 0, "Failed to open netlink socket: %d\n", errno);
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	struct sockaddr_nl sockaddr2;
	memset(&sockaddr2, 0, sizeof(struct sockaddr_nl));
	sockaddr2.nl_family = AF_NETLINK;
	sockaddr2.nl_groups = RTMGRP_IPV6_ROUTE | RTMGRP_IPV4_ROUTE | RTMGRP_NOTIFY;
	rc = bind(fd, (struct sockaddr *)&sockaddr2, sizeof(struct sockaddr_nl));
	PROX_PANIC(rc < 0, "Failed to bind to RTMGRP_NEIGH netlink group\n");
	task->route_fds.fd = fd;
	task->route_fds.events = POLL_IN;
	plog_info("\tRTMGRP_IPV4_ROUTE netlink group bound; fd = %d\n", fd);

	static char name[] = "master_arp_nd_pool";
	const int NB_ARP_MBUF = 1024;
	const int ARP_MBUF_SIZE = 2048;
	const int NB_CACHE_ARP_MBUF = 256;
	struct rte_mempool *ret = rte_mempool_create(name, NB_ARP_MBUF, ARP_MBUF_SIZE, NB_CACHE_ARP_MBUF,
		sizeof(struct rte_pktmbuf_pool_private), rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, 0,
		rte_socket_id(), 0);
	PROX_PANIC(ret == NULL, "Failed to allocate ARP memory pool on socket %u with %u elements\n",
		rte_socket_id(), NB_ARP_MBUF);
	plog_info("\tMempool %p (%s) size = %u * %u cache %u, socket %d\n", ret, name, NB_ARP_MBUF,
		ARP_MBUF_SIZE, NB_CACHE_ARP_MBUF, rte_socket_id());
	tbase->l3.arp_nd_pool = ret;
}

static void handle_route_event(struct task_base *tbase)
{
	struct task_master *task = (struct task_master *)tbase;
	struct rte_mbuf *mbufs[MAX_RING_BURST];
	int fd = task->route_fds.fd, interface_index, mask = -1;
	char interface_name[IF_NAMESIZE] = {0};
	int len = recv(fd, netlink_buf, sizeof(netlink_buf), 0);
	uint32_t ip = 0, gw_ip = 0;
	if (len < 0) {
		plog_err("Failed to recv from netlink: %d\n", errno);
		return;
	}
	struct nlmsghdr * nl_hdr = (struct nlmsghdr *)netlink_buf;
	if (nl_hdr->nlmsg_flags & NLM_F_MULTI) {
		plog_err("Unexpected multipart netlink message\n");
		return;
	}
	if ((nl_hdr->nlmsg_type != RTM_NEWROUTE) && (nl_hdr->nlmsg_type != RTM_DELROUTE))
		return;

	struct rtmsg *rtmsg = (struct rtmsg *)NLMSG_DATA(nl_hdr);
	int rtm_family = rtmsg->rtm_family;
	if ((rtm_family == AF_INET) && (rtmsg->rtm_table != RT_TABLE_MAIN) &&(rtmsg->rtm_table != RT_TABLE_LOCAL))
		return;
	int dst_len = rtmsg->rtm_dst_len;

	struct rtattr *rta = (struct rtattr *)RTM_RTA(rtmsg);
	int rtl = RTM_PAYLOAD(nl_hdr);
	for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
		switch (rta->rta_type) {
		case RTA_DST:
			ip = *((uint32_t *)RTA_DATA(rta));
			break;
		case RTA_OIF:
			interface_index = *((int *)RTA_DATA(rta));
			if (if_indextoname(interface_index, interface_name) == NULL) {
				plog_info("Unknown Interface Index %d\n", interface_index);
			}
			break;
		case RTA_METRICS:
			mask = *((int *)RTA_DATA(rta));
			break;
		case RTA_GATEWAY:
			gw_ip = *((uint32_t *)RTA_DATA(rta));
			break;
		default:
			break;
		}
	}
	int dpdk_vdev_port = -1;
	for (int i = 0; i< prox_rte_eth_dev_count_avail(); i++) {
		if (strcmp(prox_port_cfg[i].name, interface_name) == 0)
			dpdk_vdev_port = i;
	}
	if (dpdk_vdev_port != -1) {
		plogx_info("Received netlink message on tap interface %s for IP "IPv4_BYTES_FMT"/%d, Gateway  "IPv4_BYTES_FMT"\n", interface_name, IP4(ip), dst_len, IP4(gw_ip));
		int ret1 = rte_mempool_get(tbase->l3.arp_nd_pool, (void **)mbufs);
		if (unlikely(ret1 != 0)) {
			plog_err("Unable to allocate a mbuf for master to core communication\n");
			return;
		}
		int dpdk_port = prox_port_cfg[dpdk_vdev_port].dpdk_mapping;
		tx_ring_route(tbase, task->internal_port_table[dpdk_port].ring, (nl_hdr->nlmsg_type == RTM_NEWROUTE), mbufs[0], ip, gw_ip, dst_len);
	} else
		plog_info("Received netlink message on unknown interface %s for IP "IPv4_BYTES_FMT"/%d, Gateway  "IPv4_BYTES_FMT"\n", interface_name[0] ? interface_name:"", IP4(ip), dst_len, IP4(gw_ip));
	return;
}

static void handle_arp_event(struct task_base *tbase)
{
	struct task_master *task = (struct task_master *)tbase;
	struct rte_mbuf *mbufs[MAX_RING_BURST];
	struct nlmsghdr * nl_hdr;
	int fd = task->arp_fds.fd;
	int len, ret;
	uint32_t ip = 0;
	prox_rte_ether_addr mac;
	memset(&mac, 0, sizeof(mac));
	len = recv(fd, netlink_buf, sizeof(netlink_buf), 0);
	if (len < 0) {
		plog_err("Failed to recv from netlink: %d\n", errno);
		return;
	}
	nl_hdr = (struct nlmsghdr *)netlink_buf;
	if (nl_hdr->nlmsg_flags & NLM_F_MULTI) {
		plog_err("Unexpected multipart netlink message\n");
		return;
	}
	if ((nl_hdr->nlmsg_type != RTM_NEWNEIGH) && (nl_hdr->nlmsg_type != RTM_DELNEIGH))
		return;

	struct ndmsg *ndmsg = (struct ndmsg *)NLMSG_DATA(nl_hdr);
	int ndm_family = ndmsg->ndm_family;
	struct rtattr *rta = (struct rtattr *)RTM_RTA(ndmsg);
	int rtl = RTM_PAYLOAD(nl_hdr);
	for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
		switch (rta->rta_type) {
		case NDA_DST:
			ip = *((uint32_t *)RTA_DATA(rta));
			break;
		case NDA_LLADDR:
			mac = *((prox_rte_ether_addr *)(uint64_t *)RTA_DATA(rta));
			break;
		default:
			break;
		}
	}
	plogx_info("Received netlink ip "IPv4_BYTES_FMT" with mac "MAC_BYTES_FMT"\n", IP4(ip), MAC_BYTES(mac.addr_bytes));
	ret = rte_hash_lookup(task->external_ip_hash, (const void *)&ip);
	if (unlikely(ret < 0)) {
		// entry not found for this IP: we did not ask a request.
		// This can happen if the kernel updated the ARP table when receiving an ARP_REQUEST
		// We must record this, as the ARP entry is now in the kernel table
		if (prox_rte_is_zero_ether_addr(&mac)) {
			// Timeout or MAC deleted from kernel MAC table
			int ret = rte_hash_del_key(task->external_ip_hash, (const void *)&ip);
			plogx_dbg("ip "IPv4_BYTES_FMT" removed from external_ip_hash\n", IP4(ip));
			return;
		}
		int ret = rte_hash_add_key(task->external_ip_hash, (const void *)&ip);
		if (unlikely(ret < 0)) {
			plogx_dbg("IP "IPv4_BYTES_FMT" not found in external_ip_hash and unable to add it\n", IP4(ip));
			return;
		}
		memcpy(&task->external_ip_table[ret].mac, &mac, sizeof(prox_rte_ether_addr));
		plogx_dbg("ip "IPv4_BYTES_FMT" added in external_ip_hash with mac "MAC_BYTES_FMT"\n", IP4(ip), MAC_BYTES(mac.addr_bytes));
		return;
	}

	// entry found for this IP
	uint16_t nb_requests = task->external_ip_table[ret].nb_requests;
	if (nb_requests == 0) {
		return;
	}

	memcpy(&task->external_ip_table[ret].mac, &mac, sizeof(prox_rte_ether_addr));

	// If we receive a request from multiple task for the same IP, then we update all tasks
	int ret1 = rte_mempool_get(tbase->l3.arp_nd_pool, (void **)mbufs);
	if (unlikely(ret1 != 0)) {
		plog_err("Unable to allocate a mbuf for master to core communication\n");
		return;
	}
	rte_mbuf_refcnt_set(mbufs[0], nb_requests);
	for (int i = 0; i < nb_requests; i++) {
		struct rte_ring *ring = task->external_ip_table[ret].rings[i];
		struct ether_hdr_arp *hdr = rte_pktmbuf_mtod(mbufs[0], struct ether_hdr_arp *);
		memcpy(&hdr->arp.data.sha, &mac, sizeof(prox_rte_ether_addr));
		tx_ring_ip(tbase, ring, MAC_INFO_FROM_MASTER, mbufs[0], ip);
		plog_dbg("MAC_INFO_FROM_MASTER ip "IPv4_BYTES_FMT" with mac "MAC_BYTES_FMT"\n", IP4(ip), MAC_BYTES(mac.addr_bytes));
	}
	task->external_ip_table[ret].nb_requests = 0;
	return;
}

static int handle_ctrl_plane_f(struct task_base *tbase, __attribute__((unused)) struct rte_mbuf **mbuf, uint16_t n_pkts)
{
	int ring_id = 0, j, ret = 0, n = 0;
	struct rte_mbuf *mbufs[MAX_RING_BURST];
	struct task_master *task = (struct task_master *)tbase;

	/* 	Handle_master works differently than other handle functions
		It is not handled by a DPDK dataplane core
		It is no thread_generic based, hence do not receive packets the same way
	*/

	ret = ring_deq(task->ctrl_rx_ring, mbufs);
	for (j = 0; j < ret; j++) {
		handle_message(tbase, mbufs[j], ring_id);
	}
	for (int vdev_id = 0; vdev_id < task->max_vdev_id; vdev_id++) {
		struct vdev *vdev = &task->all_vdev[vdev_id];
		n = rte_eth_rx_burst(vdev->port_id, 0, mbufs, MAX_PKT_BURST);
		for (j = 0; j < n; j++) {
			tx_ring(tbase, vdev->ring, PKT_FROM_TAP, mbufs[j]);
		}
		ret +=n;
	}
	if ((task->max_vdev_id) && (poll(&task->arp_fds, 1, prox_cfg.poll_timeout) == POLL_IN)) {
		handle_arp_event(tbase);
	}
	if (poll(&task->route_fds, 1, prox_cfg.poll_timeout) == POLL_IN) {
		handle_route_event(tbase);
	}
	return ret;
}

static void init_task_master(struct task_base *tbase, struct task_args *targs)
{
	if (prox_cfg.flags & DSF_CTRL_PLANE_ENABLED) {
		struct task_master *task = (struct task_master *)tbase;

		task->ctrl_rx_ring = targs->lconf->ctrl_rings_p[0];
		task->ctrl_tx_rings = ctrl_rings;
		init_ctrl_plane(tbase);
		handle_ctrl_plane = handle_ctrl_plane_f;
	}
}

static struct task_init task_init_master = {
        .mode_str = "master",
        .init = init_task_master,
        .handle = NULL,
        .flag_features = TASK_FEATURE_NEVER_DISCARDS,
	.size = sizeof(struct task_master)
};

__attribute__((constructor)) static void reg_task_gen(void)
{
        reg_task(&task_init_master);
}
