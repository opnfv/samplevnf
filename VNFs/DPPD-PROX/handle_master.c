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

#include <rte_hash.h>
#include <rte_hash_crc.h>
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

const char *actions_string[] = {
	"ARP_PKT_FROM_NET_TO_MASTER",
	"NDP_PKT_FROM_NET_TO_MASTER",
	"IP4_REQ_MAC_TO_MASTER",
	"IP6_REQ_MAC_TO_MASTER",
	"TX_ARP_REQ_FROM_MASTER",
	"TX_ARP_REPLY_FROM_MASTER",
	"TX_NDP_FROM_MASTER",
	"MAC_INFO_FROM_MASTER",
	"MAC_INFO_FROM_MASTER_FOR_IPV6",
	"IPV6_INFO_FROM_MASTER",
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

static inline uint8_t get_command(struct rte_mbuf *mbuf)
{
	struct prox_headroom *prox_headroom = (struct prox_headroom *)(rte_pktmbuf_mtod(mbuf, uint8_t*) - sizeof(struct prox_headroom));
	return prox_headroom->command & 0xFF;
}
static inline uint8_t get_task(struct rte_mbuf *mbuf)
{
	struct prox_headroom *prox_headroom = (struct prox_headroom *)(rte_pktmbuf_mtod(mbuf, uint8_t*) - sizeof(struct prox_headroom));
	return (prox_headroom->command >> 8) & 0xFF;
}
static inline uint8_t get_core(struct rte_mbuf *mbuf)
{
	struct prox_headroom *prox_headroom = (struct prox_headroom *)(rte_pktmbuf_mtod(mbuf, uint8_t*) - sizeof(struct prox_headroom));
	return (prox_headroom->command >> 16) & 0xFF;
}
static inline uint32_t get_ip(struct rte_mbuf *mbuf)
{
	struct prox_headroom *prox_headroom = (struct prox_headroom *)(rte_pktmbuf_mtod(mbuf, uint8_t*) - sizeof(struct prox_headroom));
	return (prox_headroom->command >> 32) & 0xFFFFFFFF;
}

void register_router_to_ctrl_plane(struct task_base *tbase, uint8_t port_id, uint8_t core_id, uint8_t task_id, struct ipv6_addr *ipv6_addr,  struct ipv6_addr *router_prefix)
{
	struct task_master *task = (struct task_master *)tbase;
	task->internal_port_table[port_id].flags |= IPV6_ROUTER;
	memcpy(&task->internal_port_table[port_id].router_prefix, router_prefix, sizeof(struct ipv6_addr));
	register_node_to_ctrl_plane(tbase, ipv6_addr, port_id, core_id, task_id);
}

void register_node_to_ctrl_plane(struct task_base *tbase, struct ipv6_addr *ipv6_addr, uint8_t port_id, uint8_t core_id, uint8_t task_id)
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
	memcpy(&task->internal_port_table[port_id].ipv6_addr, ipv6_addr, sizeof(struct ipv6_addr));
	if (memcmp(ipv6_addr, &prox_cfg.random_ip, sizeof(struct ipv6_addr)) == 0) {
		task->internal_port_table[port_id].flags |= HANDLE_RANDOM_IP_FLAG;
		return;
	}
	struct ip6_port key;
	memcpy(&key.ip6, ipv6_addr, sizeof(struct ipv6_addr));
	key.port = port_id;
	int ret = rte_hash_add_key(task->internal_ip6_hash, (const void *)&key);
	if (unlikely(ret < 0)) {
		plog_err("Unable to register ip "IPv6_BYTES_FMT"\n", IPv6_BYTES(ipv6_addr->bytes));
		return;
	}
	memcpy(&task->internal_ip6_table[ret].mac, &prox_port_cfg[port_id].eth_addr, sizeof(prox_rte_ether_addr));
	task->internal_ip6_table[ret].ring = task->ctrl_tx_rings[core_id * MAX_TASKS_PER_CORE + task_id];
}

void register_ip_to_ctrl_plane(struct task_base *tbase, uint32_t ip, uint8_t port_id, uint8_t core_id, uint8_t task_id)
{
	struct task_master *task = (struct task_master *)tbase;
	struct ip_port key;
	plogx_dbg("\tregistering IP %d.%d.%d.%d with port %d core %d and task %d\n", IP4(ip), port_id, core_id, task_id);

	if (port_id >= PROX_MAX_PORTS) {
		plog_err("Unable to register ip %d.%d.%d.%d, port %d\n", IP4(ip), port_id);
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
		plog_err("Unable to register ip %d.%d.%d.%d\n", IP4(ip));
		return;
	}
	memcpy(&task->internal_ip_table[ret].mac, &prox_port_cfg[port_id].eth_addr, sizeof(prox_rte_ether_addr));
	task->internal_ip_table[ret].ring = task->ctrl_tx_rings[core_id * MAX_TASKS_PER_CORE + task_id];
}

static inline void handle_arp_reply(struct task_base *tbase, struct rte_mbuf *mbuf)
{
	struct task_master *task = (struct task_master *)tbase;
	struct ether_hdr_arp *hdr_arp = rte_pktmbuf_mtod(mbuf, struct ether_hdr_arp *);
	int i, ret;
	uint32_t key = hdr_arp->arp.data.spa;
	plogx_dbg("\tMaster handling ARP reply for ip %d.%d.%d.%d\n", IP4(key));

	ret = rte_hash_lookup(task->external_ip_hash, (const void *)&key);
	if (unlikely(ret < 0)) {
		// entry not found for this IP: we did not ask a request, delete the reply
		tx_drop(mbuf);
	} else {
		// entry found for this IP
		uint16_t nb_requests = task->external_ip_table[ret].nb_requests;
		memcpy(&hdr_arp->ether_hdr.d_addr.addr_bytes, &task->external_ip_table[ret].mac, sizeof(prox_rte_ether_addr));
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

static inline void handle_arp_request(struct task_base *tbase, struct rte_mbuf *mbuf)
{
	struct task_master *task = (struct task_master *)tbase;
	struct ether_hdr_arp *hdr_arp = rte_pktmbuf_mtod(mbuf, struct ether_hdr_arp *);
	int i, ret;
	uint8_t port = get_port(mbuf);

	struct ip_port key;
	key.ip = hdr_arp->arp.data.tpa;
	key.port = port;
	if (task->internal_port_table[port].flags & HANDLE_RANDOM_IP_FLAG) {
		prox_rte_ether_addr mac;
		plogx_dbg("\tMaster handling ARP request for ip %d.%d.%d.%d on port %d which supports random ip\n", IP4(key.ip), key.port);
		struct rte_ring *ring = task->internal_port_table[port].ring;
		create_mac(hdr_arp, &mac);
		mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);
		build_arp_reply(hdr_arp, &mac);
		tx_ring(tbase, ring, TX_ARP_REPLY_FROM_MASTER, mbuf);
		return;
	}

	plogx_dbg("\tMaster handling ARP request for ip %d.%d.%d.%d\n", IP4(key.ip));

	ret = rte_hash_lookup(task->internal_ip_hash, (const void *)&key);
	if (unlikely(ret < 0)) {
		// entry not found for this IP.
		plogx_dbg("Master ignoring ARP REQUEST received on un-registered IP %d.%d.%d.%d on port %d\n", IP4(hdr_arp->arp.data.tpa), port);
		tx_drop(mbuf);
	} else {
		struct rte_ring *ring = task->internal_ip_table[ret].ring;
		mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);
		build_arp_reply(hdr_arp, &task->internal_ip_table[ret].mac);
		tx_ring(tbase, ring, TX_ARP_REPLY_FROM_MASTER, mbuf);
	}
}

static inline void handle_unknown_ip(struct task_base *tbase, struct rte_mbuf *mbuf)
{
	struct task_master *task = (struct task_master *)tbase;
	struct ether_hdr_arp *hdr_arp = rte_pktmbuf_mtod(mbuf, struct ether_hdr_arp *);
	uint8_t port = get_port(mbuf);
	uint32_t ip_dst = get_ip(mbuf);
	int ret1, ret2, i;

	plogx_dbg("\tMaster handling unknown ip %d.%d.%d.%d for port %d\n", IP4(ip_dst), port);
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

	ret2 = rte_hash_add_key(task->external_ip_hash, (const void *)&ip_dst);
	if (unlikely(ret2 < 0)) {
		plogx_dbg("Unable to add IP %d.%d.%d.%d in external_ip_hash\n", IP4(ip_dst));
		tx_drop(mbuf);
		return;
	}

	// If multiple tasks requesting the same info, we will need to send a reply to all of them
	// However if one task sends multiple requests to the same IP (e.g. because it is not answering)
	// then we should not send multiple replies to the same task
	if (task->external_ip_table[ret2].nb_requests >= PROX_MAX_ARP_REQUESTS) {
		// This can only happen if really many tasks requests the same IP
		plogx_dbg("Unable to add request for IP %d.%d.%d.%d in external_ip_table\n", IP4(ip_dst));
		tx_drop(mbuf);
		return;
	}
	for (i = 0; i < task->external_ip_table[ret2].nb_requests; i++) {
		if (task->external_ip_table[ret2].rings[i] == ring)
			break;
	}
	if (i >= task->external_ip_table[ret2].nb_requests) {
		// If this is a new request i.e. a new task requesting a new IP
		task->external_ip_table[ret2].rings[task->external_ip_table[ret2].nb_requests] = ring;
		task->external_ip_table[ret2].nb_requests++;
		// Only needed for first request - but avoid test and copy the same 6 bytes
		// In most cases we will only have one request per IP.
		memcpy(&task->external_ip_table[ret2].mac, &task->internal_port_table[port].mac, sizeof(prox_rte_ether_addr));
	}

	// We send an ARP request even if one was just sent (and not yet answered) by another task
	mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);
	build_arp_request(mbuf, &task->internal_port_table[port].mac, ip_dst, ip_src);
	tx_ring(tbase, ring, TX_ARP_REQ_FROM_MASTER, mbuf);
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
	struct ipv6_addr *ip_src = &task->internal_port_table[port].ipv6_addr;
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
		memcpy(&task->external_ip6_table[ret2].mac, &task->internal_port_table[port].mac, sizeof(prox_rte_ether_addr));
	}

	// As timers are not handled by master, we might send an NS request even if one was just sent 
	// (and not yet answered) by another task
	mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);
	build_neighbour_sollicitation(mbuf, &task->internal_port_table[port].mac, ip_dst, ip_src);
	tx_ring(tbase, ring, TX_NDP_FROM_MASTER, mbuf);
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
		mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);	// Software calculates the checksum
		build_router_advertisement(mbuf, &prox_port_cfg[port].eth_addr, &task->internal_port_table[port].ipv6_addr, &task->internal_port_table[port].router_prefix);
		tx_ring(tbase, ring, TX_NDP_FROM_MASTER, mbuf);
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
	if (task->internal_port_table[port].flags & HANDLE_RANDOM_IP_FLAG) {
		prox_rte_ether_addr mac;
		plogx_dbg("\tMaster handling NS request for ip "IPv6_BYTES_FMT" on port %d which supports random ip\n", IPv6_BYTES(key.ip6.bytes), key.port);
		struct rte_ring *ring = task->internal_port_table[port].ring;
		create_mac_from_EUI(&key.ip6, &mac);
		mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);
		build_neighbour_advertisement(tbase, mbuf, &mac);
		tx_ring(tbase, ring, TX_NDP_FROM_MASTER, mbuf);
		return;
	}

	ret = rte_hash_lookup(task->internal_ip6_hash, (const void *)&key);
	if (unlikely(ret < 0)) {
		// entry not found for this IP.
		plogx_dbg("Master ignoring Neighbour Sollicitation received on un-registered IP "IPv6_BYTES_FMT" on port %d\n", IPv6_BYTES(key.ip6.bytes), port);
		tx_drop(mbuf);
	} else {
		struct rte_ring *ring = task->internal_ip6_table[ret].ring;
		mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);
		build_neighbour_advertisement(tbase, mbuf, &task->internal_ip6_table[ret].mac);
		tx_ring(tbase, ring, TX_NDP_FROM_MASTER, mbuf);
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
	while(option_len > 0) {
		uint8_t   type = option->type;
		switch(type) {
			case ICMPv6_source_link_layer_address:
				plog_dbg("Option %d = Source Link Layer Address\n", type);
				break;
			case ICMPv6_target_link_layer_address:
				plog_dbg("Option %d = Target Link Layer Address\n", type);
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

	struct ether_hdr_arp *hdr_arp = rte_pktmbuf_mtod(mbuf, struct ether_hdr_arp *);
	struct ipv6_addr *key = &neighbour_advertisement->destination_address;

	ret = rte_hash_lookup(task->external_ip6_hash, (const void *)key);
	if (unlikely(ret < 0)) {
		// entry not found for this IP: we did not ask a request, delete the reply
		tx_drop(mbuf);
	} else {
		// entry found for this IP
		uint16_t nb_requests = task->external_ip6_table[ret].nb_requests;
		memcpy(&hdr->d_addr.addr_bytes, &task->external_ip6_table[ret].mac, sizeof(prox_rte_ether_addr));
		// If we receive a request from multiple task for the same IP, then we update all tasks
		if (task->external_ip6_table[ret].nb_requests) {
			rte_mbuf_refcnt_set(mbuf, nb_requests);
			for (int i = 0; i < nb_requests; i++) {
				struct rte_ring *ring = task->external_ip6_table[ret].rings[i];
				tx_ring_ip6(tbase, ring, MAC_INFO_FROM_MASTER_FOR_IPV6, mbuf, &neighbour_advertisement->destination_address);
			}
			task->external_ip6_table[ret].nb_requests = 0;
		} else {
			tx_drop(mbuf);
		}
	}
}

static inline void handle_message(struct task_base *tbase, struct rte_mbuf *mbuf, int ring_id)
{
	struct ether_hdr_arp *hdr_arp;
	prox_rte_ether_hdr *hdr;
	struct icmpv6 *icmpv6;
	int command = get_command(mbuf);
	uint32_t ip;
	plogx_dbg("\tMaster received %s (%x) from mbuf %p\n", actions_string[command], command, mbuf);

	switch(command) {
	case ARP_PKT_FROM_NET_TO_MASTER:
		hdr_arp = rte_pktmbuf_mtod(mbuf, struct ether_hdr_arp *);
		if (hdr_arp->ether_hdr.ether_type != ETYPE_ARP) {
			tx_drop(mbuf);
			plog_err("\tUnexpected message received: ARP_PKT_FROM_NET_TO_MASTER with ether_type %x\n", hdr_arp->ether_hdr.ether_type);
			return;
		} else if (arp_is_gratuitous(hdr_arp)) {
			plog_info("\tReceived gratuitous packet \n");
			tx_drop(mbuf);
			return;
		} else if (memcmp(&hdr_arp->arp, &arp_reply, 8) == 0) {
			uint32_t ip = hdr_arp->arp.data.spa;
			handle_arp_reply(tbase, mbuf);
		} else if (memcmp(&hdr_arp->arp, &arp_request, 8) == 0) {
			handle_arp_request(tbase, mbuf);
		} else {
			plog_info("\tReceived unexpected ARP operation %d\n", hdr_arp->arp.oper);
			tx_drop(mbuf);
			return;
		}
		break;
	case IP4_REQ_MAC_TO_MASTER:
		handle_unknown_ip(tbase, mbuf);
		break;
	case IP6_REQ_MAC_TO_MASTER:
		handle_unknown_ip6(tbase, mbuf);
		break;
	case NDP_PKT_FROM_NET_TO_MASTER:
		hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
		prox_rte_ipv6_hdr *ipv6_hdr = (prox_rte_ipv6_hdr *)(hdr + 1);
		if (unlikely((hdr->ether_type != ETYPE_IPv6) || (ipv6_hdr->proto != ICMPv6))) {
			// Should not happen
			if (hdr->ether_type != ETYPE_IPv6)
				plog_err("\tUnexpected message received: NDP_PKT_FROM_NET_TO_MASTER with ether_type %x\n", hdr->ether_type);
			else
				plog_err("\tUnexpected message received: NDP_PKT_FROM_NET_TO_MASTER with ether_type %x and proto %x\n", hdr->ether_type, ipv6_hdr->proto);
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
	int socket = rte_lcore_to_socket_id(prox_cfg.master);
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

		task->external_ip_table = (struct external_ip_table *)prox_zmalloc(n_entries * sizeof(struct external_ip_table), socket);
		PROX_PANIC(task->external_ip_table == NULL, "Failed to allocate memory for %u entries in external ip table\n", n_entries);
		plog_info("\texternal ip table, with %d entries of size %ld\n", n_entries, sizeof(struct external_ip_table));

		hash_params.key_len = sizeof(struct ip_port);
		task->internal_ip_hash = rte_hash_create(&hash_params);
		PROX_PANIC(task->internal_ip_hash == NULL, "Failed to set up internal ip hash\n");
		plog_info("\tinternal ip hash table allocated, with %d entries of size %d\n", hash_params.entries, hash_params.key_len);
		hash_name[0]++;

		task->internal_ip_table = (struct ip_table *)prox_zmalloc(n_entries * sizeof(struct ip_table), socket);
		PROX_PANIC(task->internal_ip_table == NULL, "Failed to allocate memory for %u entries in internal ip table\n", n_entries);
		plog_info("\tinternal ip table, with %d entries of size %ld\n", n_entries, sizeof(struct ip_table));
	}

	if (prox_cfg.flags & DSF_NDP_ENABLED) {
		hash_params.key_len = sizeof(struct ipv6_addr);
		task->external_ip6_hash = rte_hash_create(&hash_params);
		PROX_PANIC(task->external_ip6_hash == NULL, "Failed to set up external ip6 hash\n");
		plog_info("\texternal ip6 hash table allocated, with %d entries of size %d\n", hash_params.entries, hash_params.key_len);
		hash_name[0]++;

		task->external_ip6_table = (struct external_ip_table *)prox_zmalloc(n_entries * sizeof(struct external_ip_table), socket);
		PROX_PANIC(task->external_ip6_table == NULL, "Failed to allocate memory for %u entries in external ip6 table\n", n_entries);
		plog_info("\texternal ip6_table, with %d entries of size %ld\n", n_entries, sizeof(struct external_ip_table));

		hash_params.key_len = sizeof(struct ip6_port);
		task->internal_ip6_hash = rte_hash_create(&hash_params);
		PROX_PANIC(task->internal_ip6_hash == NULL, "Failed to set up internal ip6 hash\n");
		plog_info("\tinternal ip6 hash table allocated, with %d entries of size %d\n", hash_params.entries, hash_params.key_len);
		hash_name[0]++;

		task->internal_ip6_table = (struct ip_table *)prox_zmalloc(n_entries * sizeof(struct ip_table), socket);
		PROX_PANIC(task->internal_ip6_table == NULL, "Failed to allocate memory for %u entries in internal ip6 table\n", n_entries);
		plog_info("\tinternal ip6 table, with %d entries of size %ld\n", n_entries, sizeof(struct ip_table));
	}
}

static int handle_ctrl_plane_f(struct task_base *tbase, __attribute__((unused)) struct rte_mbuf **mbuf, uint16_t n_pkts)
{
	int ring_id = 0, j, ret = 0;
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
