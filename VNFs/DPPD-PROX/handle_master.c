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
#include "prox_cfg.h"
#include "prox_malloc.h"
#include "quit.h"
#include "task_init.h"
#include "prox_port_cfg.h"
#include "main.h"
#include "lconf.h"
#include "input.h"
#include "tx_pkt.h"

#define PROX_MAX_ARP_REQUESTS	32	// Maximum number of tasks requesting the same MAC address

const char *actions_string[] = {"UPDATE_FROM_CTRL", "SEND_ARP_REQUEST_FROM_CTRL", "SEND_ARP_REPLY_FROM_CTRL", "HANDLE_ARP_TO_CTRL", "REQ_MAC_TO_CTRL"};

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

struct ip_table {
	struct ether_addr 	mac;
	struct rte_ring 	*ring;
};

struct external_ip_table {
	struct ether_addr 	mac;
	struct rte_ring 	*rings[PROX_MAX_ARP_REQUESTS];
	uint16_t 		nb_requests;
};

struct port_table {
	struct ether_addr 	mac;
	struct rte_ring 	*ring;
	uint32_t 		ip;
	uint8_t			port;
	uint8_t 		flags;
};

struct task_master {
        struct task_base base;
	struct rte_ring *ctrl_rx_ring;
	struct rte_ring **ctrl_tx_rings;
	struct ip_table *internal_ip_table;
	struct external_ip_table *external_ip_table;
	struct rte_hash  *external_ip_hash;
	struct rte_hash  *internal_ip_hash;
	struct port_table internal_port_table[PROX_MAX_PORTS];
};

struct ip_port {
	uint32_t ip;
	uint8_t port;
} __attribute__((packed));

static inline uint8_t get_command(struct rte_mbuf *mbuf)
{
	return mbuf->udata64 & 0xFF;
}
static inline uint8_t get_task(struct rte_mbuf *mbuf)
{
	return (mbuf->udata64 >> 8) & 0xFF;
}
static inline uint8_t get_core(struct rte_mbuf *mbuf)
{
	return (mbuf->udata64 >> 16) & 0xFF;
}
static inline uint8_t get_port(struct rte_mbuf *mbuf)
{
	return mbuf->port;
}
static inline uint32_t get_ip(struct rte_mbuf *mbuf)
{
	return (mbuf->udata64 >> 32) & 0xFFFFFFFF;
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

	/* TODO - stoe multiple rings if multiple cores able to handle IP
	   Remove them when such cores are stopped and de-register IP
	*/
	task->internal_port_table[port_id].ring = task->ctrl_tx_rings[core_id * MAX_TASKS_PER_CORE + task_id];
	memcpy(&task->internal_port_table[port_id].mac, &prox_port_cfg[port_id].eth_addr, 6);
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
	memcpy(&task->internal_ip_table[ret].mac, &prox_port_cfg[port_id].eth_addr, 6);
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
		memcpy(&hdr_arp->ether_hdr.d_addr.addr_bytes, &task->external_ip_table[ret].mac, 6);
		// If we receive a request from multiple task for the same IP, then we update all tasks
		if (task->external_ip_table[ret].nb_requests) {
			rte_mbuf_refcnt_set(mbuf, nb_requests);
			for (int i = 0; i < nb_requests; i++) {
				struct rte_ring *ring = task->external_ip_table[ret].rings[i];
				tx_ring_ip(tbase, ring, UPDATE_FROM_CTRL, mbuf, key);
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
		struct ether_addr mac;
		plogx_dbg("\tMaster handling ARP request for ip %d.%d.%d.%d on port %d which supports random ip\n", IP4(key.ip), key.port);
		struct rte_ring *ring = task->internal_port_table[port].ring;
		create_mac(hdr_arp, &mac);
		mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);
		build_arp_reply(hdr_arp, &mac);
		tx_ring(tbase, ring, ARP_REPLY_FROM_CTRL, mbuf);
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
		tx_ring(tbase, ring, ARP_REPLY_FROM_CTRL, mbuf);
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
		// entry not found for this IP: delete the reply
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
		memcpy(&task->external_ip_table[ret2].mac, &task->internal_port_table[port].mac, 6);
	}

	// We send an ARP request even if one was just sent (and not yet answered) by another task
	mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);
	build_arp_request(mbuf, &task->internal_port_table[port].mac, ip_dst, ip_src);
	tx_ring(tbase, ring, ARP_REQ_FROM_CTRL, mbuf);
}

static inline void handle_message(struct task_base *tbase, struct rte_mbuf *mbuf, int ring_id)
{
	struct ether_hdr_arp *hdr_arp = rte_pktmbuf_mtod(mbuf, struct ether_hdr_arp *);
	int command = get_command(mbuf);
	uint32_t ip;
	plogx_dbg("\tMaster received %s (%x) from mbuf %p\n", actions_string[command], command, mbuf);

	switch(command) {
	case ARP_TO_CTRL:
		if (hdr_arp->ether_hdr.ether_type != ETYPE_ARP) {
			tx_drop(mbuf);
			plog_err("\tUnexpected message received: ARP_TO_CTRL with ether_type %x\n", hdr_arp->ether_hdr.ether_type);
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
	case REQ_MAC_TO_CTRL:
		handle_unknown_ip(tbase, mbuf);
		break;
	default:
		plogx_dbg("\tMaster received unexpected message\n");
		tx_drop(mbuf);
		break;
	}
}

void init_ctrl_plane(struct task_base *tbase)
{
	prox_cfg.flags |= DSF_CTRL_PLANE_ENABLED;
	struct task_master *task = (struct task_master *)tbase;
	int socket = rte_lcore_to_socket_id(prox_cfg.master);
	uint32_t n_entries = MAX_ARP_ENTRIES * 4;
	static char hash_name[30];
	sprintf(hash_name, "A%03d_hash_arp_table", prox_cfg.master);
	struct rte_hash_parameters hash_params = {
		.name = hash_name,
		.entries = n_entries,
		.key_len = sizeof(uint32_t),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
	};
	task->external_ip_hash = rte_hash_create(&hash_params);
	PROX_PANIC(task->external_ip_hash == NULL, "Failed to set up external ip hash\n");
	plog_info("\texternal ip hash table allocated, with %d entries of size %d\n", hash_params.entries, hash_params.key_len);
	task->external_ip_table = (struct external_ip_table *)prox_zmalloc(n_entries * sizeof(struct external_ip_table), socket);
	PROX_PANIC(task->external_ip_table == NULL, "Failed to allocate memory for %u entries in external ip table\n", n_entries);
	plog_info("\texternal ip table, with %d entries of size %ld\n", n_entries, sizeof(struct external_ip_table));

	hash_name[0]++;
	hash_params.key_len = sizeof(struct ip_port);
	task->internal_ip_hash = rte_hash_create(&hash_params);
	PROX_PANIC(task->internal_ip_hash == NULL, "Failed to set up internal ip hash\n");
	plog_info("\tinternal ip hash table allocated, with %d entries of size %d\n", hash_params.entries, hash_params.key_len);
	task->internal_ip_table = (struct ip_table *)prox_zmalloc(n_entries * sizeof(struct ip_table), socket);
	PROX_PANIC(task->internal_ip_table == NULL, "Failed to allocate memory for %u entries in internal ip table\n", n_entries);
	plog_info("\tinternal ip table, with %d entries of size %ld\n", n_entries, sizeof(struct ip_table));
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
