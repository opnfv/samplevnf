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
#include <poll.h>
#include <net/if.h>

#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ether.h>

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

#define PROX_MAX_ARP_REQUESTS	32	// Maximum number of tasks requesting the same MAC address
#define NETLINK_BUF_SIZE	16384

static char netlink_buf[NETLINK_BUF_SIZE];

const char *actions_string[] = {
	"UPDATE_FROM_CTRL",		// Controlplane sending a MAC update to dataplane
	"SEND_ARP_REQUEST_FROM_CTRL",	// Controlplane requesting dataplane to send ARP request
	"SEND_ARP_REPLY_FROM_CTRL",	// Controlplane requesting dataplane to send ARP reply
	"SEND_ICMP_FROM_CTRL",		// Controlplane requesting dataplane to send ICMP message
	"SEND_BGP_FROM_CTRL",		// Controlplane requesting dataplane to send BGP message
	"ARP_TO_CTRL",			// ARP sent by datplane to Controlpane for handling
	"ICMP_TO_CTRL",			// ICMP sent by datplane to Controlpane for handling
	"BGP_TO_CTRL",			// BGP sent by datplane to Controlpane for handling
	"REQ_MAC_TO_CTRL",		// Dataplane requesting MAC resolution to Controlplane
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

struct ip_table {
	prox_rte_ether_addr 	mac;
	struct rte_ring 	*ring;
};

struct external_ip_table {
	prox_rte_ether_addr 	mac;
	struct rte_ring 	*rings[PROX_MAX_ARP_REQUESTS];
	uint16_t 		nb_requests;
};

struct port_table {
	prox_rte_ether_addr 	mac;
	struct rte_ring 	*ring;
	uint32_t 		ip;
	uint8_t			port;
	uint8_t 		flags;
	uint64_t last_echo_req_rcvd_tsc;
	uint64_t last_echo_rep_rcvd_tsc;
	uint32_t n_echo_req;
	uint32_t n_echo_rep;
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
	struct vdev all_vdev[PROX_MAX_PORTS];
	int max_vdev_id;
	struct pollfd arp_fds;
	struct pollfd route_fds;
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
		src.sin_port = rte_cpu_to_be_16(5000);

		int fd = socket(AF_INET,  SOCK_DGRAM, 0);
		PROX_PANIC(fd < 0, "Failed to open socket(AF_INET,  SOCK_DGRAM, 0)\n");
		prox_port_cfg[vdev_port].fd = fd;
		rc = bind(fd,(struct sockaddr *)&src, sizeof(struct sockaddr_in));
		PROX_PANIC(rc, "Failed to bind("IPv4_BYTES_FMT":%d): errno = %d\n", IPv4_BYTES(((uint8_t*)&src.sin_addr.s_addr)), src.sin_port, errno);
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

	/* TODO - stoe multiple rings if multiple cores able to handle IP
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

static inline void handle_arp_reply(struct task_base *tbase, struct rte_mbuf *mbuf)
{
	struct task_master *task = (struct task_master *)tbase;
	struct ether_hdr_arp *hdr_arp = rte_pktmbuf_mtod(mbuf, struct ether_hdr_arp *);
	int i, ret;
	uint32_t key = hdr_arp->arp.data.spa;
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
		prox_rte_ether_addr mac;
		plogx_dbg("\tMaster handling ARP request for ip "IPv4_BYTES_FMT" on port %d which supports random ip\n", IP4(key.ip), key.port);
		struct rte_ring *ring = task->internal_port_table[port].ring;
		create_mac(hdr_arp, &mac);
		mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);
		build_arp_reply(hdr_arp, &mac);
		tx_ring(tbase, ring, ARP_REPLY_FROM_CTRL, mbuf);
		return;
	}

	plogx_dbg("\tMaster handling ARP request for ip "IPv4_BYTES_FMT"\n", IP4(key.ip));

	ret = rte_hash_lookup(task->internal_ip_hash, (const void *)&key);
	if (unlikely(ret < 0)) {
		// entry not found for this IP.
		plogx_dbg("Master ignoring ARP REQUEST received on un-registered IP "IPv4_BYTES_FMT" on port %d\n", IP4(hdr_arp->arp.data.tpa), port);
		tx_drop(mbuf);
	} else {
		struct rte_ring *ring = task->internal_ip_table[ret].ring;
		mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);
		build_arp_reply(hdr_arp, &task->internal_ip_table[ret].mac);
		tx_ring(tbase, ring, ARP_REPLY_FROM_CTRL, mbuf);
	}
}

static inline int record_request(struct task_base *tbase, uint32_t ip_dst, uint8_t port, struct rte_ring *ring)
{
	struct task_master *task = (struct task_master *)tbase;
	int ret = rte_hash_add_key(task->external_ip_hash, (const void *)&ip_dst);
	int i;

	if (unlikely(ret < 0)) {
		// entry not found for this IP: delete the reply
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
	build_arp_request(mbuf, &task->internal_port_table[port].mac, ip_dst, ip_src);
	tx_ring(tbase, ring, ARP_REQ_FROM_CTRL, mbuf);
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
		tx_ring(tbase, ring, ICMP_FROM_CTRL, mbuf);
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

static inline void handle_message(struct task_base *tbase, struct rte_mbuf *mbuf, int ring_id)
{
	struct task_master *task = (struct task_master *)tbase;
	struct ether_hdr_arp *hdr_arp = rte_pktmbuf_mtod(mbuf, struct ether_hdr_arp *);
	int command = get_command(mbuf);
	uint8_t port = get_port(mbuf);
	uint32_t ip;
	uint8_t vdev_port = prox_port_cfg[port].dpdk_mapping;
	plogx_dbg("\tMaster received %s (%x) from mbuf %p\n", actions_string[command], command, mbuf);

	switch(command) {
	case BGP_TO_CTRL:
		if (vdev_port != NO_VDEV_PORT) {
			// If a virtual (net_tap) device is attached, send the (BGP) packet to this device
			// The kernel will receive and handle it.
			plogx_dbg("\tMaster forwarding BGP packet to TAP\n");
			int n = rte_eth_tx_burst(prox_port_cfg[port].dpdk_mapping, 0, &mbuf, 1);
			return;
		}
		tx_drop(mbuf);
		break;
	case ICMP_TO_CTRL:
		if (vdev_port != NO_VDEV_PORT) {
			// If a virtual (net_tap) device is attached, send the (PING) packet to this device
			// The kernel will receive and handle it.
			plogx_dbg("\tMaster forwarding packet to TAP\n");
			int n = rte_eth_tx_burst(prox_port_cfg[port].dpdk_mapping, 0, &mbuf, 1);
			return;
		}
		handle_icmp(tbase, mbuf);
		break;
	case ARP_TO_CTRL:
		if (vdev_port != NO_VDEV_PORT) {
			// If a virtual (net_tap) device is attached, send the (ARP) packet to this device
			// The kernel will receive and handle it.
			plogx_dbg("\tMaster forwarding packet to TAP\n");
			int n = rte_eth_tx_burst(prox_port_cfg[port].dpdk_mapping, 0, &mbuf, 1);
			return;
		}
		if (hdr_arp->ether_hdr.ether_type != ETYPE_ARP) {
			plog_err("\tUnexpected message received: ARP_TO_CTRL with ether_type %x\n", hdr_arp->ether_hdr.ether_type);
			tx_drop(mbuf);
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
				plogx_dbg("\tMaster ready to send UPDATE_FROM_CTRL ip "IPv4_BYTES_FMT" with mac "MAC_BYTES_FMT"\n",
					IP4(ip), MAC_BYTES(hdr_arp->arp.data.sha.addr_bytes));
				tx_ring_ip(tbase, ring, UPDATE_FROM_CTRL, mbuf, ip);
				return;
			}

			struct sockaddr_in dst;
			dst.sin_family = AF_INET;
			dst.sin_addr.s_addr = ip;
			dst.sin_port = rte_cpu_to_be_16(5000);
			int n = sendto(prox_port_cfg[vdev_port].fd, (char*)(&ip), 0, 0,  (struct sockaddr *)&dst, sizeof(struct sockaddr_in));
			plogx_dbg("\tSent %d bytes to TAP IP "IPv4_BYTES_FMT" using fd %d\n", n, IPv4_BYTES(((uint8_t*)&ip)), prox_port_cfg[vdev_port].fd);

			record_request(tbase, ip, port, ring);
			tx_drop(mbuf);
			break;
		}
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
	int socket_id = rte_lcore_to_socket_id(prox_cfg.master);
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
	task->external_ip_table = (struct external_ip_table *)prox_zmalloc(n_entries * sizeof(struct external_ip_table), socket_id);
	PROX_PANIC(task->external_ip_table == NULL, "Failed to allocate memory for %u entries in external ip table\n", n_entries);
	plog_info("\texternal ip table, with %d entries of size %ld\n", n_entries, sizeof(struct external_ip_table));

	hash_name[0]++;
	hash_params.key_len = sizeof(struct ip_port);
	task->internal_ip_hash = rte_hash_create(&hash_params);
	PROX_PANIC(task->internal_ip_hash == NULL, "Failed to set up internal ip hash\n");
	plog_info("\tinternal ip hash table allocated, with %d entries of size %d\n", hash_params.entries, hash_params.key_len);
	task->internal_ip_table = (struct ip_table *)prox_zmalloc(n_entries * sizeof(struct ip_table), socket_id);
	PROX_PANIC(task->internal_ip_table == NULL, "Failed to allocate memory for %u entries in internal ip table\n", n_entries);
	plog_info("\tinternal ip table, with %d entries of size %ld\n", n_entries, sizeof(struct ip_table));

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

	static char name[] = "master_arp_pool";
	const int NB_ARP_MBUF = 1024;
	const int ARP_MBUF_SIZE = 2048;
	const int NB_CACHE_ARP_MBUF = 256;
	struct rte_mempool *ret = rte_mempool_create(name, NB_ARP_MBUF, ARP_MBUF_SIZE, NB_CACHE_ARP_MBUF,
		sizeof(struct rte_pktmbuf_pool_private), rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, 0,
		rte_socket_id(), 0);
	PROX_PANIC(ret == NULL, "Failed to allocate ARP memory pool on socket %u with %u elements\n",
		rte_socket_id(), NB_ARP_MBUF);
	plog_info("\t\tMempool %p (%s) size = %u * %u cache %u, socket %d\n", ret, name, NB_ARP_MBUF,
		ARP_MBUF_SIZE, NB_CACHE_ARP_MBUF, rte_socket_id());
	tbase->l3.arp_pool = ret;
}

static int handle_route_event(struct task_base *tbase)
{
	struct task_master *task = (struct task_master *)tbase;
	int fd = task->route_fds.fd, interface_index, mask = -1;
	char interface_name[IF_NAMESIZE] = {0};
	int len = recv(fd, netlink_buf, sizeof(netlink_buf), 0);
	uint32_t ip = 0, gw_ip = 0;
	if (len < 0) {
		plog_err("Failed to recv from netlink: %d\n", errno);
		return errno;
	}
	struct nlmsghdr * nl_hdr = (struct nlmsghdr *)netlink_buf;
	if (nl_hdr->nlmsg_flags & NLM_F_MULTI) {
		plog_err("Unexpected multipart netlink message\n");
		return -1;
	}
	if ((nl_hdr->nlmsg_type != RTM_NEWROUTE) && (nl_hdr->nlmsg_type != RTM_DELROUTE))
		return 0;

	struct rtmsg *rtmsg = (struct rtmsg *)NLMSG_DATA(nl_hdr);
	int rtm_family = rtmsg->rtm_family;
	if ((rtm_family == AF_INET) && (rtmsg->rtm_table != RT_TABLE_MAIN) &&(rtmsg->rtm_table != RT_TABLE_LOCAL))
		return 0;
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
	int dpdk_port = -1;
	for (int i = 0; i< rte_eth_dev_count(); i++) {
		if (strcmp(prox_port_cfg[i].name, interface_name) == 0)
			dpdk_port = i;
	}
	if (dpdk_port != -1)
		plog_info("Received netlink message on tap interface %s for IP "IPv4_BYTES_FMT"/%d, Gateway  "IPv4_BYTES_FMT"\n", interface_name, IP4(ip), dst_len, IP4(gw_ip));
	else
		plog_info("Received netlink message on unknown interface %s for IP "IPv4_BYTES_FMT"/%d, Gateway  "IPv4_BYTES_FMT"\n", interface_name[0] ? interface_name:"", IP4(ip), dst_len, IP4(gw_ip));
	return 0;
}

static int handle_arp_event(struct task_base *tbase)
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
		return errno;
	}
	nl_hdr = (struct nlmsghdr *)netlink_buf;
	if (nl_hdr->nlmsg_flags & NLM_F_MULTI) {
		plog_err("Unexpected multipart netlink message\n");
		return -1;
	}
	if ((nl_hdr->nlmsg_type != RTM_NEWNEIGH) && (nl_hdr->nlmsg_type != RTM_DELNEIGH))
		return 0;

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
	ret = rte_hash_lookup(task->external_ip_hash, (const void *)&ip);
	if (unlikely(ret < 0)) {
		// entry not found for this IP: we did not ask a request.
		// This can happen if the kernel updated the ARP table when receiving an ARP_REQUEST
		// We must record this, as the ARP entry is now in the kernel table
		if (prox_rte_is_zero_ether_addr(&mac)) {
			// Timeout or MAC deleted from kernel MAC table
			int ret = rte_hash_del_key(task->external_ip_hash, (const void *)&ip);
			plogx_dbg("ip "IPv4_BYTES_FMT" removed from external_ip_hash\n", IP4(ip));
			return 0;
		}
		int ret = rte_hash_add_key(task->external_ip_hash, (const void *)&ip);
		if (unlikely(ret < 0)) {
			// entry not found for this IP: Ignore the reply. This can happen for instance for
			// an IP used by management plane.
			plogx_dbg("IP "IPv4_BYTES_FMT" not found in external_ip_hash and unable to add it\n", IP4(ip));
			return -1;
		}
		memcpy(&task->external_ip_table[ret].mac, &mac, sizeof(prox_rte_ether_addr));
		plogx_dbg("ip "IPv4_BYTES_FMT" added in external_ip_hash with mac "MAC_BYTES_FMT"\n", IP4(ip), MAC_BYTES(mac.addr_bytes));
		return 0;
	}

	// entry found for this IP
	uint16_t nb_requests = task->external_ip_table[ret].nb_requests;
	if (nb_requests == 0) {
		return 0;
	}

	memcpy(&task->external_ip_table[ret].mac, &mac, sizeof(prox_rte_ether_addr));

	// If we receive a request from multiple task for the same IP, then we update all tasks
	ret = rte_mempool_get(tbase->l3.arp_pool, (void **)mbufs);
	if (unlikely(ret != 0)) {
		plog_err("Unable to allocate a mbuf for master to core communication\n");
		return -1;
	}
	rte_mbuf_refcnt_set(mbufs[0], nb_requests);
	for (int i = 0; i < nb_requests; i++) {
		struct rte_ring *ring = task->external_ip_table[ret].rings[i];
		struct ether_hdr_arp *hdr = rte_pktmbuf_mtod(mbufs[0], struct ether_hdr_arp *);
		memcpy(&hdr->arp.data.sha, &mac, sizeof(prox_rte_ether_addr));
		tx_ring_ip(tbase, ring, UPDATE_FROM_CTRL, mbufs[0], ip);
		plog_dbg("UPDATE_FROM_CTRL ip "IPv4_BYTES_FMT" with mac "MAC_BYTES_FMT"\n", IP4(ip), MAC_BYTES(mac.addr_bytes));
	}
	task->external_ip_table[ret].nb_requests = 0;
	return 0;
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
	if (poll(&task->arp_fds, 1, prox_cfg.poll_timeout) == POLL_IN) {
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
