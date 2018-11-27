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

#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_version.h>
#include <rte_byteorder.h>
#include <rte_lpm.h>

#include "prox_lua_types.h"
#include "prox_lua.h"
#include "prox_malloc.h"
#include "prox_cksum.h"
#include "prefetch.h"
#include "etypes.h"
#include "log.h"
#include "quit.h"
#include "task_init.h"
#include "task_base.h"
#include "lconf.h"
#include "log.h"
#include "prox_port_cfg.h"
#include "hash_entry_types.h"
#include "prox_shared.h"
#include "handle_cgnat.h"

#define ALL_32_BITS 0xffffffff
#define BIT_16_TO_31 0xffff0000
#define BIT_8_TO_15 0x0000ff00
#define BIT_0_TO_15 0x0000ffff

struct private_key {
		uint32_t ip_addr;
		uint16_t l4_port;
} __attribute__((packed));

struct private_flow_entry {
	uint64_t flow_time;
	uint32_t ip_addr;
	uint32_t private_ip_idx;
	uint16_t l4_port;
};

struct public_key {
	uint32_t ip_addr;
	uint16_t l4_port;
} __attribute__((packed));

struct public_entry {
	uint32_t ip_addr;
	uint16_t l4_port;
	uint32_t private_ip_idx;
	uint8_t dpdk_port;
};

struct public_ip_config_info {
	uint32_t public_ip;
	uint32_t max_port_count;
	uint32_t port_free_count;
	uint16_t *port_list;
};

struct private_ip_info {
	uint64_t mac_aging_time;
	uint32_t public_ip;
	uint32_t public_ip_idx;
	struct rte_ether *private_mac;
	uint8_t static_entry;
};

struct task_nat {
	struct task_base base;
	struct rte_hash  *private_ip_hash;
	struct rte_hash  *private_ip_port_hash;
	struct rte_hash  *public_ip_port_hash;
	struct private_flow_entry *private_flow_entries;
	struct public_entry *public_entries;
	struct next_hop *next_hops;
	struct lcore_cfg *lconf;
	struct rte_lpm *ipv4_lpm;
	uint32_t total_free_port_count;
	uint32_t number_free_rules;
	int    private;
	uint32_t public_ip_count;
	uint32_t last_ip;
	struct public_ip_config_info *public_ip_config_info;
	struct private_ip_info *private_ip_info;
	uint8_t runtime_flags;
	int offload_crc;
	uint64_t src_mac[PROX_MAX_PORTS];
	uint64_t src_mac_from_dpdk_port[PROX_MAX_PORTS];
	volatile int dump_public_hash;
	volatile int dump_private_hash;
};
static __m128i proto_ipsrc_portsrc_mask;
static __m128i proto_ipdst_portdst_mask;
struct pkt_eth_ipv4 {
	struct ether_hdr ether_hdr;
	struct ipv4_hdr  ipv4_hdr;
	struct udp_hdr  udp_hdr;
} __attribute__((packed));

void task_cgnat_dump_public_hash(struct task_nat *task)
{
	task->dump_public_hash = 1;
}

void task_cgnat_dump_private_hash(struct task_nat *task)
{
	task->dump_private_hash = 1;
}

static void set_l2(struct task_nat *task, struct rte_mbuf *mbuf, uint8_t nh_idx)
{
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	*((uint64_t *)(&peth->d_addr)) = task->next_hops[nh_idx].mac_port_8bytes;
	*((uint64_t *)(&peth->s_addr)) = task->src_mac[task->next_hops[nh_idx].mac_port.out_idx];
}

static uint8_t route_ipv4(struct task_nat *task, struct rte_mbuf *mbuf)
{
	struct pkt_eth_ipv4 *pkt = rte_pktmbuf_mtod(mbuf, struct pkt_eth_ipv4 *);
	struct ipv4_hdr *ip = &pkt->ipv4_hdr;
	struct ether_hdr *peth_out;
	uint8_t tx_port;
	uint32_t dst_ip;

	switch(ip->next_proto_id) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		dst_ip = ip->dst_addr;
		break;
	default:
		/* Routing for other protocols is not implemented */
		plogx_info("Routing nit implemented for this protocol\n");
		return OUT_DISCARD;
	}

#if RTE_VERSION >= RTE_VERSION_NUM(16,4,0,1)
	uint32_t next_hop_index;
#else
	uint8_t next_hop_index;
#endif
	if (unlikely(rte_lpm_lookup(task->ipv4_lpm, rte_bswap32(dst_ip), &next_hop_index) != 0)) {
		uint8_t* dst_ipp = (uint8_t*)&dst_ip;
		plog_warn("lpm_lookup failed for ip %d.%d.%d.%d: rc = %d\n",
			dst_ipp[0], dst_ipp[1], dst_ipp[2], dst_ipp[3], -ENOENT);
		return OUT_DISCARD;
	}

	tx_port = task->next_hops[next_hop_index].mac_port.out_idx;
	set_l2(task, mbuf, next_hop_index);
	return tx_port;
}

static int release_ip(struct task_nat *task, uint32_t *ip_addr, int public_ip_idx)
{
	return 0;
}

static int release_port(struct task_nat *task, uint32_t public_ip_idx, uint16_t udp_src_port)
{
	struct public_ip_config_info *public_ip_config_info = &task->public_ip_config_info[public_ip_idx];
	if (public_ip_config_info->max_port_count > public_ip_config_info->port_free_count) {
		public_ip_config_info->port_list[public_ip_config_info->port_free_count] = udp_src_port;
		public_ip_config_info->port_free_count++;
		task->total_free_port_count ++;
		plogx_dbg("Now %d free ports for IP %d.%d.%d.%d\n", public_ip_config_info->port_free_count, IP4(public_ip_config_info->public_ip));
	} else {
		plogx_err("Unable to release port for ip index %d: max_port_count = %d, port_free_count = %d", public_ip_idx, public_ip_config_info->max_port_count, public_ip_config_info->port_free_count);
		return -1;
	}
	return 0;
}

static int get_new_ip(struct task_nat *task, uint32_t *ip_addr)
{
	struct public_ip_config_info *ip_info;
	if (++task->last_ip >= task->public_ip_count)
		task->last_ip = 0;
	for (uint32_t ip_idx = task->last_ip; ip_idx < task->public_ip_count; ip_idx++) {
		ip_info = &task->public_ip_config_info[ip_idx];
		plogx_dbg("Checking public IP index %d\n", ip_idx);
		if ((ip_info->port_free_count) > 0) {
			plogx_dbg("Public IP index %d (IP %d.%d.%d.%d) has %d free ports\n", ip_idx, IP4(ip_info->public_ip), ip_info->port_free_count);
			*ip_addr = ip_info->public_ip;
			task->last_ip = ip_idx;
			return ip_idx;
		}
	}
	for (uint32_t ip_idx = 0; ip_idx < task->last_ip; ip_idx++) {
		ip_info = &task->public_ip_config_info[ip_idx];
		if ((ip_info->port_free_count) > 0) {
			plogx_dbg("Public IP index %d (IP %d.%d.%d.%d) has %d free ports\n", ip_idx, IP4(ip_info->public_ip), ip_info->port_free_count);
			*ip_addr = ip_info->public_ip;
			task->last_ip = ip_idx;
			return ip_idx;
		}
	}
	return -1;
}

static int get_new_port(struct task_nat *task, uint32_t ip_idx, uint16_t *udp_src_port)
{
	int ret;
	struct public_ip_config_info *public_ip_config_info = &task->public_ip_config_info[ip_idx];
	if (public_ip_config_info->port_free_count > 0) {
		public_ip_config_info->port_free_count--;
		*udp_src_port = public_ip_config_info->port_list[public_ip_config_info->port_free_count];
		task->total_free_port_count --;
		plogx_info("Now %d free ports for IP %d.%d.%d.%d\n", public_ip_config_info->port_free_count, IP4(public_ip_config_info->public_ip));
	} else
		return -1;
	return 0;
}

static int delete_port_entry(struct task_nat *task, uint8_t proto, uint32_t private_ip, uint16_t private_port,  uint32_t public_ip, uint16_t public_port, int public_ip_idx)
{
	int ret;
	struct private_key private_key;
	struct public_key public_key;
//	private_key.proto = proto;
	private_key.ip_addr = private_ip;
	private_key.l4_port = private_port;
	ret = rte_hash_del_key(task->private_ip_port_hash, (const void *)&private_key);
	if (ret < 0) {
		plogx_info("Unable delete key ip %d.%d.%d.%d / port %x in private ip_port hash\n", IP4(private_ip), private_port);
		return -1;
	} else {
		plogx_dbg("Deleted ip %d.%d.%d.%d / port %x from private ip_port hash\n", IP4(private_ip), private_port);
	}
	public_key.ip_addr = public_ip;
	public_key.l4_port = public_port;
	ret = rte_hash_del_key(task->public_ip_port_hash, (const void *)&public_key);
	if (ret < 0) {
		plogx_info("Unable delete key ip %d.%d.%d.%d / port %x in public ip_port hash\n", IP4(public_ip), public_port);
		return -1;
	} else {
		plogx_dbg("Deleted ip %d.%d.%d.%d / port %x (hash index %d) from public ip_port hash\n", IP4(public_ip), public_port, ret);
		release_port(task, public_ip_idx, public_port);
	}
	return 0;
}

static int add_new_port_entry(struct task_nat *task, uint8_t proto, int public_ip_idx, int private_ip_idx, uint32_t private_src_ip, uint16_t private_udp_port, struct rte_mbuf *mbuf, uint64_t tsc, uint16_t *port)
{
	struct private_key private_key;
	struct public_key public_key;
	uint32_t ip = task->public_ip_config_info[public_ip_idx].public_ip;
	int ret;
	if (get_new_port(task, public_ip_idx, port) < 0) {
		plogx_info("Unable to find new port for IP %x\n", private_src_ip);
		return -1;
	}
//	private_key.proto = proto;
	private_key.ip_addr = private_src_ip;
	private_key.l4_port = private_udp_port;
	ret = rte_hash_add_key(task->private_ip_port_hash, (const void *)&private_key);
	if (ret < 0) {
		plogx_info("Unable add ip %d.%d.%d.%d / port %x in private ip_port hash\n", IP4(private_src_ip), private_udp_port);
		release_port(task, public_ip_idx, *port);
		return -1;
	} else if (task->private_flow_entries[ret].ip_addr) {
		plogx_dbg("Race condition properly handled: port alrerady added\n");
		release_port(task, public_ip_idx, *port);
		return ret;
	} else {
		plogx_dbg("Added ip %d.%d.%d.%d / port %x in private ip_port hash => %d.%d.%d.%d / %d - index = %d\n", IP4(private_src_ip), private_udp_port, IP4(ip), *port, ret);
	}
	task->private_flow_entries[ret].ip_addr = ip;
	task->private_flow_entries[ret].l4_port = *port;
	task->private_flow_entries[ret].flow_time = tsc;
       	task->private_flow_entries[ret].private_ip_idx = private_ip_idx;

	public_key.ip_addr = ip;
	public_key.l4_port = *port;
	plogx_dbg("Adding key ip %d.%d.%d.%d / port %x in public ip_port hash\n", IP4(ip), *port);
	ret = rte_hash_add_key(task->public_ip_port_hash, (const void *)&public_key);
	if (ret < 0) {
		plogx_info("Unable add ip %x / port %x in public ip_port hash\n", ip, *port);
		// TODO: remove from private_ip_port_hash
		release_port(task, public_ip_idx, *port);
		return -1;
	} else {
		plogx_dbg("Added ip %d.%d.%d.%d / port %x in public ip_port hash\n", IP4(ip), *port);
	}
	task->public_entries[ret].ip_addr = private_src_ip;
	task->public_entries[ret].l4_port = private_udp_port;
	task->public_entries[ret].dpdk_port = mbuf->port;
       	task->public_entries[ret].private_ip_idx = private_ip_idx;
	return ret;
}

static int handle_nat_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
        struct task_nat *task = (struct task_nat *)tbase;
        uint8_t out[MAX_PKT_BURST];
        uint16_t j;
	uint32_t *ip_addr, public_ip, private_ip;
	uint16_t *udp_src_port, port, private_port, public_port;
	struct pkt_eth_ipv4 *pkt[MAX_PKT_BURST];
	int ret, private_ip_idx, public_ip_idx = -1, port_idx;
	int new_entry = 0;
	uint8_t proto;
	uint64_t tsc = rte_rdtsc();
	void *keys[MAX_PKT_BURST];
	int32_t positions[MAX_PKT_BURST];
	int map[MAX_PKT_BURST] = {0};

	if (unlikely(task->dump_public_hash)) {
		const struct public_key *next_key;
		void *next_data;
		uint32_t iter = 0;
		int i = 0;
		int ret;

		while ((ret = rte_hash_iterate(task->public_ip_port_hash, (const void **)&next_key, &next_data, &iter)) >= 0) {
			plogx_info("Public entry %d (index %d): ip = %d.%d.%d.%d, port = %d ===> private entry: ip = %d.%d.%d.%d, port = %d\n", i++, ret, IP4(next_key->ip_addr), next_key->l4_port, IP4(task->public_entries[ret].ip_addr),task->public_entries[ret].l4_port);
		}
		task->dump_public_hash = 0;
	}
	if (unlikely(task->dump_private_hash)) {
		const struct private_key *next_key;
		void *next_data;
		uint32_t iter = 0;
		int i = 0;
		int ret;

		while ((ret = rte_hash_iterate(task->private_ip_port_hash, (const void **)&next_key, &next_data, &iter)) >= 0) {
			plogx_info("Private entry %d (index %d): ip = %d.%d.%d.%d, port = %d ===> public entry: ip = %d.%d.%d.%d, port = %d\n", i++, ret, IP4(next_key->ip_addr), next_key->l4_port, IP4(task->private_flow_entries[ret].ip_addr),task->private_flow_entries[ret].l4_port);
		}
		task->dump_private_hash = 0;
	}

       	for (j = 0; j < n_pkts; ++j) {
               	PREFETCH0(mbufs[j]);
	}
       	for (j = 0; j < n_pkts; ++j) {
		pkt[j] = rte_pktmbuf_mtod(mbufs[j], struct pkt_eth_ipv4 *);
               	PREFETCH0(pkt[j]);
	}
	if (task->private) {
       		struct private_key key[MAX_PKT_BURST];
        	for (j = 0; j < n_pkts; ++j) {
			/* Currently, only support eth/ipv4 packets */
			if (pkt[j]->ether_hdr.ether_type != ETYPE_IPv4) {
				plogx_info("Currently, only support eth/ipv4 packets\n");
				out[j] = OUT_DISCARD;
				keys[j] = (void *)NULL;
				continue;
			}
       			key[j].ip_addr = pkt[j]->ipv4_hdr.src_addr;
			key[j].l4_port = pkt[j]->udp_hdr.src_port;
			keys[j] = &key[j];
		}
		ret = rte_hash_lookup_bulk(task->private_ip_port_hash, (const void **)&keys, n_pkts, positions);
		if (unlikely(ret < 0)) {
			plogx_info("lookup_bulk failed in private_ip_port_hash\n");
			return -1;
		}
		int n_new_mapping = 0;
        	for (j = 0; j < n_pkts; ++j) {
			port_idx = positions[j];
			if (unlikely(port_idx < 0)) {
				plogx_dbg("ip %d.%d.%d.%d / port %x not found in private ip/port hash\n", IP4(pkt[j]->ipv4_hdr.src_addr), pkt[j]->udp_hdr.src_port);
				map[n_new_mapping] = j;
				keys[n_new_mapping++] = (void *)&(pkt[j]->ipv4_hdr.src_addr);
			} else {
				ip_addr = &(pkt[j]->ipv4_hdr.src_addr);
				udp_src_port = &(pkt[j]->udp_hdr.src_port);
				plogx_dbg("ip/port %d.%d.%d.%d / %x found in private ip/port hash\n", IP4(pkt[j]->ipv4_hdr.src_addr), pkt[j]->udp_hdr.src_port);
       				*ip_addr = task->private_flow_entries[port_idx].ip_addr;
       				*udp_src_port = task->private_flow_entries[port_idx].l4_port;
				uint64_t flow_time = task->private_flow_entries[port_idx].flow_time;
				if (flow_time + tsc_hz < tsc) {
					task->private_flow_entries[port_idx].flow_time = tsc;
				}
				private_ip_idx = task->private_flow_entries[port_idx].private_ip_idx;
				if (task->private_ip_info[private_ip_idx].mac_aging_time + tsc_hz < tsc)
					task->private_ip_info[private_ip_idx].mac_aging_time = tsc;
				prox_ip_udp_cksum(mbufs[j], &pkt[j]->ipv4_hdr, sizeof(struct ether_hdr), sizeof(struct ipv4_hdr), task->offload_crc);
				out[j] =  route_ipv4(task, mbufs[j]);
			}
		}

		if (n_new_mapping) {
			// Find whether at least IP is already known...
			ret = rte_hash_lookup_bulk(task->private_ip_hash, (const void **)&keys, n_new_mapping, positions);
			if (unlikely(ret < 0)) {
				plogx_info("lookup_bulk failed for private_ip_hash\n");
				for (int k = 0; k < n_new_mapping; ++k) {
					j = map[k];
					out[j] = OUT_DISCARD;
				}
				n_new_mapping = 0;
			}
       			for (int k = 0; k < n_new_mapping; ++k) {
				private_ip_idx = positions[k];
				j = map[k];
				ip_addr = &(pkt[j]->ipv4_hdr.src_addr);
				proto = pkt[j]->ipv4_hdr.next_proto_id;
				udp_src_port = &(pkt[j]->udp_hdr.src_port);
				int new_ip_entry = 0;

				if (unlikely(private_ip_idx < 0)) {
					private_ip = *ip_addr;
					private_port = *udp_src_port;
					plogx_dbg("Did not find private ip %d.%d.%d.%d in ip hash table, looking for new public ip\n", IP4(*ip_addr));
					// IP not found, need to get a new IP/port mapping
					public_ip_idx = get_new_ip(task, &public_ip);
					if (public_ip_idx < 0) {
						plogx_info("Unable to find new ip/port\n");
						out[j] = OUT_DISCARD;
						continue;
					} else {
						plogx_dbg("found new public ip %d.%d.%d.%d at public IP index %d\n", IP4(public_ip), public_ip_idx);
					}
					private_ip_idx = rte_hash_add_key(task->private_ip_hash, (const void *)ip_addr);
					// The key might be added multiple time - in case the same key was present in the bulk_lookup multiple times
					// As such this is not an issue - the add_key will returns the index as for a new key
					// This scenario should not happen often in real time use case
					// as a for a new flow (flow renewal), probably only one packet will be sent (e.g. TCP SYN)
					if (private_ip_idx < 0) {
						release_ip(task, &public_ip, public_ip_idx);
						plogx_info("Unable add ip %d.%d.%d.%d in private ip hash\n", IP4(*ip_addr));
						out[j] = OUT_DISCARD;
						continue;
					} else if (task->private_ip_info[private_ip_idx].public_ip) {
						plogx_info("race condition properly handled : ip %d.%d.%d.%d already in private ip hash\n", IP4(*ip_addr));
						release_ip(task, &public_ip, public_ip_idx);
						public_ip = task->private_ip_info[private_ip_idx].public_ip;
						public_ip_idx = task->private_ip_info[private_ip_idx].public_ip_idx;
					} else {
						plogx_dbg("Added ip %d.%d.%d.%d in private ip hash\n", IP4(*ip_addr));
						rte_memcpy(&task->private_ip_info[private_ip_idx].private_mac, ((uint8_t *)pkt) + 6, 6);
						task->private_ip_info[private_ip_idx].public_ip = public_ip;
						task->private_ip_info[private_ip_idx].static_entry = 0;
						task->private_ip_info[private_ip_idx].public_ip_idx = public_ip_idx;
						new_ip_entry = 1;
					}
				} else {
					public_ip = task->private_ip_info[private_ip_idx].public_ip;
					public_ip_idx = task->private_ip_info[private_ip_idx].public_ip_idx;
				}
				port_idx = add_new_port_entry(task, proto, public_ip_idx, private_ip_idx, *ip_addr, *udp_src_port, mbufs[j], tsc, &public_port);
				if (port_idx < 0) {
					// TODO: delete IP in ip_hash
					if ((new_ip_entry) && (task->last_ip != 0)) {
						release_ip(task, &public_ip, public_ip_idx);
						task->last_ip--;
					} else if (new_ip_entry) {
						release_ip(task, &public_ip, public_ip_idx);
						task->last_ip = task->public_ip_count-1;
					}
					plogx_info("Failed to add new port entry\n");
					out[j] = OUT_DISCARD;
					continue;
				} else {
					private_ip = *ip_addr;
					private_port = *udp_src_port;
					plogx_info("Added new ip/port: private ip/port = %d.%d.%d.%d/%x public ip/port = %d.%d.%d.%d/%x, index = %d\n", IP4(private_ip), private_port, IP4(public_ip), public_port, port_idx);
				}
       				// task->private_flow_entries[port_idx].ip_addr = task->private_ip_info[private_ip_idx].public_ip;
				plogx_info("Added new port: private ip/port = %d.%d.%d.%d/%x, public ip/port = %d.%d.%d.%d/%x\n", IP4(private_ip), private_port, IP4(task->private_ip_info[private_ip_idx].public_ip), public_port);
       				*ip_addr = public_ip ;
       				*udp_src_port = public_port;
				uint64_t flow_time = task->private_flow_entries[port_idx].flow_time;
				if (flow_time + tsc_hz < tsc) {
					task->private_flow_entries[port_idx].flow_time = tsc;
				}
				if (task->private_ip_info[private_ip_idx].mac_aging_time + tsc_hz < tsc)
					task->private_ip_info[private_ip_idx].mac_aging_time = tsc;
				prox_ip_udp_cksum(mbufs[j], &pkt[j]->ipv4_hdr, sizeof(struct ether_hdr), sizeof(struct ipv4_hdr), task->offload_crc);
				// TODO: if route fails while just added new key in table, should we delete the key from the table?
				out[j] =  route_ipv4(task, mbufs[j]);
				if (out[j] && new_entry) {
					delete_port_entry(task, proto, private_ip, private_port, *ip_addr, *udp_src_port, public_ip_idx);
					plogx_info("Deleted port: private ip/port = %d.%d.%d.%d/%x, public ip/port = %d.%d.%d.%d/%x\n", IP4(private_ip), private_port, IP4(*ip_addr), *udp_src_port);
				}
			}
		}
        	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
	} else {
		struct public_key public_key[MAX_PKT_BURST];
        	for (j = 0; j < n_pkts; ++j) {
			/* Currently, only support eth/ipv4 packets */
			if (pkt[j]->ether_hdr.ether_type != ETYPE_IPv4) {
				plogx_info("Currently, only support eth/ipv4 packets\n");
				out[j] = OUT_DISCARD;
				keys[j] = (void *)NULL;
				continue;
			}
       			public_key[j].ip_addr = pkt[j]->ipv4_hdr.dst_addr;
			public_key[j].l4_port = pkt[j]->udp_hdr.dst_port;
			keys[j] = &public_key[j];
		}
		ret = rte_hash_lookup_bulk(task->public_ip_port_hash, (const void **)&keys, n_pkts, positions);
		if (ret < 0) {
			plogx_err("Failed lookup bulk public_ip_port_hash\n");
			return -1;
		}
        	for (j = 0; j < n_pkts; ++j) {
			port_idx = positions[j];
       			ip_addr = &(pkt[j]->ipv4_hdr.dst_addr);
			udp_src_port = &(pkt[j]->udp_hdr.dst_port);
			if (port_idx < 0) {
				plogx_err("Failed to find ip/port %d.%d.%d.%d/%x in public_ip_port_hash\n", IP4(*ip_addr), *udp_src_port);
				out[j] = OUT_DISCARD;
			} else {
				plogx_dbg("Found ip/port %d.%d.%d.%d/%x in public_ip_port_hash\n", IP4(*ip_addr), *udp_src_port);
        			*ip_addr = task->public_entries[port_idx].ip_addr;
				*udp_src_port = task->public_entries[port_idx].l4_port;
				private_ip_idx = task->public_entries[port_idx].private_ip_idx;
				plogx_dbg("Found private IP info for ip %d.%d.%d.%d\n", IP4(*ip_addr));
				rte_memcpy(((uint8_t *)(pkt[j])) + 0, &task->private_ip_info[private_ip_idx].private_mac, 6);
				rte_memcpy(((uint8_t *)(pkt[j])) + 6, &task->src_mac_from_dpdk_port[task->public_entries[port_idx].dpdk_port], 6);
				out[j] = task->public_entries[port_idx].dpdk_port;
			}
			prox_ip_udp_cksum(mbufs[j], &pkt[j]->ipv4_hdr, sizeof(struct ether_hdr), sizeof(struct ipv4_hdr), task->offload_crc);
		}
        	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
	}

}

static int lua_to_hash_nat(struct task_args *targ, struct lua_State *L, enum lua_place from, const char *name, uint8_t socket)
{
	struct rte_hash *tmp_priv_ip_hash, *tmp_priv_hash, *tmp_pub_hash;
	struct private_flow_entry *tmp_priv_flow_entries;
	struct public_entry *tmp_pub_entries;
	uint32_t n_entries = 0;;
	uint32_t ip_from, ip_to;
	uint16_t port_from, port_to;
	int ret, idx, pop, pop2, pop3, n_static_entries = 0;
	uint32_t dst_ip1, dst_ip2;
	struct val_range dst_port;
	struct public_ip_config_info *ip_info;
	struct public_ip_config_info *tmp_public_ip_config_info;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

        if (!lua_istable(L, -1)) {
                plogx_err("Can't read cgnat since data is not a table\n");
                return -1;
        }

	struct tmp_public_ip {
        	uint32_t ip_beg;
		uint32_t ip_end;
        	uint16_t port_beg;
		uint16_t port_end;
	};
	struct tmp_static_ip {
		uint32_t private_ip;
		uint32_t public_ip;
	};
	struct tmp_static_ip_port {
		uint32_t private_ip;
		uint32_t public_ip;
		uint32_t n_ports;
		uint16_t private_port;
		uint16_t public_port;
		int ip_found;
		uint8_t port_found;
	};
	uint32_t n_public_groups = 0;
	uint32_t n_public_ip = 0;
	uint32_t n_static_ip = 0;
	uint32_t n_static_ip_port = 0;
	unsigned int i = 0;
	struct tmp_public_ip *tmp_public_ip = NULL;
	struct tmp_static_ip *tmp_static_ip = NULL;
	struct tmp_static_ip_port *tmp_static_ip_port = NULL;

	// Look for Dynamic entries configuration
	plogx_info("Reading dynamic NAT table\n");
	if ((pop2 = lua_getfrom(L, TABLE, "dynamic")) < 0) {
		plogx_info("No dynamic table found\n");
	} else {
		uint64_t n_ip, n_port;
        	if (!lua_istable(L, -1)) {
                	plogx_err("Can't read cgnat since data is not a table\n");
                	return -1;
        	}
		lua_len(L, -1);
		n_public_groups = lua_tointeger(L, -1);
		plogx_info("%d groups of public IP\n", n_public_groups);
		tmp_public_ip = (struct tmp_public_ip *)malloc(n_public_groups * sizeof(struct tmp_public_ip));
		PROX_PANIC(tmp_public_ip == NULL, "Failed to allocated tmp_public_ip\n");
		lua_pop(L, 1);
		lua_pushnil(L);

		while (lua_next(L, -2)) {
			if (lua_to_ip(L, TABLE, "public_ip_range_start", &dst_ip1) ||
		    		lua_to_ip(L, TABLE, "public_ip_range_stop", &dst_ip2) ||
		    		lua_to_val_range(L, TABLE, "public_port", &dst_port))
					return -1;
			PROX_PANIC(dst_ip2 < dst_ip1, "public_ip_range error: %d.%d.%d.%d < %d.%d.%d.%d\n", (dst_ip2 >> 24), (dst_ip2 >> 16) & 0xFF, (dst_ip2 >> 8) & 0xFF, dst_ip2 & 0xFF, dst_ip1 >> 24, (dst_ip1 >> 16) & 0xFF, (dst_ip1 >> 8) & 0xFF, dst_ip1 & 0xFF);
			PROX_PANIC(dst_port.end < dst_port.beg, "public_port error: %d < %d\n", dst_port.end, dst_port.beg);
			n_ip = dst_ip2 - dst_ip1 + 1;
			n_port =  dst_port.end - dst_port.beg + 1;
			n_public_ip += n_ip;
			plogx_info("Found IP from %d.%d.%d.%d to %d.%d.%d.%d and port from %d to %d\n", dst_ip1 >> 24, (dst_ip1 >> 16) & 0xFF, (dst_ip1 >> 8) & 0xFF, dst_ip1 & 0xFF, (dst_ip2 >> 24), (dst_ip2 >> 16) & 0xFF, (dst_ip2 >> 8) & 0xFF, dst_ip2 & 0xFF, dst_port.beg, dst_port.end);
			tmp_public_ip[i].ip_beg = dst_ip1;
			tmp_public_ip[i].ip_end = dst_ip2;
			tmp_public_ip[i].port_beg = dst_port.beg;
			tmp_public_ip[i++].port_end = dst_port.end;
			n_entries += n_ip * n_port;
			lua_pop(L, 1);
		}
		lua_pop(L, pop2);

	}
	i = 0;
	if ((pop2 = lua_getfrom(L, TABLE, "static_ip")) < 0) {
		plogx_info("No static ip table found\n");
	} else {
        	if (!lua_istable(L, -1)) {
                	plogx_err("Can't read cgnat since data is not a table\n");
                	return -1;
		}

		lua_len(L, -1);
		n_static_ip = lua_tointeger(L, -1);
		plogx_info("%d entries in static ip table\n", n_static_ip);
		lua_pop(L, 1);
		tmp_static_ip = (struct tmp_static_ip *)malloc(n_static_ip * sizeof(struct tmp_static_ip));
		PROX_PANIC(tmp_static_ip == NULL, "Failed to allocated tmp_static_ip\n");
		lua_pushnil(L);
		while (lua_next(L, -2)) {
			if (lua_to_ip(L, TABLE, "src_ip", &ip_from) ||
		    		lua_to_ip(L, TABLE, "dst_ip", &ip_to))
					return -1;
			ip_from = rte_bswap32(ip_from);
			ip_to = rte_bswap32(ip_to);
			tmp_static_ip[i].private_ip = ip_from;
			tmp_static_ip[i++].public_ip = ip_to;
			for (unsigned int j = 0; j < n_public_groups; j++) {
				if ((tmp_public_ip[j].ip_beg <= ip_to) && (ip_to <= tmp_public_ip[j].ip_end)) {
					PROX_PANIC(1, "list of static ip mapping overlap with list of dynamic IP => not supported yet\n");
				}
			}
			n_public_ip++;
			lua_pop(L, 1);
		}
		lua_pop(L, pop2);
	}

	i = 0;
	if ((pop2 = lua_getfrom(L, TABLE, "static_ip_port")) < 0) {
		plogx_info("No static table found\n");
	} else {
        	if (!lua_istable(L, -1)) {
                	plogx_err("Can't read cgnat since data is not a table\n");
                	return -1;
		}

		lua_len(L, -1);
		n_static_ip_port = lua_tointeger(L, -1);
		plogx_info("%d entries in static table\n", n_static_ip_port);
		lua_pop(L, 1);
		tmp_static_ip_port = (struct tmp_static_ip_port *)malloc(n_static_ip_port * sizeof(struct tmp_static_ip_port));
		PROX_PANIC(tmp_static_ip_port == NULL, "Failed to allocated tmp_static_ip_port\n");
		lua_pushnil(L);

		while (lua_next(L, -2)) {
			if (lua_to_ip(L, TABLE, "src_ip", &ip_from) ||
		    		lua_to_ip(L, TABLE, "dst_ip", &ip_to) ||
		    		lua_to_port(L, TABLE, "src_port", &port_from) ||
		    		lua_to_port(L, TABLE, "dst_port", &port_to))
					return -1;

			ip_from = rte_bswap32(ip_from);
			ip_to = rte_bswap32(ip_to);
			port_from = rte_bswap16(port_from);
			port_to = rte_bswap16(port_to);
			tmp_static_ip_port[i].private_ip = ip_from;
			tmp_static_ip_port[i].public_ip = ip_to;
			tmp_static_ip_port[i].private_port = port_from;
			tmp_static_ip_port[i].public_port = port_to;
			tmp_static_ip_port[i].n_ports = 1;
			for (unsigned int j = 0; j < n_public_groups; j++) {
				if ((tmp_public_ip[j].ip_beg <= rte_bswap32(ip_to)) && (rte_bswap32(ip_to) <= tmp_public_ip[j].ip_end)) {
					tmp_static_ip_port[i].ip_found = j + 11;
					PROX_PANIC(1, "list of static ip/port mapping overlap with list of dynamic IP => not supported yet\n");
				}
			}
			for (unsigned int j = 0; j < n_static_ip; j++) {
				if ((tmp_static_ip[j].public_ip == ip_to) ) {
					tmp_static_ip_port[i].ip_found = j + 1;
					PROX_PANIC(1, "list of static ip/port mapping overlap with list of static ip => not supported yet\n");
				}
			}
			for (unsigned int j = 0; j <= i; j++) {
				if (ip_to == tmp_static_ip_port[j].public_ip) {
					tmp_static_ip_port[i].ip_found = j + 1;
					tmp_static_ip_port[j].n_ports++;
					tmp_static_ip_port[i].n_ports = 0;
				}
			}
			i++;
			if (!tmp_static_ip_port[i].ip_found) {
				n_public_ip++;
				n_entries++;
			}
			lua_pop(L, 1);
		}
		lua_pop(L, pop2);
	}
	lua_pop(L, pop);

	tmp_public_ip_config_info = (struct public_ip_config_info *)prox_zmalloc(n_public_ip * sizeof(struct public_ip_config_info), socket);
	PROX_PANIC(tmp_public_ip_config_info == NULL, "Failed to allocate PUBLIC IP INFO\n");
	plogx_info("%d PUBLIC IP INFO allocated\n", n_public_ip);

	struct private_ip_info *tmp_priv_ip_info = (struct private_ip_info *)prox_zmalloc(4 * n_public_ip * sizeof(struct public_ip_config_info), socket);
	PROX_PANIC(tmp_priv_ip_info == NULL, "Failed to allocate PRIVATE IP INFO\n");
	plogx_info("%d PRIVATE IP INFO allocated\n", 4 * n_public_ip);

	uint32_t ip_free_count = 0;
	for (i = 0; i < n_public_groups; i++) {
		for (uint32_t ip = tmp_public_ip[i].ip_beg; ip <= tmp_public_ip[i].ip_end; ip++) {
			ip_info = &tmp_public_ip_config_info[ip_free_count];
			ip_info->public_ip = rte_bswap32(ip);
			ip_info->port_list = (uint16_t *)prox_zmalloc((dst_port.end - dst_port.beg) * sizeof(uint16_t), socket);
                       	PROX_PANIC(ip_info->port_list == NULL, "Failed to allocate list of ports for ip %x\n", ip);
			for (uint32_t port = tmp_public_ip[i].port_beg; port <= tmp_public_ip[i].port_end; port++) {
				ip_info->port_list[ip_info->port_free_count] = rte_bswap16(port);
				ip_info->port_free_count++;
			}
			ip_info->max_port_count = ip_info->port_free_count;
			plogx_dbg("Added IP %d.%d.%d.%d with ports from %x to %x at index %x\n", IP4(ip_info->public_ip), tmp_public_ip[i].port_beg, tmp_public_ip[i].port_end, ip_free_count);
			ip_free_count++;
		}
	}
	uint32_t public_ip_count = ip_free_count;
	for (i = 0; i < n_static_ip; i++) {
		ip_info = &tmp_public_ip_config_info[ip_free_count];
		ip_info->public_ip = tmp_static_ip[i].public_ip;
		ip_info->port_list = NULL;
		ip_info->max_port_count = 0;
		ip_free_count++;
	}
	for (i = 0; i < n_static_ip_port; i++) {
		if (!tmp_static_ip_port[i].ip_found) {
			ip_info = &tmp_public_ip_config_info[ip_free_count];
			ip_info->public_ip = tmp_static_ip_port[i].public_ip;
			ip_info->port_list = (uint16_t *)prox_zmalloc(tmp_static_ip_port[i].n_ports * sizeof(uint16_t), socket);
                	PROX_PANIC(ip_info->port_list == NULL, "Failed to allocate list of ports for ip %x\n", tmp_static_ip_port[i].public_ip);
			ip_info->port_list[ip_info->port_free_count] = tmp_static_ip_port[i].public_port;
			ip_info->port_free_count++;
			ip_info->max_port_count = ip_info->port_free_count;
			ip_free_count++;
		} else {
			for (unsigned j = 0; j < ip_free_count; j++) {
				ip_info = &tmp_public_ip_config_info[j];
				if (ip_info->public_ip == tmp_static_ip_port[i].public_ip) {
					ip_info = &tmp_public_ip_config_info[j];
					ip_info->port_list[ip_info->port_free_count] = tmp_static_ip_port[i].public_port;
					ip_info->port_free_count++;
					ip_info->max_port_count = ip_info->port_free_count;
					break;
				}
			}
		}
	}
	plogx_info("%d entries in dynamic table\n", n_entries);

	n_entries = n_entries * 4;
	static char hash_name[30];
	sprintf(hash_name, "A%03d_hash_nat_table", targ->lconf->id);
	struct rte_hash_parameters hash_params = {
		.name = hash_name,
		.entries = n_entries,
		.key_len = sizeof(struct private_key),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
	};
	plogx_info("hash table name = %s\n", hash_params.name);
	struct private_key private_key;
	struct public_key public_key;
	tmp_priv_hash = rte_hash_create(&hash_params);
	PROX_PANIC(tmp_priv_hash == NULL, "Failed to set up private hash table for NAT\n");
	plogx_info("private hash table allocated, with %d entries of size %d\n", hash_params.entries, hash_params.key_len);

	tmp_priv_flow_entries = (struct private_flow_entry *)prox_zmalloc(n_entries * sizeof(struct private_flow_entry), socket);
	PROX_PANIC(tmp_priv_flow_entries == NULL, "Failed to allocate memory for private NAT %u entries\n", n_entries);
	plogx_info("private data allocated, with %d entries of size %ld\n", n_entries, sizeof(struct private_flow_entry));

	hash_name[0]++;
	//hash_params.name[0]++;
	plogx_info("hash table name = %s\n", hash_params.name);
	hash_params.key_len = sizeof(uint32_t);
	hash_params.entries = 4 * ip_free_count;
	tmp_priv_ip_hash = rte_hash_create(&hash_params);
	PROX_PANIC(tmp_priv_ip_hash == NULL, "Failed to set up private ip hash table for NAT\n");
	plogx_info("private ip hash table allocated, with %d entries of size %d\n", hash_params.entries, hash_params.key_len);

	hash_name[0]++;
	//hash_params.name[0]++;
	plogx_info("hash table name = %s\n", hash_params.name);
	hash_params.entries = n_entries;
	hash_params.key_len = sizeof(struct public_key),
	tmp_pub_hash = rte_hash_create(&hash_params);
	PROX_PANIC(tmp_pub_hash == NULL, "Failed to set up public hash table for NAT\n");
	plogx_info("public hash table allocated, with %d entries of size %d\n", hash_params.entries, hash_params.key_len);

	hash_name[0]++;
	//hash_params.name[0]++;
	tmp_pub_entries = (struct public_entry *)prox_zmalloc(n_entries * sizeof(struct public_entry), socket);
	PROX_PANIC(tmp_pub_entries == NULL, "Failed to allocate memory for public NAT %u entries\n", n_entries);
	plogx_info("public data allocated, with %d entries of size %ld\n", n_entries, sizeof(struct private_flow_entry));

	for (i = 0; i < n_static_ip_port; i++) {
		ip_to = tmp_static_ip_port[i].public_ip;
		ip_from = tmp_static_ip_port[i].private_ip;
		port_to = tmp_static_ip_port[i].public_port;
		port_from = tmp_static_ip_port[i].private_port;
		private_key.ip_addr = ip_from;
		private_key.l4_port = port_from;
		ret = rte_hash_lookup(tmp_priv_hash, (const void *)&private_key);
		PROX_PANIC(ret >= 0, "Key %x %x already exists in NAT private hash table\n", ip_from, port_from);

		idx = rte_hash_add_key(tmp_priv_ip_hash, (const void *)&ip_from);
		PROX_PANIC(idx < 0, "Failed to add ip %x to NAT private hash table\n", ip_from);
		ret = rte_hash_add_key(tmp_priv_hash, (const void *)&private_key);
		PROX_PANIC(ret < 0, "Failed to add Key %x %x to NAT private hash table\n", ip_from, port_from);
		tmp_priv_flow_entries[ret].ip_addr = ip_to;
		tmp_priv_flow_entries[ret].flow_time = -1;
		tmp_priv_flow_entries[ret].private_ip_idx = idx;
		tmp_priv_flow_entries[ret].l4_port = port_to;

		public_key.ip_addr = ip_to;
		public_key.l4_port = port_to;
		ret = rte_hash_lookup(tmp_pub_hash, (const void *)&public_key);
		PROX_PANIC(ret >= 0, "Key %d.%d.%d.%d port %x (for private IP %d.%d.%d.%d port %x) already exists in NAT public hash table fir IP %d.%d.%d.%d port %x\n", IP4(ip_to), port_to, IP4(ip_from), port_from, IP4(tmp_pub_entries[ret].ip_addr), tmp_pub_entries[ret].l4_port);

		ret = rte_hash_add_key(tmp_pub_hash, (const void *)&public_key);
		PROX_PANIC(ret < 0, "Failed to add Key %x %x to NAT public hash table\n", ip_to, port_to);
		tmp_pub_entries[ret].ip_addr = ip_from;
		tmp_pub_entries[ret].l4_port = port_from;
		tmp_pub_entries[ret].private_ip_idx = idx;
	}

	for (uint8_t task_id = 0; task_id < targ->lconf->n_tasks_all; ++task_id) {
		struct task_args *target_targ = (struct task_args *)&(targ->lconf->targs[task_id]);
		enum task_mode smode = target_targ->mode;
		if (CGNAT == smode) {
			target_targ->public_ip_count = public_ip_count;
			target_targ->private_ip_hash = tmp_priv_ip_hash;
			target_targ->private_ip_port_hash = tmp_priv_hash;
			target_targ->private_ip_info = tmp_priv_ip_info;
			target_targ->private_flow_entries = tmp_priv_flow_entries;
			target_targ->public_ip_port_hash = tmp_pub_hash;
			target_targ->public_entries = tmp_pub_entries;
			target_targ->public_ip_config_info = tmp_public_ip_config_info;
		}
	}
	return 0;
}

static void early_init_task_nat(struct task_args *targ)
{
	int ret;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	if (!targ->private_ip_hash) {
		ret = lua_to_hash_nat(targ, prox_lua(), GLOBAL, targ->nat_table, socket_id);
		PROX_PANIC(ret != 0, "Failed to load NAT table from lua:\n%s\n", get_lua_to_errors());
	}
}

static void init_task_nat(struct task_base *tbase, struct task_args *targ)
{
	struct task_nat *task = (struct task_nat *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	/* Use destination IP by default. */
	task->private = targ->use_src;

	PROX_PANIC(!strcmp(targ->nat_table, ""), "No nat table specified\n");
	task->lconf = targ->lconf;
	task->runtime_flags = targ->runtime_flags;

	task->public_ip_count = targ->public_ip_count;
	task->last_ip = targ->public_ip_count;
	task->private_ip_hash = targ->private_ip_hash;
	task->private_ip_port_hash = targ->private_ip_port_hash;
	task->private_ip_info = targ->private_ip_info;
	task->private_flow_entries = targ->private_flow_entries;
	task->public_ip_port_hash = targ->public_ip_port_hash;
	task->public_entries = targ->public_entries;
	task->public_ip_config_info = targ->public_ip_config_info;

	proto_ipsrc_portsrc_mask = _mm_set_epi32(BIT_0_TO_15, 0, ALL_32_BITS, BIT_8_TO_15);
	proto_ipdst_portdst_mask = _mm_set_epi32(BIT_16_TO_31, ALL_32_BITS, 0, BIT_8_TO_15);

	struct lpm4 *lpm;

	PROX_PANIC(!strcmp(targ->route_table, ""), "route table not specified\n");
	if (targ->flags & TASK_ARG_LOCAL_LPM) {
		int ret = lua_to_lpm4(prox_lua(), GLOBAL, targ->route_table, socket_id, &lpm);
		PROX_PANIC(ret, "Failed to load IPv4 LPM:\n%s\n", get_lua_to_errors());
		prox_sh_add_socket(socket_id, targ->route_table, lpm);
		task->number_free_rules = lpm->n_free_rules;
	} else {
		lpm = prox_sh_find_socket(socket_id, targ->route_table);
		if (!lpm) {
			int ret = lua_to_lpm4(prox_lua(), GLOBAL, targ->route_table, socket_id, &lpm);
			PROX_PANIC(ret, "Failed to load IPv4 LPM:\n%s\n", get_lua_to_errors());
			prox_sh_add_socket(socket_id, targ->route_table, lpm);
		}
	}
	task->ipv4_lpm = lpm->rte_lpm;
	task->next_hops = lpm->next_hops;
	task->number_free_rules = lpm->n_free_rules;

	for (uint32_t i = 0; i < MAX_HOP_INDEX; i++) {
		int tx_port = task->next_hops[i].mac_port.out_idx;
		if ((tx_port > targ->nb_txports - 1) && (tx_port > targ->nb_txrings - 1)) {
			PROX_PANIC(1, "Routing Table contains port %d but only %d tx port/ %d ring:\n", tx_port, targ->nb_txports, targ->nb_txrings);
		}
	}

	if (targ->nb_txrings) {
		struct task_args *dtarg;
		struct core_task ct;
		for (uint32_t i = 0; i < targ->nb_txrings; ++i) {
			ct = targ->core_task_set[0].core_task[i];
			dtarg = core_targ_get(ct.core, ct.task);
			dtarg = find_reachable_task_sending_to_port(dtarg);
			task->src_mac[i] = (0x0000ffffffffffff & ((*(uint64_t*)&prox_port_cfg[dtarg->tx_port_queue[0].port].eth_addr))) | ((uint64_t)ETYPE_IPv4 << (64 - 16));
			task->src_mac_from_dpdk_port[dtarg->tx_port_queue[0].port] = task->src_mac[i];
			plogx_dbg("src_mac = %lx for port %d %d\n", task->src_mac[i], i, dtarg->tx_port_queue[0].port);
		}
	} else {
		for (uint32_t i = 0; i < targ->nb_txports; ++i) {
			task->src_mac[i] = (0x0000ffffffffffff & ((*(uint64_t*)&prox_port_cfg[targ->tx_port_queue[i].port].eth_addr))) | ((uint64_t)ETYPE_IPv4 << (64 - 16));
			task->src_mac_from_dpdk_port[targ->tx_port_queue[0].port] = task->src_mac[i];
			plogx_dbg("src_mac = %lx for port %d %d\n", task->src_mac[i], i, targ->tx_port_queue[i].port);
		}
	}

	struct prox_port_cfg *port = find_reachable_port(targ);
	if (port) {
		task->offload_crc = port->requested_tx_offload & (DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM);
	}
}

/* Basic static nat. */
static struct task_init task_init_nat = {
	.mode = CGNAT,
	.mode_str = "cgnat",
	.early_init = early_init_task_nat,
	.init = init_task_nat,
	.handle = handle_nat_bulk,
#ifdef SOFT_CRC
	.flag_features = TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS|TASK_FEATURE_ROUTING|TASK_FEATURE_ZERO_RX,
#else
	.flag_features = TASK_FEATURE_ROUTING|TASK_FEATURE_ZERO_RX,
#endif
	.size = sizeof(struct task_nat),
};

__attribute__((constructor)) static void reg_task_nat(void)
{
	reg_task(&task_init_nat);
}
