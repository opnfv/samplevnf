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

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_table_hash.h>
#include <rte_ether.h>
#include <rte_version.h>
#include <rte_byteorder.h>

#include "prox_lua.h"
#include "prox_lua_types.h"

#include "tx_pkt.h"
#include "task_init.h"
#include "task_base.h"
#include "prox_port_cfg.h"
#include "prefetch.h"
#include "lconf.h"
#include "hash_utils.h"
#include "etypes.h"
#include "prox_cksum.h"
#include "defines.h"
#include "log.h"
#include "quit.h"
#include "prox_cfg.h"
#include "parse_utils.h"
#include "cfgfile.h"
#include "prox_shared.h"
#include "prox_compat.h"

#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
#define IPPROTO_IPIP IPPROTO_IPV4
#endif

struct ipv6_tun_dest {
        struct ipv6_addr  dst_addr;
	struct ether_addr dst_mac;
};

typedef enum ipv6_tun_dir_t {
        TUNNEL_DIR_ENCAP = 0,
        TUNNEL_DIR_DECAP = 1,
} ipv6_tun_dir_t;

struct task_ipv6_tun_base {
	struct task_base        base;
	struct ether_addr       src_mac;
	uint8_t                 core_nb;
	uint64_t                keys[64];
	struct rte_mbuf*        fake_packets[64];
	uint16_t                lookup_port_mask;  // Mask used before looking up the port
	void*                   lookup_table;      // Fast lookup table for bindings
	uint32_t		runtime_flags;
	int                     offload_crc;
};

struct task_ipv6_decap {
	struct task_ipv6_tun_base   base;
        struct ether_addr           dst_mac;
};

struct task_ipv6_encap {
	struct task_ipv6_tun_base   base;
	uint32_t                    ipaddr;
	struct ipv6_addr            local_endpoint_addr;
	uint8_t                     tunnel_hop_limit;
};

#define IPv6_VERSION 6
#ifndef IPPROTO_IPV4
#define IPPROTO_IPV4	4
#endif

#define MAKE_KEY_FROM_FIELDS(ipv4_addr, port, port_mask) ( ((uint64_t)ipv4_addr << 16) | (port & port_mask) )

static int handle_ipv6_decap_bulk(struct task_base* tbase, struct rte_mbuf** rx_mbuf, const uint16_t n_pkts);
static int handle_ipv6_encap_bulk(struct task_base* tbase, struct rte_mbuf** rx_mbuf, const uint16_t n_pkts);

static void init_lookup_table(struct task_ipv6_tun_base* ptask, struct task_args *targ)
{
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	/* The lookup table is a per-core data structure to reduce the
	   memory footprint and improve cache utilization. Since
	   operations on the hash table are not safe, the data
	   structure can't be used on a per socket or on a system wide
	   basis. */
	ptask->lookup_table = prox_sh_find_core(targ->lconf->id, "ipv6_binding_table");
	if (NULL == ptask->lookup_table) {
		struct ipv6_tun_binding_table *table;
		PROX_PANIC(!strcmp(targ->tun_bindings, ""), "No tun bindings specified\n");
		int ret = lua_to_ip6_tun_binding(prox_lua(), GLOBAL, targ->tun_bindings, socket_id, &table);
		PROX_PANIC(ret, "Failed to read tun_bindings config:\n %s\n", get_lua_to_errors());

		static char hash_name[30];
		sprintf(hash_name, "ipv6_tunnel_hash_table_%03d", targ->lconf->id);

		struct prox_rte_table_params table_hash_params = {
			.name = hash_name,
			.key_size = 8,
			.n_keys = (table->num_binding_entries * 4),
			.n_buckets = (table->num_binding_entries * 2) >> 1,
			.f_hash = (rte_table_hash_op_hash)hash_crc32,
			.seed = 0,
			.key_offset = HASH_METADATA_OFFSET(0),
			.key_mask = NULL
		};
                plogx_info("IPv6 Tunnel allocating lookup table on socket %d\n", socket_id);
		ptask->lookup_table = prox_rte_table_create(&table_hash_params, socket_id, sizeof(struct ipv6_tun_dest));
		PROX_PANIC(ptask->lookup_table == NULL, "Error creating IPv6 Tunnel lookup table");

		for (unsigned idx = 0; idx < table->num_binding_entries; idx++) {
			int key_found = 0;
			void* entry_in_hash = NULL;
			struct ipv6_tun_dest data;
			struct ipv6_tun_binding_entry* entry = &table->entry[idx];
                        uint64_t key = MAKE_KEY_FROM_FIELDS(rte_cpu_to_be_32(entry->public_ipv4), entry->public_port, ptask->lookup_port_mask);
			rte_memcpy(&data.dst_addr, &entry->endpoint_addr, sizeof(struct ipv6_addr));
			rte_memcpy(&data.dst_mac, &entry->next_hop_mac, sizeof(struct ether_addr));

			int ret = prox_rte_table_key8_add(ptask->lookup_table, &key, &data, &key_found, &entry_in_hash);
			PROX_PANIC(ret, "Error adding entry (%d) to binding lookup table", idx);
			PROX_PANIC(key_found, "key_found!!! for idx=%d\n", idx);

#ifdef DBG_IPV6_TUN_BINDING
			plog_info("Bind: %x:0x%x (port_mask 0x%x) key=0x%"PRIx64"\n", entry->public_ipv4, entry->public_port, ptask->lookup_port_mask, key);
			plog_info("  -> "IPv6_BYTES_FMT" ("MAC_BYTES_FMT")\n", IPv6_BYTES(entry->endpoint_addr.bytes), MAC_BYTES(entry->next_hop_mac.addr_bytes));
			plog_info("  -> "IPv6_BYTES_FMT" ("MAC_BYTES_FMT")\n", IPv6_BYTES(data.dst_addr.bytes), MAC_BYTES(data.dst_mac.addr_bytes));
			plog_info("  -> entry_in_hash=%p\n", entry_in_hash);
#endif
		}
                plogx_info("IPv6 Tunnel created %d lookup table entries\n", table->num_binding_entries);

		prox_sh_add_core(targ->lconf->id, "ipv6_binding_table", ptask->lookup_table);
	}
}

static void init_task_ipv6_tun_base(struct task_ipv6_tun_base* tun_base, struct task_args* targ)
{
	memcpy(&tun_base->src_mac, find_reachable_port(targ), sizeof(tun_base->src_mac));

	tun_base->lookup_port_mask = targ->lookup_port_mask;  // Mask used before looking up the port

	init_lookup_table(tun_base, targ);

	for (uint32_t i = 0; i < 64; ++i) {
		tun_base->fake_packets[i] = (struct rte_mbuf*)((uint8_t*)&tun_base->keys[i] - sizeof (struct rte_mbuf));
	}

	plogx_info("IPv6 Tunnel MAC="MAC_BYTES_FMT" port_mask=0x%x\n",
		  MAC_BYTES(tun_base->src_mac.addr_bytes), tun_base->lookup_port_mask);

	struct prox_port_cfg *port = find_reachable_port(targ);
	if (port) {
		tun_base->offload_crc = port->requested_tx_offload & (DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM);
	}
}

static void init_task_ipv6_decap(struct task_base* tbase, struct task_args* targ)
{
	struct task_ipv6_decap* tun_task = (struct task_ipv6_decap*)tbase;
	struct task_ipv6_tun_base* tun_base = (struct task_ipv6_tun_base*)tun_task;

	init_task_ipv6_tun_base(tun_base, targ);
	tun_base->runtime_flags = targ->runtime_flags;

        memcpy(&tun_task->dst_mac, &targ->edaddr, sizeof(tun_task->dst_mac));
}

static void init_task_ipv6_encap(struct task_base* tbase, struct task_args* targ)
{
	struct task_ipv6_encap* tun_task = (struct task_ipv6_encap*)tbase;
	struct task_ipv6_tun_base *tun_base = (struct task_ipv6_tun_base*)tun_task;

	init_task_ipv6_tun_base(tun_base, targ);

	rte_memcpy(&tun_task->local_endpoint_addr, &targ->local_ipv6, sizeof(tun_task->local_endpoint_addr));
	tun_task->tunnel_hop_limit = targ->tunnel_hop_limit;
	tun_base->runtime_flags = targ->runtime_flags;
}

static struct task_init task_init_ipv6_decap = {
	.mode_str = "ipv6_decap",
	.init = init_task_ipv6_decap,
	.handle = handle_ipv6_decap_bulk,
	.size = sizeof(struct task_ipv6_decap)
};

static struct task_init task_init_ipv6_encap = {
	.mode_str = "ipv6_encap",
	.init = init_task_ipv6_encap,
	.handle = handle_ipv6_encap_bulk,
	.size = sizeof(struct task_ipv6_encap)
};

__attribute__((constructor)) static void reg_task_ipv6_decap(void)
{
	reg_task(&task_init_ipv6_decap);
}

__attribute__((constructor)) static void reg_task_ipv6_encap(void)
{
	reg_task(&task_init_ipv6_encap);
}

static inline uint8_t handle_ipv6_decap(struct task_ipv6_decap* ptask, struct rte_mbuf* rx_mbuf, struct ipv6_tun_dest* tun_dest);
static inline uint8_t handle_ipv6_encap(struct task_ipv6_encap* ptask, struct rte_mbuf* rx_mbuf, struct ipv6_tun_dest* tun_dest);

static inline int extract_key_fields( __attribute__((unused)) struct task_ipv6_tun_base* ptask, struct ipv4_hdr* pip4, ipv6_tun_dir_t dir, uint32_t* pAddr, uint16_t* pPort)
{
        *pAddr = (dir == TUNNEL_DIR_DECAP) ? pip4->src_addr : pip4->dst_addr;

        if (pip4->next_proto_id == IPPROTO_UDP) {
                struct udp_hdr* pudp = (struct udp_hdr *)(pip4 + 1);
                *pPort = rte_be_to_cpu_16((dir == TUNNEL_DIR_DECAP) ? pudp->src_port : pudp->dst_port);
        }
        else if (pip4->next_proto_id == IPPROTO_TCP) {
                struct tcp_hdr* ptcp = (struct tcp_hdr *)(pip4 + 1);
                *pPort = rte_be_to_cpu_16((dir == TUNNEL_DIR_DECAP) ? ptcp->src_port : ptcp->dst_port);
        }
        else {
                plog_warn("IPv6 Tunnel: IPv4 packet of unexpected type proto_id=0x%x\n", pip4->next_proto_id);
                *pPort = 0xffff;
                return -1;
        }

        return 0;
}

static inline void extract_key(struct task_ipv6_tun_base* ptask, struct ipv4_hdr* pip4, ipv6_tun_dir_t dir, uint64_t* pkey)
{
        uint32_t lookup_addr;
        uint16_t lookup_port;

        if (unlikely( extract_key_fields(ptask, pip4, dir, &lookup_addr, &lookup_port))) {
                plog_warn("IPv6 Tunnel: Unable to extract fields from packet\n");
                *pkey = 0xffffffffL;
                return;
        }

        *pkey = MAKE_KEY_FROM_FIELDS(lookup_addr, lookup_port, ptask->lookup_port_mask);
}

static inline struct ipv4_hdr* get_ipv4_decap(struct rte_mbuf *mbuf)
{
        struct ether_hdr* peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
        struct ipv6_hdr* pip6 = (struct ipv6_hdr *)(peth + 1);
        struct ipv4_hdr* pip4 = (struct ipv4_hdr*) (pip6 + 1);  // TODO - Skip Option headers

        return pip4;
}

static inline struct ipv4_hdr* get_ipv4_encap(struct rte_mbuf *mbuf)
{
        struct ether_hdr* peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
        struct ipv4_hdr* pip4 = (struct ipv4_hdr *)(peth + 1);

        return pip4;
}

static inline void extract_key_decap(struct task_ipv6_tun_base* ptask, struct rte_mbuf *mbuf, uint64_t* pkey)
{
        extract_key(ptask, get_ipv4_decap(mbuf), TUNNEL_DIR_DECAP, pkey);
}

static inline void extract_key_decap_bulk(struct task_ipv6_tun_base* ptask, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
        for (uint16_t j = 0; j < n_pkts; ++j) {
                extract_key_decap(ptask, mbufs[j], &ptask->keys[j]);
        }
}

static inline void extract_key_encap(struct task_ipv6_tun_base* ptask, struct rte_mbuf *mbuf, uint64_t* pkey)
{
        extract_key(ptask, get_ipv4_encap(mbuf), TUNNEL_DIR_ENCAP, pkey);
}

static inline void extract_key_encap_bulk(struct task_ipv6_tun_base* ptask, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
        for (uint16_t j = 0; j < n_pkts; ++j) {
                extract_key_encap(ptask, mbufs[j], &ptask->keys[j]);
        }
}

__attribute__((cold)) static void handle_error(struct task_ipv6_tun_base* ptask, struct rte_mbuf* mbuf, ipv6_tun_dir_t dir)
{
        uint32_t lookup_addr;
        uint16_t lookup_port;
        uint64_t key;

        struct ipv4_hdr* pip4 = (dir == TUNNEL_DIR_DECAP) ? get_ipv4_decap(mbuf) : get_ipv4_encap(mbuf);
        extract_key_fields(ptask, pip4, dir, &lookup_addr, &lookup_port);
        extract_key(ptask, pip4, dir, &key);

        plog_warn("IPv6 Tunnel (%s) lookup failed for "IPv4_BYTES_FMT":%d [key=0x%"PRIx64"]\n",
                        (dir == TUNNEL_DIR_DECAP) ? "decap" : "encap",
                        IPv4_BYTES(((unsigned char*)&lookup_addr)), lookup_port, key);
}

static int handle_ipv6_decap_bulk(struct task_base* tbase, struct rte_mbuf** mbufs, const uint16_t n_pkts)
{
        struct task_ipv6_decap* task = (struct task_ipv6_decap *)tbase;
        uint64_t pkts_mask = RTE_LEN2MASK(n_pkts, uint64_t);
        struct ipv6_tun_dest* entries[64];
	uint8_t out[MAX_PKT_BURST];
        uint64_t lookup_hit_mask;
        uint16_t n_kept = 0;

        prefetch_pkts(mbufs, n_pkts);

        // Lookup to verify packets are valid for their respective tunnels (their sending lwB4)
        extract_key_decap_bulk(&task->base, mbufs, n_pkts);
        prox_rte_table_key8_lookup(task->base.lookup_table, task->base.fake_packets, pkts_mask, &lookup_hit_mask, (void**)entries);

        if (likely(lookup_hit_mask == pkts_mask)) {
                for (uint16_t j = 0; j < n_pkts; ++j) {
                        out[j] = handle_ipv6_decap(task, mbufs[j], entries[j]);
                }
        }
        else {
                for (uint16_t j = 0; j < n_pkts; ++j) {
                        if (unlikely(!((lookup_hit_mask >> j) & 0x1))) {
                                handle_error(&task->base, mbufs[j], TUNNEL_DIR_DECAP);
				out[j] = OUT_DISCARD;
                                continue;
                        }
                        out[j] = handle_ipv6_decap(task, mbufs[j], entries[j]);
                }
        }

	return task->base.base.tx_pkt(tbase, mbufs, n_pkts, out);
}

static int handle_ipv6_encap_bulk(struct task_base* tbase, struct rte_mbuf** mbufs, const uint16_t n_pkts)
{
	struct task_ipv6_encap* task = (struct task_ipv6_encap *)tbase;
        uint64_t pkts_mask = RTE_LEN2MASK(n_pkts, uint64_t);
        struct ipv6_tun_dest* entries[64];
        uint64_t lookup_hit_mask;
	uint8_t out[MAX_PKT_BURST];
        uint16_t n_kept = 0;

	prefetch_first(mbufs, n_pkts);

        extract_key_encap_bulk(&task->base, mbufs, n_pkts);
        prox_rte_table_key8_lookup(task->base.lookup_table, task->base.fake_packets, pkts_mask, &lookup_hit_mask, (void**)entries);

        if (likely(lookup_hit_mask == pkts_mask)) {
                for (uint16_t j = 0; j < n_pkts; ++j) {
                        out[j] = handle_ipv6_encap(task, mbufs[j], entries[j]);
                }
        }
        else {
                for (uint16_t j = 0; j < n_pkts; ++j) {
                        if (unlikely(!((lookup_hit_mask >> j) & 0x1))) {
                                handle_error(&task->base, mbufs[j], TUNNEL_DIR_ENCAP);
				out[j] = OUT_DISCARD;
                                continue;
                        }
                        out[j] = handle_ipv6_encap(task, mbufs[j], entries[j]);
                }
        }

	return task->base.base.tx_pkt(tbase, mbufs, n_pkts, out);
}

static inline uint8_t handle_ipv6_decap(struct task_ipv6_decap* ptask, struct rte_mbuf* rx_mbuf, __attribute__((unused)) struct ipv6_tun_dest* tun_dest)
{
	struct ether_hdr* peth = rte_pktmbuf_mtod(rx_mbuf, struct ether_hdr *);
	struct task_ipv6_tun_base* tun_base = (struct task_ipv6_tun_base*)ptask;
	struct ipv4_hdr* pip4 = NULL;

	if (unlikely(peth->ether_type != ETYPE_IPv6)) {
		plog_warn("Received non IPv6 packet on ipv6 tunnel port\n");
		// Drop packet
		return OUT_DISCARD;
	}

	struct ipv6_hdr* pip6 = (struct ipv6_hdr *)(peth + 1);
	int ipv6_hdr_len = sizeof(struct ipv6_hdr);

	// TODO - Skip over any IPv6 Extension Header:
	//      If pip6->next_header is in (0, 43, 44, 50, 51, 60, 135), skip ahead pip->hdr_ext_len
	//      bytes and repeat. Increase ipv6_hdr_len with as much, each time.

	if (unlikely(pip6->proto != IPPROTO_IPIP)) {
		plog_warn("Received non IPv4 content within IPv6 tunnel packet\n");
		// Drop packet
		return OUT_DISCARD;
	}

        // Discard IPv6 encapsulation
        rte_pktmbuf_adj(rx_mbuf, ipv6_hdr_len);
        peth = rte_pktmbuf_mtod(rx_mbuf, struct ether_hdr *);
	pip4 = (struct ipv4_hdr *)(peth + 1);

        // Restore Ethernet header
        ether_addr_copy(&ptask->base.src_mac, &peth->s_addr);
        ether_addr_copy(&ptask->dst_mac, &peth->d_addr);
        peth->ether_type = ETYPE_IPv4;

#ifdef GEN_DECAP_IPV6_TO_IPV4_CKSUM
        // generate an IP checksum for ipv4 packet
        if (tun_base->runtime_flags & TASK_TX_CRC) {
                prox_ip_cksum(rx_mbuf, pip4, sizeof(struct ether_hdr), sizeof(struct ipv4_hdr), ptask->base.offload_crc);
        }
#endif

	return 0;
}

static inline uint8_t handle_ipv6_encap(struct task_ipv6_encap* ptask, struct rte_mbuf* rx_mbuf, __attribute__((unused)) struct ipv6_tun_dest* tun_dest)
{
        //plog_info("Found tunnel endpoint:"IPv6_BYTES_FMT" ("MAC_BYTES_FMT")\n", IPv6_BYTES(tun_dest->dst_addr), MAC_BYTES(tun_dest->dst_mac.addr_bytes));

	struct ether_hdr* peth = (struct ether_hdr *)(rte_pktmbuf_mtod(rx_mbuf, struct ether_hdr *));
	struct ipv4_hdr* pip4 = (struct ipv4_hdr *)(peth + 1);
	uint16_t ipv4_length = rte_be_to_cpu_16(pip4->total_length);
	struct task_ipv6_tun_base* tun_base = (struct task_ipv6_tun_base*)ptask;

	if (unlikely((pip4->version_ihl >> 4) != 4)) {
		plog_warn("Received non IPv4 packet at ipv6 tunnel input\n");
		// Drop packet
		return OUT_DISCARD;
	}

	if (pip4->time_to_live) {
		pip4->time_to_live--;
	}
	else {
		plog_info("TTL = 0 => Dropping\n");
		return OUT_DISCARD;
	}
	pip4->hdr_checksum = 0;

	// Remove padding if any (we don't want to encapsulate garbage at end of IPv4 packet)
	int padding = rte_pktmbuf_pkt_len(rx_mbuf) - (ipv4_length + sizeof(struct ether_hdr));
	if (unlikely(padding > 0)) {
	        rte_pktmbuf_trim(rx_mbuf, padding);
	}

	// Encapsulate
	const int extra_space = sizeof(struct ipv6_hdr);
	peth = (struct ether_hdr *)rte_pktmbuf_prepend(rx_mbuf, extra_space);

	// Ethernet Header
	ether_addr_copy(&ptask->base.src_mac, &peth->s_addr);
	ether_addr_copy(&tun_dest->dst_mac, &peth->d_addr);
	peth->ether_type = ETYPE_IPv6;

	// Set up IPv6 Header
	struct ipv6_hdr* pip6 = (struct ipv6_hdr *)(peth + 1);
	pip6->vtc_flow = rte_cpu_to_be_32(IPv6_VERSION << 28);
	pip6->proto = IPPROTO_IPIP;
	pip6->payload_len = rte_cpu_to_be_16(ipv4_length);
	pip6->hop_limits = ptask->tunnel_hop_limit;
	rte_memcpy(pip6->dst_addr, &tun_dest->dst_addr, sizeof(pip6->dst_addr));
	rte_memcpy(pip6->src_addr, &ptask->local_endpoint_addr, sizeof(pip6->src_addr));

	if (tun_base->runtime_flags & TASK_TX_CRC) {
	// We modified the TTL in the IPv4 header, hence have to recompute the IPv4 checksum
#define TUNNEL_L2_LEN (sizeof(struct ether_hdr) + sizeof(struct ipv6_hdr))
		prox_ip_cksum(rx_mbuf, pip4, TUNNEL_L2_LEN, sizeof(struct ipv4_hdr), ptask->base.offload_crc);
	}
	return 0;
}
