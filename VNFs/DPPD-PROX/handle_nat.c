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

struct task_nat {
	struct task_base base;
	struct rte_hash  *hash;
	uint32_t         *entries;
	int              use_src;
	int              offload_crc;
};

struct pkt_eth_ipv4 {
	struct ether_hdr ether_hdr;
	struct ipv4_hdr  ipv4_hdr;
} __attribute__((packed));

static int handle_nat(struct task_nat *task, struct rte_mbuf *mbuf)
{
	uint32_t *ip_addr;
	struct pkt_eth_ipv4 *pkt = rte_pktmbuf_mtod(mbuf, struct pkt_eth_ipv4 *);
	int ret;

	/* Currently, only support eth/ipv4 packets */
	if (pkt->ether_hdr.ether_type != ETYPE_IPv4)
		return OUT_DISCARD;
	if (task->use_src)
		ip_addr = &(pkt->ipv4_hdr.src_addr);
	else
		ip_addr = &(pkt->ipv4_hdr.dst_addr);

	ret = rte_hash_lookup(task->hash, ip_addr);

	/* Drop all packets for which no translation has been
	   configured. */
	if (ret < 0)
		return OUT_DISCARD;

        *ip_addr = task->entries[ret];
	prox_ip_udp_cksum(mbuf, &pkt->ipv4_hdr, sizeof(struct ether_hdr), sizeof(struct ipv4_hdr), task->offload_crc);
	return 0;
}

static int handle_nat_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
        struct task_nat *task = (struct task_nat *)tbase;
        uint8_t out[MAX_PKT_BURST];
        uint16_t j;
        prefetch_first(mbufs, n_pkts);
        for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef PROX_PREFETCH_OFFSET
                PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
                PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
                out[j] = handle_nat(task, mbufs[j]);
        }
#ifdef PROX_PREFETCH_OFFSET
        PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
        for (; j < n_pkts; ++j) {
                out[j] = handle_nat(task, mbufs[j]);
        }
#endif
        return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static int lua_to_hash_nat(struct lua_State *L, enum lua_place from, const char *name,
			   uint8_t socket, struct rte_hash **hash, uint32_t **entries)
{
	struct rte_hash *ret_hash;
	uint32_t *ret_entries;
	uint32_t n_entries;
	uint32_t ip_from, ip_to;
	int ret, pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	lua_len(L, -1);
	n_entries = lua_tointeger(L, -1);
	lua_pop(L, 1);

	PROX_PANIC(n_entries == 0, "No entries for NAT\n");

	static char hash_name[30] = "000_hash_nat_table";

	const struct rte_hash_parameters hash_params = {
		.name = hash_name,
		.entries = n_entries * 4,
		.key_len = sizeof(ip_from),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
	};

	ret_hash = rte_hash_create(&hash_params);
	PROX_PANIC(ret_hash == NULL, "Failed to set up hash table for NAT\n");
	name++;
	ret_entries = prox_zmalloc(n_entries * sizeof(ip_to), socket);
	PROX_PANIC(ret_entries == NULL, "Failed to allocate memory for NAT %u entries\n", n_entries);

	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (lua_to_ip(L, TABLE, "from", &ip_from) ||
		    lua_to_ip(L, TABLE, "to", &ip_to))
			return -1;

		ip_from = rte_bswap32(ip_from);
		ip_to = rte_bswap32(ip_to);

		ret = rte_hash_lookup(ret_hash, (const void *)&ip_from);
		PROX_PANIC(ret >= 0, "Key %x already exists in NAT hash table\n", ip_from);

		ret = rte_hash_add_key(ret_hash, (const void *)&ip_from);

		PROX_PANIC(ret < 0, "Failed to add Key %x to NAT hash table\n", ip_from);
		ret_entries[ret] = ip_to;
		lua_pop(L, 1);
	}

	lua_pop(L, pop);

	*hash = ret_hash;
	*entries = ret_entries;
	return 0;
}

static void init_task_nat(struct task_base *tbase, struct task_args *targ)
{
	struct task_nat *task = (struct task_nat *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	int ret;

	/* Use destination IP by default. */
	task->use_src = targ->use_src;

	PROX_PANIC(!strcmp(targ->nat_table, ""), "No nat table specified\n");
	ret = lua_to_hash_nat(prox_lua(), GLOBAL, targ->nat_table, socket_id, &task->hash, &task->entries);
	PROX_PANIC(ret != 0, "Failed to load NAT table from lua:\n%s\n", get_lua_to_errors());
	struct prox_port_cfg *port = find_reachable_port(targ);
	if (port) {
		task->offload_crc = port->requested_tx_offload & (DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM);
	}

}

/* Basic static nat. */
static struct task_init task_init_nat = {
	.mode_str = "nat",
	.init = init_task_nat,
	.handle = handle_nat_bulk,
#ifdef SOFT_CRC
	.flag_features = TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS,
#else
	.flag_features = 0,
#endif
	.size = sizeof(struct task_nat),
};

__attribute__((constructor)) static void reg_task_nat(void)
{
	reg_task(&task_init_nat);
}
