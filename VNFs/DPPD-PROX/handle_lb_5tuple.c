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
#include <rte_ether.h>
#include <rte_memcpy.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_version.h>
#include <rte_byteorder.h>

#include "handle_lb_5tuple.h"
#include "prox_malloc.h"
#include "prox_lua.h"
#include "prox_lua_types.h"
#include "etypes.h"
#include "task_init.h"
#include "task_base.h"
#include "lconf.h"
#include "log.h"
#include "prefetch.h"
#include "prox_globals.h"
#include "defines.h"
#include "quit.h"

#define BYTE_VALUE_MAX 256
#define BIT_8_TO_10    0x0000e000         // for protocol field
#define BIT_27_TO_31   0x1f000000         // for IP addresses
#define BIT_12_TO_16_27_TO_31 0x1f001f00  // for ports

#define HASH_MAX_SIZE 4*8*1024*1024

struct task_lb_5tuple {
	struct task_base base;
	uint32_t runtime_flags;
	struct rte_hash *lookup_hash;
	uint8_t out_if[HASH_MAX_SIZE] __rte_cache_aligned;
};

static __m128i mask0;
static inline uint8_t get_ipv4_dst_port(struct task_lb_5tuple *task, void *ipv4_hdr, uint8_t portid, struct rte_hash * ipv4_l3fwd_lookup_struct)
{
	int ret = 0;
	union ipv4_5tuple_host key;

	ipv4_hdr = (uint8_t *)ipv4_hdr + offsetof(struct ipv4_hdr, time_to_live);
	__m128i data = _mm_loadu_si128((__m128i*)(ipv4_hdr));
	/* Get 5 tuple: dst port, src port, dst IP address, src IP address and protocol */
        key.xmm = _mm_and_si128(data, mask0);

	/* Get 5 tuple: dst port, src port, dst IP address, src IP address and protocol */
	/*
 	rte_mov16(&key.pad0, ipv4_hdr);
	key.pad0 = 0;
	key.pad1 = 0;
	*/
	/* Find destination port */
	ret = rte_hash_lookup(ipv4_l3fwd_lookup_struct, (const void *)&key);
	return (uint8_t)((ret < 0)? portid : task->out_if[ret]);
}

static inline uint8_t handle_lb_5tuple(struct task_lb_5tuple *task, struct rte_mbuf *mbuf)
{
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;

	eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

	switch (eth_hdr->ether_type) {
	case ETYPE_IPv4:
		/* Handle IPv4 headers.*/
		ipv4_hdr = (struct ipv4_hdr *) (eth_hdr + 1);
		return get_ipv4_dst_port(task, ipv4_hdr, OUT_DISCARD, task->lookup_hash);
	default:
		return OUT_DISCARD;
	}
}

static int handle_lb_5tuple_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_lb_5tuple *task = (struct task_lb_5tuple *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint16_t j;

	prefetch_first(mbufs, n_pkts);

	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef PROX_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		out[j] = handle_lb_5tuple(task, mbufs[j]);
	}
#ifdef PROX_PREFETCH_OFFSET
	PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		out[j] = handle_lb_5tuple(task, mbufs[j]);
	}
#endif

	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static void init_task_lb_5tuple(struct task_base *tbase, struct task_args *targ)
{
	struct task_lb_5tuple *task = (struct task_lb_5tuple *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

        mask0 = _mm_set_epi32(BIT_12_TO_16_27_TO_31, BIT_27_TO_31, BIT_27_TO_31, BIT_8_TO_10);
	uint8_t *out_table = task->out_if;
	int ret = lua_to_tuples(prox_lua(), GLOBAL, "tuples", socket_id, &task->lookup_hash, &out_table);
	PROX_PANIC(ret, "Failed to read tuples from config\n");

	task->runtime_flags = targ->flags;
}

static struct task_init task_init_lb_5tuple = {
	.mode_str = "lb5tuple",
	.init = init_task_lb_5tuple,
	.handle = handle_lb_5tuple_bulk,
	.flag_features = TASK_FEATURE_NEVER_DISCARDS | TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS,
	.size = sizeof(struct task_lb_5tuple),
};

__attribute__((constructor)) static void reg_task_lb_5tuple(void)
{
	reg_task(&task_init_lb_5tuple);
}
