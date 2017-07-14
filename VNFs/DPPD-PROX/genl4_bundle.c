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

#include <string.h>
#include <rte_hash.h>
#include <rte_memory.h>
#include <rte_hash_crc.h>
#include <rte_cycles.h>
#include <rte_version.h>

#include "prox_malloc.h"
#include "prox_assert.h"
#include "cdf.h"
#include "defines.h"
#include "genl4_bundle.h"
#include "log.h"
#include "pkt_parser.h"
#include "prox_lua_types.h"

#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE
#define RTE_CACHE_LINE_ROUNDUP CACHE_LINE_ROUNDUP
#endif

/* zero on success */
int bundle_ctx_pool_create(const char *name, uint32_t n_elems, struct bundle_ctx_pool *ret, uint32_t *occur, uint32_t n_occur, struct bundle_cfg *cfg, int socket_id)
{
	size_t memsize;
	uint8_t *mem;

	const struct rte_hash_parameters params = {
		.name = name,
		.entries = rte_align32pow2(n_elems) * 8,
		//.bucket_entries = 8,
		.key_len = sizeof(struct pkt_tuple),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = socket_id,
	};

	ret->hash = rte_hash_create(&params);
	if (NULL == ret->hash)
		return -1;

	uint32_t rand_pool_size = 0, tot_occur = 0;

	if (occur) {
		for (uint32_t i = 0; i < n_occur; ++i) {
			tot_occur += occur[i];
		}

		rand_pool_size = (n_elems + (tot_occur - 1))/tot_occur*tot_occur;
	}

	memsize = 0;
	memsize += RTE_CACHE_LINE_ROUNDUP(params.entries * sizeof(ret->hash_entries[0]));
	memsize += RTE_CACHE_LINE_ROUNDUP(n_elems * sizeof(ret->free_bundles[0]));
	memsize += RTE_CACHE_LINE_ROUNDUP(n_elems * sizeof(ret->bundles[0]));
	if (occur)
		memsize += RTE_CACHE_LINE_ROUNDUP(rand_pool_size * sizeof(ret->occur));
	mem = prox_zmalloc(memsize, socket_id);
	if (NULL == mem)
		return -1;

	ret->hash_entries = (struct bundle_ctx **) mem;
	mem += RTE_CACHE_LINE_ROUNDUP(params.entries * sizeof(ret->hash_entries[0]));
	ret->free_bundles = (struct bundle_ctx **) mem;
	mem += RTE_CACHE_LINE_ROUNDUP(n_elems * sizeof(ret->free_bundles[0]));
	if (occur) {
		ret->occur = (uint32_t *)mem;
		mem += RTE_CACHE_LINE_ROUNDUP(rand_pool_size * sizeof(ret->occur));

		ret->seed = rte_rdtsc();

		size_t cur_occur = 0;
		size_t j = 0;

		for (uint32_t i = 0; i < rand_pool_size; ++i) {
			while (j >= occur[cur_occur]) {
				cur_occur++;
				if (cur_occur == n_occur)
					cur_occur = 0;
				j = 0;
			}
			j++;
			ret->occur[i] = cur_occur;
		}
		ret->n_occur = rand_pool_size;
	}
	ret->bundles = (struct bundle_ctx *) mem;

	ret->bundle_cfg = cfg;
	for (unsigned i = 0; i < n_elems; ++i) {
		ret->free_bundles[i] = &ret->bundles[i];
	}
	ret->n_free_bundles = n_elems;
	ret->tot_bundles    = n_elems;

	return 0;
}

struct bundle_ctx *bundle_ctx_pool_get(struct bundle_ctx_pool *p)
{
	if (p->n_free_bundles > 0)
		return p->free_bundles[--p->n_free_bundles];
	return NULL;
}

static struct bundle_cfg *bundle_ctx_get_cfg(struct bundle_ctx_pool *p)
{
	uint32_t rand = 0;

	/* get rand in [0, RAND_MAX rounded down] */
	do {
		rand = rand_r(&p->seed);
	} while (rand >= RAND_MAX/p->n_occur*p->n_occur);

	rand /= RAND_MAX/p->n_occur;

	PROX_ASSERT(p->n_occur);
	PROX_ASSERT(rand < p->n_occur);

	uint32_t r = p->occur[rand];
	p->occur[rand] = p->occur[--p->n_occur];

	return &p->bundle_cfg[r];
}

static void bundle_ctx_put_cfg(struct bundle_ctx_pool *p, const struct bundle_cfg *cfg)
{
	if (p->occur) {
		uint32_t r = cfg - p->bundle_cfg;
		p->occur[p->n_occur++] = r;
	}
}

struct bundle_ctx *bundle_ctx_pool_get_w_cfg(struct bundle_ctx_pool *p)
{
	if (p->n_free_bundles > 0) {
		struct bundle_ctx *ret = p->free_bundles[--p->n_free_bundles];
		ret->cfg = bundle_ctx_get_cfg(p);
		return ret;
	}

	return NULL;
}

void bundle_ctx_pool_put(struct bundle_ctx_pool *p, struct bundle_ctx *bundle)
{
	bundle_ctx_put_cfg(p, bundle->cfg);
	p->free_bundles[p->n_free_bundles++] = bundle;
}

static void bundle_cleanup(struct bundle_ctx *bundle)
{
	if (bundle->heap_ref.elem != NULL) {
		heap_del(bundle->heap, &bundle->heap_ref);
	}
}

static int bundle_iterate_streams(struct bundle_ctx *bundle, struct bundle_ctx_pool *pool, unsigned *seed, struct l4_stats *l4_stats)
{
	enum l4gen_peer peer;
	int ret = 0, old;

	while (bundle->ctx.stream_cfg->is_ended(&bundle->ctx)) {

		if (bundle->ctx.stream_cfg->proto == IPPROTO_TCP) {
			if (bundle->ctx.retransmits == 0)
				l4_stats->tcp_finished_no_retransmit++;
			else
				l4_stats->tcp_finished_retransmit++;
		}
		else
			l4_stats->udp_finished++;

		if (bundle->stream_idx + 1 != bundle->cfg->n_stream_cfgs) {
			ret = 1;
			bundle->stream_idx++;

			stream_ctx_reset_move(&bundle->ctx, bundle->cfg->stream_cfgs[bundle->stream_idx]);

			/* Update tuple */
			old = rte_hash_del_key(pool->hash, &bundle->tuple);
			if (old < 0) {
				plogx_err("Failed to delete key while trying to change tuple: %d (%s)\n",old, strerror(-old));
			}
			plogx_dbg("Moving to stream with idx %d\n", bundle->stream_idx);

			/* In case there are multiple streams, clients
			   randomized but ports fixed, it is still
			   possible to hit an infinite loop here. The
			   situations is hit if a client:port is
			   connected to a server:port in one of the
			   streams while client:port is regenerated
			   for the first stream. There is no conflict
			   yet since the server:port is
			   different. Note that this is bug since a
			   client:port can only have one open
			   connection. */
			int retries = 0;
			do {
				bundle_create_tuple(&bundle->tuple, &bundle->cfg->clients, bundle->ctx.stream_cfg, 0, seed);

				ret = rte_hash_lookup(pool->hash, (const void *)&bundle->tuple);
				if (++retries == 1000) {
					plogx_warn("Already tried 1K times\n");
					plogx_warn("Going from %d to %d\n", bundle->stream_idx -1, bundle->stream_idx);
				}
			} while (ret >= 0);

			ret = rte_hash_add_key(pool->hash, &bundle->tuple);
			if (ret < 0) {
				plogx_err("Failed to add key while moving to next stream!\n");
				return -1;
			}
			pool->hash_entries[ret] = pool->hash_entries[old];

			if (bundle->ctx.stream_cfg->proto == IPPROTO_TCP)
				l4_stats->tcp_created++;
			else
				l4_stats->udp_created++;
		}
		else {
			int a = rte_hash_del_key(pool->hash, &bundle->tuple);
			PROX_PANIC(a < 0, "Del failed (%d)! during finished all bundle (%d)\n", a, bundle->cfg->n_stream_cfgs);
			bundle_cleanup(bundle);
			bundle_ctx_pool_put(pool, bundle);

			return -1;
		}
	}
	return ret;
}

void bundle_create_tuple(struct pkt_tuple *tp, const struct host_set *clients, const struct stream_cfg *stream_cfg, int rnd_ip, unsigned  *seed)
{
	tp->dst_port = clients->port;
	tp->dst_port &= ~clients->port_mask;
	tp->dst_port |= rand_r(seed) & clients->port_mask;

	if (rnd_ip) {
		tp->dst_addr = clients->ip;
		tp->dst_addr &= ~clients->ip_mask;
		tp->dst_addr |= rand_r(seed) & clients->ip_mask;
	}

	tp->src_addr = stream_cfg->servers.ip;
	tp->src_port = stream_cfg->servers.port;
	plogx_dbg("bundle_create_tuple() with proto = %x, %d\n", stream_cfg->proto, rnd_ip);
	tp->proto_id = stream_cfg->proto;

	tp->l2_types[0] = 0x0008;
}

void bundle_init_w_cfg(struct bundle_ctx *bundle, const struct bundle_cfg *cfg, struct heap *heap, enum l4gen_peer peer, unsigned *seed)
{
	bundle->cfg = cfg;
	bundle_init(bundle, heap, peer, seed);
}

void bundle_init(struct bundle_ctx *bundle, struct heap *heap, enum l4gen_peer peer, unsigned *seed)
{
	bundle->heap_ref.elem = NULL;
	bundle->heap = heap;
	memset(&bundle->ctx, 0, sizeof(bundle->ctx));
	// TODO; assert that there is at least one stream
	bundle->stream_idx = 0;

	stream_ctx_init(&bundle->ctx, peer, bundle->cfg->stream_cfgs[bundle->stream_idx], &bundle->tuple);
	bundle_create_tuple(&bundle->tuple, &bundle->cfg->clients, bundle->ctx.stream_cfg, peer == PEER_CLIENT, seed);
}

void bundle_expire(struct bundle_ctx *bundle, struct bundle_ctx_pool *pool, struct l4_stats *l4_stats)
{
	struct pkt_tuple *pt = &bundle->tuple;

	plogx_dbg("Client = "IPv4_BYTES_FMT":%d, Server = "IPv4_BYTES_FMT":%d\n",
		  IPv4_BYTES(((uint8_t*)&pt->dst_addr)),
		  rte_bswap16(pt->dst_port),
		  IPv4_BYTES(((uint8_t*)&pt->src_addr)),
		  rte_bswap16(pt->src_port));

	int a = rte_hash_del_key(pool->hash, bundle);
	if (a < 0) {
		plogx_err("Del failed with error %d: '%s'\n", a, strerror(-a));
		plogx_err("ended = %d\n", bundle->ctx.flags & STREAM_CTX_F_TCP_ENDED);
	}

	if (bundle->ctx.stream_cfg->proto == IPPROTO_TCP)
		l4_stats->tcp_expired++;
	else
		l4_stats->udp_expired++;

	bundle_cleanup(bundle);
	bundle_ctx_pool_put(pool, bundle);
}

int bundle_proc_data(struct bundle_ctx *bundle, struct rte_mbuf *mbuf, struct l4_meta *l4_meta, struct bundle_ctx_pool *pool, unsigned *seed, struct l4_stats *l4_stats)
{
	int ret;
	uint64_t next_tsc;

	if (bundle->heap_ref.elem != NULL) {
		heap_del(bundle->heap, &bundle->heap_ref);
	}

	if (bundle_iterate_streams(bundle, pool, seed, l4_stats) < 0)
		return -1;

	uint32_t retx_before = bundle->ctx.retransmits;
	next_tsc = UINT64_MAX;
	ret = bundle->ctx.stream_cfg->proc(&bundle->ctx, mbuf, l4_meta, &next_tsc);

	if (bundle->ctx.flags & STREAM_CTX_F_EXPIRED) {
		bundle_expire(bundle, pool, l4_stats);
		return -1;
	}
	else if (next_tsc != UINT64_MAX) {
		heap_add(bundle->heap, &bundle->heap_ref, rte_rdtsc() + next_tsc);
	}
	l4_stats->tcp_retransmits += bundle->ctx.retransmits - retx_before;

	if (bundle_iterate_streams(bundle, pool, seed, l4_stats) > 0) {
		if (bundle->heap_ref.elem != NULL) {
			heap_del(bundle->heap, &bundle->heap_ref);
		}
		heap_add(bundle->heap, &bundle->heap_ref, rte_rdtsc());
	}

	return ret;
}

uint32_t bundle_cfg_length(struct bundle_cfg *cfg)
{
	uint32_t ret = 0;

	for (uint32_t i = 0; i < cfg->n_stream_cfgs; ++i) {
		ret += cfg->stream_cfgs[i]->n_bytes;
	}

	return ret;
}

uint32_t bundle_cfg_max_n_segments(struct bundle_cfg *cfg)
{
	uint32_t ret = 0;
	uint32_t cur;

	for (uint32_t i = 0; i < cfg->n_stream_cfgs; ++i) {
		cur = stream_cfg_max_n_segments(cfg->stream_cfgs[i]);
		ret = ret > cur? ret: cur;
	}

	return ret;
}
