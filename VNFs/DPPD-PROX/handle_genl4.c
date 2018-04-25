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
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <rte_cycles.h>
#include <rte_version.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>

#include "prox_lua.h"
#include "prox_lua_types.h"
#include "prox_malloc.h"
#include "file_utils.h"
#include "hash_set.h"
#include "prox_assert.h"
#include "prox_args.h"
#include "defines.h"
#include "pkt_parser.h"
#include "handle_lat.h"
#include "task_init.h"
#include "task_base.h"
#include "prox_port_cfg.h"
#include "lconf.h"
#include "log.h"
#include "quit.h"
#include "heap.h"
#include "mbuf_utils.h"
#include "genl4_bundle.h"
#include "genl4_stream_udp.h"
#include "genl4_stream_tcp.h"
#include "cdf.h"
#include "fqueue.h"
#include "token_time.h"
#include "commands.h"
#include "prox_shared.h"

#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE
#endif

struct new_tuple {
	uint32_t dst_addr;
	uint8_t proto_id;
	uint16_t dst_port;
	uint16_t l2_types[4];
} __attribute__((packed));

enum handle_state {HANDLE_QUEUED, HANDLE_SCHEDULED};

struct task_gen_server {
	struct task_base base;
	struct l4_stats l4_stats;
	struct rte_mempool *mempool;
	struct rte_hash *listen_hash;
	/* Listening bundles contain only 1 part since the state of a
	   multi_part comm is kept mostly at the client side*/
	struct bundle_cfg     **listen_entries;
	struct bundle_ctx_pool bundle_ctx_pool;
	struct bundle_cfg *bundle_cfgs; /* Loaded configurations */
	struct token_time token_time;
	enum handle_state handle_state;
	struct heap *heap;
	struct fqueue *fqueue;
	struct rte_mbuf *cur_mbufs[MAX_PKT_BURST];
	uint32_t cur_mbufs_beg;
	uint32_t cur_mbufs_end;
	uint32_t cancelled;
	uint8_t  out_saved;
	struct rte_mbuf *mbuf_saved;
	uint64_t last_tsc;
	unsigned seed;
	/* Handle scheduled events */
	struct rte_mbuf *new_mbufs[MAX_PKT_BURST];
	uint32_t n_new_mbufs;
};

struct task_gen_client {
	struct task_base base;
	struct l4_stats l4_stats;
	struct rte_mempool *mempool;
	struct bundle_ctx_pool bundle_ctx_pool;
	struct bundle_cfg *bundle_cfgs; /* Loaded configurations */
	struct token_time token_time;
	/* Create new connections and handle scheduled events */
	struct rte_mbuf *new_mbufs[MAX_PKT_BURST];
	uint32_t new_conn_cost;
	uint32_t new_conn_tokens;
	uint64_t new_conn_last_tsc;
	uint32_t n_new_mbufs;
	uint64_t last_tsc;
	struct cdf *cdf;
	unsigned seed;
	struct heap *heap;
};

static int refill_mbufs(uint32_t *n_new_mbufs, struct rte_mempool *mempool, struct rte_mbuf **mbufs)
{
	if (*n_new_mbufs == MAX_PKT_BURST)
		return 0;

	if (rte_mempool_get_bulk(mempool, (void **)mbufs, MAX_PKT_BURST - *n_new_mbufs) < 0) {
		plogx_err("4Mempool alloc failed for %d mbufs\n", MAX_PKT_BURST - *n_new_mbufs);
		return -1;
	}

	for (uint32_t i = 0; i < MAX_PKT_BURST - *n_new_mbufs; ++i) {
		init_mbuf_seg(mbufs[i]);
	}

	*n_new_mbufs = MAX_PKT_BURST;

	return 0;
}

static const struct bundle_cfg *server_accept(struct task_gen_server *task, struct new_tuple *nt)
{
	int ret = rte_hash_lookup(task->listen_hash, nt);

	if (ret < 0)
		return NULL;
	else
		return task->listen_entries[ret];
}

static int handle_gen_bulk_client(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_gen_client *task = (struct task_gen_client *)tbase;
	uint8_t out[MAX_PKT_BURST] = {0};
	struct bundle_ctx *conn;
	int ret;

	if (n_pkts) {
		for (int i = 0; i < n_pkts; ++i) {
			struct pkt_tuple pt;
			struct l4_meta l4_meta;

			if (parse_pkt(mbufs[i], &pt, &l4_meta)) {
				plogdx_err(mbufs[i], "Parsing failed\n");
				out[i] = OUT_DISCARD;
				continue;
			}

			ret = rte_hash_lookup(task->bundle_ctx_pool.hash, (const void *)&pt);

			if (ret < 0) {
				plogx_dbg("Client: packet RX that does not belong to connection:"
					  "Client = "IPv4_BYTES_FMT":%d, Server = "IPv4_BYTES_FMT":%d\n",
					  IPv4_BYTES(((uint8_t*)&pt.dst_addr)),
					  rte_bswap16(pt.dst_port),
					  IPv4_BYTES(((uint8_t*)&pt.src_addr)),
					  rte_bswap16(pt.src_port));

				plogdx_dbg(mbufs[i], NULL);

				if (pt.proto_id == IPPROTO_TCP) {
					stream_tcp_create_rst(mbufs[i], &l4_meta, &pt);
					out[i] = 0;
					continue;
				}
				else {
					out[i] = OUT_DISCARD;
					continue;
				}
			}

			conn = task->bundle_ctx_pool.hash_entries[ret];
			ret = bundle_proc_data(conn, mbufs[i], &l4_meta, &task->bundle_ctx_pool, &task->seed, &task->l4_stats);
			out[i] = ret == 0? 0: OUT_HANDLED;
		}
		task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
	}

	/* If there is at least one callback to handle, handle at most MAX_PKT_BURST */
	if (heap_top_is_lower(task->heap, rte_rdtsc())) {
		if (0 != refill_mbufs(&task->n_new_mbufs, task->mempool, task->new_mbufs))
			return 0;

		uint16_t n_called_back = 0;
		while (heap_top_is_lower(task->heap, rte_rdtsc()) && n_called_back < MAX_PKT_BURST) {
			conn = BUNDLE_CTX_UPCAST(heap_pop(task->heap));

			/* handle packet TX (retransmit or delayed transmit) */
			ret = bundle_proc_data(conn, task->new_mbufs[n_called_back], NULL, &task->bundle_ctx_pool, &task->seed, &task->l4_stats);

			if (ret == 0) {
				out[n_called_back] = 0;
				n_called_back++;
			}
		}
		plogx_dbg("During callback, will send %d packets\n", n_called_back);

		task->base.tx_pkt(&task->base, task->new_mbufs, n_called_back, out);
		task->n_new_mbufs -= n_called_back;
	}

	uint32_t n_new = task->bundle_ctx_pool.n_free_bundles;
	n_new = n_new > MAX_PKT_BURST? MAX_PKT_BURST : n_new;

	uint64_t diff = (rte_rdtsc() - task->new_conn_last_tsc)/task->new_conn_cost;
	task->new_conn_last_tsc += diff * task->new_conn_cost;
	task->new_conn_tokens += diff;

	if (task->new_conn_tokens > 16)
		task->new_conn_tokens = 16;
	if (n_new > task->new_conn_tokens)
		n_new = task->new_conn_tokens;
	task->new_conn_tokens -= n_new;
	if (n_new == 0)
		return 0;

	if (0 != refill_mbufs(&task->n_new_mbufs, task->mempool, task->new_mbufs))
		return 0;

	for (uint32_t i = 0; i < n_new; ++i) {
		struct bundle_ctx *bundle_ctx = bundle_ctx_pool_get_w_cfg(&task->bundle_ctx_pool);
		PROX_ASSERT(bundle_ctx);

		struct pkt_tuple *pt = &bundle_ctx->tuple;

		int n_retries = 0;
		do {
			/* Note that the actual packet sent will
			   contain swapped addresses and ports
			   (i.e. pkt.src <=> tuple.dst). The incoming
			   packet will match this struct. */
			bundle_init(bundle_ctx, task->heap, PEER_CLIENT, &task->seed);

			ret = rte_hash_lookup(task->bundle_ctx_pool.hash, (const void *)pt);
			if (ret >= 0) {
				if (n_retries++ == 1000) {
					plogx_err("Already tried 1K times\n");
				}
			}
		} while (ret >= 0);

		ret = rte_hash_add_key(task->bundle_ctx_pool.hash, (const void *)pt);

		if (ret < 0) {
			plogx_err("Failed to add key ret = %d, n_free = %d\n", ret, task->bundle_ctx_pool.n_free_bundles);
			bundle_ctx_pool_put(&task->bundle_ctx_pool, bundle_ctx);

			pkt_tuple_debug2(pt);
			out[i] = OUT_DISCARD;
			continue;
		}

		task->bundle_ctx_pool.hash_entries[ret] = bundle_ctx;

		if (bundle_ctx->ctx.stream_cfg->proto == IPPROTO_TCP)
			task->l4_stats.tcp_created++;
		else
			task->l4_stats.udp_created++;

		task->l4_stats.bundles_created++;

		ret = bundle_proc_data(bundle_ctx, task->new_mbufs[i], NULL, &task->bundle_ctx_pool, &task->seed, &task->l4_stats);
		out[i] = ret == 0? 0: OUT_HANDLED;
	}

	int ret2 = task->base.tx_pkt(&task->base, task->new_mbufs, n_new, out);
	task->n_new_mbufs -= n_new;
	return ret2;
}

static int handle_gen_queued(struct task_gen_server *task)
{
	uint8_t out[MAX_PKT_BURST];
	struct bundle_ctx *conn;
	struct pkt_tuple pkt_tuple;
	struct l4_meta l4_meta;
	uint16_t j;
	uint16_t cancelled = 0;
	int ret;

	if (task->cur_mbufs_beg == task->cur_mbufs_end) {
		task->cur_mbufs_end = fqueue_get(task->fqueue, task->cur_mbufs, MAX_PKT_BURST);
		task->cur_mbufs_beg = 0;
	}
	uint16_t n_pkts = task->cur_mbufs_end - task->cur_mbufs_beg;
	struct rte_mbuf **mbufs = task->cur_mbufs + task->cur_mbufs_beg;

	j = task->cancelled;
	if (task->cancelled) {
		uint16_t pkt_len = mbuf_wire_size(mbufs[0]);

		if (token_time_take(&task->token_time, pkt_len) != 0)
			return -1;

		out[0] = task->out_saved;
		task->cancelled = 0;
	}

	/* Main proc loop */
	for (; j < n_pkts; ++j) {

		if (parse_pkt(mbufs[j], &pkt_tuple, &l4_meta)) {
			plogdx_err(mbufs[j], "Unknown packet, parsing failed\n");
			out[j] = OUT_DISCARD;
		}

		conn = NULL;
		ret = rte_hash_lookup(task->bundle_ctx_pool.hash, (const void *)&pkt_tuple);

		if (ret >= 0)
			conn = task->bundle_ctx_pool.hash_entries[ret];
		else {
			/* If not part of existing connection, try to create a connection */
			struct new_tuple nt;
			nt.dst_addr = pkt_tuple.dst_addr;
			nt.proto_id = pkt_tuple.proto_id;
			nt.dst_port = pkt_tuple.dst_port;
			rte_memcpy(nt.l2_types, pkt_tuple.l2_types, sizeof(nt.l2_types));
			const struct bundle_cfg *n;

			if (NULL != (n = server_accept(task, &nt))) {
				conn = bundle_ctx_pool_get(&task->bundle_ctx_pool);
				if (!conn) {
					out[j] = OUT_DISCARD;
					plogx_err("No more free bundles to accept new connection\n");
					continue;
				}
				ret = rte_hash_add_key(task->bundle_ctx_pool.hash, (const void *)&pkt_tuple);
				if (ret < 0) {
					out[j] = OUT_DISCARD;
					bundle_ctx_pool_put(&task->bundle_ctx_pool, conn);
					plog_err("Adding key failed while trying to accept connection\n");
					continue;
				}

				task->bundle_ctx_pool.hash_entries[ret] = conn;

				bundle_init_w_cfg(conn, n, task->heap, PEER_SERVER, &task->seed);
				conn->tuple = pkt_tuple;

				if (conn->ctx.stream_cfg->proto == IPPROTO_TCP)
					task->l4_stats.tcp_created++;
				else
					task->l4_stats.udp_created++;
			}
			else {
				plog_err("Packet received for service that does not exist :\n"
					 "source ip = %0x:%u\n"
					 "dst ip    = %0x:%u\n",
					 pkt_tuple.src_addr, rte_bswap16(pkt_tuple.src_port),
					 pkt_tuple.dst_addr, rte_bswap16(pkt_tuple.dst_port));
			}
		}

		/* bundle contains either an active connection or a
		   newly created connection. If it is NULL, then not
		   listening. */
		if (NULL != conn) {
			ret = bundle_proc_data(conn, mbufs[j], &l4_meta, &task->bundle_ctx_pool, &task->seed, &task->l4_stats);

			out[j] = ret == 0? 0: OUT_HANDLED;

			if (ret == 0) {
				uint16_t pkt_len = mbuf_wire_size(mbufs[j]);

				if (token_time_take(&task->token_time, pkt_len) != 0) {
					task->out_saved = out[j];
					task->cancelled = 1;
					task->base.tx_pkt(&task->base, mbufs, j, out);
					task->cur_mbufs_beg += j;
					return -1;
				}
			}
		}
		else {
			pkt_tuple_debug(&pkt_tuple);
			plogd_dbg(mbufs[j], NULL);
			out[j] = OUT_DISCARD;
		}
	}

	task->base.tx_pkt(&task->base, mbufs, j, out);

	task->cur_mbufs_beg += j;
	return 0;
}

static int handle_gen_scheduled(struct task_gen_server *task)
{
	struct bundle_ctx *conn;
	uint8_t out[MAX_PKT_BURST];
	int ret;
	uint16_t n_called_back = 0;

	if (task->cancelled) {
		struct rte_mbuf *mbuf = task->mbuf_saved;

		uint16_t pkt_len = mbuf_wire_size(mbuf);
		if (token_time_take(&task->token_time, pkt_len) == 0) {
			task->cancelled = 0;
			out[0] = 0;
			task->base.tx_pkt(&task->base, &mbuf, 1, out);
		}
		else {
			return -1;
		}
	}

	if (0 != refill_mbufs(&task->n_new_mbufs, task->mempool, task->new_mbufs))
		return -1;

	conn = NULL;
	while (heap_top_is_lower(task->heap, rte_rdtsc()) && n_called_back < task->n_new_mbufs) {
		conn = BUNDLE_CTX_UPCAST(heap_pop(task->heap));

		/* handle packet TX (retransmit or delayed transmit) */
		ret = bundle_proc_data(conn, task->new_mbufs[n_called_back], NULL, &task->bundle_ctx_pool, &task->seed, &task->l4_stats);

		if (ret == 0) {
			struct rte_mbuf *mbuf = task->new_mbufs[n_called_back];
			uint16_t pkt_len = mbuf_wire_size(mbuf);

			if (token_time_take(&task->token_time, pkt_len) == 0) {
				out[n_called_back] = 0;
				n_called_back++;
			}
			else {

				struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
				struct ipv4_hdr *ip = (struct ipv4_hdr*)(eth + 1);
				struct tcp_hdr *tcp = (struct tcp_hdr*)(ip + 1);

				task->out_saved = 0;
				task->cancelled = 1;
				task->mbuf_saved = mbuf;
				task->base.tx_pkt(&task->base, task->new_mbufs, n_called_back, out);
				/* The mbuf that is currently been
				   processed (and which has been
				   cancelled) is saved in
				   task->mbuf_saved. It will be
				   restored as the first mbuf when
				   this function is called again. */
				task->n_new_mbufs -= (n_called_back + 1);
				return -1;
			}
		}
	}

	task->base.tx_pkt(&task->base, task->new_mbufs, n_called_back, out);
	task->n_new_mbufs -= n_called_back;

	return 0;
}

static int handle_gen_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_gen_server *task = (struct task_gen_server *)tbase;
	struct bundle_ctx *conn;
	int ret, ret2 = 0;

	token_time_update(&task->token_time, rte_rdtsc());

	if ((ret = fqueue_put(task->fqueue, mbufs, n_pkts)) != n_pkts) {
		uint8_t out[MAX_PKT_BURST];
		for (uint16_t j = 0; j < n_pkts - ret; ++j)
			out[j] = OUT_DISCARD;

		ret2 = task->base.tx_pkt(&task->base, mbufs + ret, n_pkts - ret, out);
	}
	if (task->handle_state == HANDLE_QUEUED) {
		if (handle_gen_queued(task) == 0) {
			if (handle_gen_scheduled(task) != 0)
				task->handle_state = HANDLE_SCHEDULED;
		}
	}
	else {
		if (handle_gen_scheduled(task) == 0) {
			if (handle_gen_queued(task) != 0)
				task->handle_state = HANDLE_QUEUED;
		}
	}
	return ret2;
}

static int lua_to_host_set(struct lua_State *L, enum lua_place from, const char *name, struct host_set *h)
{
	int pop;
	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1))
		return -1;

	uint32_t port = 0, port_mask = 0;

	if (lua_to_ip(L, TABLE, "ip", &h->ip) || lua_to_int(L, TABLE, "port", &port))
		return -1;

	if (lua_to_int(L, TABLE, "ip_mask", &h->ip_mask))
		h->ip_mask = 0;
	if (lua_to_int(L, TABLE, "port_mask", &port_mask))
		h->port_mask = 0;

	h->port = rte_bswap16(port);
	h->port_mask = rte_bswap16(port_mask);
	h->ip = rte_bswap32(h->ip);
	h->ip_mask = rte_bswap32(h->ip_mask);

	lua_pop(L, pop);
	return 0;
}

static int file_read_cached(const char *file_name, uint8_t **mem, uint32_t beg, uint32_t len, uint32_t socket, struct hash_set *hs)
{
	if (len == 0) {
		*mem = 0;
		return 0;
	}

	uint8_t *data_mem;

	/* Since the configuration can reference the same file from
	   multiple places, use prox_shared infrastructure to detect
	   this and return previously loaded data. */
	char name[256];

	snprintf(name, sizeof(name), "%u-%u:%s", beg, len, file_name);
	*mem = prox_sh_find_socket(socket, name);
	if (*mem)
		return 0;

	/* check if the file has been loaded on the other socket. */
	if (socket == 1 && (data_mem = prox_sh_find_socket(0, name))) {
		uint8_t *data_find = hash_set_find(hs, data_mem, len);
		if (!data_find) {
			data_find = prox_zmalloc(len, socket);
			PROX_PANIC(data_find == NULL, "Failed to allocate memory (%u bytes) to hold header for peer\n", len);

			rte_memcpy(data_find, data_mem, len);
			hash_set_add(hs, data_find, len);
		}
		*mem = data_find;
		prox_sh_add_socket(socket, name, *mem);
		return 0;
	}

	/* It is possible that a file with a different name contains
	   the same data. In that case, search all loaded files and
	   compare the data to reduce memory utilization.*/
	data_mem = malloc(len);
	PROX_PANIC(data_mem == NULL, "Failed to allocate temporary memory to hold data\n");

	if (file_read_content(file_name, data_mem, beg, len)) {
		plog_err("%s\n", file_get_error());
		return -1;
	}

	uint8_t *data_find = hash_set_find(hs, data_mem, len);
	if (!data_find) {
		data_find = prox_zmalloc(len, socket);
		PROX_PANIC(data_find == NULL, "Failed to allocate memory (%u bytes) to hold header for peer\n", len);

		rte_memcpy(data_find, data_mem, len);
		hash_set_add(hs, data_find, len);
	}

	free(data_mem);

	*mem = data_find;
	prox_sh_add_socket(socket, name, *mem);
	return 0;
}

static int lua_to_peer_data(struct lua_State *L, enum lua_place from, const char *name, uint32_t socket, struct peer_data *peer_data, size_t *cl, struct hash_set *hs)
{
	uint32_t hdr_len, hdr_beg, content_len, content_beg;
	char hdr_file[256], content_file[256];
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1))
		return -1;

	if (lua_getfrom(L, TABLE, "header") < 0)
		return -1;
	if (lua_to_int(L, TABLE, "len", &hdr_len) < 0)
		return -1;
	if (lua_to_int(L, TABLE, "beg", &hdr_beg) < 0)
		return -1;
	if (lua_to_string(L, TABLE, "file_name", hdr_file, sizeof(hdr_file)) < 0)
		return -1;
	lua_pop(L, 1);

	if (lua_getfrom(L, TABLE, "content") < 0)
		return -1;
	if (lua_to_int(L, TABLE, "len", &content_len) < 0)
		return -1;
	if (lua_to_int(L, TABLE, "beg", &content_beg) < 0)
		return -1;
	if (lua_to_string(L, TABLE, "file_name", content_file, sizeof(content_file)) < 0)
		return -1;
	lua_pop(L, 1);

	if (hdr_len == UINT32_MAX) {
		long ret = file_get_size(hdr_file);

		if (ret < 0) {
			plog_err("%s", file_get_error());
			return -1;
		}
		hdr_len = ret - hdr_beg;
	}

	if (content_len == UINT32_MAX) {
		long ret = file_get_size(content_file);

		if (ret < 0) {
			plog_err("%s", file_get_error());
			return -1;
		}
		content_len = ret - content_beg;
	}
	*cl = content_len;
	peer_data->hdr_len = hdr_len;

	if (file_read_cached(hdr_file, &peer_data->hdr, hdr_beg, hdr_len, socket, hs))
		return -1;
	if (file_read_cached(content_file, &peer_data->content, content_beg, content_len, socket, hs))
		return -1;

	lua_pop(L, pop);
	return 0;
}

static int lua_to_peer_action(struct lua_State *L, enum lua_place from, const char *name, struct peer_action *action, size_t client_contents_len, size_t server_contents_len)
{
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1))
		return -1;

	uint32_t peer, beg, len;
	if (lua_to_int(L, TABLE, "peer", &peer) ||
	    lua_to_int(L, TABLE, "beg", &beg) ||
	    lua_to_int(L, TABLE, "len", &len)) {
		return -1;
	}
	size_t data_len = (peer == PEER_CLIENT? client_contents_len : server_contents_len);
	if (len == (uint32_t)-1)
		len = data_len - beg;

	PROX_PANIC(beg + len > data_len, "Accessing data past the end (starting at %u for %u bytes) while total length is %zu\n", beg, len, data_len);

	action->peer = peer;
	action->beg = beg;
	action->len = len;
	lua_pop(L, pop);
	return 0;
}

static int lua_to_stream_cfg(struct lua_State *L, enum lua_place from, const char *name, uint32_t socket, struct stream_cfg **stream_cfg, struct hash_set *hs)
{
	int pop;
	struct stream_cfg *ret;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (lua_getfrom(L, TABLE, "actions") < 0)
		return -1;

	lua_len(prox_lua(), -1);
	uint32_t n_actions = lua_tointeger(prox_lua(), -1);
	lua_pop(prox_lua(), 1);

	lua_pop(L, 1);

	size_t mem_size = 0;
	mem_size += sizeof(*ret);
	/* one additional action is allocated to allow inserting an
	   additional "default" action to close down TCP sessions from
	   the client side. */
	mem_size += sizeof(ret->actions[0]) * (n_actions + 1);

	ret = prox_zmalloc(sizeof(*ret) + mem_size, socket);
	ret->n_actions = n_actions;

	size_t client_contents_len, server_contents_len;
	char proto[16];
	uint32_t timeout_us, timeout_time_wait_us;
	plogx_dbg("loading stream\n");
	if (lua_to_host_set(L, TABLE, "servers", &ret->servers))
		return -1;
	if (lua_to_string(L, TABLE, "l4_proto", proto, sizeof(proto)))
		return -1;
	if (lua_to_peer_data(L, TABLE, "client_data", socket, &ret->data[PEER_CLIENT], &client_contents_len, hs))
		return -1;
	if (lua_to_peer_data(L, TABLE, "server_data", socket, &ret->data[PEER_SERVER], &server_contents_len, hs))
		return -1;

	if (lua_to_int(L, TABLE, "timeout", &timeout_us)) {
		timeout_us = 1000000;
	}

	ret->tsc_timeout = usec_to_tsc(timeout_us);

	double up, dn;

	if (lua_to_double(L, TABLE, "up_bps", &up))
		up = 5000;// Default rate is 40 Mbps

	if (lua_to_double(L, TABLE, "dn_bps", &dn))
		dn = 5000;// Default rate is 40 Mbps

	const uint64_t hz = rte_get_tsc_hz();

	ret->tt_cfg[PEER_CLIENT] = token_time_cfg_create(up, hz, ETHER_MAX_LEN + 20);
	ret->tt_cfg[PEER_SERVER] = token_time_cfg_create(dn, hz, ETHER_MAX_LEN + 20);

	if (!strcmp(proto, "tcp")) {
		ret->proto = IPPROTO_TCP;
		ret->proc = stream_tcp_proc;
		ret->is_ended = stream_tcp_is_ended;

		if (lua_to_int(L, TABLE, "timeout_time_wait", &timeout_time_wait_us)) {
			timeout_time_wait_us = 2000000;
		}

		ret->tsc_timeout_time_wait = usec_to_tsc(timeout_time_wait_us);
	}
	else if (!strcmp(proto, "udp")) {
		plogx_dbg("loading UDP\n");
		ret->proto = IPPROTO_UDP;
		ret->proc = stream_udp_proc;
		ret->is_ended = stream_udp_is_ended;
	}
	else
		return -1;

	/* get all actions */
	if (lua_getfrom(L, TABLE, "actions") < 0)
		return -1;

	uint32_t idx = 0;
	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (lua_to_peer_action(L, STACK, NULL, &ret->actions[idx], client_contents_len, server_contents_len))
			return -1;

		stream_cfg_verify_action(ret, &ret->actions[idx]);

		idx++;

		lua_pop(L, 1);
	}
	lua_pop(L, 1);

	/* For TCP, one of the peers initiates closing down the
	   connection. This is signified by the last action having
	   with zero length. If such an action is not specified in the
	   configuration file, the default is for the client to close
	   the connection. This means that the TCP connection at the
	   client will go into a TIME_WAIT state and the server
	   releases all the resources avoiding resource starvation at
	   the server. */
	if (ret->proto == IPPROTO_TCP && ret->actions[ret->n_actions - 1].len != 0) {
		ret->actions[ret->n_actions].len = 0;
		ret->actions[ret->n_actions].beg = 0;
		ret->actions[ret->n_actions].peer = PEER_CLIENT;
		ret->n_actions++;
	}

	if (IPPROTO_TCP == ret->proto)
		stream_tcp_calc_len(ret, &ret->n_pkts, &ret->n_bytes);
	else
		stream_udp_calc_len(ret, &ret->n_pkts, &ret->n_bytes);

	lua_pop(L, pop);
	*stream_cfg = ret;
	return 0;
}

static int lua_to_bundle_cfg(struct lua_State *L, enum lua_place from, const char *name, uint8_t socket, struct bundle_cfg *bundle, struct hash_set *hs)
{
	int pop, pop2, idx;
	int clients_loaded = 0;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1))
		return -1;

	lua_len(prox_lua(), -1);
	bundle->n_stream_cfgs = lua_tointeger(prox_lua(), -1);
	lua_pop(prox_lua(), 1);

	bundle->stream_cfgs = prox_zmalloc(sizeof(*bundle->stream_cfgs) * bundle->n_stream_cfgs, socket);

	plogx_dbg("loading bundle cfg with %d streams\n", bundle->n_stream_cfgs);
	idx = 0;
	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (!clients_loaded) {
			if (lua_to_host_set(L, TABLE, "clients", &bundle->clients)) {
				return -1;
			}
			clients_loaded = 1;
		}
		if (lua_to_stream_cfg(L, STACK, NULL, socket, &bundle->stream_cfgs[idx], hs)) {
			return -1;
		}

		++idx;
		lua_pop(L, 1);
	}

	lua_pop(L, pop);
	return 0;
}

static void init_task_gen(struct task_base *tbase, struct task_args *targ)
{
	struct task_gen_server *task = (struct task_gen_server *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	static char name[] = "server_mempool";
	name[0]++;
	task->mempool = rte_mempool_create(name,
					   4*1024 - 1, TX_MBUF_SIZE,
					   targ->nb_cache_mbuf,
					   sizeof(struct rte_pktmbuf_pool_private),
					   rte_pktmbuf_pool_init, NULL,
					   rte_pktmbuf_init, 0,
					   socket_id, 0);
	PROX_PANIC(task->mempool == NULL, "Failed to allocate memory pool with %u elements\n", 4*1024 - 1);
	int pop = lua_getfrom(prox_lua(), GLOBAL, targ->streams);
	PROX_PANIC(pop < 0, "Failed to find '%s' in lua\n", targ->streams);

	lua_len(prox_lua(), -1);
	uint32_t n_listen = lua_tointeger(prox_lua(), -1);
	lua_pop(prox_lua(), 1);
	PROX_PANIC(n_listen == 0, "No services specified to listen on\n");

	task->bundle_cfgs = prox_zmalloc(n_listen * sizeof(task->bundle_cfgs[0]), socket_id);

	plogx_info("n_listen = %d\n", n_listen);

	struct hash_set *hs = prox_sh_find_socket(socket_id, "genl4_streams");
	if (hs == NULL) {
		/* Expected number of streams per bundle = 1, hash_set
		   will grow if full. */
		hs = hash_set_create(n_listen, socket_id);
		prox_sh_add_socket(socket_id, "genl4_streams", hs);
	}

	const struct rte_hash_parameters listen_table = {
		.name = name,
		.entries = n_listen * 4,
		.key_len = sizeof(struct new_tuple),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = socket_id,
	};
	name[0]++;

	task->listen_hash = rte_hash_create(&listen_table);
	task->listen_entries = prox_zmalloc(listen_table.entries * sizeof(task->listen_entries[0]), socket_id);

	int idx = 0;
	lua_pushnil(prox_lua());
	while (lua_next(prox_lua(), -2)) {
		task->bundle_cfgs[idx].n_stream_cfgs = 1;
		task->bundle_cfgs[idx].stream_cfgs = prox_zmalloc(sizeof(*task->bundle_cfgs[idx].stream_cfgs), socket_id);
		int ret = lua_to_stream_cfg(prox_lua(), STACK, NULL, socket_id, &task->bundle_cfgs[idx].stream_cfgs[0], hs);
		PROX_PANIC(ret, "Failed to load stream cfg\n");
		struct stream_cfg *stream = task->bundle_cfgs[idx].stream_cfgs[0];

		// TODO: check mask and add to hash for each host
		struct new_tuple nt = {
			.dst_addr = stream->servers.ip,
			.proto_id = stream->proto,
			.dst_port = stream->servers.port,
			.l2_types[0] = 0x0008,
		};

		ret = rte_hash_add_key(task->listen_hash, &nt);
		PROX_PANIC(ret < 0, "Failed to add\n");

		task->listen_entries[ret] = &task->bundle_cfgs[idx];

		plogx_dbg("Server = "IPv4_BYTES_FMT":%d\n", IPv4_BYTES(((uint8_t*)&nt.dst_addr)), rte_bswap16(nt.dst_port));
		++idx;
		lua_pop(prox_lua(), 1);
	}

	static char name2[] = "task_gen_hash2";

	name2[0]++;
	plogx_dbg("Creating bundle ctx pool\n");
	if (bundle_ctx_pool_create(name2, targ->n_concur_conn * 2, &task->bundle_ctx_pool, NULL, 0, NULL, socket_id)) {
		cmd_mem_stats();
		PROX_PANIC(1, "Failed to create conn_ctx_pool\n");
	}

	task->heap = heap_create(targ->n_concur_conn * 2, socket_id);
	task->seed = rte_rdtsc();

	/* TODO: calculate the CDF of the reply distribution and the
	   number of replies as the number to cover for 99% of the
	   replies. For now, assume that this is number is 2. */
	uint32_t queue_size = rte_align32pow2(targ->n_concur_conn * 2);

	PROX_PANIC(queue_size == 0, "Overflow resulted in queue size 0\n");
	task->fqueue = fqueue_create(queue_size, socket_id);
	PROX_PANIC(task->fqueue == NULL, "Failed to allocate local queue\n");

	uint32_t n_descriptors;

	if (targ->nb_txports) {
		PROX_PANIC(targ->nb_txports != 1, "Need exactly one TX port for L4 generation\n");
		n_descriptors = prox_port_cfg[targ->tx_port_queue[0].port].n_txd;
	} else {
		PROX_PANIC(targ->nb_txrings != 1, "Need exactly one TX ring for L4 generation\n");
		n_descriptors = 256;
	}

	struct token_time_cfg tt_cfg = {
		.bpp = targ->rate_bps,
		.period = rte_get_tsc_hz(),
		.bytes_max = n_descriptors * (ETHER_MIN_LEN + 20),
	};

	token_time_init(&task->token_time, &tt_cfg);
}

static void init_task_gen_client(struct task_base *tbase, struct task_args *targ)
{
	struct task_gen_client *task = (struct task_gen_client *)tbase;
	static char name[] = "gen_pool";
	const uint32_t socket = rte_lcore_to_socket_id(targ->lconf->id);
	name[0]++;
	task->mempool = rte_mempool_create(name,
					   4*1024 - 1, TX_MBUF_SIZE,
					   targ->nb_cache_mbuf,
					   sizeof(struct rte_pktmbuf_pool_private),
					   rte_pktmbuf_pool_init, NULL,
					   rte_pktmbuf_init, 0,
					   socket, 0);
	PROX_PANIC(task->mempool == NULL, "Failed to allocate memory pool with %u elements\n", 4*1024 - 1);

	/* streams contains a lua table. Go through it and read each
	   stream with associated imix_fraction. */
	uint32_t imix;
	uint32_t i = 0;

	int pop = lua_getfrom(prox_lua(), GLOBAL, targ->streams);
	PROX_PANIC(pop < 0, "Failed to find '%s' in lua\n", targ->streams);

	lua_len(prox_lua(), -1);
	uint32_t n_bundle_cfgs = lua_tointeger(prox_lua(), -1);
	lua_pop(prox_lua(), 1);
	PROX_PANIC(n_bundle_cfgs == 0, "No configs specified\n");
	plogx_info("loading %d bundle_cfgs\n", n_bundle_cfgs);

	struct hash_set *hs = prox_sh_find_socket(socket, "genl4_streams");
	if (hs == NULL) {
		/* Expected number of streams per bundle = 8, hash_set
		   will grow if full. */
		hs = hash_set_create(n_bundle_cfgs * 8, socket);
		prox_sh_add_socket(socket, "genl4_streams", hs);
	}

	task->bundle_cfgs = prox_zmalloc(n_bundle_cfgs * sizeof(task->bundle_cfgs[0]), socket);
	lua_pushnil(prox_lua());

	int total_imix = 0;

	uint32_t *occur = prox_zmalloc(n_bundle_cfgs * sizeof(*occur), socket);
	struct cdf *cdf = cdf_create(n_bundle_cfgs, socket);

	while (lua_next(prox_lua(), -2)) {
		PROX_PANIC(lua_to_int(prox_lua(), TABLE, "imix_fraction", &imix) ||
			   lua_to_bundle_cfg(prox_lua(), TABLE, "bundle", socket, &task->bundle_cfgs[i], hs),
			   "Failed to load bundle cfg:\n%s\n", get_lua_to_errors());
		cdf_add(cdf, imix);
		occur[i] = imix;
		total_imix += imix;
		++i;
		lua_pop(prox_lua(), 1);
	}

	lua_pop(prox_lua(), pop);
	cdf_setup(cdf);

	PROX_PANIC(targ->max_setup_rate == 0, "Max setup rate not set\n");

	task->new_conn_cost = rte_get_tsc_hz()/targ->max_setup_rate;

	static char name2[] = "task_gen_hash";
	name2[0]++;
	plogx_dbg("Creating bundle ctx pool\n");
	if (bundle_ctx_pool_create(name2, targ->n_concur_conn, &task->bundle_ctx_pool, occur, n_bundle_cfgs, task->bundle_cfgs, socket)) {
		cmd_mem_stats();
		PROX_PANIC(1, "Failed to create conn_ctx_pool\n");
	}

	task->heap = heap_create(targ->n_concur_conn, socket);
	task->seed = rte_rdtsc();
	/* task->token_time.bytes_max = MAX_PKT_BURST * (ETHER_MAX_LEN + 20); */

	/* To avoid overflowing the tx descriptors, the token bucket
	   size needs to be limited. The descriptors are filled most
	   quickly with the smallest packets. For that reason, the
	   token bucket size is given by "number of tx descriptors" *
	   "smallest Ethernet packet". */
	PROX_ASSERT(targ->nb_txports == 1);

	struct token_time_cfg tt_cfg = {
		.bpp = targ->rate_bps,
		.period = rte_get_tsc_hz(),
		.bytes_max = prox_port_cfg[targ->tx_port_queue[0].port].n_txd * (ETHER_MIN_LEN + 20),
	};

	token_time_init(&task->token_time, &tt_cfg);
}

static void start_task_gen_client(struct task_base *tbase)
{
	struct task_gen_client *task = (struct task_gen_client *)tbase;

	token_time_reset(&task->token_time, rte_rdtsc(), 0);

	task->new_conn_tokens = 0;
	task->new_conn_last_tsc = rte_rdtsc();
}

static void stop_task_gen_client(struct task_base *tbase)
{
	struct task_gen_client *task = (struct task_gen_client *)tbase;
	struct bundle_ctx *bundle;

	while (!heap_is_empty(task->heap)) {
		bundle = BUNDLE_CTX_UPCAST(heap_pop(task->heap));
		bundle_expire(bundle, &task->bundle_ctx_pool, &task->l4_stats);
	}
}

static void start_task_gen_server(struct task_base *tbase)
{
	struct task_gen_server *task = (struct task_gen_server *)tbase;

	token_time_reset(&task->token_time, rte_rdtsc(), 0);
}

static void stop_task_gen_server(struct task_base *tbase)
{
	struct task_gen_server *task = (struct task_gen_server *)tbase;
	struct bundle_ctx *bundle;
	uint8_t out[MAX_PKT_BURST];

	while (!heap_is_empty(task->heap)) {
		bundle = BUNDLE_CTX_UPCAST(heap_pop(task->heap));
		bundle_expire(bundle, &task->bundle_ctx_pool, &task->l4_stats);
	}

	if (task->cancelled) {
		struct rte_mbuf *mbuf = task->mbuf_saved;

		out[0] = OUT_DISCARD;
		task->cancelled = 0;
		task->base.tx_pkt(&task->base, &mbuf, 1, out);
	}

	do {
		if (task->cur_mbufs_beg == task->cur_mbufs_end) {
			task->cur_mbufs_end = fqueue_get(task->fqueue, task->cur_mbufs, MAX_PKT_BURST);
			task->cur_mbufs_beg = 0;
			if (task->cur_mbufs_end == 0)
				break;
		}
		uint16_t n_pkts = task->cur_mbufs_end - task->cur_mbufs_beg;
		struct rte_mbuf **mbufs = task->cur_mbufs + task->cur_mbufs_beg;

		if (n_pkts) {
			for (uint16_t j = 0; j < n_pkts; ++j) {
				out[j] = OUT_DISCARD;
			}
			task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
		}
	} while (1);
}

static struct task_init task_init_gen1 = {
	.mode_str = "genl4",
	.sub_mode_str = "server",
	.init = init_task_gen,
	.handle = handle_gen_bulk,
	.start = start_task_gen_server,
	.stop = stop_task_gen_server,
	.flag_features = TASK_FEATURE_ZERO_RX,
	.size = sizeof(struct task_gen_server),
};

static struct task_init task_init_gen2 = {
	.mode_str = "genl4",
	.init = init_task_gen_client,
	.handle = handle_gen_bulk_client,
	.start = start_task_gen_client,
	.stop = stop_task_gen_client,
	.flag_features = TASK_FEATURE_ZERO_RX,
	.size = sizeof(struct task_gen_client),
};

__attribute__((constructor)) static void reg_task_gen(void)
{
	reg_task(&task_init_gen1);
	reg_task(&task_init_gen2);
}
