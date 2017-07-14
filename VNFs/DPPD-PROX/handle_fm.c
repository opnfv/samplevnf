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

#include <dlfcn.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_eth_ctrl.h>

#include "log.h"
#include "quit.h"
#include "lconf.h"
#include "task_init.h"
#include "task_base.h"
#include "kv_store_expire.h"
#include "stats.h"
#include "prox_shared.h"
#include "etypes.h"
#include "prox_cfg.h"
#include "dpi/dpi.h"

struct task_dpi_per_core {
	void     *dpi_opaque;
};

struct task_fm {
	struct task_base          base;
	/* FM related fields */
	struct kv_store_expire   *kv_store_expire;
	void                     *dpi_opaque;

	struct dpi_engine        dpi_engine;
	struct task_dpi_per_core *dpi_shared; /* Used only during init */
};

struct eth_ip4_udp {
	struct ether_hdr l2;
	struct ipv4_hdr  l3;
	union {
		struct udp_hdr   udp;
		struct tcp_hdr   tcp;
	} l4;
} __attribute__((packed));

union pkt_type {
	struct {
		uint16_t etype;
		uint8_t  ip_byte;
		uint8_t  next_proto;
	} __attribute__((packed));
	uint32_t val;
};

static union pkt_type pkt_type_udp = {
	.next_proto = IPPROTO_UDP,
	.ip_byte    = 0x45,
	.etype      = ETYPE_IPv4,
};

static union pkt_type pkt_type_tcp = {
	.next_proto = IPPROTO_TCP,
	.ip_byte    = 0x45,
	.etype      = ETYPE_IPv4,
};

static int extract_flow_info(struct eth_ip4_udp *p, struct flow_info *fi, struct flow_info *fi_flipped, uint32_t *len, uint8_t **payload)
{
	union pkt_type pkt_type = {
		.next_proto = p->l3.next_proto_id,
		.ip_byte    = p->l3.version_ihl,
		.etype      = p->l2.ether_type,
	};

	memset(fi->reservered, 0, sizeof(fi->reservered));
	memset(fi_flipped->reservered, 0, sizeof(fi_flipped->reservered));

	if (pkt_type.val == pkt_type_udp.val) {
		fi->ip_src = p->l3.src_addr;
		fi->ip_dst = p->l3.dst_addr;
		fi->ip_proto = p->l3.next_proto_id;
		fi->port_src = p->l4.udp.src_port;
		fi->port_dst = p->l4.udp.dst_port;

		fi_flipped->ip_src = p->l3.dst_addr;
		fi_flipped->ip_dst = p->l3.src_addr;
		fi_flipped->ip_proto = p->l3.next_proto_id;
		fi_flipped->port_src = p->l4.udp.dst_port;
		fi_flipped->port_dst = p->l4.udp.src_port;

		*len = rte_be_to_cpu_16(p->l4.udp.dgram_len) - sizeof(struct udp_hdr);
		*payload = (uint8_t*)(&p->l4.udp) + sizeof(struct udp_hdr);
		return 0;
	}
	else if (pkt_type.val == pkt_type_tcp.val) {
		fi->ip_src = p->l3.src_addr;
		fi->ip_dst = p->l3.dst_addr;
		fi->ip_proto = p->l3.next_proto_id;
		fi->port_src = p->l4.tcp.src_port;
		fi->port_dst = p->l4.tcp.dst_port;

		fi_flipped->ip_src = p->l3.dst_addr;
		fi_flipped->ip_dst = p->l3.src_addr;
		fi_flipped->ip_proto = p->l3.next_proto_id;
		fi_flipped->port_src = p->l4.tcp.dst_port;
		fi_flipped->port_dst = p->l4.tcp.src_port;

		*len = rte_be_to_cpu_16(p->l3.total_length) - sizeof(struct ipv4_hdr) - ((p->l4.tcp.data_off >> 4)*4);
		*payload = ((uint8_t*)&p->l4.tcp) + ((p->l4.tcp.data_off >> 4)*4);
		return 0;
	}

	return -1;
}

static int is_flow_beg(const struct flow_info *fi, const struct eth_ip4_udp *p)
{
	return fi->ip_proto == IPPROTO_UDP ||
		(fi->ip_proto == IPPROTO_TCP && p->l4.tcp.tcp_flags & TCP_SYN_FLAG);
}

static void *lookup_flow(struct task_fm *task, struct flow_info *fi, uint64_t now_tsc)
{
	struct kv_store_expire_entry *entry;

	entry = kv_store_expire_get(task->kv_store_expire, fi, now_tsc);

	return entry ? entry_value(task->kv_store_expire, entry) : NULL;
}

static void *lookup_or_insert_flow(struct task_fm *task, struct flow_info *fi, uint64_t now_tsc)
{
	struct kv_store_expire_entry *entry;

	entry = kv_store_expire_get_or_put(task->kv_store_expire, fi, now_tsc);

	return entry ? entry_value(task->kv_store_expire, entry) : NULL;
}

static int handle_fm(struct task_fm *task, struct rte_mbuf *mbuf, uint64_t now_tsc)
{
	struct eth_ip4_udp *p;
	struct flow_info fi, fi_flipped;
	void *flow_data;
	uint32_t len;
	uint8_t *payload;
	uint32_t res[2];
	size_t res_len = 2;
	int flow_beg;
	struct dpi_payload dpi_payload;
	int is_upstream = 0;

	p = rte_pktmbuf_mtod(mbuf, struct eth_ip4_udp *);

	if (0 != extract_flow_info(p, &fi, &fi_flipped, &len, &payload)) {
		plogx_err("Unknown packet type\n");
		return OUT_DISCARD;
	}

	/* First, try to see if the flow already exists where the
	   current packet is sent by the server. */
	if (!(flow_data = lookup_flow(task, &fi_flipped, now_tsc))) {
		/* Insert a new flow, only if this is the first packet
		   in the flow. */
		is_upstream = 1;
		if (is_flow_beg(&fi, p))
			flow_data = lookup_or_insert_flow(task, &fi, now_tsc);
		else
			flow_data = lookup_flow(task, &fi, now_tsc);
	}

	if (!flow_data)
		return OUT_DISCARD;
	else if (!len)
		return 0;

	dpi_payload.payload = payload;
	dpi_payload.len = len;
	dpi_payload.client_to_server = is_upstream;
	gettimeofday(&dpi_payload.tv, NULL);
	task->dpi_engine.dpi_process(task->dpi_opaque, is_upstream? &fi : &fi_flipped, flow_data, &dpi_payload, res, &res_len);
	return OUT_HANDLED;
}

static int handle_fm_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_fm *task = (struct task_fm *)tbase;
	uint64_t now_tsc = rte_rdtsc();
	uint16_t handled = 0;
	uint16_t discard = 0;
	int ret;

	for (uint16_t i = 0; i < n_pkts; ++i) {
		ret = handle_fm(task, mbufs[i], now_tsc);
		if (ret == OUT_DISCARD)
			discard++;
		else if (ret == OUT_HANDLED)
			handled++;
	}

	for (uint16_t i = 0; i < n_pkts; ++i)
		rte_pktmbuf_free(mbufs[i]);

	TASK_STATS_ADD_DROP_HANDLED(&tbase->aux->stats, handled);
	TASK_STATS_ADD_DROP_DISCARD(&tbase->aux->stats, discard);
	return 0;
}

static void load_dpi_engine(const char *dpi_engine_path, struct dpi_engine *dst)
{
	void *handle = prox_sh_find_system(dpi_engine_path);

	if (handle == NULL) {
		plogx_info("Loading DPI engine from '%s'\n", dpi_engine_path);
		handle = dlopen(dpi_engine_path, RTLD_NOW | RTLD_GLOBAL);

		PROX_PANIC(handle == NULL, "Failed to load dpi engine from '%s' with error:\n\t\t%s\n", dpi_engine_path, dlerror());
		prox_sh_add_system(dpi_engine_path, handle);
	}

	struct dpi_engine *(*get_dpi_engine)(void) = dlsym(handle, "get_dpi_engine");

	PROX_PANIC(get_dpi_engine == NULL, "Failed to find get_dpi_engine function from '%s'\n", dpi_engine_path);
	struct dpi_engine *dpi_engine = get_dpi_engine();

	dpi_engine->dpi_print = plog_info;
	rte_memcpy(dst, dpi_engine, sizeof(*dst));
}

static uint32_t count_fm_cores(void)
{
	uint32_t n_cores = 0;
	uint32_t lcore_id = -1;
	struct lcore_cfg *lconf;

	while(prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			if (!strcmp(lconf->targs[task_id].task_init->mode_str, "fm")) {
				n_cores++;
				/* Only intersted in number of cores
				   so break here. */
				break;
			}
		}
	}

	return n_cores;
}

static struct kv_store_expire *get_shared_flow_table(struct task_args *targ, struct dpi_engine *de)
{
	struct kv_store_expire *ret = prox_sh_find_core(targ->lconf->id, "flow_table");
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	if (!ret) {
		ret = kv_store_expire_create(rte_align32pow2(targ->flow_table_size) * 4,
					     sizeof(struct flow_info),
					     de->dpi_get_flow_entry_size(),
					     socket_id,
					     de->dpi_flow_expire,
					     rte_get_tsc_hz() * 60);
		PROX_PANIC(ret == NULL, "Failed to allocate KV store\n");
		prox_sh_add_core(targ->lconf->id, "flow_table", ret);
	}
	return ret;
}

static struct task_dpi_per_core *get_shared_dpi_shared(struct task_args *targ)
{
	static const char *name = "dpi_shared";
	struct task_dpi_per_core *ret = prox_sh_find_core(targ->lconf->id, name);
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	if (!ret) {
		ret = prox_zmalloc(sizeof(*ret), socket_id);
		prox_sh_add_core(targ->lconf->id, name, ret);
	}
	return ret;
}

static void init_task_fm(struct task_base *tbase, struct task_args *targ)
{
	struct task_fm *task = (struct task_fm *)tbase;
	static int dpi_inited = 0;

	load_dpi_engine(targ->dpi_engine_path, &task->dpi_engine);

	task->kv_store_expire = get_shared_flow_table(targ, &task->dpi_engine);
	task->dpi_shared = get_shared_dpi_shared(targ);

	if (!dpi_inited) {
		uint32_t n_threads = count_fm_cores();
		const char *dpi_params[16];

		plogx_info("Initializing DPI with %u threads\n", n_threads);
		dpi_inited = 1;

		PROX_PANIC(targ->n_dpi_engine_args > 16, "Too many DPI arguments");
		for (size_t i = 0; i < targ->n_dpi_engine_args && i < 16; ++i)
			dpi_params[i] = targ->dpi_engine_args[i];

		int ret = task->dpi_engine.dpi_init(n_threads, targ->n_dpi_engine_args, dpi_params);

		PROX_PANIC(ret, "Failed to initialize DPI engine\n");
	}
}

static void start_first(struct task_base *tbase)
{
	struct task_fm *task = (struct task_fm *)tbase;
	void *ret = task->dpi_engine.dpi_thread_start();

	task->dpi_shared->dpi_opaque = ret;
	PROX_PANIC(ret == NULL, "dpi_thread_init failed\n");
}

static void start(struct task_base *tbase)
{
	struct task_fm *task = (struct task_fm *)tbase;

	task->dpi_opaque = task->dpi_shared->dpi_opaque;
	PROX_PANIC(task->dpi_opaque == NULL, "dpi_opaque == NULL");
}

static void stop(struct task_base *tbase)
{
	struct task_fm *task = (struct task_fm *)tbase;

	size_t expired = kv_store_expire_expire_all(task->kv_store_expire);
	size_t size = kv_store_expire_size(task->kv_store_expire);

	plogx_info("%zu/%zu\n", expired, size);
}

static void stop_last(struct task_base *tbase)
{
	struct task_fm *task = (struct task_fm *)tbase;

	task->dpi_engine.dpi_thread_stop(task->dpi_shared->dpi_opaque);
	task->dpi_shared->dpi_opaque = NULL;
}

static struct task_init task_init_fm = {
	.mode_str = "fm",
	.init = init_task_fm,
	.handle = handle_fm_bulk,
	.start = start,
	.stop = stop,
	.start_first = start_first,
	.stop_last = stop_last,
	.size = sizeof(struct task_fm)
};

__attribute__((constructor)) static void reg_task_fm(void)
{
	reg_task(&task_init_fm);
}
