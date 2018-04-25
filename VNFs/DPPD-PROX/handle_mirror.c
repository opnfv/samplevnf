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
#include <rte_mbuf.h>

#include "mbuf_utils.h"
#include "task_init.h"
#include "task_base.h"
#include "lconf.h"
#include "log.h"
#include "prox_port_cfg.h"
#include "quit.h"

/* Task that sends packets to multiple outputs. Note that in case of n
   outputs, the output packet rate is n times the input packet
   rate. Also, since the packet is duplicated by increasing the
   refcnt, a change to a packet in subsequent tasks connected through
   one of the outputs of this task will also change the packets as
   seen by tasks connected behind through other outputs. The correct
   way to resolve this is to create deep copies of the packet. */
struct task_mirror {
	struct task_base base;
	uint32_t         n_dests;
};

struct task_mirror_copy {
	struct task_base   base;
	struct rte_mempool *mempool;
	uint32_t           n_dests;
};

static int handle_mirror_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	int ret = 0;
	struct task_mirror *task = (struct task_mirror *)tbase;
	uint8_t out[MAX_PKT_BURST];
	struct rte_mbuf *mbufs2[MAX_PKT_BURST];

	/* Since after calling tx_pkt the mbufs parameter of a handle
	   function becomes invalid and handle_mirror calls tx_pkt
	   multiple times, the pointers are copied first. This copy is
	   used in each call to tx_pkt below. */
	rte_memcpy(mbufs2, mbufs, sizeof(mbufs[0]) * n_pkts);

	for (uint16_t j = 0; j < n_pkts; ++j) {
		rte_pktmbuf_refcnt_update(mbufs2[j], task->n_dests - 1);
	}
	for (uint16_t j = 0; j < task->n_dests; ++j) {
		memset(out, j, n_pkts);

		ret+= task->base.tx_pkt(&task->base, mbufs2, n_pkts, out);
	}
	return ret;
}

static int handle_mirror_bulk_copy(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_mirror_copy *task = (struct task_mirror_copy *)tbase;
	uint8_t out[MAX_PKT_BURST];
	int ret = 0;

	/* Send copies of the packet to all but the first
	   destination */
	struct rte_mbuf *new_pkts[MAX_PKT_BURST];

	for (uint16_t j = 1; j < task->n_dests; ++j) {
		if (rte_mempool_get_bulk(task->mempool, (void **)new_pkts, n_pkts) < 0) {
			continue;
		}
		/* Finally, forward the incoming packets. */
		for (uint16_t i = 0; i < n_pkts; ++i) {
			void *dst, *src;
			uint16_t pkt_len;

			out[i] = j;
			init_mbuf_seg(new_pkts[i]);

			pkt_len = rte_pktmbuf_pkt_len(mbufs[i]);
			rte_pktmbuf_pkt_len(new_pkts[i]) = pkt_len;
			rte_pktmbuf_data_len(new_pkts[i]) = pkt_len;

			dst = rte_pktmbuf_mtod(new_pkts[i], void *);
			src = rte_pktmbuf_mtod(mbufs[i], void *);

			rte_memcpy(dst, src, pkt_len);
		}
		ret+= task->base.tx_pkt(&task->base, new_pkts, n_pkts, out);
	}

	/* Finally, forward the incoming packets to the first destination. */
	memset(out, 0, n_pkts);
	ret+= task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
	return ret;
}

static void init_task_mirror(struct task_base *tbase, struct task_args *targ)
{
	struct task_mirror *task = (struct task_mirror *)tbase;

	task->n_dests = targ->nb_txports? targ->nb_txports : targ->nb_txrings;
}

static void init_task_mirror_copy(struct task_base *tbase, struct task_args *targ)
{
	static char name[] = "mirror_pool";
	struct task_mirror_copy *task = (struct task_mirror_copy *)tbase;
	const int sock_id = rte_lcore_to_socket_id(targ->lconf->id);
	task->n_dests = targ->nb_txports? targ->nb_txports : targ->nb_txrings;

	name[0]++;
	task->mempool = rte_mempool_create(name,
					   targ->nb_mbuf - 1, MBUF_SIZE,
					   targ->nb_cache_mbuf,
					   sizeof(struct rte_pktmbuf_pool_private),
					   rte_pktmbuf_pool_init, NULL,
					   rte_pktmbuf_init, 0,
					   sock_id, 0);
	PROX_PANIC(task->mempool == NULL,
		   "Failed to allocate memory pool on socket %u with %u elements\n",
		   sock_id, targ->nb_mbuf - 1);
	task->n_dests = targ->nb_txports? targ->nb_txports : targ->nb_txrings;
}

static struct task_init task_init_mirror = {
	.mode_str = "mirror",
	.init = init_task_mirror,
	.handle = handle_mirror_bulk,
	.flag_features = TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS | TASK_FEATURE_TXQ_FLAGS_REFCOUNT,
	.size = sizeof(struct task_mirror),
};

static struct task_init task_init_mirror2 = {
	.mode_str = "mirror",
	.sub_mode_str = "copy",
	.init = init_task_mirror_copy,
	.handle = handle_mirror_bulk_copy,
	.flag_features = TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS,
	.size = sizeof(struct task_mirror),
};

__attribute__((constructor)) static void reg_task_mirror(void)
{
	reg_task(&task_init_mirror);
	reg_task(&task_init_mirror2);
}
