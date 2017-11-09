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
#include <stdio.h>
#include <rte_cycles.h>
#include <rte_version.h>

#include "prox_malloc.h"
#include "lconf.h"
#include "log.h"
#include "random.h"
#include "handle_impair.h"
#include "prefetch.h"
#include "prox_port_cfg.h"

#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE
#endif

#define DELAY_ACCURACY	11		// accuracy of 2048 cycles ~= 1 micro-second
#define DELAY_MAX_MASK	0x1FFFFF	// Maximum 2M * 2K cycles ~1 second

struct queue_elem {
	struct rte_mbuf *mbuf;
	uint64_t        tsc;
};

struct queue {
	struct queue_elem *queue_elem;
	unsigned queue_head;
	unsigned queue_tail;
};

struct task_impair {
	struct task_base base;
	struct queue_elem *queue;
	uint32_t random_delay_us;
	uint32_t delay_us;
	uint64_t delay_time;
	uint64_t delay_time_mask;
	unsigned queue_head;
	unsigned queue_tail;
	unsigned queue_mask;
	int tresh;
	unsigned int seed;
	struct random state;
	uint64_t last_idx;
	struct queue *buffer;
	uint32_t socket_id;
	uint32_t flags;
	uint8_t src_mac[6];
};

#define IMPAIR_NEED_UPDATE     1
#define IMPAIR_SET_MAC         2

static int handle_bulk_impair(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts);
static int handle_bulk_impair_random(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts);
static int handle_bulk_random_drop(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts);

void task_impair_set_proba(struct task_base *tbase, float proba)
{
	struct task_impair *task = (struct task_impair *)tbase;
	task->tresh = ((uint64_t) RAND_MAX) * (uint32_t)(proba * 10000) / 1000000;
}

void task_impair_set_delay_us(struct task_base *tbase, uint32_t delay_us, uint32_t random_delay_us)
{
	struct task_impair *task = (struct task_impair *)tbase;
	task->flags |= IMPAIR_NEED_UPDATE;
	task->random_delay_us = random_delay_us;
	task->delay_us = delay_us;
}

static void task_impair_update(struct task_base *tbase)
{
	struct task_impair *task = (struct task_impair *)tbase;
	uint32_t queue_len = 0;
	size_t mem_size;
	if ((task->flags & IMPAIR_NEED_UPDATE) == 0)
		return;
	task->flags &= ~IMPAIR_NEED_UPDATE;
	uint64_t now = rte_rdtsc();
	uint8_t out[MAX_PKT_BURST] = {0};
	uint64_t now_idx = (now >> DELAY_ACCURACY) & DELAY_MAX_MASK;

	if (task->random_delay_us) {
		tbase->handle_bulk = handle_bulk_impair_random;
		task->delay_time = usec_to_tsc(task->random_delay_us);
		task->delay_time_mask = rte_align32pow2(task->delay_time) - 1;
		queue_len = rte_align32pow2((1250L * task->random_delay_us) / 84 / (DELAY_MAX_MASK + 1));
	} else if (task->delay_us == 0) {
		tbase->handle_bulk = handle_bulk_random_drop;
		task->delay_time = 0;
	} else {
		tbase->handle_bulk = handle_bulk_impair;
		task->delay_time = usec_to_tsc(task->delay_us);
		queue_len = rte_align32pow2(1250 * task->delay_us / 84);
	}
	if (task->queue) {
		struct rte_mbuf *new_mbufs[MAX_PKT_BURST];
		while (task->queue_tail != task->queue_head) {
			now = rte_rdtsc();
			uint16_t idx = 0;
			while (idx < MAX_PKT_BURST && task->queue_tail != task->queue_head) {
				if (task->queue[task->queue_tail].tsc <= now) {
					out[idx] = rand_r(&task->seed) <= task->tresh? 0 : OUT_DISCARD;
					new_mbufs[idx++] = task->queue[task->queue_tail].mbuf;
					task->queue_tail = (task->queue_tail + 1) & task->queue_mask;
				}
				else {
					break;
				}
			}
			if (idx)
				task->base.tx_pkt(&task->base, new_mbufs, idx, out);
		}
		prox_free(task->queue);
		task->queue = NULL;
	}
	if (task->buffer) {
		struct rte_mbuf *new_mbufs[MAX_PKT_BURST];
		while (task->last_idx != ((now_idx - 1) & DELAY_MAX_MASK)) {
			now = rte_rdtsc();
			uint16_t pkt_idx = 0;
			while ((pkt_idx < MAX_PKT_BURST) && (task->last_idx != ((now_idx - 1) & DELAY_MAX_MASK))) {
				struct queue *queue = &task->buffer[task->last_idx];
				while ((pkt_idx < MAX_PKT_BURST) && (queue->queue_tail != queue->queue_head)) {
					out[pkt_idx] = rand_r(&task->seed) <= task->tresh? 0 : OUT_DISCARD;
					new_mbufs[pkt_idx++] = queue->queue_elem[queue->queue_tail].mbuf;
					queue->queue_tail = (queue->queue_tail + 1) & task->queue_mask;
				}
				task->last_idx = (task->last_idx + 1) & DELAY_MAX_MASK;
			}

			if (pkt_idx)
				task->base.tx_pkt(&task->base, new_mbufs, pkt_idx, out);
		}
		for (int i = 0; i < DELAY_MAX_MASK + 1; i++) {
			if (task->buffer[i].queue_elem)
				prox_free(task->buffer[i].queue_elem);
		}
		prox_free(task->buffer);
		task->buffer = NULL;
	}

	if (queue_len < MAX_PKT_BURST)
		queue_len= MAX_PKT_BURST;
	task->queue_mask = queue_len - 1;
	if (task->queue_mask < MAX_PKT_BURST - 1)
		task->queue_mask = MAX_PKT_BURST - 1;
	mem_size = (task->queue_mask + 1) * sizeof(task->queue[0]);

	if (task->delay_us) {
		task->queue_head = 0;
		task->queue_tail = 0;
		task->queue = prox_zmalloc(mem_size, task->socket_id);
		if (task->queue == NULL) {
			plog_err("Not enough memory to allocate queue\n");
			task->queue_mask = 0;
		}
	} else if (task->random_delay_us) {
		size_t size = (DELAY_MAX_MASK + 1) * sizeof(struct queue);
		plog_info("Allocating %zd bytes\n", size);
		task->buffer = prox_zmalloc(size, task->socket_id);
		PROX_PANIC(task->buffer == NULL, "Not enough memory to allocate buffer\n");
		plog_info("Allocating %d x %zd bytes\n", DELAY_MAX_MASK + 1, mem_size);

		for (int i = 0; i < DELAY_MAX_MASK + 1; i++) {
			task->buffer[i].queue_elem = prox_zmalloc(mem_size, task->socket_id);
			PROX_PANIC(task->buffer[i].queue_elem == NULL, "Not enough memory to allocate buffer elems\n");
		}
	}
	random_init_seed(&task->state);
}

static int handle_bulk_random_drop(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_impair *task = (struct task_impair *)tbase;
	uint8_t out[MAX_PKT_BURST];
	struct ether_hdr * hdr[MAX_PKT_BURST];
	int ret = 0;
	for (uint16_t i = 0; i < n_pkts; ++i) {
		PREFETCH0(mbufs[i]);
	}
	for (uint16_t i = 0; i < n_pkts; ++i) {
		hdr[i] = rte_pktmbuf_mtod(mbufs[i], struct ether_hdr *);
		PREFETCH0(hdr[i]);
	}
	if (task->flags & IMPAIR_SET_MAC) {
		for (uint16_t i = 0; i < n_pkts; ++i) {
			ether_addr_copy((struct ether_addr *)&task->src_mac[0], &hdr[i]->s_addr);
			out[i] = rand_r(&task->seed) <= task->tresh? 0 : OUT_DISCARD;
		}
	} else {
		for (uint16_t i = 0; i < n_pkts; ++i) {
			out[i] = rand_r(&task->seed) <= task->tresh? 0 : OUT_DISCARD;
		}
	}
	ret = task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
	task_impair_update(tbase);
	return ret;
}

static int handle_bulk_impair(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_impair *task = (struct task_impair *)tbase;
	uint64_t now = rte_rdtsc();
	uint8_t out[MAX_PKT_BURST] = {0};
	uint16_t enqueue_failed;
	uint16_t i;
	int ret = 0;
	struct ether_hdr * hdr[MAX_PKT_BURST];
	for (uint16_t i = 0; i < n_pkts; ++i) {
		PREFETCH0(mbufs[i]);
	}
	for (uint16_t i = 0; i < n_pkts; ++i) {
		hdr[i] = rte_pktmbuf_mtod(mbufs[i], struct ether_hdr *);
		PREFETCH0(hdr[i]);
	}

	int nb_empty_slots = (task->queue_tail - task->queue_head + task->queue_mask) & task->queue_mask;
	if (likely(nb_empty_slots >= n_pkts)) {
		/* We know n_pkts fits, no need to check for every packet */
		for (i = 0; i < n_pkts; ++i) {
			if (task->flags & IMPAIR_SET_MAC)
				ether_addr_copy((struct ether_addr *)&task->src_mac[0], &hdr[i]->s_addr);
			task->queue[task->queue_head].tsc = now + task->delay_time;
			task->queue[task->queue_head].mbuf = mbufs[i];
			task->queue_head = (task->queue_head + 1) & task->queue_mask;
		}
	} else {
		for (i = 0; i < n_pkts; ++i) {
			if (((task->queue_head + 1) & task->queue_mask) != task->queue_tail) {
				if (task->flags & IMPAIR_SET_MAC)
					ether_addr_copy((struct ether_addr *)&task->src_mac[0], &hdr[i]->s_addr);
				task->queue[task->queue_head].tsc = now + task->delay_time;
				task->queue[task->queue_head].mbuf = mbufs[i];
				task->queue_head = (task->queue_head + 1) & task->queue_mask;
			}
			else {
				/* Rest does not fit, need to drop those packets. */
				enqueue_failed = i;
				for (;i < n_pkts; ++i) {
					out[i] = OUT_DISCARD;
				}
				ret+= task->base.tx_pkt(&task->base, mbufs + enqueue_failed,
					  	n_pkts - enqueue_failed, out + enqueue_failed);
				break;
			}
		}
	}

	struct rte_mbuf *new_mbufs[MAX_PKT_BURST];
	uint16_t idx = 0;

	if (task->tresh != RAND_MAX) {
		while (idx < MAX_PKT_BURST && task->queue_tail != task->queue_head) {
			if (task->queue[task->queue_tail].tsc <= now) {
				out[idx] = rand_r(&task->seed) <= task->tresh? 0 : OUT_DISCARD;
				new_mbufs[idx] = task->queue[task->queue_tail].mbuf;
				PREFETCH0(new_mbufs[idx]);
				PREFETCH0(&new_mbufs[idx]->cacheline1);
				idx++;
				task->queue_tail = (task->queue_tail + 1) & task->queue_mask;
			}
			else {
				break;
			}
		}
	} else {
		while (idx < MAX_PKT_BURST && task->queue_tail != task->queue_head) {
			if (task->queue[task->queue_tail].tsc <= now) {
				out[idx] = 0;
				new_mbufs[idx] = task->queue[task->queue_tail].mbuf;
				PREFETCH0(new_mbufs[idx]);
				PREFETCH0(&new_mbufs[idx]->cacheline1);
				idx++;
				task->queue_tail = (task->queue_tail + 1) & task->queue_mask;
			}
			else {
				break;
			}
		}
	}

	if (idx)
		ret+= task->base.tx_pkt(&task->base, new_mbufs, idx, out);
	task_impair_update(tbase);
	return ret;
}

/*
 * We want to avoid using division and mod for performance reasons.
 * We also want to support up to one second delay, and express it in tsc
 * So the delay in tsc needs up to 32 bits (supposing procesor freq is less than 4GHz).
 * If the max_delay is smaller, we make sure we use less bits.
 * Note that we lose the MSB of the xorshift - 64 bits could hold
 * two or three delays in TSC - but would probably make implementation more complex
 * and not huge gain expected. Maybe room for optimization.
 * Using this implementation, we might have to run random more than once for a delay
 * but in average this should occur less than 50% of the time.
*/

static inline uint64_t random_delay(struct random *state, uint64_t max_delay, uint64_t max_delay_mask)
{
	uint64_t val;
	while(1) {
		val = random_next(state);
		if ((val & max_delay_mask) < max_delay)
			return (val & max_delay_mask);
	}
}

static int handle_bulk_impair_random(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_impair *task = (struct task_impair *)tbase;
	uint64_t now = rte_rdtsc();
	uint8_t out[MAX_PKT_BURST];
	uint16_t enqueue_failed;
	uint16_t i;
	int ret = 0;
	uint64_t packet_time, idx;
	uint64_t now_idx = (now >> DELAY_ACCURACY) & DELAY_MAX_MASK;
	struct ether_hdr * hdr[MAX_PKT_BURST];
	for (uint16_t i = 0; i < n_pkts; ++i) {
		PREFETCH0(mbufs[i]);
	}
	for (uint16_t i = 0; i < n_pkts; ++i) {
		hdr[i] = rte_pktmbuf_mtod(mbufs[i], struct ether_hdr *);
		PREFETCH0(hdr[i]);
	}

	for (i = 0; i < n_pkts; ++i) {
		packet_time = now + random_delay(&task->state, task->delay_time, task->delay_time_mask);
		idx = (packet_time >> DELAY_ACCURACY) & DELAY_MAX_MASK;
		while (idx != ((now_idx - 1) & DELAY_MAX_MASK)) {
			struct queue *queue = &task->buffer[idx];
			if (((queue->queue_head + 1) & task->queue_mask) != queue->queue_tail) {
				if (task->flags & IMPAIR_SET_MAC)
					ether_addr_copy((struct ether_addr *)&task->src_mac[0], &hdr[i]->s_addr);
				queue->queue_elem[queue->queue_head].mbuf = mbufs[i];
				queue->queue_head = (queue->queue_head + 1) & task->queue_mask;
				break;
			} else {
				idx = (idx + 1) & DELAY_MAX_MASK;
			}
		}
		if (idx == ((now_idx - 1) & DELAY_MAX_MASK)) {
			/* Rest does not fit, need to drop packet. Note that further packets might fit as might want to be sent earlier */
			out[0] = OUT_DISCARD;
			ret+= task->base.tx_pkt(&task->base, mbufs + i, 1, out);
			plog_warn("Unexpectdly dropping packets\n");
		}
	}

	struct rte_mbuf *new_mbufs[MAX_PKT_BURST];
	uint16_t pkt_idx = 0;

	while ((pkt_idx < MAX_PKT_BURST) && (task->last_idx != ((now_idx - 1) & DELAY_MAX_MASK))) {
		struct queue *queue = &task->buffer[task->last_idx];
		while ((pkt_idx < MAX_PKT_BURST) && (queue->queue_tail != queue->queue_head)) {
			out[pkt_idx] = rand_r(&task->seed) <= task->tresh? 0 : OUT_DISCARD;
			new_mbufs[pkt_idx] = queue->queue_elem[queue->queue_tail].mbuf;
			PREFETCH0(new_mbufs[pkt_idx]);
			PREFETCH0(&new_mbufs[pkt_idx]->cacheline1);
			pkt_idx++;
			queue->queue_tail = (queue->queue_tail + 1) & task->queue_mask;
		}
		task->last_idx = (task->last_idx + 1) & DELAY_MAX_MASK;
	}

	if (pkt_idx)
		ret+= task->base.tx_pkt(&task->base, new_mbufs, pkt_idx, out);
	task_impair_update(tbase);
	return ret;
}

static void init_task(struct task_base *tbase, struct task_args *targ)
{
	struct task_impair *task = (struct task_impair *)tbase;
	uint32_t queue_len = 0;
	size_t mem_size;
	unsigned socket_id;
	uint64_t delay_us = 0;

	task->seed = rte_rdtsc();
	if (targ->probability == 0)
		targ->probability = 1000000;

	task->tresh = ((uint64_t) RAND_MAX) * targ->probability / 1000000;

	if ((targ->delay_us == 0) && (targ->random_delay_us == 0)) {
		tbase->handle_bulk = handle_bulk_random_drop;
		task->delay_time = 0;
	} else if (targ->random_delay_us) {
		tbase->handle_bulk = handle_bulk_impair_random;
		task->delay_time = usec_to_tsc(targ->random_delay_us);
		task->delay_time_mask = rte_align32pow2(task->delay_time) - 1;
		delay_us = targ->random_delay_us;
		queue_len = rte_align32pow2((1250L * delay_us) / 84 / (DELAY_MAX_MASK + 1));
	} else {
		task->delay_time = usec_to_tsc(targ->delay_us);
		delay_us = targ->delay_us;
		queue_len = rte_align32pow2(1250 * delay_us / 84);
	}
	/* Assume Line-rate is maximum transmit speed.
   	   TODO: take link speed if tx is port.
	*/
	if (queue_len < MAX_PKT_BURST)
		queue_len= MAX_PKT_BURST;
	task->queue_mask = queue_len - 1;
	if (task->queue_mask < MAX_PKT_BURST - 1)
		task->queue_mask = MAX_PKT_BURST - 1;

	mem_size = (task->queue_mask + 1) * sizeof(task->queue[0]);
	socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	task->socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	if (targ->delay_us) {
		task->queue = prox_zmalloc(mem_size, socket_id);
		PROX_PANIC(task->queue == NULL, "Not enough memory to allocate queue\n");
		task->queue_head = 0;
		task->queue_tail = 0;
	} else if (targ->random_delay_us) {
		size_t size = (DELAY_MAX_MASK + 1) * sizeof(struct queue);
		plog_info("Allocating %zd bytes\n", size);
		task->buffer = prox_zmalloc(size, socket_id);
		PROX_PANIC(task->buffer == NULL, "Not enough memory to allocate buffer\n");
		plog_info("Allocating %d x %zd bytes\n", DELAY_MAX_MASK + 1, mem_size);

		for (int i = 0; i < DELAY_MAX_MASK + 1; i++) {
			task->buffer[i].queue_elem = prox_zmalloc(mem_size, socket_id);
			PROX_PANIC(task->buffer[i].queue_elem == NULL, "Not enough memory to allocate buffer elems\n");
		}
	}
	random_init_seed(&task->state);
	if (targ->nb_txports) {
		memcpy(&task->src_mac[0], &prox_port_cfg[tbase->tx_params_hw.tx_port_queue[0].port].eth_addr, sizeof(struct ether_addr));
		task->flags = IMPAIR_SET_MAC;
	} else {
		task->flags = 0;
	}
}

static struct task_init tinit = {
	.mode_str = "impair",
	.init = init_task,
	.handle = handle_bulk_impair,
	.flag_features = TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS | TASK_FEATURE_ZERO_RX,
	.size = sizeof(struct task_impair)
};

__attribute__((constructor)) static void ctor(void)
{
	reg_task(&tinit);
}
