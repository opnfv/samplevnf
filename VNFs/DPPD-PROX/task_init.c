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
#include <rte_version.h>

#include "prox_port_cfg.h"
#include "prox_malloc.h"
#include "task_init.h"
#include "rx_pkt.h"
#include "tx_pkt.h"
#include "log.h"
#include "quit.h"
#include "lconf.h"
#include "thread_generic.h"
#include "prox_assert.h"

#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE
#endif

static unsigned first_task = 1;
LIST_HEAD(,task_init) head;

void reg_task(struct task_init* t)
{
	// PROX_PANIC(t->handle == NULL, "No handle function specified for task with name %d\n", t->mode);

	if (t->thread_x == NULL)
		t->thread_x = thread_generic;

	if (first_task) {
		first_task = 0;
		LIST_INIT(&head);
	}

	LIST_INSERT_HEAD(&head, t, entries);
}

struct task_init *to_task_init(const char *mode_str, const char *sub_mode_str)
{
	struct task_init *cur_t;

	LIST_FOREACH(cur_t, &head, entries) {
		if (!strcmp(mode_str, cur_t->mode_str) &&
		    !strcmp(sub_mode_str, cur_t->sub_mode_str)) {
			return cur_t;
		}
	}

	return NULL;
}

static int compare_strcmp(const void *a, const void *b)
{
	return strcmp(*(const char * const *)a, *(const char * const *)b);
}

int task_is_master(struct task_args *targ)
{
	return (targ->lconf->id == prox_cfg.master);
}

void tasks_list(void)
{
	struct task_init *cur_t;
	char buf[sizeof(cur_t->mode_str) + sizeof(cur_t->sub_mode_str) + 4];

	int nb_modes = 1; /* master */
	LIST_FOREACH(cur_t, &head, entries) {
		++nb_modes;
	}

	char **modes = calloc(nb_modes, sizeof(*modes));
	char **cur_m = modes;
	*cur_m++ = strdup("master");
	LIST_FOREACH(cur_t, &head, entries) {
		snprintf(buf, sizeof(buf), "%s%s%s",
			cur_t->mode_str,
			(cur_t->sub_mode_str[0] == 0) ? "" : " / ",
			cur_t->sub_mode_str);
		*cur_m++ = strdup(buf);
	}
	qsort(modes, nb_modes, sizeof(*modes), compare_strcmp);

	plog_info("=== List of supported task modes / sub modes ===\n");
	for (cur_m = modes; nb_modes; ++cur_m, --nb_modes) {
		plog_info("\t%s\n", *cur_m);
		free(*cur_m);
	}
	free(modes);
}

static size_t calc_memsize(struct task_args *targ, size_t task_size)
{
	size_t memsize = task_size;

	memsize += sizeof(struct task_base_aux);

	if (targ->nb_rxports != 0) {
		memsize += 2 * sizeof(uint8_t)*targ->nb_rxports;
	}
	if (targ->nb_rxrings != 0 || targ->tx_opt_ring_task) {
		memsize += sizeof(struct rte_ring *)*targ->nb_rxrings;
	}
	if (targ->nb_txrings != 0) {
		memsize += sizeof(struct rte_ring *) * targ->nb_txrings;
		memsize = RTE_ALIGN_CEIL(memsize, RTE_CACHE_LINE_SIZE);
		memsize += sizeof(struct ws_mbuf) + sizeof(((struct ws_mbuf*)0)->mbuf[0]) * targ->nb_txrings;
	}
	else if (targ->nb_txports != 0) {
		memsize += sizeof(struct port_queue) * targ->nb_txports;
		memsize = RTE_ALIGN_CEIL(memsize, RTE_CACHE_LINE_SIZE);
		memsize += sizeof(struct ws_mbuf) + sizeof(((struct ws_mbuf*)0)->mbuf[0]) * targ->nb_txports;
	}
	else {
		memsize = RTE_ALIGN_CEIL(memsize, RTE_CACHE_LINE_SIZE);
		memsize += sizeof(struct ws_mbuf) + sizeof(((struct ws_mbuf*)0)->mbuf[0]);
	}

	return memsize;
}

static void *flush_function(struct task_args *targ)
{
	if (targ->flags & TASK_ARG_DROP) {
		return targ->nb_txrings ? flush_queues_sw : flush_queues_hw;
	}
	else {
		return targ->nb_txrings ? flush_queues_no_drop_sw : flush_queues_no_drop_hw;
	}
}

static size_t init_rx_tx_rings_ports(struct task_args *targ, struct task_base *tbase, size_t offset)
{
	if (targ->tx_opt_ring_task) {
		tbase->rx_pkt = rx_pkt_self;
	}
	else if (targ->nb_rxrings != 0) {

		if (targ->nb_rxrings == 1) {
			tbase->rx_pkt = rx_pkt_sw1;
			tbase->rx_params_sw1.rx_ring = targ->rx_rings[0];
		}
		else {
			tbase->rx_pkt = rx_pkt_sw;
			tbase->rx_params_sw.nb_rxrings = targ->nb_rxrings;
			tbase->rx_params_sw.rx_rings = (struct rte_ring **)(((uint8_t *)tbase) + offset);
			offset += sizeof(struct rte_ring *)*tbase->rx_params_sw.nb_rxrings;

			for (uint8_t i = 0; i < tbase->rx_params_sw.nb_rxrings; ++i) {
				tbase->rx_params_sw.rx_rings[i] = targ->rx_rings[i];
			}

			if (rte_is_power_of_2(targ->nb_rxrings)) {
				tbase->rx_pkt = rx_pkt_sw_pow2;
				tbase->rx_params_sw.rxrings_mask = targ->nb_rxrings - 1;
			}
		}
	}
	else {
		if (targ->nb_rxports == 1) {
			if (targ->flags & TASK_ARG_L3)
				tbase->rx_pkt = (targ->task_init->flag_features & TASK_FEATURE_MULTI_RX)? rx_pkt_hw1_multi_l3 : rx_pkt_hw1_l3;
			else
				tbase->rx_pkt = (targ->task_init->flag_features & TASK_FEATURE_MULTI_RX)? rx_pkt_hw1_multi : rx_pkt_hw1;
			tbase->rx_params_hw1.rx_pq.port =  targ->rx_port_queue[0].port;
			tbase->rx_params_hw1.rx_pq.queue = targ->rx_port_queue[0].queue;
		}
		else {
			PROX_ASSERT((targ->nb_rxports != 0) || (targ->task_init->flag_features & TASK_FEATURE_NO_RX));
			if (targ->flags & TASK_ARG_L3)
				tbase->rx_pkt = (targ->task_init->flag_features & TASK_FEATURE_MULTI_RX)? rx_pkt_hw_multi_l3 : rx_pkt_hw_l3;
			else
				tbase->rx_pkt = (targ->task_init->flag_features & TASK_FEATURE_MULTI_RX)? rx_pkt_hw_multi : rx_pkt_hw;
			tbase->rx_params_hw.nb_rxports = targ->nb_rxports;
			tbase->rx_params_hw.rx_pq = (struct port_queue *)(((uint8_t *)tbase) + offset);
			offset += sizeof(struct port_queue) * tbase->rx_params_hw.nb_rxports;
			for (int i = 0; i< targ->nb_rxports; i++) {
				tbase->rx_params_hw.rx_pq[i].port = targ->rx_port_queue[i].port;
				tbase->rx_params_hw.rx_pq[i].queue = targ->rx_port_queue[i].queue;
			}

			if (rte_is_power_of_2(targ->nb_rxports)) {
				if (targ->flags & TASK_ARG_L3)
					tbase->rx_pkt = (targ->task_init->flag_features & TASK_FEATURE_MULTI_RX)? rx_pkt_hw_pow2_multi_l3 : rx_pkt_hw_pow2_l3;
				else
					tbase->rx_pkt = (targ->task_init->flag_features & TASK_FEATURE_MULTI_RX)? rx_pkt_hw_pow2_multi : rx_pkt_hw_pow2;
				tbase->rx_params_hw.rxport_mask = targ->nb_rxports - 1;
			}
		}
	}

	if ((targ->nb_txrings != 0) && (!targ->tx_opt_ring) && (!(targ->flags & TASK_ARG_DROP))) {
		// Transmitting to a ring in NO DROP. We need to make sure the receiving task in not running on the same core.
		// Otherwise we might end up in a dead lock: trying in a loop to transmit to a task which cannot receive anymore
		// (as not being scheduled).
		struct core_task ct;
		struct task_args *dtarg;
		for (unsigned int j = 0; j < targ->nb_txrings; j++) {
			ct = targ->core_task_set[0].core_task[j];
			PROX_PANIC(ct.core == targ->lconf->id, "Core %d, task %d: NO_DROP task transmitting to another task (core %d, task %d) running on on same core => potential deadlock\n", targ->lconf->id, targ->id, ct.core, ct.task);
			//plog_info("Core %d, task %d: NO_DROP task transmitting to another task (core %d, task %d) running on on same core => potential deadlock\n", targ->lconf->id, targ->id, ct.core, ct.task);
		}
	}
	if ((targ->nb_txrings != 0) && (targ->nb_txports == 1)) {
		/* Transmitting to multiple rings and one port */
		plog_info("Initializing with 1 port %d queue %d nb_rings=%d\n", targ->tx_port_queue[0].port, targ->tx_port_queue[0].queue, targ->nb_txrings);
		tbase->tx_params_hw_sw.tx_port_queue.port =  targ->tx_port_queue[0].port;
		tbase->tx_params_hw_sw.tx_port_queue.queue =  targ->tx_port_queue[0].queue;
		if (!targ->tx_opt_ring) {
			tbase->tx_params_hw_sw.nb_txrings = targ->nb_txrings;
			tbase->tx_params_hw_sw.tx_rings = (struct rte_ring **)(((uint8_t *)tbase) + offset);
			offset += sizeof(struct rte_ring *)*tbase->tx_params_hw_sw.nb_txrings;

			for (uint8_t i = 0; i < tbase->tx_params_hw_sw.nb_txrings; ++i) {
				tbase->tx_params_hw_sw.tx_rings[i] = targ->tx_rings[i];
			}

			offset = RTE_ALIGN_CEIL(offset, RTE_CACHE_LINE_SIZE);
			tbase->ws_mbuf = (struct ws_mbuf *)(((uint8_t *)tbase) + offset);
			offset += sizeof(struct ws_mbuf) + sizeof(((struct ws_mbuf*)0)->mbuf[0]) * tbase->tx_params_hw_sw.nb_txrings;
		}
	}
	else if (!targ->tx_opt_ring) {
		if (targ->nb_txrings != 0) {
			tbase->tx_params_sw.nb_txrings = targ->nb_txrings;
			tbase->tx_params_sw.tx_rings = (struct rte_ring **)(((uint8_t *)tbase) + offset);
			offset += sizeof(struct rte_ring *)*tbase->tx_params_sw.nb_txrings;

			for (uint8_t i = 0; i < tbase->tx_params_sw.nb_txrings; ++i) {
				tbase->tx_params_sw.tx_rings[i] = targ->tx_rings[i];
			}

			offset = RTE_ALIGN_CEIL(offset, RTE_CACHE_LINE_SIZE);
			tbase->ws_mbuf = (struct ws_mbuf *)(((uint8_t *)tbase) + offset);
			offset += sizeof(struct ws_mbuf) + sizeof(((struct ws_mbuf*)0)->mbuf[0]) * tbase->tx_params_sw.nb_txrings;
		}
		else if (targ->nb_txports != 0) {
			tbase->tx_params_hw.nb_txports = targ->nb_txports;
			tbase->tx_params_hw.tx_port_queue = (struct port_queue *)(((uint8_t *)tbase) + offset);
			offset += sizeof(struct port_queue) * tbase->tx_params_hw.nb_txports;
			for (uint8_t i = 0; i < tbase->tx_params_hw.nb_txports; ++i) {
				tbase->tx_params_hw.tx_port_queue[i].port = targ->tx_port_queue[i].port;
				tbase->tx_params_hw.tx_port_queue[i].queue = targ->tx_port_queue[i].queue;
			}

			offset = RTE_ALIGN_CEIL(offset, RTE_CACHE_LINE_SIZE);
			tbase->ws_mbuf = (struct ws_mbuf *)(((uint8_t *)tbase) + offset);
			offset += sizeof(struct ws_mbuf) + sizeof(((struct ws_mbuf*)0)->mbuf[0]) * tbase->tx_params_hw.nb_txports;
		}
		else {
			offset = RTE_ALIGN_CEIL(offset, RTE_CACHE_LINE_SIZE);
			tbase->ws_mbuf = (struct ws_mbuf *)(((uint8_t *)tbase) + offset);
			offset += sizeof(struct ws_mbuf) + sizeof(((struct ws_mbuf*)0)->mbuf[0]);
		}

		struct ws_mbuf* w = tbase->ws_mbuf;
		struct task_args *prev = targ->tx_opt_ring_task;

		while (prev) {
			prev->tbase->ws_mbuf = w;
			prev = prev->tx_opt_ring_task;
		}
	}

	if (targ->nb_txrings == 1 || targ->nb_txports == 1 || targ->tx_opt_ring) {
		if (targ->task_init->flag_features & TASK_FEATURE_NEVER_DISCARDS) {
			if (targ->tx_opt_ring) {
				tbase->tx_pkt = tx_pkt_never_discard_self;
			}
			else if (targ->flags & TASK_ARG_DROP) {
				if (targ->task_init->flag_features & TASK_FEATURE_THROUGHPUT_OPT)
					tbase->tx_pkt = targ->nb_txrings ? tx_pkt_never_discard_sw1 : tx_pkt_never_discard_hw1_thrpt_opt;
				else
					tbase->tx_pkt = targ->nb_txrings ? tx_pkt_never_discard_sw1 : tx_pkt_never_discard_hw1_lat_opt;
			}
			else {
				if (targ->task_init->flag_features & TASK_FEATURE_THROUGHPUT_OPT)
					tbase->tx_pkt = targ->nb_txrings ? tx_pkt_no_drop_never_discard_sw1 : tx_pkt_no_drop_never_discard_hw1_thrpt_opt;
				else
					tbase->tx_pkt = targ->nb_txrings ? tx_pkt_no_drop_never_discard_sw1 : tx_pkt_no_drop_never_discard_hw1_lat_opt;
			}
			if ((targ->nb_txrings) || ((targ->task_init->flag_features & TASK_FEATURE_THROUGHPUT_OPT) == 0))
	        		tbase->flags |= FLAG_NEVER_FLUSH;
			else
				targ->lconf->flush_queues[targ->task] = flush_function(targ);
		}
		else {
			if (targ->tx_opt_ring) {
				tbase->tx_pkt = tx_pkt_self;
			}
			else if (targ->flags & TASK_ARG_DROP) {
				tbase->tx_pkt = targ->nb_txrings ? tx_pkt_sw1 : tx_pkt_hw1;
			}
			else {
				tbase->tx_pkt = targ->nb_txrings ? tx_pkt_no_drop_sw1 : tx_pkt_no_drop_hw1;
			}
	        	tbase->flags |= FLAG_NEVER_FLUSH;
		}
	}
	else {
		if (targ->flags & TASK_ARG_DROP) {
			tbase->tx_pkt = targ->nb_txrings ? tx_pkt_sw : tx_pkt_hw;
		}
		else {
			tbase->tx_pkt = targ->nb_txrings ? tx_pkt_no_drop_sw : tx_pkt_no_drop_hw;
		}

		targ->lconf->flush_queues[targ->task] = flush_function(targ);
	}

	if (targ->task_init->flag_features & TASK_FEATURE_NO_RX) {
		tbase->rx_pkt = rx_pkt_dummy;
	}

	if (targ->nb_txrings == 0 && targ->nb_txports == 0) {
		tbase->tx_pkt = tx_pkt_drop_all;
	}

	return offset;
}

struct task_base *init_task_struct(struct task_args *targ)
{
	struct task_init* t = targ->task_init;
	size_t offset = 0;
	size_t memsize = calc_memsize(targ, t->size);
	uint8_t task_socket = rte_lcore_to_socket_id(targ->lconf->id);
	struct task_base *tbase = prox_zmalloc(memsize, task_socket);
	PROX_PANIC(tbase == NULL, "Failed to allocate memory for task (%zu bytes)", memsize);
	offset += t->size;

	if (targ->nb_txrings == 0 && targ->nb_txports == 0)
		tbase->flags |= FLAG_NEVER_FLUSH;

	offset = init_rx_tx_rings_ports(targ, tbase, offset);
	tbase->aux = (struct task_base_aux *)(((uint8_t *)tbase) + offset);

	if (targ->task_init->flag_features & TASK_FEATURE_TSC_RX) {
		task_base_add_rx_pkt_function(tbase, rx_pkt_tsc);
	}

	offset += sizeof(struct task_base_aux);

	tbase->handle_bulk = t->handle;

	if (targ->flags & TASK_ARG_L3) {
		plog_info("\tTask configured in L3 mode\n");
		tbase->l3.ctrl_plane_ring = targ->ctrl_plane_ring;
		if (targ->nb_txports != 0) {
			tbase->aux->tx_pkt_l2 = tbase->tx_pkt;
			tbase->tx_pkt = tx_pkt_l3;
			// Make sure control plane packets such as arp are not dropped
			tbase->aux->tx_ctrlplane_pkt = targ->nb_txrings ? tx_ctrlplane_sw : tx_ctrlplane_hw;
			task_init_l3(tbase, targ);
		}
	}

	targ->tbase = tbase;
	if (t->init) {
		t->init(tbase, targ);
	}
	tbase->aux->start = t->start;
	tbase->aux->stop = t->stop;
	tbase->aux->start_first = t->start_first;
	tbase->aux->stop_last = t->stop_last;
	if ((targ->nb_txrings != 0) && (targ->nb_txports == 1)) {
		tbase->aux->tx_pkt_hw = tx_pkt_no_drop_never_discard_hw1_no_pointer;
	}
	if (targ->tx_opt_ring) {
		tbase->aux->tx_pkt_try = tx_try_self;
	} else if (targ->nb_txrings == 1) {
		tbase->aux->tx_pkt_try = tx_try_sw1;
	} else if (targ->nb_txports) {
		tbase->aux->tx_pkt_try = tx_try_hw1;
	}

	return tbase;
}

struct task_args *find_reachable_task_sending_to_port(struct task_args *from)
{
	if (!from->nb_txrings) {
		if (from->tx_port_queue[0].port != OUT_DISCARD)
			return from;
		else
			return NULL;
	}

	struct core_task ct;
	struct task_args *dtarg, *ret;

	for (uint32_t i = 0; i < from->nb_txrings; ++i) {
		ct = from->core_task_set[0].core_task[i];
		dtarg = core_targ_get(ct.core, ct.task);
		ret = find_reachable_task_sending_to_port(dtarg);
		if (ret)
			return ret;
	}
	return NULL;
}

struct prox_port_cfg *find_reachable_port(struct task_args *from)
{
	struct task_args *dst = find_reachable_task_sending_to_port(from);

	if (dst) {
		int port_id = dst->tx_port_queue[0].port;

		return &prox_port_cfg[port_id];
	}
	return NULL;
}
