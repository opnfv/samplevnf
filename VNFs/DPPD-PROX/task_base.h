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

#ifndef _TASK_BASE_H_
#define _TASK_BASE_H_

#include <rte_common.h>
#ifndef __rte_cache_aligned
#include <rte_memory.h>
#endif

#include "defaults.h"
#include "prox_globals.h"
#include "stats_task.h"
#include "packet_utils.h"

// runtime_flags 16 bits only
#define TASK_MPLS_TAGGING              0x0001
#define TASK_ROUTING                   0x0002
#define TASK_CLASSIFY                  0x0004
#define TASK_CTRL_HANDLE_ARP           0x0008
#define TASK_MARK                      0x0020
#define TASK_FP_HANDLE_ARP             0x0040
#define TASK_TX_CRC                    0x0080
#define TASK_L3                        0x0100

// flag_features 64 bits
#define TASK_FEATURE_ROUTING           0x0001
#define TASK_FEATURE_CLASSIFY          0x0002
#define TASK_FEATURE_MULTI_RX                  0x0004
#define TASK_FEATURE_NEVER_DISCARDS            0x0008
#define TASK_FEATURE_NO_RX                     0x0010
#define TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS      0x0020
#define TASK_FEATURE_TXQ_FLAGS_MULTSEGS        0x0040
#define TASK_FEATURE_ZERO_RX                   0x0080
#define TASK_FEATURE_TXQ_FLAGS_REFCOUNT        0x0100
#define TASK_FEATURE_TSC_RX                    0x0200
#define TASK_FEATURE_THROUGHPUT_OPT            0x0400
#define TASK_FEATURE_GRE_ID                    0x1000
#define TASK_FEATURE_LUT_QINQ_RSS              0x2000
#define TASK_FEATURE_LUT_QINQ_HASH             0x4000
#define TASK_FEATURE_RX_ALL                    0x8000
#define TASK_MULTIPLE_MAC                      0x10000
#define TASK_FEATURE_TXQ_FLAGS_MULTIPLE_MEMPOOL	0x20000

#define FLAG_TX_FLUSH                  0x01
#define FLAG_NEVER_FLUSH               0x02
// Task specific flags
#define BASE_FLAG_LUT_QINQ_HASH       	0x08
#define BASE_FLAG_LUT_QINQ_RSS       	0x10

#define OUT_DISCARD 0xFF
#define OUT_HANDLED 0xFE

#define WS_MBUF_MASK (2 * MAX_PKT_BURST - 1)

/* struct ws_mbuf stores the working set of mbufs. It starts with a
   prod/cons index to keep track of the number of elemenets. */
struct ws_mbuf {
	struct {
		uint16_t        prod;
		uint16_t        cons;
	        uint16_t        nb_rx;
		uint16_t        pad; /* reserved */
	} idx[MAX_RINGS_PER_TASK];
	struct rte_mbuf *mbuf[][MAX_RING_BURST * 3]  __rte_cache_aligned;
};

struct port_queue {
	uint8_t port;
	uint8_t queue;
} __attribute__((packed));

struct rx_params_hw {
	union {
		uint8_t           nb_rxports;
		uint8_t           rxport_mask;
	};
	uint8_t           last_read_portid;
	struct port_queue *rx_pq;
} __attribute__((packed));

struct rx_params_hw1 {
	struct port_queue rx_pq;
} __attribute__((packed));

struct rx_params_sw {
	union {
		uint8_t         nb_rxrings;
		uint8_t         rxrings_mask; /* Used if rte_is_power_of_2(nb_rxrings)*/
	};
	uint8_t         last_read_ring;
	struct rte_ring **rx_rings;
} __attribute__((packed));

/* If there is only one input ring, the pointer to it can be stored
   directly into the task_base instead of having to use a pointer to a
   set of rings which would require two dereferences. */
struct rx_params_sw1 {
	struct rte_ring *rx_ring;
} __attribute__((packed));

struct tx_params_hw {
	uint16_t          nb_txports;
	struct port_queue *tx_port_queue;
} __attribute__((packed));

struct tx_params_sw {
	uint16_t         nb_txrings;
	struct rte_ring **tx_rings;
} __attribute__((packed));

struct tx_params_hw_sw {	/* Only one port supported in this mode */
	uint16_t         nb_txrings;
	struct rte_ring **tx_rings;
	struct port_queue tx_port_queue;
} __attribute__((packed));

struct task_rt_dump {
	uint32_t n_print_rx;
	uint32_t n_print_tx;
	struct input *input;
	uint32_t n_trace;
	uint32_t cur_trace;
	void     *pkt_mbuf_addr[MAX_RING_BURST]; /* To track reordering */
	uint8_t  pkt_cpy[MAX_RING_BURST][DUMP_PKT_LEN];
	uint16_t pkt_cpy_len[MAX_RING_BURST];
};

struct task_base;

#define MAX_RX_PKT_ALL 16384

#define RX_BUCKET_SIZE (2 * MAX_RING_BURST + 1) /* Limit RX bucket size */
#define TX_BUCKET_SIZE	(MAX_RING_BURST +1)

#define MAX_STACKED_RX_FUCTIONS 16

typedef uint16_t (*rx_pkt_func) (struct task_base *tbase, struct rte_mbuf ***mbufs);

struct task_base_aux {
	/* Not used when PROX_STATS is not defined */
	struct task_rt_stats stats;

	/* Used if TASK_TSC_RX is enabled*/
	struct {
		uint64_t before;
		uint64_t after;
	} tsc_rx;

	struct  rte_mbuf **all_mbufs;

	uint16_t      rx_prev_count;
	uint16_t      rx_prev_idx;
	uint16_t (*rx_pkt_prev[MAX_STACKED_RX_FUCTIONS])(struct task_base *tbase, struct rte_mbuf ***mbufs);

	uint32_t rx_bucket[RX_BUCKET_SIZE];
	uint32_t tx_bucket[TX_BUCKET_SIZE];
	int (*tx_pkt_l2)(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);
	int (*tx_pkt_orig)(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);
	int (*tx_pkt_hw)(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);
	uint16_t (*tx_pkt_try)(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts);
	void (*stop)(struct task_base *tbase);
	int (*tx_ctrlplane_pkt)(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);
	void (*start)(struct task_base *tbase);
	void (*stop_last)(struct task_base *tbase);
	void (*start_first)(struct task_base *tbase);
	struct task_rt_dump task_rt_dump;
};

/* The task_base is accessed for _all_ task types. In case
   no debugging or l3 is needed, it has been optimized to fit
   into a single cache line to minimize cache pollution */
struct task_base {
	int (*handle_bulk)(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts);
	int (*tx_pkt)(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);
	uint16_t (*rx_pkt)(struct task_base *tbase, struct rte_mbuf ***mbufs);

	struct task_base_aux* aux;
	/* The working set of mbufs contains mbufs that are currently
	   being handled. */
	struct ws_mbuf *ws_mbuf;

	uint16_t flags;

	union {
		struct rx_params_hw rx_params_hw;
		struct rx_params_hw1 rx_params_hw1;
		struct rx_params_sw rx_params_sw;
		struct rx_params_sw1 rx_params_sw1;
	};

	union {
		struct tx_params_hw tx_params_hw;
		struct tx_params_sw tx_params_sw;
		struct tx_params_hw_sw tx_params_hw_sw;
	};
	struct l3_base l3;
	uint32_t local_ipv4;
} __attribute__((packed)) __rte_cache_aligned;

static void task_base_add_rx_pkt_function(struct task_base *tbase, rx_pkt_func to_add)
{
	if (tbase->aux->rx_prev_count == MAX_STACKED_RX_FUCTIONS) {
		return;
	}

	for (int16_t i = tbase->aux->rx_prev_count; i > 0; --i) {
		tbase->aux->rx_pkt_prev[i] = tbase->aux->rx_pkt_prev[i - 1];
	}
	tbase->aux->rx_pkt_prev[0] = tbase->rx_pkt;
	tbase->rx_pkt = to_add;
	tbase->aux->rx_prev_count++;
}

static void task_base_del_rx_pkt_function(struct task_base *tbase, rx_pkt_func to_del)
{
	int cur = 0;
	int found = 0;

	if (unlikely(tbase->aux->rx_prev_count == 0)) {
		return;
	} else if (tbase->rx_pkt == to_del) {
		tbase->rx_pkt = tbase->aux->rx_pkt_prev[0];
		for (int16_t i = 0; i < tbase->aux->rx_prev_count - 1; ++i) {
			tbase->aux->rx_pkt_prev[i] = tbase->aux->rx_pkt_prev[i + 1];
		}
		found = 1;
	} else {
		for (int16_t i = 0; i < tbase->aux->rx_prev_count; ++i) {
			if (found || tbase->aux->rx_pkt_prev[i] != to_del)
				tbase->aux->rx_pkt_prev[cur++] = tbase->aux->rx_pkt_prev[i];
			else
				found = 1;
		}
	}
	if (found)
		tbase->aux->rx_prev_count--;
}

static rx_pkt_func task_base_get_original_rx_pkt_function(struct task_base *tbase)
{
	if (tbase->aux->rx_prev_count == 0)
		return tbase->rx_pkt;
	else
		return tbase->aux->rx_pkt_prev[tbase->aux->rx_prev_count - 1];
}

#endif /* _TASK_BASE_H_ */
