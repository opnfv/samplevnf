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

#ifndef _STATS_TASK_H_
#define _STATS_TASK_H_

#include <inttypes.h>

#include "clock.h"

/* The struct task_stats is read/write from the task itself and
   read-only from the core that collects the stats. Since only the
   task executing the actual work ever modifies the stats, no locking
   is required. Both a read and a write are atomic (assuming the
   correct alignment). From this, it followed that the statistics can
   be incremented directly by the task itself. In cases where these
   assumptions do not hold, a possible solution (although slightly
   less accurate) would be to keep accumulate statistics temporarily
   in a separate structure and periodically copying the statistics to
   the statistics core through atomic primitives, for example through
   rte_atomic32_set(). The accuracy would be determined by the
   frequency at which the statistics are transferred to the statistics
   core. */

struct task_rt_stats {
	uint32_t	rx_pkt_count;
	uint32_t	tx_pkt_count;
	uint32_t	drop_tx_fail;
	uint32_t	drop_discard;
	uint32_t        drop_handled;
	uint32_t	idle_cycles;
	uint64_t        rx_bytes;
	uint64_t        tx_bytes;
	uint64_t        drop_bytes;
	uint64_t        rx_non_dp;
	uint64_t        tx_non_dp;
} __attribute__((packed)) __rte_cache_aligned;

#ifdef PROX_STATS
#define TASK_STATS_ADD_IDLE(stats, cycles) do {				\
		(stats)->idle_cycles += (cycles) + rdtsc_overhead_stats; \
	} while(0)							\

#define TASK_STATS_ADD_TX(stats, ntx) do {	\
		(stats)->tx_pkt_count += ntx;	\
	} while(0)				\

#define TASK_STATS_ADD_DROP_TX_FAIL(stats, ntx) do {	\
		(stats)->drop_tx_fail += ntx;		\
	} while(0)					\

#define TASK_STATS_ADD_DROP_HANDLED(stats, ntx) do {	\
		(stats)->drop_handled += ntx;		\
	} while(0)					\

#define TASK_STATS_ADD_DROP_DISCARD(stats, ntx) do {	\
		(stats)->drop_discard += ntx;		\
	} while(0)					\

#define TASK_STATS_ADD_RX(stats, ntx) do {	\
		(stats)->rx_pkt_count += ntx;	\
	} while (0)				\

#define TASK_STATS_ADD_RX_NON_DP(stats, ntx) do {    	\
		(stats)->rx_non_dp += ntx;             \
	} while(0)

#define TASK_STATS_ADD_TX_NON_DP(stats, ntx) do {     	\
		(stats)->tx_non_dp += ntx;		\
	 } while(0)

#define TASK_STATS_ADD_RX_BYTES(stats, bytes) do {	\
		(stats)->rx_bytes += bytes;		\
	} while (0)					\

#define TASK_STATS_ADD_TX_BYTES(stats, bytes) do {	\
		(stats)->tx_bytes += bytes;		\
	} while (0)					\

#define TASK_STATS_ADD_DROP_BYTES(stats, bytes) do {	\
		(stats)->drop_bytes += bytes;		\
	} while (0)					\

#define START_EMPTY_MEASSURE() uint64_t cur_tsc = rte_rdtsc();
#else
#define TASK_STATS_ADD_IDLE(stats, cycles) do {} while(0)
#define TASK_STATS_ADD_TX(stats, ntx)  do {} while(0)
#define TASK_STATS_ADD_DROP_TX_FAIL(stats, ntx)  do {} while(0)
#define TASK_STATS_ADD_DROP_HANDLED(stats, ntx)  do {} while(0)
#define TASK_STATS_ADD_DROP_DISCARD(stats, ntx)  do {} while(0)
#define TASK_STATS_ADD_RX(stats, ntx)  do {} while(0)
#define TASK_STATS_ADD_RX_BYTES(stats, bytes)  do {} while(0)
#define TASK_STATS_ADD_TX_BYTES(stats, bytes)  do {} while(0)
#define TASK_STATS_ADD_DROP_BYTES(stats, bytes) do {} while(0)
#define START_EMPTY_MEASSURE()  do {} while(0)
#endif

struct task_stats_sample {
	uint64_t tsc;
	uint32_t tx_pkt_count;
	uint32_t drop_tx_fail;
	uint32_t drop_discard;
	uint32_t drop_handled;
	uint32_t rx_pkt_count;
	uint32_t empty_cycles;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
	uint64_t drop_bytes;
	uint64_t rx_non_dp;
	uint64_t tx_non_dp;
};

struct task_stats {
	uint64_t tot_tx_pkt_count;
	uint64_t tot_drop_tx_fail;
	uint64_t tot_drop_discard;
	uint64_t tot_drop_handled;
	uint64_t tot_rx_pkt_count;
	uint64_t tot_tx_non_dp;
	uint64_t tot_rx_non_dp;

	struct task_stats_sample sample[2];

	struct task_rt_stats *stats;
	/* flags set if total RX/TX values need to be reported set at
	   initialization time, only need to access stats values in port */
	uint8_t flags;
};

void stats_task_reset(void);
void stats_task_post_proc(void);
void stats_task_update(void);
void stats_task_init(void);

int stats_get_n_tasks_tot(void);

struct task_stats *stats_get_task_stats(uint32_t lcore_id, uint32_t task_id);
struct task_stats_sample *stats_get_task_stats_sample(uint32_t lcore_id, uint32_t task_id, int last);
void stats_task_get_host_rx_tx_packets(uint64_t *rx, uint64_t *tx, uint64_t *tsc);

uint64_t stats_core_task_tot_rx(uint8_t lcore_id, uint8_t task_id);
uint64_t stats_core_task_tot_tx(uint8_t lcore_id, uint8_t task_id);
uint64_t stats_core_task_tot_tx_fail(uint8_t lcore_id, uint8_t task_id);
uint64_t stats_core_task_tot_drop(uint8_t lcore_id, uint8_t task_id);
uint64_t stats_core_task_last_tsc(uint8_t lcore_id, uint8_t task_id);
uint64_t stats_core_task_tot_rx_non_dp(uint8_t lcore_id, uint8_t task_id);
uint64_t stats_core_task_tot_tx_non_dp(uint8_t lcore_id, uint8_t task_id);

#endif /* _STATS_TASK_H_ */
