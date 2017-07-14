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
#include <rte_cycles.h>
#include <inttypes.h>

#include "stats_global.h"
#include "stats_port.h"
#include "stats_task.h"

struct global_stats {
	struct global_stats_sample sample[2];
	struct global_stats_sample beg;
	uint8_t  started_avg;
	uint64_t start_tsc;
	uint64_t end_tsc;
};

extern int last_stat;
static struct global_stats global_stats;

uint64_t stats_get_last_tsc(void)
{
	return global_stats.sample[last_stat].tsc;
}

uint64_t stats_global_start_tsc(void)
{
	return global_stats.start_tsc;
}

uint64_t stats_global_beg_tsc(void)
{
	return global_stats.beg.tsc;
}

uint64_t stats_global_end_tsc(void)
{
	return global_stats.end_tsc;
}

struct global_stats_sample *stats_get_global_stats(int last)
{
	return &global_stats.sample[last == last_stat];
}

struct global_stats_sample *stats_get_global_stats_beg(void)
{
	return (global_stats.beg.tsc < global_stats.sample[last_stat].tsc)? &global_stats.beg : NULL;
}

void stats_global_reset(void)
{
	uint64_t now = rte_rdtsc();
	uint64_t last_tsc = global_stats.sample[last_stat].tsc;
	uint64_t prev_tsc = global_stats.sample[!last_stat].tsc;
	uint64_t end_tsc = global_stats.end_tsc;

	memset(&global_stats, 0, sizeof(struct global_stats));
	global_stats.sample[last_stat].tsc = last_tsc;
	global_stats.sample[!last_stat].tsc = prev_tsc;
	global_stats.start_tsc = now;
	global_stats.beg.tsc = now;
	global_stats.end_tsc = end_tsc;
}

void stats_global_init(unsigned avg_start, unsigned duration)
{
	uint64_t now = rte_rdtsc();

	global_stats.start_tsc = now;
	/* + 1 for rounding */
	tsc_hz = rte_get_tsc_hz();
	if (duration)
		global_stats.end_tsc = global_stats.start_tsc + (avg_start + duration + 1) * tsc_hz;

	global_stats.beg.tsc = global_stats.start_tsc + avg_start * tsc_hz;
}

void stats_global_post_proc(void)
{
	uint64_t *rx = &global_stats.sample[last_stat].host_rx_packets;
	uint64_t *tx = &global_stats.sample[last_stat].host_tx_packets;
	uint64_t *tsc = &global_stats.sample[last_stat].tsc;

	stats_task_get_host_rx_tx_packets(rx, tx, tsc);
	global_stats.sample[last_stat].nics_ierrors    = stats_port_get_ierrors();
	global_stats.sample[last_stat].nics_imissed    = stats_port_get_imissed();
	global_stats.sample[last_stat].nics_rx_packets = stats_port_get_rx_packets();
	global_stats.sample[last_stat].nics_tx_packets = stats_port_get_tx_packets();

	if (global_stats.sample[last_stat].tsc > global_stats.beg.tsc && !global_stats.started_avg) {
		global_stats.started_avg = 1;
		global_stats.beg = global_stats.sample[last_stat];
	}
}
