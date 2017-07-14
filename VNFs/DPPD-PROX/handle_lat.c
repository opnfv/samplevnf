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

//#define LAT_DEBUG

#include <rte_cycles.h>
#include <stdio.h>
#include <math.h>

#include "handle_gen.h"
#include "prox_malloc.h"
#include "mbuf_utils.h"
#include "handle_lat.h"
#include "log.h"
#include "task_init.h"
#include "task_base.h"
#include "stats.h"
#include "lconf.h"
#include "quit.h"
#include "eld.h"
#include "prox_shared.h"

#define DEFAULT_BUCKET_SIZE	10

struct lat_info {
	uint32_t rx_packet_index;
	uint32_t tx_packet_index;
	uint32_t tx_err;
	uint32_t rx_err;
	uint64_t rx_time;
	uint64_t tx_time;
	uint16_t port_queue_id;
#ifdef LAT_DEBUG
	uint16_t id_in_bulk;
	uint16_t bulk_size;
	uint64_t begin;
	uint64_t after;
	uint64_t before;
#endif
};

struct delayed_latency_entry {
	uint32_t rx_packet_idx;
	uint64_t pkt_rx_time;
	uint64_t pkt_tx_time;
	uint64_t rx_time_err;
};

struct delayed_latency {
	struct delayed_latency_entry entries[64];
};

static struct delayed_latency_entry *delayed_latency_get(struct delayed_latency *delayed_latency, uint32_t rx_packet_idx)
{
	if (delayed_latency->entries[rx_packet_idx % 64].rx_packet_idx == rx_packet_idx)
		return &delayed_latency->entries[rx_packet_idx % 64];
	else
		return NULL;
}

static struct delayed_latency_entry *delayed_latency_create(struct delayed_latency *delayed_latency, uint32_t rx_packet_idx)
{
	delayed_latency->entries[rx_packet_idx % 64].rx_packet_idx = rx_packet_idx;
	return &delayed_latency->entries[rx_packet_idx % 64];
}

struct rx_pkt_meta_data {
	uint8_t  *hdr;
	uint32_t pkt_tx_time;
	uint32_t bytes_after_in_bulk;
};

struct task_lat {
	struct task_base base;
	uint64_t limit;
	uint64_t rx_packet_index;
	uint64_t last_pkts_tsc;
	struct delayed_latency delayed_latency;
	struct lat_info *latency_buffer;
	uint32_t latency_buffer_idx;
	uint32_t latency_buffer_size;
	uint64_t begin;
	uint16_t lat_pos;
	uint16_t unique_id_pos;
	uint16_t accur_pos;
	uint16_t sig_pos;
	uint32_t sig;
	volatile uint16_t use_lt; /* which lt to use, */
	volatile uint16_t using_lt; /* 0 or 1 depending on which of the 2 measurements are used */
	struct lat_test lt[2];
	struct lat_test *lat_test;
	uint32_t generator_count;
	struct early_loss_detect *eld;
	struct rx_pkt_meta_data *rx_pkt_meta;
	FILE *fp_rx;
	FILE *fp_tx;
};

static uint32_t abs_diff(uint32_t a, uint32_t b)
{
       return a < b? UINT32_MAX - (b - a - 1) : a - b;
}

struct lat_test *task_lat_get_latency_meassurement(struct task_lat *task)
{
	if (task->use_lt == task->using_lt)
		return &task->lt[!task->using_lt];
	return NULL;
}

void task_lat_use_other_latency_meassurement(struct task_lat *task)
{
	task->use_lt = !task->using_lt;
}

static void task_lat_update_lat_test(struct task_lat *task)
{
	if (task->use_lt != task->using_lt) {
		task->using_lt = task->use_lt;
		task->lat_test = &task->lt[task->using_lt];
		task->lat_test->accuracy_limit_tsc = task->limit;
	}
}

static int compare_tx_time(const void *val1, const void *val2)
{
	const struct lat_info *ptr1 = val1;
	const struct lat_info *ptr2 = val2;

	return ptr1->tx_time - ptr2->tx_time;
}

static int compare_queue_id(const void *val1, const void *val2)
{
	return compare_tx_time(val1, val2);
}

static void fix_latency_buffer_tx_time(struct lat_info *lat, uint32_t count)
{
	uint32_t id, time, old_id = 0, old_time = 0, n_overflow = 0;

	for (uint32_t i = 0; i < count; i++) {
		id = lat->port_queue_id;
		time = lat->tx_time;
		if (id == old_id) {
			// Same queue id as previous entry; time should always increase
			if (time < old_time) {
				n_overflow++;
			}
			lat->tx_time += UINT32_MAX * n_overflow;
			old_time = time;
		} else {
			// Different queue_id, time starts again at 0
			old_id = id;
			old_time = 0;
			n_overflow = 0;
		}
	}
}

static void task_lat_count_remaining_lost_packets(struct task_lat *task)
{
	struct lat_test *lat_test = task->lat_test;

	for (uint32_t j = 0; j < task->generator_count; j++) {
		struct early_loss_detect *eld = &task->eld[j];

		lat_test->lost_packets += early_loss_detect_count_remaining_loss(eld);
	}
}

static void task_lat_reset_eld(struct task_lat *task)
{
	for (uint32_t j = 0; j < task->generator_count; j++) {
		early_loss_detect_reset(&task->eld[j]);
	}
}

static uint64_t lat_latency_buffer_get_min_tsc(struct task_lat *task)
{
	uint64_t min_tsc = UINT64_MAX;

	for (uint32_t i = 0; i < task->latency_buffer_idx; i++) {
		if (min_tsc > task->latency_buffer[i].tx_time)
			min_tsc = task->latency_buffer[i].tx_time;
	}

	return min_tsc << LATENCY_ACCURACY;
}

static uint64_t lat_info_get_lat_tsc(struct lat_info *lat_info)
{
	uint64_t lat = abs_diff(lat_info->rx_time, lat_info->tx_time);

	return lat << LATENCY_ACCURACY;
}

static uint64_t lat_info_get_tx_err_tsc(const struct lat_info *lat_info)
{
	return ((uint64_t)lat_info->tx_err) << LATENCY_ACCURACY;
}

static uint64_t lat_info_get_rx_err_tsc(const struct lat_info *lat_info)
{
	return ((uint64_t)lat_info->rx_err) << LATENCY_ACCURACY;
}

static uint64_t lat_info_get_rx_tsc(const struct lat_info *lat_info)
{
	return ((uint64_t)lat_info) << LATENCY_ACCURACY;
}

static uint64_t lat_info_get_tx_tsc(const struct lat_info *lat_info)
{
	return ((uint64_t)lat_info) << LATENCY_ACCURACY;
}

static void lat_write_latency_to_file(struct task_lat *task)
{
	uint64_t min_tsc;
	uint32_t n_loss;

	min_tsc = lat_latency_buffer_get_min_tsc(task);

	// Dumping all packet statistics
	fprintf(task->fp_rx, "Latency stats for %u packets, ordered by rx time\n", task->latency_buffer_idx);
	fprintf(task->fp_rx, "rx index; queue; tx index; lat (nsec);tx time;\n");
	for (uint32_t i = 0; i < task->latency_buffer_idx ; i++) {
		struct lat_info *lat_info = &task->latency_buffer[i];
		uint64_t lat_tsc = lat_info_get_lat_tsc(lat_info);
		uint64_t rx_tsc = lat_info_get_rx_tsc(lat_info);
		uint64_t tx_tsc = lat_info_get_tx_tsc(lat_info);

		fprintf(task->fp_rx, "%u%d;%d;%ld;%lu;%lu\n",
			lat_info->rx_packet_index,
			lat_info->port_queue_id,
			lat_info->tx_packet_index,
			tsc_to_nsec(lat_tsc),
			tsc_to_nsec(rx_tsc - min_tsc),
			tsc_to_nsec(tx_tsc - min_tsc));
	}

	// To detect dropped packets, we need to sort them based on TX
	plogx_info("Sorting packets based on queue_id\n");
	qsort (task->latency_buffer, task->latency_buffer_idx, sizeof(struct lat_info), compare_queue_id);
	plogx_info("Adapting tx_time\n");
	fix_latency_buffer_tx_time(task->latency_buffer, task->latency_buffer_idx);
	plogx_info("Sorting packets based on tx_time\n");
	qsort (task->latency_buffer, task->latency_buffer_idx, sizeof(struct lat_info), compare_tx_time);
	plogx_info("Sorted packets based on tx_time\n");

	// A packet is marked as dropped if 2 packets received from the same queue are not consecutive
	fprintf(task->fp_tx, "Latency stats for %u packets, sorted by tx time\n", task->latency_buffer_idx);
	fprintf(task->fp_tx, "queue;tx index; rx index; lat (nsec);tx time; rx time; tx_err;rx_err\n");

	uint32_t prev_tx_packet_index = -1;
	for (uint32_t i = 0; i < task->latency_buffer_idx; i++) {
		struct lat_info *lat_info = &task->latency_buffer[i];
		uint64_t lat_tsc = lat_info_get_lat_tsc(lat_info);
		uint64_t tx_err_tsc = lat_info_get_tx_err_tsc(lat_info);
		uint64_t rx_err_tsc = lat_info_get_rx_err_tsc(lat_info);
		uint64_t rx_tsc = lat_info_get_rx_tsc(lat_info);
		uint64_t tx_tsc = lat_info_get_tx_tsc(lat_info);

		/* Packet n + 64 delivers the TX error for packet n,
		   hence the last 64 packets do no have TX error. */
		if (i + 64 >= task->latency_buffer_idx) {
			tx_err_tsc = 0;
		}
		// Log dropped packet
		n_loss = lat_info->tx_packet_index - prev_tx_packet_index - 1;
		if (n_loss)
			fprintf(task->fp_tx, "===> %d;%d;0;0;0;0; lost %d packets <===\n",
				lat_info->port_queue_id,
				lat_info->tx_packet_index - n_loss, n_loss);
		// Log next packet
		fprintf(task->fp_tx, "%d;%d;%u;%lu;%lu;%lu;%lu;%lu\n",
			lat_info->port_queue_id,
			lat_info->tx_packet_index,
			lat_info->rx_packet_index,
			tsc_to_nsec(lat_tsc),
			tsc_to_nsec(tx_tsc - min_tsc),
			tsc_to_nsec(rx_tsc - min_tsc),
			tsc_to_nsec(tx_err_tsc),
			tsc_to_nsec(rx_err_tsc));
#ifdef LAT_DEBUG
		fprintf(task->fp_tx, ";%d from %d;%lu;%lu;%lu",
			lat_info->id_in_bulk,
			lat_info->bulk_size,
			tsc_to_nsec(lat_info->begin - min_tsc),
			tsc_to_nsec(lat_info->before - min_tsc),
			tsc_to_nsec(lat_info->after - min_tsc));
#endif
		fprintf(task->fp_tx, "\n");
		prev_tx_packet_index = lat_info->tx_packet_index;
	}
	fflush(task->fp_rx);
	fflush(task->fp_tx);
	task->latency_buffer_idx = 0;
}

static void lat_stop(struct task_base *tbase)
{
	struct task_lat *task = (struct task_lat *)tbase;

	if (task->unique_id_pos) {
		task_lat_count_remaining_lost_packets(task);
		task_lat_reset_eld(task);
	}
	if (task->latency_buffer)
		lat_write_latency_to_file(task);
}

#ifdef LAT_DEBUG
static void task_lat_store_lat_debug(struct task_lat *task, uint32_t rx_packet_index, uint32_t id_in_bulk, uint32_t bulk_size)
{
	struct lat_info *lat_info = &task->latency_buffer[rx_packet_index];

	lat_info->bulk_size = bulk_size;
	lat_info->id_in_bulk = id_in_bulk;
	lat_info->begin = task->begin;
	lat_info->before = task->base.aux->tsc_rx.before;
	lat_info->after = task->base.aux->tsc_rx.after;
}
#endif

static void task_lat_store_lat_buf(struct task_lat *task, uint64_t rx_packet_index, struct unique_id *unique_id, uint64_t rx_time, uint64_t tx_time, uint64_t rx_err, uint64_t tx_err)
{
	struct lat_info *lat_info;
	uint8_t generator_id = 0;
	uint32_t packet_index = 0;

	if (unique_id)
		unique_id_get(unique_id, &generator_id, &packet_index);

	/* If unique_id_pos is specified then latency is stored per
	   packet being sent. Lost packets are detected runtime, and
	   latency stored for those packets will be 0 */
	lat_info = &task->latency_buffer[task->latency_buffer_idx++];
	lat_info->rx_packet_index = task->latency_buffer_idx - 1;
	lat_info->tx_packet_index = packet_index;
	lat_info->port_queue_id = generator_id;
	lat_info->rx_time = rx_time;
	lat_info->tx_time = tx_time;
	lat_info->rx_err = rx_err;
	lat_info->tx_err = tx_err;
}

static uint32_t task_lat_early_loss_detect(struct task_lat *task, struct unique_id *unique_id)
{
	struct early_loss_detect *eld;
	uint8_t generator_id;
	uint32_t packet_index;

	unique_id_get(unique_id, &generator_id, &packet_index);

	if (generator_id >= task->generator_count)
		return 0;

	eld = &task->eld[generator_id];

	return early_loss_detect_add(eld, packet_index);
}

static uint64_t tsc_extrapolate_backward(uint64_t tsc_from, uint64_t bytes, uint64_t tsc_minimum)
{
	uint64_t tsc = tsc_from - rte_get_tsc_hz()*bytes/1250000000;
	if (likely(tsc > tsc_minimum))
		return tsc;
	else
		return tsc_minimum;
}

static void lat_test_histogram_add(struct lat_test *lat_test, uint64_t lat_tsc)
{
	uint64_t bucket_id = (lat_tsc >> lat_test->bucket_size);
	size_t bucket_count = sizeof(lat_test->buckets)/sizeof(lat_test->buckets[0]);

	bucket_id = bucket_id < bucket_count? bucket_id : bucket_count;
	lat_test->buckets[bucket_id]++;
}

static void lat_test_add_lost(struct lat_test *lat_test, uint64_t lost_packets)
{
	lat_test->lost_packets += lost_packets;
}

static void lat_test_add_latency(struct lat_test *lat_test, uint64_t lat_tsc, uint64_t error)
{
	lat_test->tot_all_pkts++;

	if (error > lat_test->accuracy_limit_tsc)
		return;
	lat_test->tot_pkts++;

	lat_test->tot_lat += lat_tsc;
	lat_test->tot_lat_error += error;

	/* (a +- b)^2 = a^2 +- (2ab + b^2) */
	lat_test->var_lat += lat_tsc * lat_tsc;
	lat_test->var_lat_error += 2 * lat_tsc * error;
	lat_test->var_lat_error += error * error;

	if (lat_tsc > lat_test->max_lat) {
		lat_test->max_lat = lat_tsc;
		lat_test->max_lat_error = error;
	}
	if (lat_tsc < lat_test->min_lat) {
		lat_test->min_lat = lat_tsc;
		lat_test->min_lat_error = error;
	}

#ifdef LATENCY_HISTOGRAM
	lat_test_histogram_add(lat_test, lat_tsc);
#endif
}

static int task_lat_can_store_latency(struct task_lat *task)
{
	return task->latency_buffer_idx < task->latency_buffer_size;
}

static void task_lat_store_lat(struct task_lat *task, uint64_t rx_packet_index, uint64_t rx_time, uint64_t tx_time, uint64_t rx_error, uint64_t tx_error, struct unique_id *unique_id)
{
	if (tx_time == 0)
		return;
	uint32_t lat_tsc = abs_diff(rx_time, tx_time) << LATENCY_ACCURACY;

	lat_test_add_latency(task->lat_test, lat_tsc, rx_error + tx_error);

	if (task_lat_can_store_latency(task)) {
		task_lat_store_lat_buf(task, rx_packet_index, unique_id, rx_time, tx_time, rx_error, tx_error);
	}
}

static int handle_lat_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_lat *task = (struct task_lat *)tbase;
	uint64_t rx_time_err;

	uint32_t pkt_rx_time, pkt_tx_time;

	if (n_pkts == 0) {
		task->begin = tbase->aux->tsc_rx.before;
		return 0;
	}

	task_lat_update_lat_test(task);

	const uint64_t rx_tsc = tbase->aux->tsc_rx.after;
	uint32_t tx_time_err = 0;

	/* Go once through all received packets and read them.  If
	   packet has just been modified by another core, the cost of
	   latency will be partialy amortized though the bulk size */
	for (uint16_t j = 0; j < n_pkts; ++j) {
		struct rte_mbuf *mbuf = mbufs[j];
		task->rx_pkt_meta[j].hdr = rte_pktmbuf_mtod(mbuf, uint8_t *);
	}
	for (uint16_t j = 0; j < n_pkts; ++j) {
	}

	if (task->sig) {
		for (uint16_t j = 0; j < n_pkts; ++j) {
			if (*(uint32_t *)(task->rx_pkt_meta[j].hdr + task->sig_pos) == task->sig)
				task->rx_pkt_meta[j].pkt_tx_time = *(uint32_t *)(task->rx_pkt_meta[j].hdr + task->lat_pos);
			else
				task->rx_pkt_meta[j].pkt_tx_time = 0;
		}
	} else {
		for (uint16_t j = 0; j < n_pkts; ++j) {
			task->rx_pkt_meta[j].pkt_tx_time = *(uint32_t *)(task->rx_pkt_meta[j].hdr + task->lat_pos);
		}
	}

	uint32_t bytes_total_in_bulk = 0;
	// Find RX time of first packet, for RX accuracy
	for (uint16_t j = 0; j < n_pkts; ++j) {
		uint16_t flipped = n_pkts - 1 - j;

		task->rx_pkt_meta[flipped].bytes_after_in_bulk = bytes_total_in_bulk;
		bytes_total_in_bulk += mbuf_wire_size(mbufs[flipped]);
	}

	pkt_rx_time = tsc_extrapolate_backward(rx_tsc, task->rx_pkt_meta[0].bytes_after_in_bulk, task->last_pkts_tsc) >> LATENCY_ACCURACY;
	if ((uint32_t)((task->begin >> LATENCY_ACCURACY)) > pkt_rx_time) {
		// Extrapolation went up to BEFORE begin => packets were stuck in the NIC but we were not seeing them
		rx_time_err = pkt_rx_time - (uint32_t)(task->last_pkts_tsc >> LATENCY_ACCURACY);
	} else {
		rx_time_err = pkt_rx_time - (uint32_t)(task->begin >> LATENCY_ACCURACY);
	}

	struct unique_id *unique_id = NULL;
	struct delayed_latency_entry *delayed_latency_entry;

	for (uint16_t j = 0; j < n_pkts; ++j) {
		struct rx_pkt_meta_data *rx_pkt_meta = &task->rx_pkt_meta[j];
		uint8_t *hdr = rx_pkt_meta->hdr;

		pkt_rx_time = tsc_extrapolate_backward(rx_tsc, rx_pkt_meta->bytes_after_in_bulk, task->last_pkts_tsc) >> LATENCY_ACCURACY;
		pkt_tx_time = rx_pkt_meta->pkt_tx_time;

		if (task->unique_id_pos) {
			unique_id = (struct unique_id *)(hdr + task->unique_id_pos);

			uint32_t n_loss = task_lat_early_loss_detect(task, unique_id);
			lat_test_add_lost(task->lat_test, n_loss);
		}

		/* If accuracy is enabled, latency is reported with a
		   delay of 64 packets since the generator puts the
		   accuracy for packet N into packet N + 64. The delay
		   ensures that all reported latencies have both rx
		   and tx error. */
		if (task->accur_pos) {
			tx_time_err = *(uint32_t *)(hdr + task->accur_pos);

			delayed_latency_entry = delayed_latency_get(&task->delayed_latency, task->rx_packet_index - 64);

			if (delayed_latency_entry) {
				task_lat_store_lat(task,
						   task->rx_packet_index,
						   delayed_latency_entry->pkt_rx_time,
						   delayed_latency_entry->pkt_tx_time,
						   delayed_latency_entry->rx_time_err,
						   tx_time_err,
						   unique_id);
			}

			delayed_latency_entry = delayed_latency_create(&task->delayed_latency, task->rx_packet_index);
			delayed_latency_entry->pkt_rx_time = pkt_rx_time;
			delayed_latency_entry->pkt_tx_time = pkt_tx_time;
			delayed_latency_entry->rx_time_err = rx_time_err;
		} else {
			task_lat_store_lat(task,
					   task->rx_packet_index,
					   pkt_rx_time,
					   pkt_tx_time,
					   0,
					   0,
					   unique_id);
		}
		task->rx_packet_index++;
	}
	int ret;
	ret = task->base.tx_pkt(&task->base, mbufs, n_pkts, NULL);
	task->begin = tbase->aux->tsc_rx.before;
	task->last_pkts_tsc = tbase->aux->tsc_rx.after;
	return ret;
}

static void init_task_lat_latency_buffer(struct task_lat *task, uint32_t core_id)
{
	const int socket_id = rte_lcore_to_socket_id(core_id);
	char name[256];
	size_t latency_buffer_mem_size = 0;

	if (task->latency_buffer_size > UINT32_MAX - MAX_RING_BURST)
		task->latency_buffer_size = UINT32_MAX - MAX_RING_BURST;

	latency_buffer_mem_size = sizeof(struct lat_info) * task->latency_buffer_size;

	task->latency_buffer = prox_zmalloc(latency_buffer_mem_size, socket_id);
	PROX_PANIC(task->latency_buffer == NULL, "Failed to allocate %ld kbytes for %s\n", latency_buffer_mem_size / 1024, name);

	sprintf(name, "latency.rx_%d.txt", core_id);
	task->fp_rx = fopen(name, "w+");
	PROX_PANIC(task->fp_rx == NULL, "Failed to open %s\n", name);

	sprintf(name, "latency.tx_%d.txt", core_id);
	task->fp_tx = fopen(name, "w+");
	PROX_PANIC(task->fp_tx == NULL, "Failed to open %s\n", name);
}

static void task_lat_init_eld(struct task_lat *task, uint8_t socket_id)
{
	uint8_t *generator_count = prox_sh_find_system("generator_count");
	size_t eld_mem_size;

	if (generator_count == NULL)
		task->generator_count = 0;
	else
		task->generator_count = *generator_count;

	eld_mem_size = sizeof(task->eld[0]) * task->generator_count;
	task->eld = prox_zmalloc(eld_mem_size, socket_id);
}

void task_lat_set_accuracy_limit(struct task_lat *task, uint32_t accuracy_limit_nsec)
{
	task->limit = nsec_to_tsc(accuracy_limit_nsec);
}

static void init_task_lat(struct task_base *tbase, struct task_args *targ)
{
	struct task_lat *task = (struct task_lat *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	task->lat_pos = targ->lat_pos;
	task->accur_pos = targ->accur_pos;
	task->unique_id_pos = targ->packet_id_pos;
	task->latency_buffer_size = targ->latency_buffer_size;

	if (task->latency_buffer_size) {
		init_task_lat_latency_buffer(task, targ->lconf->id);
	}

	if (targ->bucket_size < LATENCY_ACCURACY) {
		targ->bucket_size = DEFAULT_BUCKET_SIZE;
	}

	task->lt[0].bucket_size = targ->bucket_size - LATENCY_ACCURACY;
	task->lt[1].bucket_size = targ->bucket_size - LATENCY_ACCURACY;
        if (task->unique_id_pos) {
		task_lat_init_eld(task, socket_id);
		task_lat_reset_eld(task);
        }
	task->lat_test = &task->lt[task->using_lt];

	task_lat_set_accuracy_limit(task, targ->accuracy_limit_nsec);
	task->rx_pkt_meta = prox_zmalloc(MAX_RX_PKT_ALL * sizeof(*task->rx_pkt_meta), socket_id);
	PROX_PANIC(task->rx_pkt_meta == NULL, "unable to allocate memory to store RX packet meta data");
}

static struct task_init task_init_lat = {
	.mode_str = "lat",
	.init = init_task_lat,
	.handle = handle_lat_bulk,
	.stop = lat_stop,
	.flag_features = TASK_FEATURE_TSC_RX | TASK_FEATURE_RX_ALL | TASK_FEATURE_ZERO_RX | TASK_FEATURE_NEVER_DISCARDS,
	.size = sizeof(struct task_lat)
};

__attribute__((constructor)) static void reg_task_lat(void)
{
	reg_task(&task_init_lat);
}
