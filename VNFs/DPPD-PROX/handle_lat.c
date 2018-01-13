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
#include "prox_port_cfg.h"

#define DEFAULT_BUCKET_SIZE	10
#define ACCURACY_BUFFER_SIZE	64

struct lat_info {
	uint32_t rx_packet_index;
	uint64_t tx_packet_index;
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
	uint32_t rx_packet_id;
	uint32_t tx_packet_id;
	uint32_t packet_id;
	uint8_t generator_id;
	uint64_t pkt_rx_time;
	uint64_t pkt_tx_time;
	uint64_t rx_time_err;
};

static struct delayed_latency_entry *delayed_latency_get(struct delayed_latency_entry **delayed_latency_entries, uint8_t generator_id, uint32_t packet_id)
{
	struct delayed_latency_entry *delayed_latency_entry = &delayed_latency_entries[generator_id][packet_id % ACCURACY_BUFFER_SIZE];
	if (delayed_latency_entry->packet_id == packet_id)
		return delayed_latency_entry;
	else
		return NULL;
}

static struct delayed_latency_entry *delayed_latency_create(struct delayed_latency_entry **delayed_latency_entries, uint8_t generator_id, uint32_t packet_id)
{
	struct delayed_latency_entry *delayed_latency_entry = &delayed_latency_entries[generator_id][packet_id % ACCURACY_BUFFER_SIZE];
	delayed_latency_entry->packet_id = packet_id;
	return delayed_latency_entry;
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
	struct delayed_latency_entry **delayed_latency_entries;
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
	uint64_t link_speed;
	// Following fields are only used when starting or stopping, not in general runtime
	uint64_t *prev_tx_packet_index;
	FILE *fp_rx;
	FILE *fp_tx;
	struct prox_port_cfg *port;
};

static uint32_t diff_or_zero(uint32_t a, uint32_t b)
{
       return a < b? 0 : a - b;
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

	return ptr1->tx_time > ptr2->tx_time ? 1 : -1;
}

static int compare_tx_packet_index(const void *val1, const void *val2)
{
	const struct lat_info *ptr1 = val1;
	const struct lat_info *ptr2 = val2;

	return ptr1->tx_packet_index > ptr2->tx_packet_index ? 1 : -1;
}

static void fix_latency_buffer_tx_packet_index(struct lat_info *lat, uint32_t count)
{
	uint32_t tx_packet_index, old_tx_packet_index = lat->tx_packet_index, n_overflow = 0;
	uint32_t small = UINT32_MAX >> 1;

	lat++;

	/* Buffer is sorted so far by RX time.
	 * We might have packets being reordered by SUT.
	 *     => consider small differences as re-order and big ones as overflow of tx_packet_index.
	 * Note that:
	 *	- overflow only happens if receiving and storing 4 billions packets...
	 *	- a absolute difference of less than 2 billion packets is not considered as an overflow
	 */
	for (uint32_t i = 1; i < count; i++) {
		tx_packet_index = lat->tx_packet_index;
		if (tx_packet_index > old_tx_packet_index) {
			if (tx_packet_index - old_tx_packet_index < small) {
				// The diff is small => increasing index count
			} else {
				// The diff is big => it is more likely that the previous packet was overflow
				n_overflow--;
			}
		} else {
			if (old_tx_packet_index - tx_packet_index < small) {
				// The diff is small => packet reorder
			} else {
				// The diff is big => it is more likely that this is an overflow
				n_overflow++;
			}
		}
		lat->tx_packet_index += ((uint64_t)UINT32_MAX + 1) * n_overflow;
		old_tx_packet_index = tx_packet_index;
		lat++;
	}
}

static void fix_latency_buffer_tx_time(struct lat_info *lat, uint32_t count)
{
	uint32_t tx_time, old_tx_time = lat->tx_time, n_overflow = 0;
	uint32_t small = UINT32_MAX >> 1;
	lat++;

	/*
	 * Same algorithm as above, but with time.
	 * Note that:
	 *	- overflow happens after 4 billions "cycles" (shifted by LATENCY_ACCURACY) = ~4sec
	 *	- a absolute difference up to 2 billion (shifted) cycles (~=2sec) is not considered as an overflow
	 *		=> algorithm does not work if receiving less than 1 packet every 2 seconds
	 */
	for (uint32_t i = 1; i < count; i++) {
		tx_time = lat->tx_time;
		if (tx_time > old_tx_time) {
			if (tx_time - old_tx_time > small) {
				n_overflow--;
			}
		} else {
			if (old_tx_time - tx_time > small) {
				n_overflow++;
			}
		}
		lat->tx_time += ((uint64_t)UINT32_MAX + 1) * n_overflow;
		old_tx_time = tx_time;
		lat++;
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
	uint64_t lat = diff_or_zero(lat_info->rx_time, lat_info->tx_time);

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
	return ((uint64_t)lat_info->rx_time) << LATENCY_ACCURACY;
}

static uint64_t lat_info_get_tx_tsc(const struct lat_info *lat_info)
{
	return ((uint64_t)lat_info->tx_time) << LATENCY_ACCURACY;
}

static void lat_write_latency_to_file(struct task_lat *task)
{
	uint64_t min_tsc;
	uint64_t n_loss;

	min_tsc = lat_latency_buffer_get_min_tsc(task);

	// Dumping all packet statistics
	fprintf(task->fp_rx, "Latency stats for %u packets, ordered by rx time\n", task->latency_buffer_idx);
	fprintf(task->fp_rx, "rx index; queue; tx index; lat (nsec);tx time;\n");
	for (uint32_t i = 0; i < task->latency_buffer_idx ; i++) {
		struct lat_info *lat_info = &task->latency_buffer[i];
		uint64_t lat_tsc = lat_info_get_lat_tsc(lat_info);
		uint64_t rx_tsc = lat_info_get_rx_tsc(lat_info);
		uint64_t tx_tsc = lat_info_get_tx_tsc(lat_info);

		fprintf(task->fp_rx, "%u;%u;%lu;%lu;%lu;%lu\n",
			lat_info->rx_packet_index,
			lat_info->port_queue_id,
			lat_info->tx_packet_index,
			tsc_to_nsec(lat_tsc),
			tsc_to_nsec(rx_tsc - min_tsc),
			tsc_to_nsec(tx_tsc - min_tsc));
	}

	// To detect dropped packets, we need to sort them based on TX
	if (task->unique_id_pos) {
		plogx_info("Adapting tx_packet_index\n");
		fix_latency_buffer_tx_packet_index(task->latency_buffer, task->latency_buffer_idx);
		plogx_info("Sorting packets based on tx_packet_index\n");
		qsort (task->latency_buffer, task->latency_buffer_idx, sizeof(struct lat_info), compare_tx_packet_index);
		plogx_info("Sorted packets based on packet_index\n");
	} else {
		plogx_info("Adapting tx_time\n");
		fix_latency_buffer_tx_time(task->latency_buffer, task->latency_buffer_idx);
		plogx_info("Sorting packets based on tx_time\n");
		qsort (task->latency_buffer, task->latency_buffer_idx, sizeof(struct lat_info), compare_tx_time);
		plogx_info("Sorted packets based on packet_time\n");
	}

	// A packet is marked as dropped if 2 packets received from the same queue are not consecutive
	fprintf(task->fp_tx, "Latency stats for %u packets, sorted by tx time\n", task->latency_buffer_idx);
	fprintf(task->fp_tx, "queue;tx index; rx index; lat (nsec);tx time; rx time; tx_err;rx_err\n");

	for (uint32_t i = 0; i < task->generator_count;i++)
		task->prev_tx_packet_index[i] = -1;

	for (uint32_t i = 0; i < task->latency_buffer_idx; i++) {
		struct lat_info *lat_info = &task->latency_buffer[i];
		uint64_t lat_tsc = lat_info_get_lat_tsc(lat_info);
		uint64_t tx_err_tsc = lat_info_get_tx_err_tsc(lat_info);
		uint64_t rx_err_tsc = lat_info_get_rx_err_tsc(lat_info);
		uint64_t rx_tsc = lat_info_get_rx_tsc(lat_info);
		uint64_t tx_tsc = lat_info_get_tx_tsc(lat_info);

		/* Packet n + ACCURACY_BUFFER_SIZE delivers the TX error for packet n,
		   hence the last ACCURACY_BUFFER_SIZE packets do no have TX error. */
		if (i + ACCURACY_BUFFER_SIZE >= task->latency_buffer_idx) {
			tx_err_tsc = 0;
		}

		if (lat_info->port_queue_id >= task->generator_count) {
			plog_err("Unexpected generator id %u for packet %lu - skipping packet\n",
				lat_info->port_queue_id, lat_info->tx_packet_index);
			continue;
		}
		// Log dropped packet
		n_loss = lat_info->tx_packet_index - task->prev_tx_packet_index[lat_info->port_queue_id] - 1;
		if (n_loss)
			fprintf(task->fp_tx, "===> %u;%lu;0;0;0;0;0;0 lost %lu packets <===\n",
				lat_info->port_queue_id,
				lat_info->tx_packet_index - n_loss, n_loss);
		// Log next packet
		fprintf(task->fp_tx, "%u;%lu;%u;%lu;%lu;%lu;%lu;%lu",
			lat_info->port_queue_id,
			lat_info->tx_packet_index,
			lat_info->rx_packet_index,
			tsc_to_nsec(lat_tsc),
			tsc_to_nsec(tx_tsc - min_tsc),
			tsc_to_nsec(rx_tsc - min_tsc),
			tsc_to_nsec(tx_err_tsc),
			tsc_to_nsec(rx_err_tsc));
#ifdef LAT_DEBUG
		fprintf(task->fp_tx, ";%u from %u;%lu;%lu;%lu",
			lat_info->id_in_bulk,
			lat_info->bulk_size,
			tsc_to_nsec(lat_info->begin - min_tsc),
			tsc_to_nsec(lat_info->before - min_tsc),
			tsc_to_nsec(lat_info->after - min_tsc));
#endif
		fprintf(task->fp_tx, "\n");
		task->prev_tx_packet_index[lat_info->port_queue_id] = lat_info->tx_packet_index;
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

static void task_lat_store_lat_buf(struct task_lat *task, uint64_t rx_packet_index, uint64_t rx_time, uint64_t tx_time, uint64_t rx_err, uint64_t tx_err, uint32_t packet_id, uint8_t generator_id)
{
	struct lat_info *lat_info;

	/* If unique_id_pos is specified then latency is stored per
	   packet being sent. Lost packets are detected runtime, and
	   latency stored for those packets will be 0 */
	lat_info = &task->latency_buffer[task->latency_buffer_idx++];
	lat_info->rx_packet_index = rx_packet_index;
	lat_info->tx_packet_index = packet_id;
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

static uint64_t tsc_extrapolate_backward(uint64_t link_speed, uint64_t tsc_from, uint64_t bytes, uint64_t tsc_minimum)
{
	uint64_t tsc = tsc_from - (rte_get_tsc_hz()*bytes)/link_speed;
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

static void task_lat_store_lat(struct task_lat *task, uint64_t rx_packet_index, uint64_t rx_time, uint64_t tx_time, uint64_t rx_error, uint64_t tx_error, uint32_t packet_id, uint8_t generator_id)
{
	if (tx_time == 0)
		return;
	uint32_t lat_tsc = diff_or_zero(rx_time, tx_time) << LATENCY_ACCURACY;

	lat_test_add_latency(task->lat_test, lat_tsc, rx_error + tx_error);

	if (task_lat_can_store_latency(task)) {
		task_lat_store_lat_buf(task, rx_packet_index, rx_time, tx_time, rx_error, tx_error, packet_id, generator_id);
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

	pkt_rx_time = tsc_extrapolate_backward(task->link_speed, rx_tsc, task->rx_pkt_meta[0].bytes_after_in_bulk, task->last_pkts_tsc) >> LATENCY_ACCURACY;
	if ((uint32_t)((task->begin >> LATENCY_ACCURACY)) > pkt_rx_time) {
		// Extrapolation went up to BEFORE begin => packets were stuck in the NIC but we were not seeing them
		rx_time_err = pkt_rx_time - (uint32_t)(task->last_pkts_tsc >> LATENCY_ACCURACY);
	} else {
		rx_time_err = pkt_rx_time - (uint32_t)(task->begin >> LATENCY_ACCURACY);
	}

	struct unique_id *unique_id = NULL;
	struct delayed_latency_entry *delayed_latency_entry;
	uint32_t packet_id, generator_id;

	for (uint16_t j = 0; j < n_pkts; ++j) {
		struct rx_pkt_meta_data *rx_pkt_meta = &task->rx_pkt_meta[j];
		uint8_t *hdr = rx_pkt_meta->hdr;

		pkt_rx_time = tsc_extrapolate_backward(task->link_speed, rx_tsc, rx_pkt_meta->bytes_after_in_bulk, task->last_pkts_tsc) >> LATENCY_ACCURACY;
		pkt_tx_time = rx_pkt_meta->pkt_tx_time;

		if (task->unique_id_pos) {
			unique_id = (struct unique_id *)(hdr + task->unique_id_pos);

			uint32_t n_loss = task_lat_early_loss_detect(task, unique_id);
			packet_id = unique_id->packet_id;
			generator_id = unique_id->generator_id;
			lat_test_add_lost(task->lat_test, n_loss);
		} else {
			packet_id = task->rx_packet_index;
			generator_id = 0;
		}
		task->lat_test->tot_all_pkts++;

		/* If accuracy is enabled, latency is reported with a
		   delay of ACCURACY_BUFFER_SIZE packets since the generator puts the
		   accuracy for packet N into packet N + ACCURACY_BUFFER_SIZE. The delay
		   ensures that all reported latencies have both rx
		   and tx error. */
		if (task->accur_pos) {
			tx_time_err = *(uint32_t *)(hdr + task->accur_pos);

			delayed_latency_entry = delayed_latency_get(task->delayed_latency_entries, generator_id, packet_id - ACCURACY_BUFFER_SIZE);

			if (delayed_latency_entry) {
				task_lat_store_lat(task,
						   delayed_latency_entry->rx_packet_id,
						   delayed_latency_entry->pkt_rx_time,
						   delayed_latency_entry->pkt_tx_time,
						   delayed_latency_entry->rx_time_err,
						   tx_time_err,
						   delayed_latency_entry->tx_packet_id,
						   delayed_latency_entry->generator_id);
			}

			delayed_latency_entry = delayed_latency_create(task->delayed_latency_entries, generator_id, packet_id);
			delayed_latency_entry->pkt_rx_time = pkt_rx_time;
			delayed_latency_entry->pkt_tx_time = pkt_tx_time;
			delayed_latency_entry->rx_time_err = rx_time_err;
			delayed_latency_entry->rx_packet_id = task->rx_packet_index;
			delayed_latency_entry->tx_packet_id = packet_id;
			delayed_latency_entry->generator_id = generator_id;
		} else {
			task_lat_store_lat(task, task->rx_packet_index, pkt_rx_time, pkt_tx_time, 0, 0, packet_id, generator_id);
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
	PROX_PANIC(task->latency_buffer == NULL, "Failed to allocate %zu kbytes for latency_buffer\n", latency_buffer_mem_size / 1024);

	sprintf(name, "latency.rx_%u.txt", core_id);
	task->fp_rx = fopen(name, "w+");
	PROX_PANIC(task->fp_rx == NULL, "Failed to open %s\n", name);

	sprintf(name, "latency.tx_%u.txt", core_id);
	task->fp_tx = fopen(name, "w+");
	PROX_PANIC(task->fp_tx == NULL, "Failed to open %s\n", name);

	task->prev_tx_packet_index = prox_zmalloc(sizeof(task->prev_tx_packet_index[0]) * task->generator_count, socket_id);
	PROX_PANIC(task->prev_tx_packet_index == NULL, "Failed to allocated prev_tx_packet_index\n");
}

static void task_init_generator_count(struct task_lat *task)
{
	uint8_t *generator_count = prox_sh_find_system("generator_count");

	if (generator_count == NULL) {
		task->generator_count = 1;
		plog_info("\tNo generators found, hard-coding to %u generators\n", task->generator_count);
	} else
		task->generator_count = *generator_count;
	plog_info("\tLatency using %u generators\n", task->generator_count);
}

static void task_lat_init_eld(struct task_lat *task, uint8_t socket_id)
{
	size_t eld_mem_size;

	eld_mem_size = sizeof(task->eld[0]) * task->generator_count;
	task->eld = prox_zmalloc(eld_mem_size, socket_id);
	PROX_PANIC(task->eld == NULL, "Failed to allocate eld\n");
}

void task_lat_set_accuracy_limit(struct task_lat *task, uint32_t accuracy_limit_nsec)
{
	task->limit = nsec_to_tsc(accuracy_limit_nsec);
}

static void lat_start(struct task_base *tbase)
{
	struct task_lat *task = (struct task_lat *)tbase;

	if (task->port) {
		// task->port->link->speed reports the link speed in Mbps e.g. 40k for a 40 Gbps NIC
		// task->link_speed reported link speed in Bytes per sec.
		task->link_speed = task->port->link_speed * 125000L;
		plog_info("\tReceiving at %lu Mbps\n", 8 * task->link_speed / 1000000);
	}
}

static void init_task_lat(struct task_base *tbase, struct task_args *targ)
{
	struct task_lat *task = (struct task_lat *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);

	task->lat_pos = targ->lat_pos;
	task->accur_pos = targ->accur_pos;
	task->sig_pos = targ->sig_pos;
	task->sig = targ->sig;

	task->unique_id_pos = targ->packet_id_pos;
	task->latency_buffer_size = targ->latency_buffer_size;

	task_init_generator_count(task);

	if (task->latency_buffer_size) {
		init_task_lat_latency_buffer(task, targ->lconf->id);
	}

	if (targ->bucket_size < DEFAULT_BUCKET_SIZE) {
		targ->bucket_size = DEFAULT_BUCKET_SIZE;
	}

	if (task->accur_pos) {
		task->delayed_latency_entries = prox_zmalloc(sizeof(*task->delayed_latency_entries) * task->generator_count , socket_id);
		PROX_PANIC(task->delayed_latency_entries == NULL, "Failed to allocate array for storing delayed latency entries\n");
		for (uint i = 0; i < task->generator_count; i++) {
			task->delayed_latency_entries[i] = prox_zmalloc(sizeof(**task->delayed_latency_entries) * ACCURACY_BUFFER_SIZE, socket_id);
			PROX_PANIC(task->delayed_latency_entries[i] == NULL, "Failed to allocate array for storing delayed latency entries\n");
		}
		if (task->unique_id_pos == 0) {
			/* When using accuracy feature, the accuracy from TX is written ACCURACY_BUFFER_SIZE packets later
			* We can only retrieve the good packet if a packet id is written to it.
			* Otherwise we will use the packet RECEIVED ACCURACY_BUFFER_SIZE packets ago which is OK if
			* packets are not re-ordered. If packets are re-ordered, then the matching between
			* the tx accuracy znd the latency is wrong.
			*/
			plog_warn("\tWhen accuracy feature is used, a unique id should ideally also be used\n");
		}
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

	task->link_speed = UINT64_MAX;
	if (targ->nb_rxports) {
		// task->port structure is only used while starting handle_lat to get the link_speed.
		// link_speed can not be quiried at init as the port has not been initialized yet.
		struct prox_port_cfg *port = &prox_port_cfg[targ->rx_port_queue[0].port];
		task->port = port;
	}
}

static struct task_init task_init_lat = {
	.mode_str = "lat",
	.init = init_task_lat,
	.handle = handle_lat_bulk,
	.start = lat_start,
	.stop = lat_stop,
	.flag_features = TASK_FEATURE_TSC_RX | TASK_FEATURE_RX_ALL | TASK_FEATURE_ZERO_RX | TASK_FEATURE_NEVER_DISCARDS,
	.size = sizeof(struct task_lat)
};

__attribute__((constructor)) static void reg_task_lat(void)
{
	reg_task(&task_init_lat);
}
