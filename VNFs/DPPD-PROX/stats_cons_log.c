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

#include <rte_cycles.h>

#include "stats.h"
#include "stats_l4gen.h"
#include "stats_cons_log.h"
#include "prox_cfg.h"
#include "prox_args.h"
#include "prox_assert.h"
#include "commands.h"

static struct stats_cons stats_cons_log = {
	.init = stats_cons_log_init,
	.notify = stats_cons_log_notify,
	.finish = stats_cons_log_finish,
#ifndef DPI_STATS
	.flags = STATS_CONS_F_ALL,
#else
	.flags = STATS_CONS_F_PORTS|STATS_CONS_F_TASKS,
#endif
};

struct header {
	uint64_t hz;
	uint64_t now;
	uint64_t n_entries;
	uint64_t n_entry_fields;
	uint8_t  n_entry_field_size[64];
};

static void header_init(struct header *hdr, uint64_t hz, uint64_t now, uint64_t n_entries) {
	memset(hdr, 0, sizeof(*hdr));
	hdr->hz = hz;
	hdr->now = now;
	hdr->n_entries = n_entries;
}

static void header_add_field(struct header *hdr, uint8_t size) {
	hdr->n_entry_field_size[hdr->n_entry_fields++] = size;
}

static void header_write(struct header *hdr, FILE *fp) {
	size_t header_size_no_fields = sizeof(*hdr) - sizeof(hdr->n_entry_field_size);
	size_t header_size_effective = header_size_no_fields + hdr->n_entry_fields;

	fwrite(hdr, header_size_effective, 1, fp);
}

#define BUFFERED_RECORD_LEN 16384

#define STATS_DUMP_FILE_NAME "stats_dump"
static FILE *fp;

struct entry {
	uint32_t lcore_id;
	uint32_t task_id;
#ifndef DPI_STATS
	uint32_t l4_stats_id;
#endif
};

static struct entry entries[64];
static uint64_t n_entries;

#ifndef DPI_STATS
struct record {
	uint32_t lcore_id;
	uint32_t task_id;
	uint64_t active_connections;
	uint64_t bundles_created;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
	uint64_t tsc;
} __attribute__((packed));
#else
struct record {
	uint32_t lcore_id;
	uint32_t task_id;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
	uint64_t drop_bytes;
	uint64_t tsc;
} __attribute__((packed));
#endif

static struct record buf[BUFFERED_RECORD_LEN];
static size_t buf_pos = 0;

struct stats_cons *stats_cons_log_get(void)
{
	return &stats_cons_log;
}

#ifndef DPI_STATS
void stats_cons_log_init(void)
{
	fp = fopen(STATS_DUMP_FILE_NAME, "w");
	if (!fp)
		return;

	uint32_t lcore_id = -1;

	while(prox_core_next(&lcore_id, 0) == 0) {
		struct lcore_cfg *lconf = &lcore_cfg[lcore_id];

		if (lconf->n_tasks_all && (strcmp(lconf->targs[0].task_init->mode_str, "genl4") ||
					   strcmp(lconf->targs[0].task_init->sub_mode_str, "")))
			continue;

		for (uint32_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			entries[n_entries].lcore_id = lcore_id;
			entries[n_entries].task_id = task_id;
			entries[n_entries].l4_stats_id = n_entries;
			n_entries++;
			if (n_entries == sizeof(entries)/sizeof(entries[0]))
				break;
		}
		cmd_rx_bw_start(lcore_id);
		cmd_tx_bw_start(lcore_id);
		if (n_entries == sizeof(entries)/sizeof(entries[0]))
			break;
	}

	struct header hdr;

	header_init(&hdr, rte_get_tsc_hz(), rte_rdtsc(), n_entries);
	header_add_field(&hdr, sizeof(((struct record *)0)->lcore_id));
	header_add_field(&hdr, sizeof(((struct record *)0)->task_id));
	header_add_field(&hdr, sizeof(((struct record *)0)->active_connections));
	header_add_field(&hdr, sizeof(((struct record *)0)->bundles_created));
	header_add_field(&hdr, sizeof(((struct record *)0)->rx_bytes));
	header_add_field(&hdr, sizeof(((struct record *)0)->tx_bytes));
	header_add_field(&hdr, sizeof(((struct record *)0)->tsc));

	header_write(&hdr, fp);
}

void stats_cons_log_notify(void)
{
	const uint32_t n_l4gen = stats_get_n_l4gen();

	if (buf_pos + n_entries > sizeof(buf)/sizeof(buf[0])) {
		fwrite(buf, sizeof(buf[0]), buf_pos, fp);
		buf_pos = 0;
	}
	PROX_ASSERT(buf_pos + n_entries <= sizeof(buf)/sizeof(buf[0]));

	for (uint32_t i = 0; i < n_entries; ++i) {
		uint32_t c = entries[i].lcore_id;
		uint32_t t = entries[i].task_id;
		uint32_t j = entries[i].l4_stats_id;
		struct l4_stats_sample *clast = stats_get_l4_stats_sample(j, 1);
		struct task_stats *l = stats_get_task_stats(c, t);
		struct task_stats_sample *last = stats_get_task_stats_sample(c, t, 1);

		buf[buf_pos].lcore_id = c;
		buf[buf_pos].task_id  = t;

		uint64_t tot_created = clast->stats.tcp_created + clast->stats.udp_created;
		uint64_t tot_finished = clast->stats.tcp_finished_retransmit + clast->stats.tcp_finished_no_retransmit +
			clast->stats.udp_finished + clast->stats.udp_expired + clast->stats.tcp_expired;

		buf[buf_pos].active_connections = tot_created - tot_finished;
		buf[buf_pos].bundles_created = clast->stats.bundles_created;
		buf[buf_pos].rx_bytes = last->rx_bytes;
		buf[buf_pos].tx_bytes = last->tx_bytes;
		buf[buf_pos].tsc = clast->tsc;

		buf_pos++;
	}
}

#else
void stats_cons_log_init(void)
{
	uint64_t el = rte_get_tsc_hz();
	uint64_t now = rte_rdtsc();

	fp = fopen(STATS_DUMP_FILE_NAME, "w");
	if (!fp)
		return;

	uint32_t lcore_id = -1;

	while(prox_core_next(&lcore_id, 0) == 0) {
		struct lcore_cfg *lconf = &lcore_cfg[lcore_id];

		if (!lconf->n_tasks_all)
			continue;

		for (uint32_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			if (strcmp(lconf->targs[task_id].task_init->mode_str, "lbpos"))
				continue;

			entries[n_entries].lcore_id = lcore_id;
			entries[n_entries].task_id = task_id;
			n_entries++;
			if (n_entries == sizeof(entries)/sizeof(entries[0]))
				break;
		}
		cmd_rx_bw_start(lcore_id);
		cmd_tx_bw_start(lcore_id);
		if (n_entries == sizeof(entries)/sizeof(entries[0]))
			break;
	}

	struct header hdr;

	header_init(&hdr, rte_get_tsc_hz(), rte_rdtsc(), n_entries);
	header_add_field(&hdr, sizeof(((struct record *)0)->lcore_id));
	header_add_field(&hdr, sizeof(((struct record *)0)->task_id));
	header_add_field(&hdr, sizeof(((struct record *)0)->rx_bytes));
	header_add_field(&hdr, sizeof(((struct record *)0)->tx_bytes));
	header_add_field(&hdr, sizeof(((struct record *)0)->drop_bytes));
	header_add_field(&hdr, sizeof(((struct record *)0)->tsc));
	header_write(&hdr, fp);
}

void stats_cons_log_notify(void)
{
	for (uint32_t i = 0; i < n_entries; ++i) {
		uint32_t c = entries[i].lcore_id;
		uint32_t t = entries[i].task_id;
		struct task_stats *l = stats_get_task_stats(c, t);
		struct task_stats_sample *last = stats_get_task_stats_sample(c, t, 1);

		buf[buf_pos].lcore_id = c;
		buf[buf_pos].task_id  = t;
		buf[buf_pos].tx_bytes = last->tx_bytes;
		buf[buf_pos].rx_bytes = last->rx_bytes;
		buf[buf_pos].drop_bytes = last->drop_bytes;
		/* buf[buf_pos].drop_tx_fail = l->tot_drop_tx_fail; */
		buf[buf_pos].tsc = last->tsc;

		buf_pos++;

		if (buf_pos == sizeof(buf)/sizeof(buf[0])) {
			fwrite(buf, sizeof(buf), 1, fp);
			buf_pos = 0;
		}
	}
}
#endif

void stats_cons_log_finish(void)
{
	if (fp) {
		if (buf_pos) {
			fwrite(buf, sizeof(buf[0]), buf_pos, fp);
			buf_pos = 0;
		}
		fclose(fp);
	}
}
