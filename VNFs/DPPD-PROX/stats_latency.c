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

#include "prox_malloc.h"
#include "stats_latency.h"
#include "handle_lat.h"
#include "prox_cfg.h"
#include "prox_args.h"

struct stats_latency_manager_entry {
	struct task_lat        *task;
	uint8_t                lcore_id;
	uint8_t                task_id;
	struct lat_test_flows        lat_test_flows;
	struct lat_test_flows        tot_lat_test_flows;
	struct stats_latency   stats[LATENCY_NUMBER_OF_FLOWS];
	struct stats_latency   tot[LATENCY_NUMBER_OF_FLOWS];
};

struct stats_latency_manager {
	uint16_t n_latency;
	struct stats_latency_manager_entry entries[0]; /* copy of stats when running update stats. */
};

static struct stats_latency_manager *slm;

void stats_latency_reset(void)
{
	for (uint32_t i = 0; i < LATENCY_NUMBER_OF_FLOWS; i++)
		for (uint16_t i = 0; i < slm->n_latency; ++i)
			lat_test_reset(&slm->entries[i].tot_lat_test_flows.flows[i]);
}

int stats_get_n_latency(void)
{
	return slm->n_latency;
}

uint32_t stats_latency_get_core_id(uint32_t i)
{
	return slm->entries[i].lcore_id;
}

uint32_t stats_latency_get_task_id(uint32_t i)
{
	return slm->entries[i].task_id;
}

struct stats_latency *stats_latency_get(uint32_t i)
{
	return &slm->entries[i].stats[0]; /* TODO , support multiple flows*/
}

struct stats_latency *stats_latency_tot_get(uint32_t i)
{
	return &slm->entries[i].tot[0]; /* TODO , support multiple flows*/
}

static struct stats_latency_manager_entry *stats_latency_entry_find(uint8_t lcore_id, uint8_t task_id)
{
	struct stats_latency_manager_entry *entry;

	for (uint16_t i = 0; i < stats_get_n_latency(); ++i) {
		entry = &slm->entries[i];

		if (entry->lcore_id == lcore_id && entry->task_id == task_id) {
			return entry;
		}
	}
	return NULL;
}

struct stats_latency *stats_latency_tot_find(uint32_t lcore_id, uint32_t task_id, uint32_t flowid)
{
	struct stats_latency_manager_entry *entry = stats_latency_entry_find(lcore_id, task_id);

	if (!entry)
		return NULL;
	else
		return &entry->tot[flowid];
}

struct stats_latency *stats_latency_find(uint32_t lcore_id, uint32_t task_id, uint32_t flowid)
{
	struct stats_latency_manager_entry *entry = stats_latency_entry_find(lcore_id, task_id);

	if (!entry)
		return NULL;
	else
		return &entry->stats[flowid];
}

static int task_runs_observable_latency(struct task_args *targ)
{
	/* Note that multiple ports or rings are only supported
	   if they all receive packets configured in the same way
	   e.g. same timestamp pos. */
	return !strcmp(targ->task_init->mode_str, "lat") &&
		(targ->nb_rxports >= 1 || targ->nb_rxrings >= 1);
}

static struct stats_latency_manager *alloc_stats_latency_manager(void)
{
	const uint32_t socket_id = rte_lcore_to_socket_id(rte_lcore_id());
	struct stats_latency_manager *ret;
	struct lcore_cfg *lconf;
	uint32_t n_latency = 0;
	uint32_t lcore_id;
	size_t mem_size;

	lcore_id = -1;
	while (prox_core_next(&lcore_id, 0) == 0) {
		lconf = &lcore_cfg[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			struct task_args *targ = &lconf->targs[task_id];
			if (task_runs_observable_latency(targ))
				++n_latency;
		}
	}
	mem_size = sizeof(*ret) + sizeof(ret->entries[0]) * n_latency;

	ret = prox_zmalloc(mem_size, socket_id);
	return ret;
}

static void stats_latency_add_task(struct lcore_cfg *lconf, struct task_args *targ)
{
	struct stats_latency_manager_entry *new_entry = &slm->entries[slm->n_latency];

	new_entry->task = (struct task_lat *)targ->tbase;
	new_entry->lcore_id = lconf->id;
	new_entry->task_id = targ->id;
	for (uint32_t i = 0; i < LATENCY_NUMBER_OF_FLOWS; i++) {
		new_entry->tot_lat_test_flows.flows[i].min_lat = -1;
	}
	slm->n_latency++;
}

void stats_latency_init(void)
{
	struct lcore_cfg *lconf = NULL;
	struct task_args *targ;

	slm = alloc_stats_latency_manager();

	while (core_targ_next(&lconf, &targ, 0) == 0) {
		if (task_runs_observable_latency(targ))
			stats_latency_add_task(lconf, targ);
	}
}

#ifdef LATENCY_HISTOGRAM
void stats_core_lat_histogram(uint8_t lcore_id, uint8_t task_id, uint32_t flowid, uint64_t **buckets)
{
	struct stats_latency_manager_entry *lat_stats;
	uint64_t tsc;

	lat_stats = stats_latency_entry_find(lcore_id, task_id);

	if (lat_stats)
		*buckets = lat_stats->lat_test_flows.flows[flowid].buckets;
	else
		*buckets = NULL;
}
#endif

static void stats_latency_fetch_entry(struct stats_latency_manager_entry *entry)
{
	struct lat_test_flows *lat_test_remote = task_lat_get_latency_meassurement(entry->task);

	if (!lat_test_remote)
		return;

	for (uint32_t i = 0; i < LATENCY_NUMBER_OF_FLOWS; i++) {
		if (lat_test_remote->flows[i].tot_all_pkts) {
			lat_test_copy(&entry->lat_test_flows.flows[i], &lat_test_remote->flows[i]);
			lat_test_reset(&lat_test_remote->flows[i]);
			lat_test_combine(&entry->tot_lat_test_flows.flows[i], &entry->lat_test_flows.flows[i]);
		}
	}

	task_lat_use_other_latency_meassurement(entry->task);
}

static void stats_latency_from_lat_test(struct stats_latency *dst, struct lat_test *src)
{
	/* In case packets were received, but measurements were too
	   inaccurate */
	if (src->tot_pkts) {
		dst->max = lat_test_get_max(src);
		dst->min = lat_test_get_min(src);
		dst->avg = lat_test_get_avg(src);
		dst->stddev = lat_test_get_stddev(src);
		dst->tot_lat = src->tot_lat;
		dst->var_lat = src->var_lat;
		dst->ipdv_lat = src->ipdv_lat;
	}
	dst->accuracy_limit = lat_test_get_accuracy_limit(src);
	dst->period = lat_test_get_period(src);
	dst->tot_packets = src->tot_pkts;
	dst->tot_all_packets = src->tot_all_pkts;
	dst->lost_packets = src->lost_packets;
}

static void stats_latency_update_entry(struct stats_latency_manager_entry *entry)
{
	for (uint32_t i = 0; i < LATENCY_NUMBER_OF_FLOWS; i++) {
		if (entry->lat_test_flows.flows[i].tot_all_pkts) {
			stats_latency_from_lat_test(&entry->stats[i], &entry->lat_test_flows.flows[i]);
			stats_latency_from_lat_test(&entry->tot[i], &entry->tot_lat_test_flows.flows[i]);
		}
	}
}

void stats_latency_update(void)
{
	for (uint16_t i = 0; i < slm->n_latency; ++i)
		stats_latency_fetch_entry(&slm->entries[i]);
	for (uint16_t i = 0; i < slm->n_latency; ++i)
		stats_latency_update_entry(&slm->entries[i]);
}
