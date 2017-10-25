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

#include <rte_lcore.h>

#include "prox_malloc.h"
#include "stats_core.h"
#include "cqm.h"
#include "log.h"
#include "msr.h"
#include "parse_utils.h"
#include "prox_cfg.h"
#include "lconf.h"

struct stats_core_manager {
	struct rdt_features rdt_features;
	int                msr_support;
	int                max_core_id;
	uint16_t           n_lcore_stats;
	int cache_size[RTE_MAX_LCORE];
	struct lcore_stats lcore_stats_set[0];
};

static struct stats_core_manager *scm;
extern int last_stat;

static int get_L3_size(void)
{
	char buf[1024]= "/proc/cpuinfo";
	FILE* fd = fopen(buf, "r");
	if (fd == NULL) {
		plogx_err("Could not open %s", buf);
		return -1;
	}
	int lcore = -1, val = 0, size = 0;
	while (fgets(buf, sizeof(buf), fd) != NULL) {
		if (sscanf(buf, "processor : %u", &val) == 1) {
			lcore = val;
			scm->max_core_id = lcore;
		}
		if (sscanf(buf, "cache size : %u", &val) == 1) {
			size = val;
			if ((lcore != -1) && (lcore < RTE_MAX_LCORE)) {
				scm->cache_size[lcore] = size * 1024;
			}
		}
	}
	fclose(fd);
	plog_info("\tMaximum core_id = %d\n", scm->max_core_id);
	return 0;
}

int stats_get_n_lcore_stats(void)
{
	return scm->n_lcore_stats;
}

int stats_cpu_freq_enabled(void)
{
	return scm->msr_support;
}

int stats_cmt_enabled(void)
{
	return cmt_is_supported();
}

int stats_cat_enabled(void)
{
	return cat_is_supported();
}

int stats_mbm_enabled(void)
{
	return mbm_is_supported();
}

uint32_t stats_lcore_find_stat_id(uint32_t lcore_id)
{
	for (int i = 0; i < scm->n_lcore_stats; ++i)
		if (scm->lcore_stats_set[i].lcore_id == lcore_id)
			return i;
	return 0;
}

struct lcore_stats_sample *stats_get_lcore_stats_sample(uint32_t stat_id, int l)
{
	return &scm->lcore_stats_set[stat_id].sample[l == last_stat];
}

struct lcore_stats *stats_get_lcore_stats(uint32_t stat_id)
{
	return &scm->lcore_stats_set[stat_id];
}

static struct stats_core_manager *alloc_stats_core_manager(void)
{
	const int socket_id = rte_lcore_to_socket_id(rte_lcore_id());
	uint32_t n_lcore_stats = 0;
	uint32_t lcore_id;
	size_t mem_size;

	lcore_id = -1;
	while (prox_core_next(&lcore_id, 0) == 0)
		n_lcore_stats++;
	mem_size = sizeof(struct stats_core_manager) + sizeof(struct lcore_stats) * n_lcore_stats;
	return prox_zmalloc(mem_size, socket_id);
}

void stats_lcore_init(void)
{
	struct lcore_cfg *lconf;
	uint32_t lcore_id;
	int j = 0;

	scm = alloc_stats_core_manager();

	if (is_virtualized()) {
		plog_info("Not initializing msr as running in a VM\n");
		scm->msr_support = 0;
	} else if ((scm->msr_support = !msr_init()) == 0) {
		plog_warn("Failed to open msr pseudo-file (missing msr kernel module?)\n");
	}

	scm->n_lcore_stats = 0;
	lcore_id = -1;
	get_L3_size();
	while (prox_core_next(&lcore_id, 0) == 0) {
		scm->lcore_stats_set[scm->n_lcore_stats++].lcore_id = lcore_id;
	}
	if (!rdt_is_supported())
		return;

	if (!scm->msr_support) {
		plog_warn("CPU supports RDT but msr module not loaded. Disabling RDT stats.\n");
		return;
	}

	if (0 != rdt_get_features(&scm->rdt_features)) {
		plog_warn("Failed to get RDT features\n");
		return;
	}
	else {
		rdt_init_stat_core(rte_lcore_id());
	}

	/* Start using last rmid, to keep first rmid for technologies (like cat) where there are less rmid */
	uint32_t last_rmid = scm->rdt_features.cmt_max_rmid;
	for (uint32_t i = 0; i < scm->n_lcore_stats; ++i) {
		scm->lcore_stats_set[i].rmid = last_rmid; // cmt_max_rmid is used by non-monitored cores
		last_rmid--;
	}

	uint64_t cache_set;
	for (uint32_t i = 0; i < scm->n_lcore_stats; ++i) {
		plog_info("\tAssociating core %u to rmid %lu (associating each core used by prox to a different rmid)\n", scm->lcore_stats_set[i].lcore_id, scm->lcore_stats_set[i].rmid);
		cqm_assoc(scm->lcore_stats_set[i].lcore_id, scm->lcore_stats_set[i].rmid);
		uint32_t lcore_id = scm->lcore_stats_set[i].lcore_id;
		lconf = &lcore_cfg[lcore_id];
		cache_set = lconf->cache_set;
		if ((cache_set) && (cache_set < PROX_MAX_CACHE_SET)) {
			scm->lcore_stats_set[i].class = cache_set;
			scm->lcore_stats_set[i].cat_mask = prox_cache_set_cfg[cache_set].mask;
			if (prox_cache_set_cfg[cache_set].socket_id == -1) {
				prox_cache_set_cfg[cache_set].socket_id = scm->lcore_stats_set[i].socket_id;
				prox_cache_set_cfg[cache_set].lcore_id = lcore_id;
			} else if (prox_cache_set_cfg[cache_set].socket_id != (int32_t)scm->lcore_stats_set[i].socket_id) {
				plog_err("Unsupported config: Using same cache set on two different socket\n");
			}
		} else {
			scm->lcore_stats_set[i].class = 0;
			scm->lcore_stats_set[i].cat_mask = (1 << cat_get_num_ways()) -1;
		}
	}
	cat_log_init(0);
	last_rmid = scm->rdt_features.cat_max_rmid;
	for (int i = 0; i < PROX_MAX_CACHE_SET; i++) {
		if (prox_cache_set_cfg[i].mask) {
			plog_info("\tSetting cache set %d to %x\n", i, prox_cache_set_cfg[i].mask);
			cat_set_class_mask(prox_cache_set_cfg[i].lcore_id, i, prox_cache_set_cfg[i].mask);
        	}
       	}
	for (uint32_t i = 0; i < scm->n_lcore_stats; ++i) {
		uint32_t lcore_id = scm->lcore_stats_set[i].lcore_id;
		lconf = &lcore_cfg[lcore_id];
		cache_set = lconf->cache_set;
		if (cache_set) {
			if (prox_cache_set_cfg[cache_set].mask) {
				scm->lcore_stats_set[i].rmid = (scm->lcore_stats_set[i].rmid) | (cache_set << 32);
				plog_info("\tCache set = %ld for core %d\n", cache_set, lcore_id);
				cqm_assoc(lcore_id, scm->lcore_stats_set[i].rmid);
			} else {
				plog_err("\tUndefined Cache set = %ld for core %d\n", cache_set, lcore_id);
			}
		} else {
			if (prox_cache_set_cfg[cache_set].mask) {
				scm->lcore_stats_set[i].rmid = (scm->lcore_stats_set[i].rmid);
				plog_info("\tUsing default cache set for core %d\n", lcore_id);
				cqm_assoc(lcore_id, scm->lcore_stats_set[i].rmid);
			} else {
				plog_info("\tNo default cache set for core %d\n", lcore_id);
			}
		}
	}
}

static void stats_lcore_update_freq(void)
{
	for (uint8_t i = 0; i < scm->n_lcore_stats; ++i) {
		struct lcore_stats *ls = &scm->lcore_stats_set[i];
		struct lcore_stats_sample *lss = &ls->sample[last_stat];

		msr_read(&lss->afreq, ls->lcore_id, 0xe8);
		msr_read(&lss->mfreq, ls->lcore_id, 0xe7);
	}
}
void stats_update_cache_mask(uint32_t lcore_id, uint32_t mask)
{
	for (uint8_t i = 0; i < scm->n_lcore_stats; ++i) {
		struct lcore_stats *ls = &scm->lcore_stats_set[i];
		if (ls->lcore_id == lcore_id) {
			plog_info("Updating  core %d stats %d to mask %x\n", lcore_id, i, mask);
			scm->lcore_stats_set[i].cat_mask = mask;
		}
	}
}

static void stats_lcore_update_rdt(void)
{
	for (uint8_t i = 0; i < scm->n_lcore_stats; ++i) {
		struct lcore_stats *ls = &scm->lcore_stats_set[i];

		if (ls->rmid) {
			cmt_read_ctr(&ls->cmt_data, ls->rmid, ls->lcore_id);
			mbm_read_tot_bdw(&ls->mbm_tot, ls->rmid, ls->lcore_id);
			mbm_read_loc_bdw(&ls->mbm_loc, ls->rmid, ls->lcore_id);
		}
	}
}

void stats_lcore_post_proc(void)
{
	/* update CQM stats (calculate fraction and bytes reported) */
	for (uint8_t i = 0; i < scm->n_lcore_stats; ++i) {
		struct lcore_stats *ls = &scm->lcore_stats_set[i];
		struct lcore_stats_sample *lss = &ls->sample[last_stat];

		if (ls->rmid) {
			ls->cmt_bytes = ls->cmt_data * scm->rdt_features.upscaling_factor;
			lss->mbm_tot_bytes = ls->mbm_tot * scm->rdt_features.upscaling_factor;
			lss->mbm_loc_bytes = ls->mbm_loc * scm->rdt_features.upscaling_factor;
			//plogx_dbg("cache[core %d] = %ld\n", ls->lcore_id, ls->cmt_bytes);
		}
	}
	for (uint8_t i = 0; i < scm->n_lcore_stats; ++i) {
		struct lcore_stats *ls = &scm->lcore_stats_set[i];

		if (ls->rmid && scm->cache_size[ls->lcore_id])
			ls->cmt_fraction = ls->cmt_bytes * 10000 / scm->cache_size[ls->lcore_id];
		else
			ls->cmt_fraction = 0;
	}
}

void stats_lcore_update(void)
{
	if (scm->msr_support)
		stats_lcore_update_freq();
	if (rdt_is_supported())
		stats_lcore_update_rdt();
}

void stats_lcore_assoc_rmid(void)
{
	for (uint32_t i = 0; i < scm->n_lcore_stats; ++i) {
		uint32_t lcore_id = scm->lcore_stats_set[i].lcore_id;
		scm->lcore_stats_set[i].rmid = scm->lcore_stats_set[i].rmid & 0xffffffff;
		cqm_assoc(lcore_id, scm->lcore_stats_set[i].rmid);
	}
}
