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

#include <rte_mempool.h>
#include <rte_version.h>
#include <inttypes.h>

#include "prox_malloc.h"
#include "prox_port_cfg.h"
#include "stats_mempool.h"

struct stats_mempool_manager {
	uint32_t n_mempools;
	struct mempool_stats mempool_stats[0];
};

static struct stats_mempool_manager *smm;

struct mempool_stats *stats_get_mempool_stats(uint32_t i)
{
	return &smm->mempool_stats[i];
}

int stats_get_n_mempools(void)
{
	return smm->n_mempools;
}

static struct stats_mempool_manager *alloc_stats_mempool_manager(void)
{
	const uint32_t socket_id = rte_lcore_to_socket_id(rte_lcore_id());
	uint32_t n_max_mempools = sizeof(prox_port_cfg[0].pool)/sizeof(prox_port_cfg[0].pool[0]);
	uint32_t n_mempools = 0;
	size_t mem_size = sizeof(struct stats_mempool_manager);

	for (uint8_t i = 0; i < PROX_MAX_PORTS; ++i) {
		if (!prox_port_cfg[i].active)
			continue;

		for (uint8_t j = 0; j < n_max_mempools; ++j) {
			if (prox_port_cfg[i].pool[j] && prox_port_cfg[i].pool_size[j]) {
				mem_size += sizeof(struct mempool_stats);
			}
		}
	}

	return prox_zmalloc(mem_size, socket_id);
}

void stats_mempool_init(void)
{
	uint32_t n_max_mempools = sizeof(prox_port_cfg[0].pool)/sizeof(prox_port_cfg[0].pool[0]);

	smm = alloc_stats_mempool_manager();
	for (uint8_t i = 0; i < PROX_MAX_PORTS; ++i) {
		if (!prox_port_cfg[i].active)
			continue;

		for (uint8_t j = 0; j < n_max_mempools; ++j) {
			if (prox_port_cfg[i].pool[j] && prox_port_cfg[i].pool_size[j]) {
				struct mempool_stats *ms = &smm->mempool_stats[smm->n_mempools];

				ms->pool = prox_port_cfg[i].pool[j];
				ms->port = i;
				ms->queue = j;
				ms->size = prox_port_cfg[i].pool_size[j];
				smm->n_mempools++;
			}
		}
	}
}

void stats_mempool_update(void)
{
	for (uint8_t mp_id = 0; mp_id < smm->n_mempools; ++mp_id) {
		/* Note: The function free_count returns the number of used entries. */
#if RTE_VERSION >= RTE_VERSION_NUM(17,5,0,0)
		smm->mempool_stats[mp_id].free = rte_mempool_avail_count(smm->mempool_stats[mp_id].pool);
#else
		smm->mempool_stats[mp_id].free = rte_mempool_count(smm->mempool_stats[mp_id].pool);
#endif
	}
}
