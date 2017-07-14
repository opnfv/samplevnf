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

#ifndef _STATS_CORE_H_
#define _STATS_CORE_H_

#include <inttypes.h>

struct lcore_stats_sample {
	uint64_t afreq;
	uint64_t mfreq;
	uint64_t mbm_tot_bytes;
	uint64_t mbm_loc_bytes;
};

struct lcore_stats {
	uint32_t lcore_id;
	uint32_t socket_id;
	uint64_t rmid;
	uint64_t cmt_data;
	uint64_t cmt_bytes;
	uint64_t mbm_tot_bytes;
	uint64_t mbm_loc_bytes;
	uint64_t cmt_fraction;
	uint32_t cat_mask;
	uint64_t mbm_tot;
	uint64_t mbm_loc;
	uint32_t class;
	struct lcore_stats_sample sample[2];
};

uint32_t stats_lcore_find_stat_id(uint32_t lcore_id);
int stats_get_n_lcore_stats(void);
struct lcore_stats *stats_get_lcore_stats(uint32_t stat_id);
struct lcore_stats_sample *stats_get_lcore_stats_sample(uint32_t stat_id, int last);
int stats_cpu_freq_enabled(void);
int stats_cmt_enabled(void);
int stats_cat_enabled(void);
int stats_mbm_enabled(void);
void stats_lcore_update(void);
void stats_lcore_init(void);
void stats_lcore_post_proc(void);
void stats_update_cache_mask(uint32_t lcore_id, uint32_t mask);
void stats_lcore_assoc_rmid(void);

#endif /* _STATS_CORE_H_ */
