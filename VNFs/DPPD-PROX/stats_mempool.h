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

#ifndef _STATS_MEMPOOL_H_
#define _STATS_MEMPOOL_H_

#include <inttypes.h>
#include <stddef.h>

struct mempool_stats {
	struct rte_mempool *pool;
	uint16_t port;
	uint16_t queue;
	size_t free;
	size_t size;
};

void stats_mempool_init(void);
struct mempool_stats *stats_get_mempool_stats(uint32_t i);
int stats_get_n_mempools(void);
void stats_mempool_update(void);

#endif /* _STATS_MEMPOOL_H_ */
