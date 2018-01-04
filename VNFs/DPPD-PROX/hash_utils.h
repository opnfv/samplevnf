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

#ifndef _HASH_UTILS_H_
#define _HASH_UTILS_H_

#include <rte_common.h>
#include <rte_version.h>

struct rte_table_hash;

/* Take DPDK 2.2.0 ABI change into account: offset 0 now means first byte of mbuf struct
 * see http://www.dpdk.org/browse/dpdk/commit/?id=ba92d511ddacf863fafaaa14c0577f30ee57d092
 */
#if RTE_VERSION >= RTE_VERSION_NUM(2,2,0,0)
#define HASH_METADATA_OFFSET(offset)	(sizeof(struct rte_mbuf) + (offset))
#else
#define HASH_METADATA_OFFSET(offset)	(offset)
#endif

/* Wrap crc32 hash function to match that required for rte_table */
uint64_t hash_crc32(void* key, void *key_mask, uint32_t key_size, uint64_t seed);

void print_hash_table_size(const struct rte_table_hash *h);
void print_hash_table(const struct rte_table_hash *h);

uint64_t get_bucket_key8(void* table, uint32_t bucket_idx, void** key, void** entries);
uint64_t get_bucket(void* table, uint32_t bucket_idx, void** key, void** entries);
#endif /* _HASH_UTILS_H_ */
