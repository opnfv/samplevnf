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

#include "hash_entry_types.h"
#include "hash_utils.h"
#include "expire_cpe.h"
#include "prox_compat.h"

#define MAX_TSC	       __UINT64_C(0xFFFFFFFFFFFFFFFF)

void check_expire_cpe(void* data)
{
	struct expire_cpe *um = (struct expire_cpe *)data;
	uint64_t cur_tsc = rte_rdtsc();
	struct cpe_data *entries[4] = {0};
	void *key[4] = {0};
	uint64_t n_buckets = get_bucket_key8(um->cpe_table, um->bucket_index, key, (void**)entries);

	for (uint8_t i = 0; i < 4 && entries[i]; ++i) {
		if (entries[i]->tsc < cur_tsc) {
			int key_found = 0;
			void* entry = 0;
			prox_rte_table_key8_delete(um->cpe_table, key[i], &key_found, entry);
		}
	}

        um->bucket_index++;
        um->bucket_index &= (n_buckets - 1);
}
