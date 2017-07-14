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

#include <string.h>
#include <stdio.h>

#include "prox_cfg.h"

#define CM_N_BITS (sizeof(prox_cfg.core_mask[0]) * 8)
#define CM_ALL_N_BITS (sizeof(prox_cfg.core_mask) * 8)

struct prox_cfg prox_cfg = {
	.update_interval_str = "1"
};

static int prox_cm_isset(const uint32_t lcore_id)
{
	uint64_t cm;
	uint32_t cm_idx;

	if (lcore_id > CM_ALL_N_BITS)
		return -1;

	cm = __UINT64_C(1) << (lcore_id % CM_N_BITS);
	cm_idx = PROX_CM_DIM - 1 - lcore_id / CM_N_BITS;
	return !!(prox_cfg.core_mask[cm_idx] & cm);
}

int prox_core_active(const uint32_t lcore_id, const int with_master)
{
	int ret;

	ret = prox_cm_isset(lcore_id);
	if (ret < 0)
		return 0;

	if (with_master)
		return ret || lcore_id == prox_cfg.master;
	else
		return ret && lcore_id != prox_cfg.master;
}

int prox_core_next(uint32_t* lcore_id, const int with_master)
{
	for (uint32_t i = *lcore_id + 1; i < CM_ALL_N_BITS; ++i) {
		if (prox_core_active(i, with_master)) {
			*lcore_id = i;
			return 0;
		}
	}
	return -1;
}

int prox_core_to_hex(char *dst, const size_t size, const int with_master)
{
	uint64_t cm;
	uint32_t cm_len;
	uint32_t cm_first = 0;
	uint32_t master = prox_cfg.master;

	/* Minimum size of the string has to big enough to hold the
	   bitmask in hex (including the prefix "0x"). */
	if (size < PROX_CM_STR_LEN)
		return 0;

	snprintf(dst, size, "0x");
	for (uint32_t i = 0; i < PROX_CM_DIM; ++i, cm_first = i) {
		if ((with_master && ((CM_ALL_N_BITS - 1 - master) / CM_N_BITS == i * CM_N_BITS)) ||
		    prox_cfg.core_mask[i]) {
			break;
		}
	}

	for (uint32_t i = cm_first; i < PROX_CM_DIM; ++i) {
		cm = prox_cfg.core_mask[i];
		if (with_master && ((CM_ALL_N_BITS - 1 - master) / CM_N_BITS == i)) {
			cm |= (__UINT64_C(1) << (master % CM_N_BITS));
		}

		snprintf(dst + strlen(dst), size - strlen(dst), i == cm_first? "%lx" : "%016lx", cm);
	}

	return 0;
}

int prox_core_to_str(char *dst, const size_t size, const int with_master)
{
	uint32_t lcore_id = -1;
	uint32_t first = 1;

	*dst = 0;
	lcore_id - 1;
	while (prox_core_next(&lcore_id, with_master) == 0) {
		/* Stop printing to string if there is not engough
		   space left. Assume that adding 1 core to the string
		   will take at most 5 + 1 bytes implying that
		   lcore_id < 999. Check if ther is space for another
		   6 bytes to add an elipsis */
		if (12 + strlen(dst) > size) {
			if (6 + strlen(dst) > size) {
				snprintf(dst + strlen(dst), size - strlen(dst), ", ...");
				return 0;
			}
			return -1;
		}

		snprintf(dst + strlen(dst), size - strlen(dst), first? "%u" : ", %u", lcore_id);
		first = 0;
	}

	return 0;
}

void prox_core_clr(void)
{
	memset(prox_cfg.core_mask, 0, sizeof(prox_cfg.core_mask));
}

int prox_core_set_active(const uint32_t lcore_id)
{
	uint32_t cm_idx;
	uint64_t cm;

	if (lcore_id > CM_ALL_N_BITS)
		return -1;

	cm = __UINT64_C(1) << (lcore_id % CM_N_BITS);
	cm_idx = PROX_CM_DIM - 1 - lcore_id / CM_N_BITS;
	prox_cfg.core_mask[cm_idx] |= cm;

	return 0;
}
