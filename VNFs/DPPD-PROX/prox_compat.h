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
#include <rte_common.h>
#include <rte_table_hash.h>
#include <rte_hash_crc.h>
#include "hash_utils.h"

/* This is a copy of the rte_table_hash_params from DPDK 17.11  *
 * So if DPDK decides to change the structure the modifications *
 * to PROX code should mainly be limited to this file           *
 */
struct prox_rte_table_params {
	const char *name;
	uint32_t key_size;
	uint32_t key_offset;
	uint8_t *key_mask;
	uint32_t n_keys;
	uint32_t n_buckets;
	rte_table_hash_op_hash f_hash;
	uint64_t seed;
};

#if RTE_VERSION < RTE_VERSION_NUM(17,11,0,0)

static void *prox_rte_table_create(struct prox_rte_table_params *params, int socket_id, uint32_t entry_size)
{
	if (params->key_size == 8) {
		struct rte_table_hash_key8_ext_params dpdk17_08_params;
        	dpdk17_08_params.n_entries = params->n_keys;
        	dpdk17_08_params.n_entries_ext = params->n_keys >> 2;
        	dpdk17_08_params.f_hash = (rte_table_hash_op_hash)rte_hash_crc;
        	dpdk17_08_params.seed = params->seed;
        	dpdk17_08_params.signature_offset = HASH_METADATA_OFFSET(8);  // Ignored for dosig
        	dpdk17_08_params.key_offset = HASH_METADATA_OFFSET(0);
        	dpdk17_08_params.key_mask = params->key_mask;
		return rte_table_hash_key8_ext_dosig_ops.f_create(&dpdk17_08_params, socket_id, entry_size);
	} else {
		struct rte_table_hash_ext_params dpdk17_08_params;
		dpdk17_08_params.key_size = params->key_size;
		dpdk17_08_params.n_keys = params->n_keys;
		dpdk17_08_params.n_buckets = params->n_buckets;
		dpdk17_08_params.n_buckets_ext = params->n_buckets >> 1;
		dpdk17_08_params.seed = params->seed;
		dpdk17_08_params.f_hash = (rte_table_hash_op_hash)rte_hash_crc;
		dpdk17_08_params.signature_offset = HASH_METADATA_OFFSET(0);
		dpdk17_08_params.key_offset = HASH_METADATA_OFFSET(0);
		return rte_table_hash_ext_dosig_ops.f_create(&dpdk17_08_params, socket_id, entry_size);
	}
};

#define prox_rte_table_free        rte_table_hash_ext_dosig_ops.f_free
#define prox_rte_table_add         rte_table_hash_ext_dosig_ops.f_add
#define prox_rte_table_delete      rte_table_hash_ext_dosig_ops.f_delete
#define prox_rte_table_add_bulk    rte_table_hash_ext_dosig_ops.f_add_bulk
#define prox_rte_table_delete_bulk rte_table_hash_ext_dosig_ops.f_delete_bulk
#define prox_rte_table_lookup      rte_table_hash_ext_dosig_ops.f_lookup
#define prox_rte_table_stats       rte_table_hash_ext_dosig_ops.f_stats

#define prox_rte_table_key8_free        rte_table_hash_key8_ext_dosig_ops.f_free
#define prox_rte_table_key8_add         rte_table_hash_key8_ext_dosig_ops.f_add
#define prox_rte_table_key8_delete      rte_table_hash_key8_ext_dosig_ops.f_delete
#define prox_rte_table_key8_add_bulk    rte_table_hash_key8_ext_dosig_ops.f_add_bulk
#define prox_rte_table_key8_delete_bulk rte_table_hash_key8_ext_dosig_ops.f_delete_bulk
#define prox_rte_table_key8_lookup      rte_table_hash_key8_ext_dosig_ops.f_lookup
#define prox_rte_table_key8_stats       rte_table_hash_key8_ext_dosig_ops.f_stats

#define rte_log_set_global_level rte_set_log_level

#else

static void *prox_rte_table_create(struct prox_rte_table_params *params, int socket_id, uint32_t entry_size)
{
	struct rte_table_hash_params dpdk_17_11_params;
        dpdk_17_11_params.name = params->name;
        dpdk_17_11_params.key_size = params->key_size;
        dpdk_17_11_params.key_offset = params->key_offset;
        dpdk_17_11_params.key_mask = params->key_mask;
        dpdk_17_11_params.n_keys = params->n_keys;
        dpdk_17_11_params.n_buckets = rte_align32pow2(params->n_buckets);
        dpdk_17_11_params.f_hash = params->f_hash;
        dpdk_17_11_params.seed = params->seed;

	if (params->key_size == 8) {
		return rte_table_hash_key8_ext_ops.f_create(&dpdk_17_11_params, socket_id, entry_size);
	} else {
		return rte_table_hash_ext_ops.f_create(&dpdk_17_11_params, socket_id, entry_size);
	}
}

#define prox_rte_table_free        rte_table_hash_ext_ops.f_free
#define prox_rte_table_add         rte_table_hash_ext_ops.f_add
#define prox_rte_table_delete      rte_table_hash_ext_ops.f_delete
#define prox_rte_table_add_bulk    rte_table_hash_ext_ops.f_add_bulk
#define prox_rte_table_delete_bulk rte_table_hash_ext_ops.f_delete_bulk
#define prox_rte_table_lookup      rte_table_hash_ext_ops.f_lookup
#define prox_rte_table_stats       rte_table_hash_ext_ops.f_stats

#define prox_rte_table_key8_free        rte_table_hash_key8_ext_ops.f_free
#define prox_rte_table_key8_add         rte_table_hash_key8_ext_ops.f_add
#define prox_rte_table_key8_delete      rte_table_hash_key8_ext_ops.f_delete
#define prox_rte_table_key8_add_bulk    rte_table_hash_key8_ext_ops.f_add_bulk
#define prox_rte_table_key8_delete_bulk rte_table_hash_key8_ext_ops.f_delete_bulk
#define prox_rte_table_key8_lookup      rte_table_hash_key8_ext_ops.f_lookup
#define prox_rte_table_key8_stats       rte_table_hash_key8_ext_ops.f_stats

#endif

#if RTE_VERSION < RTE_VERSION_NUM(18,8,0,0)
#define rte_cryptodev_sym_get_private_session_size rte_cryptodev_get_private_session_size
#endif

#ifndef DEV_RX_OFFLOAD_CRC_STRIP
#define DEV_RX_OFFLOAD_CRC_STRIP 0x00001000
#endif
#ifndef DEV_RX_OFFLOAD_JUMBO_FRAME
#define DEV_RX_OFFLOAD_JUMBO_FRAME 0x00000800
#endif
