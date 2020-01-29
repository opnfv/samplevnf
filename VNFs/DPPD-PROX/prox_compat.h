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
#ifndef _PROX_COMPAT_H_
#define _PROX_COMPAT_H_
#include <rte_common.h>
#include <rte_table_hash.h>
#include <rte_hash_crc.h>
#include <rte_cryptodev.h>
#include "hash_utils.h"
#include "quit.h"

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

#ifndef DEV_RX_OFFLOAD_JUMBO_FRAME
#define DEV_RX_OFFLOAD_JUMBO_FRAME 0x00000800
#endif

#ifndef DEV_RX_OFFLOAD_KEEP_CRC
#ifndef DEV_RX_OFFLOAD_CRC_STRIP
#define DEV_RX_OFFLOAD_CRC_STRIP 0x00001000
#endif
#endif

#if RTE_VERSION < RTE_VERSION_NUM(19,2,0,0)
#define RTE_COLOR_GREEN e_RTE_METER_GREEN
#define RTE_COLOR_YELLOW e_RTE_METER_YELLOW
#define RTE_COLOR_RED e_RTE_METER_RED
#define prox_rte_color rte_meter_color
#define prox_rte_sched_port_pkt_read_tree_path(A,B,C,D,E,F) rte_sched_port_pkt_read_tree_path(B,C,D,E,F)
#define prox_rte_sched_port_pkt_write(A,B,C,D,E,F,G) rte_sched_port_pkt_write(B,C,D,E,F,G);
#else
#define prox_rte_color rte_color
#define prox_rte_sched_port_pkt_read_tree_path(A,B,C,D,E,F) rte_sched_port_pkt_read_tree_path(A,B,C,D,E,F)
#define prox_rte_sched_port_pkt_write(A,B,C,D,E,F,G) rte_sched_port_pkt_write(A,B,C,D,E,F,G);
#endif

#if RTE_VERSION < RTE_VERSION_NUM(19,8,0,0)
#if RTE_VERSION >= RTE_VERSION_NUM(18,5,0,0)
typedef struct vxlan_gpe_hdr prox_rte_vxlan_gpe_hdr;
#endif
#define PROX_RTE_ETHER_CRC_LEN ETHER_CRC_LEN
#define PROX_RTE_ETHER_MIN_LEN ETHER_MIN_LEN
#define PROX_RTE_ETHER_MAX_LEN ETHER_MAX_LEN
#define PROX_RTE_ETHER_HDR_LEN ETHER_HDR_LEN
#define PROX_RTE_TCP_SYN_FLAG TCP_SYN_FLAG
#define PROX_RTE_TCP_FIN_FLAG TCP_FIN_FLAG
#define PROX_RTE_TCP_RST_FLAG TCP_RST_FLAG
#define PROX_RTE_TCP_ACK_FLAG TCP_ACK_FLAG

#define prox_rte_ether_addr_copy ether_addr_copy
#define prox_rte_eth_random_addr eth_random_addr

typedef struct ipv6_hdr prox_rte_ipv6_hdr;
typedef struct ipv4_hdr prox_rte_ipv4_hdr;
typedef struct ether_addr prox_rte_ether_addr;
typedef struct ether_hdr prox_rte_ether_hdr;
typedef struct vlan_hdr prox_rte_vlan_hdr;
typedef struct udp_hdr prox_rte_udp_hdr;
typedef struct tcp_hdr prox_rte_tcp_hdr;

#ifndef RTE_SCHED_BE_QUEUES_PER_PIPE
#define RTE_SCHED_BE_QUEUES_PER_PIPE RTE_SCHED_QUEUES_PER_PIPE
#endif

#define PROX_RTE_IS_IPV4_MCAST IS_IPV4_MCAST
#define prox_rte_is_same_ether_addr is_same_ether_addr
#else

#define PROX_RTE_ETHER_CRC_LEN RTE_ETHER_CRC_LEN
#define PROX_RTE_ETHER_MIN_LEN RTE_ETHER_MIN_LEN
#define PROX_RTE_ETHER_MAX_LEN RTE_ETHER_MAX_LEN
#define PROX_RTE_ETHER_HDR_LEN RTE_ETHER_HDR_LEN
#define PROX_RTE_TCP_SYN_FLAG RTE_TCP_SYN_FLAG
#define PROX_RTE_TCP_FIN_FLAG RTE_TCP_FIN_FLAG
#define PROX_RTE_TCP_RST_FLAG RTE_TCP_RST_FLAG
#define PROX_RTE_TCP_ACK_FLAG RTE_TCP_ACK_FLAG

#define prox_rte_ether_addr_copy rte_ether_addr_copy
#define prox_rte_eth_random_addr rte_eth_random_addr

typedef struct rte_ipv6_hdr prox_rte_ipv6_hdr;
typedef struct rte_ipv4_hdr prox_rte_ipv4_hdr;
typedef struct rte_ether_addr prox_rte_ether_addr;
typedef struct rte_ether_hdr prox_rte_ether_hdr;
typedef struct rte_vlan_hdr prox_rte_vlan_hdr;
typedef struct rte_vxlan_gpe_hdr prox_rte_vxlan_gpe_hdr;
typedef struct rte_udp_hdr prox_rte_udp_hdr;
typedef struct rte_tcp_hdr prox_rte_tcp_hdr;

#define PROX_RTE_IS_IPV4_MCAST  RTE_IS_IPV4_MCAST
#define prox_rte_is_same_ether_addr rte_is_same_ether_addr

#endif

static inline char *prox_strncpy(char * dest, const char * src, size_t count)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wstringop-truncation"
	strncpy(dest, src, count);
#pragma GCC diagnostic pop
	PROX_PANIC(dest[count - 1] != 0, "\t\tError in strncpy: buffer overrun (%lu bytes)", count);
	return dest;
}
#ifdef RTE_LIBRTE_PMD_AESNI_MB
#if RTE_VERSION < RTE_VERSION_NUM(19,5,0,0)
//RFC4303
struct prox_esp_hdr {
        uint32_t spi;
        uint32_t seq;
};
struct prox_rte_cryptodev_qp_conf {
	uint32_t nb_descriptors; /**< Number of descriptors per queue pair */
	struct rte_mempool * 	mp_session;
	struct rte_mempool * 	mp_session_private;
};

static int prox_rte_cryptodev_queue_pair_setup(uint8_t dev_id, uint16_t queue_pair_id, struct prox_rte_cryptodev_qp_conf *qp_conf, int socket_id)
{
	struct rte_mempool *session_pool = qp_conf->mp_session;
	return rte_cryptodev_queue_pair_setup(dev_id, queue_pair_id, (struct rte_cryptodev_qp_conf *)qp_conf, socket_id, session_pool);
}

#else
#define prox_rte_cryptodev_qp_conf rte_cryptodev_qp_conf
static int prox_rte_cryptodev_queue_pair_setup(uint8_t dev_id, uint16_t queue_pair_id, struct prox_rte_cryptodev_qp_conf *qp_conf, int socket_id)
{
	return rte_cryptodev_queue_pair_setup(dev_id, queue_pair_id, (struct rte_cryptodev_qp_conf *)qp_conf, socket_id);
}

#if RTE_VERSION < RTE_VERSION_NUM(19,8,0,0)
#define prox_esp_hdr esp_hdr

#else	// From DPDK 19.08
#define prox_esp_hdr rte_esp_hdr

#endif
#endif
#endif	// CONFIG_RTE_LIBRTE_PMD_AESNI_MB

#endif // _PROX_COMPAT_H
