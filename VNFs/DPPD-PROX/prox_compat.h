/*
// Copyright (c) 2010-2020 Intel Corporation
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
#include <rte_ethdev.h>
#include <rte_hash_crc.h>
#include <rte_cryptodev.h>

#include "hash_utils.h"
#include "log.h"

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

#if RTE_VERSION < RTE_VERSION_NUM(16,4,0,0)
typedef uint8_t prox_next_hop_index_type;
#else
typedef uint32_t prox_next_hop_index_type;
#endif

#if RTE_VERSION < RTE_VERSION_NUM(16,7,0,0)
static void rte_mempool_free(struct rte_mempool *mp)
{
	plog_warn("rte_mempool_free not supported in this DPDK - upgrade DPDK to avoid memory leaks\n");
}
#endif

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

static inline int prox_rte_eth_dev_get_port_by_name(const char *name, uint16_t *port_id)
{
#if RTE_VERSION < RTE_VERSION_NUM(16,7,0,0)
	plog_err("Not supported in DPDK version <= 16.04 by lack of rte_eth_dev_get_port_by_name support\n");
	return -1;
#else
	return rte_eth_dev_get_port_by_name(name, (uint8_t *)port_id);
#endif
}

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

#define prox_rte_eth_dev_get_port_by_name rte_eth_dev_get_port_by_name

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
#define PROX_RTE_IP_ICMP_ECHO_REPLY IP_ICMP_ECHO_REPLY
#define PROX_RTE_IP_ICMP_ECHO_REQUEST IP_ICMP_ECHO_REQUEST

#define prox_rte_ether_addr_copy ether_addr_copy
#define prox_rte_eth_random_addr eth_random_addr

typedef struct ipv6_hdr prox_rte_ipv6_hdr;
typedef struct ipv4_hdr prox_rte_ipv4_hdr;
typedef struct ether_addr prox_rte_ether_addr;
typedef struct ether_hdr prox_rte_ether_hdr;
typedef struct vlan_hdr prox_rte_vlan_hdr;
typedef struct udp_hdr prox_rte_udp_hdr;
typedef struct tcp_hdr prox_rte_tcp_hdr;
typedef struct icmp_hdr prox_rte_icmp_hdr;

#ifndef RTE_SCHED_BE_QUEUES_PER_PIPE
#define RTE_SCHED_BE_QUEUES_PER_PIPE RTE_SCHED_QUEUES_PER_PIPE
#endif

#define PROX_RTE_IS_IPV4_MCAST IS_IPV4_MCAST
#define prox_rte_is_same_ether_addr is_same_ether_addr
#define prox_rte_is_zero_ether_addr is_zero_ether_addr
#else //  >= 19.08

#define PROX_RTE_ETHER_CRC_LEN RTE_ETHER_CRC_LEN
#define PROX_RTE_ETHER_MIN_LEN RTE_ETHER_MIN_LEN
#define PROX_RTE_ETHER_MAX_LEN RTE_ETHER_MAX_LEN
#define PROX_RTE_ETHER_HDR_LEN RTE_ETHER_HDR_LEN
#define PROX_RTE_TCP_SYN_FLAG RTE_TCP_SYN_FLAG
#define PROX_RTE_TCP_FIN_FLAG RTE_TCP_FIN_FLAG
#define PROX_RTE_TCP_RST_FLAG RTE_TCP_RST_FLAG
#define PROX_RTE_TCP_ACK_FLAG RTE_TCP_ACK_FLAG
#define PROX_RTE_IP_ICMP_ECHO_REPLY RTE_IP_ICMP_ECHO_REPLY
#define PROX_RTE_IP_ICMP_ECHO_REQUEST RTE_IP_ICMP_ECHO_REQUEST

#define prox_rte_ether_addr_copy rte_ether_addr_copy
#define prox_rte_eth_random_addr rte_eth_random_addr

typedef struct rte_ipv6_hdr prox_rte_ipv6_hdr;
typedef struct rte_ipv4_hdr prox_rte_ipv4_hdr;
typedef struct rte_ether_addr prox_rte_ether_addr;
#if RTE_VERSION < RTE_VERSION_NUM(21,11,0,0)
typedef struct rte_ether_hdr prox_rte_ether_hdr;
#else
typedef struct prox_rte_ether_hdr
{
	struct rte_ether_addr d_addr; /**< Destination address. */
	struct rte_ether_addr s_addr; /**< Source address. */
	rte_be16_t ether_type; /**< Frame type. */
} __rte_aligned(2) prox_rte_ether_hdr;
#endif
typedef struct rte_vlan_hdr prox_rte_vlan_hdr;
typedef struct rte_vxlan_gpe_hdr prox_rte_vxlan_gpe_hdr;
typedef struct rte_udp_hdr prox_rte_udp_hdr;
typedef struct rte_tcp_hdr prox_rte_tcp_hdr;
typedef struct rte_icmp_hdr prox_rte_icmp_hdr;

#define PROX_RTE_IS_IPV4_MCAST  RTE_IS_IPV4_MCAST
#define prox_rte_is_same_ether_addr rte_is_same_ether_addr
#define prox_rte_is_zero_ether_addr rte_is_zero_ether_addr

#endif

char *prox_strncpy(char * dest, const char * src, size_t count);

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

#if RTE_VERSION < RTE_VERSION_NUM(19,11,0,0)
#define prox_rte_eth_dev_count_avail() rte_eth_dev_count()
#else
#define prox_rte_eth_dev_count_avail() rte_eth_dev_count_avail()
#endif

// deal with RTE_DEPRECATED symbols

#if RTE_VERSION < RTE_VERSION_NUM(20,11,0,0)
#define SKIP_MAIN			SKIP_MASTER
#define CALL_MAIN			CALL_MASTER
#define RTE_DEVTYPE_ALLOWED		RTE_DEVTYPE_WHITELISTED_PCI
#define RTE_DEVTYPE_BLOCKED		RTE_DEVTYPE_BLACKLISTED_PCI
#define RTE_LCORE_FOREACH_WORKER	RTE_LCORE_FOREACH_SLAVE
#if RTE_VERSION >= RTE_VERSION_NUM(17,8,0,0)
#define RTE_DEV_ALLOWED			RTE_DEV_WHITELISTED
#define RTE_DEV_BLOCKED			RTE_DEV_BLACKLISTED
#define RTE_BUS_SCAN_ALLOWLIST		RTE_BUS_SCAN_WHITELIST
#define RTE_BUS_SCAN_BLOCKLIST		RTE_BUS_SCAN_BLACKLIST
#endif
#endif

#if RTE_VERSION < RTE_VERSION_NUM(21,5,0,0)
#define RTE_PCI_ANY_ID			PCI_ANY_ID
#define PKT_RX_OUTER_IP_CKSUM_BAD	PKT_RX_EIP_CKSUM_BAD
#endif

#if RTE_VERSION < RTE_VERSION_NUM(21,11,0,0)
#define RTE_MEMPOOL_HEADER_SIZE		MEMPOOL_HEADER_SIZE
#define RTE_MBUF_F_RX_RSS_HASH		PKT_RX_RSS_HASH
#define RTE_MBUF_F_RX_FDIR		PKT_RX_FDIR
#define RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD	PKT_RX_OUTER_IP_CKSUM_BAD
#define RTE_MBUF_F_RX_IP_CKSUM_BAD	PKT_RX_IP_CKSUM_BAD
#define RTE_MBUF_F_RX_L4_CKSUM_BAD	PKT_RX_L4_CKSUM_BAD
#define RTE_MBUF_F_RX_IEEE1588_PTP	PKT_RX_IEEE1588_PTP
#define RTE_MBUF_F_RX_IEEE1588_TMST	PKT_RX_IEEE1588_TMST
#define RTE_MBUF_F_RX_FDIR_ID		PKT_RX_FDIR_ID
#define RTE_MBUF_F_RX_FDIR_FLX		PKT_RX_FDIR_FLX
#define RTE_MBUF_F_TX_QINQ		PKT_TX_QINQ_PKT
#define RTE_MBUF_F_TX_TCP_SEG		PKT_TX_TCP_SEG
#define RTE_MBUF_F_TX_IEEE1588_TMST	PKT_TX_IEEE1588_TMST
#define RTE_MBUF_F_TX_L4_NO_CKSUM	PKT_TX_L4_NO_CKSUM
#define RTE_MBUF_F_TX_TCP_CKSUM		PKT_TX_TCP_CKSUM
#define RTE_MBUF_F_TX_SCTP_CKSUM	PKT_TX_SCTP_CKSUM
#define RTE_MBUF_F_TX_UDP_CKSUM		PKT_TX_UDP_CKSUM
#define RTE_MBUF_F_TX_L4_MASK		PKT_TX_L4_MASK
#define RTE_MBUF_F_TX_IP_CKSUM		PKT_TX_IP_CKSUM
#define RTE_MBUF_F_TX_IPV4		PKT_TX_IPV4
#define RTE_MBUF_F_TX_IPV6		PKT_TX_IPV6
#define RTE_MBUF_F_TX_VLAN		PKT_TX_VLAN_PKT
#define RTE_MBUF_F_TX_OUTER_IP_CKSUM	PKT_TX_OUTER_IP_CKSUM
#define RTE_MBUF_F_TX_OUTER_IPV4	PKT_TX_OUTER_IPV4
#define RTE_MBUF_F_TX_OUTER_IPV6	PKT_TX_OUTER_IPV6
#define RTE_MBUF_F_INDIRECT		IND_ATTACHED_MBUF
#define RTE_ETH_LINK_SPEED_AUTONEG	ETH_LINK_SPEED_AUTONEG
#define RTE_ETH_LINK_SPEED_FIXED	ETH_LINK_SPEED_FIXED
#define RTE_ETH_LINK_SPEED_10M_HD	ETH_LINK_SPEED_10M_HD
#define RTE_ETH_LINK_SPEED_10M		ETH_LINK_SPEED_10M
#define RTE_ETH_LINK_SPEED_100M_HD	ETH_LINK_SPEED_100M_HD
#define RTE_ETH_LINK_SPEED_100M		ETH_LINK_SPEED_100M
#define RTE_ETH_LINK_SPEED_1G		ETH_LINK_SPEED_1G
#define RTE_ETH_LINK_SPEED_2_5G		ETH_LINK_SPEED_2_5G
#define RTE_ETH_LINK_SPEED_5G		ETH_LINK_SPEED_5G
#define RTE_ETH_LINK_SPEED_10G		ETH_LINK_SPEED_10G
#define RTE_ETH_LINK_SPEED_20G		ETH_LINK_SPEED_20G
#define RTE_ETH_LINK_SPEED_25G		ETH_LINK_SPEED_25G
#define RTE_ETH_LINK_SPEED_40G		ETH_LINK_SPEED_40G
#define RTE_ETH_LINK_SPEED_50G		ETH_LINK_SPEED_50G
#define RTE_ETH_LINK_SPEED_56G		ETH_LINK_SPEED_56G
#define RTE_ETH_LINK_SPEED_100G		ETH_LINK_SPEED_100G
#define RTE_ETH_SPEED_NUM_NONE		ETH_SPEED_NUM_NONE
#define RTE_ETH_SPEED_NUM_10M		ETH_SPEED_NUM_10M
#define RTE_ETH_SPEED_NUM_100M		ETH_SPEED_NUM_100M
#define RTE_ETH_SPEED_NUM_1G		ETH_SPEED_NUM_1G
#define RTE_ETH_SPEED_NUM_2_5G		ETH_SPEED_NUM_2_5G
#define RTE_ETH_SPEED_NUM_5G		ETH_SPEED_NUM_5G
#define RTE_ETH_SPEED_NUM_10G		ETH_SPEED_NUM_10G
#define RTE_ETH_SPEED_NUM_20G		ETH_SPEED_NUM_20G
#define RTE_ETH_SPEED_NUM_25G		ETH_SPEED_NUM_25G
#define RTE_ETH_SPEED_NUM_40G		ETH_SPEED_NUM_40G
#define RTE_ETH_SPEED_NUM_50G		ETH_SPEED_NUM_50G
#define RTE_ETH_SPEED_NUM_56G		ETH_SPEED_NUM_56G
#define RTE_ETH_SPEED_NUM_100G		ETH_SPEED_NUM_100G
#define RTE_ETH_LINK_HALF_DUPLEX	ETH_LINK_HALF_DUPLEX
#define RTE_ETH_LINK_FULL_DUPLEX	ETH_LINK_FULL_DUPLEX
#define RTE_ETH_LINK_DOWN		ETH_LINK_DOWN
#define RTE_ETH_LINK_UP			ETH_LINK_UP
#define RTE_ETH_LINK_FIXED		ETH_LINK_FIXED
#define RTE_ETH_LINK_AUTONEG		ETH_LINK_AUTONEG
#define RTE_ETH_MQ_RX_RSS_FLAG		ETH_MQ_RX_RSS_FLAG
#define RTE_ETH_MQ_RX_DCB_FLAG		ETH_MQ_RX_DCB_FLAG
#define RTE_ETH_MQ_RX_VMDQ_FLAG		ETH_MQ_RX_VMDQ_FLAG
#define RTE_ETH_MQ_RX_NONE		ETH_MQ_RX_NONE
#define RTE_ETH_MQ_RX_RSS		ETH_MQ_RX_RSS
#define RTE_ETH_MQ_RX_DCB		ETH_MQ_RX_DCB
#define RTE_ETH_MQ_RX_DCB_RSS		ETH_MQ_RX_DCB_RSS
#define RTE_ETH_MQ_RX_VMDQ_ONLY		ETH_MQ_RX_VMDQ_ONLY
#define RTE_ETH_MQ_RX_VMDQ_RSS		ETH_MQ_RX_VMDQ_RSS
#define RTE_ETH_MQ_RX_VMDQ_DCB		ETH_MQ_RX_VMDQ_DCB
#define RTE_ETH_MQ_RX_VMDQ_DCB_RSS	ETH_MQ_RX_VMDQ_DCB_RSS
#define RTE_ETH_MQ_TX_NONE		ETH_MQ_TX_NONE
#define RTE_ETH_MQ_TX_DCB		ETH_MQ_TX_DCB
#define RTE_ETH_MQ_TX_VMDQ_DCB		ETH_MQ_TX_VMDQ_DCB
#define RTE_ETH_MQ_TX_VMDQ_ONLY		ETH_MQ_TX_VMDQ_ONLY
#define RTE_ETH_VLAN_TYPE_UNKNOWN	ETH_VLAN_TYPE_UNKNOWN
#define RTE_ETH_VLAN_TYPE_INNER		ETH_VLAN_TYPE_INNER
#define RTE_ETH_VLAN_TYPE_OUTER		ETH_VLAN_TYPE_OUTER
#define RTE_ETH_VLAN_TYPE_MAX		ETH_VLAN_TYPE_MAX
#define RTE_ETH_RSS_IPV4		ETH_RSS_IPV4
#define RTE_ETH_RSS_FRAG_IPV4		ETH_RSS_FRAG_IPV4
#define RTE_ETH_RSS_NONFRAG_IPV4_TCP	ETH_RSS_NONFRAG_IPV4_TCP
#define RTE_ETH_RSS_NONFRAG_IPV4_UDP	ETH_RSS_NONFRAG_IPV4_UDP
#define RTE_ETH_RSS_NONFRAG_IPV4_SCTP	ETH_RSS_NONFRAG_IPV4_SCTP
#define RTE_ETH_RSS_NONFRAG_IPV4_OTHER	ETH_RSS_NONFRAG_IPV4_OTHER
#define RTE_ETH_RSS_IPV6		ETH_RSS_IPV6
#define RTE_ETH_RSS_FRAG_IPV6		ETH_RSS_FRAG_IPV6
#define RTE_ETH_RSS_NONFRAG_IPV6_TCP	ETH_RSS_NONFRAG_IPV6_TCP
#define RTE_ETH_RSS_NONFRAG_IPV6_UDP	ETH_RSS_NONFRAG_IPV6_UDP
#define RTE_ETH_RSS_NONFRAG_IPV6_SCTP	ETH_RSS_NONFRAG_IPV6_SCTP
#define RTE_ETH_RSS_NONFRAG_IPV6_OTHER	ETH_RSS_NONFRAG_IPV6_OTHER
#define RTE_ETH_RSS_L2_PAYLOAD		ETH_RSS_L2_PAYLOAD
#define RTE_ETH_RSS_IPV6_EX		ETH_RSS_IPV6_EX
#define RTE_ETH_RSS_IPV6_TCP_EX		ETH_RSS_IPV6_TCP_EX
#define RTE_ETH_RSS_IPV6_UDP_EX		ETH_RSS_IPV6_UDP_EX
#define RTE_ETH_RSS_IP			ETH_RSS_IP
#define RTE_ETH_RSS_UDP			ETH_RSS_UDP
#define RTE_ETH_RSS_TCP			ETH_RSS_TCP
#define RTE_ETH_RSS_SCTP		ETH_RSS_SCTP
#define RTE_ETH_RSS_PROTO_MASK		ETH_RSS_PROTO_MASK
#define RTE_ETH_RSS_RETA_SIZE_64	ETH_RSS_RETA_SIZE_64
#define RTE_ETH_RSS_RETA_SIZE_128	ETH_RSS_RETA_SIZE_128
#define RTE_ETH_RSS_RETA_SIZE_512	ETH_RSS_RETA_SIZE_512
#define RTE_ETH_RETA_GROUP_SIZE		RTE_RETA_GROUP_SIZE
#define RTE_ETH_VMDQ_MAX_VLAN_FILTERS	ETH_VMDQ_MAX_VLAN_FILTERS
#define RTE_ETH_DCB_NUM_USER_PRIORITIES	ETH_DCB_NUM_USER_PRIORITIES
#define RTE_ETH_VMDQ_DCB_NUM_QUEUES	ETH_VMDQ_DCB_NUM_QUEUES
#define RTE_ETH_DCB_NUM_QUEUES		ETH_DCB_NUM_QUEUES
#define RTE_ETH_DCB_PG_SUPPORT		ETH_DCB_PG_SUPPORT
#define RTE_ETH_DCB_PFC_SUPPORT		ETH_DCB_PFC_SUPPORT
#define RTE_ETH_VLAN_STRIP_OFFLOAD	ETH_VLAN_STRIP_OFFLOAD
#define RTE_ETH_VLAN_FILTER_OFFLOAD	ETH_VLAN_FILTER_OFFLOAD
#define RTE_ETH_VLAN_EXTEND_OFFLOAD	ETH_VLAN_EXTEND_OFFLOAD
#define RTE_ETH_VLAN_STRIP_MASK		ETH_VLAN_STRIP_MASK
#define RTE_ETH_VLAN_FILTER_MASK	ETH_VLAN_FILTER_MASK
#define RTE_ETH_VLAN_EXTEND_MASK	ETH_VLAN_EXTEND_MASK
#define RTE_ETH_VLAN_ID_MAX		ETH_VLAN_ID_MAX
#define RTE_ETH_NUM_RECEIVE_MAC_ADDR	ETH_NUM_RECEIVE_MAC_ADDR
#define RTE_ETH_VMDQ_NUM_UC_HASH_ARRAY	ETH_VMDQ_NUM_UC_HASH_ARRAY
#define RTE_ETH_VMDQ_ACCEPT_UNTAG	ETH_VMDQ_ACCEPT_UNTAG
#define RTE_ETH_VMDQ_ACCEPT_HASH_MC	ETH_VMDQ_ACCEPT_HASH_MC
#define RTE_ETH_VMDQ_ACCEPT_HASH_UC	ETH_VMDQ_ACCEPT_HASH_UC
#define RTE_ETH_VMDQ_ACCEPT_BROADCAST	ETH_VMDQ_ACCEPT_BROADCAST
#define RTE_ETH_VMDQ_ACCEPT_MULTICAST	ETH_VMDQ_ACCEPT_MULTICAST
#define RTE_ETH_4_TCS			ETH_4_TCS
#define RTE_ETH_8_TCS			ETH_8_TCS
#define RTE_ETH_8_POOLS			ETH_8_POOLS
#define RTE_ETH_16_POOLS		ETH_16_POOLS
#define RTE_ETH_32_POOLS		ETH_32_POOLS
#define RTE_ETH_64_POOLS		ETH_64_POOLS
#define RTE_ETH_FC_NONE			RTE_FC_NONE
#define RTE_ETH_FC_RX_PAUSE		RTE_FC_RX_PAUSE
#define RTE_ETH_FC_TX_PAUSE		RTE_FC_TX_PAUSE
#define RTE_ETH_FC_FULL			RTE_FC_FULL
#define RTE_ETH_TUNNEL_TYPE_NONE	RTE_TUNNEL_TYPE_NONE
#define RTE_ETH_TUNNEL_TYPE_VXLAN	RTE_TUNNEL_TYPE_VXLAN
#define RTE_ETH_TUNNEL_TYPE_GENEVE	RTE_TUNNEL_TYPE_GENEVE
#define RTE_ETH_TUNNEL_TYPE_TEREDO	RTE_TUNNEL_TYPE_TEREDO
#define RTE_ETH_TUNNEL_TYPE_NVGRE	RTE_TUNNEL_TYPE_NVGRE
#define RTE_ETH_TUNNEL_TYPE_IP_IN_GRE	RTE_TUNNEL_TYPE_IP_IN_GRE
#define RTE_ETH_L2_TUNNEL_TYPE_E_TAG	RTE_L2_TUNNEL_TYPE_E_TAG
#define RTE_ETH_TUNNEL_TYPE_MAX		RTE_TUNNEL_TYPE_MAX
#define RTE_ETH_FDIR_PBALLOC_64K	RTE_FDIR_PBALLOC_64K
#define RTE_ETH_FDIR_PBALLOC_128K	RTE_FDIR_PBALLOC_128K
#define RTE_ETH_FDIR_PBALLOC_256K	RTE_FDIR_PBALLOC_256K
#define RTE_ETH_RX_OFFLOAD_VLAN_STRIP	DEV_RX_OFFLOAD_VLAN_STRIP
#define RTE_ETH_RX_OFFLOAD_IPV4_CKSUM	DEV_RX_OFFLOAD_IPV4_CKSUM
#define RTE_ETH_RX_OFFLOAD_UDP_CKSUM	DEV_RX_OFFLOAD_UDP_CKSUM
#define RTE_ETH_RX_OFFLOAD_TCP_CKSUM	DEV_RX_OFFLOAD_TCP_CKSUM
#define RTE_ETH_RX_OFFLOAD_TCP_LRO	DEV_RX_OFFLOAD_TCP_LRO
#define RTE_ETH_RX_OFFLOAD_QINQ_STRIP	DEV_RX_OFFLOAD_QINQ_STRIP
#define RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM	DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM
#define RTE_ETH_TX_OFFLOAD_VLAN_INSERT	DEV_TX_OFFLOAD_VLAN_INSERT
#define RTE_ETH_TX_OFFLOAD_IPV4_CKSUM	DEV_TX_OFFLOAD_IPV4_CKSUM
#define RTE_ETH_TX_OFFLOAD_UDP_CKSUM	DEV_TX_OFFLOAD_UDP_CKSUM
#define RTE_ETH_TX_OFFLOAD_TCP_CKSUM	DEV_TX_OFFLOAD_TCP_CKSUM
#define RTE_ETH_TX_OFFLOAD_SCTP_CKSUM	DEV_TX_OFFLOAD_SCTP_CKSUM
#define RTE_ETH_TX_OFFLOAD_TCP_TSO	DEV_TX_OFFLOAD_TCP_TSO
#define RTE_ETH_TX_OFFLOAD_UDP_TSO	DEV_TX_OFFLOAD_UDP_TSO
#define RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM	DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM
#define RTE_ETH_TX_OFFLOAD_QINQ_INSERT	DEV_TX_OFFLOAD_QINQ_INSERT
#define RTE_ETH_DCB_NUM_TCS		ETH_DCB_NUM_TCS
#define RTE_ETH_MAX_VMDQ_POOL		ETH_MAX_VMDQ_POOL
#if RTE_VERSION >= RTE_VERSION_NUM(16,7,0,0)
#define RTE_MEMPOOL_REGISTER_OPS	MEMPOOL_REGISTER_OPS
#define RTE_MBUF_F_RX_VLAN_STRIPPED	PKT_RX_VLAN_STRIPPED
#define RTE_MBUF_F_RX_QINQ_STRIPPED	PKT_RX_QINQ_STRIPPED
#define RTE_ETH_RSS_PORT		ETH_RSS_PORT
#define RTE_ETH_RSS_VXLAN		ETH_RSS_VXLAN
#define RTE_ETH_RSS_GENEVE		ETH_RSS_GENEVE
#define RTE_ETH_RSS_NVGRE		ETH_RSS_NVGRE
#define RTE_ETH_RSS_TUNNEL		ETH_RSS_TUNNEL
#define RTE_ETH_RSS_RETA_SIZE_256	ETH_RSS_RETA_SIZE_256
#endif
#if RTE_VERSION >= RTE_VERSION_NUM(16,11,0,0)
#define RTE_MBUF_F_RX_IP_CKSUM_MASK	PKT_RX_IP_CKSUM_MASK
#define RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN	PKT_RX_IP_CKSUM_UNKNOWN
#define RTE_MBUF_F_RX_IP_CKSUM_GOOD	PKT_RX_IP_CKSUM_GOOD
#define RTE_MBUF_F_RX_IP_CKSUM_NONE	PKT_RX_IP_CKSUM_NONE
#define RTE_MBUF_F_RX_L4_CKSUM_MASK	PKT_RX_L4_CKSUM_MASK
#define RTE_MBUF_F_RX_L4_CKSUM_UNKNOWN	PKT_RX_L4_CKSUM_UNKNOWN
#define RTE_MBUF_F_RX_L4_CKSUM_GOOD	PKT_RX_L4_CKSUM_GOOD
#define RTE_MBUF_F_RX_L4_CKSUM_NONE	PKT_RX_L4_CKSUM_NONE
#define RTE_MBUF_F_RX_LRO		PKT_RX_LRO
#define RTE_MBUF_F_TX_TUNNEL_VXLAN	PKT_TX_TUNNEL_VXLAN
#define RTE_MBUF_F_TX_TUNNEL_GRE	PKT_TX_TUNNEL_GRE
#define RTE_MBUF_F_TX_TUNNEL_IPIP	PKT_TX_TUNNEL_IPIP
#define RTE_MBUF_F_TX_TUNNEL_GENEVE	PKT_TX_TUNNEL_GENEVE
#define RTE_MBUF_F_TX_TUNNEL_MASK	PKT_TX_TUNNEL_MASK
#define RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO	DEV_TX_OFFLOAD_VXLAN_TNL_TSO
#define RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO		DEV_TX_OFFLOAD_GRE_TNL_TSO
#define RTE_ETH_TX_OFFLOAD_IPIP_TNL_TSO		DEV_TX_OFFLOAD_IPIP_TNL_TSO
#define RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO	DEV_TX_OFFLOAD_GENEVE_TNL_TSO
#endif
#if RTE_VERSION >= RTE_VERSION_NUM(17,2,0,0)
#define RTE_MBUF_F_TX_MACSEC		PKT_TX_MACSEC
#define RTE_MBUF_F_TX_OFFLOAD_MASK	PKT_TX_OFFLOAD_MASK
#define RTE_ETH_RX_OFFLOAD_MACSEC_STRIP		DEV_RX_OFFLOAD_MACSEC_STRIP
#define RTE_ETH_TX_OFFLOAD_MACSEC_INSERT	DEV_TX_OFFLOAD_MACSEC_INSERT
#endif
#if RTE_VERSION >= RTE_VERSION_NUM(17,8,0,0)
#define RTE_MBUF_F_TX_TUNNEL_MPLSINUDP	PKT_TX_TUNNEL_MPLSINUDP
#define RTE_ETH_TX_OFFLOAD_MT_LOCKFREE	DEV_TX_OFFLOAD_MT_LOCKFREE
#endif
#if RTE_VERSION >= RTE_VERSION_NUM(17,11,0,0)
#define RTE_MBUF_F_RX_VLAN			PKT_RX_VLAN
#define RTE_MBUF_F_RX_SEC_OFFLOAD		PKT_RX_SEC_OFFLOAD
#define RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED	PKT_RX_SEC_OFFLOAD_FAILED
#define RTE_MBUF_F_RX_QINQ			PKT_RX_QINQ
#define RTE_MBUF_F_TX_SEC_OFFLOAD		PKT_TX_SEC_OFFLOAD
#define RTE_ETH_RX_OFFLOAD_HEADER_SPLIT	DEV_RX_OFFLOAD_HEADER_SPLIT
#define RTE_ETH_RX_OFFLOAD_VLAN_FILTER	DEV_RX_OFFLOAD_VLAN_FILTER
#define RTE_ETH_RX_OFFLOAD_VLAN_EXTEND	DEV_RX_OFFLOAD_VLAN_EXTEND
#define RTE_ETH_RX_OFFLOAD_SCATTER	DEV_RX_OFFLOAD_SCATTER
#define RTE_ETH_RX_OFFLOAD_TIMESTAMP	DEV_RX_OFFLOAD_TIMESTAMP
#define RTE_ETH_RX_OFFLOAD_SECURITY	DEV_RX_OFFLOAD_SECURITY
#define RTE_ETH_RX_OFFLOAD_CHECKSUM	DEV_RX_OFFLOAD_CHECKSUM
#define RTE_ETH_RX_OFFLOAD_VLAN		DEV_RX_OFFLOAD_VLAN
#define RTE_ETH_TX_OFFLOAD_MULTI_SEGS	DEV_TX_OFFLOAD_MULTI_SEGS
#define RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE	DEV_TX_OFFLOAD_MBUF_FAST_FREE
#define RTE_ETH_TX_OFFLOAD_SECURITY	DEV_TX_OFFLOAD_SECURITY
#endif
#if RTE_VERSION >= RTE_VERSION_NUM(18,2,0,0)
#define RTE_MBUF_F_TX_UDP_SEG		PKT_TX_UDP_SEG
#endif
#if RTE_VERSION >= RTE_VERSION_NUM(18,5,0,0)
#define RTE_MBUF_F_TX_TUNNEL_VXLAN_GPE	PKT_TX_TUNNEL_VXLAN_GPE
#define RTE_MBUF_F_TX_TUNNEL_IP		PKT_TX_TUNNEL_IP
#define RTE_MBUF_F_TX_TUNNEL_UDP	PKT_TX_TUNNEL_UDP
#define RTE_MBUF_F_EXTERNAL		EXT_ATTACHED_MBUF
#define RTE_ETH_TX_OFFLOAD_UDP_TNL_TSO	DEV_TX_OFFLOAD_UDP_TNL_TSO
#define RTE_ETH_TX_OFFLOAD_IP_TNL_TSO	DEV_TX_OFFLOAD_IP_TNL_TSO
#endif
#if RTE_VERSION >= RTE_VERSION_NUM(18,11,0,0)
#define RTE_MBUF_F_RX_OUTER_L4_CKSUM_MASK	PKT_RX_OUTER_L4_CKSUM_MASK
#define RTE_MBUF_F_RX_OUTER_L4_CKSUM_UNKNOWN	PKT_RX_OUTER_L4_CKSUM_UNKNOWN
#define RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD	PKT_RX_OUTER_L4_CKSUM_BAD
#define RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD	PKT_RX_OUTER_L4_CKSUM_GOOD
#define RTE_MBUF_F_RX_OUTER_L4_CKSUM_INVALID	PKT_RX_OUTER_L4_CKSUM_INVALID
#define RTE_MBUF_F_TX_OUTER_UDP_CKSUM		PKT_TX_OUTER_UDP_CKSUM
#define RTE_ETH_RX_OFFLOAD_SCTP_CKSUM		DEV_RX_OFFLOAD_SCTP_CKSUM
#define RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM	DEV_RX_OFFLOAD_OUTER_UDP_CKSUM
#define RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM	DEV_TX_OFFLOAD_OUTER_UDP_CKSUM
#endif
#if RTE_VERSION >= RTE_VERSION_NUM(19,5,0,0)
#define RTE_ETH_TUNNEL_TYPE_VXLAN_GPE	RTE_TUNNEL_TYPE_VXLAN_GPE
#endif
#if RTE_VERSION >= RTE_VERSION_NUM(19,8,0,0)
#define RTE_ETH_QINQ_STRIP_OFFLOAD	ETH_QINQ_STRIP_OFFLOAD
#define RTE_ETH_QINQ_STRIP_MASK		ETH_QINQ_STRIP_MASK
#endif
#if RTE_VERSION >= RTE_VERSION_NUM(19,11,0,0)
#define RTE_MBUF_DYNFLAG_RX_METADATA	PKT_RX_DYNF_METADATA
#define RTE_MBUF_DYNFLAG_TX_METADATA	PKT_TX_DYNF_METADATA
#define RTE_MBUF_F_FIRST_FREE		PKT_FIRST_FREE
#define RTE_MBUF_F_LAST_FREE		PKT_LAST_FREE
#define RTE_MBUF_F_TX_TUNNEL_GTP	PKT_TX_TUNNEL_GTP
#define RTE_ETH_RSS_GTPU		ETH_RSS_GTPU
#define RTE_ETH_RSS_L3_SRC_ONLY		ETH_RSS_L3_SRC_ONLY
#define RTE_ETH_RSS_L3_DST_ONLY		ETH_RSS_L3_DST_ONLY
#define RTE_ETH_RSS_L4_SRC_ONLY		ETH_RSS_L4_SRC_ONLY
#define RTE_ETH_RSS_L4_DST_ONLY		ETH_RSS_L4_DST_ONLY
#define RTE_ETH_RX_OFFLOAD_RSS_HASH	DEV_RX_OFFLOAD_RSS_HASH
#endif
#if RTE_VERSION >= RTE_VERSION_NUM(20,5,0,0)
#define RTE_ETH_LINK_SPEED_200G		ETH_LINK_SPEED_200G
#define RTE_ETH_SPEED_NUM_200G		ETH_SPEED_NUM_200G
#define RTE_ETH_RSS_ETH			ETH_RSS_ETH
#define RTE_ETH_RSS_S_VLAN		ETH_RSS_S_VLAN
#define RTE_ETH_RSS_C_VLAN		ETH_RSS_C_VLAN
#define RTE_ETH_RSS_ESP			ETH_RSS_ESP
#define RTE_ETH_RSS_AH			ETH_RSS_AH
#define RTE_ETH_RSS_L2TPV3		ETH_RSS_L2TPV3
#define RTE_ETH_RSS_PFCP		ETH_RSS_PFCP
#define RTE_ETH_RSS_L2_SRC_ONLY		ETH_RSS_L2_SRC_ONLY
#define RTE_ETH_RSS_L2_DST_ONLY		ETH_RSS_L2_DST_ONLY
#define RTE_ETH_RSS_VLAN		ETH_RSS_VLAN
#endif
#if RTE_VERSION >= RTE_VERSION_NUM(20,8,0,0)
#define RTE_ETH_RSS_PPPOE		ETH_RSS_PPPOE
#define RTE_ETH_RSS_IPV6_PRE32		ETH_RSS_IPV6_PRE32
#define RTE_ETH_RSS_IPV6_PRE40		ETH_RSS_IPV6_PRE40
#define RTE_ETH_RSS_IPV6_PRE48		ETH_RSS_IPV6_PRE48
#define RTE_ETH_RSS_IPV6_PRE56		ETH_RSS_IPV6_PRE56
#define RTE_ETH_RSS_IPV6_PRE64		ETH_RSS_IPV6_PRE64
#define RTE_ETH_RSS_IPV6_PRE96		ETH_RSS_IPV6_PRE96
#define RTE_ETH_RSS_IPV6_PRE32_UDP	ETH_RSS_IPV6_PRE32_UDP
#define RTE_ETH_RSS_IPV6_PRE40_UDP	ETH_RSS_IPV6_PRE40_UDP
#define RTE_ETH_RSS_IPV6_PRE48_UDP	ETH_RSS_IPV6_PRE48_UDP
#define RTE_ETH_RSS_IPV6_PRE56_UDP	ETH_RSS_IPV6_PRE56_UDP
#define RTE_ETH_RSS_IPV6_PRE64_UDP	ETH_RSS_IPV6_PRE64_UDP
#define RTE_ETH_RSS_IPV6_PRE96_UDP	ETH_RSS_IPV6_PRE96_UDP
#define RTE_ETH_RSS_IPV6_PRE32_TCP	ETH_RSS_IPV6_PRE32_TCP
#define RTE_ETH_RSS_IPV6_PRE40_TCP	ETH_RSS_IPV6_PRE40_TCP
#define RTE_ETH_RSS_IPV6_PRE48_TCP	ETH_RSS_IPV6_PRE48_TCP
#define RTE_ETH_RSS_IPV6_PRE56_TCP	ETH_RSS_IPV6_PRE56_TCP
#define RTE_ETH_RSS_IPV6_PRE64_TCP	ETH_RSS_IPV6_PRE64_TCP
#define RTE_ETH_RSS_IPV6_PRE96_TCP	ETH_RSS_IPV6_PRE96_TCP
#define RTE_ETH_RSS_IPV6_PRE32_SCTP	ETH_RSS_IPV6_PRE32_SCTP
#define RTE_ETH_RSS_IPV6_PRE40_SCTP	ETH_RSS_IPV6_PRE40_SCTP
#define RTE_ETH_RSS_IPV6_PRE48_SCTP	ETH_RSS_IPV6_PRE48_SCTP
#define RTE_ETH_RSS_IPV6_PRE56_SCTP	ETH_RSS_IPV6_PRE56_SCTP
#define RTE_ETH_RSS_IPV6_PRE64_SCTP	ETH_RSS_IPV6_PRE64_SCTP
#define RTE_ETH_RSS_IPV6_PRE96_SCTP	ETH_RSS_IPV6_PRE96_SCTP
#define RTE_ETH_TX_OFFLOAD_SEND_ON_TIMESTAMP	DEV_TX_OFFLOAD_SEND_ON_TIMESTAMP
#endif
#if RTE_VERSION >= RTE_VERSION_NUM(20,11,0,0)
#define RTE_ETH_SPEED_NUM_UNKNOWN	ETH_SPEED_NUM_UNKNOWN
#define RTE_ETH_RSS_ECPRI		ETH_RSS_ECPRI
#define RTE_ETH_RSS_LEVEL_PMD_DEFAULT	ETH_RSS_LEVEL_PMD_DEFAULT
#define RTE_ETH_RSS_LEVEL_OUTERMOST	ETH_RSS_LEVEL_OUTERMOST
#define RTE_ETH_RSS_LEVEL_INNERMOST	ETH_RSS_LEVEL_INNERMOST
#define RTE_ETH_RSS_LEVEL_MASK		ETH_RSS_LEVEL_MASK
#define RTE_ETH_RSS_LEVEL		ETH_RSS_LEVEL
#endif
#if RTE_VERSION >= RTE_VERSION_NUM(21,2,0,0)
#define RTE_ETH_RSS_MPLS		ETH_RSS_MPLS
#define RTE_ETH_TUNNEL_TYPE_ECPRI	RTE_TUNNEL_TYPE_ECPRI
#endif

#ifndef DEV_RX_OFFLOAD_JUMBO_FRAME
#define RTE_ETH_RX_OFFLOAD_JUMBO_FRAME	0x00000800
#else
#define RTE_ETH_RX_OFFLOAD_JUMBO_FRAME	DEV_RX_OFFLOAD_JUMBO_FRAME
#endif

#ifndef DEV_RX_OFFLOAD_KEEP_CRC
#ifndef DEV_RX_OFFLOAD_CRC_STRIP
#define RTE_ETH_RX_OFFLOAD_CRC_STRIP	0x00001000
#else
#define RTE_ETH_RX_OFFLOAD_CRC_STRIP	DEV_RX_OFFLOAD_CRC_STRIP
#endif
#define RTE_ETH_RX_OFFLOAD_KEEP_CRC	_force_error_if_defined_
#undef  RTE_ETH_RX_OFFLOAD_KEEP_CRC

#else
#ifndef DEV_RX_OFFLOAD_CRC_STRIP
#define RTE_ETH_RX_OFFLOAD_CRC_STRIP	_force_error_if_defined_
#undef  RTE_ETH_RX_OFFLOAD_CRC_STRIP
#else
#define RTE_ETH_RX_OFFLOAD_CRC_STRIP	DEV_RX_OFFLOAD_CRC_STRIP
#endif
#define RTE_ETH_RX_OFFLOAD_KEEP_CRC	DEV_RX_OFFLOAD_KEEP_CRC
#endif

#else //  >= 21.11
#define RTE_ETH_RX_OFFLOAD_JUMBO_FRAME	RTE_BIT64(11)
#define RTE_ETH_RX_OFFLOAD_CRC_STRIP	_force_error_if_defined_
#undef  RTE_ETH_RX_OFFLOAD_CRC_STRIP
#endif

#endif // _PROX_COMPAT_H
