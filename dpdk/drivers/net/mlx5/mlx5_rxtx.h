/*-
 *   BSD LICENSE
 *
 *   Copyright 2015 6WIND S.A.
 *   Copyright 2015 Mellanox.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of 6WIND S.A. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef RTE_PMD_MLX5_RXTX_H_
#define RTE_PMD_MLX5_RXTX_H_

#include <stddef.h>
#include <stdint.h>

/* Verbs header. */
/* ISO C doesn't support unnamed structs/unions, disabling -pedantic. */
#ifdef PEDANTIC
#pragma GCC diagnostic ignored "-pedantic"
#endif
#include <infiniband/verbs.h>
#ifdef PEDANTIC
#pragma GCC diagnostic error "-pedantic"
#endif

/* DPDK headers don't like -pedantic. */
#ifdef PEDANTIC
#pragma GCC diagnostic ignored "-pedantic"
#endif
#include <rte_mbuf.h>
#include <rte_mempool.h>
#ifdef PEDANTIC
#pragma GCC diagnostic error "-pedantic"
#endif

#include "mlx5_utils.h"
#include "mlx5.h"
#include "mlx5_autoconf.h"
#include "mlx5_defs.h"

struct mlx5_rxq_stats {
	unsigned int idx; /**< Mapping index. */
#ifdef MLX5_PMD_SOFT_COUNTERS
	uint64_t ipackets; /**< Total of successfully received packets. */
	uint64_t ibytes; /**< Total of successfully received bytes. */
#endif
	uint64_t idropped; /**< Total of packets dropped when RX ring full. */
	uint64_t rx_nombuf; /**< Total of RX mbuf allocation failures. */
};

struct mlx5_txq_stats {
	unsigned int idx; /**< Mapping index. */
#ifdef MLX5_PMD_SOFT_COUNTERS
	uint64_t opackets; /**< Total of successfully sent packets. */
	uint64_t obytes; /**< Total of successfully sent bytes. */
#endif
	uint64_t odropped; /**< Total of packets not sent when TX ring full. */
};

/* RX element (scattered packets). */
struct rxq_elt_sp {
	struct ibv_sge sges[MLX5_PMD_SGE_WR_N]; /* Scatter/Gather Elements. */
	struct rte_mbuf *bufs[MLX5_PMD_SGE_WR_N]; /* SGEs buffers. */
};

/* RX element. */
struct rxq_elt {
	struct ibv_sge sge; /* Scatter/Gather Element. */
	struct rte_mbuf *buf; /* SGE buffer. */
};

/* Flow director queue structure. */
struct fdir_queue {
	struct ibv_qp *qp; /* Associated RX QP. */
	struct ibv_exp_rwq_ind_table *ind_table; /* Indirection table. */
};

struct priv;

/* RX queue descriptor. */
struct rxq {
	struct priv *priv; /* Back pointer to private data. */
	struct rte_mempool *mp; /* Memory Pool for allocations. */
	struct ibv_cq *cq; /* Completion Queue. */
	struct ibv_exp_wq *wq; /* Work Queue. */
	int32_t (*poll)(); /* Verbs poll function. */
	int32_t (*recv)(); /* Verbs receive function. */
	unsigned int port_id; /* Port ID for incoming packets. */
	unsigned int elts_n; /* (*elts)[] length. */
	unsigned int elts_head; /* Current index in (*elts)[]. */
	unsigned int sp:1; /* Use scattered RX elements. */
	unsigned int csum:1; /* Enable checksum offloading. */
	unsigned int csum_l2tun:1; /* Same for L2 tunnels. */
	unsigned int vlan_strip:1; /* Enable VLAN stripping. */
	unsigned int crc_present:1; /* CRC must be subtracted. */
	union {
		struct rxq_elt_sp (*sp)[]; /* Scattered RX elements. */
		struct rxq_elt (*no_sp)[]; /* RX elements. */
	} elts;
	uint32_t mb_len; /* Length of a mp-issued mbuf. */
	unsigned int socket; /* CPU socket ID for allocations. */
	struct mlx5_rxq_stats stats; /* RX queue counters. */
	struct ibv_exp_res_domain *rd; /* Resource Domain. */
	struct fdir_queue fdir_queue; /* Flow director queue. */
	struct ibv_mr *mr; /* Memory Region (for mp). */
	struct ibv_exp_wq_family *if_wq; /* WQ burst interface. */
#ifdef HAVE_EXP_DEVICE_ATTR_VLAN_OFFLOADS
	struct ibv_exp_cq_family_v1 *if_cq; /* CQ interface. */
#else /* HAVE_EXP_DEVICE_ATTR_VLAN_OFFLOADS */
	struct ibv_exp_cq_family *if_cq; /* CQ interface. */
#endif /* HAVE_EXP_DEVICE_ATTR_VLAN_OFFLOADS */
};

/* Hash RX queue types. */
enum hash_rxq_type {
	HASH_RXQ_TCPV4,
	HASH_RXQ_UDPV4,
	HASH_RXQ_IPV4,
#ifdef HAVE_FLOW_SPEC_IPV6
	HASH_RXQ_TCPV6,
	HASH_RXQ_UDPV6,
	HASH_RXQ_IPV6,
#endif /* HAVE_FLOW_SPEC_IPV6 */
	HASH_RXQ_ETH,
};

/* Flow structure with Ethernet specification. It is packed to prevent padding
 * between attr and spec as this layout is expected by libibverbs. */
struct flow_attr_spec_eth {
	struct ibv_exp_flow_attr attr;
	struct ibv_exp_flow_spec_eth spec;
} __attribute__((packed));

/* Define a struct flow_attr_spec_eth object as an array of at least
 * "size" bytes. Room after the first index is normally used to store
 * extra flow specifications. */
#define FLOW_ATTR_SPEC_ETH(name, size) \
	struct flow_attr_spec_eth name \
		[((size) / sizeof(struct flow_attr_spec_eth)) + \
		 !!((size) % sizeof(struct flow_attr_spec_eth))]

/* Initialization data for hash RX queue. */
struct hash_rxq_init {
	uint64_t hash_fields; /* Fields that participate in the hash. */
	uint64_t dpdk_rss_hf; /* Matching DPDK RSS hash fields. */
	unsigned int flow_priority; /* Flow priority to use. */
	union {
		struct {
			enum ibv_exp_flow_spec_type type;
			uint16_t size;
		} hdr;
		struct ibv_exp_flow_spec_tcp_udp tcp_udp;
		struct ibv_exp_flow_spec_ipv4 ipv4;
#ifdef HAVE_FLOW_SPEC_IPV6
		struct ibv_exp_flow_spec_ipv6 ipv6;
#endif /* HAVE_FLOW_SPEC_IPV6 */
		struct ibv_exp_flow_spec_eth eth;
	} flow_spec; /* Flow specification template. */
	const struct hash_rxq_init *underlayer; /* Pointer to underlayer. */
};

/* Initialization data for indirection table. */
struct ind_table_init {
	unsigned int max_size; /* Maximum number of WQs. */
	/* Hash RX queues using this table. */
	unsigned int hash_types;
	unsigned int hash_types_n;
};

/* Initialization data for special flows. */
struct special_flow_init {
	uint8_t dst_mac_val[6];
	uint8_t dst_mac_mask[6];
	unsigned int hash_types;
	unsigned int per_vlan:1;
};

enum hash_rxq_flow_type {
	HASH_RXQ_FLOW_TYPE_PROMISC,
	HASH_RXQ_FLOW_TYPE_ALLMULTI,
	HASH_RXQ_FLOW_TYPE_BROADCAST,
	HASH_RXQ_FLOW_TYPE_IPV6MULTI,
	HASH_RXQ_FLOW_TYPE_MAC,
};

#ifndef NDEBUG
static inline const char *
hash_rxq_flow_type_str(enum hash_rxq_flow_type flow_type)
{
	switch (flow_type) {
	case HASH_RXQ_FLOW_TYPE_PROMISC:
		return "promiscuous";
	case HASH_RXQ_FLOW_TYPE_ALLMULTI:
		return "allmulticast";
	case HASH_RXQ_FLOW_TYPE_BROADCAST:
		return "broadcast";
	case HASH_RXQ_FLOW_TYPE_IPV6MULTI:
		return "IPv6 multicast";
	case HASH_RXQ_FLOW_TYPE_MAC:
		return "MAC";
	}
	return NULL;
}
#endif /* NDEBUG */

struct hash_rxq {
	struct priv *priv; /* Back pointer to private data. */
	struct ibv_qp *qp; /* Hash RX QP. */
	enum hash_rxq_type type; /* Hash RX queue type. */
	/* MAC flow steering rules, one per VLAN ID. */
	struct ibv_exp_flow *mac_flow[MLX5_MAX_MAC_ADDRESSES][MLX5_MAX_VLAN_IDS];
	struct ibv_exp_flow *special_flow
		[MLX5_MAX_SPECIAL_FLOWS][MLX5_MAX_VLAN_IDS];
};

/* TX element. */
struct txq_elt {
	struct rte_mbuf *buf;
};

/* Linear buffer type. It is used when transmitting buffers with too many
 * segments that do not fit the hardware queue (see max_send_sge).
 * Extra segments are copied (linearized) in such buffers, replacing the
 * last SGE during TX.
 * The size is arbitrary but large enough to hold a jumbo frame with
 * 8 segments considering mbuf.buf_len is about 2048 bytes. */
typedef uint8_t linear_t[16384];

/* TX queue descriptor. */
struct txq {
	struct priv *priv; /* Back pointer to private data. */
	int32_t (*poll_cnt)(struct ibv_cq *cq, uint32_t max);
	int (*send_pending)();
#ifdef HAVE_VERBS_VLAN_INSERTION
	int (*send_pending_vlan)();
#endif
#if MLX5_PMD_MAX_INLINE > 0
	int (*send_pending_inline)();
#ifdef HAVE_VERBS_VLAN_INSERTION
	int (*send_pending_inline_vlan)();
#endif
#endif
#if MLX5_PMD_SGE_WR_N > 1
	int (*send_pending_sg_list)();
#ifdef HAVE_VERBS_VLAN_INSERTION
	int (*send_pending_sg_list_vlan)();
#endif
#endif
	int (*send_flush)(struct ibv_qp *qp);
	struct ibv_cq *cq; /* Completion Queue. */
	struct ibv_qp *qp; /* Queue Pair. */
	struct txq_elt (*elts)[]; /* TX elements. */
#if MLX5_PMD_MAX_INLINE > 0
	uint32_t max_inline; /* Max inline send size <= MLX5_PMD_MAX_INLINE. */
#endif
	unsigned int elts_n; /* (*elts)[] length. */
	unsigned int elts_head; /* Current index in (*elts)[]. */
	unsigned int elts_tail; /* First element awaiting completion. */
	unsigned int elts_comp; /* Number of completion requests. */
	unsigned int elts_comp_cd; /* Countdown for next completion request. */
	unsigned int elts_comp_cd_init; /* Initial value for countdown. */
	struct {
		const struct rte_mempool *mp; /* Cached Memory Pool. */
		struct ibv_mr *mr; /* Memory Region (for mp). */
		uint32_t lkey; /* mr->lkey */
	} mp2mr[MLX5_PMD_TX_MP_CACHE]; /* MP to MR translation table. */
	struct mlx5_txq_stats stats; /* TX queue counters. */
	/* Elements used only for init part are here. */
	linear_t (*elts_linear)[]; /* Linearized buffers. */
	struct ibv_mr *mr_linear; /* Memory Region for linearized buffers. */
#ifdef HAVE_VERBS_VLAN_INSERTION
	struct ibv_exp_qp_burst_family_v1 *if_qp; /* QP burst interface. */
#else
	struct ibv_exp_qp_burst_family *if_qp; /* QP burst interface. */
#endif
	struct ibv_exp_cq_family *if_cq; /* CQ interface. */
	struct ibv_exp_res_domain *rd; /* Resource Domain. */
	unsigned int socket; /* CPU socket ID for allocations. */
};

/* mlx5_rxq.c */

extern const struct hash_rxq_init hash_rxq_init[];
extern const unsigned int hash_rxq_init_n;

extern uint8_t rss_hash_default_key[];
extern const size_t rss_hash_default_key_len;

size_t priv_flow_attr(struct priv *, struct ibv_exp_flow_attr *,
		      size_t, enum hash_rxq_type);
int priv_create_hash_rxqs(struct priv *);
void priv_destroy_hash_rxqs(struct priv *);
int priv_allow_flow_type(struct priv *, enum hash_rxq_flow_type);
int priv_rehash_flows(struct priv *);
void rxq_cleanup(struct rxq *);
int rxq_rehash(struct rte_eth_dev *, struct rxq *);
int rxq_setup(struct rte_eth_dev *, struct rxq *, uint16_t, unsigned int,
	      const struct rte_eth_rxconf *, struct rte_mempool *);
int mlx5_rx_queue_setup(struct rte_eth_dev *, uint16_t, uint16_t, unsigned int,
			const struct rte_eth_rxconf *, struct rte_mempool *);
void mlx5_rx_queue_release(void *);
uint16_t mlx5_rx_burst_secondary_setup(void *dpdk_rxq, struct rte_mbuf **pkts,
			      uint16_t pkts_n);


/* mlx5_txq.c */

void txq_cleanup(struct txq *);
int txq_setup(struct rte_eth_dev *dev, struct txq *txq, uint16_t desc,
	  unsigned int socket, const struct rte_eth_txconf *conf);

int mlx5_tx_queue_setup(struct rte_eth_dev *, uint16_t, uint16_t, unsigned int,
			const struct rte_eth_txconf *);
void mlx5_tx_queue_release(void *);
uint16_t mlx5_tx_burst_secondary_setup(void *dpdk_txq, struct rte_mbuf **pkts,
			      uint16_t pkts_n);

/* mlx5_rxtx.c */

struct ibv_mr *mlx5_mp2mr(struct ibv_pd *, const struct rte_mempool *);
void txq_mp2mr_iter(const struct rte_mempool *, void *);
uint16_t mlx5_tx_burst(void *, struct rte_mbuf **, uint16_t);
uint16_t mlx5_rx_burst_sp(void *, struct rte_mbuf **, uint16_t);
uint16_t mlx5_rx_burst(void *, struct rte_mbuf **, uint16_t);
uint16_t removed_tx_burst(void *, struct rte_mbuf **, uint16_t);
uint16_t removed_rx_burst(void *, struct rte_mbuf **, uint16_t);

#endif /* RTE_PMD_MLX5_RXTX_H_ */
