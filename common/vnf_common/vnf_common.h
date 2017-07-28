/*
// Copyright (c) 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef __INCLUDE_VNF_COMMON_H__
#define __INCLUDE_VNF_COMMON_H__

#include <rte_pipeline.h>
#include <rte_ether.h>

#define MBUF_HDR_ROOM 256
#define ETH_HDR_SIZE  14
#define IP_HDR_SRC_ADR_OFST 12
#define IP_HDR_DST_ADR_OFST 16
#define IP_HDR_PROTOCOL_OFST 9
#define IP_HDR_SIZE  20
#define IPV6_HDR_SRC_ADR_OFST 8
#define IPV6_HDR_DST_ADR_OFST 24
#define IPV6_HDR_PROTOCOL_OFST 6
#define IPV6_HDR_SIZE  40

#define ETH_TYPE_ARP     0x0806
#define ETH_TYPE_IPV4    0x0800

#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_TCP  6
#define IP_PROTOCOL_UDP  17

#define ETH_TYPE_IPV6    0x86DD
#define IP_PROTOCOL_ICMPV6 58

#define PKT_ING_DIR 0
#define PKT_EGR_DIR 1

#ifndef PIPELINE_MAX_PORT_IN
#define PIPELINE_MAX_PORT_IN 64
#endif

#define RTE_PIPELINE_MAX_NAME_SZ 124

#define INVALID_DESTIF 255

enum {
	VNF_PRV_PORT_ID,
	VNF_PUB_PORT_ID,
};
void show_ports_info(void);
void trim(char *input);
uint8_t get_in_port_dir(uint8_t in_port_id);
uint8_t is_phy_port_privte(uint16_t phy_port);
uint32_t get_prv_to_pub_port(uint32_t *ip_addr, uint8_t type);
uint32_t get_pub_to_prv_port(uint32_t *ip_addr, uint8_t type);

static inline void drop_pkt(uint32_t pkt_num, uint64_t *mask)
{
	*mask ^= 1LLU << pkt_num;
}

extern uint8_t in_port_dir_a[PIPELINE_MAX_PORT_IN];
extern uint8_t prv_to_pub_map[PIPELINE_MAX_PORT_IN];
extern uint8_t pub_to_prv_map[PIPELINE_MAX_PORT_IN];
extern uint8_t prv_in_port_a[PIPELINE_MAX_PORT_IN];

extern uint32_t link_hw_addr_array_idx;

struct rte_port_in {
	/* Input parameters */
	struct rte_port_in_ops ops;
	rte_pipeline_port_in_action_handler f_action;
	void *arg_ah;
	uint32_t burst_size;

	/* The table to which this port is connected */
	uint32_t table_id;

	/* Handle to low-level port */
	void *h_port;

	/* List of enabled ports */
	struct rte_port_in *next;

	/* Statistics */
	uint64_t n_pkts_dropped_by_ah;
};

struct rte_port_out {
	/* Input parameters */
	struct rte_port_out_ops ops;
	rte_pipeline_port_out_action_handler f_action;
	void *arg_ah;

	/* Handle to low-level port */
	void *h_port;

	/* Statistics */
	uint64_t n_pkts_dropped_by_ah;
};

struct rte_table {
	/* Input parameters */
	struct rte_table_ops ops;
	rte_pipeline_table_action_handler_hit f_action_hit;
	rte_pipeline_table_action_handler_miss f_action_miss;
	void *arg_ah;
	struct rte_pipeline_table_entry *default_entry;
	uint32_t entry_size;

	uint32_t table_next_id;
	uint32_t table_next_id_valid;

	/* Handle to the low-level table object */
	void *h_table;

	/* Statistics */
	uint64_t n_pkts_dropped_by_lkp_hit_ah;
	uint64_t n_pkts_dropped_by_lkp_miss_ah;
	uint64_t n_pkts_dropped_lkp_hit;
	uint64_t n_pkts_dropped_lkp_miss;
};


struct rte_pipeline {
	/* Input parameters */
	char name[RTE_PIPELINE_MAX_NAME_SZ];
	int socket_id;
	uint32_t offset_port_id;

	/* Internal tables */
	struct rte_port_in ports_in[RTE_PIPELINE_PORT_IN_MAX];
	struct rte_port_out ports_out[RTE_PIPELINE_PORT_OUT_MAX];
	struct rte_table tables[RTE_PIPELINE_TABLE_MAX];

	/* Occupancy of internal tables */
	uint32_t num_ports_in;
	uint32_t num_ports_out;
	uint32_t num_tables;

	/* List of enabled ports */
	uint64_t enabled_port_in_mask;
	struct rte_port_in *port_in_next;

	/* Pipeline run structures */
	struct rte_mbuf *pkts[RTE_PORT_IN_BURST_SIZE_MAX];
	struct rte_pipeline_table_entry *entries[RTE_PORT_IN_BURST_SIZE_MAX];
	uint64_t action_mask0[RTE_PIPELINE_ACTIONS];
	uint64_t action_mask1[RTE_PIPELINE_ACTIONS];
	uint64_t pkts_mask;
	uint64_t n_pkts_ah_drop;
	uint64_t pkts_drop_mask;
} __rte_cache_aligned;

/* RTE_ DPDK LIB structures to get HWQ & SWQ info */
struct rte_port_ethdev_writer {
	 struct rte_port_out_stats stats;

	 struct rte_mbuf *tx_buf[2 * RTE_PORT_IN_BURST_SIZE_MAX];
	 uint32_t tx_burst_sz;
	 uint16_t tx_buf_count;
	 uint64_t bsz_mask;
	 uint16_t queue_id;
	 uint8_t port_id;
};
struct rte_port_ethdev_reader {
	 struct rte_port_in_stats stats;

	 uint16_t queue_id;
	 uint8_t port_id;
};
struct rte_port_ring_writer {
	 struct rte_port_out_stats stats;

	 struct rte_mbuf *tx_buf[2 * RTE_PORT_IN_BURST_SIZE_MAX];
	 struct rte_ring *ring;
	 uint32_t tx_burst_sz;
	 uint32_t tx_buf_count;
	 uint64_t bsz_mask;
	 uint32_t is_multi;
};
struct rte_port_ring_reader {
	 struct rte_port_in_stats stats;

	 struct rte_ring *ring;
};

uint8_t get_in_port_dir(uint8_t in_port_id);
uint8_t is_phy_port_privte(uint16_t phy_port);
uint8_t is_port_index_privte(uint16_t phy_port);
#endif
