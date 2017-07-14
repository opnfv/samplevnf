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

#ifndef __INCLUDE_PIPELINE_CGNAPT_BE_H__
#define __INCLUDE_PIPELINE_CGNAPT_BE_H__

/**
 * @file
 * Pipeline CG-NAPT BE.
 *
 * Pipeline CG-NAPT Back End (BE).
 * Responsible for packet processing.
 *
 */

#include "pipeline_common_be.h"
#include "vnf_common.h"
#include <rte_pipeline.h>
#include <rte_hash.h>
#include "pipeline_timer_be.h"
#include "pipeline_arpicmp_be.h"
#include "cgnapt_pcp_be.h"
#include "lib_arp.h"

#define PIPELINE_CGNAPT_KEY_MAX_SIZE  64

extern uint8_t CGNAPT_DEBUG;
#define CGNAPT_DBG_CMD_OFST 8
#define CGNAPT_DBG_CMD_STATS_SHOW 0
#define CGNAPT_DBG_CMD_STATS_CLEAR 1
#define CGNAPT_DBG_CMD_DBG_LEVEL 2
#define CGNAPT_DBG_CMD_DBG_SHOW 3
#define CGNAPT_DBG_CMD_LS_ENTRY 4
#define CGNAPT_DBG_CMD_DYN 5
#define CGNAPT_DBG_CMD_IF_STATS 6
#define CGNAPT_DBG_CMD_INSTRUMENTATION 7
#define CGNAPT_DBG_CMD_ITER_COM_TBL 8
#define CGNAPT_DBG_CMD_MAPS_INFO 9
#define CGNAPT_DBG_CMD_OFST1 10
#define CGNAPT_DBG_CMD_IPV6 11
#define CGNAPT_DBG_CMD_PRINT_DS 12
#define CGNAPT_DBG_CMD_PRINT_NSP 13
#define CGNAPT_DBG_MAX_CLI_PER_PUB_IP 14
#define CGNAPT_DBG_PUB_IP_LIST 15
#define CGNAPT_DBG_TIMING_INST 16


#ifdef PCP_ENABLE

#define CGNAPT_DBG_PCP 17
/* PCP sub commands */
enum{
CGNAPT_PCP_CMD_STATS,
CGNAPT_PCP_CMD_PCP_ENABLE,
CGNAPT_PCP_CMD_GET_LIFETIME,
CGNAPT_PCP_CMD_SET_LIFETIME,
CGNAPT_PCP_CMD_OFST = 8,
};

#endif

/*
 * CGNAPT_DBG_CMD_INSTRUMENTATION Sub commands
*/
 #define CGNAPT_CMD_INSTRUMENTATION_SUB0 0
 #define CGNAPT_CMD_INSTRUMENTATION_SUB1 1
 #define CGNAPT_CMD_INSTRUMENTATION_SUB2 2

/*
 * CGNAPT_DBG_CMD_IF_STATS Sub commands
*/
#define CGNAPT_IF_STATS_HWQ 0
#define CGNAPT_IF_STATS_SWQ 1
#define CGNAPT_IF_STATS_OTH 2

/* Version command info */
#define CGNAPT_VER_CMD_OFST 8
#define CGNAPT_VER_CMD_VER 1

/* Network Specific Prefix commnd */
#define CGNAPT_NSP_CMD_OFST 8

/* #define PIPELINE_CGNAPT_INSTRUMENTATION */
#ifdef PIPELINE_CGNAPT_INSTRUMENTATION
void *instrumentation_port_in_arg;
struct rte_mempool *cgnapt_test_pktmbuf_pool;

#define INST_ARRAY_SIZE 100000
#define CGNAPT_INST5_SIG 0xAA
#define CGNAPT_INST5_WAIT 200
#define CGNAPT_INST5_OFST 10

uint64_t *inst_start_time;
uint64_t *inst_end_time;
uint32_t *inst_diff_time;

uint32_t cgnapt_inst_index;
uint32_t cgnapt_inst5_flag;
uint32_t cgnapt_inst5_wait;
uint8_t cgnapt_num_func_to_inst;

#endif

#define CGNAPT_VERSION "1.8"
#define CGNAPT_DYN_TIMEOUT (3*10)	/* 30 secs */
#define MAX_DYN_ENTRY (70000 * 16)

#define NAPT_ENTRY_STALE 1
#define NAPT_ENTRY_VALID 0

/* For max_port_per_client */
#define MAX_PORT_INVALID_KEY -1
#define MAX_PORT_NOT_REACHED  0
#define MAX_PORT_REACHED      1
/* increment */
#define MAX_PORT_INC_SUCCESS  1
#define MAX_PORT_INC_REACHED  0
#define MAX_PORT_INC_ERROR   -1
/* decrement */
#define MAX_PORT_DEC_SUCCESS  1
#define MAX_PORT_DEC_REACHED  0
#define MAX_PORT_DEC_ERROR   -1
/* add_entry */
#define MAX_PORT_ADD_SUCCESS    1
#define MAX_PORT_ADD_UNSUCCESS  0
#define MAX_PORT_ADD_ERROR     -1
/* del_entry */
#define MAX_PORT_DEL_SUCCESS    1
#define MAX_PORT_DEL_UNSUCCESS  0
#define MAX_PORT_DEL_ERROR     -1

#define PIPELINE_CGNAPT_TABLE_AH_HIT(f_ah, f_pkt_work, f_pkt4_work)	\
static int								\
f_ah(									\
	struct rte_pipeline *rte_p,					\
	struct rte_mbuf **pkts,						\
	uint64_t pkts_mask,						\
	struct rte_pipeline_table_entry **entries,			\
	void *arg)							\
{									\
	uint64_t pkts_in_mask = pkts_mask;				\
	uint64_t pkts_out_mask = pkts_mask;				\
	uint64_t time = rte_rdtsc();					\
									\
	if ((pkts_in_mask & (pkts_in_mask + 1)) == 0) {			\
		uint64_t n_pkts = __builtin_popcountll(pkts_in_mask);	\
		uint32_t i;						\
									\
		for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4) {		\
			uint64_t mask = f_pkt4_work(&pkts[i],		\
				&entries[i], i, arg);			\
			pkts_out_mask ^= mask << i;			\
		}							\
									\
		for ( ; i < n_pkts; i++) {				\
			uint64_t mask = f_pkt_work(pkts[i],		\
				entries[i], i, arg);			\
			pkts_out_mask ^= mask << i;			\
		}							\
	} else								\
		for ( ; pkts_in_mask; ) {				\
			uint32_t pos = __builtin_ctzll(pkts_in_mask);	\
			uint64_t pkt_mask = 1LLU << pos;		\
			uint64_t mask = f_pkt_work(pkts[pos],		\
				entries[pos], pos, arg);		\
									\
			pkts_in_mask &= ~pkt_mask;			\
			pkts_out_mask ^= mask << pos;			\
		}							\
									\
	rte_pipeline_ah_packet_drop(rte_p, pkts_out_mask ^ pkts_mask);	\
									\
	return 0;							\
}

#define PIPELINE_CGNAPT_PORT_OUT_AH(f_ah, f_pkt_work, f_pkt4_work)	\
static int								\
f_ah(									\
	__rte_unused struct rte_pipeline *rte_p,			\
	struct rte_mbuf **pkt,						\
	uint32_t *pkts_mask,						\
	void *arg)							\
{									\
	f_pkt4_work(pkt, arg);						\
	f_pkt_work(*pkt, arg);						\
									\
	int i = *pkts_mask; i++;					\
	return 0;							\
}

#define PIPELINE_CGNAPT_PORT_OUT_BAH(f_ah, f_pkt_work, f_pkt4_work)	\
static int								\
f_ah(									\
__rte_unused struct rte_pipeline *rte_p,				\
struct rte_mbuf **pkt,							\
uint32_t *pkts_mask,							\
void *arg)								\
{									\
	f_pkt4_work(pkt, arg);						\
									\
	f_pkt_work(*pkt, arg);						\
									\
	int i = *pkts_mask; i++;					\
	return 0;							\
}

#define PIPELINE_CGNAPT_KEY_PORT_IN_AH(f_ah, f_pkt_work, f_pkt4_work)	\
static int								\
f_ah(									\
	struct rte_pipeline *rte_p,					\
	struct rte_mbuf **pkts,						\
	uint32_t n_pkts,						\
	void *arg)							\
{									\
	uint32_t i;							\
									\
	if (CGNAPT_DEBUG > 1)						\
		printf("cgnapt_key hit fn: %"PRIu32"\n", n_pkts);	\
									\
	pkt_burst_cnt = 0;						\
	for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)			\
		f_pkt4_work(&pkts[i], arg);				\
									\
	for ( ; i < n_pkts; i++)					\
		f_pkt_work(pkts[i], arg);				\
									\
									\
	return 0;							\
}									\


#define PIPELINE_CGNAPT_TABLE_AH_MISS(f_ah, f_pkt_work, f_pkt4_work)	\
static int								\
f_ah(									\
	struct rte_pipeline *rte_p,					\
	struct rte_mbuf **pkts,						\
	uint64_t pkts_mask,						\
	struct rte_pipeline_table_entry **entries,			\
	void *arg)							\
{									\
	uint64_t pkts_in_mask = pkts_mask;				\
	uint64_t pkts_out_mask = pkts_mask;				\
	uint64_t time = rte_rdtsc();					\
									\
	if ((pkts_in_mask & (pkts_in_mask + 1)) == 0) {			\
		uint64_t n_pkts = __builtin_popcountll(pkts_in_mask);	\
		uint32_t i;						\
									\
		for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4) {		\
			uint64_t mask = f_pkt4_work(&pkts[i],		\
				&entries[i], i, arg);			\
			pkts_out_mask ^= mask << i;			\
		}							\
									\
		for ( ; i < n_pkts; i++) {				\
			uint64_t mask = f_pkt_work(pkts[i],		\
				entries[i], i, arg);			\
			pkts_out_mask ^= mask << i;			\
		}							\
	} else								\
		for ( ; pkts_in_mask; ) {				\
			uint32_t pos = __builtin_ctzll(pkts_in_mask);	\
			uint64_t pkt_mask = 1LLU << pos;		\
			uint64_t mask = f_pkt_work(pkts[pos],		\
				entries[pos], pos, arg);		\
									\
			pkts_in_mask &= ~pkt_mask;			\
			pkts_out_mask ^= mask << pos;			\
		}							\
									\
	rte_pipeline_ah_packet_drop(rte_p, pkts_out_mask ^ pkts_mask);	\
									\
	return 0;							\
}

/* IPv4 offsets */
#define SRC_ADR_OFST_IP4 (MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_SRC_ADR_OFST)
#define DST_ADR_OFST_IP4 (MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_DST_ADR_OFST)
#define SRC_PRT_OFST_IP4_TCP (MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_SIZE)
#define SRC_PRT_OFST_IP4_UDP SRC_PRT_OFST_IP4_TCP
#define DST_PRT_OFST_IP4_TCP (MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_SIZE + 2)
#define DST_PRT_OFST_IP4_UDP DST_PRT_OFST_IP4_TCP
#define PROT_OFST_IP4 (MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_PROTOCOL_OFST)
#define IDEN_OFST_IP4_ICMP (MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_SIZE + 4)
#define SEQN_OFST_IP4_ICMP (MBUF_HDR_ROOM + ETH_HDR_SIZE + IP_HDR_SIZE + 6)

/*NAT64*/

/* IPv6 offsets */
#define SRC_ADR_OFST_IP6 (MBUF_HDR_ROOM + ETH_HDR_SIZE + IPV6_HDR_SRC_ADR_OFST)
#define DST_ADR_OFST_IP6 (MBUF_HDR_ROOM + ETH_HDR_SIZE + IPV6_HDR_DST_ADR_OFST)
#define SRC_PRT_OFST_IP6 (MBUF_HDR_ROOM + ETH_HDR_SIZE + IPV6_HDR_SIZE)
#define DST_PRT_OFST_IP6 (MBUF_HDR_ROOM + ETH_HDR_SIZE + IPV6_HDR_SIZE + 2)
#define PROT_OFST_IP6 (MBUF_HDR_ROOM + ETH_HDR_SIZE + IPV6_HDR_PROTOCOL_OFST)

/* After IPv6 to IPv4 conversion */
#define SRC_ADR_OFST_IP6t4 (20 + MBUF_HDR_ROOM + ETH_HDR_SIZE + \
					IP_HDR_SRC_ADR_OFST)
#define DST_ADR_OFST_IP6t4 (20 + MBUF_HDR_ROOM + ETH_HDR_SIZE + \
					IP_HDR_DST_ADR_OFST)
#define SRC_PRT_OFST_IP6t4 (20 + MBUF_HDR_ROOM + ETH_HDR_SIZE + \
					IP_HDR_SIZE)
#define DST_PRT_OFST_IP6t4 (20 + MBUF_HDR_ROOM + ETH_HDR_SIZE + \
					IP_HDR_SIZE + 2)
#define PROT_OFST_IP6t4 (20 + MBUF_HDR_ROOM + ETH_HDR_SIZE + \
					IP_HDR_PROTOCOL_OFST)
#define ETH_OFST_IP6t4 (20 + MBUF_HDR_ROOM)

/* After IPv4 to IPv6 conversion */
#define DST_PRT_OFST_IP4t6 (MBUF_HDR_ROOM + ETH_HDR_SIZE + \
				IPV6_HDR_SIZE + 2 - 20)
#define DST_ADR_OFST_IP4t6 (MBUF_HDR_ROOM + ETH_HDR_SIZE + \
				IPV6_HDR_DST_ADR_OFST - 20)

#define TRAFFIC_TYPE_IPV4  4
#define TRAFFIC_TYPE_IPV6  6

#define CGNAPT_MAX_PUB_IP 256


/**
 * A structure defining public ip and associated client count.
 */
struct public_ip {
	uint32_t ip;
	rte_atomic16_t count;	/* how many clients are using the public_ip */
} all_public_ip[CGNAPT_MAX_PUB_IP];

/**
 * Command to dump number of clients using an IP address.
 */
void print_num_ip_clients(void);

extern struct rte_hash *napt_common_table;
extern struct public_ip all_public_ip[CGNAPT_MAX_PUB_IP];

/**
 * A structure defining pipeline_cgnapt - placeholder for all
 * CGNAPT pipeline variables
 *
 *
 */
struct pipeline_cgnapt {
	struct pipeline p;
	pipeline_msg_req_handler custom_handlers[PIPELINE_CGNAPT_MSG_REQS];

	uint32_t n_flows;
	uint32_t key_offset;
	uint32_t key_size;
	uint32_t hash_offset;

	uint32_t n_entries;

	/* Dynamic NAPT Start */
	uint8_t is_static_cgnapt;
	uint16_t max_port_per_client;
	uint16_t max_clients_per_ip;

	struct pub_ip_port_set *pub_ip_port_set;
	uint8_t pub_ip_count;
	struct pub_ip_range *pub_ip_range;
	uint8_t pub_ip_range_count;

	struct napt_port_alloc_elem *allocated_ports;
	struct napt_port_alloc_elem *free_ports;
	struct rte_ring *port_alloc_ring;

	uint64_t *port_map;
	uint16_t port_map_array_size;

	uint64_t n_cgnapt_entry_deleted;
	uint64_t n_cgnapt_entry_added;
	uint64_t naptedPktCount;
	uint64_t naptDroppedPktCount;

	uint64_t inaptedPktCount;
	uint64_t enaptedPktCount;
	uint64_t receivedPktCount;
	uint64_t missedPktCount;
	uint64_t dynCgnaptCount;
	uint64_t arpicmpPktCount;

	uint64_t app_params_addr;
	uint8_t pipeline_num;
	uint8_t pkt_burst_cnt;
	uint8_t hw_checksum_reqd;
	uint8_t traffic_type;
	uint8_t links_map[PIPELINE_MAX_PORT_IN];
	uint8_t outport_id[PIPELINE_MAX_PORT_IN];

	struct pipeline_cgnapt_entry_key
			cgnapt_dyn_ent_table[RTE_PORT_IN_BURST_SIZE_MAX];
	uint32_t cgnapt_dyn_ent_index[RTE_PORT_IN_BURST_SIZE_MAX];

	/* table lookup keys */
	struct pipeline_cgnapt_entry_key keys[RTE_HASH_LOOKUP_BULK_MAX];
	/* pointers to table lookup keys */
	void *key_ptrs[RTE_HASH_LOOKUP_BULK_MAX];
	/* table lookup results */
	int32_t lkup_indx[RTE_HASH_LOOKUP_BULK_MAX];
	/* entries used for pkts fwd */
	struct rte_pipeline_table_entry *entries[RTE_HASH_LOOKUP_BULK_MAX];
	uint64_t valid_packets;	/* bitmap of valid packets to process */
	uint64_t invalid_packets;/* bitmap of invalid packets to be dropped */

	uint8_t vnf_set;	/* to identify as separate LB-CGNAPT set */

	/* Local ARP & ND Tables */
	struct lib_arp_route_table_entry
		local_lib_arp_route_table[MAX_ARP_RT_ENTRY];
	uint8_t local_lib_arp_route_ent_cnt;
	struct lib_nd_route_table_entry
		local_lib_nd_route_table[MAX_ND_RT_ENTRY];
	uint8_t local_lib_nd_route_ent_cnt;

	/* For internal debugging purpose */
#ifdef CGNAPT_TIMING_INST
	uint64_t in_port_exit_timestamp;
	uint64_t external_time_sum;
	uint64_t internal_time_sum;
	uint32_t time_measurements;
	uint32_t max_time_mesurements;
	uint8_t time_measurements_on;
#endif

#ifdef CGNAPT_DEBUGGING

	uint32_t naptDebugCount;

	uint64_t naptDroppedPktCount1;
	uint64_t naptDroppedPktCount2;
	uint64_t naptDroppedPktCount3;
	uint64_t naptDroppedPktCount4;
	uint64_t naptDroppedPktCount5;
	uint64_t naptDroppedPktCount6;

	uint64_t kpc1, kpc2;

	uint64_t missedpktcount1;
	uint64_t missedpktcount2;
	uint64_t missedpktcount3;
	uint64_t missedpktcount4;
	uint64_t missedpktcount5;
	uint64_t missedpktcount6;
	uint64_t missedpktcount7;
	uint64_t missedpktcount8;
	uint64_t missedpktcount9;
	uint64_t missedpktcount10;

	uint64_t missedpktcount11;
	uint64_t missedpktcount12;


	uint64_t max_port_dec_err1;
	uint64_t max_port_dec_err2;
	uint64_t max_port_dec_err3;
	uint64_t max_port_dec_success;

	uint64_t pfb_err;
	uint64_t pfb_ret;
	uint64_t pfb_get;
	uint64_t pfb_suc;
	uint64_t gfp_suc;
	uint64_t gfp_get;
	uint64_t gfp_ret;
	uint64_t gfp_err;
#endif
} __rte_cache_aligned;

/**
 * A structure defining the CG-NAPT input port handler arg.
 */
struct pipeline_cgnapt_in_port_h_arg {
	struct pipeline_cgnapt *p;
	uint8_t in_port_id;
};

enum {
	CGNAPT_PRV_PORT_ID,
	CGNAPT_PUB_PORT_ID,
};

uint16_t cgnapt_meta_offset;
uint8_t dual_stack_enable;
uint16_t dest_if_offset;
uint8_t nat_only_config_flag;
uint8_t CGNAPT_DEBUG;

#if (RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN)
/* x86 == little endian   */
/* network  == big endian */
#define CHECK_ENDIAN_16(x) rte_be_to_cpu_16(x)
#else
#define CHECK_ENDIAN_16(x) (x)
#endif
#define IP_VHL_DEF (0x40 | 0x05)
struct rte_mempool *cgnapt_icmp_pktmbuf_tx_pool;
struct rte_mbuf *cgnapt_icmp_pkt;
struct rte_pipeline *myP;
uint8_t icmp_pool_init;

#define MAX_NUM_LOCAL_MAC_ADDRESS 16

/***** NAT64 NSP declarations *****/
/**
 * A structure defining nsp node.
 */
struct cgnapt_nsp_node {
	struct pipeline_cgnapt_nsp_t nsp;
	struct cgnapt_nsp_node *next;
};

struct cgnapt_nsp_node *nsp_ll;

/***** Common Table declarations *****/
#define IP_VERSION_4 4
#define IP_VERSION_6 6
#define MAX_NAPT_ENTRIES 16777216       /* 0x1000000 */
#define NUM_NAPT_PORT_BULK_ALLOC 250


struct rte_hash *napt_common_table;
struct cgnapt_table_entry *napt_hash_tbl_entries;

/***** Multiple NAT IP declarations *****/

/**
 * A structure defining public ip and associated port range set
 */
struct pub_ip_port_set {
	uint32_t ip;
	uint16_t start_port;
	uint16_t end_port;
};

/**
 * A structure defining public ip range
 */
struct pub_ip_range {
	uint32_t start_ip;
	uint32_t end_ip;
};

/***** Common Port Allocation declarations *****/

int create_napt_common_table(uint32_t nFlows);
struct rte_mempool *napt_port_pool;

#define MAX_CGNAPT_SETS 16

/**
 * A structure defining a bulk port allocation element.
 */
struct napt_port_alloc_elem {
	uint32_t count;
	uint32_t ip_addr[NUM_NAPT_PORT_BULK_ALLOC];
	uint16_t ports[NUM_NAPT_PORT_BULK_ALLOC];
};

int napt_port_alloc_init(struct pipeline_cgnapt *p_nat);
void release_iport(uint16_t port, uint32_t public_ip,
			 struct pipeline_cgnapt *p_nat);
int get_free_iport(struct pipeline_cgnapt *p_nat, uint32_t *public_ip);

/***************************** Function declarations *************************/

void
pkt4_work_cgnapt_ipv6_prv(struct rte_mbuf **pkts,
				uint32_t in_pkt_num,
				void *arg, struct pipeline_cgnapt *p_nat);
void
pkt_work_cgnapt_ipv6_prv(struct rte_mbuf *pkts,
			 uint32_t in_pkt_num,
			 void *arg, struct pipeline_cgnapt *p_nat);

void
pkt4_work_cgnapt_ipv6_pub(struct rte_mbuf **pkts,
				uint32_t in_pkt_num,
				void *arg, struct pipeline_cgnapt *p_nat);
void
pkt_work_cgnapt_ipv6_pub(struct rte_mbuf *pkt,
			 uint32_t in_pkt_num,
			 void *arg, struct pipeline_cgnapt *p_nat);

void
pkt4_work_cgnapt_ipv4_prv(struct rte_mbuf **pkts,
				uint32_t in_pkt_num,
				void *arg, struct pipeline_cgnapt *p_nat);

void
pkt_work_cgnapt_ipv4_prv(struct rte_mbuf **pkts,
			 uint32_t in_pkt_num,
			 void *arg, struct pipeline_cgnapt *p_nat);

void
pkt4_work_cgnapt_ipv4_pub(struct rte_mbuf **pkts,
				uint32_t in_pkt_num,
				void *arg, struct pipeline_cgnapt *p_nat);
void
pkt_work_cgnapt_ipv4_pub(struct rte_mbuf **pkts,
			 uint32_t in_pkt_num,
			 void *arg, struct pipeline_cgnapt *p_nat);

/* in port handler key functions */
void
pkt4_work_cgnapt_key_ipv4_prv(struct rte_mbuf **pkts,
						uint32_t pkt_num,
						void *arg, struct pipeline_cgnapt *p_nat);

void
pkt_work_cgnapt_key_ipv4_prv(struct rte_mbuf *pkt,
					 uint32_t pkt_num,
					 void *arg, struct pipeline_cgnapt *p_nat);

void
pkt4_work_cgnapt_key_ipv4_pub(struct rte_mbuf **pkts,
						uint32_t pkt_num,
						void *arg, struct pipeline_cgnapt *p_nat);

void
pkt_work_cgnapt_key_ipv4_pub(struct rte_mbuf *pkt,
					 uint32_t pkt_num,
					 void *arg, struct pipeline_cgnapt *p_nat);
void
pkt4_work_cgnapt_key_ipv6_pub(struct rte_mbuf **pkts,
						uint32_t pkt_num,
						void *arg, struct pipeline_cgnapt *p_nat);
void
pkt_work_cgnapt_key_ipv6_pub(struct rte_mbuf *pkts,
					 uint32_t pkt_num,
					 void *arg, struct pipeline_cgnapt *p_nat);
void
pkt4_work_cgnapt_key_ipv6_prv(struct rte_mbuf **pkts,
						uint32_t pkt_num,
						void *arg, struct pipeline_cgnapt *p_nat);
void
pkt_work_cgnapt_key_ipv6_prv(struct rte_mbuf *pkt,
					 uint32_t pkt_num,
					 void *arg, struct pipeline_cgnapt *p_nat);

void send_icmp_dest_unreachable_msg(void);
unsigned short cksum_calc(unsigned short *addr, int len);
void print_mbuf(const char *rx_tx, unsigned int portid, struct rte_mbuf *mbuf,
		unsigned int line);


/* Max port per client declarations */
/**
 * A structure defining maximun ports per client
 */
struct max_port_per_client {
	uint32_t prv_ip;
	uint32_t prv_phy_port;
	uint8_t max_port_cnt;
};

/**
 * A structure defining maximun ports per client key
 */
struct max_port_per_client_key {
	uint32_t prv_ip;
	uint32_t prv_phy_port;
};

struct rte_hash *max_port_per_client_hash;
struct max_port_per_client *max_port_per_client_array;


int init_max_port_per_client(struct pipeline_cgnapt *p_nat);
int is_max_port_per_client_reached(uint32_t prv_ip_param,
					 uint32_t prv_phy_port_param,
					 struct pipeline_cgnapt *p_nat);
int increment_max_port_counter(uint32_t prv_ip_param,
						 uint32_t prv_phy_port_param,
						 struct pipeline_cgnapt *p_nat);
int decrement_max_port_counter(uint32_t prv_ip_param,
						 uint32_t prv_phy_port_param,
						 struct pipeline_cgnapt *p_nat);
int max_port_per_client_add_entry(uint32_t prv_ip_param,
					uint32_t prv_phy_port_param,
					struct pipeline_cgnapt *p_nat);
int max_port_per_client_del_entry(uint32_t prv_ip_param,
					uint32_t prv_phy_port_param,
					struct pipeline_cgnapt *p_nat);

/* Print functions */
void print_pkt(struct rte_mbuf *pkt);
void log_pkt(struct rte_mbuf *pkt);
void print_key(struct pipeline_cgnapt_entry_key *key);
void print_entry1(struct rte_pipeline_table_entry *entry);
void print_cgnapt_entry(struct cgnapt_table_entry *entry);
void my_print_entry(struct cgnapt_table_entry *ent);

/* CLI custom handler back-end helper functions */

void *pipeline_cgnapt_msg_req_custom_handler(
	struct pipeline *p,
	void *msg);

void *pipeline_cgnapt_msg_req_entry_add_handler(
	struct pipeline *p,
	void *msg);

void *pipeline_cgnapt_msg_req_entry_del_handler(
	struct pipeline *p,
	void *msg);

void *pipeline_cgnapt_msg_req_entry_sync_handler(
	struct pipeline *p,
	void *msg);

void *pipeline_cgnapt_msg_req_entry_dbg_handler(
	struct pipeline *p,
	void *msg);

void *pipeline_cgnapt_msg_req_entry_addm_handler(
	struct pipeline *p,
	void *msg);

void *pipeline_cgnapt_msg_req_ver_handler(
	struct pipeline *p,
	void *msg);

void *pipeline_cgnapt_msg_req_nsp_add_handler(
	struct pipeline *p,
	void *msg);

void *pipeline_cgnapt_msg_req_nsp_del_handler(
	struct pipeline *p,
	void *msg);
#ifdef PCP_ENABLE
extern void *pipeline_cgnapt_msg_req_pcp_handler(
	struct pipeline *p,
	void *msg);
#endif

int pipeline_cgnapt_msg_req_entry_addm_pair(
	struct pipeline *p, void *msg,
	uint32_t src_ip, uint16_t src_port,
	uint32_t dest_ip, uint16_t dest_port,
	uint16_t rx_port, uint32_t ttl,
	uint8_t type, uint8_t src_ipv6[16]);

/* CGNAPT Functions */
uint64_t pkt_miss_cgnapt(
	struct pipeline_cgnapt_entry_key *key,
	struct rte_mbuf *pkt,
	struct rte_pipeline_table_entry **table_entry,
	uint64_t *pkts_mask,
	uint32_t pkt_num,
	void *arg);

struct cgnapt_table_entry *add_dynamic_cgnapt_entry(
	struct pipeline *p,
	struct pipeline_cgnapt_entry_key *key,
	//#ifdef PCP_ENABLE
	uint32_t timeout,
	//#endif
	uint8_t pkt_type,
	uint8_t *src_addr,
	uint8_t *err);

void calculate_hw_checksum(
	struct rte_mbuf *pkt,
	uint8_t ip_ver,
	uint8_t protocol);

uint64_t nextPowerOf2(uint64_t n);
struct ether_addr *get_local_link_hw_addr(uint8_t out_port);
uint8_t local_dest_mac_present(uint8_t out_port);

enum PKT_TYPE {
PKT_TYPE_IPV4,
PKT_TYPE_IPV6,
PKT_TYPE_IPV6to4,
PKT_TYPE_IPV4to6,
};
void hw_checksum(struct rte_mbuf *pkt, enum PKT_TYPE ver);
void sw_checksum(struct rte_mbuf *pkt, enum PKT_TYPE ver);
int rte_get_pkt_ver(struct rte_mbuf *pkt);
void print_common_table(void);
#if CT_CGNAT
extern int add_dynamic_cgnapt_entry_alg(
	struct pipeline *p,
	struct pipeline_cgnapt_entry_key *key,
	struct cgnapt_table_entry **entry_ptr1,
	struct cgnapt_table_entry **entry_ptr2);
#endif
#endif
