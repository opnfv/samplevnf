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

#ifndef __INCLUDE_PIPELINE_ACL_BE_H__
#define __INCLUDE_PIPELINE_ACL_BE_H__

/**
 * @file
 * Pipeline ACL BE.
 *
 * Pipeline ACL Back End (BE).
 * Responsible for packet processing.
 *
 */

#include "pipeline_common_be.h"
#include "rte_ct_tcp.h"
#include "pipeline_arpicmp_be.h"

enum pipeline_acl_key_type {
	PIPELINE_ACL_IPV4_5TUPLE,
	PIPELINE_ACL_IPV6_5TUPLE
};

#define MBUF_HDR_ROOM 256
#define ETH_HDR_SIZE  14
#define IP_HDR_SIZE  20
#define IP_HDR_DSCP_OFST 1
#define IP_HDR_LENGTH_OFST 2
#define IP_HDR_PROTOCOL_OFST 9
#define IP_HDR_DST_ADR_OFST 16
#define IP_VERSION_4 4
#define IP_VERSION_6 6

/* IPv6 */
#define IP_HDR_SIZE_IPV6  40
#define IP_HDR_DSCP_OFST_IPV6 0
#define IP_HDR_LENGTH_OFST_IPV6 4
#define IP_HDR_PROTOCOL_OFST_IPV6 6
#define IP_HDR_DST_ADR_OFST_IPV6 24

#define IPv4_HDR_VERSION 4
#define IPv6_HDR_VERSION 6
#define IP_VERSION_CHECK 4

extern int rte_ACL_hi_counter_block_in_use;
extern uint8_t ACL_DEBUG;

/**
 * A structure defining the ACL counter block.
 * One counter block per ACL Thread
 */
struct rte_ACL_counter_block {
	char name[PIPELINE_NAME_SIZE];
	/* as long as a counter doesn't cross cache line, writes are atomic */
	uint64_t tpkts_processed;
	uint64_t bytes_processed;	/* includes all L3 and higher headers */

	uint64_t pkts_drop;
	uint64_t pkts_received;
	uint64_t pkts_drop_ttl;
	uint64_t pkts_drop_bad_size;
	uint64_t pkts_drop_fragmented;
	uint64_t pkts_drop_without_arp_entry;

	struct rte_CT_counter_block *ct_counters;

	uint64_t sum_latencies;
	/* average latency = sum_latencies / count_latencies */
	uint32_t count_latencies;
} __rte_cache_aligned;

#define MAX_ACL_INSTANCES 12/* max number ACL threads, actual usually less */

extern struct rte_ACL_counter_block rte_acl_counter_table[MAX_ACL_INSTANCES]
	__rte_cache_aligned;

/**
 * A structure defining the IPv4 5-Tuple for ACL rules.
 */
struct pipeline_acl_key_ipv4_5tuple {
	uint32_t src_ip;
	uint32_t src_ip_mask;
	uint32_t dst_ip;
	uint32_t dst_ip_mask;
	uint16_t src_port_from;
	uint16_t src_port_to;
	uint16_t dst_port_from;
	uint16_t dst_port_to;
	uint8_t proto;
	uint8_t proto_mask;
};

/**
 * A structure defining the IPv6 5-Tuple for ACL rules.
 */
struct pipeline_acl_key_ipv6_5tuple {
	uint8_t src_ip[16];
	uint32_t src_ip_mask;
	uint8_t dst_ip[16];
	uint32_t dst_ip_mask;
	uint16_t src_port_from;
	uint16_t src_port_to;
	uint16_t dst_port_from;
	uint16_t dst_port_to;
	uint8_t proto;
	uint8_t proto_mask;
};

/**
 * A structure defining the key to store ACL rule.
 * For both IPv4 and IPv6.
 */
struct pipeline_acl_key {
	enum pipeline_acl_key_type type;
	union {
		struct pipeline_acl_key_ipv4_5tuple ipv4_5tuple;
		struct pipeline_acl_key_ipv6_5tuple ipv6_5tuple;
	} key;
};

/**
 * A structure defining the ACL pipeline table.
 */
struct acl_table_entry {
	struct rte_pipeline_table_entry head;
	uint32_t action_id;
};

/* Define ACL actions for bitmap */
#define acl_action_packet_drop		1
#define acl_action_packet_accept	2
#define acl_action_nat				4
#define acl_action_fwd				8
#define acl_action_count			16
#define acl_action_dscp				32
#define acl_action_conntrack		64
#define acl_action_connexist		128

#define acl_private_public			0
#define acl_public_private			1

#define action_array_max            10000

/**
 * A structure defining the key to store an ACL action.
 */
struct pipeline_action_key {
	uint32_t action_id;
	uint32_t action_bitmap;
	uint32_t nat_port;
	uint32_t fwd_port;
	uint8_t dscp_priority;
	uint8_t private_public;
} __rte_cache_aligned;

/**
 * A structure defining the Action counters.
 * One Action Counter Block per ACL thread.
 */
struct action_counter_block {
	uint64_t byteCount;
	uint64_t packetCount;
} __rte_cache_aligned;

extern struct pipeline_action_key *action_array_a;
extern struct pipeline_action_key *action_array_b;
extern struct pipeline_action_key *action_array_active;
extern struct pipeline_action_key *action_array_standby;
extern uint32_t action_array_size;

extern struct action_counter_block
	action_counter_table[MAX_ACL_INSTANCES][action_array_max]
	__rte_cache_aligned;

enum pipeline_acl_msg_req_type {
	PIPELINE_ACL_MSG_REQ_DBG = 0,
	PIPELINE_ACL_MSG_REQS
};

/**
 * A structure defining the add ACL rule command response message.
 */
struct pipeline_acl_add_msg_rsp {
	int status;
	int key_found;
	void *entry_ptr;
};

/**
 * A structure defining the debug command request message.
 */
struct pipeline_acl_dbg_msg_req {
	enum pipeline_msg_req_type type;
	enum pipeline_acl_msg_req_type subtype;

	/* data */
	uint8_t dbg;
};

/**
 * A structure defining the debug command response message.
 */
struct pipeline_acl_dbg_msg_rsp {
	int status;
	void *entry_ptr;
};

extern struct pipeline_be_ops pipeline_acl_be_ops;

extern int rte_ct_initialize_default_timeouts(struct rte_ct_cnxn_tracker
					      *new_cnxn_tracker);

#endif
