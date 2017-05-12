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

#ifndef __INCLUDE_ACL_LIB_H__
#define __INCLUDE_ACL_LIB_H__

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <rte_pipeline.h>
#include <rte_table_acl.h>
#include "rte_cnxn_tracking.h"
#include "rte_ct_tcp.h"
/* Define VNF actions for bitmap */
#define lib_acl_action_packet_drop		1
#define lib_acl_action_packet_accept	2
#define lib_acl_action_nat				4
#define lib_acl_action_fwd				8
#define lib_acl_action_count			16
#define lib_acl_action_dscp				32
#define lib_acl_action_conntrack		64
#define lib_acl_action_connexist		128
#define action_array_max            10000
#define lib_acl_private_public			0
#define lib_acl_public_private			1
#define IP_HDR_DSCP_OFST 1
#define IPv4_HDR_VERSION 4
#define IPv6_HDR_VERSION 6
#define IP_HDR_DSCP_OFST_IPV6 0
#define IP_VERSION_CHECK 4
#define IP_START (MBUF_HDR_ROOM + ETH_HDR_SIZE)
#define DEFULT_NUM_RULE (4*1024)
/**
 * A structure defining the key to store an VNF action.
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
 * One Action Counter Block per VNF thread.
 */
struct action_counter_block {
	uint64_t byteCount;
	uint64_t packetCount;
} __rte_cache_aligned;

/**
 * A structure defining the ACL library table.
 */
struct lib_acl_table_entry {
	struct rte_pipeline_table_entry head;
	uint32_t action_id;
};


struct lib_acl {
	uint32_t n_rules;
	uint32_t n_rule_fields;
	struct rte_acl_field_def *field_format;
	uint32_t field_format_size;
	int action_counter_index;
	struct lib_acl_table_entry
	*plib_acl_entries_ipv4[RTE_PORT_IN_BURST_SIZE_MAX];
	struct lib_acl_table_entry
	*plib_acl_entries_ipv6[RTE_PORT_IN_BURST_SIZE_MAX];
} __rte_cache_aligned;

void *lib_acl_create_active_standby_table_ipv4(uint8_t table_num,
		uint32_t *libacl_n_rules);

void *lib_acl_create_active_standby_table_ipv6(uint8_t table_num,
		uint32_t *libacl_n_rules);
int lib_acl_parse_config(struct lib_acl *plib_acl,
		char *arg_name, char *arg_value,
		uint32_t *libacl_n_rules);
uint64_t
lib_acl_ipv4_pkt_work_key(struct lib_acl *plib_acl,
	struct rte_mbuf **pkts, uint64_t pkts_mask,
	uint64_t *pkts_drop_without_rule,
	void *plib_acl_rule_table_ipv4_active,
	struct pipeline_action_key *action_array_active,
	struct action_counter_block (*p_action_counter_table)[action_array_max],
	uint64_t *conntrack_mask,
	uint64_t *connexist_mask);
uint64_t
lib_acl_ipv6_pkt_work_key(struct lib_acl *plib_acl,
	struct rte_mbuf **pkts, uint64_t pkts_mask,
	uint64_t *pkts_drop_without_rule,
	void *plib_acl_rule_table_ipv6_active,
	struct pipeline_action_key *action_array_active,
	struct action_counter_block (*p_action_counter_table)[action_array_max],
	uint64_t *conntrack_mask,
	uint64_t *connexist_mask);


#endif
