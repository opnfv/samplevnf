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

#ifndef __INCLUDE_PIPELINE_VFW_BE_H__
#define __INCLUDE_PIPELINE_VFW_BE_H__

/**
 * @file
 * Pipeline VFW BE.
 *
 * Pipeline VFW Back End (BE).
 * Responsible for packet processing.
 *
 */
#include <stdint.h>
#include <rte_ether.h>

#include "pipeline_common_be.h"
#include "rte_cnxn_tracking.h"
#include "rte_ct_tcp.h"
#include "lib_acl.h"

/*#define VFW_DEBUG 0*/
uint8_t vfw_debug;
extern uint8_t VFW_DEBUG;
extern uint8_t firewall_flag;
extern uint8_t cnxn_tracking_is_active;
#define KEY_SIZE 10              /*IPV4 src_ip + dst_ip + src_port + dst_port */
#define IP_32BIT_SIZE 4
#define MAX_VFW_INSTANCES 12       /* max number fw threads, actual usually less */
#define IPv4_HDR_VERSION 4
#define IPv6_HDR_VERSION 6
#define IP_VERSION_CHECK 4
extern int rte_VFW_hi_counter_block_in_use;

enum pipeline_vfw_key_type {
       PIPELINE_VFW_IPV4_5TUPLE,
       PIPELINE_VFW_IPV6_5TUPLE
};
 /**
 * A structure defining the VFW counter block.
 * One counter block per VFW Thread
 */
struct rte_VFW_counter_block {
       char name[PIPELINE_NAME_SIZE];

       /* as long as a counter doesn't cross cache line, writes are atomic */
       uint64_t pkts_received;
       uint64_t bytes_processed; /**< includes all L3 and higher headers. */
       uint64_t num_batch_pkts_sum;
       uint32_t num_pkts_measurements;
       uint32_t unused_counter;

       uint64_t entry_timestamp;
       uint64_t exit_timestamp;
       uint64_t internal_time_sum;
       uint64_t external_time_sum;
       uint32_t time_measurements;
       uint32_t count_latencies;
       /**< Sum latencies */
       uint64_t sum_latencies;
       uint64_t pkts_drop_without_rule;
       uint64_t pkts_acl_forwarded;

       /**< Total packets drop for ttl value by firewall.*/
       uint64_t pkts_drop_ttl;
       /**< Total packets drop for bad size by firewall. */
       uint64_t pkts_drop_bad_size;
       /**< Total packets drop for fragmented by firewall. */
       uint64_t pkts_drop_fragmented;
       /**< Total packets drop for without arp entry by firewall.*/
       uint64_t pkts_drop_without_arp_entry;
       /**< Total packets drop for ipv6 not tcp/udp by firewall. */
       uint64_t pkts_drop_unsupported_type;
       /**< A pointer to connection tracker counters.*/
       struct rte_CT_counter_block *ct_counters;
       /* average latency = sum_latencies / count_latencies */
       uint64_t pkts_fw_forwarded;
       uint64_t arpicmpPktCount;
} __rte_cache_aligned;

/** The counter table for VFW pipeline per thread data.*/
extern struct rte_VFW_counter_block
rte_vfw_counter_table[MAX_VFW_INSTANCES] __rte_cache_aligned;

/**
 * A structure defining the IPv4 5-Tuple for VFW rules.
 */
struct pipeline_vfw_key_ipv4_5tuple {
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
 * A structure defining the IPv6 5-Tuple for VFW rules.
 */
struct pipeline_vfw_key_ipv6_5tuple {
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

/* Messages from CLI for processing by packet processing */

enum pipeline_tcpfw_msg_req_type {

       PIPELINE_TCPFW_MSG_REQ_ENTRY_STATUS,
       PIPELINE_TCPFW_MSG_REQ_DBG,
       PIPELINE_TCPFW_MSG_REQ_SYNPROXY_FLAGS,
       PIPELINE_TCPFW_MSG_REQS
};
/**
 * A structure defining the key to store VFW rule.
 * For both IPv4 and IPv6.
 */
struct pipeline_vfw_key {
       enum pipeline_vfw_key_type type;
       union {
              struct pipeline_vfw_key_ipv4_5tuple ipv4_5tuple;
              struct pipeline_vfw_key_ipv6_5tuple ipv6_5tuple;
       } key;
};



extern struct pipeline_action_key *action_array_a;
extern struct pipeline_action_key *action_array_b;
extern struct pipeline_action_key *action_array_active;
extern struct pipeline_action_key *action_array_standby;
extern uint32_t action_array_size;

extern struct action_counter_block
action_counter_table[MAX_VFW_INSTANCES][action_array_max]
__rte_cache_aligned;

/**
 * A structure defining the add VFW rule command response message.
 */
struct pipeline_vfw_add_msg_rsp {
       int status;
       int key_found;
       void *entry_ptr;
};

struct app_pipeline_vfw_entry_params {
       uint32_t s_addr;
       uint16_t s_port;
       uint32_t d_addr;
       uint16_t d_port;

};

struct pipeline_vfw_entry_key {
       uint32_t ip1[IP_32BIT_SIZE];
       uint32_t ip2[IP_32BIT_SIZE];
       uint16_t port1;
       uint16_t port2;
};

/* Messages from CLI for processing by packet processing */

enum pipeline_vfw_msg_req_type {
       PIPELINE_VFW_MSG_REQ_SYNPROXY_FLAGS,
       PIPELINE_VFW_MSG_REQS
};

/*
 * A structure defining the synproxy ON/OFF command request message.
 */
struct pipeline_vfw_synproxy_flag_msg_req {
       enum pipeline_msg_req_type type;
       enum pipeline_vfw_msg_req_type subtype;

       /* data */
       uint8_t synproxy_flag;
};

/**
 * A structure defining the synproxy ON/OFF command response message.
 */
struct pipeline_vfw_synproxy_flag_msg_rsp {
       int status;
       void *entry_ptr;
};
extern struct pipeline_be_ops pipeline_vfw_be_ops;

extern int rte_ct_initialize_default_timeouts(struct rte_ct_cnxn_tracker
                                         *new_cnxn_tracker);

#endif
