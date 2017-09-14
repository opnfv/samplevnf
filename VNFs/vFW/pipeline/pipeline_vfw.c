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

/**
 * @file
 * Pipeline VFW FE Implementation.
 *
 * Implementation of the Pipeline VFW Front End (FE).
 * Runs on the Master pipeline, responsible for CLI commands.
 *
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_hexdump.h>
#include <rte_malloc.h>
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_etheraddr.h>
#include <cmdline_socket.h>
#include <cmdline.h>
#include <rte_table_acl.h>

#include "app.h"
#include "pipeline_common_fe.h"
#include "pipeline_master.h"
#include "pipeline_vfw.h"
#include "pipeline_vfw_be.h"
#include "rte_cnxn_tracking.h"

struct app_params *myapp;
#define MAX_BUF_SIZE    2048
extern struct cmdline *pipe_cl;
extern int my_inet_pton_ipv6(int af, const char *src, void *dst);

/**
 * A structure defining the VFW rule for the TAILQ Tables.
 */
struct app_pipeline_vfw_rule {
       struct pipeline_vfw_key key;
       int32_t priority;
       uint32_t port_id;
       uint32_t action_id;
       uint32_t command;
       void *entry_ptr;

        TAILQ_ENTRY(app_pipeline_vfw_rule) node;
};

/**
 * A structure defining the VFW pipeline front end data.
 */
struct app_pipeline_vfw {
       /* parameters */
       uint32_t n_ports_in;
       uint32_t n_ports_out;
};

/*
 * Define a structure to calculate performance measurements for VFW.
 * VFW continually updates counters for total number of packets
 * processed, and total number of bytes processed. Each VFW backend thread
 * i.e.the packet processing instances updates their own copy of these counters.
 * An optional, 1 second periodic timer fires on the master core, which combines
 * those numbers to perform byte and packet per second calculations, without
 * burdening the packet processors.
 */
#define RTE_VFW_PERF_MSR_BUFF_SIZE 8       /* must be power of 2 */
#define RTE_VFW_PERF_MSR_BUFF_SIZE_MASK (RTE_VFW_PERF_MSR_BUFF_SIZE - 1)

/**
 * A structure defining the VFW performance measurements.
 */
struct rte_vfw_performance_measures_t {
       /* two circular buffers */
       uint64_t total_packets[RTE_VFW_PERF_MSR_BUFF_SIZE];
       uint64_t total_bytes[RTE_VFW_PERF_MSR_BUFF_SIZE];
       uint32_t bytes_last_second;
       uint32_t ave_bytes_per_second;
       uint32_t pkts_last_second;
       uint32_t ave_pkts_per_second;
       /* times data has been (over-)written into buffers */
       uint64_t total_entries;
       uint8_t current_index;       /* for circular buffers */
};

struct rte_vfw_performance_measures_t rte_vfw_performance_measures;

/*
 * Active and Standby Tables
 * Active and standby tables exist to allow modifying VFW rules and
 * actions and having no impact on the packet processing running on
 * the multiple VFW threads/pipelines. The packet processing does a
 * lookup on the active tables. Each VFW thread/pipeline runs on
 * a separate core (i.e. 2,3,4, etc).
 *
 * All CLI actions run on the VFW Front End (FE) code on Core 0.
 * All changes, adding/delete rules and action occurs on the standby tables.
 * In activate the changes in the standby table, the CLI command is entered:
 * p vfw applyruleset
 *
 * The standby tables become active. The active table becomes the standby.
 * The new standby table gets updated with the changes that were done.
 *
 * Table descriptions:
 * VFW Rule Tables TAILQ - 2 global tables active/standby per ipv4,ipv6
 * The TAILQ tables are required for the LS CLI command and in order
 * to do a lookup using a rule when adding or deleting a rule.
 * The VFW TRIE tables in DPDK do not allow this type of listing or lookup.
 *
 * VFW Rule Tables TRIE - 2 global tables active/standby per ipv4, ipv6
 * The TRIE tables are the tables used during packet processing.
 * A bulk lookup can be performed by passing in a burst of packets.
 * Unfortunately, the current implementation of the TRIE tables does
 * not allow lookup using a rule. Hence the need for the TAILQ tables.
 *
 * VFW Action Tables ARRAY - 2 global tables active/standby
 * The action tables stores the VFW actions.
 * Every rule has an action id which defines what action to take
 * when a packet matching that rule is received.
 * Actions: accept, drop, fwd, count, nat, dscp, conntrack
 *
 * Command Table TAILQ - 1 table
 * After the active and standby tables are swithover, the new standby
 * table needs to be updated with all the changes that were done.
 * This table stores all the add and delete commands and updates
 * the new standby table when the applyruleset command executes.
 *
 * The active and standby tables can be displayed individually:
 * p vfw ls 0    <== active VFW rules
 * p vfw ls 1    <== standby VFW rules
 * p action ls 0 <== active VFW actions
 * p action ls 1 <== standby VFW actions
 */

/* Only create global VFW tables once */
int vfw_rule_table_created;

/*
 * VFW Rule Tables TAILQ - see description above
 * Two tables/counters are required for active and standby.
 * The A and B tables/counters are the actual instances.
 * The pointers are set to point to these tables/counters.
 * The pointers are updated during the switchover for the applyruleset.
 */

/* Definition of the the TAILQ table */
TAILQ_HEAD(app_pipeline_vfw_rule_type, app_pipeline_vfw_rule);
/* Instances of tables and counters */
struct app_pipeline_vfw_rule_type vfw_tailq_rules_ipv4a;
struct app_pipeline_vfw_rule_type vfw_tailq_rules_ipv4b;
struct app_pipeline_vfw_rule_type vfw_tailq_rules_ipv6a;
struct app_pipeline_vfw_rule_type vfw_tailq_rules_ipv6b;
uint32_t vfw_n_tailq_rules_ipv4a;
uint32_t vfw_n_tailq_rules_ipv6a;
uint32_t vfw_n_tailq_rules_ipv4b;
uint32_t vfw_n_tailq_rules_ipv6b;
/* Pointers to tables and counters for switchover in applyruleset */
struct app_pipeline_vfw_rule_type *vfw_tailq_rules_ipv4_active;
struct app_pipeline_vfw_rule_type *vfw_tailq_rules_ipv4_standby;
struct app_pipeline_vfw_rule_type *vfw_tailq_rules_ipv6_active;
struct app_pipeline_vfw_rule_type *vfw_tailq_rules_ipv6_standby;
struct app_pipeline_vfw_rule_type *vfw_tailq_rules_temp_ptr;
uint32_t *vfw_n_tailq_rules_ipv4_active;
uint32_t *vfw_n_tailq_rules_ipv4_standby;
uint32_t *vfw_n_tailq_rules_ipv6_active;
uint32_t *vfw_n_tailq_rules_ipv6_standby;

/* VFW commands to update new standby tables after switchover */
TAILQ_HEAD(, app_pipeline_vfw_rule) vfw_commands;

/* VFW IPV4 and IPV6 enable flags for debugging (Default both on) */
int vfw_ipv4_enabled = 1;
int vfw_ipv6_enabled = 1;

/* Number of VFW Rules, default 4 * 1024 */
uint32_t vfw_n_rules = 4 * 1024;
/* VFW Rule Table TRIE - 2 (Active, Standby) Global table per ipv4, ipv6 */
void *vfw_rule_table_ipv4_active;
void *vfw_rule_table_ipv4_standby;
void *vfw_rule_table_ipv6_active;
void *vfw_rule_table_ipv6_standby;

/**
 * Reset running averages for performance measurements.
 *
 */
static void rte_vfw_reset_running_averages(void)
{
       memset(&rte_vfw_performance_measures, 0,
              sizeof(rte_vfw_performance_measures));
};

/**
 * Compute performance calculations on master to reduce computing on
 * packet processor.
 *
 * @param total_bytes
 *  Total bytes processed during this interval.
 * @param total_packets
 *  Total packets processed during this interval.
 *
 */
static void rte_vfw_update_performance_measures(uint64_t total_bytes,
                                             uint64_t total_packets)
{
       /* make readable */
       struct rte_vfw_performance_measures_t *pm =
           &rte_vfw_performance_measures;

       if (unlikely(pm->total_entries == 0 && total_packets == 0))
              /* the timer is running, but no traffic started yet,
               * so do nothing */
              return;

       if (likely(pm->total_entries > 0)) {
              uint8_t oldest_index;
              uint8_t divisor;

              pm->bytes_last_second =
                  total_bytes - pm->total_bytes[pm->current_index];
              pm->pkts_last_second =
                  total_packets - pm->total_packets[pm->current_index];

              /* if total_entries zero, current_index must remain as zero */
              pm->current_index =
                  (pm->current_index +
                   1) & RTE_VFW_PERF_MSR_BUFF_SIZE_MASK;

              if (unlikely
                  (pm->total_entries <= RTE_VFW_PERF_MSR_BUFF_SIZE)) {
                     /* oldest value is at element 0 */
                     oldest_index = 0;
                     divisor = pm->total_entries;
                     /* note, prior to incrementing total_entries */
              } else {
                     /* oldest value is at element about to be overwritten */
                     oldest_index = pm->current_index;
                     divisor = RTE_VFW_PERF_MSR_BUFF_SIZE;
              }

              pm->ave_bytes_per_second =
                  (total_bytes - pm->total_bytes[oldest_index]) / divisor;
              pm->ave_pkts_per_second =
                  (total_packets - pm->total_packets[oldest_index]) / divisor;
       }

       pm->total_bytes[pm->current_index] = total_bytes;
       pm->total_packets[pm->current_index] = total_packets;
       pm->total_entries++;
}

/**
 * Combine data from all vfw+connection tracking instances.
 * Calculate various statistics. Dump to console.
 *
 */
static void rte_vfw_sum_and_print_counters(void)
{
       int i;
       struct rte_VFW_counter_block vfw_counter_sums;
       struct rte_CT_counter_block ct_counter_sums;
       /* For ct instance with this fw instance */
       struct rte_CT_counter_block *ct_counters;

       memset(&vfw_counter_sums, 0, sizeof(vfw_counter_sums));
       memset(&ct_counter_sums, 0, sizeof(ct_counter_sums));

       for (i = 0; i <= rte_VFW_hi_counter_block_in_use; i++) {
              struct rte_VFW_counter_block *vfw_ctrs =
                  &rte_vfw_counter_table[i];
              ct_counters = rte_vfw_counter_table[i].ct_counters;

              uint64_t average_internal_time =
                  vfw_ctrs->time_measurements ==
                  0 ? 0 : vfw_ctrs->internal_time_sum /
                  vfw_ctrs->time_measurements;
              uint64_t average_external_time =
                  vfw_ctrs->time_measurements ==
                  0 ? 0 : vfw_ctrs->external_time_sum /
                  vfw_ctrs->time_measurements;
              uint64_t average_pkts_in_batch =
                  vfw_ctrs->num_pkts_measurements ==
                  0 ? 0 : vfw_ctrs->num_batch_pkts_sum /
                  vfw_ctrs->num_pkts_measurements;

              printf("{\"VFW counters\" : {\"id\" : \"%s\",\"packets_processed\" : %"
                     PRIu64 ", \"bytes_processed\" : %"
                     PRIu64 ", \"average_pkts_in_batch\" : %"
                     PRIu64 ", \"average_internal_time_in_clocks\" : %"
                     PRIu64 ", \"average_external_time_in_clocks\" : %"
                     PRIu64 ", \"total_time_measures\" : %"
                     PRIu32 ", \"ct_packets_forwarded\" : %"
                     PRIu64 ", \"ct_packets_dropped\" : %"
                     PRIu64 "}}\n",
                     vfw_ctrs->name,
                     vfw_ctrs->pkts_received,
                     vfw_ctrs->bytes_processed,
                     average_pkts_in_batch,
                     average_internal_time,
                     average_external_time,
                     vfw_ctrs->time_measurements,
                     ct_counters->pkts_forwarded, ct_counters->pkts_drop);

              /* sum VFW counters */
              vfw_counter_sums.bytes_processed +=
                  vfw_ctrs->bytes_processed;
              vfw_counter_sums.pkts_drop_without_rule +=
                  vfw_ctrs->pkts_drop_without_rule;
              vfw_counter_sums.pkts_received += vfw_ctrs->pkts_received;
              vfw_counter_sums.pkts_drop_ttl += vfw_ctrs->pkts_drop_ttl;
              vfw_counter_sums.pkts_drop_bad_size +=
                  vfw_ctrs->pkts_drop_bad_size;
              vfw_counter_sums.pkts_drop_fragmented +=
                  vfw_ctrs->pkts_drop_fragmented;
              vfw_counter_sums.pkts_drop_without_arp_entry +=
                  vfw_ctrs->pkts_drop_without_arp_entry;
              vfw_counter_sums.sum_latencies += vfw_ctrs->sum_latencies;
              vfw_counter_sums.count_latencies +=
                  vfw_ctrs->count_latencies;

              vfw_counter_sums.internal_time_sum +=
                  vfw_ctrs->internal_time_sum;
              vfw_counter_sums.external_time_sum +=
                  vfw_ctrs->external_time_sum;
              vfw_counter_sums.time_measurements +=
                  vfw_ctrs->time_measurements;
              vfw_counter_sums.pkts_drop_unsupported_type +=
                  vfw_ctrs->pkts_drop_unsupported_type;

              /* sum cnxn tracking counters */
              ct_counter_sums.current_active_sessions +=
                  ct_counters->current_active_sessions;
              ct_counter_sums.sessions_activated +=
                  ct_counters->sessions_activated;
              ct_counter_sums.sessions_reactivated +=
                  ct_counters->sessions_reactivated;
              ct_counter_sums.sessions_established +=
                  ct_counters->sessions_established;
              ct_counter_sums.sessions_closed += ct_counters->sessions_closed;
              ct_counter_sums.sessions_timedout +=
                  ct_counters->sessions_timedout;
              ct_counter_sums.pkts_forwarded += ct_counters->pkts_forwarded;
              ct_counter_sums.pkts_drop += ct_counters->pkts_drop;
              ct_counter_sums.pkts_drop_invalid_conn +=
                  ct_counters->pkts_drop_invalid_conn;
              ct_counter_sums.pkts_drop_invalid_state +=
                  ct_counters->pkts_drop_invalid_state;
              ct_counter_sums.pkts_drop_invalid_rst +=
                  ct_counters->pkts_drop_invalid_rst;
              ct_counter_sums.pkts_drop_outof_window +=
                  ct_counters->pkts_drop_outof_window;
       }

       rte_vfw_update_performance_measures(vfw_counter_sums.
                                          bytes_processed,
                                          vfw_counter_sums.
                                          pkts_received);
       uint64_t average_latency =
           vfw_counter_sums.count_latencies ==
           0 ? 0 : vfw_counter_sums.sum_latencies /
           vfw_counter_sums.count_latencies;

       printf("{\"VFW sum counters\" : {"
              "\"packets_last_sec\" : %"
              PRIu32 ", \"average_packets_per_sec\" : %"
              PRIu32 ", \"bytes_last_sec\" : %"
              PRIu32 ", \"average_bytes_per_sec\" : %"
              PRIu32 ", \"pkts_received\" : %"
              PRIu64 ", \"bytes_processed\" : %"
              PRIu64 ", \"average_latency_in_clocks\" : %"
              PRIu64 ", \"ct_packets_forwarded\" : %"
              PRIu64 ", \"ct_packets_dropped\" : %"
              PRIu64 ", \"drops\" : {"
              "\"TTL_zero\" : %" PRIu64 ", \"bad_size\" : %"
              PRIu64 ", \"fragmented_packet\" : %"
              PRIu64 ", \"unsupported_packet_types\" : %"
              PRIu64 ", \"no_arp_entry\" : %"
              PRIu64 "}, \"ct_sessions\" : {"
              "\"active\" : %" PRIu64 ", \"open\" : %"
              PRIu64 ", \"re-open_attempt\" : %"
              PRIu64 ", \"established\" : %"
              PRIu64 ", \"closed\" : %"
              PRIu64 ", \"timeout\" : %"
              PRIu64 "}, \"ct_drops\" : {"
              "\"out_of_window\" : %" PRIu64 ", \"invalid_conn\" : %"
              PRIu64 ", \"invalid_state_transition\" : %"
              PRIu64 " \"RST\" : %"
              PRIu64 "}}}\n",
              rte_vfw_performance_measures.pkts_last_second,
              rte_vfw_performance_measures.ave_pkts_per_second,
              rte_vfw_performance_measures.bytes_last_second,
              rte_vfw_performance_measures.ave_bytes_per_second,
              vfw_counter_sums.pkts_received,
              vfw_counter_sums.bytes_processed,
              average_latency,
              ct_counter_sums.pkts_forwarded,
              ct_counter_sums.pkts_drop,
              vfw_counter_sums.pkts_drop_ttl,
              vfw_counter_sums.pkts_drop_bad_size,
              vfw_counter_sums.pkts_drop_fragmented,
              vfw_counter_sums.pkts_drop_unsupported_type,
              vfw_counter_sums.pkts_drop_without_arp_entry,
              ct_counter_sums.current_active_sessions,
              ct_counter_sums.sessions_activated,
              ct_counter_sums.sessions_reactivated,
              ct_counter_sums.sessions_established,
              ct_counter_sums.sessions_closed,
              ct_counter_sums.sessions_timedout,
              ct_counter_sums.pkts_drop_outof_window,
              ct_counter_sums.pkts_drop_invalid_conn,
              ct_counter_sums.pkts_drop_invalid_state,
              ct_counter_sums.pkts_drop_invalid_rst);

}

/**
 * Callback routine for 1 second, periodic timer.
 *
 * @param rt
 *  A pointer to the rte_timer.
 * @param arg
 *  A pointer to application specific arguments (not used).
 *
 * @return
 *  0 on success and port_id is filled, negative on error.
 */
static void rte_dump_vfw_counters_from_master(
              __rte_unused struct rte_timer *rt, __rte_unused void *arg)
{
       rte_vfw_sum_and_print_counters();
}

int rte_vfw_hertz_computed;       /* only launch timer once */
uint64_t rte_vfw_ticks_in_one_second;
/* TODO: is processor hertz computed/stored elsewhere? */
struct rte_timer rte_vfw_one_second_timer = RTE_TIMER_INITIALIZER;

/**
 * Print IPv4 Rule.
 *
 * @param rule
 *  A pointer to the rule.
 *
 */
static void print_vfw_ipv4_rule(struct app_pipeline_vfw_rule *rule)
{
       printf("Prio = %" PRId32 " (SA = %" PRIu32 ".%" PRIu32
              ".%" PRIu32 ".%" PRIu32 "/%" PRIu32 ", DA = %"
              PRIu32 ".%" PRIu32
              ".%" PRIu32 ".%" PRIu32 "/%" PRIu32 ", SP = %"
              PRIu32 "-%" PRIu32 ", DP = %"
              PRIu32 "-%" PRIu32 ", Proto = %"
              PRIu32 " / 0x%" PRIx32 ") => Action ID = %"
              PRIu32 " (entry ptr = %p)\n",
              rule->priority,
              (rule->key.key.ipv4_5tuple.src_ip >> 24) & 0xFF,
              (rule->key.key.ipv4_5tuple.src_ip >> 16) & 0xFF,
              (rule->key.key.ipv4_5tuple.src_ip >> 8) & 0xFF,
              rule->key.key.ipv4_5tuple.src_ip & 0xFF,
              rule->key.key.ipv4_5tuple.src_ip_mask,
              (rule->key.key.ipv4_5tuple.dst_ip >> 24) & 0xFF,
              (rule->key.key.ipv4_5tuple.dst_ip >> 16) & 0xFF,
              (rule->key.key.ipv4_5tuple.dst_ip >> 8) & 0xFF,
              rule->key.key.ipv4_5tuple.dst_ip & 0xFF,
              rule->key.key.ipv4_5tuple.dst_ip_mask,
              rule->key.key.ipv4_5tuple.src_port_from,
              rule->key.key.ipv4_5tuple.src_port_to,
              rule->key.key.ipv4_5tuple.dst_port_from,
              rule->key.key.ipv4_5tuple.dst_port_to,
              rule->key.key.ipv4_5tuple.proto,
              rule->key.key.ipv4_5tuple.proto_mask,
              rule->action_id, rule->entry_ptr);
}

/**
 * Print IPv6 Rule.
 *
 * @param rule
 *  A pointer to the rule.
 *
 */
static void print_vfw_ipv6_rule(struct app_pipeline_vfw_rule *rule)
{
       printf("Prio = %" PRId32 " (SA = %02" PRIx8 "%02" PRIx8
              ":%02" PRIx8 "%02" PRIx8 ":%02" PRIx8 "%02" PRIx8
              ":%02" PRIx8 "%02" PRIx8 ":%02" PRIx8 "%02" PRIx8
              ":%02" PRIx8 "%02" PRIx8 ":%02" PRIx8 "%02" PRIx8
              ":%02" PRIx8 "%02" PRIx8 "/" "%" PRIu32 ", DA = %02"
              PRIx8 "%02" PRIx8 ":%02" PRIx8
              "%02" PRIx8 ":%02" PRIx8 "%02" PRIx8 ":%02" PRIx8
              "%02" PRIx8 ":%02" PRIx8 "%02" PRIx8 ":%02" PRIx8
              "%02" PRIx8 ":%02" PRIx8 "%02" PRIx8 ":%02" PRIx8
              "%02" PRIx8 "/" "%" PRIu32", " "SP = %" PRIu32 "-%" PRIu32
              ", DP = %" PRIu32 "-%" PRIu32 ", Proto = %"
              PRIu32 " / 0x%" PRIx32 ") => Action ID = %"
              PRIu32 " (entry ptr = %p)\n", rule->priority,
              (rule->key.key.ipv6_5tuple.src_ip[0]),
              (rule->key.key.ipv6_5tuple.src_ip[1]),
              (rule->key.key.ipv6_5tuple.src_ip[2]),
              (rule->key.key.ipv6_5tuple.src_ip[3]),
              (rule->key.key.ipv6_5tuple.src_ip[4]),
              (rule->key.key.ipv6_5tuple.src_ip[5]),
              (rule->key.key.ipv6_5tuple.src_ip[6]),
              (rule->key.key.ipv6_5tuple.src_ip[7]),
              (rule->key.key.ipv6_5tuple.src_ip[8]),
              (rule->key.key.ipv6_5tuple.src_ip[9]),
              (rule->key.key.ipv6_5tuple.src_ip[10]),
              (rule->key.key.ipv6_5tuple.src_ip[11]),
              (rule->key.key.ipv6_5tuple.src_ip[12]),
              (rule->key.key.ipv6_5tuple.src_ip[13]),
              (rule->key.key.ipv6_5tuple.src_ip[14]),
              (rule->key.key.ipv6_5tuple.src_ip[15]),
              rule->key.key.ipv6_5tuple.src_ip_mask,
              (rule->key.key.ipv6_5tuple.dst_ip[0]),
              (rule->key.key.ipv6_5tuple.dst_ip[1]),
              (rule->key.key.ipv6_5tuple.dst_ip[2]),
              (rule->key.key.ipv6_5tuple.dst_ip[3]),
              (rule->key.key.ipv6_5tuple.dst_ip[4]),
              (rule->key.key.ipv6_5tuple.dst_ip[5]),
              (rule->key.key.ipv6_5tuple.dst_ip[6]),
              (rule->key.key.ipv6_5tuple.dst_ip[7]),
              (rule->key.key.ipv6_5tuple.dst_ip[8]),
              (rule->key.key.ipv6_5tuple.dst_ip[9]),
              (rule->key.key.ipv6_5tuple.dst_ip[10]),
              (rule->key.key.ipv6_5tuple.dst_ip[11]),
              (rule->key.key.ipv6_5tuple.dst_ip[12]),
              (rule->key.key.ipv6_5tuple.dst_ip[13]),
              (rule->key.key.ipv6_5tuple.dst_ip[14]),
              (rule->key.key.ipv6_5tuple.dst_ip[15]),
              rule->key.key.ipv6_5tuple.dst_ip_mask,
              rule->key.key.ipv6_5tuple.src_port_from,
              rule->key.key.ipv6_5tuple.src_port_to,
              rule->key.key.ipv6_5tuple.dst_port_from,
              rule->key.key.ipv6_5tuple.dst_port_to,
              rule->key.key.ipv6_5tuple.proto,
              rule->key.key.ipv6_5tuple.proto_mask, rule->action_id,
              rule->entry_ptr);
}

/**
 * Find an VFW rule.
 * This function is used by the add and delete rule functions.
 * Since all updates are done on the standby tables,
 * only search the standby tables.
 * Both IPv4 and IPv6 rules can be searched
 *
 * @param key
 *  A pointer to the rule to be found.
 *
 * @return
 *  - Pointer to the rule found.
 *  - NULL if no rule found.
 */
static struct app_pipeline_vfw_rule *app_pipeline_vfw_rule_find(
              struct pipeline_vfw_key *key)
{
       /*
        * This function is used by the add and delete rule functions.
        * Since all updates are done on the standby tables,
        * only search the standby tables.
        */

       struct app_pipeline_vfw_rule *r;

       if (key->type == PIPELINE_VFW_IPV4_5TUPLE) {
              TAILQ_FOREACH(r, vfw_tailq_rules_ipv4_standby, node)
                  if (memcmp(key,
                            &r->key,
                            sizeof(struct pipeline_vfw_key)) == 0)
                     return r;
       } else {              /* IPV6 */
              TAILQ_FOREACH(r, vfw_tailq_rules_ipv6_standby, node)
                  if (memcmp(key,
                            &r->key,
                            sizeof(struct pipeline_vfw_key)) == 0)
                     return r;
       }

       return NULL;
}


/**
 * Synproxy ON/OFF CLI command.
 *
 * @param app
 *  A pointer to the application parameter.
 * @param pipeline_id
 *  pipeline ID.
 * @param synproxy_flag
 * 0-OFF,1-ON.
 *
 * @return
 *  Response message contains status.
 */

static int
app_pipeline_vfw_synproxy_flag(struct app_params *app,
                              uint32_t pipeline_id, uint8_t synproxy_flag)
{
       struct app_pipeline_acl *p;
       struct pipeline_vfw_synproxy_flag_msg_req *req;
       struct pipeline_vfw_synproxy_flag_msg_rsp *rsp;

       /* Check input arguments */
       if (app == NULL)
              return -1;
       p = app_pipeline_data_fe(app, pipeline_id, &pipeline_vfw);
       if (p == NULL)
              return -1;
       /* Allocate and write request */
       req = app_msg_alloc(app);
       if (req == NULL)
              return -1;
       req->type = PIPELINE_MSG_REQ_CUSTOM;
       req->subtype = PIPELINE_VFW_MSG_REQ_SYNPROXY_FLAGS;
       req->synproxy_flag = synproxy_flag;

       /* Send request and wait for response */
       rsp = app_msg_send_recv(app, pipeline_id, req, MSG_TIMEOUT_DEFAULT);
       if (rsp == NULL) {
              printf("Failed communication with TCP firewall\n");
              return -1;
       }
       /* Read response and write rule */
       if (rsp->status) {
              printf("res status=%d", rsp->status);
              app_msg_free(app, rsp);
              return -1;
       }

       /* Free response */
       app_msg_free(app, rsp);

       return 0;
}

/**
 * Display VFW Rules to the console.
 * Rules from Active and standby tables can be dispayed.
 * Both IPv4 and IPv6 will be displayed.
 *
 * @param app
 *  A pointer to application specific data.
 * @param active_standby_table
 *  Specifies which table to display:
 *    - active_rule_table (0)
 *    - standby_rule_table (1)
 *
 */
static void
app_pipeline_vfw_ls(__attribute__ ((unused)) struct app_params *app,
              uint32_t active_standby_table)
{
       struct app_pipeline_vfw_rule *rule;
       uint32_t n_rules;
       int priority;

       if (active_standby_table == active_rule_table) {
              n_rules = *vfw_n_tailq_rules_ipv4_active;
              if (n_rules > 0)
                     printf("VFW Active Table IPV4 Rules\n");
              for (priority = 0; n_rules; priority++)
                     TAILQ_FOREACH(rule, vfw_tailq_rules_ipv4_active,
                                  node)
                         if (rule->priority == priority) {
                            print_vfw_ipv4_rule(rule);
                            n_rules--;
                     }

              n_rules = *vfw_n_tailq_rules_ipv6_active;
              if (n_rules > 0)
                     printf("VFW Active Table IPV6 Rules\n");
              for (priority = 0; n_rules; priority++)
                     TAILQ_FOREACH(rule, vfw_tailq_rules_ipv6_active,
                                  node)
                         if (rule->priority == priority) {
                            print_vfw_ipv6_rule(rule);
                            n_rules--;
                     }
       } else {
              n_rules = *vfw_n_tailq_rules_ipv4_standby;
              if (n_rules > 0)
                     printf("VFW Standby Table IPV4 Rules\n");
              for (priority = 0; n_rules; priority++)
                     TAILQ_FOREACH(rule, vfw_tailq_rules_ipv4_standby,
                                  node)
                         if (rule->priority == priority) {
                            print_vfw_ipv4_rule(rule);
                            n_rules--;
                     }

              n_rules = *vfw_n_tailq_rules_ipv6_standby;
              if (n_rules > 0)
                     printf("VFW Standby Table IPV6a Rules\n");
              for (priority = 0; n_rules; priority++)
                     TAILQ_FOREACH(rule, vfw_tailq_rules_ipv6_standby,
                                  node)
                         if (rule->priority == priority) {
                            print_vfw_ipv6_rule(rule);
                            n_rules--;
                     }
       }
       printf("\n");
}

/**
 * Initialize VFW pipeline Front End (FE).
 *
 * @param params
 *  A pointer to pipeline parameters
 * @param arg
 *  A pointer to pipeline specific data (not used).
 *
 * @return
 *  - A pointer to the pipeline FE
 *  - NULL if initialization failed.
 */
static void *app_pipeline_vfw_init(struct pipeline_params *params,
                                  __rte_unused void *arg)
{
       struct app_pipeline_vfw *p;
       uint32_t size;

       /* Check input arguments */
       if ((params == NULL) ||
           (params->n_ports_in == 0) || (params->n_ports_out == 0))
              return NULL;

       /* Memory allocation */
       size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct app_pipeline_vfw));
       p = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
       if (p == NULL)
              return NULL;

       /* Initialization */
       p->n_ports_in = params->n_ports_in;
       p->n_ports_out = params->n_ports_out;

       if (!vfw_rule_table_created) {
              /* Only create and init once when first VFW pipeline/thread
               * comes up */

              /* Init tailq tables */
              TAILQ_INIT(&vfw_tailq_rules_ipv4a);
              vfw_n_tailq_rules_ipv4a = 0;
              TAILQ_INIT(&vfw_tailq_rules_ipv4b);
              vfw_n_tailq_rules_ipv4b = 0;
              TAILQ_INIT(&vfw_tailq_rules_ipv6a);
              vfw_n_tailq_rules_ipv6a = 0;
              TAILQ_INIT(&vfw_tailq_rules_ipv6b);
              vfw_n_tailq_rules_ipv6b = 0;
              TAILQ_INIT(&vfw_commands);
              vfw_tailq_rules_ipv4_active = &vfw_tailq_rules_ipv4a;
              vfw_tailq_rules_ipv4_standby = &vfw_tailq_rules_ipv4b;
              vfw_tailq_rules_ipv6_active = &vfw_tailq_rules_ipv6a;
              vfw_tailq_rules_ipv6_standby = &vfw_tailq_rules_ipv6b;
              vfw_n_tailq_rules_ipv4_active = &vfw_n_tailq_rules_ipv4a;
              vfw_n_tailq_rules_ipv4_standby = &vfw_n_tailq_rules_ipv4b;
              vfw_n_tailq_rules_ipv6_active = &vfw_n_tailq_rules_ipv6a;
              vfw_n_tailq_rules_ipv6_standby = &vfw_n_tailq_rules_ipv6b;

              /* Both IPV4 and IPV6 enabled by default */
              vfw_ipv4_enabled = 1;
              vfw_ipv6_enabled = 1;

              printf("VFW FE Init Create Tables vfw_n_rules = %i\n",
                   vfw_n_rules);

              /* Init Action Array and Counter Table */
              action_array_size =
                  RTE_CACHE_LINE_ROUNDUP(sizeof(struct pipeline_action_key) *
                                      action_array_max);
              action_array_a =
                  rte_zmalloc(NULL, action_array_size, RTE_CACHE_LINE_SIZE);
              if (action_array_a == NULL)
                     return NULL;
              action_array_b =
                  rte_zmalloc(NULL, action_array_size, RTE_CACHE_LINE_SIZE);
              if (action_array_b == NULL)
                     return NULL;
              memset(action_array_a, 0, action_array_size);
              memset(action_array_b, 0, action_array_size);
              action_array_active = action_array_a;
              action_array_standby = action_array_b;
              memset(&action_counter_table, 0, sizeof(action_counter_table));

              vfw_rule_table_created = 1;
       }

       if (!rte_vfw_hertz_computed) {
              /* all initialization serialized on core 0,
               * so no need for lock */
              rte_vfw_ticks_in_one_second = rte_get_tsc_hz();
              rte_vfw_hertz_computed = 1;
       }

       return (void *)p;
}

/**
 * Free VFW pipeline resources.
 *
 * @param pipeline
 *  A pointer to the pipeline to delete.
 *
 * @return
 *  0 on success, negative on error.
 */
static int app_pipeline_vfw_free(void *pipeline)
{
       struct app_pipeline_vfw *p = pipeline;

       /* Check input arguments */
       if (p == NULL)
              return -1;

       /* Free resources */
       /* Ignore Klockwork infinite loop issues for all while loops */
       while (!TAILQ_EMPTY(&vfw_tailq_rules_ipv4a)) {
              struct app_pipeline_vfw_rule *rule;

              rule = TAILQ_FIRST(&vfw_tailq_rules_ipv4a);
              TAILQ_REMOVE(&vfw_tailq_rules_ipv4a, rule, node);
              rte_free(rule);
       }
       while (!TAILQ_EMPTY(&vfw_tailq_rules_ipv4b)) {
              struct app_pipeline_vfw_rule *rule;

              rule = TAILQ_FIRST(&vfw_tailq_rules_ipv4b);
              TAILQ_REMOVE(&vfw_tailq_rules_ipv4b, rule, node);
              rte_free(rule);
       }
       while (!TAILQ_EMPTY(&vfw_tailq_rules_ipv6a)) {
              struct app_pipeline_vfw_rule *rule;

              rule = TAILQ_FIRST(&vfw_tailq_rules_ipv6a);
              TAILQ_REMOVE(&vfw_tailq_rules_ipv6a, rule, node);
              rte_free(rule);
       }
       while (!TAILQ_EMPTY(&vfw_tailq_rules_ipv6b)) {
              struct app_pipeline_vfw_rule *rule;

              rule = TAILQ_FIRST(&vfw_tailq_rules_ipv6b);
              TAILQ_REMOVE(&vfw_tailq_rules_ipv6b, rule, node);
              rte_free(rule);
       }
       while (!TAILQ_EMPTY(&vfw_commands)) {
              struct app_pipeline_vfw_rule *command;

              command = TAILQ_FIRST(&vfw_commands);
              TAILQ_REMOVE(&vfw_commands, command, node);
              rte_free(command);
       }
       rte_free(action_array_a);
       rte_free(action_array_b);
       rte_free(p);
       return 0;
}

/**
 * Verify that the VFW rule is valid.
 * Both IPv4 and IPv6 rules
 *
 * @param key
 *  A pointer to the VFW rule to verify.
 *
 * @return
 *  0 on success, negative on error.
 */
static int
app_pipeline_vfw_key_check_and_normalize(struct pipeline_vfw_key *key)
{
       switch (key->type) {
       case PIPELINE_VFW_IPV4_5TUPLE:
              {
                     uint32_t src_ip_depth =
                         key->key.ipv4_5tuple.src_ip_mask;
                     uint32_t dst_ip_depth =
                         key->key.ipv4_5tuple.dst_ip_mask;
                     uint16_t src_port_from =
                         key->key.ipv4_5tuple.src_port_from;
                     uint16_t src_port_to = key->key.ipv4_5tuple.src_port_to;
                     uint16_t dst_port_from =
                         key->key.ipv4_5tuple.dst_port_from;
                     uint16_t dst_port_to = key->key.ipv4_5tuple.dst_port_to;

                     uint32_t src_ip_netmask = 0;
                     uint32_t dst_ip_netmask = 0;

                     if ((src_ip_depth > 32) ||
                         (dst_ip_depth > 32) ||
                         (src_port_from > src_port_to) ||
                         (dst_port_from > dst_port_to))
                            return -1;

                     if (src_ip_depth)
                            src_ip_netmask = (~0) << (32 - src_ip_depth);

                     if (dst_ip_depth)
                            dst_ip_netmask = ((~0) << (32 - dst_ip_depth));

                     key->key.ipv4_5tuple.src_ip &= src_ip_netmask;
                     key->key.ipv4_5tuple.dst_ip &= dst_ip_netmask;

                     return 0;
              }
       case PIPELINE_VFW_IPV6_5TUPLE:
              {
                     uint32_t src_ip_depth =
                         key->key.ipv6_5tuple.src_ip_mask;
                     uint32_t dst_ip_depth =
                         key->key.ipv6_5tuple.dst_ip_mask;
                     uint8_t src_ip_netmask[16];
                     uint8_t dst_ip_netmask[16];
                     int i;

                     convert_prefixlen_to_netmask_ipv6(src_ip_depth,
                                                   src_ip_netmask);
                     convert_prefixlen_to_netmask_ipv6(dst_ip_depth,
                                                   dst_ip_netmask);
                     for (i = 0; i < 16; i++) {
                            key->key.ipv6_5tuple.src_ip[i] &=
                                src_ip_netmask[i];
                            key->key.ipv6_5tuple.dst_ip[i] &=
                                dst_ip_netmask[i];
                     }
                     return 0;
              }

       default:
              return -1;
       }
}

/**
 * Add VFW rule to the VFW rule table.
 * Rules are added standby table.
 * Applyruleset command will activate the change.
 * Both IPv4 and IPv6 rules can be added.
 *
 * @param app
 *  A pointer to the VFW pipeline parameters.
 * @param key
 *  A pointer to the VFW rule to add.
 * @param priority
 *  Priority of the VFW rule.
 * @param port_id
 *  Port ID of the VFW rule.
 * @param action_id
 *  Action ID of the VFW rule. Defined in Action Table.
 *
 * @return
 *  0 on success, negative on error.
 */
int
app_pipeline_vfw_add_rule(struct app_params *app,
                          struct pipeline_vfw_key *key,
                          uint32_t priority,
                          uint32_t port_id, uint32_t action_id)
{
       struct app_pipeline_vfw_rule *rule;
       struct pipeline_vfw_add_msg_rsp *rsp;
       int new_rule, src_field_start, dst_field_start, i;
       uint32_t *ip1, *ip2, *ip3, *ip4, src_mask, dest_mask;
       uint32_t src_ip[IPV6_32BIT_LENGTH], dst_ip[IPV6_32BIT_LENGTH];
       const uint32_t nbu32 = sizeof(uint32_t) * CHAR_BIT;

       struct rte_table_acl_rule_add_params params;
       struct lib_acl_table_entry entry = {
              .head = {
                      .action = RTE_PIPELINE_ACTION_PORT,
                      {.port_id = port_id},
                      },
              .action_id = action_id,
       };

       memset(&params, 0, sizeof(params));

       /* Check input arguments */
       if ((app == NULL) ||
           (key == NULL) || !((key->type == PIPELINE_VFW_IPV4_5TUPLE) ||
                            (key->type == PIPELINE_VFW_IPV6_5TUPLE)))
              return -1;

       if (action_id > action_array_max) {
              printf("Action ID greater than max\n");
              return -1;
       }

       if (app_pipeline_vfw_key_check_and_normalize(key) != 0)
              return -1;

       /* Find existing rule or allocate new rule */
       rule = app_pipeline_vfw_rule_find(key);
       new_rule = (rule == NULL);
       if (rule == NULL) {
              rule = rte_malloc(NULL, sizeof(*rule), RTE_CACHE_LINE_SIZE);

              if (rule == NULL)
                     return -1;
       }

       /* Allocate Response */
       rsp = app_msg_alloc(app);
       if (rsp == NULL) {
              if (new_rule)
                     rte_free(rule);
              return -1;
       }

       switch (key->type) {
       case PIPELINE_VFW_IPV4_5TUPLE:
              params.priority = priority;
              params.field_value[0].value.u8 = key->key.ipv4_5tuple.proto;
              params.field_value[0].mask_range.u8 =
                  key->key.ipv4_5tuple.proto_mask;
              params.field_value[1].value.u32 = key->key.ipv4_5tuple.src_ip;
              params.field_value[1].mask_range.u32 =
                  key->key.ipv4_5tuple.src_ip_mask;
              params.field_value[2].value.u32 = key->key.ipv4_5tuple.dst_ip;
              params.field_value[2].mask_range.u32 =
                  key->key.ipv4_5tuple.dst_ip_mask;
              params.field_value[3].value.u16 =
                  key->key.ipv4_5tuple.src_port_from;
              params.field_value[3].mask_range.u16 =
                  key->key.ipv4_5tuple.src_port_to;
              params.field_value[4].value.u16 =
                  key->key.ipv4_5tuple.dst_port_from;
              params.field_value[4].mask_range.u16 =
                  key->key.ipv4_5tuple.dst_port_to;

              rsp->status =
                  rte_table_acl_ops.f_add(vfw_rule_table_ipv4_standby,
                                       &params,
                                       (struct rte_pipeline_table_entry *)
                                       &entry, &rsp->key_found,
                                       (void **)&rsp->entry_ptr);

              if (rsp->status != 0)
                     printf
                         ("IPV4 Add Rule Command failed key_found: %i\n",
                          rsp->key_found);
              else
                     printf
                         ("IPV4 Add Rule Command success key_found: %i\n",
                          rsp->key_found);

              break;

       case PIPELINE_VFW_IPV6_5TUPLE:
              ip1 = (uint32_t *) (key->key.ipv6_5tuple.src_ip);
              ip2 = ip1 + 1;
              ip3 = ip1 + 2;
              ip4 = ip1 + 3;

              params.priority = priority;
              params.field_value[0].value.u8 = key->key.ipv6_5tuple.proto;
              params.field_value[0].mask_range.u8 =
                  key->key.ipv6_5tuple.proto_mask;

              src_ip[0] = rte_bswap32(*ip1);
              src_ip[1] = rte_bswap32(*ip2);
              src_ip[2] = rte_bswap32(*ip3);
              src_ip[3] = rte_bswap32(*ip4);

              src_mask = key->key.ipv6_5tuple.src_ip_mask;

              src_field_start = 1;
              for (i = 0; i != RTE_DIM(src_ip); i++, src_field_start++) {
                     if (src_mask >= (i + 1) * nbu32)
                            params.field_value[src_field_start].mask_range.
                                u32 = nbu32;
                     else
                            params.field_value[src_field_start].mask_range.
                                u32 =
                                src_mask >
                                (i * nbu32) ? src_mask - (i * 32) : 0;
                     params.field_value[src_field_start].value.u32 =
                         src_ip[i];
              }

              ip1 = (uint32_t *) (key->key.ipv6_5tuple.dst_ip);
              ip2 = ip1 + 1;
              ip3 = ip1 + 2;
              ip4 = ip1 + 3;

              dst_ip[0] = rte_bswap32(*ip1);
              dst_ip[1] = rte_bswap32(*ip2);
              dst_ip[2] = rte_bswap32(*ip3);
              dst_ip[3] = rte_bswap32(*ip4);

              dest_mask = key->key.ipv6_5tuple.dst_ip_mask;

              dst_field_start = 5;
              for (i = 0; i != RTE_DIM(dst_ip); i++, dst_field_start++) {
                     if (dest_mask >= (i + 1) * nbu32)
                            params.field_value[dst_field_start].mask_range.
                                u32 = nbu32;
                     else
                            params.field_value[dst_field_start].mask_range.
                                u32 =
                                dest_mask >
                                (i * nbu32) ? dest_mask - (i * 32) : 0;
                     params.field_value[dst_field_start].value.u32 =
                         dst_ip[i];
              }

              params.field_value[9].value.u16 =
                  key->key.ipv6_5tuple.src_port_from;
              params.field_value[9].mask_range.u16 =
                  key->key.ipv6_5tuple.src_port_to;
              params.field_value[10].value.u16 =
                  key->key.ipv6_5tuple.dst_port_from;
              params.field_value[10].mask_range.u16 =
                  key->key.ipv6_5tuple.dst_port_to;

              rsp->status =
                  rte_table_acl_ops.f_add(vfw_rule_table_ipv6_standby,
                                       &params,
                                       (struct rte_pipeline_table_entry *)
                                       &entry, &rsp->key_found,
                                       (void **)&rsp->entry_ptr);

              if (rsp->status != 0)
                     printf
                         ("IPV6 Add Rule Command failed key_found: %i\n",
                          rsp->key_found);
              else
                     printf
                         ("IPV6 Add Rule Command success key_found: %i\n",
                          rsp->key_found);

              break;

       default:
              /* Error */
              app_msg_free(app, rsp);
              if (new_rule)
                     rte_free(rule);
              return -1;
       }

       /* Read response and write rule */
       if (rsp->status ||
           (rsp->entry_ptr == NULL) ||
           ((new_rule == 0) && (rsp->key_found == 0)) ||
           ((new_rule == 1) && (rsp->key_found == 1))) {
              app_msg_free(app, rsp);
              if (new_rule)
                     rte_free(rule);
              return -1;
       }

       memcpy(&rule->key, key, sizeof(*key));
       rule->priority = priority;
       rule->port_id = port_id;
       rule->action_id = action_id;
       rule->entry_ptr = rsp->entry_ptr;

       /* Commit rule */
       if (new_rule) {
              if (key->type == PIPELINE_VFW_IPV4_5TUPLE) {
                     TAILQ_INSERT_TAIL(vfw_tailq_rules_ipv4_standby, rule,
                                     node);
                     (*vfw_n_tailq_rules_ipv4_standby)++;
              } else {       /* IPV6 */
                     TAILQ_INSERT_TAIL(vfw_tailq_rules_ipv6_standby, rule,
                                     node);
                     (*vfw_n_tailq_rules_ipv6_standby)++;
              }
       }

       if (key->type == PIPELINE_VFW_IPV4_5TUPLE)
              print_vfw_ipv4_rule(rule);
       else
              print_vfw_ipv6_rule(rule);

       /* Free response */
       app_msg_free(app, rsp);

       return 0;
}

/**
 * Delete VFW rule from the VFW rule table.
 * Rules deleted from standby tables.
 * Applyruleset command will activate the change.
 * Both IPv4 and IPv6 rules can be deleted.
 *
 * @param app
 *  A pointer to the VFW pipeline parameters.
 * @param key
 *  A pointer to the VFW rule to delete.
 *
 * @return
 *  0 on success, negative on error.
 */
int
app_pipeline_vfw_delete_rule(struct app_params *app,
                            struct pipeline_vfw_key *key)
{
       struct app_pipeline_vfw_rule *rule;
       int status, key_found;
       int  src_field_start, dst_field_start, i;
       uint32_t *ip1, *ip2, *ip3, *ip4, src_mask, dest_mask;
       uint32_t src_ip[IPV6_32BIT_LENGTH], dst_ip[IPV6_32BIT_LENGTH];
       const uint32_t nbu32 = sizeof(uint32_t) * CHAR_BIT;


       struct rte_table_acl_rule_delete_params params;

       memset(&params, 0, sizeof(params));

       /* Check input arguments */
       if ((app == NULL) ||
           (key == NULL) || !((key->type == PIPELINE_VFW_IPV4_5TUPLE) ||
                            (key->type == PIPELINE_VFW_IPV6_5TUPLE)))
              return -1;

       if (app_pipeline_vfw_key_check_and_normalize(key) != 0)
              return -1;

       /* Find rule */
       rule = app_pipeline_vfw_rule_find(key);
       if (rule == NULL) {
              printf("VFW Delete Rule - Rule does not exist\n");
              return 0;
       }

       switch (key->type) {
       case PIPELINE_VFW_IPV4_5TUPLE:
              params.field_value[0].value.u8 = key->key.ipv4_5tuple.proto;
              params.field_value[0].mask_range.u8 =
                  key->key.ipv4_5tuple.proto_mask;
              params.field_value[1].value.u32 = key->key.ipv4_5tuple.src_ip;
              params.field_value[1].mask_range.u32 =
                  key->key.ipv4_5tuple.src_ip_mask;
              params.field_value[2].value.u32 = key->key.ipv4_5tuple.dst_ip;
              params.field_value[2].mask_range.u32 =
                  key->key.ipv4_5tuple.dst_ip_mask;
              params.field_value[3].value.u16 =
                  key->key.ipv4_5tuple.src_port_from;
              params.field_value[3].mask_range.u16 =
                  key->key.ipv4_5tuple.src_port_to;
              params.field_value[4].value.u16 =
                  key->key.ipv4_5tuple.dst_port_from;
              params.field_value[4].mask_range.u16 =
                  key->key.ipv4_5tuple.dst_port_to;

              status =
                  rte_table_acl_ops.f_delete(vfw_rule_table_ipv4_standby,
                                          &params, &key_found, NULL);

              if (status != 0)
                     printf
                         ("IPV4 Del Rule Command failed key_found: %i\n",
                          key_found);
              else
                     printf
                         ("IPV4 Del Rule Command success key_found: %i\n",
                          key_found);

              break;

       case PIPELINE_VFW_IPV6_5TUPLE:
              ip1 = (uint32_t *) (key->key.ipv6_5tuple.src_ip);
              ip2 = ip1 + 1;
              ip3 = ip1 + 2;
              ip4 = ip1 + 3;

              params.field_value[0].value.u8 = key->key.ipv6_5tuple.proto;
              params.field_value[0].mask_range.u8 =
                  key->key.ipv6_5tuple.proto_mask;

              src_ip[0] = rte_bswap32(*ip1);
              src_ip[1] = rte_bswap32(*ip2);
              src_ip[2] = rte_bswap32(*ip3);
              src_ip[3] = rte_bswap32(*ip4);

              src_mask = key->key.ipv6_5tuple.src_ip_mask;

              src_field_start = 1;
              for (i = 0; i != RTE_DIM(src_ip); i++, src_field_start++) {
                     if (src_mask >= (i + 1) * nbu32)
                            params.field_value[src_field_start].mask_range.
                                u32 = nbu32;
                     else
                            params.field_value[src_field_start].mask_range.
                                u32 =
                                src_mask >
                                (i * nbu32) ? src_mask - (i * 32) : 0;
                     params.field_value[src_field_start].value.u32 =
                         src_ip[i];
              }

              ip1 = (uint32_t *) (key->key.ipv6_5tuple.dst_ip);
              ip2 = ip1 + 1;
              ip3 = ip1 + 2;
              ip4 = ip1 + 3;

              dst_ip[0] = rte_bswap32(*ip1);
              dst_ip[1] = rte_bswap32(*ip2);
              dst_ip[2] = rte_bswap32(*ip3);
              dst_ip[3] = rte_bswap32(*ip4);

              dest_mask = key->key.ipv6_5tuple.dst_ip_mask;

              dst_field_start = 5;
              for (i = 0; i != RTE_DIM(dst_ip); i++, dst_field_start++) {
                     if (dest_mask >= (i + 1) * nbu32)
                            params.field_value[dst_field_start].mask_range.
                                u32 = nbu32;
                     else
                            params.field_value[dst_field_start].mask_range.
                                u32 =
                                dest_mask >
                                (i * nbu32) ? dest_mask - (i * 32) : 0;
                     params.field_value[dst_field_start].value.u32 =
                         dst_ip[i];
              }

              params.field_value[9].value.u16 =
                  key->key.ipv6_5tuple.src_port_from;
              params.field_value[9].mask_range.u16 =
                  key->key.ipv6_5tuple.src_port_to;
              params.field_value[10].value.u16 =
                  key->key.ipv6_5tuple.dst_port_from;
              params.field_value[10].mask_range.u16 =
                  key->key.ipv6_5tuple.dst_port_to;


              status =
                  rte_table_acl_ops.f_delete(vfw_rule_table_ipv6_standby,
                                          &params, &key_found, NULL);

              if (status != 0)
                     printf("IPV6 Del Rule Command failed key_found: %i\n",
                          key_found);
              else
                     printf("IPV6 Del Rule Command success key_found: %i\n",
                          key_found);

              break;

       default:
              /* Error */
              return -1;
       }

       /* Read response */
       if (status || !key_found)
              return -1;

       /* Remove rule */
       if (key->type == PIPELINE_VFW_IPV4_5TUPLE) {
              TAILQ_REMOVE(vfw_tailq_rules_ipv4_standby, rule, node);
              (*vfw_n_tailq_rules_ipv4_standby)--;
       } else {              /* IPV6 */
              TAILQ_REMOVE(vfw_tailq_rules_ipv6_standby, rule, node);
              (*vfw_n_tailq_rules_ipv6_standby)--;
       }

       rte_free(rule);

       return 0;
}

/**
 * Clear all VFW rules from the VFW rule table.
 * Rules cleared from standby tables.
 * Applyruleset command will activate the change.
 * Both IPv4 and IPv6 rules will be cleared.
 *
 * @param app
 *  A pointer to the VFW pipeline parameters.
 *
 * @return
 *  0 on success, negative on error.
 */
int app_pipeline_vfw_clearrules(struct app_params *app)
{
       struct app_pipeline_vfw_rule *rule;
       struct app_pipeline_vfw_rule *command;
       uint32_t n_rules;

       int priority;

       /* Check input arguments */
       if (app == NULL)
              return -1;

       n_rules = *vfw_n_tailq_rules_ipv4_standby;
       for (priority = 0; n_rules; priority++) {
              TAILQ_FOREACH(rule, vfw_tailq_rules_ipv4_standby, node) {
                     if (rule->priority == priority) {
                            struct pipeline_vfw_key key = rule->key;

                            /* Store command to update standby tables
                             * after switchover */
                            command =
                                rte_malloc(NULL, sizeof(*command),
                                          RTE_CACHE_LINE_SIZE);
                            if (command == NULL) {
                                   printf("Cannot allocation command\n");
                                   return -1;
                            }
                            memset(command, 0,
                                   sizeof(struct app_pipeline_vfw_rule));
                            memcpy(&command->key, &key, sizeof(key));
                            command->command = vfw_delete_command;
                            TAILQ_INSERT_TAIL(&vfw_commands, command,
                                            node);

                            /* Delete rule */
                            app_pipeline_vfw_delete_rule(app, &key);
                            n_rules--;
                     }
              }
       }

       n_rules = *vfw_n_tailq_rules_ipv6_standby;
       for (priority = 0; n_rules; priority++) {
              TAILQ_FOREACH(rule, vfw_tailq_rules_ipv6_standby, node) {
                     if (rule->priority == priority) {
                            struct pipeline_vfw_key key = rule->key;

                            /* Store command to update standby tables
                             * after switchover */
                            command =
                                rte_malloc(NULL, sizeof(*command),
                                          RTE_CACHE_LINE_SIZE);
                            if (command == NULL) {
                                   printf("Cannot allocation command\n");
                                   return -1;
                            }
                            memset(command, 0,
                                   sizeof(struct app_pipeline_vfw_rule));
                            memcpy(&command->key, &key, sizeof(key));
                            command->command = vfw_delete_command;
                            TAILQ_INSERT_TAIL(&vfw_commands, command,
                                            node);

                            /* Delete rule */
                            app_pipeline_vfw_delete_rule(app, &key);
                            n_rules--;
                     }
              }
       }

       /* Clear Action Array */
       memset(action_array_standby, 0, action_array_size);

       return 0;
}

/*
 * loadrules
 */

/**
 * Open file and process all commands in the file.
 *
 * @param ctx
 *  A pointer to the CLI context
 * @param file_name
 *  A pointer to the file to process.
 *
 */
static void app_loadrules_file(cmdline_parse_ctx_t *ctx, const char *file_name)
{
       struct cmdline *file_cl;
       int fd;

       fd = open(file_name, O_RDONLY);
       if (fd < 0) {
              printf("Cannot open file \"%s\"\n", file_name);
              return;
       }

       file_cl = cmdline_new(ctx, "", fd, 1);
       cmdline_interact(file_cl);
       close(fd);
}

struct cmd_loadrules_file_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t vfw_string;
       cmdline_fixed_string_t loadrules_string;
       char file_name[APP_FILE_NAME_SIZE];
};

/**
 * Parse load rules command.
 * Verify that file exists.
 * Clear existing rules and action.
 * Process commands in command file.
 *
 * @param parsed_result
 *  A pointer to the CLI command parsed result
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data.
 *
 * @return
 *  0 on success, negative on error.
 *
 */
static void
cmd_loadrules_parsed(void *parsed_result, struct cmdline *cl, void *data)
{
       struct cmd_loadrules_file_result *params = parsed_result;
       struct app_params *app = data;
       int status;
       int fd;

       /* Make sure the file exists before clearing rules and actions */
       fd = open(params->file_name, O_RDONLY);
       if (fd < 0) {
              printf("Cannot open file \"%s\"\n", params->file_name);
              return;
       }
       close(fd);

       /* Clear all rules and actions */
       status = app_pipeline_vfw_clearrules(app);

       if (status != 0) {
              printf("Command clearrules failed\n");
              return;
       }

       /* Process commands in script file */
       app_loadrules_file(cl->ctx, params->file_name);
}

cmdline_parse_token_string_t cmd_loadrules_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_loadrules_file_result,
                      p_string, "p");

cmdline_parse_token_string_t cmd_loadrules_vfw_string =
TOKEN_STRING_INITIALIZER(struct cmd_loadrules_file_result,
                      vfw_string, "vfw");

cmdline_parse_token_string_t cmd_loadrules_loadrules_string =
TOKEN_STRING_INITIALIZER(struct cmd_loadrules_file_result, loadrules_string,
                      "loadrules");

cmdline_parse_token_string_t cmd_loadrules_file_name =
TOKEN_STRING_INITIALIZER(struct cmd_loadrules_file_result, file_name, NULL);

cmdline_parse_inst_t cmd_loadrules = {
       .f = cmd_loadrules_parsed,
       .data = NULL,
       .help_str = "VFW Load Rules",
       .tokens = {
                 (void *)&cmd_loadrules_p_string,
                 (void *)&cmd_loadrules_vfw_string,
                 (void *)&cmd_loadrules_loadrules_string,
                 (void *)&cmd_loadrules_file_name,
                 NULL,
                 },
};

/**
 * Add Action to the Action table.
 * Actions are added standby table.
 * Applyruleset command will activate the change.
 *
 * @param app
 *  A pointer to the VFW pipeline parameters.
 * @param key
 *  A pointer to the Action to add.
 *
 * @return
 *  0 on success, negative on error.
 */
int
app_pipeline_action_add(__attribute__ ((unused)) struct app_params *app,
              struct pipeline_action_key *key)
{

       /*
        * This function will update the action IDs on the standby table.
        * Activating the changes is done with the applyruleset command.
        */

       uint32_t action_bitmap = key->action_bitmap;
       uint32_t action_id = key->action_id;

       if (action_id >= action_array_max) {
              if (VFW_DEBUG)
                     printf("Action id: %u out of range\n", action_id);
              return -1;
       }

       action_array_standby[action_id].action_id = action_id;

       if (VFW_DEBUG)
              printf("Adding action id: %u Type: ", action_id);
       if (action_bitmap == lib_acl_action_packet_accept) {
              action_array_standby[action_id].action_bitmap |=
                  lib_acl_action_packet_accept;
              if (VFW_DEBUG)
                     printf("Accept\n");
       }
       if (action_bitmap == lib_acl_action_packet_drop) {
              action_array_standby[action_id].action_bitmap |=
                  lib_acl_action_packet_drop;
              if (VFW_DEBUG)
                     printf("Drop\n");
       }
       if (action_bitmap == lib_acl_action_nat) {
              action_array_standby[action_id].action_bitmap |=
                  lib_acl_action_nat;
              action_array_standby[action_id].nat_port = key->nat_port;
              if (VFW_DEBUG)
                     printf("NAT  Port ID: %u\n", key->nat_port);
       }
       if (action_bitmap == lib_acl_action_fwd) {
              action_array_standby[action_id].action_bitmap |=
                  lib_acl_action_fwd;
              action_array_standby[action_id].fwd_port = key->fwd_port;
              if (VFW_DEBUG)
                     printf("FWD  Port ID: %u\n", key->fwd_port);
       }
       if (action_bitmap == lib_acl_action_count) {
              action_array_standby[action_id].action_bitmap |=
                  lib_acl_action_count;
              if (VFW_DEBUG)
                     printf("Count\n");
       }
       if (action_bitmap == lib_acl_action_conntrack) {
              action_array_standby[action_id].action_bitmap |=
                  lib_acl_action_conntrack;
              if (VFW_DEBUG)
                     printf("Conntrack\n");
       }
       if (action_bitmap == lib_acl_action_connexist) {
              action_array_standby[action_id].action_bitmap |=
                  lib_acl_action_connexist;
              action_array_standby[action_id].private_public =
                  key->private_public;
              if (VFW_DEBUG)
                     printf("Conntrack   prvpub: %i\n", key->private_public);
       }
       if (action_bitmap == lib_acl_action_dscp) {
              action_array_standby[action_id].action_bitmap |=
                  lib_acl_action_dscp;
              action_array_standby[action_id].dscp_priority =
                  key->dscp_priority;
              if (VFW_DEBUG)
                     printf("DSCP  Priority: %u\n", key->dscp_priority);
       }

       if (VFW_DEBUG)
              printf("action_bitmap: %" PRIu32 "\n",
                     action_array_standby[action_id].action_bitmap);

       return 0;
}

/**
 * Delete Action from the Action table.
 * Actions are deleted from the standby table.
 * Applyruleset command will activate the change.
 *
 * @param app
 *  A pointer to the VFW pipeline parameters.
 * @param key
 *  A pointer to the Action to delete.
 *
 * @return
 *  0 on success, negative on error.
 */
int
app_pipeline_action_delete(__attribute__ ((unused)) struct app_params *app,
                        struct pipeline_action_key *key)
{
       /*
        * This function will update the action IDs on the standby table.
        * Activating the changes is done with the applyruleset command.
        */

       uint32_t action_bitmap = key->action_bitmap;
       uint32_t action_id = key->action_id;

       if (action_id >= action_array_max) {
              if (VFW_DEBUG)
                     printf("Action id: %u out of range\n", action_id);
              return -1;
       }

       if (action_array_standby[action_id].action_bitmap & action_bitmap)
              action_array_standby[action_id].action_bitmap &= ~action_bitmap;
       else
              printf("VFW Action Delete - Action not set\n");

       if (VFW_DEBUG) {
              printf("Deleting action id: %u Type: ", key->action_id);
              if (action_bitmap == lib_acl_action_packet_accept)
                     printf("Accept\n");
              if (action_bitmap == lib_acl_action_packet_drop)
                     printf("Drop\n");
              if (action_bitmap == lib_acl_action_nat)
                     printf("NAT\n");
              if (action_bitmap == lib_acl_action_fwd)
                     printf("FWD\n");
              if (action_bitmap == lib_acl_action_count)
                     printf("Count\n");
              if (action_bitmap == lib_acl_action_conntrack)
                     printf("Conntrack\n");
              if (action_bitmap == lib_acl_action_connexist)
                     printf("Connexist\n");
              if (action_bitmap == lib_acl_action_dscp)
                     printf("DSCP\n");

              printf("action_bitmap: %" PRIu32 "\n",
                     action_array_standby[action_id].action_bitmap);
       }

       return 0;
}

/*
 * p vfw add
 */

/**
 * A structure defining the VFW add rule command.
 */
struct cmd_vfw_add_ip_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t vfw_string;
       cmdline_fixed_string_t add_string;
       int32_t priority;
       cmdline_ipaddr_t src_ip;
       uint32_t src_ip_mask;
       cmdline_ipaddr_t dst_ip;
       uint32_t dst_ip_mask;
       uint16_t src_port_from;
       uint16_t src_port_to;
       uint16_t dst_port_from;
       uint16_t dst_port_to;
       uint8_t proto;
       uint8_t proto_mask;
       uint8_t port_id;
       uint32_t action_id;
};

/**
 * Parse VFW add rule CLI command.
 * Add rule to standby table.
 * Store command to update standby table
 * after applyruleset command is invoked.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_vfw_add_ip_parsed(void *parsed_result, __attribute__ ((unused))
                      struct cmdline *cl, void *data)
{
       struct cmd_vfw_add_ip_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_vfw_key key;
       struct app_pipeline_vfw_rule *command;
       int status;

       memset(&key, 0, sizeof(struct pipeline_vfw_key));

       if (params->src_ip.family == AF_INET) {
              key.type = PIPELINE_VFW_IPV4_5TUPLE;
              key.key.ipv4_5tuple.src_ip = rte_bswap32((uint32_t)
                                                  params->src_ip.addr.
                                                  ipv4.s_addr);
              key.key.ipv4_5tuple.src_ip_mask = params->src_ip_mask;
              key.key.ipv4_5tuple.dst_ip = rte_bswap32((uint32_t)
                                                  params->dst_ip.addr.
                                                  ipv4.s_addr);
              key.key.ipv4_5tuple.dst_ip_mask = params->dst_ip_mask;
              key.key.ipv4_5tuple.src_port_from = params->src_port_from;
              key.key.ipv4_5tuple.src_port_to = params->src_port_to;
              key.key.ipv4_5tuple.dst_port_from = params->dst_port_from;
              key.key.ipv4_5tuple.dst_port_to = params->dst_port_to;
              key.key.ipv4_5tuple.proto = params->proto;
              key.key.ipv4_5tuple.proto_mask = params->proto_mask;
       }
       if (params->src_ip.family == AF_INET6) {
              if (VFW_DEBUG)
                     printf("entered IPV6");
              key.type = PIPELINE_VFW_IPV6_5TUPLE;
              memcpy(key.key.ipv6_5tuple.src_ip,
                     params->src_ip.addr.ipv6.s6_addr,
                     sizeof(params->src_ip.addr.ipv6.s6_addr));
              key.key.ipv6_5tuple.src_ip_mask = params->src_ip_mask;
              memcpy(key.key.ipv6_5tuple.dst_ip,
                     params->dst_ip.addr.ipv6.s6_addr,
                     sizeof(params->src_ip.addr.ipv6.s6_addr));
              key.key.ipv6_5tuple.dst_ip_mask = params->dst_ip_mask;
              key.key.ipv6_5tuple.src_port_from = params->src_port_from;
              key.key.ipv6_5tuple.src_port_to = params->src_port_to;
              key.key.ipv6_5tuple.dst_port_from = params->dst_port_from;
              key.key.ipv6_5tuple.dst_port_to = params->dst_port_to;
              key.key.ipv6_5tuple.proto = params->proto;
              key.key.ipv6_5tuple.proto_mask = params->proto_mask;
       }
       /* Set to 1 as default, overwritten by Action FWD/NAT Port */
       status = app_pipeline_vfw_add_rule(app, &key, params->priority, 1,
                                         params->action_id);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }

       /* Store command to update standby tables after switchover */
       command = rte_malloc(NULL, sizeof(*command), RTE_CACHE_LINE_SIZE);
       if (command == NULL) {
              printf("Cannot allocation command\n");
              return;
       }
       memset(command, 0, sizeof(struct app_pipeline_vfw_rule));
       memcpy(&command->key, &key, sizeof(key));
       command->priority = params->priority;
       command->port_id = params->port_id;
       command->action_id = params->action_id;
       command->command = vfw_add_command;
       TAILQ_INSERT_TAIL(&vfw_commands, command, node);
}

cmdline_parse_token_string_t cmd_vfw_add_ip_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_add_ip_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_vfw_add_ip_acl_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_add_ip_result,
                      vfw_string, "vfw");

cmdline_parse_token_string_t cmd_vfw_add_ip_add_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_add_ip_result,
                      add_string, "add");

cmdline_parse_token_num_t cmd_vfw_add_ip_priority =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_add_ip_result, priority,
                    INT32);

cmdline_parse_token_ipaddr_t cmd_vfw_add_ip_src_ip =
TOKEN_IPADDR_INITIALIZER(struct cmd_vfw_add_ip_result, src_ip);

cmdline_parse_token_num_t cmd_vfw_add_ip_src_ip_mask =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_add_ip_result, src_ip_mask,
                    UINT32);

cmdline_parse_token_ipaddr_t cmd_vfw_add_ip_dst_ip =
TOKEN_IPADDR_INITIALIZER(struct cmd_vfw_add_ip_result, dst_ip);

cmdline_parse_token_num_t cmd_vfw_add_ip_dst_ip_mask =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_add_ip_result, dst_ip_mask,
                    UINT32);

cmdline_parse_token_num_t cmd_vfw_add_ip_src_port_from =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_add_ip_result,
                    src_port_from, UINT16);

cmdline_parse_token_num_t cmd_vfw_add_ip_src_port_to =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_add_ip_result,
                    src_port_to, UINT16);

cmdline_parse_token_num_t cmd_vfw_add_ip_dst_port_from =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_add_ip_result,
                    dst_port_from, UINT16);

cmdline_parse_token_num_t cmd_vfw_add_ip_dst_port_to =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_add_ip_result,
                    dst_port_to, UINT16);

cmdline_parse_token_num_t cmd_vfw_add_ip_proto =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_add_ip_result,
                    proto, UINT8);

cmdline_parse_token_num_t cmd_vfw_add_ip_proto_mask =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_add_ip_result,
                    proto_mask, UINT8);

cmdline_parse_token_num_t cmd_vfw_add_ip_port_id =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_add_ip_result,
                    port_id, UINT8);

cmdline_parse_token_num_t cmd_vfw_add_ip_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_add_ip_result,
                    action_id, UINT32);

cmdline_parse_inst_t cmd_vfw_add_ip = {
       .f = cmd_vfw_add_ip_parsed,
       .data = NULL,
       .help_str = "VFW rule add",
       .tokens = {
                 (void *)&cmd_vfw_add_ip_p_string,
                 (void *)&cmd_vfw_add_ip_acl_string,
                 (void *)&cmd_vfw_add_ip_add_string,
                 (void *)&cmd_vfw_add_ip_priority,
                 (void *)&cmd_vfw_add_ip_src_ip,
                 (void *)&cmd_vfw_add_ip_src_ip_mask,
                 (void *)&cmd_vfw_add_ip_dst_ip,
                 (void *)&cmd_vfw_add_ip_dst_ip_mask,
                 (void *)&cmd_vfw_add_ip_src_port_from,
                 (void *)&cmd_vfw_add_ip_src_port_to,
                 (void *)&cmd_vfw_add_ip_dst_port_from,
                 (void *)&cmd_vfw_add_ip_dst_port_to,
                 (void *)&cmd_vfw_add_ip_proto,
                 (void *)&cmd_vfw_add_ip_proto_mask,
                 (void *)&cmd_vfw_add_ip_action_id,
                 NULL,
                 },
};

/*
 * p vfw del
 */

/**
 * A structure defining the VFW delete rule command.
 */
struct cmd_vfw_del_ip_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t vfw_string;
       cmdline_fixed_string_t del_string;
       cmdline_ipaddr_t src_ip;
       uint32_t src_ip_mask;
       cmdline_ipaddr_t dst_ip;
       uint32_t dst_ip_mask;
       uint16_t src_port_from;
       uint16_t src_port_to;
       uint16_t dst_port_from;
       uint16_t dst_port_to;
       uint8_t proto;
       uint8_t proto_mask;
};

/**
 * Parse VFW delete rule CLI command.
 * Delete rule from standby table.
 * Store command to update standby table
 * after applyruleset command is invoked.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_vfw_del_ip_parsed(void *parsed_result, __attribute__ ((unused))
                      struct cmdline *cl, void *data)
{
       struct cmd_vfw_del_ip_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_vfw_key key;
       struct app_pipeline_vfw_rule *command;
       int status;

       memset(&key, 0, sizeof(struct pipeline_vfw_key));

       if (params->src_ip.family == AF_INET) {
              key.type = PIPELINE_VFW_IPV4_5TUPLE;
              key.key.ipv4_5tuple.src_ip = rte_bswap32((uint32_t)
                                                  params->src_ip.addr.
                                                  ipv4.s_addr);
              key.key.ipv4_5tuple.src_ip_mask = params->src_ip_mask;
              key.key.ipv4_5tuple.dst_ip = rte_bswap32((uint32_t)
                                                  params->dst_ip.addr.
                                                  ipv4.s_addr);
              key.key.ipv4_5tuple.dst_ip_mask = params->dst_ip_mask;
              key.key.ipv4_5tuple.src_port_from = params->src_port_from;
              key.key.ipv4_5tuple.src_port_to = params->src_port_to;
              key.key.ipv4_5tuple.dst_port_from = params->dst_port_from;
              key.key.ipv4_5tuple.dst_port_to = params->dst_port_to;
              key.key.ipv4_5tuple.proto = params->proto;
              key.key.ipv4_5tuple.proto_mask = params->proto_mask;
       }
       if (params->src_ip.family == AF_INET6) {
              key.type = PIPELINE_VFW_IPV6_5TUPLE;
              memcpy(key.key.ipv6_5tuple.src_ip,
                     params->src_ip.addr.ipv6.s6_addr,
                     sizeof(params->src_ip.addr.ipv6.s6_addr));
              key.key.ipv6_5tuple.src_ip_mask = params->src_ip_mask;
              memcpy(key.key.ipv6_5tuple.dst_ip,
                     params->dst_ip.addr.ipv6.s6_addr,
                     sizeof(params->dst_ip.addr.ipv6.s6_addr));
              key.key.ipv6_5tuple.dst_ip_mask = params->dst_ip_mask;
              key.key.ipv6_5tuple.src_port_from = params->src_port_from;
              key.key.ipv6_5tuple.src_port_to = params->src_port_to;
              key.key.ipv6_5tuple.dst_port_from = params->dst_port_from;
              key.key.ipv6_5tuple.dst_port_to = params->dst_port_to;
              key.key.ipv6_5tuple.proto = params->proto;
              key.key.ipv6_5tuple.proto_mask = params->proto_mask;
       }

       status = app_pipeline_vfw_delete_rule(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }

       /* Store command to update standby tables after switchover */
       command = rte_malloc(NULL, sizeof(*command), RTE_CACHE_LINE_SIZE);
       if (command == NULL) {
              printf("Cannot allocation command\n");
              return;
       }
       memset(command, 0, sizeof(struct app_pipeline_vfw_rule));
       memcpy(&command->key, &key, sizeof(key));
       command->command = vfw_delete_command;
       TAILQ_INSERT_TAIL(&vfw_commands, command, node);
}

cmdline_parse_token_string_t cmd_vfw_del_ip_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_del_ip_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_vfw_del_ip_acl_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_del_ip_result,
                      vfw_string, "vfw");

cmdline_parse_token_string_t cmd_vfw_del_ip_del_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_del_ip_result,
                      del_string, "del");

cmdline_parse_token_ipaddr_t cmd_vfw_del_ip_src_ip =
TOKEN_IPADDR_INITIALIZER(struct cmd_vfw_del_ip_result, src_ip);

cmdline_parse_token_num_t cmd_vfw_del_ip_src_ip_mask =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_del_ip_result, src_ip_mask,
                    UINT32);

cmdline_parse_token_ipaddr_t cmd_vfw_del_ip_dst_ip =
TOKEN_IPADDR_INITIALIZER(struct cmd_vfw_del_ip_result, dst_ip);

cmdline_parse_token_num_t cmd_vfw_del_ip_dst_ip_mask =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_del_ip_result, dst_ip_mask,
                    UINT32);

cmdline_parse_token_num_t cmd_vfw_del_ip_src_port_from =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_del_ip_result,
                    src_port_from, UINT16);

cmdline_parse_token_num_t cmd_vfw_del_ip_src_port_to =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_del_ip_result, src_port_to,
                    UINT16);

cmdline_parse_token_num_t cmd_vfw_del_ip_dst_port_from =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_del_ip_result,
                    dst_port_from, UINT16);

cmdline_parse_token_num_t cmd_vfw_del_ip_dst_port_to =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_del_ip_result,
                    dst_port_to, UINT16);

cmdline_parse_token_num_t cmd_vfw_del_ip_proto =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_del_ip_result,
                    proto, UINT8);

cmdline_parse_token_num_t cmd_vfw_del_ip_proto_mask =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_del_ip_result, proto_mask,
                    UINT8);

cmdline_parse_inst_t cmd_vfw_del_ip = {
       .f = cmd_vfw_del_ip_parsed,
       .data = NULL,
       .help_str = "VFW rule delete",
       .tokens = {
                 (void *)&cmd_vfw_del_ip_p_string,
                 (void *)&cmd_vfw_del_ip_acl_string,
                 (void *)&cmd_vfw_del_ip_del_string,
                 (void *)&cmd_vfw_del_ip_src_ip,
                 (void *)&cmd_vfw_del_ip_src_ip_mask,
                 (void *)&cmd_vfw_del_ip_dst_ip,
                 (void *)&cmd_vfw_del_ip_dst_ip_mask,
                 (void *)&cmd_vfw_del_ip_src_port_from,
                 (void *)&cmd_vfw_del_ip_src_port_to,
                 (void *)&cmd_vfw_del_ip_dst_port_from,
                 (void *)&cmd_vfw_del_ip_dst_port_to,
                 (void *)&cmd_vfw_del_ip_proto,
                 (void *)&cmd_vfw_del_ip_proto_mask,
                 NULL,
                 },
};

/*
 * p vfw stats
 */

/**
 * A structure defining the VFW stats command.
 */
struct cmd_vfw_stats_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t vfw_string;
       cmdline_fixed_string_t stats_string;
};

/**
 * Display VFW and Connection Tracker stats to the console.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_vfw_stats_parsed(__attribute__ ((unused)) void *parsed_result,
              __attribute__ ((unused)) struct cmdline *cl,
              __attribute__ ((unused)) void *data)
{
       int i, j;
       struct rte_VFW_counter_block vfw_counter_sums;
       struct rte_CT_counter_block ct_counter_sums;
       struct rte_CT_counter_block *ct_counters;
       struct action_counter_block action_counter_sum[action_array_max];
       uint64_t sum_pkts_drop_fw = 0;

       memset(&vfw_counter_sums, 0, sizeof(vfw_counter_sums));
       memset(&ct_counter_sums, 0, sizeof(ct_counter_sums));
       memset(&action_counter_sum, 0, sizeof(action_counter_sum));

       printf("VFW Stats\n");
       for (i = 0; i <= rte_VFW_hi_counter_block_in_use; i++) {
              struct rte_VFW_counter_block *vfw_ctrs =
                  &rte_vfw_counter_table[i];
              ct_counters = rte_vfw_counter_table[i].ct_counters;

              uint64_t average_internal_time =
                  vfw_ctrs->time_measurements ==
                  0 ? 0 : vfw_ctrs->internal_time_sum /
                  vfw_ctrs->time_measurements;
              uint64_t average_external_time =
                  vfw_ctrs->time_measurements ==
                  0 ? 0 : vfw_ctrs->external_time_sum /
                  vfw_ctrs->time_measurements;
              uint64_t average_pkts_in_batch =
                  vfw_ctrs->num_pkts_measurements ==
                  0 ? 0 : vfw_ctrs->num_batch_pkts_sum /
                  vfw_ctrs->num_pkts_measurements;
              uint64_t pkts_drop_fw = vfw_ctrs->pkts_drop_ttl +
                                   vfw_ctrs->pkts_drop_bad_size +
                                   vfw_ctrs->pkts_drop_fragmented +
                                   vfw_ctrs->pkts_drop_unsupported_type;

              printf("{\"VFW_counters\" : {\"id\" : \"%s\", \" pkts_received\": %"
                     PRIu64 ", \" pkts_fw_forwarded\": %"
                     PRIu64 ", \" pkts_drop_fw\": %"
                     PRIu64 ", \" pkts_acl_forwarded\": %"
                     PRIu64 ", \"pkts_drop_without_rule\" : %"
                     PRIu64 ", \"average_pkts_in_batch\" : %"
                     PRIu64 ", \"average_internal_time_in_clocks\" : %"
                     PRIu64 ", \"average_external_time_in_clocks\" : %"
                     PRIu64 ", \"total_time_measures\" : %"
                     PRIu32 ", \"ct_packets_forwarded\" : %"
                     PRIu64 ", \"ct_packets_dropped\" : %"
                     PRIu64 ", \"bytes_processed \": %"
                     PRIu64 ", \"ct_sessions\" : {"
                     "\"active\" : %" PRIu64 ", \"open_attempt\" : %"
                     PRIu64 ", \"re-open_attempt\" : %"
                     PRIu64 ", \"established\" : %"
                     PRIu64 ", \"closed\" : %"
                     PRIu64 ", \"timeout\" : %"
                     PRIu64 "}, \"ct_drops\" : {"
                     "\"out_of_window\" : %" PRIu64 ", \"invalid_conn\" : %"
                     PRIu64 ", \"invalid_state_transition\" : %"
                     PRIu64 " \"RST\" : %"
                     PRIu64 "}}\n",
                     vfw_ctrs->name,
                     vfw_ctrs->pkts_received,
                     vfw_ctrs->pkts_fw_forwarded,
                     pkts_drop_fw,
                     vfw_ctrs->pkts_acl_forwarded,
                     vfw_ctrs->pkts_drop_without_rule,
                     average_pkts_in_batch,
                     average_internal_time,
                     average_external_time,
                     vfw_ctrs->time_measurements,
                     ct_counters->pkts_forwarded,
                     ct_counters->pkts_drop,
                     vfw_ctrs->bytes_processed,
                     ct_counters->current_active_sessions,
                     ct_counters->sessions_activated,
                     ct_counters->sessions_reactivated,
                     ct_counters->sessions_established,
                     ct_counters->sessions_closed,
                     ct_counters->sessions_timedout,
                     ct_counters->pkts_drop_outof_window,
                     ct_counters->pkts_drop_invalid_conn,
                     ct_counters->pkts_drop_invalid_state,
                     ct_counters->pkts_drop_invalid_rst);

              vfw_counter_sums.bytes_processed +=
                  vfw_ctrs->bytes_processed;

              vfw_counter_sums.internal_time_sum +=
                  vfw_ctrs->internal_time_sum;
              vfw_counter_sums.external_time_sum +=
                  vfw_ctrs->external_time_sum;
              vfw_counter_sums.time_measurements +=
                  vfw_ctrs->time_measurements;

              vfw_counter_sums.pkts_drop_ttl += vfw_ctrs->pkts_drop_ttl;
              vfw_counter_sums.pkts_drop_bad_size +=
                  vfw_ctrs->pkts_drop_bad_size;
              vfw_counter_sums.pkts_drop_fragmented +=
                  vfw_ctrs->pkts_drop_fragmented;
              vfw_counter_sums.pkts_drop_unsupported_type +=
                  vfw_ctrs->pkts_drop_unsupported_type;
              vfw_counter_sums.pkts_drop_without_arp_entry +=
                  vfw_ctrs->pkts_drop_without_arp_entry;

              vfw_counter_sums.pkts_drop_without_rule +=
                  vfw_ctrs->pkts_drop_without_rule;
              vfw_counter_sums.pkts_received += vfw_ctrs->pkts_received;
              vfw_counter_sums.pkts_fw_forwarded +=
                     vfw_ctrs->pkts_fw_forwarded;
              vfw_counter_sums.pkts_acl_forwarded +=
                     vfw_ctrs->pkts_acl_forwarded;
              sum_pkts_drop_fw += pkts_drop_fw;
              ct_counter_sums.pkts_forwarded += ct_counters->pkts_forwarded;
              ct_counter_sums.pkts_drop += ct_counters->pkts_drop;
              ct_counter_sums.current_active_sessions +=
                  ct_counters->current_active_sessions;
              ct_counter_sums.sessions_activated +=
                  ct_counters->sessions_activated;
              ct_counter_sums.sessions_reactivated +=
                  ct_counters->sessions_reactivated;
              ct_counter_sums.sessions_established +=
                  ct_counters->sessions_established;
              ct_counter_sums.sessions_closed += ct_counters->sessions_closed;
              ct_counter_sums.sessions_timedout +=
                  ct_counters->sessions_timedout;
              ct_counter_sums.pkts_drop_invalid_conn +=
                  ct_counters->pkts_drop_invalid_conn;
              ct_counter_sums.pkts_drop_invalid_state +=
                  ct_counters->pkts_drop_invalid_state;
              ct_counter_sums.pkts_drop_invalid_rst +=
                  ct_counters->pkts_drop_invalid_rst;
              ct_counter_sums.pkts_drop_outof_window +=
                  ct_counters->pkts_drop_outof_window;

       }

       printf("VFW TOTAL: pkts_received: %"
                     PRIu64 ", \"pkts_fw_forwarded\": %"
                     PRIu64 ", \"pkts_drop_fw\": %"
                     PRIu64 ", \"fw_drops\" : {"
                     "\"TTL_zero\" : %" PRIu64 ", \"bad_size\" : %"
                     PRIu64 ", \"fragmented_packet\" : %"
                     PRIu64 ", \"unsupported_packet_types\" : %"
                     PRIu64 ", \"no_arp_entry\" : %"
                     PRIu64 "}, \"pkts_acl_forwarded\": %"
                     PRIu64 ", \"pkts_drop_without_rule\": %"
                     PRIu64 ", \"packets_last_sec\" : %"
                     PRIu32 ", \"average_packets_per_sec\" : %"
                     PRIu32 ", \"bytes_last_sec\" : %"
                     PRIu32 ", \"average_bytes_per_sec\" : %"
                     PRIu32 ", \"bytes_processed \": %"
                     PRIu64 "\n",
                     vfw_counter_sums.pkts_received,
                     vfw_counter_sums.pkts_fw_forwarded,
                     sum_pkts_drop_fw,
                     vfw_counter_sums.pkts_drop_ttl,
                     vfw_counter_sums.pkts_drop_bad_size,
                     vfw_counter_sums.pkts_drop_fragmented,
                     vfw_counter_sums.pkts_drop_unsupported_type,
                     vfw_counter_sums.pkts_drop_without_arp_entry,
                     vfw_counter_sums.pkts_acl_forwarded,
                     vfw_counter_sums.pkts_drop_without_rule,
                     rte_vfw_performance_measures.pkts_last_second,
                     rte_vfw_performance_measures.ave_pkts_per_second,
                     rte_vfw_performance_measures.bytes_last_second,
                     rte_vfw_performance_measures.ave_bytes_per_second,
                     vfw_counter_sums.bytes_processed);

       printf("\"CT TOTAL: ct_packets_forwarded\" : %"
                     PRIu64 ", \" ct_packets_dropped\" : %"
                     PRIu64 ", \"ct_sessions\" : {"
                     "\"active\" : %" PRIu64 ", \"open_attempt\" : %"
                     PRIu64 ", \"re-open_attempt\" : %"
                     PRIu64 ", \"established\" : %"
                     PRIu64 ", \"closed\" : %"
                     PRIu64 ", \"timeout\" : %"
                     PRIu64 "}, \"ct_drops\" : {"
                     "\"out_of_window\" : %" PRIu64 ", \"invalid_conn\" : %"
                     PRIu64 ", \"invalid_state_transition\" : %"
                     PRIu64 " \"RST\" : %"
                     PRIu64 "}\n",
                     ct_counter_sums.pkts_forwarded,
                     ct_counter_sums.pkts_drop,
                     ct_counter_sums.current_active_sessions,
                     ct_counter_sums.sessions_activated,
                     ct_counter_sums.sessions_reactivated,
                     ct_counter_sums.sessions_established,
                     ct_counter_sums.sessions_closed,
                     ct_counter_sums.sessions_timedout,
                     ct_counter_sums.pkts_drop_outof_window,
                     ct_counter_sums.pkts_drop_invalid_conn,
                     ct_counter_sums.pkts_drop_invalid_state,
                     ct_counter_sums.pkts_drop_invalid_rst);

       for (i = 0; i <= rte_VFW_hi_counter_block_in_use; i++) {
              for (j = 0; j < action_array_max; j++) {
                     if (action_array_active[j].
                         action_bitmap & lib_acl_action_count) {
                            action_counter_sum[j].packetCount +=
                                action_counter_table[i][j].packetCount;
                            action_counter_sum[j].byteCount +=
                                action_counter_table[i][j].byteCount;
                     }
              }
       }

       for (j = 0; j < action_array_max; j++) {
              if (action_array_active[j].action_bitmap & lib_acl_action_count)
                     printf("Action ID: %02u, packetCount: %" PRIu64
                            ", byteCount: %" PRIu64 "\n", j,
                            action_counter_sum[j].packetCount,
                            action_counter_sum[j].byteCount);
       }
}

cmdline_parse_token_string_t cmd_vfw_stats_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_stats_result,
                      p_string, "p");

cmdline_parse_token_string_t cmd_vfw_stats_acl_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_stats_result,
                      vfw_string, "vfw");

cmdline_parse_token_string_t cmd_vfw_stats_stats_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_stats_result,
                      stats_string, "stats");

cmdline_parse_inst_t cmd_vfw_stats = {
       .f = cmd_vfw_stats_parsed,
       .data = NULL,
       .help_str = "VFW stats",
       .tokens = {
                 (void *)&cmd_vfw_stats_p_string,
                 (void *)&cmd_vfw_stats_acl_string,
                 (void *)&cmd_vfw_stats_stats_string,
                 NULL,
                 },
};

/*
 * p vfw clearstats
 */

/**
 * A structure defining the VFW clear stats command.
 */
struct cmd_vfw_clearstats_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t vfw_string;
       cmdline_fixed_string_t clearstats_string;
};

/**
 * Clear VFW and Connection Tracker stats.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void cmd_vfw_clearstats_parsed(__attribute__ ((unused))
                                    void *parsed_result,
                                    __attribute__ ((unused))
                                    struct cmdline *cl,
                                    __attribute__ ((unused))
                                    void *data)
{
       int i;
       struct rte_CT_counter_block *ct_counters;

       for (i = 0; i <= rte_VFW_hi_counter_block_in_use; i++) {
              ct_counters = rte_vfw_counter_table[i].ct_counters;
              rte_vfw_counter_table[i].bytes_processed = 0;
              rte_vfw_counter_table[i].pkts_drop_without_rule = 0;
              rte_vfw_counter_table[i].pkts_received = 0;
              rte_vfw_counter_table[i].pkts_drop_ttl = 0;
              rte_vfw_counter_table[i].pkts_drop_bad_size = 0;
              rte_vfw_counter_table[i].pkts_drop_fragmented = 0;
              rte_vfw_counter_table[i].pkts_drop_unsupported_type = 0;
              rte_vfw_counter_table[i].pkts_drop_without_arp_entry = 0;
              rte_vfw_counter_table[i].internal_time_sum = 0;
              rte_vfw_counter_table[i].external_time_sum = 0;
              rte_vfw_counter_table[i].time_measurements = 0;
              rte_vfw_counter_table[i].ct_counters->pkts_forwarded = 0;
              rte_vfw_counter_table[i].ct_counters->pkts_drop = 0;
              rte_vfw_counter_table[i].pkts_fw_forwarded = 0;
              rte_vfw_counter_table[i].pkts_acl_forwarded = 0;
              ct_counters->current_active_sessions = 0;
              ct_counters->sessions_activated = 0;
              ct_counters->sessions_reactivated = 0;
              ct_counters->sessions_established = 0;
              ct_counters->sessions_closed = 0;
              ct_counters->sessions_timedout = 0;
              ct_counters->pkts_drop_invalid_conn = 0;
              ct_counters->pkts_drop_invalid_state = 0;
              ct_counters->pkts_drop_invalid_rst = 0;
              ct_counters->pkts_drop_outof_window = 0;
       }

       memset(&action_counter_table, 0, sizeof(action_counter_table));
       rte_vfw_reset_running_averages();
}

cmdline_parse_token_string_t cmd_vfw_clearstats_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_clearstats_result,
                      p_string, "p");

cmdline_parse_token_string_t cmd_vfw_clearstats_acl_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_clearstats_result,
                      vfw_string, "vfw");

cmdline_parse_token_string_t cmd_vfw_clearstats_clearstats_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_clearstats_result,
                      clearstats_string, "clearstats");

cmdline_parse_inst_t cmd_vfw_clearstats = {
       .f = cmd_vfw_clearstats_parsed,
       .data = NULL,
       .help_str = "VFW clearstats",
       .tokens = {
                 (void *)&cmd_vfw_clearstats_p_string,
                 (void *)&cmd_vfw_clearstats_acl_string,
                 (void *)&cmd_vfw_clearstats_clearstats_string,
                 NULL,
                 },
};

/*
 * p vfw dbg
 */

/**
 * A structure defining the VFW debug command.
 */
struct cmd_vfw_dbg_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t vfw_string;
       cmdline_fixed_string_t dbg_string;
       uint8_t dbg;
};

/**
 * Parse and handle VFW debug command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void cmd_vfw_dbg_parsed(void *parsed_result, __attribute__ ((unused))
                              struct cmdline *cl, __rte_unused void *data)
{

        struct cmd_vfw_dbg_result *params = parsed_result;
       if (params->dbg == 0) {
              printf("DBG turned OFF\n");
              VFW_DEBUG = 0;
       } else if (params->dbg == 1) {
              printf("DBG turned ON\n");
              VFW_DEBUG = 1;
       } else if (params->dbg == 2) {
              printf("VFW IPV4 enabled\n");
              printf("VFW IPV6 enabled\n");
              vfw_ipv4_enabled = 1;
              vfw_ipv6_enabled = 1;
       } else if (params->dbg == 3) {
              printf("VFW IPV4 enabled\n");
              printf("VFW IPV6 disabled\n");
              vfw_ipv4_enabled = 1;
              vfw_ipv6_enabled = 0;
       } else if (params->dbg == 4) {
              printf("VFW IPV4 disabled\n");
              printf("VFW IPV6 enabled\n");
              vfw_ipv4_enabled = 0;
              vfw_ipv6_enabled = 1;
       } else if (params->dbg == 5) {
              printf("VFW Version: 3.03\n");
       } else
              printf("Invalid DBG setting\n");
}

cmdline_parse_token_string_t cmd_vfw_dbg_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_dbg_result,
                      p_string, "p");

cmdline_parse_token_string_t cmd_vfw_dbg_acl_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_dbg_result,
                      vfw_string, "vfw");

cmdline_parse_token_string_t cmd_vfw_dbg_dbg_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_dbg_result,
                      dbg_string, "dbg");

cmdline_parse_token_num_t cmd_vfw_dbg_dbg =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_dbg_result, dbg,
                    UINT8);

cmdline_parse_inst_t cmd_vfw_dbg = {
       .f = cmd_vfw_dbg_parsed,
       .data = NULL,
       .help_str = "VFW dbg",
       .tokens = {
                 (void *)&cmd_vfw_dbg_p_string,
                 (void *)&cmd_vfw_dbg_acl_string,
                 (void *)&cmd_vfw_dbg_dbg_string,
                 (void *)&cmd_vfw_dbg_dbg,
                 NULL,
                 },
};

/*
 * p vfw clearrules
 */

/**
 * A structure defining the VFW clear rules command.
 */
struct cmd_vfw_clearrules_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t vfw_string;
       cmdline_fixed_string_t clearrules_string;
};

/**
 * Parse clear rule command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void cmd_vfw_clearrules_parsed(__attribute__ ((unused))
                                    void *parsed_result,
                                    __attribute__ ((unused))
                                    struct cmdline *cl, void *data)
{
       struct app_params *app = data;
       int status;

       status = app_pipeline_vfw_clearrules(app);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_vfw_clearrules_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_clearrules_result,
                      p_string, "p");

cmdline_parse_token_string_t cmd_vfw_clearrules_acl_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_clearrules_result,
                      vfw_string, "vfw");

cmdline_parse_token_string_t cmd_vfw_clearrules_clearrules_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_clearrules_result,
                      clearrules_string, "clearrules");

cmdline_parse_inst_t cmd_vfw_clearrules = {
       .f = cmd_vfw_clearrules_parsed,
       .data = NULL,
       .help_str = "VFW clearrules",
       .tokens = {
                 (void *)&cmd_vfw_clearrules_p_string,
                 (void *)&cmd_vfw_clearrules_acl_string,
                 (void *)&cmd_vfw_clearrules_clearrules_string,
                 NULL,
                 },
};

/*
 * p vfw ls
 */

/**
 * A structure defining the VFW ls CLI command result.
 */
struct cmd_vfw_ls_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t vfw_string;
       cmdline_fixed_string_t ls_string;
       uint32_t table_instance;
};

/**
 * Parse VFW ls command to display rules to the console.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void cmd_vfw_ls_parsed(__attribute__ ((unused))
                             void *parsed_result, __attribute__ ((unused))
                             struct cmdline *cl, void *data)
{
       struct app_params *app = data;
       struct cmd_vfw_ls_result *params = parsed_result;

       app_pipeline_vfw_ls(app, params->table_instance);
}

cmdline_parse_token_string_t cmd_vfw_ls_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_ls_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_vfw_ls_acl_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_ls_result,
                      vfw_string, "vfw");

cmdline_parse_token_string_t cmd_vfw_ls_ls_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_ls_result, ls_string,
                      "ls");

cmdline_parse_token_num_t cmd_vfw_ls_table_instance =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_ls_result, table_instance,
                    UINT32);

cmdline_parse_inst_t cmd_vfw_ls = {
       .f = cmd_vfw_ls_parsed,
       .data = NULL,
       .help_str = "VFW rule list",
       .tokens = {
                 (void *)&cmd_vfw_ls_p_string,
                 (void *)&cmd_vfw_ls_acl_string,
                 (void *)&cmd_vfw_ls_ls_string,
                 (void *)&cmd_vfw_ls_table_instance,
                 NULL,
                 },
};

/*
 * p vfw applyruleset
 */

/**
 * A structure defining the VFW apply ruleset command.
 */
struct cmd_vfw_applyruleset_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t vfw_string;
       cmdline_fixed_string_t applyruleset_string;
};

/**
 * Parse VFW Apply Ruleset Command.
 * Switchover active and standby tables.
 * Sync newly standby tables to match updated data.
 * Both VFW rule and VFW action tables updated.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void cmd_vfw_applyruleset_parsed(__attribute__ ((unused))
                                      void *parsed_result,
                                      __attribute__ ((unused))
                                      struct cmdline *cl, void *data)
{
       struct app_params *app = data;
       void *temp_ptr;
       uint32_t *temp_count_ptr;
       struct pipeline_action_key *action_array_temp_ptr;
       int status;

       printf("VFW Apply Ruleset\n");

       /* Switchover Active and Standby TRIE rule tables */
       temp_ptr = vfw_rule_table_ipv4_active;
       vfw_rule_table_ipv4_active = vfw_rule_table_ipv4_standby;
       vfw_rule_table_ipv4_standby = temp_ptr;
       temp_ptr = vfw_rule_table_ipv6_active;
       vfw_rule_table_ipv6_active = vfw_rule_table_ipv6_standby;
       vfw_rule_table_ipv6_standby = temp_ptr;

       /* Switchover tailq tables */
       vfw_tailq_rules_temp_ptr = vfw_tailq_rules_ipv4_active;
       vfw_tailq_rules_ipv4_active = vfw_tailq_rules_ipv4_standby;
       vfw_tailq_rules_ipv4_standby = vfw_tailq_rules_temp_ptr;
       vfw_tailq_rules_temp_ptr = vfw_tailq_rules_ipv6_active;
       vfw_tailq_rules_ipv6_active = vfw_tailq_rules_ipv6_standby;
       vfw_tailq_rules_ipv6_standby = vfw_tailq_rules_temp_ptr;
       temp_count_ptr = vfw_n_tailq_rules_ipv4_active;
       vfw_n_tailq_rules_ipv4_active = vfw_n_tailq_rules_ipv4_standby;
       vfw_n_tailq_rules_ipv4_standby = temp_count_ptr;
       temp_count_ptr = vfw_n_tailq_rules_ipv6_active;
       vfw_n_tailq_rules_ipv6_active = vfw_n_tailq_rules_ipv6_standby;
       vfw_n_tailq_rules_ipv6_standby = temp_count_ptr;

       /* Switchover Active and Standby action table */
       action_array_temp_ptr = action_array_active;
       action_array_active = action_array_standby;
       action_array_standby = action_array_temp_ptr;
       /* Update Standby action table with all changes */
       memcpy(action_array_standby, action_array_active, action_array_size);

       /* Update Standby Rule Tables with all changes */
       while (!TAILQ_EMPTY(&vfw_commands)) {
              struct app_pipeline_vfw_rule *command;

              command = TAILQ_FIRST(&vfw_commands);
              TAILQ_REMOVE(&vfw_commands, command, node);

              if (command->command == vfw_add_command) {
                     status = app_pipeline_vfw_add_rule(app,
                                                       &command->key,
                                                       command->priority,
                                                       command->port_id,
                                                       command->
                                                       action_id);
              } else
                     status =
                         app_pipeline_vfw_delete_rule(app, &command->key);

              if (status != 0) {
                     printf("Command applyruleset add rule failed\n");
                     rte_free(command);
                     return;
              }

              rte_free(command);
       }
}

cmdline_parse_token_string_t cmd_vfw_applyruleset_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_applyruleset_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_vfw_applyruleset_acl_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_applyruleset_result,
                      vfw_string, "vfw");

cmdline_parse_token_string_t cmd_vfw_applyruleset_applyruleset_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_applyruleset_result,
                      applyruleset_string,
                      "applyruleset");

cmdline_parse_inst_t cmd_vfw_applyruleset = {
       .f = cmd_vfw_applyruleset_parsed,
       .data = NULL,
       .help_str = "VFW applyruleset",
       .tokens = {
                 (void *)&cmd_vfw_applyruleset_p_string,
                 (void *)&cmd_vfw_applyruleset_acl_string,
                 (void *)&cmd_vfw_applyruleset_applyruleset_string,
                 NULL,
                 },
};
/*
 * p action add accept
 */

/**
 * A structure defining the add accept action command.
 */
struct cmd_action_add_accept_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t add_string;
       int32_t action_id;
       cmdline_fixed_string_t accept_string;
};

/**
 * Parse Accept Action Add Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_action_add_accept_parsed(void *parsed_result, __attribute__ ((unused))
                          struct cmdline *cl, void *data)
{
       struct cmd_action_add_accept_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_action_key key;
       int status;

       key.action_id = params->action_id;
       key.action_bitmap = lib_acl_action_packet_accept;

       status = app_pipeline_action_add(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_action_add_accept_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_accept_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_add_accept_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_accept_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_add_accept_add_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_accept_result,
                      add_string, "add");

cmdline_parse_token_num_t cmd_action_add_accept_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_add_accept_result, action_id,
                    UINT32);

cmdline_parse_token_string_t cmd_action_add_accept_accept_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_accept_result,
                      accept_string, "accept");

cmdline_parse_inst_t cmd_action_add_accept = {
       .f = cmd_action_add_accept_parsed,
       .data = NULL,
       .help_str = "VFW action add accept",
       .tokens = {
                 (void *)&cmd_action_add_accept_p_string,
                 (void *)&cmd_action_add_accept_action_string,
                 (void *)&cmd_action_add_accept_add_string,
                 (void *)&cmd_action_add_accept_action_id,
                 (void *)&cmd_action_add_accept_accept_string,
                 NULL,
                 },
};

/*
 * p action del accept
 */

/**
 * A structure defining the delete accept action command.
 */
struct cmd_action_del_accept_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t del_string;
       int32_t action_id;
       cmdline_fixed_string_t accept_string;
};

/**
 * Parse Accept Action Delete Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_action_del_accept_parsed(void *parsed_result, __attribute__ ((unused))
                          struct cmdline *cl, void *data)
{
       struct cmd_action_del_accept_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_action_key key;
       int status;

       key.action_id = params->action_id;
       key.action_bitmap = lib_acl_action_packet_accept;

       status = app_pipeline_action_delete(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_action_del_accept_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_accept_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_del_accept_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_accept_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_del_accept_del_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_accept_result,
                      del_string, "del");

cmdline_parse_token_num_t cmd_action_del_accept_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_del_accept_result, action_id,
                    UINT32);

cmdline_parse_token_string_t cmd_action_del_accept_accept_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_accept_result,
                      accept_string, "accept");

cmdline_parse_inst_t cmd_action_del_accept = {
       .f = cmd_action_del_accept_parsed,
       .data = NULL,
       .help_str = "VFW action delete accept",
       .tokens = {
                 (void *)&cmd_action_del_accept_p_string,
                 (void *)&cmd_action_del_accept_action_string,
                 (void *)&cmd_action_del_accept_del_string,
                 (void *)&cmd_action_del_accept_action_id,
                 (void *)&cmd_action_del_accept_accept_string,
                 NULL,
                 },
};

/*
 * p action add drop
 */

/**
 * A structure defining the add drop action command.
 */
struct cmd_action_add_drop_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t add_string;
       int32_t action_id;
       cmdline_fixed_string_t drop_string;
};

/**
 * Parse Drop Action Add Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_action_add_drop_parsed(void *parsed_result, __attribute__ ((unused))
                        struct cmdline *cl, void *data)
{
       struct cmd_action_add_drop_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_action_key key;
       int status;

       key.action_id = params->action_id;
       key.action_bitmap = lib_acl_action_packet_drop;

       status = app_pipeline_action_add(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_action_add_drop_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_drop_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_add_drop_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_drop_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_add_drop_add_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_drop_result,
                      add_string, "add");

cmdline_parse_token_num_t cmd_action_add_drop_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_add_drop_result, action_id,
                    UINT32);

cmdline_parse_token_string_t cmd_action_add_drop_drop_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_drop_result,
                      drop_string, "drop");

cmdline_parse_inst_t cmd_action_add_drop = {
       .f = cmd_action_add_drop_parsed,
       .data = NULL,
       .help_str = "VFW action add drop",
       .tokens = {
                 (void *)&cmd_action_add_drop_p_string,
                 (void *)&cmd_action_add_drop_action_string,
                 (void *)&cmd_action_add_drop_add_string,
                 (void *)&cmd_action_add_drop_action_id,
                 (void *)&cmd_action_add_drop_drop_string,
                 NULL,
                 },
};

/*
 * p action del drop
 */

/**
 * A structure defining the delete drop action command.
 */
struct cmd_action_del_drop_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t del_string;
       int32_t action_id;
       cmdline_fixed_string_t drop_string;
};

/**
 * Parse Drop Action Delete Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_action_del_drop_parsed(void *parsed_result, __attribute__ ((unused))
                        struct cmdline *cl, void *data)
{
       struct cmd_action_del_drop_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_action_key key;
       int status;

       key.action_id = params->action_id;
       key.action_bitmap = lib_acl_action_packet_drop;

       status = app_pipeline_action_delete(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_action_del_drop_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_drop_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_del_drop_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_drop_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_del_drop_del_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_drop_result,
                      del_string, "del");

cmdline_parse_token_num_t cmd_action_del_drop_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_del_drop_result, action_id,
                    UINT32);

cmdline_parse_token_string_t cmd_action_del_drop_drop_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_drop_result,
                      drop_string, "drop");

cmdline_parse_inst_t cmd_action_del_drop = {
       .f = cmd_action_del_drop_parsed,
       .data = NULL,
       .help_str = "VFW action delete drop",
       .tokens = {
                 (void *)&cmd_action_del_drop_p_string,
                 (void *)&cmd_action_del_drop_action_string,
                 (void *)&cmd_action_del_drop_del_string,
                 (void *)&cmd_action_del_drop_action_id,
                 (void *)&cmd_action_del_drop_drop_string,
                 NULL,
                 },
};

/*
 * p action add fwd
 */

/**
 * A structure defining the add forward action command.
 */
struct cmd_action_add_fwd_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t add_string;
       int32_t action_id;
       cmdline_fixed_string_t fwd_string;
       int32_t port_id;
};

/**
 * Parse Forward Action Add Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_action_add_fwd_parsed(void *parsed_result, __attribute__ ((unused))
                       struct cmdline *cl, void *data)
{
       struct cmd_action_add_fwd_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_action_key key;
       int status;

       key.action_id = params->action_id;
       key.action_bitmap = lib_acl_action_fwd;
       key.fwd_port = params->port_id;

       status = app_pipeline_action_add(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_action_add_fwd_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_fwd_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_add_fwd_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_fwd_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_add_fwd_add_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_fwd_result,
                      add_string, "add");

cmdline_parse_token_num_t cmd_action_add_fwd_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_add_fwd_result, action_id,
                    UINT32);

cmdline_parse_token_string_t cmd_action_add_fwd_fwd_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_fwd_result,
                      fwd_string, "fwd");

cmdline_parse_token_num_t cmd_action_add_fwd_port_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_add_fwd_result, port_id,
                    UINT32);

cmdline_parse_inst_t cmd_action_add_fwd = {
       .f = cmd_action_add_fwd_parsed,
       .data = NULL,
       .help_str = "VFW action add fwd",
       .tokens = {
                 (void *)&cmd_action_add_fwd_p_string,
                 (void *)&cmd_action_add_fwd_action_string,
                 (void *)&cmd_action_add_fwd_add_string,
                 (void *)&cmd_action_add_fwd_action_id,
                 (void *)&cmd_action_add_fwd_fwd_string,
                 (void *)&cmd_action_add_fwd_port_id,
                 NULL,
                 },
};

/*
 * p action del fwd
 */

/**
 * A structure defining the delete forward action command.
 */
struct cmd_action_del_fwd_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t del_string;
       int32_t action_id;
       cmdline_fixed_string_t fwd_string;
};

/**
 * Parse Forward Action Delete Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_action_del_fwd_parsed(void *parsed_result, __attribute__ ((unused))
                       struct cmdline *cl, void *data)
{
       struct cmd_action_del_fwd_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_action_key key;
       int status;

       key.action_id = params->action_id;
       key.action_bitmap = lib_acl_action_fwd;

       status = app_pipeline_action_delete(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_action_del_fwd_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_fwd_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_del_fwd_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_fwd_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_del_fwd_del_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_fwd_result,
                      del_string, "del");

cmdline_parse_token_num_t cmd_action_del_fwd_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_del_fwd_result, action_id,
                    UINT32);

cmdline_parse_token_string_t cmd_action_del_fwd_fwd_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_fwd_result,
                      fwd_string, "fwd");

cmdline_parse_inst_t cmd_action_del_fwd = {
       .f = cmd_action_del_fwd_parsed,
       .data = NULL,
       .help_str = "VFW action delete fwd",
       .tokens = {
                 (void *)&cmd_action_del_fwd_p_string,
                 (void *)&cmd_action_del_fwd_action_string,
                 (void *)&cmd_action_del_fwd_del_string,
                 (void *)&cmd_action_del_fwd_action_id,
                 (void *)&cmd_action_del_fwd_fwd_string,
                 NULL,
                 },
};

/*
 * p action add nat
 */

/**
 * A structure defining the add NAT action command.
 */
struct cmd_action_add_nat_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t add_string;
       int32_t action_id;
       cmdline_fixed_string_t nat_string;
       int32_t port_id;
};

/**
 * Parse NAT Action Add Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_action_add_nat_parsed(void *parsed_result, __attribute__ ((unused))
                       struct cmdline *cl, void *data)
{
       struct cmd_action_add_nat_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_action_key key;
       int status;

       key.action_id = params->action_id;
       key.action_bitmap = lib_acl_action_nat;
       key.nat_port = params->port_id;

       status = app_pipeline_action_add(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_action_add_nat_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_nat_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_add_nat_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_nat_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_add_nat_add_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_nat_result,
                      add_string, "add");

cmdline_parse_token_num_t cmd_action_add_nat_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_add_nat_result, action_id,
                    UINT32);

cmdline_parse_token_string_t cmd_action_add_nat_nat_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_nat_result,
                      nat_string, "nat");

cmdline_parse_token_num_t cmd_action_add_nat_port_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_add_nat_result, port_id,
                    UINT32);

cmdline_parse_inst_t cmd_action_add_nat = {
       .f = cmd_action_add_nat_parsed,
       .data = NULL,
       .help_str = "VFW action add nat",
       .tokens = {
                 (void *)&cmd_action_add_nat_p_string,
                 (void *)&cmd_action_add_nat_action_string,
                 (void *)&cmd_action_add_nat_add_string,
                 (void *)&cmd_action_add_nat_action_id,
                 (void *)&cmd_action_add_nat_nat_string,
                 (void *)&cmd_action_add_nat_port_id,
                 NULL,
                 },
};

/*
 * p action del nat
 */

/**
 * A structure defining the delete NAT action command.
 */
struct cmd_action_del_nat_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t del_string;
       int32_t action_id;
       cmdline_fixed_string_t nat_string;
};

/**
 * Parse NAT Action Delete Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_action_del_nat_parsed(void *parsed_result, __attribute__ ((unused))
                       struct cmdline *cl, void *data)
{
       struct cmd_action_del_nat_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_action_key key;
       int status;

       key.action_id = params->action_id;
       key.action_bitmap = lib_acl_action_nat;

       status = app_pipeline_action_delete(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_action_del_nat_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_nat_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_del_nat_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_nat_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_del_nat_del_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_nat_result,
                      del_string, "del");

cmdline_parse_token_num_t cmd_action_del_nat_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_del_nat_result, action_id,
                    UINT32);

cmdline_parse_token_string_t cmd_action_del_nat_nat_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_nat_result,
                      nat_string, "nat");

cmdline_parse_inst_t cmd_action_del_nat = {
       .f = cmd_action_del_nat_parsed,
       .data = NULL,
       .help_str = "VFW action delete nat",
       .tokens = {
                 (void *)&cmd_action_del_nat_p_string,
                 (void *)&cmd_action_del_nat_action_string,
                 (void *)&cmd_action_del_nat_del_string,
                 (void *)&cmd_action_del_nat_action_id,
                 (void *)&cmd_action_del_nat_nat_string,
                 NULL,
                 },
};

/*
 * p action add count
 */

/**
 * A structure defining the add count action command.
 */
struct cmd_action_add_count_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t add_string;
       int32_t action_id;
       cmdline_fixed_string_t count_string;
};

/**
 * Parse Count Action Add Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_action_add_count_parsed(void *parsed_result, __attribute__ ((unused))
                         struct cmdline *cl, void *data)
{
       struct cmd_action_add_count_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_action_key key;
       int status;

       key.action_id = params->action_id;
       key.action_bitmap = lib_acl_action_count;

       status = app_pipeline_action_add(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_action_add_count_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_count_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_add_count_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_count_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_add_count_add_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_count_result,
                      add_string, "add");

cmdline_parse_token_num_t cmd_action_add_count_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_add_count_result, action_id,
                    UINT32);

cmdline_parse_token_string_t cmd_action_add_count_count_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_count_result,
                      count_string, "count");

cmdline_parse_inst_t cmd_action_add_count = {
       .f = cmd_action_add_count_parsed,
       .data = NULL,
       .help_str = "VFW action add count",
       .tokens = {
                 (void *)&cmd_action_add_count_p_string,
                 (void *)&cmd_action_add_count_action_string,
                 (void *)&cmd_action_add_count_add_string,
                 (void *)&cmd_action_add_count_action_id,
                 (void *)&cmd_action_add_count_count_string,
                 NULL,
                 },
};

/*
 * p action del count
 */

/**
 * A structure defining the delete count action command.
 */
struct cmd_action_del_count_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t del_string;
       int32_t action_id;
       cmdline_fixed_string_t count_string;
};

/**
 * Parse Count Action Delete Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_action_del_count_parsed(void *parsed_result, __attribute__ ((unused))
                         struct cmdline *cl, void *data)
{
       struct cmd_action_del_count_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_action_key key;
       int status;

       key.action_id = params->action_id;
       key.action_bitmap = lib_acl_action_count;

       status = app_pipeline_action_delete(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_action_del_count_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_count_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_del_count_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_count_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_del_count_del_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_count_result,
                      del_string, "del");

cmdline_parse_token_num_t cmd_action_del_count_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_del_count_result, action_id,
                    UINT32);

cmdline_parse_token_string_t cmd_action_del_count_count_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_count_result,
                      count_string, "count");

cmdline_parse_inst_t cmd_action_del_count = {
       .f = cmd_action_del_count_parsed,
       .data = NULL,
       .help_str = "VFW action delete count",
       .tokens = {
                 (void *)&cmd_action_del_count_p_string,
                 (void *)&cmd_action_del_count_action_string,
                 (void *)&cmd_action_del_count_del_string,
                 (void *)&cmd_action_del_count_action_id,
                 (void *)&cmd_action_del_count_count_string,
                 NULL,
                 },
};

/*
 * p action add dscp
 */

/**
 * A structure defining the add DSCP action command.
 */
struct cmd_action_add_dscp_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t add_string;
       int32_t action_id;
       cmdline_fixed_string_t dscp_string;
       uint8_t dscp_priority;
};

/**
 * Parse DSCP Action Add Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_action_add_dscp_parsed(void *parsed_result, __attribute__ ((unused))
                        struct cmdline *cl, void *data)
{
       struct cmd_action_add_dscp_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_action_key key;
       int status;

       key.action_id = params->action_id;
       key.action_bitmap = lib_acl_action_dscp;
       key.dscp_priority = params->dscp_priority;

       status = app_pipeline_action_add(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_action_add_dscp_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_dscp_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_add_dscp_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_dscp_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_add_dscp_add_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_dscp_result,
                      add_string, "add");

cmdline_parse_token_num_t cmd_action_add_dscp_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_add_dscp_result, action_id,
                    UINT32);

cmdline_parse_token_string_t cmd_action_add_dscp_dscp_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_dscp_result,
                      dscp_string, "dscp");

cmdline_parse_token_num_t cmd_action_add_dscp_dscp_priority =
TOKEN_NUM_INITIALIZER(struct cmd_action_add_dscp_result, dscp_priority,
                    UINT8);

cmdline_parse_inst_t cmd_action_add_dscp = {
       .f = cmd_action_add_dscp_parsed,
       .data = NULL,
       .help_str = "VFW action add dscp",
       .tokens = {
                 (void *)&cmd_action_add_dscp_p_string,
                 (void *)&cmd_action_add_dscp_action_string,
                 (void *)&cmd_action_add_dscp_add_string,
                 (void *)&cmd_action_add_dscp_action_id,
                 (void *)&cmd_action_add_dscp_dscp_string,
                 (void *)&cmd_action_add_dscp_dscp_priority,
                 NULL,
                 },
};

/*
 * p action del dscp
 */

/**
 * A structure defining the delete DSCP action command.
 */
struct cmd_action_del_dscp_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t del_string;
       int32_t action_id;
       cmdline_fixed_string_t dscp_string;
};

/**
 * Parse DSCP Action Delete Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_action_del_dscp_parsed(void *parsed_result, __attribute__ ((unused))
                        struct cmdline *cl, void *data)
{
       struct cmd_action_del_dscp_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_action_key key;
       int status;

       key.action_id = params->action_id;
       key.action_bitmap = lib_acl_action_dscp;

       status = app_pipeline_action_delete(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_action_del_dscp_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_dscp_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_del_dscp_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_dscp_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_del_dscp_del_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_dscp_result,
                      del_string, "del");

cmdline_parse_token_num_t cmd_action_del_dscp_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_del_dscp_result, action_id,
                    UINT32);

cmdline_parse_token_string_t cmd_action_del_dscp_dscp_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_dscp_result,
                      dscp_string, "dscp");

cmdline_parse_inst_t cmd_action_del_dscp = {
       .f = cmd_action_del_dscp_parsed,
       .data = NULL,
       .help_str = "VFW action delete dscp",
       .tokens = {
                 (void *)&cmd_action_del_dscp_p_string,
                 (void *)&cmd_action_del_dscp_action_string,
                 (void *)&cmd_action_del_dscp_del_string,
                 (void *)&cmd_action_del_dscp_action_id,
                 (void *)&cmd_action_del_dscp_dscp_string,
                 NULL,
                 },
};

/*
 * p action add conntrack
 */

/**
 * A structure defining the add Connection Tracking action command.
 */
struct cmd_action_add_conntrack_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t add_string;
       int32_t action_id;
       cmdline_fixed_string_t conntrack_string;
};

/**
 * Parse Connection Tracking Action Add Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_action_add_conntrack_parsed(void *parsed_result, __attribute__ ((unused))
                            struct cmdline *cl, void *data)
{
       struct cmd_action_add_conntrack_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_action_key key;
       int status;

       key.action_id = params->action_id;
       key.action_bitmap = lib_acl_action_conntrack;

       status = app_pipeline_action_add(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_action_add_conntrack_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_conntrack_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_add_conntrack_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_conntrack_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_add_conntrack_add_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_conntrack_result,
                      add_string, "add");

cmdline_parse_token_num_t cmd_action_add_conntrack_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_add_conntrack_result, action_id,
                    UINT32);

cmdline_parse_token_string_t cmd_action_add_conntrack_conntrack_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_conntrack_result,
                      conntrack_string, "conntrack");

cmdline_parse_inst_t cmd_action_add_conntrack = {
       .f = cmd_action_add_conntrack_parsed,
       .data = NULL,
       .help_str = "VFW action add conntrack",
       .tokens = {
                 (void *)&cmd_action_add_conntrack_p_string,
                 (void *)&cmd_action_add_conntrack_action_string,
                 (void *)&cmd_action_add_conntrack_add_string,
                 (void *)&cmd_action_add_conntrack_action_id,
                 (void *)&cmd_action_add_conntrack_conntrack_string,
                 NULL,
                 },
};

/*
 * p action del conntrack
 */

/**
 * A structure defining the delete Connection Tracking action command.
 */
struct cmd_action_del_conntrack_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t del_string;
       int32_t action_id;
       cmdline_fixed_string_t conntrack_string;
};

/**
 * Parse Connection Tracking Action Delete Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_action_del_conntrack_parsed(void *parsed_result, __attribute__ ((unused))
                            struct cmdline *cl, void *data)
{
       struct cmd_action_del_conntrack_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_action_key key;
       int status;

       key.action_id = params->action_id;
       key.action_bitmap = lib_acl_action_conntrack;

       status = app_pipeline_action_delete(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_action_del_conntrack_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_conntrack_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_del_conntrack_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_conntrack_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_del_conntrack_del_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_conntrack_result,
                      del_string, "del");

cmdline_parse_token_num_t cmd_action_del_conntrack_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_del_conntrack_result, action_id,
                    UINT32);

cmdline_parse_token_string_t cmd_action_del_conntrack_conntrack_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_conntrack_result,
                      conntrack_string, "conntrack");

cmdline_parse_inst_t cmd_action_del_conntrack = {
       .f = cmd_action_del_conntrack_parsed,
       .data = NULL,
       .help_str = "VFW action delete conntrack",
       .tokens = {
                 (void *)&cmd_action_del_conntrack_p_string,
                 (void *)&cmd_action_del_conntrack_action_string,
                 (void *)&cmd_action_del_conntrack_del_string,
                 (void *)&cmd_action_del_conntrack_action_id,
                 (void *)&cmd_action_del_conntrack_conntrack_string,
                 NULL,
                 },
};

/*
 * p action add connexist
 */

/**
 * A structure defining the add Connection Exist action command.
 */
struct cmd_action_add_connexist_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t add_string;
       int32_t action_id;
       cmdline_fixed_string_t connexist_string;
       cmdline_fixed_string_t private_public_string;
};

/**
 * Parse Connection Exist Action Add Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_action_add_connexist_parsed(void *parsed_result, __attribute__ ((unused))
                            struct cmdline *cl, void *data)
{
       struct cmd_action_add_connexist_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_action_key key;
       int status;

       if (VFW_DEBUG)
              printf("public_private: %s\n", params->private_public_string);
       key.action_id = params->action_id;
       key.action_bitmap = lib_acl_action_connexist;
       if (strcmp(params->private_public_string, "prvpub") == 0)
              key.private_public = lib_acl_private_public;
       else if (strcmp(params->private_public_string, "pubprv") == 0)
              key.private_public = lib_acl_public_private;
       else {
              printf("Command failed - Invalid string: %s\n",
                     params->private_public_string);
              return;
       }

       status = app_pipeline_action_add(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_action_add_connexist_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_connexist_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_add_connexist_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_connexist_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_add_connexist_add_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_connexist_result,
                      add_string, "add");

cmdline_parse_token_num_t cmd_action_add_connexist_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_add_connexist_result, action_id,
                    UINT32);

cmdline_parse_token_string_t cmd_action_add_connexist_connexist_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_connexist_result,
                      connexist_string, "connexist");

cmdline_parse_token_string_t cmd_action_add_connexist_private_public =
TOKEN_STRING_INITIALIZER(struct cmd_action_add_connexist_result,
                      private_public_string,
                      NULL);

cmdline_parse_inst_t cmd_action_add_connexist = {
       .f = cmd_action_add_connexist_parsed,
       .data = NULL,
       .help_str = "VFW action add connexist",
       .tokens = {
                 (void *)&cmd_action_add_connexist_p_string,
                 (void *)&cmd_action_add_connexist_action_string,
                 (void *)&cmd_action_add_connexist_add_string,
                 (void *)&cmd_action_add_connexist_action_id,
                 (void *)&cmd_action_add_connexist_connexist_string,
                 (void *)&cmd_action_add_connexist_private_public,
                 NULL,
                 },
};

/*
 * p action del connexist
 */

/**
 * A structure defining the delete Connection Exist action command.
 */
struct cmd_action_del_connexist_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t del_string;
       int32_t action_id;
       cmdline_fixed_string_t connexist_string;
};

/**
 * Parse Connection Exist Action Delete Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_action_del_connexist_parsed(void *parsed_result, __attribute__ ((unused))
                            struct cmdline *cl, void *data)
{
       struct cmd_action_del_connexist_result *params = parsed_result;
       struct app_params *app = data;
       struct pipeline_action_key key;
       int status;

       key.action_id = params->action_id;
       key.action_bitmap = lib_acl_action_connexist;

       status = app_pipeline_action_delete(app, &key);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_action_del_connexist_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_connexist_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_del_connexist_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_connexist_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_del_connexist_add_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_connexist_result,
                      del_string, "del");

cmdline_parse_token_num_t cmd_action_del_connexist_action_id =
TOKEN_NUM_INITIALIZER(struct cmd_action_del_connexist_result, action_id,
                    UINT32);

cmdline_parse_token_string_t cmd_action_del_connexist_connexist_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_del_connexist_result,
                      connexist_string, "connexist");

cmdline_parse_inst_t cmd_action_del_connexist = {
       .f = cmd_action_del_connexist_parsed,
       .data = NULL,
       .help_str = "VFW action del connexist",
       .tokens = {
                 (void *)&cmd_action_del_connexist_p_string,
                 (void *)&cmd_action_del_connexist_action_string,
                 (void *)&cmd_action_del_connexist_add_string,
                 (void *)&cmd_action_del_connexist_action_id,
                 (void *)&cmd_action_del_connexist_connexist_string,
                 NULL,
                 },
};

/*
 * p action ls
 */

/**
 * A structure defining the action ls command.
 */
struct cmd_action_ls_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t action_string;
       cmdline_fixed_string_t ls_string;
       uint32_t table_instance;
};

/**
 * Parse Action LS Command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void cmd_action_ls_parsed(void *parsed_result, __attribute__ ((unused))
              struct cmdline *cl, __attribute__ ((unused)) void *data)
{
       struct cmd_action_ls_result *params = parsed_result;
       uint32_t action_bitmap, i, j;
       uint8_t action_found = 0;
       struct action_counter_block action_counter_sum;

       if (params->table_instance == active_rule_table) {
              printf("Active Action Table:\n");
              printf("Action ID     Action\n");
              printf("=========     ======\n");

              for (i = 0; i < action_array_max; i++) {
                     action_bitmap = action_array_active[i].action_bitmap;
                     if (action_bitmap != 0) {
                            action_found = 1;
                            if (action_bitmap &
                                          lib_acl_action_packet_accept)
                                   printf("  %04u        Accept\n", i);
                            if (action_bitmap & lib_acl_action_packet_drop)
                                   printf("  %04u        Drop\n", i);
                            if (action_bitmap & lib_acl_action_nat)
                                   printf("  %04"PRIu32
                                          "        NAT       NAT Port: %"
                                          PRIu32"\n",
                                          i,
                                 action_array_active[i].nat_port);
                            if (action_bitmap & lib_acl_action_fwd)
                                   printf("  %04"PRIu32
                                          "        FWD       FWD Port: %"
                                          PRIu32"\n",
                                          i,
                                          action_array_active[i].
                                          fwd_port);
                            if (action_bitmap & lib_acl_action_count) {
                                   action_counter_sum.packetCount = 0;
                                   action_counter_sum.byteCount = 0;
                                   for (j = 0; j <= (uint32_t)
                                   rte_VFW_hi_counter_block_in_use;
                                   j++) {
                                          action_counter_sum.
                                              packetCount +=
                                              action_counter_table[j][i].
                                              packetCount;
                                          action_counter_sum.byteCount +=
                                              action_counter_table[j][i].
                                              byteCount;
                                   }
                                   printf("  %04"PRIu32
                                          "       Count    Packet Count:%"
                                          PRIu64 "   Byte Count: %" PRIu64
                                          "\n", i,
                                          action_counter_sum.packetCount,
                                          action_counter_sum.byteCount);
                            }
                            if (action_bitmap & lib_acl_action_conntrack)
                                   printf("  %04u        Conntrack\n", i);
                            if (action_bitmap & lib_acl_action_connexist) {
                                   printf("  %04u        Connexist", i);
                                   if (action_array_active[i].
                                       private_public ==
                                       lib_acl_private_public)
                                          printf(" prvpub\n");
                                   else
                                          printf(" pubprv\n");
                            }
                            if (action_bitmap & lib_acl_action_dscp)
                                   printf
                                       ("  %04"PRIu32
                                        "        DSCP     DSCP Priority: %"
                                        PRIu8"\n",
                                        i,
                                        action_array_active[i].
                                        dscp_priority);
                     }
              }

              if (!action_found)
                     printf("None\n");

       } else {
              action_found = 0;
              printf("Standby Action Table:\n");
              printf("Action ID     Action\n");
              printf("=========     ======\n");

              for (i = 0; i < action_array_max; i++) {
                     action_bitmap = action_array_standby[i].action_bitmap;
                     if (action_bitmap != 0) {
                            action_found = 1;
                            if (action_bitmap &
                                          lib_acl_action_packet_accept)
                                   printf("  %04u        Accept\n", i);
                            if (action_bitmap & lib_acl_action_packet_drop)
                                   printf("  %04u        Drop\n", i);
                            if (action_bitmap & lib_acl_action_nat)
                                   printf
                                          ("  %04"PRIu32
                                           "        NAT       NAT Port: %"
                                           PRIu32"\n", i,
                                           action_array_standby[i].
                                           nat_port);
                            if (action_bitmap & lib_acl_action_fwd)
                                   printf
                                          ("  %04"PRIu32
                                           "        FWD       FWD Port: %"
                                           PRIu32"\n", i,
                                           action_array_standby[i].
                                           fwd_port);
                            if (action_bitmap & lib_acl_action_count)
                                   printf("  %04u        Count\n", i);
                            if (action_bitmap & lib_acl_action_conntrack)
                                   printf("  %04u        Conntrack\n", i);
                            if (action_bitmap & lib_acl_action_connexist) {
                                   printf("  %04u        Connexist", i);
                                   if (action_array_standby[i].
                                       private_public ==
                                       lib_acl_private_public)
                                          printf(" prvpub\n");
                                   else
                                          printf(" pubprv\n");
                            }
                            if (action_bitmap & lib_acl_action_dscp)
                                   printf("  %04"PRIu32
                                    "       DSCP     DSCP Priority: %"
                                    PRIu8"\n", i,
                                    action_array_standby[i].
                                    dscp_priority);
                     }
              }

              if (!action_found)
                     printf("None\n");
       }
}

cmdline_parse_token_string_t cmd_action_ls_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_ls_result, p_string,
                      "p");

cmdline_parse_token_string_t cmd_action_ls_action_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_ls_result,
                      action_string, "action");

cmdline_parse_token_string_t cmd_action_ls_ls_string =
TOKEN_STRING_INITIALIZER(struct cmd_action_ls_result, ls_string,
                      "ls");

cmdline_parse_token_num_t cmd_action_ls_table_instance =
TOKEN_NUM_INITIALIZER(struct cmd_action_ls_result, table_instance,
                    UINT32);

cmdline_parse_inst_t cmd_action_ls = {
       .f = cmd_action_ls_parsed,
       .data = NULL,
       .help_str = "VFW action list",
       .tokens = {
                 (void *)&cmd_action_ls_p_string,
                 (void *)&cmd_action_ls_action_string,
                 (void *)&cmd_action_ls_ls_string,
                 (void *)&cmd_action_ls_table_instance,
                 NULL,
                 },
};

/*
 * p vfw onesectimer start/stop
 */

/**
 * A structure defining the VFW Dump Counter start/stop command.
 */
struct cmd_vfw_per_sec_ctr_dump_result {
       cmdline_fixed_string_t p_string;
       cmdline_fixed_string_t vfw_string;
       cmdline_fixed_string_t per_sec_ctr_dump_string;
       cmdline_fixed_string_t stop_string;
};

/**
 * Parse Dump Counter Start Command.
 * Start timer to display stats to console at regular intervals.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
       cmd_vfw_per_sec_ctr_dump_start_parsed(
                     __attribute__ ((unused)) void *parsed_result,
                     __attribute__ ((unused))
                     struct cmdline *cl, __attribute__ ((unused)) void *data)
{
       rte_vfw_reset_running_averages();
       /* execute timeout on current core */
       uint32_t core_id = rte_lcore_id();
       int success =
           rte_timer_reset(&rte_vfw_one_second_timer,
                         rte_vfw_ticks_in_one_second, PERIODICAL, core_id,
                         rte_dump_vfw_counters_from_master, NULL);
        if (success < 0)
              printf("CNXN_TRACKER: Failed to set connection timer.\n");
}

/**
 * Parse Dump Counter Stop Command.
 * Stop timer that was started to display stats.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
       cmd_vfw_per_sec_ctr_dump_stop_parsed(
                     __attribute__ ((unused)) void *parsed_result,
                     __attribute__ ((unused))
                     struct cmdline *cl, __attribute__ ((unused)) void *data)
{
       rte_timer_stop(&rte_vfw_one_second_timer);
}

cmdline_parse_token_string_t cmd_vfw_per_sec_ctr_dump_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_per_sec_ctr_dump_result,
                      p_string, "p");

cmdline_parse_token_string_t cmd_vfw_per_sec_ctr_dump_acl_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_per_sec_ctr_dump_result,
                      vfw_string, "vfw");

cmdline_parse_token_string_t cmd_vfw_per_sec_ctr_dump_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_per_sec_ctr_dump_result,
                      per_sec_ctr_dump_string, "counterdump");

cmdline_parse_token_string_t cmd_vfw_stop_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_per_sec_ctr_dump_result,
                      stop_string, "stop");

cmdline_parse_token_string_t cmd_vfw_start_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_per_sec_ctr_dump_result,
                      stop_string, "start");

cmdline_parse_inst_t cmd_vfw_per_sec_ctr_dump_stop = {
       .f = cmd_vfw_per_sec_ctr_dump_stop_parsed,
       .data = NULL,
       .help_str = "VFW counterdump stop",
       .tokens = {
                 (void *)&cmd_vfw_per_sec_ctr_dump_p_string,
                 (void *)&cmd_vfw_per_sec_ctr_dump_acl_string,
                 (void *)&cmd_vfw_per_sec_ctr_dump_string,
                 (void *)&cmd_vfw_stop_string,
                 NULL,
                 },
};

cmdline_parse_inst_t cmd_vfw_per_sec_ctr_dump_start = {
       .f = cmd_vfw_per_sec_ctr_dump_start_parsed,
       .data = NULL,
       .help_str = "VFW counterdump start",
       .tokens = {
                 (void *)&cmd_vfw_per_sec_ctr_dump_p_string,
                 (void *)&cmd_vfw_per_sec_ctr_dump_acl_string,
                 (void *)&cmd_vfw_per_sec_ctr_dump_string,
                 (void *)&cmd_vfw_start_string,
                 NULL,
                 },
};

/**
 * A structure defining the VFW firewall ON/OFF command.
 */
struct cmd_vfw_firewall_flag_result {
       cmdline_fixed_string_t p_string;
       uint32_t pipeline_id;
       cmdline_fixed_string_t vfw_string;
       cmdline_fixed_string_t firewall_flag_string;
       uint8_t firewall_flag;
};

/**
 * Parse VFW Firewall ON/OFF CLI command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_vfw_firewall_flag_parsed(void *parsed_result, __attribute__ ((unused))
              struct cmdline *cl, __attribute__ ((unused)) void *data)
{
       struct cmd_vfw_firewall_flag_result *params = parsed_result;

       if (params->firewall_flag == 0) {
              printf("firewall turned OFF\n");
              firewall_flag = 0;
       } else if (params->firewall_flag == 1) {
              printf("firewall turned ON\n");
              firewall_flag = 1;
       } else
              printf("Invalid firewall setting\n");
}

cmdline_parse_token_string_t cmd_vfw_firewall_flag_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_firewall_flag_result,
                      p_string, "p");

cmdline_parse_token_string_t cmd_vfw_firewall_flag_vfw_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_firewall_flag_result,
                      vfw_string, "vfw");

cmdline_parse_token_string_t cmd_vfw_firewall_flag_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_firewall_flag_result,
                      firewall_flag_string, "firewall");

cmdline_parse_token_num_t cmd_vfw_firewall_flag =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_firewall_flag_result, firewall_flag,
                    UINT8);

cmdline_parse_inst_t cmd_vfw_firewall = {
       .f = cmd_vfw_firewall_flag_parsed,
       .data = NULL,
       .help_str = "VFW firewall_flag",
       .tokens = {
                 (void *)&cmd_vfw_firewall_flag_p_string,
                 (void *)&cmd_vfw_firewall_flag_vfw_string,
                 (void *)&cmd_vfw_firewall_flag_string,
                 (void *)&cmd_vfw_firewall_flag,
                 NULL,
                 },
};


/**
 * A structure defining the TCPFW conntrack ON/OFF command.
 */
struct cmd_vfw_fw_conntrack_result {
       cmdline_fixed_string_t p_string;
       uint32_t pipeline_id;
       cmdline_fixed_string_t tcpfw_string;
       cmdline_fixed_string_t conntrack_string;
       uint8_t conntrack_flag;
};

/**
 * Parse VFW_TCPFW conntrack ON/OFF CLI command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void cmd_vfw_fw_conntrack_parsed(
              void *parsed_result,
              __attribute__((unused)) struct cmdline *cl,
              __rte_unused void *data)
{
       struct cmd_vfw_fw_conntrack_result *params = parsed_result;

       if (params->conntrack_flag == 0) {
              printf("firewall conntrack turned OFF\n");
              cnxn_tracking_is_active = 0;
       } else if (params->conntrack_flag == 1) {
              printf("firewall conntrack turned ON\n");
              cnxn_tracking_is_active = 1;
       } else
              printf("Invalid firewall conntrack setting\n");

}
cmdline_parse_token_string_t cmd_vfw_fw_conntrack_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_fw_conntrack_result,
              p_string, "p");

cmdline_parse_token_string_t cmd_vfw_fw_conntrack_fw_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_fw_conntrack_result,
              tcpfw_string, "vfw");

cmdline_parse_token_string_t cmd_vfw_fw_conntrack_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_fw_conntrack_result,
              conntrack_string, "conntrack");

cmdline_parse_token_num_t cmd_vfw_fw_conntrack_flag =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_fw_conntrack_result, conntrack_flag,
              UINT8);
cmdline_parse_inst_t cmd_vfw_fw_conntrack = {
       .f = cmd_vfw_fw_conntrack_parsed,
       .data = NULL,
       .help_str = "VFW FW conntrack",
       .tokens = {
              (void *) &cmd_vfw_fw_conntrack_p_string,
              (void *) &cmd_vfw_fw_conntrack_fw_string,
              (void *) &cmd_vfw_fw_conntrack_string,
              (void *) &cmd_vfw_fw_conntrack_flag,
              NULL,
       },
};

/**
 * A structure defining the VFW synproxy ON/OFFcommand.
 */
struct cmd_vfw_synproxy_flag_result {
       cmdline_fixed_string_t p_string;
       uint32_t pipeline_id;
       cmdline_fixed_string_t vfw_string;
       cmdline_fixed_string_t synproxy_flag_string;
       uint8_t synproxy_flag;
};

/**
 * Parse TCPFW synproxy ON/OFF CLI command.
 *
 * @param parsed_result
 *  A pointer to CLI command parsed result.
 * @param cl
 *  A pointer to command line context.
 * @param data
 *  A pointer to command specific data
 *
 */
static void
cmd_vfw_synproxy_flag_parsed(void *parsed_result, __attribute__ ((unused))
                            struct cmdline *cl, void *data)
{
       struct cmd_vfw_synproxy_flag_result *params = parsed_result;
       struct app_params *app = data;
       int status;

       status = app_pipeline_vfw_synproxy_flag(app,
                                             params->pipeline_id,
                                             params->synproxy_flag);

       if (status != 0) {
              printf("Command failed\n");
              return;
       }
}

cmdline_parse_token_string_t cmd_vfw_synproxy_flag_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_synproxy_flag_result,
                      p_string, "p");

cmdline_parse_token_num_t cmd_vfw_synproxy_flag_pipeline_id =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_synproxy_flag_result,
                    pipeline_id, UINT32);

cmdline_parse_token_string_t cmd_vfw_synproxy_flag_vfw_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_synproxy_flag_result,
                      vfw_string, "vfw");

cmdline_parse_token_string_t cmd_vfw_synproxy_flag_string =
TOKEN_STRING_INITIALIZER(struct cmd_vfw_synproxy_flag_result,
                      synproxy_flag_string, "synproxy");

cmdline_parse_token_num_t cmd_vfw_synproxy_flag =
TOKEN_NUM_INITIALIZER(struct cmd_vfw_synproxy_flag_result, synproxy_flag,
              UINT8);

static uint32_t rules_loaded;
static int vfw_field_found(const char *key,
            const char *filename,
            char *path,
            size_t pathlen,
            void *user_data);

static int vfw_field_get(const char *key, const char *value, size_t valuelen,
 void *user_data);
static int vfw_field_stored(const char *path, long long file_size, void *user_data);

int vfw_clearrules_handler(struct mg_connection *conn, __rte_unused void *cbdata)
{
       struct app_params *app = myapp;
       int status;
       mg_printf(conn,
                 "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                 "close\r\n\r\n");
       mg_printf(conn, "<html><body>");
       mg_printf(conn, "</body></html>\n");

       status = app_pipeline_vfw_clearrules(app);

       if (status != 0) {
              mg_printf(conn, "Command failed\n");
              return 1;
       }

       mg_printf(conn, "Command Success\n");
       return 1;
}

int vfw_clearstats_handler(__rte_unused struct mg_connection *conn,
		 __rte_unused void *cbdata)
{
       int i;
       struct rte_CT_counter_block *ct_counters;

       for (i = 0; i <= rte_VFW_hi_counter_block_in_use; i++) {
              ct_counters = rte_vfw_counter_table[i].ct_counters;
              rte_vfw_counter_table[i].bytes_processed = 0;
              rte_vfw_counter_table[i].pkts_drop_without_rule = 0;
              rte_vfw_counter_table[i].pkts_received = 0;
              rte_vfw_counter_table[i].pkts_drop_ttl = 0;
              rte_vfw_counter_table[i].pkts_drop_bad_size = 0;
              rte_vfw_counter_table[i].pkts_drop_fragmented = 0;
              rte_vfw_counter_table[i].pkts_drop_unsupported_type = 0;
              rte_vfw_counter_table[i].pkts_drop_without_arp_entry = 0;
              rte_vfw_counter_table[i].internal_time_sum = 0;
              rte_vfw_counter_table[i].external_time_sum = 0;
              rte_vfw_counter_table[i].time_measurements = 0;
              rte_vfw_counter_table[i].ct_counters->pkts_forwarded = 0;
              rte_vfw_counter_table[i].ct_counters->pkts_drop = 0;
              rte_vfw_counter_table[i].pkts_fw_forwarded = 0;
              rte_vfw_counter_table[i].pkts_acl_forwarded = 0;
              ct_counters->current_active_sessions = 0;
              ct_counters->sessions_activated = 0;
              ct_counters->sessions_reactivated = 0;
              ct_counters->sessions_established = 0;
              ct_counters->sessions_closed = 0;
              ct_counters->sessions_timedout = 0;
              ct_counters->pkts_drop_invalid_conn = 0;
              ct_counters->pkts_drop_invalid_state = 0;
              ct_counters->pkts_drop_invalid_rst = 0;
              ct_counters->pkts_drop_outof_window = 0;
       }

       memset(&action_counter_table, 0, sizeof(action_counter_table));
       rte_vfw_reset_running_averages();
       return 1;
}

int vfw_stats_handler(struct mg_connection *conn, __rte_unused void *cbdata)
{
       const struct mg_request_info *ri = mg_get_request_info(conn);
       int i, j;
       struct rte_VFW_counter_block vfw_counter_sums;
       struct rte_CT_counter_block ct_counter_sums;
       struct rte_CT_counter_block *ct_counters;
       struct action_counter_block action_counter_sum[action_array_max];
       uint64_t sum_pkts_drop_fw = 0;
       
       if (!strcmp(ri->request_method, "POST")) {
               mg_printf(conn,
                       "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                       "close\r\n\r\n");
               mg_printf(conn, "<html><body>");
               mg_printf(conn, "Command Passed \n");
               vfw_clearstats_handler(conn, cbdata);
               mg_printf(conn, "</body></html>\n");
               return 1;
       }

       if (strcmp(ri->request_method, "GET")) {
               mg_printf(conn,
                         "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n");
               mg_printf(conn, "Content-Type: text/plain\r\n\r\n");
               mg_printf(conn,
                         "%s method not allowed in the GET handler\n",
                         ri->request_method);
               return 1;
       }

       memset(&vfw_counter_sums, 0, sizeof(vfw_counter_sums));
       memset(&ct_counter_sums, 0, sizeof(ct_counter_sums));

       mg_printf(conn,
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                "close\r\n\r\n");
       mg_printf(conn, "<html><body>");
       mg_printf(conn, "VFW Stats\n");
       for (i = 0; i <= rte_VFW_hi_counter_block_in_use; i++) {
              struct rte_VFW_counter_block *vfw_ctrs =
                  &rte_vfw_counter_table[i];
              ct_counters = rte_vfw_counter_table[i].ct_counters;

              uint64_t average_internal_time =
                  vfw_ctrs->time_measurements ==
                  0 ? 0 : vfw_ctrs->internal_time_sum /
                  vfw_ctrs->time_measurements;
              uint64_t average_external_time =
                  vfw_ctrs->time_measurements ==
                  0 ? 0 : vfw_ctrs->external_time_sum /
                  vfw_ctrs->time_measurements;
              uint64_t average_pkts_in_batch =
                  vfw_ctrs->num_pkts_measurements ==
                  0 ? 0 : vfw_ctrs->num_batch_pkts_sum /
                  vfw_ctrs->num_pkts_measurements;
              uint64_t pkts_drop_fw = vfw_ctrs->pkts_drop_ttl +
                                   vfw_ctrs->pkts_drop_bad_size +
                                   vfw_ctrs->pkts_drop_fragmented +
                                   vfw_ctrs->pkts_drop_unsupported_type;

              mg_printf(conn, "{\"VFW_counters\" : {\"id\" : \"%s\", \" pkts_received\": %"
                     PRIu64 ", \" pkts_fw_forwarded\": %"
                     PRIu64 ", \" pkts_drop_fw\": %"
                     PRIu64 ", \" pkts_acl_forwarded\": %"
                     PRIu64 ", \"pkts_drop_without_rule\" : %"
                     PRIu64 ", \"average_pkts_in_batch\" : %"
                     PRIu64 ", \"average_internal_time_in_clocks\" : %"
                     PRIu64 ", \"average_external_time_in_clocks\" : %"
                     PRIu64 ", \"total_time_measures\" : %"
                     PRIu32 ", \"ct_packets_forwarded\" : %"
                     PRIu64 ", \"ct_packets_dropped\" : %"
                     PRIu64 ", \"bytes_processed \": %"
                     PRIu64 ", \"ct_sessions\" : {"
                     "\"active\" : %" PRIu64 ", \"open_attempt\" : %"
                     PRIu64 ", \"re-open_attempt\" : %"
                     PRIu64 ", \"established\" : %"
                     PRIu64 ", \"closed\" : %"
                     PRIu64 ", \"timeout\" : %"
                     PRIu64 "}, \"ct_drops\" : {"
                     "\"out_of_window\" : %" PRIu64 ", \"invalid_conn\" : %"
                     PRIu64 ", \"invalid_state_transition\" : %"
                     PRIu64 " \"RST\" : %"
                     PRIu64 "}}\n",
                     vfw_ctrs->name,
                     vfw_ctrs->pkts_received,
                     vfw_ctrs->pkts_fw_forwarded,
                     pkts_drop_fw,
                     vfw_ctrs->pkts_acl_forwarded,
                     vfw_ctrs->pkts_drop_without_rule,
                     average_pkts_in_batch,
                     average_internal_time,
                     average_external_time,
                     vfw_ctrs->time_measurements,
                     ct_counters->pkts_forwarded,
                     ct_counters->pkts_drop,
                     vfw_ctrs->bytes_processed,
                     ct_counters->current_active_sessions,
                     ct_counters->sessions_activated,
                     ct_counters->sessions_reactivated,
                     ct_counters->sessions_established,
                     ct_counters->sessions_closed,
                     ct_counters->sessions_timedout,
                     ct_counters->pkts_drop_outof_window,
                     ct_counters->pkts_drop_invalid_conn,
                     ct_counters->pkts_drop_invalid_state,
                     ct_counters->pkts_drop_invalid_rst);

              vfw_counter_sums.bytes_processed +=
                  vfw_ctrs->bytes_processed;

              vfw_counter_sums.internal_time_sum +=
                  vfw_ctrs->internal_time_sum;
              vfw_counter_sums.external_time_sum +=
                  vfw_ctrs->external_time_sum;
              vfw_counter_sums.time_measurements +=
                  vfw_ctrs->time_measurements;

              vfw_counter_sums.pkts_drop_ttl += vfw_ctrs->pkts_drop_ttl;
              vfw_counter_sums.pkts_drop_bad_size +=
                  vfw_ctrs->pkts_drop_bad_size;
              vfw_counter_sums.pkts_drop_fragmented +=
                  vfw_ctrs->pkts_drop_fragmented;
              vfw_counter_sums.pkts_drop_unsupported_type +=
                  vfw_ctrs->pkts_drop_unsupported_type;
              vfw_counter_sums.pkts_drop_without_arp_entry +=
                  vfw_ctrs->pkts_drop_without_arp_entry;

              vfw_counter_sums.pkts_drop_without_rule +=
                  vfw_ctrs->pkts_drop_without_rule;
              vfw_counter_sums.pkts_received += vfw_ctrs->pkts_received;
              vfw_counter_sums.pkts_fw_forwarded +=
                     vfw_ctrs->pkts_fw_forwarded;
              vfw_counter_sums.pkts_acl_forwarded +=
                     vfw_ctrs->pkts_acl_forwarded;
              sum_pkts_drop_fw += pkts_drop_fw;
              ct_counter_sums.pkts_forwarded += ct_counters->pkts_forwarded;
              ct_counter_sums.pkts_drop += ct_counters->pkts_drop;
              ct_counter_sums.current_active_sessions +=
                  ct_counters->current_active_sessions;
              ct_counter_sums.sessions_activated +=
                  ct_counters->sessions_activated;
              ct_counter_sums.sessions_reactivated +=
                  ct_counters->sessions_reactivated;
              ct_counter_sums.sessions_established +=
                  ct_counters->sessions_established;
              ct_counter_sums.sessions_closed += ct_counters->sessions_closed;
              ct_counter_sums.sessions_timedout +=
                  ct_counters->sessions_timedout;
              ct_counter_sums.pkts_drop_invalid_conn +=
                  ct_counters->pkts_drop_invalid_conn;
              ct_counter_sums.pkts_drop_invalid_state +=
                  ct_counters->pkts_drop_invalid_state;
              ct_counter_sums.pkts_drop_invalid_rst +=
                  ct_counters->pkts_drop_invalid_rst;
              ct_counter_sums.pkts_drop_outof_window +=
                  ct_counters->pkts_drop_outof_window;

       }

       mg_printf(conn, "VFW TOTAL: pkts_received: %"
                     PRIu64 ", \"pkts_fw_forwarded\": %"
                     PRIu64 ", \"pkts_drop_fw\": %"
                     PRIu64 ", \"fw_drops\" : {"
                     "\"TTL_zero\" : %" PRIu64 ", \"bad_size\" : %"
                     PRIu64 ", \"fragmented_packet\" : %"
                     PRIu64 ", \"unsupported_packet_types\" : %"
                     PRIu64 ", \"no_arp_entry\" : %"
                     PRIu64 "}, \"pkts_acl_forwarded\": %"
                     PRIu64 ", \"pkts_drop_without_rule\": %"
                     PRIu64 ", \"packets_last_sec\" : %"
                     PRIu32 ", \"average_packets_per_sec\" : %"
                     PRIu32 ", \"bytes_last_sec\" : %"
                     PRIu32 ", \"average_bytes_per_sec\" : %"
                     PRIu32 ", \"bytes_processed \": %"
                     PRIu64 "\n",
                     vfw_counter_sums.pkts_received,
                     vfw_counter_sums.pkts_fw_forwarded,
                     sum_pkts_drop_fw,
                     vfw_counter_sums.pkts_drop_ttl,
                     vfw_counter_sums.pkts_drop_bad_size,
                     vfw_counter_sums.pkts_drop_fragmented,
                     vfw_counter_sums.pkts_drop_unsupported_type,
                     vfw_counter_sums.pkts_drop_without_arp_entry,
                     vfw_counter_sums.pkts_acl_forwarded,
                     vfw_counter_sums.pkts_drop_without_rule,
                     rte_vfw_performance_measures.pkts_last_second,
                     rte_vfw_performance_measures.ave_pkts_per_second,
                     rte_vfw_performance_measures.bytes_last_second,
                     rte_vfw_performance_measures.ave_bytes_per_second,
                     vfw_counter_sums.bytes_processed);

       mg_printf(conn, "\"CT TOTAL: ct_packets_forwarded\" : %"
                     PRIu64 ", \" ct_packets_dropped\" : %"
                     PRIu64 ", \"ct_sessions\" : {"
                     "\"active\" : %" PRIu64 ", \"open_attempt\" : %"
                     PRIu64 ", \"re-open_attempt\" : %"
                     PRIu64 ", \"established\" : %"
                     PRIu64 ", \"closed\" : %"
                     PRIu64 ", \"timeout\" : %"
                     PRIu64 "}, \"ct_drops\" : {"
                     "\"out_of_window\" : %" PRIu64 ", \"invalid_conn\" : %"
                     PRIu64 ", \"invalid_state_transition\" : %"
                     PRIu64 " \"RST\" : %"
                     PRIu64 "}\n",
                     ct_counter_sums.pkts_forwarded,
                     ct_counter_sums.pkts_drop,
                     ct_counter_sums.current_active_sessions,
                     ct_counter_sums.sessions_activated,
                     ct_counter_sums.sessions_reactivated,
                     ct_counter_sums.sessions_established,
                     ct_counter_sums.sessions_closed,
                     ct_counter_sums.sessions_timedout,
                     ct_counter_sums.pkts_drop_outof_window,
                     ct_counter_sums.pkts_drop_invalid_conn,
                     ct_counter_sums.pkts_drop_invalid_state,
                     ct_counter_sums.pkts_drop_invalid_rst);

       for (i = 0; i <= rte_VFW_hi_counter_block_in_use; i++) {
              for (j = 0; j < action_array_max; j++) {
                     if (action_array_active[j].
                         action_bitmap & lib_acl_action_count) {
                            action_counter_sum[j].packetCount +=
                                action_counter_table[i][j].packetCount;
                            action_counter_sum[j].byteCount +=
                                action_counter_table[i][j].byteCount;
                     }
              }
       }

       for (j = 0; j < action_array_max; j++) {
              if (action_array_active[j].action_bitmap & lib_acl_action_count)
                     mg_printf(conn, "Action ID: %02u, packetCount: %" PRIu64
                            ", byteCount: %" PRIu64 "\n", j,
                            action_counter_sum[j].packetCount,
                            action_counter_sum[j].byteCount);
       }
       mg_printf(conn, "</body></html>");

       return 1;

}

int vfw_rules_handler(struct mg_connection *conn, __rte_unused void *cbdata)
{
 
        const struct mg_request_info *req_info = mg_get_request_info(conn);
	if (strcmp(req_info->request_method, "GET")) {
        	mg_printf(conn, "Only GET method allowed");
		return 1;
	}

        mg_printf(conn,
                 "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                 "close\r\n\r\n");
        mg_printf(conn, "<html><body>");
        mg_printf(conn, "<h2> These are the methods that are supported </h2>");
        mg_printf(conn, "<h3>     /load  </h3>");
        mg_printf(conn, "<h3>     /clear </h3>");
        mg_printf(conn, "<html><body>");
	
        mg_printf(conn, "</body></html>\n");

	return 1;
}

static int vfw_field_found(const char *key,
            const char *filename,
            char *path,
            size_t pathlen,
            void *user_data)
{
        struct mg_connection *conn = (struct mg_connection *)user_data;

        mg_printf(conn, "\r\n\r\n%s:\r\n", key);
	mg_printf(conn, "Inside vfw_field_found %s \n", filename);

        if (filename && *filename) {
		snprintf(path, pathlen, "/tmp/%s", filename);
		int fd;

		mg_printf(conn, "path: %s\n", path);

		/* Make sure the file exists before clearing rules and actions */
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			mg_printf(conn, "Cannot open file \"%s\"\n", filename);
			return FORM_FIELD_STORAGE_GET;
		}
		close(fd);

		return FORM_FIELD_STORAGE_STORE;
	}
        
	return FORM_FIELD_STORAGE_GET;
}

static int vfw_field_get(const char *key, const char *value, size_t valuelen,
	 void *user_data)
{
        struct mg_connection *conn = (struct mg_connection *)user_data;

        if (key[0]) {
                mg_printf(conn, "%s = ", key);
        }
        mg_write(conn, value, valuelen);

        return 0;
}

static int vfw_field_stored(const char *path, long long file_size,
	 void *user_data)
{
        struct mg_connection *conn = (struct mg_connection *)user_data;
	int status;

        mg_printf(conn,
                  "stored as %s (%lu bytes)\r\n\r\n",
                  path,
                  (unsigned long)file_size);

	/* Clear all rules and actions */
	status = app_pipeline_vfw_clearrules(myapp);
	if (status != 0) {
		mg_printf(conn, "Command clearrules failed\n");
		return 1;
	}

	/* Process commands in script file */
	app_loadrules_file(pipe_cl->ctx, path);
	rules_loaded = 1;

        return 0;
}

int vfw_cmd_ver_handler(__rte_unused struct mg_connection *conn, __rte_unused void *cbdata)
{
        mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: "
                  "text/plain\r\nConnection: close\r\n\r\n");
        mg_printf(conn, "<html><body>");
	mg_printf(conn, "<p>Command Passed</p>");
        mg_printf(conn, "</body></html>\n");

	return 1;
}

int vfw_load_rules_handler(struct mg_connection *conn, __rte_unused void *cbdata)
{
        /* Handler may access the request info using mg_get_request_info */
	int ret;
        const struct mg_request_info *req_info = mg_get_request_info(conn);
        struct mg_form_data_handler fdh = {vfw_field_found, vfw_field_get,
						 vfw_field_stored, 0};

        /* It would be possible to check the request info here before calling
         * mg_handle_form_request. */
        (void)req_info;

        mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: "
                  "text/plain\r\nConnection: close\r\n\r\n");

        if (!strcmp(req_info->request_method, "GET")) {
		mg_printf(conn, "Rule file is %s\n", rules_loaded? "LOADED":"NOT LOADED");
	}

        if (strcmp(req_info->request_method, "PUT")) {
        	mg_printf(conn, "Only PUT method allowed");
		return 1;
	}

        fdh.user_data = (void *)conn;

        /* Call the form handler */
        mg_printf(conn, "Form data:");
        ret = mg_handle_form_request(conn, &fdh);
        mg_printf(conn, "\r\n%i fields found", ret);

        //mg_handle_form_request(conn, &fdh);
        //mg_printf(conn, "\r\n script file handled");
	//rules_loaded = 1;

        return 1;
}

void rest_api_vfw_init(struct mg_context *ctx, struct app_params *app)
{
	myapp = app;

	/* vFW commands */
	mg_set_request_handler(ctx, "/vnf/config/rules", vfw_rules_handler, 0);
	mg_set_request_handler(ctx, "/vnf/config/rules/load", vfw_load_rules_handler, 0);
	mg_set_request_handler(ctx, "/vnf/config/rules/clear", vfw_clearrules_handler, 0);
	mg_set_request_handler(ctx, "/vnf/stats", vfw_stats_handler, 0);
	mg_set_request_handler(ctx, "/vnf/status", vfw_cmd_ver_handler, 0);

}

cmdline_parse_inst_t cmd_vfw_synproxy = {
       .f = cmd_vfw_synproxy_flag_parsed,
       .data = NULL,
       .help_str = "VFW synproxy_flag",
       .tokens = {
              (void *)&cmd_vfw_synproxy_flag_p_string,
              (void *)&cmd_vfw_synproxy_flag_pipeline_id,
              (void *)&cmd_vfw_synproxy_flag_vfw_string,
              (void *)&cmd_vfw_synproxy_flag_string,
              (void *)&cmd_vfw_synproxy_flag,
              NULL,
       },
};

static cmdline_parse_ctx_t pipeline_cmds[] = {
#ifdef ACL_ENABLE
       (cmdline_parse_inst_t *) &cmd_vfw_add_ip,
       (cmdline_parse_inst_t *) &cmd_vfw_del_ip,
       (cmdline_parse_inst_t *) &cmd_vfw_dbg,
       (cmdline_parse_inst_t *) &cmd_vfw_clearrules,
       (cmdline_parse_inst_t *) &cmd_loadrules,
       (cmdline_parse_inst_t *) &cmd_vfw_ls,
       (cmdline_parse_inst_t *) &cmd_action_add_accept,
       (cmdline_parse_inst_t *) &cmd_action_del_accept,
       (cmdline_parse_inst_t *) &cmd_action_add_drop,
       (cmdline_parse_inst_t *) &cmd_action_del_drop,
       (cmdline_parse_inst_t *) &cmd_action_add_fwd,
       (cmdline_parse_inst_t *) &cmd_action_del_fwd,
       (cmdline_parse_inst_t *) &cmd_action_add_nat,
       (cmdline_parse_inst_t *) &cmd_action_del_nat,
       (cmdline_parse_inst_t *) &cmd_action_add_count,
       (cmdline_parse_inst_t *) &cmd_action_del_count,
       (cmdline_parse_inst_t *) &cmd_action_add_dscp,
       (cmdline_parse_inst_t *) &cmd_action_del_dscp,
       (cmdline_parse_inst_t *) &cmd_action_add_conntrack,
       (cmdline_parse_inst_t *) &cmd_action_del_conntrack,
       (cmdline_parse_inst_t *) &cmd_action_add_connexist,
       (cmdline_parse_inst_t *) &cmd_action_del_connexist,
       (cmdline_parse_inst_t *) &cmd_action_ls,
       (cmdline_parse_inst_t *) &cmd_vfw_applyruleset,
#endif
       (cmdline_parse_inst_t *) &cmd_vfw_stats,
       (cmdline_parse_inst_t *) &cmd_vfw_clearstats,
       (cmdline_parse_inst_t *) &cmd_vfw_per_sec_ctr_dump_stop,
       (cmdline_parse_inst_t *) &cmd_vfw_per_sec_ctr_dump_start,
       (cmdline_parse_inst_t *) &cmd_vfw_synproxy,
       (cmdline_parse_inst_t *) &cmd_vfw_firewall,
#ifndef ACL_ENABLE
       (cmdline_parse_inst_t *) &cmd_vfw_fw_conntrack,
#endif
       NULL,
};

static struct pipeline_fe_ops pipeline_vfw_fe_ops = {
       .f_init = app_pipeline_vfw_init,
       .f_free = app_pipeline_vfw_free,
       .cmds = pipeline_cmds,
};

struct pipeline_type pipeline_vfw = {
       .name = "VFW",
       .be_ops = &pipeline_vfw_be_ops,
       .fe_ops = &pipeline_vfw_fe_ops,
};
