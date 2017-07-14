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

#include <rte_mbuf.h>
#include <rte_acl.h>
#include <rte_ip.h>
#include <rte_cycles.h>
#include <rte_version.h>

#include "prox_lua.h"
#include "prox_lua_types.h"

#include "log.h"
#include "quit.h"
#include "parse_utils.h"
#include "ip_subnet.h"
#include "handle_acl.h"
#include "acl_field_def.h"
#include "task_init.h"
#include "task_base.h"
#include "lconf.h"
#include "prefetch.h"
#include "etypes.h"

struct task_acl {
	struct task_base base;
	struct rte_acl_ctx *context;
	const uint8_t *ptuples[64];

	uint32_t       n_rules;
	uint32_t       n_max_rules;

	void           *field_defs;
	size_t         field_defs_size;
	uint32_t       n_field_defs;
};

static void set_tc(struct rte_mbuf *mbuf, uint32_t tc)
{
#if RTE_VERSION >= RTE_VERSION_NUM(1,8,0,0)
	uint32_t subport, pipe, traffic_class, queue;
	enum rte_meter_color color;

	rte_sched_port_pkt_read_tree_path(mbuf, &subport, &pipe, &traffic_class, &queue);
	color = rte_sched_port_pkt_read_color(mbuf);

	rte_sched_port_pkt_write(mbuf, subport, pipe, tc, queue, color);
#else
	struct rte_sched_port_hierarchy *sched =
		(struct rte_sched_port_hierarchy *) &mbuf->pkt.hash.sched;
	sched->traffic_class = tc;
#endif
}

static int handle_acl_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_acl *task = (struct task_acl *)tbase;
	uint32_t results[64];
	uint8_t out[MAX_PKT_BURST];
	uint16_t j;

#ifdef PROX_PREFETCH_OFFSET
	for (j = 0; j < PROX_PREFETCH_OFFSET && j < n_pkts; ++j) {
		PREFETCH0(mbufs[j]);
	}
	for (j = 1; j < PROX_PREFETCH_OFFSET && j < n_pkts; ++j) {
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j - 1], void *));
	}
#endif
	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef PROX_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		/* TODO: detect version_ihl != 0x45. Extract relevant
		   fields of that packet and point ptuples[j] to the
		   extracted verion. Note that this is very unlikely. */
		task->ptuples[j] = rte_pktmbuf_mtod(mbufs[j], uint8_t *);
	}
#ifdef PROX_PREFETCH_OFFSET
	PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		task->ptuples[j] = rte_pktmbuf_mtod(mbufs[j], uint8_t *);
	}
#endif

	rte_acl_classify(task->context, (const uint8_t **)task->ptuples, results, n_pkts, 1);

	for (uint8_t i = 0; i < n_pkts; ++i) {
		switch (results[i]) {
		default:
		case ACL_NOT_SET:
		case ACL_DROP:
			out[i] = OUT_DISCARD;
			break;
		case ACL_ALLOW:
			out[i] = 0;
		case ACL_RATE_LIMIT:
			set_tc(mbufs[i], 3);
			break;
		};
	}

	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static void acl_msg(struct task_base *tbase, void **data, uint16_t n_msgs)
{
	struct task_acl *task = (struct task_acl *)tbase;
	struct acl4_rule **new_rules = (struct acl4_rule **)data;
	uint16_t i;

	for (i = 0; i < n_msgs; ++i) {
		if (task->n_rules == task->n_max_rules) {
			plog_err("Failed to add %d rule%s (already at maximum number of rules (%d))",
				n_msgs - i, (n_msgs - i)? "s" : "", task->n_max_rules);
			break;
		}

		new_rules[i]->data.priority = ++task->n_rules;
		rte_acl_add_rules(task->context, (struct rte_acl_rule*) new_rules[i], 1);
	}

	/* No need to rebuild if no rules have been added */
	if (!i) {
		return ;
	}

	struct rte_acl_config acl_build_param;
	/* Perform builds */
	acl_build_param.num_categories = 1;

	acl_build_param.num_fields = task->n_field_defs;
	rte_memcpy(&acl_build_param.defs, task->field_defs, task->field_defs_size);

	int ret;
	PROX_PANIC((ret = rte_acl_build(task->context, &acl_build_param)),
		   "Failed to build ACL trie (%d)\n", ret);
}

static void init_task_acl(struct task_base *tbase, struct task_args *targ)
{
	struct task_acl *task = (struct task_acl *)tbase;
	int use_qinq = targ->flags & TASK_ARG_QINQ_ACL;

	char name[PATH_MAX];
	struct rte_acl_param acl_param;

	/* Create ACL contexts */
	snprintf(name, sizeof(name), "acl-%d-%d", targ->lconf->id, targ->task);

	if (use_qinq) {
		task->n_field_defs    = RTE_DIM(pkt_qinq_ipv4_udp_defs);
		task->field_defs      = pkt_qinq_ipv4_udp_defs;
		task->field_defs_size = sizeof(pkt_qinq_ipv4_udp_defs);
	} else {
		task->n_field_defs    = RTE_DIM(pkt_eth_ipv4_udp_defs);
		task->field_defs      = pkt_eth_ipv4_udp_defs;
		task->field_defs_size = sizeof(pkt_eth_ipv4_udp_defs);
	}

	acl_param.name = name;
	acl_param.socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	acl_param.rule_size = RTE_ACL_RULE_SZ(task->n_field_defs);
	acl_param.max_rule_num = targ->n_max_rules;

	task->n_max_rules = targ->n_max_rules;
	task->context = rte_acl_create(&acl_param);

	PROX_PANIC(task->context == NULL, "Failed to create ACL context\n");
	uint32_t free_rules = targ->n_max_rules;

	PROX_PANIC(!strcmp(targ->rules, ""), "No rule specified for ACL\n");

	int ret = lua_to_rules(prox_lua(), GLOBAL, targ->rules, task->context, &free_rules, use_qinq, targ->qinq_tag);
	PROX_PANIC(ret, "Failed to read rules from config:\n%s\n", get_lua_to_errors());
	task->n_rules = targ->n_max_rules - free_rules;

	plog_info("Configured %d rules\n", task->n_rules);

	if (task->n_rules) {
		struct rte_acl_config acl_build_param;
		/* Perform builds */
		acl_build_param.num_categories = 1;
#if RTE_VERSION >= RTE_VERSION_NUM(2,1,0,0)
		acl_build_param.max_size = 0;
#endif

		acl_build_param.num_fields = task->n_field_defs;
		rte_memcpy(&acl_build_param.defs, task->field_defs, task->field_defs_size);

		plog_info("Building trie structure\n");
		PROX_PANIC(rte_acl_build(task->context, &acl_build_param),
			   "Failed to build ACL trie\n");
	}

	targ->lconf->ctrl_timeout = freq_to_tsc(targ->ctrl_freq);
	targ->lconf->ctrl_func_m[targ->task] = acl_msg;
}

int str_to_rule(struct acl4_rule *rule, char** fields, int n_rules, int use_qinq)
{
	uint32_t svlan, svlan_mask;
	uint32_t cvlan, cvlan_mask;

	uint32_t ip_proto, ip_proto_mask;

	struct ip4_subnet ip_src;
	struct ip4_subnet ip_dst;

	uint32_t sport_lo, sport_hi;
	uint32_t dport_lo, dport_hi;

	enum acl_action class = ACL_NOT_SET;
	char class_str[24];

	PROX_PANIC(parse_int_mask(&svlan, &svlan_mask, fields[0]), "Error parsing svlan: %s\n", get_parse_err());
	PROX_PANIC(parse_int_mask(&cvlan, &cvlan_mask, fields[1]), "Error parsing cvlan: %s\n", get_parse_err());
	PROX_PANIC(parse_int_mask(&ip_proto, &ip_proto_mask, fields[2]), "Error parsing ip protocol: %s\n", get_parse_err());
	PROX_PANIC(parse_ip4_cidr(&ip_src, fields[3]), "Error parsing source IP subnet: %s\n", get_parse_err());
	PROX_PANIC(parse_ip4_cidr(&ip_dst, fields[4]), "Error parsing dest IP subnet: %s\n", get_parse_err());

	PROX_PANIC(parse_range(&sport_lo, &sport_hi, fields[5]), "Error parsing source port range: %s\n", get_parse_err());
	PROX_PANIC(parse_range(&dport_lo, &dport_hi, fields[6]), "Error parsing destination port range: %s\n", get_parse_err());

	PROX_PANIC(parse_str(class_str, fields[7], sizeof(class_str)), "Error parsing action: %s\n", get_parse_err());

	if (!strcmp(class_str, "drop")) {
		class = ACL_DROP;
	}
	else if (!strcmp(class_str, "allow")) {
		class = ACL_ALLOW;
	}
	else if (!strcmp(class_str, "rate limit")) {
		class = ACL_RATE_LIMIT;
	}
	else {
		plog_err("unknown class type: %s\n", class_str);
	}

	rule->data.userdata = class; /* allow, drop or ratelimit */
	rule->data.category_mask = 1;
	rule->data.priority = n_rules;

	/* Configuration for rules is done in little-endian so no bswap is needed here.. */

	rule->fields[0].value.u8 = ip_proto;
	rule->fields[0].mask_range.u8 = ip_proto_mask;
	rule->fields[1].value.u32 = ip_src.ip;
	rule->fields[1].mask_range.u32 = ip_src.prefix;

	rule->fields[2].value.u32 = ip_dst.ip;
	rule->fields[2].mask_range.u32 = ip_dst.prefix;

	rule->fields[3].value.u16 = sport_lo;
	rule->fields[3].mask_range.u16 = sport_hi;

	rule->fields[4].value.u16 = dport_lo;
	rule->fields[4].mask_range.u16 = dport_hi;

	if (use_qinq) {
		rule->fields[5].value.u16 = rte_bswap16(ETYPE_8021ad);
		rule->fields[5].mask_range.u16 = 0xffff;

		/* To mask out the TCI and only keep the VID, the mask should be 0x0fff */
		rule->fields[6].value.u16 = svlan;
		rule->fields[6].mask_range.u16 = svlan_mask;

		rule->fields[7].value.u16 = rte_bswap16(ETYPE_VLAN);
		rule->fields[7].mask_range.u16 = 0xffff;

		rule->fields[8].value.u16 = cvlan;
		rule->fields[8].mask_range.u16 = cvlan_mask;
	}
	else {
		/* Reuse first ethertype from vlan to check if packet is IPv4 packet */
		rule->fields[5].value.u16 =  rte_bswap16(ETYPE_IPv4);
		rule->fields[5].mask_range.u16 = 0xffff;

		/* Other fields are ignored */
		rule->fields[6].value.u16 = 0;
		rule->fields[6].mask_range.u16 = 0;
		rule->fields[7].value.u16 = 0;
		rule->fields[7].mask_range.u16 = 0;
		rule->fields[8].value.u16 = 0;
		rule->fields[8].mask_range.u16 = 0;
	}
	return 0;
}

static struct task_init task_init_acl = {
	.mode_str = "acl",
	.init = init_task_acl,
	.handle = handle_acl_bulk,
	.size = sizeof(struct task_acl)
};

__attribute__((constructor)) static void reg_task_acl(void)
{
	reg_task(&task_init_acl);
}
