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
#include "lib_acl.h"
#include "vnf_common.h"
#include <rte_port.h>
#define ACL_LIB_DEBUG 0
static struct rte_acl_field_def field_format_ipv4[] = {
	/* Protocol */
	[0] = {
				 .type = RTE_ACL_FIELD_TYPE_BITMASK,
				 .size = sizeof(uint8_t),
				 .field_index = 0,
				 .input_index = 0,
				 .offset = sizeof(struct ether_hdr) +
				 offsetof(struct ipv4_hdr, next_proto_id),
				 },

	/* Source IP address (IPv4) */
	[1] = {
				 .type = RTE_ACL_FIELD_TYPE_MASK,
				 .size = sizeof(uint32_t),
				 .field_index = 1,
				 .input_index = 1,
				 .offset = sizeof(struct ether_hdr) +
				 offsetof(struct ipv4_hdr, src_addr),
				 },

	/* Destination IP address (IPv4) */
	[2] = {
				 .type = RTE_ACL_FIELD_TYPE_MASK,
				 .size = sizeof(uint32_t),
				 .field_index = 2,
				 .input_index = 2,
				 .offset = sizeof(struct ether_hdr) +
				 offsetof(struct ipv4_hdr, dst_addr),
				 },

	/* Source Port */
	[3] = {
				 .type = RTE_ACL_FIELD_TYPE_RANGE,
				 .size = sizeof(uint16_t),
				 .field_index = 3,
				 .input_index = 3,
				 .offset = sizeof(struct ether_hdr) +
				 sizeof(struct ipv4_hdr) + offsetof(struct tcp_hdr, src_port),
				 },

	/* Destination Port */
	[4] = {
				 .type = RTE_ACL_FIELD_TYPE_RANGE,
				 .size = sizeof(uint16_t),
				 .field_index = 4,
				 .input_index = 3,
				 .offset = sizeof(struct ether_hdr) +
				 sizeof(struct ipv4_hdr) + offsetof(struct tcp_hdr, dst_port),
				 },
};

#define SIZEOF_VLAN_HDR                          4

static struct rte_acl_field_def field_format_vlan_ipv4[] = {
	/* Protocol */
	[0] = {
				 .type = RTE_ACL_FIELD_TYPE_BITMASK,
				 .size = sizeof(uint8_t),
				 .field_index = 0,
				 .input_index = 0,
				 .offset = sizeof(struct ether_hdr) +
				 SIZEOF_VLAN_HDR + offsetof(struct ipv4_hdr, next_proto_id),
				 },

	/* Source IP address (IPv4) */
	[1] = {
				 .type = RTE_ACL_FIELD_TYPE_MASK,
				 .size = sizeof(uint32_t),
				 .field_index = 1,
				 .input_index = 1,
				 .offset = sizeof(struct ether_hdr) +
				 SIZEOF_VLAN_HDR + offsetof(struct ipv4_hdr, src_addr),
				 },

	/* Destination IP address (IPv4) */
	[2] = {
				 .type = RTE_ACL_FIELD_TYPE_MASK,
				 .size = sizeof(uint32_t),
				 .field_index = 2,
				 .input_index = 2,
				 .offset = sizeof(struct ether_hdr) +
				 SIZEOF_VLAN_HDR + offsetof(struct ipv4_hdr, dst_addr),
				 },

	/* Source Port */
	[3] = {
				 .type = RTE_ACL_FIELD_TYPE_RANGE,
				 .size = sizeof(uint16_t),
				 .field_index = 3,
				 .input_index = 3,
				 .offset = sizeof(struct ether_hdr) +
				 SIZEOF_VLAN_HDR +
				 sizeof(struct ipv4_hdr) + offsetof(struct tcp_hdr, src_port),
				 },

	/* Destination Port */
	[4] = {
				 .type = RTE_ACL_FIELD_TYPE_RANGE,
				 .size = sizeof(uint16_t),
				 .field_index = 4,
				 .input_index = 4,
				 .offset = sizeof(struct ether_hdr) +
				 SIZEOF_VLAN_HDR +
				 sizeof(struct ipv4_hdr) + offsetof(struct tcp_hdr, dst_port),
				 },
};

#define SIZEOF_QINQ_HEADER                       8

static struct rte_acl_field_def field_format_qinq_ipv4[] = {
	/* Protocol */
	[0] = {
				 .type = RTE_ACL_FIELD_TYPE_BITMASK,
				 .size = sizeof(uint8_t),
				 .field_index = 0,
				 .input_index = 0,
				 .offset = sizeof(struct ether_hdr) +
				 SIZEOF_QINQ_HEADER + offsetof(struct ipv4_hdr, next_proto_id),
				 },

	/* Source IP address (IPv4) */
	[1] = {
				 .type = RTE_ACL_FIELD_TYPE_MASK,
				 .size = sizeof(uint32_t),
				 .field_index = 1,
				 .input_index = 1,
				 .offset = sizeof(struct ether_hdr) +
				 SIZEOF_QINQ_HEADER + offsetof(struct ipv4_hdr, src_addr),
				 },

	/* Destination IP address (IPv4) */
	[2] = {
				 .type = RTE_ACL_FIELD_TYPE_MASK,
				 .size = sizeof(uint32_t),
				 .field_index = 2,
				 .input_index = 2,
				 .offset = sizeof(struct ether_hdr) +
				 SIZEOF_QINQ_HEADER + offsetof(struct ipv4_hdr, dst_addr),
				 },

	/* Source Port */
	[3] = {
				 .type = RTE_ACL_FIELD_TYPE_RANGE,
				 .size = sizeof(uint16_t),
				 .field_index = 3,
				 .input_index = 3,
				 .offset = sizeof(struct ether_hdr) +
				 SIZEOF_QINQ_HEADER +
				 sizeof(struct ipv4_hdr) + offsetof(struct tcp_hdr, src_port),
				 },

	/* Destination Port */
	[4] = {
				 .type = RTE_ACL_FIELD_TYPE_RANGE,
				 .size = sizeof(uint16_t),
				 .field_index = 4,
				 .input_index = 4,
				 .offset = sizeof(struct ether_hdr) +
				 SIZEOF_QINQ_HEADER +
				 sizeof(struct ipv4_hdr) + offsetof(struct tcp_hdr, dst_port),
				 },
};

static struct rte_acl_field_def field_format_ipv6[] = {
	/* Protocol */
	[0] = {
				 .type = RTE_ACL_FIELD_TYPE_BITMASK,
				 .size = sizeof(uint8_t),
				 .field_index = 0,
				 .input_index = 0,
				 .offset = sizeof(struct ether_hdr) +
				 offsetof(struct ipv6_hdr, proto),
				 },

	/* Source IP address (IPv6) */
	[1] = {
				 .type = RTE_ACL_FIELD_TYPE_MASK,
				 .size = sizeof(uint32_t),
				 .field_index = 1,
				 .input_index = 1,
				 .offset = sizeof(struct ether_hdr) +
				 offsetof(struct ipv6_hdr, src_addr),
				 },

	[2] = {
				 .type = RTE_ACL_FIELD_TYPE_MASK,
				 .size = sizeof(uint32_t),
				 .field_index = 2,
				 .input_index = 2,
				 .offset = sizeof(struct ether_hdr) +
				 offsetof(struct ipv6_hdr, src_addr) + sizeof(uint32_t),
				 },

	[3] = {
				 .type = RTE_ACL_FIELD_TYPE_MASK,
				 .size = sizeof(uint32_t),
				 .field_index = 3,
				 .input_index = 3,
				 .offset = sizeof(struct ether_hdr) +
				 offsetof(struct ipv6_hdr, src_addr) + 2 * sizeof(uint32_t),
				 },

	[4] = {
				 .type = RTE_ACL_FIELD_TYPE_MASK,
				 .size = sizeof(uint32_t),
				 .field_index = 4,
				 .input_index = 4,
				 .offset = sizeof(struct ether_hdr) +
				 offsetof(struct ipv6_hdr, src_addr) + 3 * sizeof(uint32_t),
				 },

	/* Destination IP address (IPv6) */
	[5] = {
				 .type = RTE_ACL_FIELD_TYPE_MASK,
				 .size = sizeof(uint32_t),
				 .field_index = 5,
				 .input_index = 5,
				 .offset = sizeof(struct ether_hdr) +
				 offsetof(struct ipv6_hdr, dst_addr),
				 },

	[6] = {
				 .type = RTE_ACL_FIELD_TYPE_MASK,
				 .size = sizeof(uint32_t),
				 .field_index = 6,
				 .input_index = 6,
				 .offset = sizeof(struct ether_hdr) +
				 offsetof(struct ipv6_hdr, dst_addr) + sizeof(uint32_t),
				 },

	[7] = {
				 .type = RTE_ACL_FIELD_TYPE_MASK,
				 .size = sizeof(uint32_t),
				 .field_index = 7,
				 .input_index = 7,
				 .offset = sizeof(struct ether_hdr) +
				 offsetof(struct ipv6_hdr, dst_addr) + 2 * sizeof(uint32_t),
				 },

	[8] = {
				 .type = RTE_ACL_FIELD_TYPE_MASK,
				 .size = sizeof(uint32_t),
				 .field_index = 8,
				 .input_index = 8,
				 .offset = sizeof(struct ether_hdr) +
				 offsetof(struct ipv6_hdr, dst_addr) + 3 * sizeof(uint32_t),
				 },

	/* Source Port */
	[9] = {
				 .type = RTE_ACL_FIELD_TYPE_RANGE,
				 .size = sizeof(uint16_t),
				 .field_index = 9,
				 .input_index = 9,
				 .offset = sizeof(struct ether_hdr) +
				 sizeof(struct ipv6_hdr) + offsetof(struct tcp_hdr, src_port),
				 },

	/* Destination Port */
	[10] = {
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = 10,
		.input_index = 9,
		.offset = sizeof(struct ether_hdr) +
		sizeof(struct ipv6_hdr) + offsetof(struct tcp_hdr, dst_port),
		},
};

void *lib_acl_create_active_standby_table_ipv4(uint8_t table_num,
		uint32_t *libacl_n_rules)
{
	printf("Create LIBACL active IPV4 Tables rte_socket_id(): %i\n",
			rte_socket_id());

	/* Create IPV4 LIBACL Rule Tables */
	struct rte_table_acl_params common_ipv4_table_libacl_params = {
		.name = "LIBACLIPV4A",
		.n_rules = *libacl_n_rules,
		.n_rule_fields = RTE_DIM(field_format_ipv4),
	};

	memcpy(common_ipv4_table_libacl_params.field_format,
			field_format_ipv4, sizeof(field_format_ipv4));

	uint32_t ipv4_entry_size = sizeof(struct lib_acl_table_entry);
	/* Create second IPV4 Table */
	if (table_num == 2)
		common_ipv4_table_libacl_params.name = "LIBACLIPV4B";
	return	rte_table_acl_ops.f_create(&common_ipv4_table_libacl_params,
			rte_socket_id(),
			ipv4_entry_size);


}

void *lib_acl_create_active_standby_table_ipv6(uint8_t table_num,
		uint32_t *libacl_n_rules)
{
	printf("Create LIBACL active IPV6 Tables rte_socket_id(): %i\n",
			rte_socket_id());
	/* Create IPV6 LIBACL Rule Tables */
	struct rte_table_acl_params common_ipv6_table_libacl_params = {
		.name = "LIBACLIPV6A",
		.n_rules = *libacl_n_rules,
		.n_rule_fields = RTE_DIM(field_format_ipv6),
	};

	memcpy(common_ipv6_table_libacl_params.field_format,
			field_format_ipv6, sizeof(field_format_ipv6));

	uint32_t ipv6_entry_size = sizeof(struct lib_acl_table_entry);
	/* Create second IPV6 table */
	if (table_num == 2)
		common_ipv6_table_libacl_params.name = "LIBACLIPV6B";
	return	rte_table_acl_ops.f_create(&common_ipv6_table_libacl_params,
			rte_socket_id(),
			ipv6_entry_size);


}
int lib_acl_parse_config(struct lib_acl *plib_acl,
		char *arg_name, char *arg_value,
		uint32_t *libacl_n_rules)
{
	uint32_t n_rules_present = 0;
	uint32_t pkt_type_present = 0;
	/* defaults */
	plib_acl->n_rules = DEFULT_NUM_RULE;
	*libacl_n_rules = DEFULT_NUM_RULE;
	plib_acl->n_rule_fields = RTE_DIM(field_format_ipv4);
	plib_acl->field_format = field_format_ipv4;
	plib_acl->field_format_size = sizeof(field_format_ipv4);
	if (strcmp(arg_name, "n_rules") == 0) {
		if (n_rules_present) {
			printf("n_rules_present");
			return -1;
		}
		n_rules_present = 1;

		plib_acl->n_rules = atoi(arg_value);
		*libacl_n_rules = atoi(arg_value);
		return 0;
	}
	if (strcmp(arg_name, "pkt_type") == 0) {
		if (pkt_type_present) {
			printf("pkt_type");
			return -1;
		}
		pkt_type_present = 1;

		/* ipv4 */
		if (strcmp(arg_value, "ipv4") == 0) {
			plib_acl->n_rule_fields =
				RTE_DIM(field_format_ipv4);
			plib_acl->field_format = field_format_ipv4;
			plib_acl->field_format_size =
				sizeof(field_format_ipv4);
			return 0;
		}

		/* vlan_ipv4 */
		if (strcmp(arg_value, "vlan_ipv4") == 0) {
			plib_acl->n_rule_fields =
				RTE_DIM(field_format_vlan_ipv4);
			plib_acl->field_format =
				field_format_vlan_ipv4;
			plib_acl->field_format_size =
				sizeof(field_format_vlan_ipv4);
			return 0;
		}

		/* qinq_ipv4 */
		if (strcmp(arg_value, "qinq_ipv4") == 0) {
			plib_acl->n_rule_fields =
				RTE_DIM(field_format_qinq_ipv4);
			plib_acl->field_format =
				field_format_qinq_ipv4;
			plib_acl->field_format_size =
				sizeof(field_format_qinq_ipv4);
			return 0;
		}

		/* ipv6 */
		if (strcmp(arg_value, "ipv6") == 0) {
			plib_acl->n_rule_fields =
				RTE_DIM(field_format_ipv6);
			plib_acl->field_format = field_format_ipv6;
			plib_acl->field_format_size =
				sizeof(field_format_ipv6);
			return 0;
		}
		/* other */
		printf("other");
		return -1;
	}
	/* Parameter not processed in this parse function */
	return 1;
}


/**
 * Main packet processing function.
 * 64 packet bit mask are used to identify which packets to forward.
 * Performs the following:
 *  - Burst lookup packets in the IPv4 ACL Rule Table.
 *  - Lookup Action Table, perform actions.
 *  - Burst lookup Connection Tracking, if enabled.
 *  - Lookup MAC address.
 *  - Set bit mask.
 *  - Packets with bit mask set are forwarded
 *
 * @param p
 *  A pointer to the pipeline.
 * @param pkts
 *  A pointer to a burst of packets.
 * @param n_pkts
 *  Number of packets to process.
 * @param arg
 *  A pointer to pipeline specific data.
 *
 * @return
 *  0 on success, negative on error.
 */
	uint64_t
lib_acl_ipv4_pkt_work_key(struct lib_acl *plib_acl,
	struct rte_mbuf **pkts, uint64_t pkts_mask,
	uint64_t *pkts_drop_without_rule,
	void *plib_acl_rule_table_ipv4_active,
	struct pipeline_action_key *action_array_active,
	struct action_counter_block (*p_action_counter_table)[action_array_max],
	uint64_t *conntrack_mask,
	uint64_t *connexist_mask)
{

	uint64_t lookup_hit_mask_ipv4 = 0;
	uint64_t lookup_miss_mask_ipv4 = 0;
	int status;

	if (ACL_LIB_DEBUG)
		printf("ACL IPV4 Lookup Mask Before = 0x%"PRIx64"\n",
				pkts_mask);
	status = rte_table_acl_ops.f_lookup(
			plib_acl_rule_table_ipv4_active,
			pkts, pkts_mask, &lookup_hit_mask_ipv4,
			(void **) plib_acl->plib_acl_entries_ipv4);
	if (status < 0)
		printf("Lookup Failed\n");
	if (ACL_LIB_DEBUG)
		printf("ACL IPV4 Lookup Mask After = 0x%"PRIx64"\n",
				lookup_hit_mask_ipv4);
	if (ACL_LIB_DEBUG)
		printf("ACL Lookup Mask After = 0x%"PRIx64"\n",
				lookup_hit_mask_ipv4);

	lookup_miss_mask_ipv4 = pkts_mask & (~lookup_hit_mask_ipv4);
	pkts_mask = lookup_hit_mask_ipv4;
	*pkts_drop_without_rule += __builtin_popcountll(lookup_miss_mask_ipv4);
	if (ACL_LIB_DEBUG)
		printf("pkt_work_acl_key pkts_drop: %" PRIu64 " n_pkts: %u\n",
				*pkts_drop_without_rule,
				__builtin_popcountll(lookup_miss_mask_ipv4));
	/* bitmap of packets left to process for ARP */
	uint64_t pkts_to_process = lookup_hit_mask_ipv4;

	for (; pkts_to_process;) {
		uint8_t pos = (uint8_t)__builtin_ctzll(pkts_to_process);
		/* bitmask representing only this packet */
		uint64_t pkt_mask = 1LLU << pos;
		/* remove this packet from remaining list */
		pkts_to_process &= ~pkt_mask;
		struct rte_mbuf *pkt = pkts[pos];



		struct lib_acl_table_entry *entry =
			(struct lib_acl_table_entry *)
			plib_acl->plib_acl_entries_ipv4[pos];
		uint16_t phy_port = entry->head.port_id;
		uint32_t action_id = entry->action_id;

		if (ACL_LIB_DEBUG)
			printf("action_id = %u\n", action_id);

		uint32_t dscp_offset = IP_START + IP_HDR_DSCP_OFST;

		if (action_array_active[action_id].action_bitmap &
				lib_acl_action_count) {
			p_action_counter_table
				[plib_acl->action_counter_index]
				[action_id].packetCount++;
			p_action_counter_table
				[plib_acl->action_counter_index]
				[action_id].byteCount +=
				rte_pktmbuf_pkt_len(pkt);
			if (ACL_LIB_DEBUG)
				printf("Action Count   Packet Count: %"
						PRIu64 "  Byte Count: %"
						PRIu64 "\n"
						, p_action_counter_table
						[plib_acl->action_counter_index]
						[action_id].packetCount,
						p_action_counter_table
						[plib_acl->action_counter_index]
						[action_id].byteCount);
		}

		if (action_array_active[action_id].action_bitmap &
				lib_acl_action_packet_drop) {

			/* Drop packet by changing the mask */
			if (ACL_LIB_DEBUG)
				printf("ACL before drop pkt_mask %"
						PRIx64", pkt_num %d\n",
						pkts_mask, pos);
			pkts_mask &= ~(1LLU << pos);
			(*pkts_drop_without_rule)++;
			if (ACL_LIB_DEBUG)
				printf("ACL after drop pkt_mask %" PRIx64
					", pkt_num %d, action_packet_drop %"
					PRIu64 "\n", pkts_mask, pos,
					*pkts_drop_without_rule);
		}

		if (action_array_active[action_id].action_bitmap &
				lib_acl_action_fwd) {
			phy_port = action_array_active[action_id].
				fwd_port;
			entry->head.port_id = phy_port;
			if (ACL_LIB_DEBUG)
				printf("Action FWD  Port ID: %"
						PRIu16"\n", phy_port);
		}

		if (action_array_active[action_id].action_bitmap &
				lib_acl_action_nat) {
			phy_port = action_array_active[action_id].
				nat_port;
			entry->head.port_id = phy_port;
			if (ACL_LIB_DEBUG)
				printf("Action NAT  Port ID: %"
						PRIu16"\n", phy_port);
		}

		if (action_array_active[action_id].action_bitmap &
				lib_acl_action_dscp) {

			/* Set DSCP priority */
			uint8_t *dscp = RTE_MBUF_METADATA_UINT8_PTR(pkt,
					dscp_offset);
			*dscp = action_array_active[action_id].
				dscp_priority << 2;
			if (ACL_LIB_DEBUG)
				printf("Action DSCP   DSCP Priority: %"
						PRIu16 "\n", *dscp);
		}

		if (action_array_active[action_id].action_bitmap &
				lib_acl_action_packet_accept) {
			if (ACL_LIB_DEBUG)
				printf("Action Accept\n");

			if (action_array_active[action_id].action_bitmap
					& lib_acl_action_conntrack) {

				/* Set conntrack bit for this pkt */
				*conntrack_mask |= pkt_mask;
				if (ACL_LIB_DEBUG)
					printf("ACL CT enabled: 0x%"
							PRIx64"  pkt_mask: 0x%"
							PRIx64"\n",
							*conntrack_mask,
							pkt_mask);
			}

			if (action_array_active[action_id].action_bitmap
					& lib_acl_action_connexist) {

				/* Set conntrack bit for this pkt */
				*conntrack_mask |= pkt_mask;

				/* Set connexist bit for this pkt for
				 * public -> private */
				/* Private -> public packet will open
				 * the connection */
				if (action_array_active[action_id].
						private_public ==
						lib_acl_public_private)
					*connexist_mask |= pkt_mask;

				if (ACL_LIB_DEBUG)
					printf("ACL Connexist ENB CT:0x%"
							PRIx64"  connexist: 0x%"
							PRIx64"  pkt_mask: 0x%"
							PRIx64"\n",
							*conntrack_mask,
							*connexist_mask,
							pkt_mask);
			}
		}

	}
	return pkts_mask;
}
/**
 * Main packet processing function.
 * 64 packet bit mask are used to identify which packets to forward.
 * Performs the following:
 *  - Burst lookup packets in the IPv6 ACL Rule Table.
 *  - Lookup Action Table, perform actions.
 *  - Burst lookup Connection Tracking, if enabled.
 *  - Lookup MAC address.
 *  - Set bit mask.
 *  - Packets with bit mask set are forwarded
 *
 * @param p
 *  A pointer to the pipeline.
 * @param pkts
 *  A pointer to a burst of packets.
 * @param n_pkts
 *  Number of packets to process.
 * @param arg
 *  A pointer to pipeline specific data.
 *
 * @return
 *  0 on success, negative on error.
 */
	uint64_t
lib_acl_ipv6_pkt_work_key(struct lib_acl *plib_acl,
	struct rte_mbuf **pkts, uint64_t pkts_mask,
	uint64_t *pkts_drop_without_rule,
	void *plib_acl_rule_table_ipv6_active,
	struct pipeline_action_key *action_array_active,
	struct action_counter_block (*p_action_counter_table)[action_array_max],
	uint64_t *conntrack_mask,
	uint64_t *connexist_mask)
{

	uint64_t lookup_hit_mask_ipv6 = 0;
	uint64_t lookup_miss_mask_ipv6 = 0;
	int status;


	if (ACL_LIB_DEBUG)
		printf("ACL IPV6 Lookup Mask Before = 0x%"PRIx64"\n",
				pkts_mask);
	status = rte_table_acl_ops.f_lookup(
			plib_acl_rule_table_ipv6_active,
			pkts, pkts_mask, &lookup_hit_mask_ipv6,
			(void **) plib_acl->plib_acl_entries_ipv6);
	if (status < 0)
		printf("Lookup Failed\n");
	if (ACL_LIB_DEBUG)
		printf("ACL IPV6 Lookup Mask After = 0x%"PRIx64"\n",
				lookup_hit_mask_ipv6);

	if (ACL_LIB_DEBUG)
		printf("ACL Lookup Mask After = 0x%"PRIx64"\n",
				lookup_hit_mask_ipv6);

	lookup_miss_mask_ipv6 = pkts_mask & (~lookup_hit_mask_ipv6);
	pkts_mask = lookup_hit_mask_ipv6;
	*pkts_drop_without_rule += __builtin_popcountll(lookup_miss_mask_ipv6);
	if (ACL_LIB_DEBUG)
		printf("pkt_work_acl_key pkts_drop: %" PRIu64 " n_pkts: %u\n",
				*pkts_drop_without_rule,
				__builtin_popcountll(lookup_miss_mask_ipv6));
	/* bitmap of packets left to process for ARP */
	uint64_t pkts_to_process = lookup_hit_mask_ipv6;

	for (; pkts_to_process;) {
		uint8_t pos = (uint8_t)__builtin_ctzll(pkts_to_process);
		/* bitmask representing only this packet */
		uint64_t pkt_mask = 1LLU << pos;
		/* remove this packet from remaining list */
		pkts_to_process &= ~pkt_mask;
		struct rte_mbuf *pkt = pkts[pos];


		struct lib_acl_table_entry *entry =
			(struct lib_acl_table_entry *)
			plib_acl->plib_acl_entries_ipv6[pos];
		uint16_t phy_port = entry->head.port_id;
		uint32_t action_id = entry->action_id;

		if (ACL_LIB_DEBUG)
			printf("action_id = %u\n", action_id);

		if (action_array_active[action_id].action_bitmap &
				lib_acl_action_count) {
			p_action_counter_table
				[plib_acl->action_counter_index]
				[action_id].packetCount++;
			p_action_counter_table
				[plib_acl->action_counter_index]
				[action_id].byteCount +=
				rte_pktmbuf_pkt_len(pkt);
			if (ACL_LIB_DEBUG)
				printf("Action Count   Packet Count: %"
						PRIu64 "  Byte Count: %"
						PRIu64 "\n",
						p_action_counter_table
						[plib_acl->action_counter_index]
						[action_id].packetCount,
						p_action_counter_table
						[plib_acl->action_counter_index]
						[action_id].byteCount);
		}

		if (action_array_active[action_id].action_bitmap &
				lib_acl_action_packet_drop) {
			/* Drop packet by changing the mask */
			if (ACL_LIB_DEBUG)
				printf("ACL before drop pkt_mask %"
						PRIx64", pkt_num %d\n",
						pkts_mask, pos);
			pkts_mask &= ~(1LLU << pos);
			(*pkts_drop_without_rule)++;
			if (ACL_LIB_DEBUG)
				printf("ACL after drop pkt_mask %" PRIx64
					", pkt_num %d, action_packet_drop %"
					PRIu64 "\n", pkts_mask, pos,
					*pkts_drop_without_rule);

		}

		if (action_array_active[action_id].action_bitmap &
				lib_acl_action_fwd) {
			phy_port = action_array_active[action_id].
				fwd_port;
			entry->head.port_id = phy_port;
			if (ACL_LIB_DEBUG)
				printf("Action FWD  Port ID: %"
						PRIu16"\n", phy_port);
		}

		if (action_array_active[action_id].action_bitmap &
				lib_acl_action_nat) {
			phy_port = action_array_active[action_id].
				nat_port;
			entry->head.port_id = phy_port;
			if (ACL_LIB_DEBUG)
				printf("Action NAT  Port ID: %"
						PRIu16"\n", phy_port);
		}

		if (action_array_active[action_id].action_bitmap &
				lib_acl_action_dscp) {

			/* Set DSCP priority */
			uint32_t dscp_offset = IP_START +
				IP_HDR_DSCP_OFST_IPV6;
			uint16_t *dscp = RTE_MBUF_METADATA_UINT16_PTR(
					pkt, dscp_offset);
			uint16_t temp = *dscp;
			uint16_t dscp_value = (rte_bswap16(temp) &
					0XF00F);
			uint8_t dscp_store =
				action_array_active
				[action_id].dscp_priority << 2;
			uint16_t dscp_temp = dscp_store;

			dscp_temp = dscp_temp << 4;
			*dscp = rte_bswap16(dscp_temp | dscp_value);
			if (ACL_LIB_DEBUG)
				printf("Action DSCP   DSCP Priority: %"
						PRIu16"\n", *dscp);
		}

		if (action_array_active[action_id].action_bitmap
				& lib_acl_action_packet_accept) {
			if (ACL_LIB_DEBUG)
				printf("Action Accept\n");

			if (action_array_active[action_id].action_bitmap
					& lib_acl_action_conntrack) {

				/* Set conntrack bit for this pkt */
				*conntrack_mask |= pkt_mask;
				if (ACL_LIB_DEBUG)
					printf("ACL CT enabled: 0x%"
							PRIx64" pkt_mask: 0x%"
							PRIx64"\n",
							*conntrack_mask,
							pkt_mask);
			}

			if (action_array_active[action_id].action_bitmap
					& lib_acl_action_connexist) {

				/* Set conntrack bit for this pkt */
				*conntrack_mask |= pkt_mask;

				/* Set connexist bit for this pkt for
				 * public -> private */
				/* Private -> public packet will open
				 * the connection */
				if (action_array_active[action_id].
						private_public ==
						lib_acl_public_private)
					*connexist_mask |= pkt_mask;

				if (ACL_LIB_DEBUG)
					printf("ACL Connexist ENB CT:0x%"
							PRIx64"  connexist: 0x%"
							PRIx64"  pkt_mask: 0x%"
							PRIx64"\n",
							*conntrack_mask,
							*connexist_mask,
							pkt_mask);
			}
		}
	}
	return pkts_mask;
}
