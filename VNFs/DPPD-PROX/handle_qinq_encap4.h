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

#ifndef _HANDLE_QINQ_ENCAP4_H_
#define _HANDLE_QINQ_ENCAP4_H_

#include <rte_ip.h>
#include <rte_ether.h>

#include "log.h"
#include "prox_assert.h"
#include "etypes.h"
#include "mpls.h"
#include "task_init.h"

struct task_qinq_encap4 {
        struct task_base base;
        struct rte_table_hash  *cpe_table;
	uint16_t         qinq_tag;
	uint64_t         src_mac[PROX_MAX_PORTS];
	int              offload_crc;
        uint8_t          runtime_flags;
        uint8_t          *dscp;
        uint64_t         keys[64];
        struct rte_mbuf* fake_packets[64];
        uint64_t         cpe_timeout;
#ifdef ENABLE_EXTRA_USER_STATISTICS
        uint32_t        *stats_per_user;
	uint32_t 	n_users;
#endif
};

struct qinq_gre_entry {
	uint16_t svlan;
	uint16_t cvlan;
	uint32_t gre_id;
	uint32_t user;
	uint32_t rss; // RSS based on Toeplitz_hash(svlan and cvlan)
};

struct qinq_gre_map {
	uint32_t              count;
	struct qinq_gre_entry entries[0];
};

struct qinq_gre_map *get_qinq_gre_map(struct task_args *targ);

struct task_args;
struct prox_shared;

void init_qinq_gre_table(struct task_args *targ, struct qinq_gre_map *qinq_gre_map);
void init_qinq_gre_hash(struct task_args *targ, struct qinq_gre_map *qinq_gre_map);
void init_cpe4_table(struct task_args *targ);
void init_cpe4_hash(struct task_args *targ);

static inline uint8_t mpls_untag(struct rte_mbuf *mbuf)
{
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	const uint16_t eth_type = peth->ether_type;

	if (eth_type == ETYPE_MPLSU) {
		struct ether_hdr *pneweth = (struct ether_hdr *)rte_pktmbuf_adj(mbuf, 4);
		const struct mpls_hdr *mpls = (const struct mpls_hdr *)(peth + 1);

		if (mpls->bos == 0) {
			// Double MPLS tag
			pneweth = (struct ether_hdr *)rte_pktmbuf_adj(mbuf, 4);
			PROX_ASSERT(pneweth);
		}

		const struct ipv4_hdr *pip = (const struct ipv4_hdr *)(pneweth + 1);
		if ((pip->version_ihl >> 4) == 4) {
			pneweth->ether_type = ETYPE_IPv4;
			return 1;
		}
		else if ((pip->version_ihl >> 4) == 6) {
			pneweth->ether_type = ETYPE_IPv6;
			return 1;
		}

		plog_info("Error removing MPLS: unexpected IP version: %d\n", pip->version_ihl >> 4);
		return 0;
	}
	if (eth_type != ETYPE_LLDP) {
		plog_info("Error Removing MPLS: ether_type = %#06x\n", eth_type);
	}
	return 0;
}

#endif /* _HANDLE_QINQ_ENCAP4_H_ */
