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

#include <rte_ip.h>

#include "log.h"
#include "tx_pkt.h"
#include "task_base.h"
#include "task_init.h"
#include "mpls.h"
#include "defines.h"
#include "prefetch.h"
#include "qinq.h"
#include "prox_assert.h"
#include "etypes.h"

struct task_untag {
	struct task_base base;
	uint16_t         etype;
};

static void init_task_untag(struct task_base *tbase, __attribute__((unused)) struct task_args *targ)
{
	struct task_untag *task = (struct task_untag *)tbase;
	task->etype = targ->etype;
}

static inline uint8_t handle_untag(struct task_untag *task, struct rte_mbuf *mbuf);

static int handle_untag_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_untag *task = (struct task_untag *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint16_t j;

	prefetch_first(mbufs, n_pkts);

	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef PROX_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		out[j] = handle_untag(task, mbufs[j]);
	}
#ifdef PROX_PREFETCH_OFFSET
	PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		out[j] = handle_untag(task, mbufs[j]);
	}
#endif

	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static inline uint8_t untag_mpls(struct rte_mbuf *mbuf, struct ether_hdr *peth)
{
	struct ether_hdr *pneweth = (struct ether_hdr *)rte_pktmbuf_adj(mbuf, 4);
	const struct mpls_hdr *mpls = (const struct mpls_hdr *)(peth + 1);
	const struct ipv4_hdr *pip = (const struct ipv4_hdr *)(mpls + 1);
	PROX_ASSERT(pneweth);

	if (mpls->bos == 0) {
		// Double MPLS tag
		pneweth = (struct ether_hdr *)rte_pktmbuf_adj(mbuf, 4);
		PROX_ASSERT(pneweth);
	}

	if ((pip->version_ihl >> 4) == 4) {
		pneweth->ether_type = ETYPE_IPv4;
		return 0;
	}
	else if ((pip->version_ihl >> 4) == 6) {
		pneweth->ether_type = ETYPE_IPv6;
		return 0;
	}

	plog_warn("Failed Decoding MPLS Packet - neither IPv4 neither IPv6: version %u\n", pip->version_ihl);
	return OUT_DISCARD;
}

static uint8_t untag_qinq(struct rte_mbuf *mbuf, struct qinq_hdr *qinq)
{
	if ((qinq->cvlan.eth_proto != ETYPE_VLAN)) {
		plog_warn("Unexpected proto in QinQ = %#04x\n", qinq->cvlan.eth_proto);
		return OUT_DISCARD;
	}

	rte_pktmbuf_adj(mbuf, sizeof(struct qinq_hdr) - sizeof(struct ether_hdr));
	return 0;
}

static inline uint8_t handle_untag(struct task_untag *task, struct rte_mbuf *mbuf)
{
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	const uint16_t etype = peth->ether_type;

	if (etype != task->etype) {
		plog_warn("Failed Removing %04x tag: ether_type = %#06x\n", task->etype, peth->ether_type);
		return OUT_DISCARD;
	}

	switch (etype) {
	case ETYPE_MPLSU:
		/* MPLS Decapsulation */
		return untag_mpls(mbuf, peth);
	case ETYPE_LLDP:
		return OUT_DISCARD;
	case ETYPE_IPv6:
		return 0;
	case ETYPE_IPv4:
		return 0;
	case ETYPE_8021ad:
	case ETYPE_VLAN:
		return untag_qinq(mbuf, (struct qinq_hdr *)peth);
	default:
		plog_warn("Failed untagging header: ether_type = %#06x is not supported\n", peth->ether_type);
		return OUT_DISCARD;
	}
}

static struct task_init task_init_untag = {
	.mode_str = "untag",
	.init = init_task_untag,
	.handle = handle_untag_bulk,
	.size = sizeof(struct task_untag)
};

__attribute__((constructor)) static void reg_task_untag(void)
{
	reg_task(&task_init_untag);
}
