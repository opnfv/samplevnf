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
#include <stdio.h>
#include <string.h>
#include <rte_version.h>

#include "prox_lua.h"
#include "prox_lua_types.h"

#include "lconf.h"
#include "task_base.h"
#include "task_init.h"
#include "defines.h"
#include "prefetch.h"
#include "qinq.h"
#include "prox_cfg.h"
#include "log.h"
#include "quit.h"
#include "prox_shared.h"
#include "mbuf_utils.h"
#include "handle_aggregator.h"

#define PRIORITY_DHCP	(HIGH_PRIORITY)

#define TASK_STATS_ADD_DROP_TX_FAIL_PRIO(stats, ntx, prio) do {    \
	(stats)->drop_tx_fail_prio[prio] += ntx;           \
	} while(0)
#define TASK_STATS_ADD_TX_PRIO(stats, ntx, prio) do {    \
                (stats)->rx_prio[prio] += ntx;           \
        } while(0)                                      \

static inline uint8_t detect_l4_priority(uint8_t l3_priority, const struct ipv4_hdr *ipv4_hdr)
{
	if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
		const struct udp_hdr *udp = (const struct udp_hdr *)((const uint8_t *)ipv4_hdr + sizeof(struct ipv4_hdr));
		if (((udp->src_port == 0x67) && (udp->dst_port == 0x68)) || ((udp->src_port == 0x68) && (udp->dst_port == 0x67))) {
			return PRIORITY_DHCP;
		}
	}
	return l3_priority;
}

static inline uint8_t detect_l3_priority(uint8_t l2_priority, const struct ipv4_hdr *ipv4_hdr)
{
	uint8_t dscp;
	if ((ipv4_hdr->version_ihl >> 4) == 4) {
	} else if ((ipv4_hdr->version_ihl >> 4) == 6) {
		plog_warn("IPv6 Not implemented\n");
		return OUT_DISCARD;
	} else {
		plog_warn("Unexpected IP version\n");
		return OUT_DISCARD;
	}
	dscp = ipv4_hdr->type_of_service >> 2;
	if (dscp)
		return MAX_PRIORITIES - dscp - 1;
	else
		return l2_priority;
}

static inline uint8_t detect_l2_priority(const struct qinq_hdr *pqinq)
{
	if (pqinq->cvlan.eth_proto != ETYPE_VLAN) {
		plog_warn("Unexpected proto in QinQ = %#04x\n", pqinq->cvlan.eth_proto);
		return OUT_DISCARD;
	}
	uint16_t svlan_priority = ntohs(pqinq->svlan.vlan_tci >> 13);
	uint16_t cvlan_priority = ntohs(pqinq->cvlan.vlan_tci >> 13);
	if (svlan_priority)
		return svlan_priority;
	else
		return cvlan_priority;
}

static inline void buffer_packet(struct task_aggregator *task, struct rte_mbuf *mbuf, uint8_t priority)
{
	struct task_base *tbase = (struct task_base *)task;

	struct task_buffer *prio = &task->priority[priority];
	if (prio->pkt_nb < BUFFER_LENGTH) {
		prio->buffer[prio->pkt_pos] = mbuf;
		prio->pkt_pos++;
		if (prio->pkt_pos == BUFFER_LENGTH)
			prio->pkt_pos = 0;
		prio->pkt_nb++;
	} else {
		task->drop.buffer[task->drop.pkt_nb] = mbuf;
		task->drop.pkt_nb++;
		TASK_STATS_ADD_DROP_TX_FAIL_PRIO(&task->stats, 1, priority);
	}
}

static inline void handle_aggregator(struct task_aggregator *task, struct rte_mbuf *mbuf)
{
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	uint8_t priority = 0;
	const struct qinq_hdr *pqinq;
	const struct ipv4_hdr *ipv4_hdr;

	const uint16_t eth_type = peth->ether_type;
	switch (eth_type) {
	case ETYPE_MPLSU:
	case ETYPE_MPLSM:
		break;
	case ETYPE_8021ad:
		pqinq = rte_pktmbuf_mtod(mbuf, const struct qinq_hdr *);
		if ((priority = detect_l2_priority(pqinq)) == OUT_DISCARD)
			break;
		ipv4_hdr = (const struct ipv4_hdr *)(pqinq + 1);
		if ((priority = detect_l3_priority(priority, ipv4_hdr)) == OUT_DISCARD)
			break;
		if ((priority = detect_l4_priority(priority, ipv4_hdr)) == OUT_DISCARD)
			break;
		break;
	case ETYPE_VLAN:
		break;
	case ETYPE_IPv4:
		ipv4_hdr = (const struct ipv4_hdr *)(peth+1);
		if ((priority = detect_l3_priority(LOW_PRIORITY, ipv4_hdr)) == OUT_DISCARD)
			break;
		if ((priority = detect_l4_priority(priority, ipv4_hdr)) == OUT_DISCARD)
			break;
		break;
	case ETYPE_IPv6:
		break;
	case ETYPE_ARP:
		break;
	default:
		break;
	}
	if (priority == OUT_DISCARD) {
		task->drop.buffer[task->drop.pkt_nb] = mbuf;
		task->drop.pkt_nb++;
		return;
	}
	buffer_packet(task, mbuf, priority);
}

static int handle_aggregator_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_aggregator *task = (struct task_aggregator *)tbase;

	uint16_t j;
	uint32_t drop_bytes = 0;
#ifdef PROX_PREFETCH_OFFSET
	for (j = 0; j < PROX_PREFETCH_OFFSET && j < n_pkts; ++j) {
		prefetch_nta(mbufs[j]);
	}
	for (j = 1; j < PROX_PREFETCH_OFFSET && j < n_pkts; ++j) {
		prefetch_nta(rte_pktmbuf_mtod(mbufs[j - 1], void *));
	}
#endif
	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef PROX_PREFETCH_OFFSET
		prefetch_nta(mbufs[j + PREFETCH_OFFSET]);
		prefetch_nta(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		handle_aggregator(task, mbufs[j]);
	}
#ifdef PROX_PREFETCH_OFFSET
	prefetch_nta(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		handle_aggregator(task, mbufs[j]);
	}
#endif

	for (int i = 0 ; i < task->drop.pkt_nb; i++) {
		drop_bytes += mbuf_wire_size(task->drop.buffer[i]);
		rte_pktmbuf_free(task->drop.buffer[i]);
	}
	TASK_STATS_ADD_DROP_TX_FAIL(&tbase->aux->stats, task->drop.pkt_nb);
	TASK_STATS_ADD_DROP_BYTES(&tbase->aux->stats, drop_bytes);
	task->drop.pkt_nb = 0;

	for (int priority = 0; priority < MAX_PRIORITIES; priority++) {
		struct task_buffer *prio = &task->priority[priority];
		if (prio->pkt_nb) {
			uint8_t n = 0;
			if (prio->pkt_pos > prio->pkt_nb) {
				struct rte_mbuf **buf = prio->buffer + prio->pkt_pos - prio->pkt_nb;
				n = tbase->aux->tx_pkt_try(&task->base, buf, prio->pkt_nb);
			} else {
				struct rte_mbuf **buf = prio->buffer + BUFFER_LENGTH + prio->pkt_pos - prio->pkt_nb;
				n = tbase->aux->tx_pkt_try(&task->base, buf, prio->pkt_nb - prio->pkt_pos);
				if (n == (prio->pkt_nb - prio->pkt_pos))
					n += tbase->aux->tx_pkt_try(&task->base, prio->buffer, prio->pkt_pos);
			}
			prio->pkt_nb -=n;
			TASK_STATS_ADD_TX_PRIO(&task->stats, n, priority);
			if (prio->pkt_nb)
				break;
		}
	}
	return 0;
}

static void init_task_aggregator(struct task_base *tbase, struct task_args *targ)
{
	struct task_aggregator *task = (struct task_aggregator *)tbase;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);
}

static struct task_init task_init_aggregator = {
	.mode_str = "aggreg",
	.init = init_task_aggregator,
	.handle = handle_aggregator_bulk,
	.flag_features = TASK_FEATURE_NEVER_DISCARDS,
	.size = sizeof(struct task_aggregator)
};

__attribute__((constructor)) static void reg_task_aggregator(void)
{
	reg_task(&task_init_aggregator);
}
