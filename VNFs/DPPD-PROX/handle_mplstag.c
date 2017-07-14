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

#include "defines.h"
#include "hash_entry_types.h"
#include "mpls.h"
#include "prefetch.h"
#include "task_base.h"
#include "tx_pkt.h"
#include "task_init.h"
#include "prox_port_cfg.h"
#include "prox_cksum.h"
#include "thread_generic.h"
#include "prefetch.h"
#include "prox_assert.h"
#include "etypes.h"
#include "log.h"
#include "mbuf_utils.h"

struct task_unmpls {
	struct task_base base;
	uint8_t n_tags;
};

static void init_task_unmpls(__attribute__((unused)) struct task_base *tbase,
			     __attribute__((unused)) struct task_args *targ)
{
}

static inline uint8_t handle_unmpls(__attribute__((unused)) struct task_unmpls *task, struct rte_mbuf *mbuf)
{
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
        struct mpls_hdr *mpls = (struct mpls_hdr *)(peth + 1);
        uint32_t mpls_len = sizeof(struct mpls_hdr);
        while (!(mpls->bytes & 0x00010000)) {
                mpls++;
                mpls_len += sizeof(struct mpls_hdr);
        }
		uint32_t tot_eth_addr_len = 2*sizeof(struct ether_addr);
		rte_memcpy(((uint8_t *)peth) + mpls_len, peth, tot_eth_addr_len);
        struct ipv4_hdr *ip = (struct ipv4_hdr *)(mpls + 1);
        switch (ip->version_ihl >> 4) {
        case 4:
                peth = (struct ether_hdr *)rte_pktmbuf_adj(mbuf, mpls_len);
                peth->ether_type = ETYPE_IPv4;
                return 0;
        case 6:
                peth = (struct ether_hdr *)rte_pktmbuf_adj(mbuf, mpls_len);
                peth->ether_type = ETYPE_IPv6;
                return 0;
        default:
                plog_warn("Failed Decoding MPLS Packet - neither IPv4 nor IPv6: version %u\n", ip->version_ihl);
                return OUT_DISCARD;
        }
}

static int handle_unmpls_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
        struct task_unmpls *task = (struct task_unmpls *)tbase;
        uint8_t out[MAX_PKT_BURST];
        uint16_t j;
        prefetch_first(mbufs, n_pkts);
        for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef PROX_PREFETCH_OFFSET
                PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
                PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
                out[j] = handle_unmpls(task, mbufs[j]);
        }
#ifdef PROX_PREFETCH_OFFSET
        PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
        for (; j < n_pkts; ++j) {
                out[j] = handle_unmpls(task, mbufs[j]);
        }
#endif
        return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static struct task_init task_init_unmpls = {
	.mode_str = "unmpls",
	.init = init_task_unmpls,
	.handle = handle_unmpls_bulk,
	.thread_x = thread_generic,
	.size = sizeof(struct task_unmpls)
};

struct task_tagmpls {
	struct task_base base;
	uint8_t n_tags;
};

static void init_task_tagmpls(__attribute__((unused)) struct task_base *tbase,
			      __attribute__((unused)) struct task_args *targ)
{
}

static inline uint8_t handle_tagmpls(__attribute__((unused)) struct task_tagmpls *task, struct rte_mbuf *mbuf)
{
        struct ether_hdr *peth = (struct ether_hdr *)rte_pktmbuf_prepend(mbuf, 4);
        PROX_ASSERT(peth);
        rte_prefetch0(peth);
	uint32_t mpls = 0;

	uint32_t tot_eth_addr_len = 2*sizeof(struct ether_addr);
	rte_memcpy(peth, ((uint8_t *)peth) + sizeof(struct mpls_hdr), tot_eth_addr_len);
        *((uint32_t *)(peth + 1)) = mpls | 0x00010000; // Set BoS to 1
        peth->ether_type = ETYPE_MPLSU;
        return 0;
}

static int handle_tagmpls_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
        struct task_tagmpls *task = (struct task_tagmpls *)tbase;
        uint8_t out[MAX_PKT_BURST];
        uint16_t j;
        prefetch_first(mbufs, n_pkts);
        for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef PROX_PREFETCH_OFFSET
                PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
                PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
                out[j] = handle_tagmpls(task, mbufs[j]);
        }
#ifdef PROX_PREFETCH_OFFSET
        PREFETCH0(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
        for (; j < n_pkts; ++j) {
                out[j] = handle_tagmpls(task, mbufs[j]);
        }
#endif
        return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static struct task_init task_init_tagmpls = {
	.mode_str = "tagmpls",
	.init = init_task_tagmpls,
	.handle = handle_tagmpls_bulk,
	.size = sizeof(struct task_tagmpls)
};

__attribute__((constructor)) static void reg_task_mplstag(void)
{
	reg_task(&task_init_unmpls);
	reg_task(&task_init_tagmpls);
}
