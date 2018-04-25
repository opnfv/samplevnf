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
#include <rte_udp.h>

#include "task_init.h"
#include "task_base.h"
#include "lconf.h"
#include "log.h"
#include "arp.h"
#include "handle_swap.h"
#include "prox_port_cfg.h"
#include "mpls.h"
#include "qinq.h"
#include "gre.h"
#include "prefetch.h"

struct task_swap {
	struct task_base base;
	uint8_t src_dst_mac[12];
	uint32_t runtime_flags;
};

static void write_src_and_dst_mac(struct task_swap *task, struct rte_mbuf *mbuf)
{
	struct ether_hdr *hdr;
	struct ether_addr mac;

	if (unlikely((task->runtime_flags & (TASK_ARG_DST_MAC_SET|TASK_ARG_SRC_MAC_SET)) == (TASK_ARG_DST_MAC_SET|TASK_ARG_SRC_MAC_SET))) {
		/* Source and Destination mac hardcoded */
		hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
              	rte_memcpy(hdr, task->src_dst_mac, sizeof(task->src_dst_mac));
	} else {
		hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
		if (likely((task->runtime_flags & TASK_ARG_SRC_MAC_SET) == 0)) {
			/* dst mac will be used as src mac */
			ether_addr_copy(&hdr->d_addr, &mac);
		}

		if (unlikely(task->runtime_flags & TASK_ARG_DST_MAC_SET))
			ether_addr_copy((struct ether_addr *)&task->src_dst_mac[0], &hdr->d_addr);
		else
			ether_addr_copy(&hdr->s_addr, &hdr->d_addr);

		if (unlikely(task->runtime_flags & TASK_ARG_SRC_MAC_SET)) {
			ether_addr_copy((struct ether_addr *)&task->src_dst_mac[6], &hdr->s_addr);
		} else {
			ether_addr_copy(&mac, &hdr->s_addr);
		}
	}
}
static inline int handle_arp_request(struct task_swap *task, struct ether_hdr_arp *hdr_arp, struct ether_addr *s_addr, uint32_t ip)
{
	if ((hdr_arp->arp.data.tpa == ip) || (ip == 0)) {
		build_arp_reply(hdr_arp, s_addr);
		return 0;
	} else if (task->runtime_flags & TASK_MULTIPLE_MAC) {
		struct ether_addr tmp_s_addr;
		create_mac(hdr_arp, &tmp_s_addr);
		build_arp_reply(hdr_arp, &tmp_s_addr);
		return 0;
	} else {
		plogx_dbg("Received ARP on unexpected IP %x, expecting %x\n", rte_be_to_cpu_32(hdr_arp->arp.data.tpa), rte_be_to_cpu_32(ip));
		return OUT_DISCARD;
	}
}

/*
 * swap mode does not send arp requests, so does not expect arp replies
 * Need to understand later whether we must send arp requests
 */
static inline int handle_arp_replies(struct task_swap *task, struct ether_hdr_arp *hdr_arp)
{
	return OUT_DISCARD;
}

static int handle_swap_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_swap *task = (struct task_swap *)tbase;
	struct ether_hdr *hdr;
	struct ether_addr mac;
	struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp_hdr;
	uint32_t ip;
	uint16_t port;
	uint8_t out[64] = {0};
	struct mpls_hdr *mpls;
	uint32_t mpls_len = 0;
	struct qinq_hdr *qinq;
	struct vlan_hdr *vlan;
	struct ether_hdr_arp *hdr_arp;
	uint16_t j;

	for (j = 0; j < n_pkts; ++j) {
		PREFETCH0(mbufs[j]);
	}
	for (j = 0; j < n_pkts; ++j) {
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j], void *));
	}

	for (uint16_t j = 0; j < n_pkts; ++j) {
		hdr = rte_pktmbuf_mtod(mbufs[j], struct ether_hdr *);
		switch (hdr->ether_type) {
		case ETYPE_MPLSU:
			mpls = (struct mpls_hdr *)(hdr + 1);
			while (!(mpls->bytes & 0x00010000)) {
				mpls++;
				mpls_len += sizeof(struct mpls_hdr);
			}
			mpls_len += sizeof(struct mpls_hdr);
			ip_hdr = (struct ipv4_hdr *)(mpls + 1);
			break;
		case ETYPE_8021ad:
			qinq = (struct qinq_hdr *)hdr;
			if (qinq->cvlan.eth_proto != ETYPE_VLAN) {
				plog_warn("Unexpected proto in QinQ = %#04x\n", qinq->cvlan.eth_proto);
				out[j] = OUT_DISCARD;
				continue;
			}
			ip_hdr = (struct ipv4_hdr *)(qinq + 1);
			break;
		case ETYPE_VLAN:
			vlan = (struct vlan_hdr *)(hdr + 1);
			if (vlan->eth_proto == ETYPE_IPv4) {
				ip_hdr = (struct ipv4_hdr *)(vlan + 1);
			} else if (vlan->eth_proto == ETYPE_VLAN) {
				vlan = (struct vlan_hdr *)(vlan + 1);
				if (vlan->eth_proto == ETYPE_IPv4) {
					ip_hdr = (struct ipv4_hdr *)(vlan + 1);
				}
				else if (vlan->eth_proto == ETYPE_IPv6) {
					plog_warn("Unsupported IPv6\n");
					out[j] = OUT_DISCARD;
					continue;
				}
				else {
					plog_warn("Unsupported packet type\n");
					out[j] = OUT_DISCARD;
					continue;
				}
			} else {
				plog_warn("Unsupported packet type\n");
				out[j] = OUT_DISCARD;
				continue;
			}
			break;
		case ETYPE_IPv4:
			ip_hdr = (struct ipv4_hdr *)(hdr + 1);
			break;
		case ETYPE_IPv6:
			plog_warn("Unsupported IPv6\n");
			out[j] = OUT_DISCARD;
			continue;
		case ETYPE_LLDP:
			out[j] = OUT_DISCARD;
			continue;
		default:
			plog_warn("Unsupported ether_type 0x%x\n", hdr->ether_type);
			out[j] = OUT_DISCARD;
			continue;
		}
		udp_hdr = (struct udp_hdr *)(ip_hdr + 1);
		ip = ip_hdr->dst_addr;
		ip_hdr->dst_addr = ip_hdr->src_addr;
		ip_hdr->src_addr = ip;
		if (ip_hdr->next_proto_id == IPPROTO_GRE) {
			struct gre_hdr *pgre = (struct gre_hdr *)(ip_hdr + 1);
			struct ipv4_hdr *inner_ip_hdr = ((struct ipv4_hdr *)(pgre + 1));
			ip = inner_ip_hdr->dst_addr;
			inner_ip_hdr->dst_addr = inner_ip_hdr->src_addr;
			inner_ip_hdr->src_addr = ip;
			udp_hdr = (struct udp_hdr *)(inner_ip_hdr + 1);
			port = udp_hdr->dst_port;
			udp_hdr->dst_port = udp_hdr->src_port;
			udp_hdr->src_port = port;
		} else {
			port = udp_hdr->dst_port;
			udp_hdr->dst_port = udp_hdr->src_port;
			udp_hdr->src_port = port;
		}
		write_src_and_dst_mac(task, mbufs[j]);
	}
	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static void init_task_swap(struct task_base *tbase, struct task_args *targ)
{
	struct task_swap *task = (struct task_swap *)tbase;
	struct ether_addr *src_addr, *dst_addr;

	/*
	 * The destination MAC of the outgoing packet is based on the config file:
	 *    - 'dst mac=xx:xx:xx:xx:xx:xx' => the pre-configured mac will be used as dst mac
	 *    - 'dst mac=packet'            => the src mac of the incoming packet is used as dst mac
	 *    - (default - no 'dst mac')    => the src mac from the incoming packet is used as dst mac
	 *
	 * The source MAC of the outgoing packet is based on the config file:
	 *    - 'src mac=xx:xx:xx:xx:xx:xx' => the pre-configured mac will be used as src mac
	 *    - 'src mac=packet'            => the dst mac of the incoming packet is used as src mac
	 *    - 'src mac=hw'                => the mac address of the tx port is used as src mac
	 *                                     An error is returned if there are no physical tx ports
	 *    - (default - no 'src mac')    => if there is physical tx port, the mac of that port is used as src mac
	 *    - (default - no 'src mac')       if there are no physical tx ports the dst mac of the incoming packet
	 */

	if (targ->flags & TASK_ARG_DST_MAC_SET) {
		dst_addr = &targ->edaddr;
		memcpy(&task->src_dst_mac[0], dst_addr, sizeof(*src_addr));
	}

	PROX_PANIC(targ->flags & TASK_ARG_DO_NOT_SET_SRC_MAC, "src mac must be set in swap mode, by definition => src mac=no is not supported\n");
	PROX_PANIC(targ->flags & TASK_ARG_DO_NOT_SET_DST_MAC, "dst mac must be set in swap mode, by definition => dst mac=no is not supported\n");

	if (targ->flags & TASK_ARG_SRC_MAC_SET) {
		src_addr =  &targ->esaddr;
		memcpy(&task->src_dst_mac[6], src_addr, sizeof(*dst_addr));
		plog_info("\t\tCore %d: src mac set from config file\n", targ->lconf->id);
	} else {
		if (targ->flags & TASK_ARG_HW_SRC_MAC)
			PROX_PANIC(targ->nb_txports == 0, "src mac set to hw but no tx port\n");
		if (targ->nb_txports) {
			src_addr = &prox_port_cfg[task->base.tx_params_hw.tx_port_queue[0].port].eth_addr;
			memcpy(&task->src_dst_mac[6], src_addr, sizeof(*dst_addr));
			targ->flags |= TASK_ARG_SRC_MAC_SET;
			plog_info("\t\tCore %d: src mac set from port\n", targ->lconf->id);
		}
	}
	task->runtime_flags = targ->flags;
}

static struct task_init task_init_swap = {
	.mode_str = "swap",
	.init = init_task_swap,
	.handle = handle_swap_bulk,
	.flag_features = TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS,
	.size = sizeof(struct task_swap),
};

static struct task_init task_init_swap_arp = {
	.mode_str = "swap",
	.sub_mode_str = "l3",
	.init = init_task_swap,
	.handle = handle_swap_bulk,
	.flag_features = TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS,
	.size = sizeof(struct task_swap),
};

__attribute__((constructor)) static void reg_task_swap(void)
{
	reg_task(&task_init_swap);
	reg_task(&task_init_swap_arp);
}
