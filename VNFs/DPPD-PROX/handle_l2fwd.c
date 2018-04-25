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

#include "task_init.h"
#include "task_base.h"
#include "lconf.h"
#include "log.h"
#include "prox_port_cfg.h"

struct task_l2fwd {
	struct task_base base;
	uint8_t src_dst_mac[12];
	uint32_t runtime_flags;
};

static int handle_l2fwd_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_l2fwd *task = (struct task_l2fwd *)tbase;
	struct ether_hdr *hdr;
	struct ether_addr mac;

	if ((task->runtime_flags & (TASK_ARG_DST_MAC_SET|TASK_ARG_SRC_MAC_SET)) == (TASK_ARG_DST_MAC_SET|TASK_ARG_SRC_MAC_SET)) {
		/* Source and Destination mac hardcoded */
		for (uint16_t j = 0; j < n_pkts; ++j) {
			hdr = rte_pktmbuf_mtod(mbufs[j], struct ether_hdr *);
               		rte_memcpy(hdr, task->src_dst_mac, sizeof(task->src_dst_mac));
		}
	} else {
		for (uint16_t j = 0; j < n_pkts; ++j) {
			hdr = rte_pktmbuf_mtod(mbufs[j], struct ether_hdr *);
			if ((task->runtime_flags & (TASK_ARG_DO_NOT_SET_SRC_MAC|TASK_ARG_SRC_MAC_SET)) == 0) {
				/* dst mac will be used as src mac */
				ether_addr_copy(&hdr->d_addr, &mac);
			}

			if (task->runtime_flags & TASK_ARG_DST_MAC_SET)
				ether_addr_copy((struct ether_addr *)&task->src_dst_mac[0], &hdr->d_addr);
			else if ((task->runtime_flags & TASK_ARG_DO_NOT_SET_DST_MAC) == 0)
				ether_addr_copy(&hdr->s_addr, &hdr->d_addr);

			if (task->runtime_flags & TASK_ARG_SRC_MAC_SET) {
				ether_addr_copy((struct ether_addr *)&task->src_dst_mac[6], &hdr->s_addr);
			} else if ((task->runtime_flags & TASK_ARG_DO_NOT_SET_SRC_MAC) == 0) {
				ether_addr_copy(&mac, &hdr->s_addr);
			}
		}
	}
	return task->base.tx_pkt(&task->base, mbufs, n_pkts, NULL);
}

static void init_task_l2fwd(struct task_base *tbase, struct task_args *targ)
{
	struct task_l2fwd *task = (struct task_l2fwd *)tbase;
	struct ether_addr *src_addr, *dst_addr;

	/*
	 * The destination MAC of the outgoing packet is based on the config file:
	 *    - 'dst mac=xx:xx:xx:xx:xx:xx' => the pre-configured mac will be used as dst mac
	 *    - 'dst mac=packet'            => the src mac of the incoming packet is used as dst mac
	 *    - 'dst mac=no'                => the dst mac is untouched
	 *    - (default - no 'dst mac')    => the src mac from the incoming packet is used as dst mac
	 *
	 * The source MAC of the outgoing packet is based on the config file:
	 *    - 'src mac=xx:xx:xx:xx:xx:xx' => the pre-configured mac will be used as src mac
	 *    - 'src mac=packet'            => the dst mac of the incoming packet is used as src mac
	 *    - 'src mac=hw'                => the mac address of the tx port is used as src mac
	 *                                     An error is returned if there are no physical tx ports
	 *    - 'src mac=no'                => the src mac is untouched
	 *    - (default - no 'src mac')    => if there is physical tx port, the mac of that port is used as src mac
	 *    - (default - no 'src mac')       if there are no physical tx ports the dst mac of the incoming packet
                                                    is used as src mac
	 */

	if (targ->flags & TASK_ARG_DST_MAC_SET) {
		dst_addr = &targ->edaddr;
		memcpy(&task->src_dst_mac[0], dst_addr, sizeof(*src_addr));
	}

	if (targ->flags & TASK_ARG_SRC_MAC_SET) {
		src_addr =  &targ->esaddr;
		memcpy(&task->src_dst_mac[6], src_addr, sizeof(*dst_addr));
		plog_info("\t\tCore %d: src mac set from config file\n", targ->lconf->id);
	} else if ((targ->flags & TASK_ARG_DO_NOT_SET_SRC_MAC) == 0) {
		if (targ->flags & TASK_ARG_HW_SRC_MAC)
			PROX_PANIC(targ->nb_txports == 0, "src mac set to hw but no tx port\n");
		if (targ->nb_txports) {
			src_addr = &prox_port_cfg[task->base.tx_params_hw.tx_port_queue[0].port].eth_addr;
			targ->flags |= TASK_ARG_SRC_MAC_SET;
			plog_info("\t\tCore %d: src mac set from port\n", targ->lconf->id);
			memcpy(&task->src_dst_mac[6], src_addr, sizeof(*dst_addr));
		}
	}
	task->runtime_flags = targ->flags;
}

static struct task_init task_init_l2fwd = {
	.mode_str = "l2fwd",
	.init = init_task_l2fwd,
	.handle = handle_l2fwd_bulk,
	.flag_features = TASK_FEATURE_NEVER_DISCARDS|TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS,
	.size = sizeof(struct task_l2fwd),
};

__attribute__((constructor)) static void reg_task_l2fwd(void)
{
	reg_task(&task_init_l2fwd);
}
