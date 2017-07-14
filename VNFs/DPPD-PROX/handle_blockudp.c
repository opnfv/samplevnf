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
#include <rte_ether.h>

#include "task_base.h"
#include "task_init.h"
#include "defines.h"
#include "etypes.h"
#include "prefetch.h"
#include "log.h"

struct task_blockudp {
	struct task_base    base;
};

static int handle_blockudp_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_blockudp *task = (struct task_blockudp *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint16_t j;

	for (j = 0; j < n_pkts; ++j) {
		struct ether_hdr *peth = rte_pktmbuf_mtod(mbufs[j], struct ether_hdr *);
		struct ipv4_hdr *pip = (struct ipv4_hdr *) (peth + 1);
		out[j] = peth->ether_type == ETYPE_IPv4 && pip->next_proto_id == 0x11 ? OUT_DISCARD : 0;
	}

	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static void init_task_blockudp(__attribute__((unused)) struct task_base *tbase,
			   __attribute__((unused)) struct task_args *targ)
{
}

static struct task_init task_init_blockudp = {
	.mode_str = "blockudp",
	.init = init_task_blockudp,
	.handle = handle_blockudp_bulk,
	.size = sizeof(struct task_blockudp)
};

__attribute__((constructor)) static void reg_task_blockudp(void)
{
	reg_task(&task_init_blockudp);
}
