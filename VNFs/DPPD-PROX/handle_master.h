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

#include "task_base.h"
#include "task_init.h"

enum arp_actions {
	UPDATE_FROM_CTRL,
	ARP_REQ_FROM_CTRL,
	ARP_REPLY_FROM_CTRL,
	ARP_TO_CTRL,
	REQ_MAC_TO_CTRL,
	MAX_ACTIONS
};

#define HANDLE_RANDOM_IP_FLAG	1
#define RANDOM_IP		0xffffffff

const char *actions_string[MAX_ACTIONS];

void init_ctrl_plane(struct task_base *tbase);

int (*handle_ctrl_plane)(struct task_base *tbase, struct rte_mbuf **mbuf, uint16_t n_pkts);

static inline void tx_drop(struct rte_mbuf *mbuf)
{
	rte_pktmbuf_free(mbuf);
}

void register_ip_to_ctrl_plane(struct task_base *task, uint32_t ip, uint8_t port_id, uint8_t core_id, uint8_t task_id);
