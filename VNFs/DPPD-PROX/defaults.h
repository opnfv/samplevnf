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

#ifndef _DEFAULTS_H_
#define _DEFAULTS_H_

#include <rte_ether.h>

struct prox_cfg;
struct lcore_cfg;

void set_global_defaults(struct prox_cfg* prox_cfg);
void set_task_defaults(struct prox_cfg* prox_cfg, struct lcore_cfg* lcore_cfg_init);
void set_port_defaults(void);

#define MAX_PKT_BURST   64
#define MAX_RING_BURST	64
#define DUMP_PKT_LEN 128

#if MAX_RING_BURST < MAX_PKT_BURST
#error MAX_RING_BURST < MAX_PKT_BURST
#endif

#define NUM_VCPES               65536
#define GRE_BUCKET_ENTRIES      4
#define MAX_GRE                 (NUM_VCPES * GRE_BUCKET_ENTRIES)
#define MAX_RSS_QUEUE_BITS      9

#define PROX_VLAN_TAG_SIZE	4
#define MBUF_SIZE (ETHER_MAX_LEN + (unsigned)sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM +  2 * PROX_VLAN_TAG_SIZE)

#define PROX_MTU   ETHER_MAX_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN

#endif /* _DEFAULTS_H_ */
