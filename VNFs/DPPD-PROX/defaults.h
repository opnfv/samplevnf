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

#define MAX_PKT_SIZE	10000
#define MAX_PKT_BURST   64
#define MAX_RING_BURST	64
#define DUMP_PKT_LEN 	MAX_PKT_SIZE

#if MAX_RING_BURST < MAX_PKT_BURST
#error MAX_RING_BURST < MAX_PKT_BURST
#endif

#define NUM_VCPES               65536
#define GRE_BUCKET_ENTRIES      4
#define MAX_GRE                 (NUM_VCPES * GRE_BUCKET_ENTRIES)
#define MAX_RSS_QUEUE_BITS      9

#define PROX_VLAN_TAG_SIZE	4

/* MBUF_SIZE can be configured based on the following:
   - If only one segment is used ETH_TXQ_FLAGS_NOMULTSEGS can be used resulting
     in vector mode used for transmission hence higher performance
   - Only one segment is used by the rx function if the mbuf size is big enough
   - Bigger mbufs result in more memory used, hence slighly lower performance (DTLB misses)
   - Selecting the smaller mbuf is not obvious as pmds might behave slighly differently:
     - on ixgbe a 1526 + 256 mbuf size will cause any packets bigger than 1024 bytes to be segmented
     - on i40e a 1526 + 256 mbuf size will cause any packets bigger than 1408 bytes to be segmented
     - other pmds might have additional requirements
   As the performance decrease due to the usage of bigger mbuf is not very important, we prefer
   here to use  the same, bigger, mbuf size for all pmds, making the code easier to support.
   An mbuf size of 2048 + 128 + 128 + 8 can hold a 2048 packet, and only one segment will be used
   except if jumbo frames are enabled. +8 (VLAN) is needed for i40e (and maybe other pmds).
   TX_MBUF_SIZE is used for when transmitting only: in this case the mbuf size can be smaller.
*/
#define MBUF_SIZE (2048 + (unsigned)sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM + 2 * PROX_VLAN_TAG_SIZE)
#define TX_MBUF_SIZE (ETHER_MAX_LEN + (unsigned)sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM +  2 * PROX_VLAN_TAG_SIZE)

#define PROX_MTU   ETHER_MAX_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN

#endif /* _DEFAULTS_H_ */
