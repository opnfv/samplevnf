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

#ifndef _TX_PKT_H_
#define _TX_PKT_H_

#include <inttypes.h>

struct task_base;
struct rte_mbuf;

void flush_queues_hw(struct task_base *tbase);
void flush_queues_sw(struct task_base *tbase);

void flush_queues_no_drop_hw(struct task_base *tbase);
void flush_queues_no_drop_sw(struct task_base *tbase);

/* The following four transmit functions always send packets to the
   single output unless the packet should be dropped. These functions
   are used if (1) the task is only sending to one destination and
   (2), packets can potentially be dropped (as specified by the out
   parameter, which is either NO_PORT_AVAIL or 0). */
int tx_pkt_no_drop_hw1(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);
int tx_pkt_no_drop_sw1(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);
int tx_pkt_hw1(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);
int tx_pkt_sw1(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);

/* The following four transmit functions are used if (1) the task is
   only sending to one destination and (2), packets are never dropped
   by the task (the out parameter is ignored). */
int tx_pkt_no_drop_never_discard_hw1_lat_opt(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);
int tx_pkt_no_drop_never_discard_hw1_thrpt_opt(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);
int tx_pkt_no_drop_never_discard_hw1_no_pointer(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);
int tx_pkt_no_drop_never_discard_sw1(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);
int tx_pkt_never_discard_hw1_lat_opt(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);
int tx_pkt_never_discard_hw1_thrpt_opt(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);
int tx_pkt_never_discard_sw1(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);

/* The two "self" transmit functions are used if the task is
   transmitting to another task running on the same core and the
   destination task ID is one higher than the current task. The never_discard
   version of the function ignores the out parameter and should
   therefor only be used if the task never discards packets.*/
int tx_pkt_self(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);
int tx_pkt_never_discard_self(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts, uint8_t *out);

/* The following four tarnsmit functions are the most general. They
   are used if (1) packets can be dropped and (2) there are multiple
   outputs in the task. */
int tx_pkt_no_drop_hw(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out);
int tx_pkt_no_drop_sw(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out);
int tx_pkt_hw(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out);
int tx_pkt_sw(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out);
int tx_ctrlplane_hw(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out);
int tx_ctrlplane_sw(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out);

int tx_pkt_trace(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out);
int tx_pkt_dump(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out);
int tx_pkt_distr(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out);
int tx_pkt_bw(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out);

uint16_t tx_try_sw1(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts);
uint16_t tx_try_hw1(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts);
uint16_t tx_try_self(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts);

/* When there are no output ports, this function is configured as the
   tx function. This tx function can be used to make each task a
   sink. */
int tx_pkt_drop_all(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out);
int tx_pkt_l3(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts, uint8_t *out);

void tx_ring_cti(struct task_base *tbase, struct rte_ring *ring, uint16_t command, struct rte_mbuf *mbuf, uint8_t core_id, uint8_t task_id, uint32_t ip);
void tx_ring_ip(struct task_base *tbase, struct rte_ring *ring, uint16_t command, struct rte_mbuf *mbuf, uint32_t ip);
void tx_ring(struct task_base *tbase, struct rte_ring *ring, uint16_t command, struct rte_mbuf *mbuf);

#endif /* _TX_PKT_H_ */
