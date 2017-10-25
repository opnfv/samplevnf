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

#ifndef _RX_PKT_H_
#define _RX_PKT_H_

#include <inttypes.h>

struct rte_mbuf;
struct task_base;
struct rte_ring;

uint16_t rx_pkt_hw(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_hw_pow2(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_hw1(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_hw_l3(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_hw_pow2_l3(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_hw1_l3(struct task_base *tbase, struct rte_mbuf ***mbufs);

/* The _multi variation of the function is used to work-around the
   problem with QoS, multi-seg mbufs and vector PMD. When vector
   PMD returns more than 32 packets, the two variations of the
   receive function can be merged back together. */
uint16_t rx_pkt_hw_multi(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_hw_pow2_multi(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_hw1_multi(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_hw_multi_l3(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_hw_pow2_multi_l3(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_hw1_multi_l3(struct task_base *tbase, struct rte_mbuf ***mbufs);

uint16_t rx_pkt_sw(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_sw_pow2(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_sw1(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_self(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_dummy(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_dump(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_trace(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_distr(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_bw(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_tsc(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t rx_pkt_all(struct task_base *tbase, struct rte_mbuf ***mbufs);
uint16_t ring_deq(struct rte_ring *r, struct rte_mbuf **mbufs);

#endif /* _RX_PKT_H_ */
