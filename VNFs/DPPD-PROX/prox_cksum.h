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

#ifndef _PROX_CKSUM_H_
#define _PROX_CKSUM_H_

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <rte_version.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_mbuf.h>

#if RTE_VERSION >= RTE_VERSION_NUM(1,8,0,0)
#define CALC_TX_OL(l2_len, l3_len) ((uint64_t)(l2_len) | (uint64_t)(l3_len) << 7)
#else
#define CALC_TX_OL(l2_len, l3_len) (((uint64_t)(l2_len) << 9) | (uint64_t)(l3_len))
#endif

static void prox_ip_cksum_hw(struct rte_mbuf *mbuf, uint16_t l2_len, uint16_t l3_len)
{
#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
	mbuf->pkt.vlan_macip.data = CALC_TX_OL(l2_len, l3_len);
#else
	mbuf->tx_offload = CALC_TX_OL(l2_len, l3_len);
#endif
	mbuf->ol_flags |= PKT_TX_IP_CKSUM;
}

void prox_ip_cksum_sw(struct ipv4_hdr *buf);

static inline void prox_ip_cksum(struct rte_mbuf *mbuf, struct ipv4_hdr *buf, uint16_t l2_len, uint16_t l3_len, int offload)
{
	buf->hdr_checksum = 0;
#ifdef SOFT_CRC
	prox_ip_cksum_sw(buf);
#else
	if (offload)
		prox_ip_cksum_hw(mbuf, l2_len, l3_len);
	else {
		prox_ip_cksum_sw(buf);
		/* TODO: calculate UDP checksum */
	}
#endif
}

void prox_ip_udp_cksum(struct rte_mbuf *mbuf, struct ipv4_hdr *buf, uint16_t l2_len, uint16_t l3_len, int cksum_offload);

/* src_ip_addr/dst_ip_addr are in network byte order */
void prox_udp_cksum_sw(struct udp_hdr *udp, uint16_t len, uint32_t src_ip_addr, uint32_t dst_ip_addr);
void prox_tcp_cksum_sw(struct tcp_hdr *tcp, uint16_t len, uint32_t src_ip_addr, uint32_t dst_ip_addr);

#endif /* _PROX_CKSUM_H_ */
