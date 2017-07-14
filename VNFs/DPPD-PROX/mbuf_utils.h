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

#ifndef _MBUF_UTILS_H_
#define _MBUF_UTILS_H_

#include <string.h>

#include <rte_ip.h>
#include <rte_version.h>
#include <rte_ether.h>

static void init_mbuf_seg(struct rte_mbuf *mbuf)
{
#if RTE_VERSION >= RTE_VERSION_NUM(1,8,0,0)
	mbuf->nb_segs = 1;
#else
	mbuf->pkt.nb_segs = 1;
#endif
	rte_mbuf_refcnt_set(mbuf, 1);
}

static uint16_t pkt_len_to_wire_size(uint16_t pkt_len)
{
	return (pkt_len < 60? 60 : pkt_len) + ETHER_CRC_LEN + 20;
}

static uint16_t mbuf_wire_size(const struct rte_mbuf *mbuf)
{
	uint16_t pkt_len = rte_pktmbuf_pkt_len(mbuf);

	return pkt_len_to_wire_size(pkt_len);
}

static uint16_t mbuf_calc_padlen(const struct rte_mbuf *mbuf, void *pkt, struct ipv4_hdr *ipv4)
{
	uint16_t pkt_len = rte_pktmbuf_pkt_len(mbuf);
	uint16_t ip_offset = (uint8_t *)ipv4 - (uint8_t*)pkt;
	uint16_t ip_total_len = rte_be_to_cpu_16(ipv4->total_length);

	return pkt_len - ip_total_len - ip_offset;
}

#endif /* _MBUF_UTILS_H_ */
