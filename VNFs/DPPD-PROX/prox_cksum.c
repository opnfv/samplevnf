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

#include "prox_cksum.h"
#include "prox_port_cfg.h"
#include <rte_byteorder.h>
#include "log.h"

/* compute IP 16 bit checksum */
/* The hdr_checksum field must be set to 0 by the caller. */
inline void prox_ip_cksum_sw(struct ipv4_hdr *buf)
{
	const uint16_t size = sizeof(struct ipv4_hdr);
	uint32_t cksum = 0;
	uint32_t nb_dwords;
	uint32_t tail, mask;
	/* Defining pdwd as (uint32_t *) causes some optimization issues (gcc -O2).
	 In prox_ip_cksum(), hdr_checksum is set to 0, as expected by the code below,
	 but when *pdwd is plain uint32_t, GCC does not see the pointer aliasing on
	 the IPv4 header, optimizes this hdr_checksum initialization away, and hence
	 breaks the expectations of the checksum computation loop below.
	 The following typedef tells GCC that the IPv4 header may be aliased by
	 pdwd, which prevents GCC from removing the hdr_checksum = 0 assignment.
	*/
	typedef uint32_t __attribute__((__may_alias__)) uint32_may_alias;
	uint32_may_alias *pdwd = (uint32_may_alias *)buf;

	/* compute 16 bit checksum using hi and low parts of 32 bit integers */
	for (nb_dwords = (size >> 2); nb_dwords > 0; --nb_dwords) {
		cksum += (*pdwd >> 16);
		cksum += (*pdwd & 0xFFFF);
		++pdwd;
	}

	/* deal with the odd byte length */
	if (size & 0x03) {
		tail = *pdwd;
		/* calculate mask for valid parts */
		mask = 0xFFFFFFFF << ((size & 0x03) << 3);
		/* clear unused bits */
		tail &= ~mask;

		cksum += (tail >> 16) + (tail & 0xFFFF);
	}

	cksum = (cksum >> 16) + (cksum & 0xFFFF);
	cksum = (cksum >> 16) + (cksum & 0xFFFF);

	buf->hdr_checksum = ~((uint16_t)cksum);
}

static inline uint16_t calc_pseudo_checksum(uint8_t ipproto, uint16_t len, uint32_t src_ip_addr, uint32_t dst_ip_addr)
{
	uint32_t csum = 0;

	csum += (src_ip_addr >> 16) + (src_ip_addr & 0xFFFF);
	csum += (dst_ip_addr >> 16) + (dst_ip_addr & 0xFFFF);
	csum += rte_bswap16(ipproto) + rte_bswap16(len);
	csum = (csum >> 16) + (csum & 0xFFFF);
	return csum;
}

static inline void prox_write_udp_pseudo_hdr(struct udp_hdr *udp, uint16_t len, uint32_t src_ip_addr, uint32_t dst_ip_addr)
{
	/* Note that the csum is not complemented, while the pseaudo
	   header checksum is calculated as "... the 16-bit one's
	   complement of the one's complement sum of a pseudo header
	   of information ...", the psuedoheader forms as a basis for
	   the actual checksum calculated later either in software or
	   hardware. */
	udp->dgram_cksum = calc_pseudo_checksum(IPPROTO_UDP, len, src_ip_addr, dst_ip_addr);
}

static inline void prox_write_tcp_pseudo_hdr(struct tcp_hdr *tcp, uint16_t len, uint32_t src_ip_addr, uint32_t dst_ip_addr)
{
	tcp->cksum = calc_pseudo_checksum(IPPROTO_TCP, len, src_ip_addr, dst_ip_addr);
}

inline void prox_ip_udp_cksum(struct rte_mbuf *mbuf, struct ipv4_hdr *pip, uint16_t l2_len, uint16_t l3_len, int cksum_offload)
{
	prox_ip_cksum(mbuf, pip, l2_len, l3_len, cksum_offload & DEV_TX_OFFLOAD_IPV4_CKSUM);

	uint32_t l4_len = rte_bswap16(pip->total_length) - l3_len;
	if (pip->next_proto_id == IPPROTO_UDP) {
		struct udp_hdr *udp = (struct udp_hdr *)(((uint8_t*)pip) + l3_len);
#ifndef SOFT_CRC
		if (cksum_offload & DEV_TX_OFFLOAD_UDP_CKSUM) {
			mbuf->ol_flags |= PKT_TX_UDP_CKSUM;
			prox_write_udp_pseudo_hdr(udp, l4_len, pip->src_addr, pip->dst_addr);
		} else
#endif
		prox_udp_cksum_sw(udp, l4_len, pip->src_addr, pip->dst_addr);
	} else if (pip->next_proto_id == IPPROTO_TCP) {
		struct tcp_hdr *tcp = (struct tcp_hdr *)(((uint8_t*)pip) + l3_len);
#ifndef SOFT_CRC
		if (cksum_offload & DEV_TX_OFFLOAD_TCP_CKSUM) {
			prox_write_tcp_pseudo_hdr(tcp, l4_len, pip->src_addr, pip->dst_addr);
			mbuf->ol_flags |= PKT_TX_UDP_CKSUM;
		} else
#endif
		prox_tcp_cksum_sw(tcp, l4_len, pip->src_addr, pip->dst_addr);
	}
}

static inline uint16_t checksum_byte_seq(uint16_t *buf, uint16_t len)
{
	uint32_t csum = 0;

	while (len > 1) {
		csum += *buf;
		while (csum >> 16) {
			csum &= 0xffff;
			csum +=1;
		}
		buf++;
		len -= 2;
	}

	if (len) {
		csum += *(uint8_t*)buf;
		while (csum >> 16) {
			csum &= 0xffff;
			csum +=1;
		}
	}
	return ~csum;
}

inline void prox_udp_cksum_sw(struct udp_hdr *udp, uint16_t len, uint32_t src_ip_addr, uint32_t dst_ip_addr)
{
	prox_write_udp_pseudo_hdr(udp, len, src_ip_addr, dst_ip_addr);
	uint16_t csum = checksum_byte_seq((uint16_t *)udp, len);
	udp->dgram_cksum = csum;
}

inline void prox_tcp_cksum_sw(struct tcp_hdr *tcp, uint16_t len, uint32_t src_ip_addr, uint32_t dst_ip_addr)
{
	prox_write_tcp_pseudo_hdr(tcp, len, src_ip_addr, dst_ip_addr);

	uint16_t csum = checksum_byte_seq((uint16_t *)tcp, len);
	tcp->cksum = csum;
}
