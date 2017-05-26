/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __L3FWD_LPM_SSE_H__
#define __L3FWD_LPM_SSE_H__

#include "l3fwd_sse.h"

static inline __attribute__((always_inline)) uint16_t
lpm_get_dst_port(const struct lcore_conf *qconf, struct rte_mbuf *pkt,
		uint8_t portid)
{
	uint32_t next_hop_ipv4;
	uint8_t next_hop_ipv6;
	struct ipv6_hdr *ipv6_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct ether_hdr *eth_hdr;

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
		ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);

		return (uint16_t) ((rte_lpm_lookup(qconf->ipv4_lookup_struct,
				rte_be_to_cpu_32(ipv4_hdr->dst_addr), &next_hop_ipv4) == 0) ?
						next_hop_ipv4 : portid);

	} else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
		ipv6_hdr = (struct ipv6_hdr *)(eth_hdr + 1);

		return (uint16_t) ((rte_lpm6_lookup(qconf->ipv6_lookup_struct,
				ipv6_hdr->dst_addr, &next_hop_ipv6) == 0)
				? next_hop_ipv6 : portid);

	}

	return portid;
}

/*
 * lpm_get_dst_port optimized routine for packets where dst_ipv4 is already
 * precalculated. If packet is ipv6 dst_addr is taken directly from packet
 * header and dst_ipv4 value is not used.
 */
static inline __attribute__((always_inline)) uint16_t
lpm_get_dst_port_with_ipv4(const struct lcore_conf *qconf, struct rte_mbuf *pkt,
	uint32_t dst_ipv4, uint8_t portid)
{
	uint32_t next_hop_ipv4;
	uint8_t next_hop_ipv6;
	struct ipv6_hdr *ipv6_hdr;
	struct ether_hdr *eth_hdr;

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
		return (uint16_t) ((rte_lpm_lookup(qconf->ipv4_lookup_struct, dst_ipv4,
			&next_hop_ipv4) == 0) ? next_hop_ipv4 : portid);

	} else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
		ipv6_hdr = (struct ipv6_hdr *)(eth_hdr + 1);

		return (uint16_t) ((rte_lpm6_lookup(qconf->ipv6_lookup_struct,
				ipv6_hdr->dst_addr, &next_hop_ipv6) == 0)
				? next_hop_ipv6 : portid);

	}

	return portid;

}

/*
 * Read packet_type and destination IPV4 addresses from 4 mbufs.
 */
static inline void
processx4_step1(struct rte_mbuf *pkt[FWDSTEP],
		__m128i *dip,
		uint32_t *ipv4_flag)
{
	struct ipv4_hdr *ipv4_hdr;
	struct ether_hdr *eth_hdr;
	uint32_t x0, x1, x2, x3;

	eth_hdr = rte_pktmbuf_mtod(pkt[0], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	x0 = ipv4_hdr->dst_addr;
	ipv4_flag[0] = pkt[0]->packet_type & RTE_PTYPE_L3_IPV4;

	eth_hdr = rte_pktmbuf_mtod(pkt[1], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	x1 = ipv4_hdr->dst_addr;
	ipv4_flag[0] &= pkt[1]->packet_type;

	eth_hdr = rte_pktmbuf_mtod(pkt[2], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	x2 = ipv4_hdr->dst_addr;
	ipv4_flag[0] &= pkt[2]->packet_type;

	eth_hdr = rte_pktmbuf_mtod(pkt[3], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	x3 = ipv4_hdr->dst_addr;
	ipv4_flag[0] &= pkt[3]->packet_type;

	dip[0] = _mm_set_epi32(x3, x2, x1, x0);
}

/*
 * Lookup into LPM for destination port.
 * If lookup fails, use incoming port (portid) as destination port.
 */
static inline void
processx4_step2(const struct lcore_conf *qconf,
		__m128i dip,
		uint32_t ipv4_flag,
		uint8_t portid,
		struct rte_mbuf *pkt[FWDSTEP],
		uint16_t dprt[FWDSTEP])
{
	rte_xmm_t dst;
	const  __m128i bswap_mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11,
						4, 5, 6, 7, 0, 1, 2, 3);

	/* Byte swap 4 IPV4 addresses. */
	dip = _mm_shuffle_epi8(dip, bswap_mask);

	/* if all 4 packets are IPV4. */
	if (likely(ipv4_flag)) {
		rte_lpm_lookupx4(qconf->ipv4_lookup_struct, dip, dst.u32,
			portid);
		/* get rid of unused upper 16 bit for each dport. */
		dst.x = _mm_packs_epi32(dst.x, dst.x);
		*(uint64_t *)dprt = dst.u64[0];
	} else {
		dst.x = dip;
		dprt[0] = lpm_get_dst_port_with_ipv4(qconf, pkt[0], dst.u32[0], portid);
		dprt[1] = lpm_get_dst_port_with_ipv4(qconf, pkt[1], dst.u32[1], portid);
		dprt[2] = lpm_get_dst_port_with_ipv4(qconf, pkt[2], dst.u32[2], portid);
		dprt[3] = lpm_get_dst_port_with_ipv4(qconf, pkt[3], dst.u32[3], portid);
	}
}

/*
 * Buffer optimized handling of packets, invoked
 * from main_loop.
 */
static inline void
l3fwd_lpm_send_packets(int nb_rx, struct rte_mbuf **pkts_burst,
			uint8_t portid, struct lcore_conf *qconf)
{
	int32_t j;
	uint16_t dst_port[MAX_PKT_BURST];
	__m128i dip[MAX_PKT_BURST / FWDSTEP];
	uint32_t ipv4_flag[MAX_PKT_BURST / FWDSTEP];
	const int32_t k = RTE_ALIGN_FLOOR(nb_rx, FWDSTEP);

	for (j = 0; j != k; j += FWDSTEP)
		processx4_step1(&pkts_burst[j], &dip[j / FWDSTEP],
				&ipv4_flag[j / FWDSTEP]);

	for (j = 0; j != k; j += FWDSTEP)
		processx4_step2(qconf, dip[j / FWDSTEP],
				ipv4_flag[j / FWDSTEP], portid, &pkts_burst[j], &dst_port[j]);

	/* Classify last up to 3 packets one by one */
	switch (nb_rx % FWDSTEP) {
	case 3:
		dst_port[j] = lpm_get_dst_port(qconf, pkts_burst[j], portid);
		j++;
	case 2:
		dst_port[j] = lpm_get_dst_port(qconf, pkts_burst[j], portid);
		j++;
	case 1:
		dst_port[j] = lpm_get_dst_port(qconf, pkts_burst[j], portid);
		j++;
	}

	send_packets_multi(qconf, pkts_burst, dst_port, nb_rx);
}

#endif /* __L3FWD_LPM_SSE_H__ */
