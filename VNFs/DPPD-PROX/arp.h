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

#ifndef _ARP_H_
#define _ARP_H_

#include <rte_ether.h>
#include "etypes.h"
#include "mbuf_utils.h"

#define ARP_REQUEST	0x100
#define ARP_REPLY	0x200

struct _arp_ipv4 {
	struct ether_addr sha; /* Sender hardware address */
	uint32_t spa;          /* Sender protocol address */
	struct ether_addr tha; /* Target hardware address */
	uint32_t tpa;          /* Target protocol address */
} __attribute__((__packed__));
typedef struct _arp_ipv4 arp_ipv4_t;

struct my_arp_t {
	uint16_t   htype;
	uint16_t   ptype;
	uint8_t    hlen;
	uint8_t    plen;
	uint16_t   oper;
	arp_ipv4_t data;
} __attribute__((__packed__));

struct ether_hdr_arp {
	struct ether_hdr ether_hdr;
	struct my_arp_t arp;
};

static int arp_is_gratuitous(struct ether_hdr_arp *hdr)
{
	return hdr->arp.data.spa == hdr->arp.data.tpa;
}

static inline void build_arp_reply(struct ether_hdr_arp *hdr_arp, struct ether_addr *s_addr)
{
	uint32_t ip_source = hdr_arp->arp.data.spa;

	memcpy(hdr_arp->ether_hdr.d_addr.addr_bytes, hdr_arp->ether_hdr.s_addr.addr_bytes, sizeof(struct ether_addr));
	memcpy(hdr_arp->ether_hdr.s_addr.addr_bytes, s_addr, sizeof(struct ether_addr));

	hdr_arp->arp.data.spa = hdr_arp->arp.data.tpa;
	hdr_arp->arp.data.tpa = ip_source;
	hdr_arp->arp.oper = 0x200;
	memcpy(&hdr_arp->arp.data.tha, &hdr_arp->arp.data.sha, sizeof(struct ether_addr));
	memcpy(&hdr_arp->arp.data.sha, s_addr, sizeof(struct ether_addr));
}

static inline void build_arp_request(struct rte_mbuf *mbuf, struct ether_addr *src_mac, uint32_t ip_dst, uint32_t ip_src)
{
	struct ether_hdr_arp *hdr_arp = rte_pktmbuf_mtod(mbuf, struct ether_hdr_arp *);
	uint64_t mac_bcast = 0xFFFFFFFFFFFF;
	rte_pktmbuf_pkt_len(mbuf) = 42;
	rte_pktmbuf_data_len(mbuf) = 42;
	init_mbuf_seg(mbuf);

	memcpy(&hdr_arp->ether_hdr.d_addr.addr_bytes, &mac_bcast, 6);
	memcpy(&hdr_arp->ether_hdr.s_addr.addr_bytes, src_mac, 6);
	hdr_arp->ether_hdr.ether_type = ETYPE_ARP;
	hdr_arp->arp.htype = 0x100,
	hdr_arp->arp.ptype = 0x0008;
	hdr_arp->arp.hlen = 6;
	hdr_arp->arp.plen = 4;
	hdr_arp->arp.oper = 0x100;
	hdr_arp->arp.data.spa = ip_src;
	hdr_arp->arp.data.tpa = ip_dst;
	memset(&hdr_arp->arp.data.tha, 0, sizeof(struct ether_addr));
	memcpy(&hdr_arp->arp.data.sha, src_mac, sizeof(struct ether_addr));
}

static void create_mac(struct ether_hdr_arp *hdr, struct ether_addr *addr)
{
        addr->addr_bytes[0] = 0x2;
        addr->addr_bytes[1] = 0;
        // Instead of sending a completely random MAC address, create the following MAC:
        // 02:00:x1:x2:x3:x4 where x1:x2:x3:x4 is the IP address
        memcpy(addr->addr_bytes + 2, (uint32_t *)&hdr->arp.data.tpa, 4);
}

#endif /* _ARP_H_ */
