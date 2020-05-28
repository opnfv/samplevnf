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
#include "prox_compat.h"
#include "etypes.h"
#include "mbuf_utils.h"

#define ARP_REQUEST	0x100
#define ARP_REPLY	0x200

struct _arp_ipv4 {
	prox_rte_ether_addr sha; /* Sender hardware address */
	uint32_t spa;          /* Sender protocol address */
	prox_rte_ether_addr tha; /* Target hardware address */
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
	prox_rte_ether_hdr ether_hdr;
	struct my_arp_t arp;
};

static int arp_is_gratuitous(struct my_arp_t *arp)
{
	return arp->data.spa == arp->data.tpa;
}

// This build an arp reply based on a an request
static inline void build_arp_reply(prox_rte_ether_hdr *ether_hdr, prox_rte_ether_addr *s_addr, struct my_arp_t *arp)
{
	uint32_t ip_source = arp->data.spa;

	memcpy(ether_hdr->d_addr.addr_bytes, ether_hdr->s_addr.addr_bytes, sizeof(prox_rte_ether_addr));
	memcpy(ether_hdr->s_addr.addr_bytes, s_addr, sizeof(prox_rte_ether_addr));

	arp->data.spa = arp->data.tpa;
	arp->data.tpa = ip_source;
	arp->oper = 0x200;
	memcpy(&arp->data.tha, &arp->data.sha, sizeof(prox_rte_ether_addr));
	memcpy(&arp->data.sha, s_addr, sizeof(prox_rte_ether_addr));
}

static inline void build_arp_request(struct rte_mbuf *mbuf, prox_rte_ether_addr *src_mac, uint32_t ip_dst, uint32_t ip_src, uint16_t vlan)
{
	struct ether_hdr_arp *hdr_arp;
	prox_rte_vlan_hdr *vlan_hdr;
	prox_rte_ether_hdr *ether_hdr;
	struct my_arp_t *arp;
	uint64_t mac_bcast = 0xFFFFFFFFFFFF;
	init_mbuf_seg(mbuf);

	if (vlan) {
		ether_hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
		vlan_hdr = (prox_rte_vlan_hdr *)(ether_hdr + 1);
		arp = (struct my_arp_t *)(vlan_hdr + 1);
		ether_hdr->ether_type = ETYPE_VLAN;
		vlan_hdr->eth_proto = ETYPE_ARP;
		vlan_hdr->vlan_tci = rte_cpu_to_be_16(vlan);
		rte_pktmbuf_pkt_len(mbuf) = 42 + sizeof(prox_rte_vlan_hdr);
		rte_pktmbuf_data_len(mbuf) = 42 + sizeof(prox_rte_vlan_hdr);
	} else {
		ether_hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
		arp = (struct my_arp_t *)(ether_hdr + 1);
		ether_hdr->ether_type = ETYPE_ARP;
		rte_pktmbuf_pkt_len(mbuf) = 42;
		rte_pktmbuf_data_len(mbuf) = 42;
	}

	memcpy(&ether_hdr->d_addr.addr_bytes, &mac_bcast, 6);
	memcpy(&ether_hdr->s_addr.addr_bytes, src_mac, 6);
	arp->htype = 0x100,
	arp->ptype = 0x0008;
	arp->hlen = 6;
	arp->plen = 4;
	arp->oper = 0x100;
	arp->data.spa = ip_src;
	arp->data.tpa = ip_dst;
	memset(&arp->data.tha, 0, sizeof(prox_rte_ether_addr));
	memcpy(&arp->data.sha, src_mac, sizeof(prox_rte_ether_addr));
}

static void create_mac(struct my_arp_t *arp, prox_rte_ether_addr *addr)
{
        addr->addr_bytes[0] = 0x2;
        addr->addr_bytes[1] = 0;
        // Instead of sending a completely random MAC address, create the following MAC:
        // 02:00:x1:x2:x3:x4 where x1:x2:x3:x4 is the IP address
        memcpy(addr->addr_bytes + 2, (uint32_t *)&arp->data.tpa, 4);
}

#endif /* _ARP_H_ */
