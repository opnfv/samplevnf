/*
// Copyright (c) 2020 Intel Corporation
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

#include "task_base.h"
#include "handle_master.h"
#include "prox_cfg.h"
#include "prox_ipv6.h"

struct ipv6_addr null_addr = {{0}};
char ip6_str[40]; // 8 blocks of 2 bytes (4 char) + 1x ":" between blocks

void set_mcast_mac_from_ipv6(prox_rte_ether_addr *mac, struct ipv6_addr *ipv6_addr)
{
	mac->addr_bytes[0] = 0x33;
	mac->addr_bytes[1] = 0x33;
	memcpy(((uint32_t *)&mac->addr_bytes[2]), (uint32_t *)(&ipv6_addr->bytes[12]), sizeof(uint32_t));
}

// Note that this function is not Mthread safe and would result in garbage if called simultaneously from multiple threads
// This function is however only used for debugging, printing errors...
char *IP6_Canonical(struct ipv6_addr *addr)
{
	uint8_t *a = (uint8_t *)addr;
	char *ptr = ip6_str;
	int field = -1, len = 0, stored_field = 0, stored_len = 0;

	// Find longest run of consecutive 16-bit 0 fields
	for (int i = 0; i < 8; i++) {
		if (((int)a[i * 2] == 0) && ((int)a[i * 2 + 1] == 0)) {
			len++;
			if (field == -1)
				field = i;	// Store where the first 0 field started
		} else {
			if (len > stored_len) {
				// the longest run of consecutive 16-bit 0 fields MUST be shortened
				stored_len = len;
				stored_field = field;
			}
			len = 0;
			field = -1;
		}
	}
	if (len > stored_len) {
		// the longest run of consecutive 16-bit 0 fields MUST be shortened
		stored_len = len;
		stored_field = field;
	}
	if (stored_len <= 1) {
		// The symbol "::" MUST NOT be used to shorten just one 16-bit 0 field.
		stored_len = 0;
		stored_field = -1;
	}
	for (int i = 0; i < 8; i++) {
		if (i == stored_field) {
			sprintf(ptr, ":");
			ptr++;
			if (i == 0) {
				sprintf(ptr, ":");
				ptr++;
			}
			i +=stored_len - 1;	// ++ done in for loop
			continue;
		}
		if ((int)a[i * 2] & 0xF0) {
			sprintf(ptr, "%02x%02x", (int)a[i * 2], (int)a[i * 2 + 1]);
			ptr+=4;
		} else if ((int)a[i * 2] & 0x0F) {
			sprintf(ptr, "%x%02x", (int)a[i * 2] >> 4, (int)a[i * 2] + 1);
			ptr+=3;
		} else if ((int)a[i * 2 + 1] & 0xF0) {
			sprintf(ptr, "%02x", (int)a[i * 2 + 1]);
			ptr+=2;
		} else {
			sprintf(ptr, "%x", ((int)a[i * 2 + 1]) & 0xF);
			ptr++;
		}
		if (i != 7) {
			sprintf(ptr, ":");
			ptr++;
		}
	}
	return ip6_str;
}

void set_link_local(struct ipv6_addr *ipv6_addr)
{
	ipv6_addr->bytes[0] = 0xfe;
	ipv6_addr->bytes[1] = 0x80;
}

// Create Extended Unique Identifier (RFC 2373)
// Store it in LSB of IPv6 address
void set_EUI(struct ipv6_addr *ipv6_addr, prox_rte_ether_addr *mac)
{
	memcpy(&ipv6_addr->bytes[8], mac, 3);						// Copy first 3 bytes of MAC
	ipv6_addr->bytes[8] = ipv6_addr->bytes[8] ^ 0x02; 				// Invert Universal/local bit
	ipv6_addr->bytes[11] = 0xff;							// Next 2 bytes are 0xfffe
	ipv6_addr->bytes[12] = 0xfe;
	memcpy(&ipv6_addr->bytes[13], &mac->addr_bytes[3], 3);				// Copy last 3 bytes
	// plog_info("mac = "MAC_BYTES_FMT", eui = "IPv6_BYTES_FMT"\n", MAC_BYTES(mac->addr_bytes), IPv6_BYTES(ipv6_addr->bytes));
}

void create_mac_from_EUI(struct ipv6_addr *ipv6_addr, prox_rte_ether_addr *mac)
{
	memcpy(mac, &ipv6_addr->bytes[8], 3);
	mac->addr_bytes[0] = mac->addr_bytes[0] ^ 0x02;
	memcpy(&mac->addr_bytes[3], &ipv6_addr->bytes[13], 3);
}

static inline prox_rte_ipv6_hdr *prox_set_vlan_ipv6(prox_rte_ether_hdr *peth, uint16_t vlan)
{
	prox_rte_ipv6_hdr *ipv6_hdr;

	if (vlan) {
		prox_rte_vlan_hdr *vlan_hdr = (prox_rte_vlan_hdr *)(peth + 1);
		ipv6_hdr = (prox_rte_ipv6_hdr *)(vlan_hdr + 1);
		peth->ether_type = ETYPE_VLAN;
		vlan_hdr->eth_proto = ETYPE_IPv6;
		vlan_hdr->vlan_tci = rte_cpu_to_be_16(vlan);
	} else {
		ipv6_hdr = (prox_rte_ipv6_hdr *)(peth + 1);
		peth->ether_type = ETYPE_IPv6;
	}
	return ipv6_hdr;
}

void build_router_advertisement(struct rte_mbuf *mbuf, prox_rte_ether_addr *s_addr, struct ipv6_addr *ipv6_s_addr, struct ipv6_addr *router_prefix, uint16_t vlan)
{
	prox_rte_ether_hdr *peth = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
	init_mbuf_seg(mbuf);
	mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);  // Software calculates the checksum

	memcpy(peth->d_addr.addr_bytes, &prox_cfg.all_nodes_mac_addr, sizeof(prox_rte_ether_addr));
	memcpy(peth->s_addr.addr_bytes, s_addr, sizeof(prox_rte_ether_addr));

	prox_rte_ipv6_hdr *ipv6_hdr = prox_set_vlan_ipv6(peth, vlan);
	ipv6_hdr->vtc_flow = 0x00000060;
	ipv6_hdr->payload_len = rte_cpu_to_be_16(sizeof(struct icmpv6_RA) + sizeof(struct icmpv6_prefix_option));
	ipv6_hdr->proto = ICMPv6;
	ipv6_hdr->hop_limits = 255;
	memcpy(ipv6_hdr->src_addr, ipv6_s_addr, sizeof(struct ipv6_addr));	// 0 = "Unspecified address" if unknown
	memcpy(ipv6_hdr->dst_addr, &prox_cfg.all_nodes_ipv6_mcast_addr, sizeof(struct ipv6_addr));

	struct icmpv6_RA *router_advertisement = (struct icmpv6_RA *)(ipv6_hdr + 1);
	router_advertisement->type = ICMPv6_RA;
	router_advertisement->code = 0;
	router_advertisement->hop_limit = 255;
	router_advertisement->bits = 0;	// M and O bits set to 0 => no dhcpv6
	router_advertisement->router_lifespan = rte_cpu_to_be_16(9000);		// 9000 sec
	router_advertisement->reachable_timeout = rte_cpu_to_be_32(30000);	// 1 sec
	router_advertisement->retrans_timeout = rte_cpu_to_be_32(1000);       // 30 sec

	struct icmpv6_option *option = &router_advertisement->options;
	option->type = ICMPv6_source_link_layer_address;
	option->length = 1;	// 8 bytes
	memcpy(&option->data, s_addr, sizeof(prox_rte_ether_addr));

	struct icmpv6_prefix_option *prefix_option = (struct icmpv6_prefix_option *)(option + 1);
	prefix_option->type = ICMPv6_prefix_information;
	prefix_option->length = 4;		// 32 bytes
	prefix_option->prefix_length = 64;	// 64 bits in prefix
	prefix_option->flag = 0xc0;		// on-link flag & autonamous address-configuration flag are set
	prefix_option->valid_lifetime = rte_cpu_to_be_32(86400);	// 1 day
	prefix_option->preferred_lifetime = rte_cpu_to_be_32(43200);	// 12 hours
	prefix_option->reserved = 0;
	memcpy(&prefix_option->prefix, router_prefix, sizeof(struct ipv6_addr));
	// Could Add MTU Option
	router_advertisement->checksum = 0;
	router_advertisement->checksum = rte_ipv6_udptcp_cksum(ipv6_hdr, router_advertisement);

	uint16_t pktlen = rte_be_to_cpu_16(ipv6_hdr->payload_len) + sizeof(prox_rte_ipv6_hdr) + sizeof(prox_rte_ether_hdr);
	rte_pktmbuf_pkt_len(mbuf) = pktlen + (vlan ? 4 : 0);
	rte_pktmbuf_data_len(mbuf) = pktlen + (vlan ? 4 : 0);
}

void build_router_sollicitation(struct rte_mbuf *mbuf, prox_rte_ether_addr *s_addr, struct ipv6_addr *ipv6_s_addr, uint16_t vlan)
{
	prox_rte_ether_hdr *peth = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);

	init_mbuf_seg(mbuf);
	mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);  // Software calculates the checksum

	memcpy(peth->d_addr.addr_bytes, &prox_cfg.all_routers_mac_addr, sizeof(prox_rte_ether_addr));
	memcpy(peth->s_addr.addr_bytes, s_addr, sizeof(prox_rte_ether_addr));

	prox_rte_ipv6_hdr *ipv6_hdr = prox_set_vlan_ipv6(peth, vlan);
	ipv6_hdr->vtc_flow = 0x00000060;
	ipv6_hdr->payload_len = rte_cpu_to_be_16(sizeof(struct icmpv6_RS));
	ipv6_hdr->proto = ICMPv6;
	ipv6_hdr->hop_limits = 255;
	memcpy(ipv6_hdr->src_addr, ipv6_s_addr, sizeof(struct ipv6_addr));	// 0 = "Unspecified address" if unknown
	memcpy(ipv6_hdr->dst_addr, &prox_cfg.all_routers_ipv6_mcast_addr, sizeof(struct ipv6_addr));

	struct icmpv6_RS *router_sollicitation = (struct icmpv6_RS *)(ipv6_hdr + 1);
	router_sollicitation->type = ICMPv6_RS;
	router_sollicitation->code = 0;
	router_sollicitation->options.type = ICMPv6_source_link_layer_address;
	router_sollicitation->options.length = 1;	// 8 bytes
	memcpy(&router_sollicitation->options.data, s_addr, sizeof(prox_rte_ether_addr));

	router_sollicitation->checksum = 0;
	router_sollicitation->checksum = rte_ipv6_udptcp_cksum(ipv6_hdr, router_sollicitation);
	uint16_t pktlen = rte_be_to_cpu_16(ipv6_hdr->payload_len) + sizeof(prox_rte_ipv6_hdr) + sizeof(prox_rte_ether_hdr);
	rte_pktmbuf_pkt_len(mbuf) = pktlen + (vlan ? 4 : 0);
	rte_pktmbuf_data_len(mbuf) = pktlen + (vlan ? 4 : 0);
}

void build_neighbour_sollicitation(struct rte_mbuf *mbuf, prox_rte_ether_addr *s_addr, struct ipv6_addr *dst, struct ipv6_addr *src, uint16_t vlan)
{
	prox_rte_ether_hdr *peth = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
	prox_rte_ether_addr mac_dst;
	set_mcast_mac_from_ipv6(&mac_dst, dst);

	init_mbuf_seg(mbuf);
	mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);  // Software calculates the checksum

	memcpy(peth->d_addr.addr_bytes, &mac_dst, sizeof(prox_rte_ether_addr));
	memcpy(peth->s_addr.addr_bytes, s_addr, sizeof(prox_rte_ether_addr));

	prox_rte_ipv6_hdr *ipv6_hdr = prox_set_vlan_ipv6(peth, vlan);

	ipv6_hdr->vtc_flow = 0x00000060;
	ipv6_hdr->payload_len = rte_cpu_to_be_16(sizeof(struct icmpv6_NS));
	ipv6_hdr->proto = ICMPv6;
	ipv6_hdr->hop_limits = 255;
	memcpy(ipv6_hdr->src_addr, src, 16);
	memcpy(ipv6_hdr->dst_addr, dst, 16);

	struct icmpv6_NS *neighbour_sollicitation = (struct icmpv6_NS *)(ipv6_hdr + 1);
	neighbour_sollicitation->type = ICMPv6_NS;
	neighbour_sollicitation->code = 0;
	neighbour_sollicitation->reserved = 0;
	memcpy(&neighbour_sollicitation->target_address, dst, sizeof(struct ipv6_addr));
	neighbour_sollicitation->options.type = ICMPv6_source_link_layer_address;
	neighbour_sollicitation->options.length = 1;	// 8 bytes
	memcpy(&neighbour_sollicitation->options.data, s_addr, sizeof(prox_rte_ether_addr));
	neighbour_sollicitation->checksum = 0;
	neighbour_sollicitation->checksum = rte_ipv6_udptcp_cksum(ipv6_hdr, neighbour_sollicitation);

	uint16_t pktlen = rte_be_to_cpu_16(ipv6_hdr->payload_len) + sizeof(prox_rte_ipv6_hdr) + sizeof(prox_rte_ether_hdr);
	rte_pktmbuf_pkt_len(mbuf) = pktlen + (vlan ? 4 : 0);
	rte_pktmbuf_data_len(mbuf) = pktlen + (vlan ? 4 : 0);
}

void build_neighbour_advertisement(struct task_base *tbase, struct rte_mbuf *mbuf, prox_rte_ether_addr *target, struct ipv6_addr *src_ipv6_addr, int sollicited, uint16_t vlan)
{
	struct task_master *task = (struct task_master *)tbase;
	prox_rte_ether_hdr *peth = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);

	uint8_t port_id = get_port(mbuf);

	init_mbuf_seg(mbuf);
	mbuf->ol_flags &= ~(PKT_TX_IP_CKSUM|PKT_TX_UDP_CKSUM);  // Software calculates the checksum

	prox_rte_ipv6_hdr *ipv6_hdr = prox_set_vlan_ipv6(peth, vlan);

	// If source mac is null, use all_nodes_mac_addr.
	if ((!sollicited) || (memcmp(peth->s_addr.addr_bytes, &null_addr, sizeof(struct ipv6_addr)) == 0)) {
		memcpy(peth->d_addr.addr_bytes, &prox_cfg.all_nodes_mac_addr, sizeof(prox_rte_ether_addr));
		memcpy(ipv6_hdr->dst_addr, &prox_cfg.all_nodes_ipv6_mcast_addr, sizeof(struct ipv6_addr));
	} else {
		memcpy(peth->d_addr.addr_bytes, peth->s_addr.addr_bytes, sizeof(prox_rte_ether_addr));
		memcpy(ipv6_hdr->dst_addr, ipv6_hdr->src_addr, sizeof(struct ipv6_addr));
	}

	memcpy(peth->s_addr.addr_bytes, &task->internal_port_table[port_id].mac, sizeof(prox_rte_ether_addr));

	ipv6_hdr->vtc_flow = 0x00000060;
	ipv6_hdr->payload_len = rte_cpu_to_be_16(sizeof(struct icmpv6_NA));
	ipv6_hdr->proto = ICMPv6;
	ipv6_hdr->hop_limits = 255;
	memcpy(ipv6_hdr->src_addr, src_ipv6_addr, sizeof(struct ipv6_addr));

	struct icmpv6_NA *neighbour_advertisement = (struct icmpv6_NA *)(ipv6_hdr + 1);
	neighbour_advertisement->type = ICMPv6_NA;
	neighbour_advertisement->code = 0;
	neighbour_advertisement->reserved = 0;
	if (task->internal_port_table[port_id].flags & IPV6_ROUTER)
		neighbour_advertisement->bits = 0xC0; // R+S bit set
	else
		neighbour_advertisement->bits = 0x40; // S bit set
	if (!sollicited) {
		memcpy(&neighbour_advertisement->destination_address, src_ipv6_addr, sizeof(struct ipv6_addr));
		neighbour_advertisement->bits &= 0xBF; // Clear S bit
		neighbour_advertisement->bits |= 0x20; // Overide bit
	}
	// else neighbour_advertisement->destination_address is already set to neighbour_sollicitation->target_address

	struct icmpv6_option *option = &neighbour_advertisement->options;
	// Do not think this is necessary
	// option->type = ICMPv6_source_link_layer_address;
	// option->length = 1;	// 8 bytes
	// memcpy(&option->data, &task->internal_port_table[port_id].mac, sizeof(prox_rte_ether_addr));

	// option = option + 1;
	option->type = ICMPv6_target_link_layer_address;
	option->length = 1;	// 8 bytes
	memcpy(&option->data, target, sizeof(prox_rte_ether_addr));

	neighbour_advertisement->checksum = 0;
	neighbour_advertisement->checksum = rte_ipv6_udptcp_cksum(ipv6_hdr, neighbour_advertisement);
	uint16_t pktlen = rte_be_to_cpu_16(ipv6_hdr->payload_len) + sizeof(prox_rte_ipv6_hdr) + sizeof(prox_rte_ether_hdr);
	rte_pktmbuf_pkt_len(mbuf) = pktlen + (vlan ? 4 : 0);
	rte_pktmbuf_data_len(mbuf) = pktlen + (vlan ? 4 : 0);
}

prox_rte_ipv6_hdr *prox_get_ipv6_hdr(prox_rte_ether_hdr *hdr, uint16_t len, uint16_t *vlan)
{
	prox_rte_vlan_hdr *vlan_hdr;
	prox_rte_ipv6_hdr *ipv6_hdr;
	uint16_t ether_type = hdr->ether_type;
	uint16_t l2_len = sizeof(prox_rte_ether_hdr);
	ipv6_hdr = (prox_rte_ipv6_hdr *)(hdr + 1);

	while (((ether_type == ETYPE_8021ad) || (ether_type == ETYPE_VLAN)) && (l2_len + sizeof(prox_rte_vlan_hdr) < len)) {
		vlan_hdr = (prox_rte_vlan_hdr *)((uint8_t *)hdr + l2_len);
		l2_len +=4;
		ether_type = vlan_hdr->eth_proto;
		*vlan = rte_be_to_cpu_16(vlan_hdr->vlan_tci & 0xFF0F);
		ipv6_hdr = (prox_rte_ipv6_hdr *)(vlan_hdr + 1);
	}
	if (ether_type == ETYPE_IPv6)
		return ipv6_hdr;
	else
		return NULL;
}
