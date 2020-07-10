/*
// Copyright (c) 2010-2020 Intel Corporation
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

#include <rte_lcore.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_lpm.h>

#include "task_base.h"
#include "lconf.h"
#include "prefetch.h"
#include "log.h"
#include "defines.h"
#include "handle_master.h"
#include "prox_port_cfg.h"
#include "packet_utils.h"
#include "prox_shared.h"
#include "prox_lua.h"
#include "hash_entry_types.h"
#include "prox_compat.h"
#include "prox_cfg.h"
#include "defines.h"
#include "prox_ipv6.h"
#include "tx_pkt.h"

static inline int find_ip(struct ether_hdr_arp *pkt, uint16_t len, uint32_t *ip_dst, uint16_t *vlan)
{
	prox_rte_vlan_hdr *vlan_hdr;
	prox_rte_ether_hdr *eth_hdr = (prox_rte_ether_hdr*)pkt;
	prox_rte_ipv4_hdr *ip;
	uint16_t ether_type = eth_hdr->ether_type;
	uint16_t l2_len = sizeof(prox_rte_ether_hdr);

	*vlan = 0;
	// Unstack VLAN tags
	while (((ether_type == ETYPE_8021ad) || (ether_type == ETYPE_VLAN)) && (l2_len + sizeof(prox_rte_vlan_hdr) < len)) {
		vlan_hdr = (prox_rte_vlan_hdr *)((uint8_t *)pkt + l2_len);
		l2_len +=4;
		ether_type = vlan_hdr->eth_proto;
		*vlan = rte_be_to_cpu_16(vlan_hdr->vlan_tci & 0xFF0F);	// Store VLAN, or CVLAN if QinQ
	}

	switch (ether_type) {
	case ETYPE_MPLSU:
	case ETYPE_MPLSM:
		// In case of MPLS, next hop MAC is based on MPLS, not destination IP
		l2_len = 0;
		break;
	case ETYPE_IPv4:
		break;
	case ETYPE_EoGRE:
	case ETYPE_ARP:
	case ETYPE_IPv6:
		l2_len = 0;
		break;
	default:
		l2_len = 0;
		plog_warn("Unsupported packet type %x - CRC might be wrong\n", ether_type);
		break;
	}

	if (l2_len && (l2_len + sizeof(prox_rte_ipv4_hdr) <= len)) {
		prox_rte_ipv4_hdr *ip = (prox_rte_ipv4_hdr *)((uint8_t *)pkt + l2_len);
		// TODO: implement LPM => replace ip_dst by next hop IP DST
		*ip_dst = ip->dst_addr;
		return 0;
	}
	return -1;
}

static inline void find_vlan(struct ether_hdr_arp *pkt, uint16_t len, uint16_t *vlan)
{
	prox_rte_vlan_hdr *vlan_hdr;
	prox_rte_ether_hdr *eth_hdr = (prox_rte_ether_hdr*)pkt;
	uint16_t ether_type = eth_hdr->ether_type;
	uint16_t l2_len = sizeof(prox_rte_ether_hdr);

	*vlan = 0;
	// Unstack VLAN tags
	while (((ether_type == ETYPE_8021ad) || (ether_type == ETYPE_VLAN)) && (l2_len + sizeof(prox_rte_vlan_hdr) < len)) {
		vlan_hdr = (prox_rte_vlan_hdr *)((uint8_t *)pkt + l2_len);
		l2_len +=4;
		ether_type = vlan_hdr->eth_proto;
		*vlan = rte_be_to_cpu_16(vlan_hdr->vlan_tci & 0xFF0F);  // Store VLAN, or CVLAN if QinQ
	}
}

static inline struct ipv6_addr *find_ip6(prox_rte_ether_hdr *pkt, uint16_t len, struct ipv6_addr *ip_dst, uint16_t *vlan)
{
	prox_rte_vlan_hdr *vlan_hdr;
	prox_rte_ipv6_hdr *ip;
	uint16_t ether_type = pkt->ether_type;
	uint16_t l2_len = sizeof(prox_rte_ether_hdr);

	*vlan = 0;
	// Unstack VLAN tags
	while (((ether_type == ETYPE_8021ad) || (ether_type == ETYPE_VLAN)) && (l2_len + sizeof(prox_rte_vlan_hdr) < len)) {
		vlan_hdr = (prox_rte_vlan_hdr *)((uint8_t *)pkt + l2_len);
		l2_len +=4;
		ether_type = vlan_hdr->eth_proto;
		*vlan = rte_be_to_cpu_16(vlan_hdr->vlan_tci & 0xFF0F);	// Store VLAN, or CVLAN if QinQ
	}

	switch (ether_type) {
	case ETYPE_MPLSU:
	case ETYPE_MPLSM:
		// In case of MPLS, next hop MAC is based on MPLS, not destination IP
		l2_len = 0;
		break;
	case ETYPE_IPv4:
	case ETYPE_EoGRE:
	case ETYPE_ARP:
		l2_len = 0;
		break;
	case ETYPE_IPv6:
		break;
	default:
		l2_len = 0;
		plog_warn("Unsupported packet type %x - CRC might be wrong\n", ether_type);
		break;
	}

	if (l2_len && (l2_len + sizeof(prox_rte_ipv6_hdr) <= len)) {
		prox_rte_ipv6_hdr *ip = (prox_rte_ipv6_hdr *)((uint8_t *)pkt + l2_len);
		// TODO: implement LPM => replace ip_dst by next hop IP DST
		memcpy(ip_dst, &ip->dst_addr, sizeof(struct ipv6_addr));
		return (struct ipv6_addr *)&ip->src_addr;
	}
	return NULL;
}

static void send_unsollicited_neighbour_advertisement(struct task_base *tbase, struct task_args *targ)
{
	int ret;
	uint8_t out = 0, port_id = tbase->l3.reachable_port_id;
	struct rte_mbuf *mbuf;

	ret = rte_mempool_get(tbase->l3.arp_nd_pool, (void **)&mbuf);
	if (likely(ret == 0)) {
		mbuf->port = port_id;
		build_neighbour_advertisement(tbase->l3.tmaster, mbuf, &prox_port_cfg[port_id].eth_addr, &targ->local_ipv6, PROX_UNSOLLICITED);
		tbase->aux->tx_ctrlplane_pkt(tbase, &mbuf, 1, &out);
		TASK_STATS_ADD_TX_NON_DP(&tbase->aux->stats, 1);
	} else {
		plog_err("Failed to get a mbuf from arp/ndp mempool\n");
	}
}

static void send_router_sollicitation(struct task_base *tbase, struct task_args *targ)
{
	int ret;
	uint8_t out = 0, port_id = tbase->l3.reachable_port_id;
	struct rte_mbuf *mbuf;

	ret = rte_mempool_get(tbase->l3.arp_nd_pool, (void **)&mbuf);
	if (likely(ret == 0)) {
		mbuf->port = port_id;
		build_router_sollicitation(mbuf, &prox_port_cfg[port_id].eth_addr, &targ->local_ipv6);
		tbase->aux->tx_ctrlplane_pkt(tbase, &mbuf, 1, &out);
		TASK_STATS_ADD_TX_NON_DP(&tbase->aux->stats, 1);
	} else {
		plog_err("Failed to get a mbuf from arp/ndp mempool\n");
	}
}

/* This implementation could be improved: instead of checking each time we send a packet whether we need also
   to send an ARP, we should only check whether the MAC is valid.
   We should check arp_ndp_retransmit_timeout in the master process. This would also require the generating task to clear its arp ring
   to avoid sending many ARP while starting after a long stop.
   We could also check for reachable_timeout in the master so that dataplane has only to check whether MAC is available
   but this would require either thread safety, or the the exchange of information between master and generating core.
   */

static inline int add_key_and_send_arp(struct rte_hash *ip_hash, uint32_t *ip_dst, struct arp_table *entries,  uint64_t tsc, uint64_t hz, uint32_t arp_ndp_retransmit_timeout, prox_next_hop_index_type nh, uint64_t **time)
{
	int ret = rte_hash_add_key(ip_hash, (const void *)ip_dst);
	if (unlikely(ret < 0)) {
		// No reason to send ARP, as reply would be anyhow ignored
		plogx_err("Unable to add ip "IPv4_BYTES_FMT" in mac_hash\n", IP4(*ip_dst));
		return DROP_MBUF;
	} else {
		entries[ret].ip = *ip_dst;
		entries[ret].nh = nh;
		*time = &entries[ret].arp_ndp_retransmit_timeout;
	}
	return SEND_ARP_ND;
}

static inline int update_mac_and_send_mbuf(struct arp_table *entry, prox_rte_ether_addr *mac, uint64_t tsc, uint64_t hz, uint32_t arp_ndp_retransmit_timeout, uint64_t **time)
{
	if (likely((tsc < entry->arp_ndp_retransmit_timeout) && (tsc < entry->reachable_timeout))) {
		memcpy(mac, &entry->mac, sizeof(prox_rte_ether_addr));
		return SEND_MBUF;
	} else if (tsc > entry->arp_ndp_retransmit_timeout) {
		// long time since we have sent an arp, send arp
		*time = &entry->arp_ndp_retransmit_timeout;
		if (tsc < entry->reachable_timeout){
			// MAC is valid in the table => send also the mbuf
			memcpy(mac, &entry->mac, sizeof(prox_rte_ether_addr));
			return SEND_MBUF_AND_ARP_ND;
		} else {
			// MAC still unknown, or timed out => only send ARP
			return SEND_ARP_ND;
		}
	}
	// MAC is unknown and we already sent an ARP recently, drop mbuf and wait for ARP reply
	return DROP_MBUF;
}

int write_dst_mac(struct task_base *tbase, struct rte_mbuf *mbuf, uint32_t *ip_dst, uint16_t *vlan, uint64_t **time, uint64_t tsc)
{
	const uint64_t hz = rte_get_tsc_hz();
	struct ether_hdr_arp *packet = rte_pktmbuf_mtod(mbuf, struct ether_hdr_arp *);
	prox_rte_ether_addr *mac = &packet->ether_hdr.d_addr;
	prox_next_hop_index_type next_hop_index;
	static uint64_t last_tsc = 0, n_no_route = 0;

	struct l3_base *l3 = &(tbase->l3);

	// First find the next hop
	if (l3->ipv4_lpm) {
		// A routing table was configured
		// If a gw (gateway_ipv4) is also specified, it is used as default gw only i.e. lowest priority (shortest prefix)
		// This is implemented automatically through lpm
		uint16_t len = rte_pktmbuf_pkt_len(mbuf);
		if (find_ip(packet, len, ip_dst, vlan) != 0) {
			// Unable to find IP address => non IP packet => send it as it
			return SEND_MBUF;
		}
		if (unlikely(rte_lpm_lookup(l3->ipv4_lpm, rte_bswap32(*ip_dst), &next_hop_index) != 0)) {
			// Prevent printing too many messages
			n_no_route++;
			if (tsc > last_tsc + rte_get_tsc_hz()) {
				plogx_err("No route to IP "IPv4_BYTES_FMT" (%ld times)\n", IP4(*ip_dst), n_no_route);
				last_tsc = tsc;
				n_no_route = 0;
			}
			return DROP_MBUF;
		}
		struct arp_table *entry = &l3->next_hops[next_hop_index];

		if (entry->ip) {
			*ip_dst = entry->ip;
			return update_mac_and_send_mbuf(entry, mac, tsc, hz, l3->arp_ndp_retransmit_timeout, time);
		}

		// no next ip: this is a local route
		// Find IP in lookup table. Send ARP if not found
		int ret = rte_hash_lookup(l3->ip_hash, (const void *)ip_dst);
		if (unlikely(ret < 0)) {
			// IP not found, try to send an ARP
			return add_key_and_send_arp(l3->ip_hash, ip_dst, l3->arp_table, tsc, hz, l3->arp_ndp_retransmit_timeout, MAX_HOP_INDEX, time);
		} else {
			return update_mac_and_send_mbuf(&l3->arp_table[ret], mac, tsc, hz, l3->arp_ndp_retransmit_timeout, time);
		}
		return 0;
	}
	// No Routing table specified: only a local ip and maybe a gateway
	// Old default behavior: if a gw is specified, ALL packets go to this gateway (even those we could send w/o the gw

	uint16_t len = rte_pktmbuf_pkt_len(mbuf);
	if (l3->gw.ip) {
		find_vlan(packet, len, vlan);
		if (likely((l3->flags & FLAG_DST_MAC_KNOWN) && (tsc < l3->gw.arp_ndp_retransmit_timeout) && (tsc < l3->gw.reachable_timeout))) {
			memcpy(mac, &l3->gw.mac, sizeof(prox_rte_ether_addr));
			return SEND_MBUF;
		} else if (tsc > l3->gw.arp_ndp_retransmit_timeout) {
			// long time since we have successfully sent an arp, send arp
			// If sending ARP failed (ring full) then arp_ndp_retransmit_timeout is not updated to avoid having to wait 1 sec to send ARP REQ again
			*time = &l3->gw.arp_ndp_retransmit_timeout;
			l3->gw.arp_ndp_retransmit_timeout = tsc + l3->arp_ndp_retransmit_timeout * hz / 1000;

			*ip_dst = l3->gw.ip;
			if ((l3->flags & FLAG_DST_MAC_KNOWN) && (tsc < l3->gw.reachable_timeout)){
				// MAC is valid in the table => send also the mbuf
				memcpy(mac, &l3->gw.mac, sizeof(prox_rte_ether_addr));
				return SEND_MBUF_AND_ARP_ND;
			} else {
				// MAC still unknown, or timed out => only send ARP
				return SEND_ARP_ND;
			}
		} else {
			// MAC is unknown and we already sent an ARP recently, drop mbuf and wait for ARP reply
			return DROP_MBUF;
		}
	}

	if (find_ip(packet, len, ip_dst, vlan) != 0) {
		// Unable to find IP address => non IP packet => send it as it
		return SEND_MBUF;
	}
	if (likely(l3->n_pkts < 4)) {
		for (unsigned int idx = 0; idx < l3->n_pkts; idx++) {
			if (*ip_dst == l3->optimized_arp_table[idx].ip) {
				return update_mac_and_send_mbuf(&l3->optimized_arp_table[idx], mac, tsc, hz, l3->arp_ndp_retransmit_timeout, time);
			}
		}
		// IP address not found in table
		l3->optimized_arp_table[l3->n_pkts].ip = *ip_dst;
		*time = &l3->optimized_arp_table[l3->n_pkts].arp_ndp_retransmit_timeout;
		l3->n_pkts++;

		if (l3->n_pkts < 4) {
			return SEND_ARP_ND;
		}

		// We have too many IP addresses to search linearly; lets use hash table instead => copy all entries in hash table
		for (uint32_t idx = 0; idx < l3->n_pkts; idx++) {
			uint32_t ip = l3->optimized_arp_table[idx].ip;
			int ret = rte_hash_add_key(l3->ip_hash, (const void *)&ip);
			if (ret < 0) {
				// This should not happen as few entries so far.
				// If it happens, we still send the ARP as easier:
				//      If the ARP corresponds to this error, the ARP reply will be ignored
				//      If ARP does not correspond to this error/ip, then ARP reply will be handled.
				plogx_err("Unable add ip "IPv4_BYTES_FMT" in mac_hash (already %d entries)\n", IP4(ip), idx);
			} else {
				memcpy(&l3->arp_table[ret], &l3->optimized_arp_table[idx], sizeof(struct arp_table));
			}
		}
		return SEND_ARP_ND;
	} else {
		// Find IP in lookup table. Send ARP if not found
		int ret = rte_hash_lookup(l3->ip_hash, (const void *)ip_dst);
		if (unlikely(ret < 0)) {
			// IP not found, try to send an ARP
			return add_key_and_send_arp(l3->ip_hash, ip_dst, &l3->arp_table[ret], tsc, hz, l3->arp_ndp_retransmit_timeout, MAX_HOP_INDEX, time);
		} else {
			// IP has been found
			return update_mac_and_send_mbuf(&l3->arp_table[ret], mac, tsc, hz, l3->arp_ndp_retransmit_timeout, time);
		}
	}
	// Should not happen
	return DROP_MBUF;
}

int write_ip6_dst_mac(struct task_base *tbase, struct rte_mbuf *mbuf, struct ipv6_addr *ip_dst, uint16_t *vlan)
{
	const uint64_t hz = rte_get_tsc_hz();
	prox_rte_ether_hdr *packet = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
	prox_rte_ether_addr *mac = &packet->d_addr;
	struct ipv6_addr *used_ip_src;

	uint64_t tsc = rte_rdtsc();
	uint16_t len = rte_pktmbuf_pkt_len(mbuf);

	struct ipv6_addr *pkt_src_ip6;
	if ((pkt_src_ip6 = find_ip6(packet, len, ip_dst, vlan)) == NULL) {
		// Unable to find IP address => non IP packet => send it as it
		return SEND_MBUF;
	}
	struct l3_base *l3 = &(tbase->l3);
	if (memcmp(&l3->local_ipv6, ip_dst, 8) == 0) {
		// Same prefix as local -> use local
		used_ip_src = &l3->local_ipv6;
	} else if (memcmp(&l3->global_ipv6 , &null_addr, 16) != 0) {
		// Global IP is defined -> use it
		used_ip_src = &l3->global_ipv6;
	} else {
		plog_info("Error as trying to send a packet to "IPv6_BYTES_FMT" using "IPv6_BYTES_FMT" (local)\n", IPv6_BYTES(ip_dst->bytes), IPv6_BYTES(l3->local_ipv6.bytes));
		return DROP_MBUF;
	}

	memcpy(pkt_src_ip6, used_ip_src, sizeof(struct ipv6_addr));
	if (likely(l3->n_pkts < 4)) {
		for (unsigned int idx = 0; idx < l3->n_pkts; idx++) {
			if (memcmp(ip_dst, &l3->optimized_arp_table[idx].ip6, sizeof(struct ipv6_addr)) == 0) {
				 // IP address already in table
				if ((tsc < l3->optimized_arp_table[idx].arp_ndp_retransmit_timeout) && (tsc < l3->optimized_arp_table[idx].reachable_timeout)) {
					// MAC address was recently updated in table, use it
					// plog_dbg("Valid MAC address found => send packet\n");
					memcpy(mac, &l3->optimized_arp_table[idx].mac, sizeof(prox_rte_ether_addr));
					return SEND_MBUF;
				} else if (tsc > l3->optimized_arp_table[idx].arp_ndp_retransmit_timeout) {
					// NDP not sent since a long time, send NDP
					l3->optimized_arp_table[idx].arp_ndp_retransmit_timeout = tsc + l3->arp_ndp_retransmit_timeout * hz / 1000;
					if (tsc < l3->optimized_arp_table[idx].reachable_timeout) {
						// MAC still valid => also send mbuf
						plog_dbg("Valid MAC found but NDP retransmit timeout => send packet and NDP\n");
						memcpy(mac, &l3->optimized_arp_table[idx].mac, sizeof(prox_rte_ether_addr));
						return SEND_MBUF_AND_ARP_ND;
					} else {
						plog_dbg("Unknown MAC => send NDP but cannot send packet\n");
						// MAC unvalid => only send NDP
						return SEND_ARP_ND;
					}
				} else {
					//  NDP timeout elapsed, MAC not valid anymore but waiting for NDP reply
					// plog_dbg("NDP reachable timeout elapsed - waiting for NDP reply\n");
					return DROP_MBUF;
				}
			}
		}
		// IP address not found in table
		memcpy(&l3->optimized_arp_table[l3->n_pkts].ip6, ip_dst, sizeof(struct ipv6_addr));
		l3->optimized_arp_table[l3->n_pkts].arp_ndp_retransmit_timeout = tsc + l3->arp_ndp_retransmit_timeout * hz / 1000;
		l3->n_pkts++;

		if (l3->n_pkts < 4) {
			return SEND_ARP_ND;
		}

		// We have too many IP addresses to search linearly; lets use hash table instead => copy all entries in hash table
		for (uint32_t idx = 0; idx < l3->n_pkts; idx++) {
			struct ipv6_addr *ip6 = &l3->optimized_arp_table[idx].ip6;
			int ret = rte_hash_add_key(l3->ip6_hash, (const void *)ip6);
			if (ret < 0) {
				// This should not happen as few entries so far.
				// If it happens, we still send the NDP as easier:
				//      If the NDP corresponds to this error, the NDP reply will be ignored
				//      If NDP does not correspond to this error/ip, then NDP reply will be handled.
				plogx_err("Unable add ip "IPv6_BYTES_FMT" in mac_hash (already %d entries)\n", IPv6_BYTES(ip6->bytes), idx);
			} else {
				memcpy(&l3->arp_table[ret], &l3->optimized_arp_table[idx], sizeof(struct arp_table));
			}
		}
		return SEND_ARP_ND;
	} else {
		// Find IP in lookup table. Send ND if not found
		int ret = rte_hash_lookup(l3->ip6_hash, (const void *)ip_dst);
		if (unlikely(ret < 0)) {
			// IP not found, try to send an ND
			int ret = rte_hash_add_key(l3->ip6_hash, (const void *)ip_dst);
			if (ret < 0) {
				// No reason to send NDP, as reply would be anyhow ignored
				plogx_err("Unable to add ip "IPv6_BYTES_FMT" in mac_hash\n", IPv6_BYTES(ip_dst->bytes));
				return DROP_MBUF;
			} else {
				memcpy(&l3->arp_table[ret].ip6, ip_dst, sizeof(struct ipv6_addr));
				l3->arp_table[ret].arp_ndp_retransmit_timeout = tsc + l3->arp_ndp_retransmit_timeout * hz / 1000;
			}
			return SEND_ARP_ND;
		} else {
			// IP has been found
			if (likely((tsc < l3->arp_table[ret].arp_ndp_retransmit_timeout) && (tsc < l3->arp_table[ret].reachable_timeout))) {
				// MAC still valid and NDP sent recently
				memcpy(mac, &l3->arp_table[ret].mac, sizeof(prox_rte_ether_addr));
				return SEND_MBUF;
			} else if (tsc > l3->arp_table[ret].arp_ndp_retransmit_timeout) {
				// NDP not sent since a long time, send NDP
				l3->arp_table[ret].arp_ndp_retransmit_timeout = tsc + l3->arp_ndp_retransmit_timeout * hz / 1000;
				if (tsc < l3->arp_table[ret].reachable_timeout) {
					// MAC still valid => send also MBUF
					memcpy(mac, &l3->arp_table[ret].mac, sizeof(prox_rte_ether_addr));
					return SEND_MBUF_AND_ARP_ND;
				} else {
					return SEND_ARP_ND;
				}
			} else {
				return DROP_MBUF;
			}
		}
	}
	// Should not happen
	return DROP_MBUF;
}

void task_init_l3(struct task_base *tbase, struct task_args *targ)
{
	static char hash_name[30];
	uint32_t n_entries = MAX_ARP_ENTRIES * 4;
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	sprintf(hash_name, "A%03d_%03d_mac_table", targ->lconf->id, targ->id);

	hash_name[0]++;

	struct rte_hash_parameters hash_params = {
		.name = hash_name,
		.entries = n_entries,
		.key_len = sizeof(uint32_t),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
	};
	if (targ->flags & TASK_ARG_L3) {
		plog_info("\tInitializing L3 (IPv4)\n");
		tbase->l3.ip_hash = rte_hash_create(&hash_params);
		PROX_PANIC(tbase->l3.ip_hash == NULL, "Failed to set up ip hash table\n");
		hash_name[0]++;
	}

	if (targ->flags & TASK_ARG_NDP) {
		plog_info("\tInitializing NDP (IPv6)\n");
		hash_params.key_len = sizeof(struct ipv6_addr);
		tbase->l3.ip6_hash = rte_hash_create(&hash_params);
		PROX_PANIC(tbase->l3.ip6_hash == NULL, "Failed to set up ip hash table\n");
	}
	tbase->l3.arp_table = (struct arp_table *)prox_zmalloc(n_entries * sizeof(struct arp_table), socket_id);
	PROX_PANIC(tbase->l3.arp_table == NULL, "Failed to allocate memory for %u entries in arp/ndp table\n", n_entries);
	plog_info("\tarp/ndp table, with %d entries of size %ld\n", n_entries, sizeof(struct l3_base));

	targ->lconf->ctrl_func_p[targ->task] = handle_ctrl_plane_pkts;
	targ->lconf->ctrl_timeout = freq_to_tsc(targ->ctrl_freq);
	tbase->l3.gw.ip = rte_cpu_to_be_32(targ->gateway_ipv4);
	tbase->flags |= TASK_L3;
	tbase->l3.core_id = targ->lconf->id;
	tbase->l3.task_id = targ->id;
	tbase->l3.tmaster = targ->tmaster;
	tbase->l3.seed = (uint)rte_rdtsc();
	if (targ->reachable_timeout != 0)
		tbase->l3.reachable_timeout = targ->reachable_timeout;
	else
		tbase->l3.reachable_timeout = DEFAULT_ARP_TIMEOUT;
	if (targ->arp_ndp_retransmit_timeout != 0)
		tbase->l3.arp_ndp_retransmit_timeout = targ->arp_ndp_retransmit_timeout;
	else
		tbase->l3.arp_ndp_retransmit_timeout = DEFAULT_ARP_UPDATE_TIME;
}

void task_start_l3(struct task_base *tbase, struct task_args *targ)
{
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	const int NB_ARP_ND_MBUF = 1024;
	const int ARP_ND_MBUF_SIZE = 2048;
	const int NB_CACHE_ARP_ND_MBUF = 256;

	struct prox_port_cfg *port = find_reachable_port(targ);
        if (port && (tbase->l3.arp_nd_pool == NULL)) {
		static char name[] = "arp0_pool";
                tbase->l3.reachable_port_id = port - prox_port_cfg;
		if ((targ->local_ipv4 && port->ip) && (targ->local_ipv4 != port->ip)) {
			PROX_PANIC(1, "local_ipv4 in core section ("IPv4_BYTES_FMT") differs from port section ("IPv4_BYTES_FMT")\n", IP4(rte_be_to_cpu_32(targ->local_ipv4)), IP4(rte_be_to_cpu_32(port->ip)));
		}
		if ((targ->local_ipv4 && port->ip) && (targ->local_prefix != port->prefix)) {
			PROX_PANIC(1, "local_ipv4 prefix in core section (%d) differs from port section (%d)\n", targ->local_prefix, port->prefix);
		}
		if (!targ->local_ipv4) {
			targ->local_ipv4 = port->ip;
			targ->local_prefix = port->prefix;
			plog_info("Setting core local_ipv4 from port %d local_ipv4 to "IPv4_BYTES_FMT"\n", tbase->l3.reachable_port_id, IP4(rte_be_to_cpu_32(port->ip)));
		}
		if (targ->local_ipv4) {
			tbase->l3.local_ipv4 = rte_be_to_cpu_32(targ->local_ipv4);
			register_ip_to_ctrl_plane(tbase->l3.tmaster, tbase->l3.local_ipv4, tbase->l3.reachable_port_id, targ->lconf->id, targ->id);
        	}
		if (strcmp(targ->route_table, "") != 0) {
			struct lpm4 *lpm;
			int ret;

			PROX_PANIC(tbase->l3.local_ipv4 == 0, "missing local_ipv4 while route table is specified in L3 mode\n");

			// LPM might be modified runtime => do not share with other cores
			ret = lua_to_lpm4(prox_lua(), GLOBAL, targ->route_table, socket_id, &lpm);
			PROX_PANIC(ret, "Failed to load IPv4 LPM:\n%s\n", get_lua_to_errors());

			tbase->l3.ipv4_lpm = lpm->rte_lpm;
			tbase->l3.next_hops = prox_zmalloc(sizeof(*tbase->l3.next_hops) * MAX_HOP_INDEX, socket_id);
			PROX_PANIC(tbase->l3.next_hops == NULL, "Could not allocate memory for next hop\n");

			for (uint32_t i = 0; i < MAX_HOP_INDEX; i++) {
				if (!lpm->next_hops[i].ip_dst)
					continue;
				tbase->l3.nb_gws++;
				tbase->l3.next_hops[i].ip = rte_bswap32(lpm->next_hops[i].ip_dst);
				int tx_port = lpm->next_hops[i].mac_port.out_idx;
				// gen only supports one port right now .... hence port = 0
				if ((tx_port > targ->nb_txports - 1) && (tx_port > targ->nb_txrings - 1)) {
					PROX_PANIC(1, "Routing Table contains port %d but only %d tx port/ %d ring:\n", tx_port, targ->nb_txports, targ->nb_txrings);
				}
			}
			plog_info("Using routing table %s in l3 mode, with %d gateways\n", targ->route_table, tbase->l3.nb_gws);

			// Last but one "next_hop_index" is not a gateway but direct routes
			tbase->l3.next_hops[tbase->l3.nb_gws].ip = 0;
			ret = rte_lpm_add(tbase->l3.ipv4_lpm, targ->local_ipv4, targ->local_prefix, tbase->l3.nb_gws++);
			PROX_PANIC(ret, "Failed to add local_ipv4 "IPv4_BYTES_FMT"/%d to lpm\n", IP4(tbase->l3.local_ipv4), targ->local_prefix);
			// Last "next_hop_index" is default gw
			tbase->l3.next_hops[tbase->l3.nb_gws].ip = rte_bswap32(targ->gateway_ipv4);
			if (targ->gateway_ipv4) {
				ret = rte_lpm_add(tbase->l3.ipv4_lpm, targ->gateway_ipv4, 0, tbase->l3.nb_gws++);
				PROX_PANIC(ret, "Failed to add gateway_ipv4 "IPv4_BYTES_FMT"/%d to lpm\n", IP4(tbase->l3.gw.ip), 0);
			}
		}

		master_init_vdev(tbase->l3.tmaster, tbase->l3.reachable_port_id, targ->lconf->id, targ->id);

		// Create IPv6 addr if none were configured
		if (targ->flags & TASK_ARG_NDP) {
			if (!memcmp(&targ->local_ipv6, &null_addr, 16)) {
				set_link_local(&targ->local_ipv6);
				set_EUI(&targ->local_ipv6, &port->eth_addr);
			}
			plog_info("\tCore %d, task %d, local IPv6 addr is "IPv6_BYTES_FMT" (%s)\n",
				targ->lconf->id, targ->id,
				IPv6_BYTES(targ->local_ipv6.bytes),
				IP6_Canonical(&targ->local_ipv6));
			memcpy(&tbase->l3.local_ipv6, &targ->local_ipv6, sizeof(struct ipv6_addr));

			if (memcmp(&targ->global_ipv6, &null_addr, sizeof(struct ipv6_addr))) {
				memcpy(&tbase->l3.global_ipv6, &targ->global_ipv6, sizeof(struct ipv6_addr));
				plog_info("\tCore %d, task %d, global IPv6 addr is "IPv6_BYTES_FMT" (%s)\n",
					targ->lconf->id, targ->id,
					IPv6_BYTES(targ->global_ipv6.bytes),
					IP6_Canonical(&targ->global_ipv6));
			}
			if (targ->ipv6_router)
				register_router_to_ctrl_plane(tbase->l3.tmaster, tbase->l3.reachable_port_id, targ->lconf->id, targ->id, &targ->local_ipv6, &targ->global_ipv6, &targ->router_prefix);
			else
				register_node_to_ctrl_plane(tbase->l3.tmaster, &targ->local_ipv6, &targ->global_ipv6, tbase->l3.reachable_port_id, targ->lconf->id, targ->id);
		}

		name[3]++;
		struct rte_mempool *ret = rte_mempool_create(name, NB_ARP_ND_MBUF, ARP_ND_MBUF_SIZE, NB_CACHE_ARP_ND_MBUF,
			sizeof(struct rte_pktmbuf_pool_private), rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, 0,
			rte_socket_id(), 0);
		PROX_PANIC(ret == NULL, "Failed to allocate ARP/ND memory pool on socket %u with %u elements\n",
			rte_socket_id(), NB_ARP_ND_MBUF);
		plog_info("\tMempool %p (%s) size = %u * %u cache %u, socket %d (for ARP/ND)\n", ret, name, NB_ARP_ND_MBUF,
			ARP_ND_MBUF_SIZE, NB_CACHE_ARP_ND_MBUF, rte_socket_id());
		tbase->l3.arp_nd_pool = ret;
		if ((targ->flags & TASK_ARG_NDP) && (!targ->ipv6_router)) {
			plog_info("Sending Router Sollicitation\n");
			send_router_sollicitation(tbase, targ);
		}
		if ((targ->flags & TASK_ARG_NDP) && (targ->flags & TASK_ARG_SEND_NA_AT_STARTUP)) {
			plog_info("Sending unsollicited Neighbour Advertisement\n");
			send_unsollicited_neighbour_advertisement(tbase, targ);

		}
	}
}

void task_set_gateway_ip(struct task_base *tbase, uint32_t ip)
{
	tbase->l3.gw.ip = ip;
	tbase->flags &= ~FLAG_DST_MAC_KNOWN;
}

void task_set_local_ip(struct task_base *tbase, uint32_t ip)
{
	tbase->l3.local_ipv4 = ip;
}

static void reset_arp_ndp_retransmit_timeout(struct l3_base *l3, uint32_t ip)
{
	uint32_t idx;
	plogx_dbg("MAC entry for IP "IPv4_BYTES_FMT" timeout in kernel\n", IP4(ip));

	if (l3->ipv4_lpm) {
		int ret = rte_hash_lookup(l3->ip_hash, (const void *)&ip);
		if (ret >= 0)
			l3->arp_table[ret].arp_ndp_retransmit_timeout = 0;
	} else if (ip == l3->gw.ip) {
		l3->gw.arp_ndp_retransmit_timeout = 0;
	} else if (l3->n_pkts < 4) {
		for (idx = 0; idx < l3->n_pkts; idx++) {
			uint32_t ip_dst = l3->optimized_arp_table[idx].ip;
			if (ip_dst == ip)
				break;
		}
		if (idx < l3->n_pkts) {
			l3->optimized_arp_table[idx].arp_ndp_retransmit_timeout = 0;
		}
	} else {
		int ret = rte_hash_lookup(l3->ip_hash, (const void *)&ip);
		if (ret >= 0)
			l3->arp_table[ret].arp_ndp_retransmit_timeout = 0;
	}
	return;
}

static prox_next_hop_index_type get_nh_index(struct task_base *tbase, uint32_t gw_ip)
{
	// Check if gateway already exists
	for (prox_next_hop_index_type i = 0; i < tbase->l3.nb_gws; i++) {
		if (tbase->l3.next_hops[i].ip == gw_ip) {
			return i;
		}
	}
	if (tbase->l3.nb_gws < MAX_HOP_INDEX) {
		tbase->l3.next_hops[tbase->l3.nb_gws].ip = gw_ip;
		tbase->l3.nb_gws++;
		return tbase->l3.nb_gws - 1;
	} else
		return MAX_HOP_INDEX;
}
void handle_ctrl_plane_pkts(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	uint8_t out[1];
	const uint64_t hz = rte_get_tsc_hz();
	uint32_t ip, ip_dst, idx, gateway_ip, prefix;
	prox_next_hop_index_type gateway_index;
	int j, ret, modified_route;
	uint64_t addr;
	struct ipv6_addr *ip6, *ip6_dst;
	uint16_t command;
	prox_rte_ether_hdr *hdr;
	struct ether_hdr_arp *hdr_arp;
	struct l3_base *l3 = &tbase->l3;
	uint64_t tsc= rte_rdtsc();
	uint64_t reachable_timeout = l3->reachable_timeout * hz / 1000;
	uint32_t nh;
	prox_rte_ipv4_hdr *pip;
	prox_rte_udp_hdr *udp_hdr;
	uint8_t port = tbase->l3.reachable_port_id;

	for (j = 0; j < n_pkts; ++j) {
		PREFETCH0(mbufs[j]);
	}
	for (j = 0; j < n_pkts; ++j) {
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j], void *));
	}

	for (j = 0; j < n_pkts; ++j) {
		pip = NULL;
		udp_hdr = NULL;
		out[0] = OUT_HANDLED;
		command = get_command(mbufs[j]);
		plogx_dbg("\tReceived %s mbuf %p\n", actions_string[command], mbufs[j]);
		switch(command) {
		case ROUTE_ADD_FROM_MASTER:
			ip = ctrl_ring_get_ip(mbufs[j]);
			gateway_ip = ctrl_ring_get_gateway_ip(mbufs[j]);
			prefix = ctrl_ring_get_prefix(mbufs[j]);
			gateway_index = get_nh_index(tbase, gateway_ip);
			if (gateway_index >= MAX_HOP_INDEX) {
				plog_err("Unable to find or define gateway index - too many\n");
				return;
			}
			modified_route = rte_lpm_is_rule_present(tbase->l3.ipv4_lpm, rte_bswap32(ip), prefix, &nh);
			ret = rte_lpm_add(tbase->l3.ipv4_lpm, rte_bswap32(ip), prefix, gateway_index);
			if (ret < 0) {
				plog_err("Failed to add route to "IPv4_BYTES_FMT"/%d using "IPv4_BYTES_FMT"(index = %d)\n", IP4(ip), prefix, IP4(gateway_ip), gateway_index);
			} else if (modified_route)
				plogx_dbg("Modified route to "IPv4_BYTES_FMT"/%d using "IPv4_BYTES_FMT"(index = %d) (was using "IPv4_BYTES_FMT"(index = %d)\n", IP4(ip), prefix, IP4(gateway_ip), gateway_index, IP4(tbase->l3.next_hops[nh].ip), nh);
			else {
				plogx_dbg("Added new route to "IPv4_BYTES_FMT"/%d using "IPv4_BYTES_FMT"(index = %d)\n", IP4(ip), prefix, IP4(gateway_ip), gateway_index);
			}
			tx_drop(mbufs[j]);
			break;
		case ROUTE_DEL_FROM_MASTER:
			ip = ctrl_ring_get_ip(mbufs[j]);
			prefix = ctrl_ring_get_prefix(mbufs[j]);

			ret = rte_lpm_is_rule_present(tbase->l3.ipv4_lpm, rte_bswap32(ip), prefix, &nh);
			if (ret > 0) {
				ret = rte_lpm_delete(tbase->l3.ipv4_lpm, rte_bswap32(ip), prefix);
				if (ret < 0) {
					plog_err("Failed to add rule\n");
				}
				plog_info("Deleting route to "IPv4_BYTES_FMT"/%d\n", IP4(ip), prefix);
			}
			tx_drop(mbufs[j]);
			break;
		case MAC_INFO_FROM_MASTER:
			hdr_arp = rte_pktmbuf_mtod(mbufs[j], struct ether_hdr_arp *);
			ip = get_ip(mbufs[j]);

			if (prox_rte_is_zero_ether_addr(&hdr_arp->arp.data.sha)) {
				// MAC timeout or deleted from kernel table => reset update_time
				// This will cause us to send new ARP request
				// However, as reachable_timeout not touched, we should continue sending our regular IP packets
				reset_arp_ndp_retransmit_timeout(l3, ip);
				return;
			} else
				plogx_dbg("\tUpdating MAC entry for IP "IPv4_BYTES_FMT" with MAC "MAC_BYTES_FMT"\n",
					IP4(ip), MAC_BYTES(hdr_arp->arp.data.sha.addr_bytes));

			if (l3->ipv4_lpm) {
				uint32_t nh;
				struct arp_table *entry;
				ret = rte_hash_add_key(l3->ip_hash, (const void *)&ip);
				if (ret < 0) {
					plogx_info("Unable add ip "IPv4_BYTES_FMT" in mac_hash\n", IP4(ip));
				} else if ((nh = l3->arp_table[ret].nh) != MAX_HOP_INDEX) {
					entry = &l3->next_hops[nh];
					memcpy(&entry->mac, &(hdr_arp->arp.data.sha), sizeof(prox_rte_ether_addr));
					entry->reachable_timeout = tsc + reachable_timeout;
					update_arp_ndp_retransmit_timeout(l3, &entry->arp_ndp_retransmit_timeout, l3->arp_ndp_retransmit_timeout);
				} else {
					memcpy(&l3->arp_table[ret].mac, &(hdr_arp->arp.data.sha), sizeof(prox_rte_ether_addr));
					l3->arp_table[ret].reachable_timeout = tsc + reachable_timeout;
					update_arp_ndp_retransmit_timeout(l3, &l3->arp_table[ret].arp_ndp_retransmit_timeout, l3->arp_ndp_retransmit_timeout);
				}
			}
			else if (ip == l3->gw.ip) {
				// MAC address of the gateway
				memcpy(&l3->gw.mac, &hdr_arp->arp.data.sha, 6);
				l3->flags |= FLAG_DST_MAC_KNOWN;
				l3->gw.reachable_timeout = tsc + reachable_timeout;
				update_arp_ndp_retransmit_timeout(l3, &l3->gw.arp_ndp_retransmit_timeout, l3->arp_ndp_retransmit_timeout);
			} else if (l3->n_pkts < 4) {
				// Few packets tracked - should be faster to loop through them thean using a hash table
				for (idx = 0; idx < l3->n_pkts; idx++) {
					ip_dst = l3->optimized_arp_table[idx].ip;
					if (ip_dst == ip)
						break;
				}
				if (idx < l3->n_pkts) {
					memcpy(&l3->optimized_arp_table[idx].mac, &(hdr_arp->arp.data.sha), sizeof(prox_rte_ether_addr));
					l3->optimized_arp_table[idx].reachable_timeout = tsc + reachable_timeout;
					update_arp_ndp_retransmit_timeout(l3, &l3->optimized_arp_table[idx].arp_ndp_retransmit_timeout, l3->arp_ndp_retransmit_timeout);
				}
			} else {
				ret = rte_hash_add_key(l3->ip_hash, (const void *)&ip);
				if (ret < 0) {
					plogx_info("Unable add ip "IPv4_BYTES_FMT" in mac_hash\n", IP4(ip));
				} else {
					memcpy(&l3->arp_table[ret].mac, &(hdr_arp->arp.data.sha), sizeof(prox_rte_ether_addr));
					l3->arp_table[ret].reachable_timeout = tsc + reachable_timeout;
					update_arp_ndp_retransmit_timeout(l3, &l3->arp_table[ret].arp_ndp_retransmit_timeout, l3->arp_ndp_retransmit_timeout);
				}
			}
			tx_drop(mbufs[j]);
			break;
		case MAC_INFO_FROM_MASTER_FOR_IPV6:
			ip6 = ctrl_ring_get_ipv6_addr(mbufs[j]);
			uint64_t data = ctrl_ring_get_data(mbufs[j]);

			if (l3->n_pkts < 4) {
				// Few packets tracked - should be faster to loop through them thean using a hash table
				for (idx = 0; idx < l3->n_pkts; idx++) {
					ip6_dst = &l3->optimized_arp_table[idx].ip6;
					if (memcmp(ip6_dst, ip6, sizeof(struct ipv6_addr)) == 0)
						break;
				}
				if (idx < l3->n_pkts) {
					// IP found; this is a reply for one of our requests!
					memcpy(&l3->optimized_arp_table[idx].mac, &data, sizeof(prox_rte_ether_addr));
					l3->optimized_arp_table[idx].reachable_timeout = tsc + l3->reachable_timeout * hz / 1000;
				}
			} else {
				int ret = rte_hash_add_key(l3->ip6_hash, (const void *)ip6);
				if (ret < 0) {
					plogx_info("Unable add ip "IPv6_BYTES_FMT" in mac_hash\n", IPv6_BYTES(ip6->bytes));
				} else {
					memcpy(&l3->arp_table[ret].mac, &data, sizeof(prox_rte_ether_addr));
					l3->arp_table[ret].reachable_timeout = tsc + l3->reachable_timeout * hz / 1000;
				}
			}
			tx_drop(mbufs[j]);
			break;
		case SEND_NDP_FROM_MASTER:
		case SEND_ARP_REQUEST_FROM_MASTER:
		case SEND_ARP_REPLY_FROM_MASTER:
			out[0] = 0;
			// tx_ctrlplane_pkt does not drop packets
			plogx_dbg("\tForwarding (ARP) packet from master\n");
			tbase->aux->tx_ctrlplane_pkt(tbase, &mbufs[j], 1, out);
			TASK_STATS_ADD_TX_NON_DP(&tbase->aux->stats, 1);
			break;
		case SEND_ICMP_FROM_MASTER:
			out[0] = 0;
			// tx_ctrlplane_pkt does not drop packets
			plogx_dbg("\tForwarding (PING) packet from master\n");
			tbase->aux->tx_ctrlplane_pkt(tbase, &mbufs[j], 1, out);
			TASK_STATS_ADD_TX_NON_DP(&tbase->aux->stats, 1);
			break;
		case PKT_FROM_TAP:
			// Drop Pseudo packets sent to generate ARP requests
			// There are other IPv4 packets sent from TAP which we cannot delete e.g. BGP packets
			out[0] = 0;
			hdr = rte_pktmbuf_mtod(mbufs[j], prox_rte_ether_hdr *);
			if (hdr->ether_type == ETYPE_IPv4) {
				pip = (prox_rte_ipv4_hdr *)(hdr + 1);
			} else if (hdr->ether_type == ETYPE_VLAN) {
				prox_rte_vlan_hdr *vlan = (prox_rte_vlan_hdr *)(hdr + 1);
				vlan = (prox_rte_vlan_hdr *)(hdr + 1);
				if (vlan->eth_proto == ETYPE_IPv4) {
					pip = (prox_rte_ipv4_hdr *)(vlan + 1);
				}
			}
			if (pip && (pip->next_proto_id == IPPROTO_UDP)) {
				udp_hdr = (prox_rte_udp_hdr *)(pip + 1);
				if ((udp_hdr->dst_port == rte_cpu_to_be_16(PROX_PSEUDO_PKT_PORT)) &&
					(udp_hdr->src_port == rte_cpu_to_be_16(PROX_PSEUDO_PKT_PORT)) &&
					(rte_be_to_cpu_16(udp_hdr->dgram_len) == 8)) {
					plogx_dbg("Dropping PROX packet\n");
					tx_drop(mbufs[j]);
					return;
				}
			}
/* Debugging ...
			uint16_t src_port = 0, dst_port = 0, len = 0;
			if (udp_hdr) {
				src_port = udp_hdr->src_port;
				dst_port = udp_hdr->dst_port;
				len = rte_be_to_cpu_16(udp_hdr->dgram_len);
			}
			plogx_dbg("tForwarding TAP packet from master. Type = %x, pip=%p, udp = %p, udp = {src = %x, dst = %x, len = %d}\n", hdr->ether_type, pip, udp_hdr, src_port, dst_port,len );
*/
			// tx_ctrlplane_pkt does not drop packets
			tbase->aux->tx_ctrlplane_pkt(tbase, &mbufs[j], 1, out);
			TASK_STATS_ADD_TX_NON_DP(&tbase->aux->stats, 1);
			break;
		case IPV6_INFO_FROM_MASTER:
			// addr = ctrl_ring_get_data(mbufs[j]);
			ip6 = ctrl_ring_get_ipv6_addr(mbufs[j]);
			if (memcmp(&l3->global_ipv6 , &null_addr, 16) == 0) {
				memcpy(&l3->global_ipv6, ip6, sizeof(struct ipv6_addr));
				plog_info("Core %d task %d received global IP "IPv6_BYTES_FMT"\n", l3->core_id, l3->task_id, IPv6_BYTES(ip6->bytes));
			} else if (memcmp(&l3->global_ipv6, ip6, 8) == 0) {
				if (l3->prefix_printed == 0) {
					plog_info("Core %d task %d received expected prefix "IPv6_PREFIX_FMT"\n", l3->core_id, l3->task_id, IPv6_PREFIX(ip6->bytes));
					l3->prefix_printed = 1;
				}
			} else {
				plog_warn("Core %d task %d received unexpected prefix "IPv6_PREFIX_FMT", IP = "IPv6_PREFIX_FMT"\n", l3->core_id, l3->task_id, IPv6_PREFIX(ip6->bytes), IPv6_PREFIX(l3->global_ipv6.bytes));
			}
			tx_drop(mbufs[j]);
			break;
		default:
			plog_err("Unexpected message received: %d\n", command);
			tx_drop(mbufs[j]);
			break;
		}
	}
}
