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
#include "task_base.h"
#include "lconf.h"
#include "prefetch.h"
#include "log.h"
#include "handle_master.h"
#include "prox_port_cfg.h"
#include "prox_cfg.h"
#include "defines.h"
#include "prox_ipv6.h"
#include "tx_pkt.h"

static inline int find_ip(struct ether_hdr_arp *pkt, uint16_t len, uint32_t *ip_dst)
{
	prox_rte_vlan_hdr *vlan_hdr;
	prox_rte_ether_hdr *eth_hdr = (prox_rte_ether_hdr*)pkt;
	prox_rte_ipv4_hdr *ip;
	uint16_t ether_type = eth_hdr->ether_type;
	uint16_t l2_len = sizeof(prox_rte_ether_hdr);

	// Unstack VLAN tags
	while (((ether_type == ETYPE_8021ad) || (ether_type == ETYPE_VLAN)) && (l2_len + sizeof(prox_rte_vlan_hdr) < len)) {
		vlan_hdr = (prox_rte_vlan_hdr *)((uint8_t *)pkt + l2_len);
		l2_len +=4;
		ether_type = vlan_hdr->eth_proto;
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

static inline struct ipv6_addr *find_ip6(prox_rte_ether_hdr *pkt, uint16_t len, struct ipv6_addr *ip_dst)
{
	prox_rte_vlan_hdr *vlan_hdr;
	prox_rte_ipv6_hdr *ip;
	uint16_t ether_type = pkt->ether_type;
	uint16_t l2_len = sizeof(prox_rte_ether_hdr);

	// Unstack VLAN tags
	while (((ether_type == ETYPE_8021ad) || (ether_type == ETYPE_VLAN)) && (l2_len + sizeof(prox_rte_vlan_hdr) < len)) {
		vlan_hdr = (prox_rte_vlan_hdr *)((uint8_t *)pkt + l2_len);
		l2_len +=4;
		ether_type = vlan_hdr->eth_proto;
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

int write_dst_mac(struct task_base *tbase, struct rte_mbuf *mbuf, uint32_t *ip_dst)
{
	const uint64_t hz = rte_get_tsc_hz();
	struct ether_hdr_arp *packet = rte_pktmbuf_mtod(mbuf, struct ether_hdr_arp *);
	prox_rte_ether_addr *mac = &packet->ether_hdr.d_addr;

	uint64_t tsc = rte_rdtsc();
	struct l3_base *l3 = &(tbase->l3);
	if (l3->gw.ip) {
		if (likely((l3->flags & FLAG_DST_MAC_KNOWN) && (tsc < l3->gw.arp_ndp_retransmit_timeout) && (tsc < l3->gw.reachable_timeout))) {
			memcpy(mac, &l3->gw.mac, sizeof(prox_rte_ether_addr));
			return SEND_MBUF;
		} else if (tsc > l3->gw.arp_ndp_retransmit_timeout) {
			// long time since we have sent an arp, send arp
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

	uint16_t len = rte_pktmbuf_pkt_len(mbuf);
	if (find_ip(packet, len, ip_dst) != 0) {
		// Unable to find IP address => non IP packet => send it as it
		return SEND_MBUF;
	}
	if (likely(l3->n_pkts < 4)) {
		for (unsigned int idx = 0; idx < l3->n_pkts; idx++) {
			if (*ip_dst == l3->optimized_arp_table[idx].ip) {
				// IP address already in table
				if ((tsc < l3->optimized_arp_table[idx].arp_ndp_retransmit_timeout) && (tsc < l3->optimized_arp_table[idx].reachable_timeout)) {
					// MAC address was recently updated in table, use it
					memcpy(mac, &l3->optimized_arp_table[idx].mac, sizeof(prox_rte_ether_addr));
					return SEND_MBUF;
				} else if (tsc > l3->optimized_arp_table[idx].arp_ndp_retransmit_timeout) {
					// ARP not sent since a long time, send ARP
					l3->optimized_arp_table[idx].arp_ndp_retransmit_timeout = tsc + l3->arp_ndp_retransmit_timeout * hz / 1000;
					if (tsc < l3->optimized_arp_table[idx].reachable_timeout) {
						// MAC still valid => also send mbuf
						memcpy(mac, &l3->optimized_arp_table[idx].mac, sizeof(prox_rte_ether_addr));
						return SEND_MBUF_AND_ARP_ND;
					} else {
						// MAC unvalid => only send ARP
						return SEND_ARP_ND;
					}
				} else {
					//  ARP timeout elapsed, MAC not valid anymore but waiting for ARP reply
					return DROP_MBUF;
				}
			}
		}
		// IP address not found in table
		l3->optimized_arp_table[l3->n_pkts].ip = *ip_dst;
		l3->optimized_arp_table[l3->n_pkts].arp_ndp_retransmit_timeout = tsc + l3->arp_ndp_retransmit_timeout * hz / 1000;
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
				plogx_err("Unable add ip %d.%d.%d.%d in mac_hash (already %d entries)\n", IP4(ip), idx);
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
			int ret = rte_hash_add_key(l3->ip_hash, (const void *)ip_dst);
			if (ret < 0) {
				// No reason to send ARP, as reply would be anyhow ignored
				plogx_err("Unable to add ip %d.%d.%d.%d in mac_hash\n", IP4(*ip_dst));
				return DROP_MBUF;
			} else {
				l3->arp_table[ret].ip = *ip_dst;
				l3->arp_table[ret].arp_ndp_retransmit_timeout = tsc + l3->arp_ndp_retransmit_timeout * hz / 1000;
			}
			return SEND_ARP_ND;
		} else {
			// IP has been found
			if (likely((tsc < l3->arp_table[ret].arp_ndp_retransmit_timeout) && (tsc < l3->arp_table[ret].reachable_timeout))) {
				// MAC still valid and ARP sent recently
				memcpy(mac, &l3->arp_table[ret].mac, sizeof(prox_rte_ether_addr));
				return SEND_MBUF;
			} else if (tsc > l3->arp_table[ret].arp_ndp_retransmit_timeout) {
				// ARP not sent since a long time, send ARP
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

int write_ip6_dst_mac(struct task_base *tbase, struct rte_mbuf *mbuf, struct ipv6_addr *ip_dst)
{
	const uint64_t hz = rte_get_tsc_hz();
	prox_rte_ether_hdr *packet = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
	prox_rte_ether_addr *mac = &packet->d_addr;
	struct ipv6_addr *used_ip_src;

	uint64_t tsc = rte_rdtsc();
	uint16_t len = rte_pktmbuf_pkt_len(mbuf);

	struct ipv6_addr *pkt_src_ip6;
	if ((pkt_src_ip6 = find_ip6(packet, len, ip_dst)) == NULL) {
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
	if (tbase->l3.reachable_timeout != 0)
		tbase->l3.reachable_timeout = targ->reachable_timeout;
	else
		tbase->l3.reachable_timeout = DEFAULT_ARP_TIMEOUT;
	if (tbase->l3.arp_ndp_retransmit_timeout != 0)
		tbase->l3.arp_ndp_retransmit_timeout = targ->arp_ndp_retransmit_timeout;
	else
		tbase->l3.arp_ndp_retransmit_timeout = DEFAULT_ARP_UPDATE_TIME;
}

void task_start_l3(struct task_base *tbase, struct task_args *targ)
{
	const int NB_ARP_ND_MBUF = 1024;
	const int ARP_ND_MBUF_SIZE = 2048;
	const int NB_CACHE_ARP_ND_MBUF = 256;

	struct prox_port_cfg *port = find_reachable_port(targ);
        if (port && (tbase->l3.arp_nd_pool == NULL)) {
		static char name[] = "arp0_pool";
                tbase->l3.reachable_port_id = port - prox_port_cfg;
		if (targ->local_ipv4) {
			tbase->l3.local_ipv4 = rte_be_to_cpu_32(targ->local_ipv4);
			register_ip_to_ctrl_plane(tbase->l3.tmaster, tbase->l3.local_ipv4, tbase->l3.reachable_port_id, targ->lconf->id, targ->id);
        	}

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
			send_router_sollicitation(tbase, targ);
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

void handle_ctrl_plane_pkts(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	uint8_t out[1];
	const uint64_t hz = rte_get_tsc_hz();
	uint64_t addr;
	uint32_t ip, ip_dst, idx;
	struct ipv6_addr *ip6, *ip6_dst;
	int j;
	uint16_t command;
	struct ether_hdr_arp *hdr;
	struct l3_base *l3 = &tbase->l3;
	uint64_t tsc= rte_rdtsc();
	uint8_t port = tbase->l3.reachable_port_id;

	for (j = 0; j < n_pkts; ++j) {
		PREFETCH0(mbufs[j]);
	}
	for (j = 0; j < n_pkts; ++j) {
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j], void *));
	}

	for (j = 0; j < n_pkts; ++j) {
		out[0] = OUT_HANDLED;
		command = ctrl_ring_get_command(mbufs[j]) & 0xFFFF;
		plogx_dbg("\tReceived %s mbuf %p\n", actions_string[command], mbufs[j]);
		switch(command) {
		case MAC_INFO_FROM_MASTER:
			hdr = rte_pktmbuf_mtod(mbufs[j], struct ether_hdr_arp *);
			ip = (ctrl_ring_get_command(mbufs[j]) >> 32) & 0xFFFFFFFF;

			if (ip == l3->gw.ip) {
				// MAC address of the gateway
				memcpy(&l3->gw.mac, &hdr->arp.data.sha, 6);
				l3->flags |= FLAG_DST_MAC_KNOWN;
				l3->gw.reachable_timeout = tsc + l3->reachable_timeout * hz / 1000;
			} else if (l3->n_pkts < 4) {
				// Few packets tracked - should be faster to loop through them thean using a hash table
				for (idx = 0; idx < l3->n_pkts; idx++) {
					ip_dst = l3->optimized_arp_table[idx].ip;
					if (ip_dst == ip)
						break;
				}
				if (idx < l3->n_pkts) {
					// IP found; this is a reply of one of our requests!
					memcpy(&l3->optimized_arp_table[idx].mac, &(hdr->arp.data.sha), sizeof(prox_rte_ether_addr));
					l3->optimized_arp_table[idx].reachable_timeout = tsc + l3->reachable_timeout * hz / 1000;
				}
			} else {
				int ret = rte_hash_add_key(l3->ip_hash, (const void *)&ip);
				if (ret < 0) {
					plogx_info("Unable add ip %d.%d.%d.%d in mac_hash\n", IP4(ip));
				} else {
					memcpy(&l3->arp_table[ret].mac, &(hdr->arp.data.sha), sizeof(prox_rte_ether_addr));
					l3->arp_table[ret].reachable_timeout = tsc + l3->reachable_timeout * hz / 1000;
				}
			}
			tx_drop(mbufs[j]);
			break;
		case MAC_INFO_FROM_MASTER_FOR_IPV6:
			hdr = rte_pktmbuf_mtod(mbufs[j], struct ether_hdr_arp *);
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
		case TX_NDP_FROM_MASTER:
		case TX_ARP_REQ_FROM_MASTER:
		case TX_ARP_REPLY_FROM_MASTER:
			out[0] = 0;
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
