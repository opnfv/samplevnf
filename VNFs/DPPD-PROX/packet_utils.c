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

#include <rte_lcore.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include "task_base.h"
#include "lconf.h"
#include "prefetch.h"
#include "log.h"
#include "handle_master.h"
#include "prox_port_cfg.h"

static inline int find_ip(struct ether_hdr_arp *pkt, uint16_t len, uint32_t *ip_dst)
{
	struct vlan_hdr *vlan_hdr;
	struct ether_hdr *eth_hdr = (struct ether_hdr*)pkt;
	struct ipv4_hdr *ip;
	uint16_t ether_type = eth_hdr->ether_type;
	uint16_t l2_len = sizeof(struct ether_hdr);

	// Unstack VLAN tags
	while (((ether_type == ETYPE_8021ad) || (ether_type == ETYPE_VLAN)) && (l2_len + sizeof(struct vlan_hdr) < len)) {
		vlan_hdr = (struct vlan_hdr *)((uint8_t *)pkt + l2_len);
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

	if (l2_len && (l2_len + sizeof(struct ipv4_hdr) <= len)) {
		struct ipv4_hdr *ip = (struct ipv4_hdr *)((uint8_t *)pkt + l2_len);
		// TODO: implement LPM => replace ip_dst by next hop IP DST
		*ip_dst = ip->dst_addr;
		return 0;
	}
	return -1;
}

/* This implementation could be improved: instead of checking each time we send a packet whether we need also
   to send an ARP, we should only check whether the MAC is valid.
   We should check arp_update_time in the master process. This would also require the generating task to clear its arp ring
   to avoid sending many ARP while starting after a long stop.
   We could also check for arp_timeout in the master so that dataplane has only to check whether MAC is available
   but this would require either thread safety, or the the exchange of information between master and generating core.
*/

int write_dst_mac(struct task_base *tbase, struct rte_mbuf *mbuf, uint32_t *ip_dst)
{
	const uint64_t hz = rte_get_tsc_hz();
	struct ether_hdr_arp *packet = rte_pktmbuf_mtod(mbuf, struct ether_hdr_arp *);
	struct ether_addr *mac = &packet->ether_hdr.d_addr;

	uint64_t tsc = rte_rdtsc();
	struct l3_base *l3 = &(tbase->l3);
	if (l3->gw.ip) {
		if (likely((l3->flags & FLAG_DST_MAC_KNOWN) && (tsc < l3->gw.arp_update_time) && (tsc < l3->gw.arp_timeout))) {
			memcpy(mac, &l3->gw.mac, sizeof(struct ether_addr));
			return SEND_MBUF;
		} else if (tsc > l3->gw.arp_update_time) {
			// long time since we have sent an arp, send arp
			l3->gw.arp_update_time = tsc + l3->arp_update_time * hz / 1000;
			*ip_dst = l3->gw.ip;
			if ((l3->flags & FLAG_DST_MAC_KNOWN) && (tsc < l3->gw.arp_timeout)){
				// MAC is valid in the table => send also the mbuf
				memcpy(mac, &l3->gw.mac, sizeof(struct ether_addr));
				return SEND_MBUF_AND_ARP;
			} else {
				// MAC still unknown, or timed out => only send ARP
				return SEND_ARP;
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
				if ((tsc < l3->optimized_arp_table[idx].arp_update_time) && (tsc < l3->optimized_arp_table[idx].arp_timeout)) {
					// MAC address was recently updated in table, use it
					memcpy(mac, &l3->optimized_arp_table[idx].mac, sizeof(struct ether_addr));
					return SEND_MBUF;
				} else if (tsc > l3->optimized_arp_table[idx].arp_update_time) {
					// ARP not sent since a long time, send ARP
					l3->optimized_arp_table[idx].arp_update_time = tsc + l3->arp_update_time * hz / 1000;
					if (tsc < l3->optimized_arp_table[idx].arp_timeout) {
						// MAC still valid => also send mbuf
						memcpy(mac, &l3->optimized_arp_table[idx].mac, sizeof(struct ether_addr));
						return SEND_MBUF_AND_ARP;
					} else {
						// MAC unvalid => only send ARP
						return SEND_ARP;
					}
				} else {
					//  ARP timeout elapsed, MAC not valid anymore but waiting for ARP reply
					return DROP_MBUF;
				}
			}
		}
		// IP address not found in table
		l3->optimized_arp_table[l3->n_pkts].ip = *ip_dst;
		l3->optimized_arp_table[l3->n_pkts].arp_update_time = tsc + l3->arp_update_time * hz / 1000;
		l3->n_pkts++;

		if (l3->n_pkts < 4) {
			return SEND_ARP;
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
		return SEND_ARP;
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
				l3->arp_table[ret].arp_update_time = tsc + l3->arp_update_time * hz / 1000;
			}
			return SEND_ARP;
		} else {
			// IP has been found
			if (likely((tsc < l3->arp_table[ret].arp_update_time) && (tsc < l3->arp_table[ret].arp_timeout))) {
				// MAC still valid and ARP sent recently
				memcpy(mac, &l3->arp_table[ret].mac, sizeof(struct ether_addr));
				return SEND_MBUF;
			} else if (tsc > l3->arp_table[ret].arp_update_time) {
				// ARP not sent since a long time, send ARP
				l3->arp_table[ret].arp_update_time = tsc + l3->arp_update_time * hz / 1000;
				if (tsc < l3->arp_table[ret].arp_timeout) {
					// MAC still valid => send also MBUF
					memcpy(mac, &l3->arp_table[ret].mac, sizeof(struct ether_addr));
					return SEND_MBUF_AND_ARP;
				} else {
					return SEND_ARP;
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
	tbase->l3.ip_hash = rte_hash_create(&hash_params);
	PROX_PANIC(tbase->l3.ip_hash == NULL, "Failed to set up ip hash table\n");

	tbase->l3.arp_table = (struct arp_table *)prox_zmalloc(n_entries * sizeof(struct arp_table), socket_id);
	PROX_PANIC(tbase->l3.arp_table == NULL, "Failed to allocate memory for %u entries in arp table\n", n_entries);
	plog_info("\tarp table, with %d entries of size %ld\n", n_entries, sizeof(struct l3_base));

	targ->lconf->ctrl_func_p[targ->task] = handle_ctrl_plane_pkts;
	targ->lconf->ctrl_timeout = freq_to_tsc(targ->ctrl_freq);
	tbase->l3.gw.ip = rte_cpu_to_be_32(targ->gateway_ipv4);
	tbase->flags |= TASK_L3;
	tbase->l3.core_id = targ->lconf->id;
	tbase->l3.task_id = targ->id;
	tbase->l3.tmaster = targ->tmaster;
	if (tbase->l3.arp_timeout != 0)
		tbase->l3.arp_timeout = targ->arp_timeout;
	else
		tbase->l3.arp_timeout = DEFAULT_ARP_TIMEOUT;
	if (tbase->l3.arp_update_time != 0)
		tbase->l3.arp_update_time = targ->arp_update_time;
	else
		tbase->l3.arp_update_time = DEFAULT_ARP_UPDATE_TIME;
}

void task_start_l3(struct task_base *tbase, struct task_args *targ)
{
	const int NB_ARP_MBUF = 1024;
	const int ARP_MBUF_SIZE = 2048;
	const int NB_CACHE_ARP_MBUF = 256;

	struct prox_port_cfg *port = find_reachable_port(targ);
        if (port && (tbase->l3.arp_pool == NULL)) {
		static char name[] = "arp0_pool";
                tbase->l3.reachable_port_id = port - prox_port_cfg;
		if (targ->local_ipv4) {
			tbase->local_ipv4 = rte_be_to_cpu_32(targ->local_ipv4);
			register_ip_to_ctrl_plane(tbase->l3.tmaster, tbase->local_ipv4, tbase->l3.reachable_port_id, targ->lconf->id, targ->id);
        	}
		name[3]++;
		struct rte_mempool *ret = rte_mempool_create(name, NB_ARP_MBUF, ARP_MBUF_SIZE, NB_CACHE_ARP_MBUF,
			sizeof(struct rte_pktmbuf_pool_private), rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, 0,
			rte_socket_id(), 0);
		PROX_PANIC(ret == NULL, "Failed to allocate ARP memory pool on socket %u with %u elements\n",
			rte_socket_id(), NB_ARP_MBUF);
		plog_info("\t\tMempool %p (%s) size = %u * %u cache %u, socket %d\n", ret, name, NB_ARP_MBUF,
			ARP_MBUF_SIZE, NB_CACHE_ARP_MBUF, rte_socket_id());
		tbase->l3.arp_pool = ret;
	}
}

void task_set_gateway_ip(struct task_base *tbase, uint32_t ip)
{
	tbase->l3.gw.ip = ip;
	tbase->flags &= ~FLAG_DST_MAC_KNOWN;
}

void task_set_local_ip(struct task_base *tbase, uint32_t ip)
{
	tbase->local_ipv4 = ip;
}

void handle_ctrl_plane_pkts(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	uint8_t out[1];
	const uint64_t hz = rte_get_tsc_hz();
	uint32_t ip, ip_dst, idx;
	int j;
	uint16_t command;
	struct ether_hdr_arp *hdr;
	struct l3_base *l3 = &tbase->l3;
	uint64_t tsc= rte_rdtsc();

	for (j = 0; j < n_pkts; ++j) {
		PREFETCH0(mbufs[j]);
	}
	for (j = 0; j < n_pkts; ++j) {
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j], void *));
	}

	for (j = 0; j < n_pkts; ++j) {
		out[0] = OUT_HANDLED;
		command = mbufs[j]->udata64 & 0xFFFF;
		plogx_dbg("\tReceived %s mbuf %p\n", actions_string[command], mbufs[j]);
		switch(command) {
		case UPDATE_FROM_CTRL:
			hdr = rte_pktmbuf_mtod(mbufs[j], struct ether_hdr_arp *);
			ip = (mbufs[j]->udata64 >> 32) & 0xFFFFFFFF;

			if (ip == l3->gw.ip) {
				// MAC address of the gateway
				memcpy(&l3->gw.mac, &hdr->arp.data.sha, 6);
				l3->flags |= FLAG_DST_MAC_KNOWN;
				l3->gw.arp_timeout = tsc + l3->arp_timeout * hz / 1000;
			} else if (l3->n_pkts < 4) {
				// Few packets tracked - should be faster to loop through them thean using a hash table
				for (idx = 0; idx < l3->n_pkts; idx++) {
					ip_dst = l3->optimized_arp_table[idx].ip;
					if (ip_dst == ip)
						break;
				}
				if (idx < l3->n_pkts) {
					// IP not found; this is a reply while we never asked for the request!
					memcpy(&l3->optimized_arp_table[idx].mac, &(hdr->arp.data.sha), sizeof(struct ether_addr));
					l3->optimized_arp_table[idx].arp_timeout = tsc + l3->arp_timeout * hz / 1000;
				}
			} else {
				int ret = rte_hash_add_key(l3->ip_hash, (const void *)&ip);
				if (ret < 0) {
					plogx_info("Unable add ip %d.%d.%d.%d in mac_hash\n", IP4(ip));
				} else {
					memcpy(&l3->arp_table[ret].mac, &(hdr->arp.data.sha), sizeof(struct ether_addr));
					l3->arp_table[ret].arp_timeout = tsc + l3->arp_timeout * hz / 1000;
				}
			}
			tx_drop(mbufs[j]);
			break;
		case ARP_REPLY_FROM_CTRL:
		case ARP_REQ_FROM_CTRL:
			out[0] = 0;
			// tx_ctrlplane_pkt does not drop packets
			tbase->aux->tx_ctrlplane_pkt(tbase, &mbufs[j], 1, out);
			TASK_STATS_ADD_TX_NON_DP(&tbase->aux->stats, 1);
			break;
		}
	}
}
