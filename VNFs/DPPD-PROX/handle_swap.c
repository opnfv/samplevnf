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

#include <rte_mbuf.h>
#include <rte_udp.h>

#include "task_init.h"
#include "task_base.h"
#include "lconf.h"
#include "log.h"
#include "prox_port_cfg.h"
#include "mpls.h"
#include "qinq.h"
#include "gre.h"
#include "prefetch.h"
#include "defines.h"
#include "igmp.h"
#include "prox_cksum.h"
#include "prox_compat.h"

struct task_swap {
	struct task_base base;
	struct rte_mempool *igmp_pool;
	uint32_t runtime_flags;
	uint32_t igmp_address;
	uint8_t src_dst_mac[12];
	uint32_t local_ipv4;
	int offload_crc;
	uint64_t last_echo_req_rcvd_tsc;
	uint64_t last_echo_rep_rcvd_tsc;
	uint32_t n_echo_req;
	uint32_t n_echo_rep;
};

#define NB_IGMP_MBUF  		1024
#define IGMP_MBUF_SIZE 		2048
#define NB_CACHE_IGMP_MBUF  	256

static void write_src_and_dst_mac(struct task_swap *task, struct rte_mbuf *mbuf)
{
	prox_rte_ether_hdr *hdr;
	prox_rte_ether_addr mac;

	if (unlikely((task->runtime_flags & (TASK_ARG_DST_MAC_SET|TASK_ARG_SRC_MAC_SET)) == (TASK_ARG_DST_MAC_SET|TASK_ARG_SRC_MAC_SET))) {
		/* Source and Destination mac hardcoded */
		hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
              	rte_memcpy(hdr, task->src_dst_mac, sizeof(task->src_dst_mac));
	} else {
		hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
		if (likely((task->runtime_flags & TASK_ARG_SRC_MAC_SET) == 0)) {
			/* dst mac will be used as src mac */
			prox_rte_ether_addr_copy(&hdr->d_addr, &mac);
		}

		if (unlikely(task->runtime_flags & TASK_ARG_DST_MAC_SET))
			prox_rte_ether_addr_copy((prox_rte_ether_addr *)&task->src_dst_mac[0], &hdr->d_addr);
		else
			prox_rte_ether_addr_copy(&hdr->s_addr, &hdr->d_addr);

		if (unlikely(task->runtime_flags & TASK_ARG_SRC_MAC_SET)) {
			prox_rte_ether_addr_copy((prox_rte_ether_addr *)&task->src_dst_mac[6], &hdr->s_addr);
		} else {
			prox_rte_ether_addr_copy(&mac, &hdr->s_addr);
		}
	}
}
static inline void build_mcast_mac(uint32_t ip, prox_rte_ether_addr *dst_mac)
{
	// MAC address is 01:00:5e followed by 23 LSB of IP address
	uint64_t mac = 0x0000005e0001L | ((ip & 0xFFFF7F00L) << 16);
	memcpy(dst_mac, &mac, sizeof(prox_rte_ether_addr));
}

static inline void build_icmp_reply_message(struct task_base *tbase, struct rte_mbuf *mbuf)
{
	struct task_swap *task = (struct task_swap *)tbase;
	prox_rte_ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
	prox_rte_ether_addr dst_mac;
	prox_rte_ether_addr_copy(&hdr->s_addr, &dst_mac);
	prox_rte_ether_addr_copy(&hdr->d_addr, &hdr->s_addr);
	prox_rte_ether_addr_copy(&dst_mac, &hdr->d_addr);
	prox_rte_ipv4_hdr *ip_hdr = (prox_rte_ipv4_hdr *)(hdr + 1);
	ip_hdr->dst_addr = ip_hdr->src_addr;
	ip_hdr->src_addr = task->local_ipv4;
	prox_rte_icmp_hdr *picmp = (prox_rte_icmp_hdr *)(ip_hdr + 1);
	picmp->icmp_type = PROX_RTE_IP_ICMP_ECHO_REPLY;
}

static inline void build_igmp_message(struct task_base *tbase, struct rte_mbuf *mbuf, uint32_t ip, uint8_t igmp_message)
{
	struct task_swap *task = (struct task_swap *)tbase;
	prox_rte_ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
	prox_rte_ether_addr dst_mac;
	build_mcast_mac(ip, &dst_mac);

        rte_pktmbuf_pkt_len(mbuf) = 46;
        rte_pktmbuf_data_len(mbuf) = 46;
        init_mbuf_seg(mbuf);

        prox_rte_ether_addr_copy(&dst_mac, &hdr->d_addr);
	prox_rte_ether_addr_copy((prox_rte_ether_addr *)&task->src_dst_mac[6], &hdr->s_addr);
	hdr->ether_type = ETYPE_IPv4;

	prox_rte_ipv4_hdr *ip_hdr = (prox_rte_ipv4_hdr *)(hdr + 1);
	ip_hdr->version_ihl = 0x45;		/**< version and header length */
	ip_hdr->type_of_service = 0;	/**< type of service */
	ip_hdr->total_length = rte_cpu_to_be_16(32);		/**< length of packet */
	ip_hdr->packet_id = 0;		/**< packet ID */
	ip_hdr->fragment_offset = 0;	/**< fragmentation offset */
	ip_hdr->time_to_live = 1;		/**< time to live */
	ip_hdr->next_proto_id = IPPROTO_IGMP;		/**< protocol ID */
	ip_hdr->hdr_checksum = 0;		/**< header checksum */
	ip_hdr->src_addr = task->local_ipv4;		/**< source address */
	ip_hdr->dst_addr = ip;	/**< destination address */
	struct igmpv2_hdr *pigmp = (struct igmpv2_hdr *)(ip_hdr + 1);
	pigmp->type = igmp_message;
	pigmp->max_resp_time = 0;
	pigmp->checksum = 0;
	pigmp->group_address = ip;
	prox_ip_udp_cksum(mbuf, ip_hdr, sizeof(prox_rte_ether_hdr), sizeof(prox_rte_ipv4_hdr), task->offload_crc);
}

static void stop_swap(struct task_base *tbase)
{
	struct task_swap *task = (struct task_swap *)tbase;
	if (task->igmp_pool) {
		rte_mempool_free(task->igmp_pool);
		task->igmp_pool = NULL;
	}
}

static void handle_ipv6(struct task_swap *task, struct rte_mbuf *mbufs, prox_rte_ipv6_hdr *ipv6_hdr, uint8_t *out)
{
	__m128i ip =  _mm_loadu_si128((__m128i*)&(ipv6_hdr->src_addr));
	uint16_t port;
	uint16_t payload_len;
	prox_rte_udp_hdr *udp_hdr;

	rte_mov16((uint8_t *)&(ipv6_hdr->src_addr), (uint8_t *)&(ipv6_hdr->dst_addr));	// Copy dst into src
	rte_mov16((uint8_t *)&(ipv6_hdr->dst_addr), (uint8_t *)&ip);			// Copy src into dst
	switch(ipv6_hdr->proto) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			payload_len = ipv6_hdr->payload_len;
			udp_hdr = (prox_rte_udp_hdr *)(ipv6_hdr + 1);
			if (unlikely(udp_hdr->dgram_len < payload_len)) {
				plog_warn("Unexpected L4 len (%u) versus L3 payload len (%u) in IPv6 packet\n", udp_hdr->dgram_len, payload_len);
				*out = OUT_DISCARD;
				break;
			}
			port = udp_hdr->dst_port;
			udp_hdr->dst_port = udp_hdr->src_port;
			udp_hdr->src_port = port;
			write_src_and_dst_mac(task, mbufs);
			*out = 0;
			break;
		default:
			plog_warn("Unsupported next hop %u in IPv6 packet\n", ipv6_hdr->proto);
			*out = OUT_DISCARD;
			break;
	}
}

static int handle_swap_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_swap *task = (struct task_swap *)tbase;
	prox_rte_ether_hdr *hdr;
	prox_rte_ether_addr mac;
	prox_rte_ipv4_hdr *ip_hdr;
	prox_rte_udp_hdr *udp_hdr;
	prox_rte_ipv6_hdr *ipv6_hdr;
	struct gre_hdr *pgre;
	prox_rte_ipv4_hdr *inner_ip_hdr;
	uint32_t ip;
	uint16_t port;
	uint8_t out[64] = {0};
	struct mpls_hdr *mpls;
	uint32_t mpls_len = 0;
	struct qinq_hdr *qinq;
	prox_rte_vlan_hdr *vlan;
	uint16_t j;
	struct igmpv2_hdr *pigmp;
	prox_rte_icmp_hdr *picmp;
	uint8_t type;

	for (j = 0; j < n_pkts; ++j) {
		PREFETCH0(mbufs[j]);
	}
	for (j = 0; j < n_pkts; ++j) {
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j], void *));
	}

	// TODO 1: check packet is long enough for Ethernet + IP + UDP = 42 bytes
	for (uint16_t j = 0; j < n_pkts; ++j) {
		hdr = rte_pktmbuf_mtod(mbufs[j], prox_rte_ether_hdr *);
		switch (hdr->ether_type) {
		case ETYPE_MPLSU:
			mpls = (struct mpls_hdr *)(hdr + 1);
			while (!(mpls->bytes & 0x00010000)) {
				// TODO: verify pcket length
				mpls++;
				mpls_len += sizeof(struct mpls_hdr);
			}
			mpls_len += sizeof(struct mpls_hdr);
			ip_hdr = (prox_rte_ipv4_hdr *)(mpls + 1);
			if (unlikely((ip_hdr->version_ihl >> 4) == 6)) {
				ipv6_hdr = (prox_rte_ipv6_hdr *)(ip_hdr);
				handle_ipv6(task, mbufs[j], ipv6_hdr, &out[j]);
				continue;
			}
			break;
		case ETYPE_8021ad:
			qinq = (struct qinq_hdr *)hdr;
			if (qinq->cvlan.eth_proto != ETYPE_VLAN) {
				plog_warn("Unexpected proto in QinQ = %#04x\n", qinq->cvlan.eth_proto);
				out[j] = OUT_DISCARD;
				continue;
			}
			if (qinq->ether_type == ETYPE_IPv4) {
				ip_hdr = (prox_rte_ipv4_hdr *)(qinq + 1);
			} else if (qinq->ether_type == ETYPE_IPv6) {
				ipv6_hdr = (prox_rte_ipv6_hdr *)(qinq + 1);
				handle_ipv6(task, mbufs[j], ipv6_hdr, &out[j]);
				continue;
			} else {
				plog_warn("Unsupported packet type\n");
				out[j] = OUT_DISCARD;
				continue;
			}
			break;
		case ETYPE_VLAN:
			vlan = (prox_rte_vlan_hdr *)(hdr + 1);
			if (vlan->eth_proto == ETYPE_IPv4) {
				ip_hdr = (prox_rte_ipv4_hdr *)(vlan + 1);
			} else if (vlan->eth_proto == ETYPE_IPv6) {
				ipv6_hdr = (prox_rte_ipv6_hdr *)(vlan + 1);
				handle_ipv6(task, mbufs[j], ipv6_hdr, &out[j]);
				continue;
			} else if (vlan->eth_proto == ETYPE_VLAN) {
				vlan = (prox_rte_vlan_hdr *)(vlan + 1);
				if (vlan->eth_proto == ETYPE_IPv4) {
					ip_hdr = (prox_rte_ipv4_hdr *)(vlan + 1);
				}
				else if (vlan->eth_proto == ETYPE_IPv6) {
					ipv6_hdr = (prox_rte_ipv6_hdr *)(vlan + 1);
					handle_ipv6(task, mbufs[j], ipv6_hdr, &out[j]);
					continue;
				}
				else {
					plog_warn("Unsupported packet type\n");
					out[j] = OUT_DISCARD;
					continue;
				}
			} else {
				plog_warn("Unsupported packet type\n");
				out[j] = OUT_DISCARD;
				continue;
			}
			break;
		case ETYPE_IPv4:
			ip_hdr = (prox_rte_ipv4_hdr *)(hdr + 1);
			break;
		case ETYPE_IPv6:
			ipv6_hdr = (prox_rte_ipv6_hdr *)(hdr + 1);
			handle_ipv6(task, mbufs[j], ipv6_hdr, &out[j]);
			continue;
		case ETYPE_LLDP:
			out[j] = OUT_DISCARD;
			continue;
		default:
			plog_warn("Unsupported ether_type 0x%x\n", hdr->ether_type);
			out[j] = OUT_DISCARD;
			continue;
		}
		// TODO 2 : check packet is long enough for Ethernet + IP + UDP + extra header (VLAN, MPLS, ...)
		// IPv4 packet

		ip = ip_hdr->dst_addr;
		if (unlikely((ip_hdr->version_ihl >> 4) != 4)) {
			out[j] = OUT_DISCARD;
			continue;
		}

		switch (ip_hdr->next_proto_id) {
		case IPPROTO_GRE:
			ip_hdr->dst_addr = ip_hdr->src_addr;
			ip_hdr->src_addr = ip;

			pgre = (struct gre_hdr *)(ip_hdr + 1);
			inner_ip_hdr = ((prox_rte_ipv4_hdr *)(pgre + 1));
			ip = inner_ip_hdr->dst_addr;
			inner_ip_hdr->dst_addr = inner_ip_hdr->src_addr;
			inner_ip_hdr->src_addr = ip;

			udp_hdr = (prox_rte_udp_hdr *)(inner_ip_hdr + 1);
			// TODO 3.1 : verify proto is UPD or TCP
			port = udp_hdr->dst_port;
			udp_hdr->dst_port = udp_hdr->src_port;
			udp_hdr->src_port = port;
			write_src_and_dst_mac(task, mbufs[j]);
			break;
		case IPPROTO_UDP:
		case IPPROTO_TCP:
			if (unlikely(task->igmp_address && PROX_RTE_IS_IPV4_MCAST(rte_be_to_cpu_32(ip)))) {
				out[j] = OUT_DISCARD;
				continue;
			}
			udp_hdr = (prox_rte_udp_hdr *)(ip_hdr + 1);
			ip_hdr->dst_addr = ip_hdr->src_addr;
			ip_hdr->src_addr = ip;

			port = udp_hdr->dst_port;
			udp_hdr->dst_port = udp_hdr->src_port;
			udp_hdr->src_port = port;
			write_src_and_dst_mac(task, mbufs[j]);
			break;
		case IPPROTO_ICMP:
			picmp = (prox_rte_icmp_hdr *)(ip_hdr + 1);
			type = picmp->icmp_type;
			if (type == PROX_RTE_IP_ICMP_ECHO_REQUEST) {
				if (ip_hdr->dst_addr == task->local_ipv4) {
					task->n_echo_req++;
					if (rte_rdtsc() - task->last_echo_req_rcvd_tsc > rte_get_tsc_hz()) {
						plog_info("Received %u Echo Request on IP "IPv4_BYTES_FMT" (last received from IP "IPv4_BYTES_FMT")\n", task->n_echo_req, IPv4_BYTES(((uint8_t*)&ip_hdr->dst_addr)), IPv4_BYTES(((uint8_t*)&ip_hdr->src_addr)));
						task->n_echo_req = 0;
						task->last_echo_req_rcvd_tsc = rte_rdtsc();
					}
					build_icmp_reply_message(tbase, mbufs[j]);
				} else {
					out[j] = OUT_DISCARD;
					continue;
				}
			} else if (type == PROX_RTE_IP_ICMP_ECHO_REPLY) {
				if (ip_hdr->dst_addr == task->local_ipv4) {
					task->n_echo_rep++;
					if (rte_rdtsc() - task->last_echo_rep_rcvd_tsc > rte_get_tsc_hz()) {
						plog_info("Received %u Echo Reply on IP "IPv4_BYTES_FMT" (last received from IP "IPv4_BYTES_FMT")\n", task->n_echo_rep, IPv4_BYTES(((uint8_t*)&ip_hdr->dst_addr)), IPv4_BYTES(((uint8_t*)&ip_hdr->src_addr)));
						task->n_echo_rep = 0;
						task->last_echo_rep_rcvd_tsc = rte_rdtsc();
					}
				} else {
					out[j] = OUT_DISCARD;
					continue;
				}
			} else {
				out[j] = OUT_DISCARD;
				continue;
			}
			break;
		case IPPROTO_IGMP:
			pigmp = (struct igmpv2_hdr *)(ip_hdr + 1);
			// TODO: check packet len
			type = pigmp->type;
			if (type == IGMP_MEMBERSHIP_QUERY) {
				if (task->igmp_address) {
					// We have an address registered
					if ((task->igmp_address == pigmp->group_address) || (pigmp->group_address == 0)) {
						// We get a request for the registered address, or to 0.0.0.0
						build_igmp_message(tbase, mbufs[j], task->igmp_address, IGMP_MEMBERSHIP_REPORT);	// replace Membership query packet with a response
					} else {
						// Discard as either we are not registered or this is a query for a different group
						out[j] = OUT_DISCARD;
						continue;
					}
				} else {
					// Discard as either we are not registered
					out[j] = OUT_DISCARD;
					continue;
				}
			} else {
				// Do not forward other IGMP packets back
				out[j] = OUT_DISCARD;
				continue;
			}
			break;
		default:
			plog_warn("Unsupported IP protocol 0x%x\n", ip_hdr->next_proto_id);
			out[j] = OUT_DISCARD;
			continue;
		}
	}
	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

void igmp_join_group(struct task_base *tbase, uint32_t igmp_address)
{
	struct task_swap *task = (struct task_swap *)tbase;
	struct rte_mbuf *igmp_mbuf;
	uint8_t out[64] = {0};
	int ret;

	task->igmp_address = igmp_address;
	ret = rte_mempool_get(task->igmp_pool, (void **)&igmp_mbuf);
	if (ret != 0) {
		plog_err("Unable to allocate igmp mbuf\n");
		return;
	}
	build_igmp_message(tbase, igmp_mbuf, task->igmp_address, IGMP_MEMBERSHIP_REPORT);
	task->base.tx_pkt(&task->base, &igmp_mbuf, 1, out);
}

void igmp_leave_group(struct task_base *tbase)
{
	struct task_swap *task = (struct task_swap *)tbase;
	struct rte_mbuf *igmp_mbuf;
	uint8_t out[64] = {0};
	int ret;

	task->igmp_address = 0;
	ret = rte_mempool_get(task->igmp_pool, (void **)&igmp_mbuf);
	if (ret != 0) {
		plog_err("Unable to allocate igmp mbuf\n");
		return;
	}
	build_igmp_message(tbase, igmp_mbuf, task->igmp_address, IGMP_LEAVE_GROUP);
	task->base.tx_pkt(&task->base, &igmp_mbuf, 1, out);
}

static void init_task_swap(struct task_base *tbase, struct task_args *targ)
{
	struct task_swap *task = (struct task_swap *)tbase;
	prox_rte_ether_addr *src_addr, *dst_addr;

	/*
	 * The destination MAC of the outgoing packet is based on the config file:
	 *    - 'dst mac=xx:xx:xx:xx:xx:xx' => the pre-configured mac will be used as dst mac
	 *    - 'dst mac=packet'            => the src mac of the incoming packet is used as dst mac
	 *    - (default - no 'dst mac')    => the src mac from the incoming packet is used as dst mac
	 *
	 * The source MAC of the outgoing packet is based on the config file:
	 *    - 'src mac=xx:xx:xx:xx:xx:xx' => the pre-configured mac will be used as src mac
	 *    - 'src mac=packet'            => the dst mac of the incoming packet is used as src mac
	 *    - 'src mac=hw'                => the mac address of the tx port is used as src mac
	 *                                     An error is returned if there are no physical tx ports
	 *    - (default - no 'src mac')    => if there is physical tx port, the mac of that port is used as src mac
	 *    - (default - no 'src mac')       if there are no physical tx ports the dst mac of the incoming packet
	 */

	if (targ->flags & TASK_ARG_DST_MAC_SET) {
		dst_addr = &targ->edaddr;
		memcpy(&task->src_dst_mac[0], dst_addr, sizeof(*src_addr));
	}

	PROX_PANIC(targ->flags & TASK_ARG_DO_NOT_SET_SRC_MAC, "src mac must be set in swap mode, by definition => src mac=no is not supported\n");
	PROX_PANIC(targ->flags & TASK_ARG_DO_NOT_SET_DST_MAC, "dst mac must be set in swap mode, by definition => dst mac=no is not supported\n");

	if (targ->flags & TASK_ARG_SRC_MAC_SET) {
		src_addr =  &targ->esaddr;
		memcpy(&task->src_dst_mac[6], src_addr, sizeof(*dst_addr));
		plog_info("\t\tCore %d: src mac set from config file\n", targ->lconf->id);
	} else {
		if (targ->flags & TASK_ARG_HW_SRC_MAC)
			PROX_PANIC(targ->nb_txports == 0, "src mac set to hw but no tx port\n");
		if (targ->nb_txports) {
			src_addr = &prox_port_cfg[task->base.tx_params_hw.tx_port_queue[0].port].eth_addr;
			memcpy(&task->src_dst_mac[6], src_addr, sizeof(*dst_addr));
			targ->flags |= TASK_ARG_SRC_MAC_SET;
			plog_info("\t\tCore %d: src mac set from port\n", targ->lconf->id);
		}
	}
	task->runtime_flags = targ->flags;
	task->igmp_address =  rte_cpu_to_be_32(targ->igmp_address);
	if (task->igmp_pool == NULL) {
		static char name[] = "igmp0_pool";
		name[4]++;
		struct rte_mempool *ret = rte_mempool_create(name, NB_IGMP_MBUF, IGMP_MBUF_SIZE, NB_CACHE_IGMP_MBUF,
			sizeof(struct rte_pktmbuf_pool_private), rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, 0,
			rte_socket_id(), 0);
		PROX_PANIC(ret == NULL, "Failed to allocate IGMP memory pool on socket %u with %u elements\n",
			rte_socket_id(), NB_IGMP_MBUF);
		plog_info("\t\tMempool %p (%s) size = %u * %u cache %u, socket %d\n", ret, name, NB_IGMP_MBUF,
			IGMP_MBUF_SIZE, NB_CACHE_IGMP_MBUF, rte_socket_id());
		task->igmp_pool = ret;
	}
	task->local_ipv4 = rte_cpu_to_be_32(targ->local_ipv4);

	struct prox_port_cfg *port = find_reachable_port(targ);
	if (port) {
		task->offload_crc = port->requested_tx_offload & (DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM);
	}
}

static struct task_init task_init_swap = {
	.mode_str = "swap",
	.init = init_task_swap,
	.handle = handle_swap_bulk,
	.flag_features = 0,
	.size = sizeof(struct task_swap),
	.stop_last = stop_swap
};

__attribute__((constructor)) static void reg_task_swap(void)
{
	reg_task(&task_init_swap);
}
