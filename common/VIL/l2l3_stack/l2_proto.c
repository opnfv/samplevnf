/*
// Copyright (c) 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

/*
 *	Filename - l2_proto.c
 *	L2 Protocol Handler
 */

#include "l2_proto.h"

static struct proto_packet_type *proto_list[3];
/*
 *	Function to register the rx functions for different ethertypes. This is maintained in a list.
 */
void
list_add_type(uint16_t type,
				void (*func) (struct rte_mbuf **, uint16_t, uint64_t,
					l2_phy_interface_t *))
{
	if (type == ETHER_TYPE_IPv4) {
		proto_list[IPv4_VAL] =
				rte_malloc(NULL, sizeof(struct proto_packet_type),
						 RTE_CACHE_LINE_SIZE);
		proto_list[IPv4_VAL]->type = type;
		proto_list[IPv4_VAL]->func = func;
	}

	else if (type == ETHER_TYPE_ARP) {
		proto_list[ARP_VAL] =
				rte_malloc(NULL, sizeof(struct proto_packet_type),
						 RTE_CACHE_LINE_SIZE);
		proto_list[ARP_VAL]->type = type;
		proto_list[ARP_VAL]->func = func;
	} else if (type == ETHER_TYPE_IPv6) {
		proto_list[IPv6_VAL] =
				rte_malloc(NULL, sizeof(struct proto_packet_type),
						 RTE_CACHE_LINE_SIZE);
		proto_list[IPv6_VAL]->type = type;
		proto_list[IPv6_VAL]->func = func;
	}

}

/*
 *	Check the mac address to see whether it is destined to this host or not.
 *	Call relevant functions registered by other modules when the ethertype matches,
 *	if it is destined to this host. Drop the packet otherwise.
 */

void
l2_check_mac(struct rte_mbuf *m[IFM_BURST_SIZE], l2_phy_interface_t *port,
			 uint8_t i, uint64_t *pkts_mask, uint64_t *arp_pkts_mask,
			 uint64_t *ipv4_pkts_mask, uint64_t *ipv6_pkts_mask)
{
	struct ether_hdr *eth=NULL;
	uint16_t same_mac=0;
	uint16_t ethtype = 0;

	if (m[i] != NULL) {
		eth = rte_pktmbuf_mtod(m[i], struct ether_hdr *);
		if(eth)
		ethtype = rte_be_to_cpu_16(eth->ether_type);
		if (eth == NULL) {
			/*Destination MAC address inside the packet */
			printf("l2_check_mac: Ethernet Dest Addr NULL !!!\n");
			return;
		}
		ethtype = rte_be_to_cpu_16(eth->ether_type);
#if L2_PROTO_DBG
		printf("%s => mbuf pkt dest mac addr: %x:%x:%x:%x:%x:%x\n",
					 __FUNCTION__, eth->d_addr.addr_bytes[0],
					 eth->d_addr.addr_bytes[1], eth->d_addr.addr_bytes[2],
					 eth->d_addr.addr_bytes[3], eth->d_addr.addr_bytes[4],
					 eth->d_addr.addr_bytes[5]);
		printf("%s => port mac addr: %x:%x:%x:%x:%x:%x\n", __FUNCTION__,
					 port->macaddr[0], port->macaddr[1], port->macaddr[2],
					 port->macaddr[3], port->macaddr[4], port->macaddr[5]);

#endif
		/*     Compare the mac addresses       */
		same_mac =
				(is_same_ether_addr
				 (&eth->d_addr, (struct ether_addr *)port->macaddr)
				 ||
				 ((is_broadcast_ether_addr
					 ((struct ether_addr *)&eth->d_addr)
					 && (ethtype == ETHER_TYPE_ARP)))
				 || (ethtype == ETHER_TYPE_IPv6
			 && eth->d_addr.addr_bytes[0] == 0x33
			 && eth->d_addr.addr_bytes[1] == 0x33));

		if (!same_mac) {
			uint64_t temp_mask = 1LLU << i;
			*pkts_mask ^= temp_mask;
			rte_pktmbuf_free(m[i]);
			m[i] = NULL;
		} else if ((ethtype == ETHER_TYPE_IPv4) && same_mac) {
			uint64_t temp_mask = 1LLU << i;
			*ipv4_pkts_mask ^= temp_mask;
		} else if ((ethtype == ETHER_TYPE_ARP) && same_mac) {
			uint64_t temp_mask = 1LLU << i;
			*arp_pkts_mask ^= temp_mask;
		} else if ((ethtype == ETHER_TYPE_IPv6) && same_mac) {
			uint64_t temp_mask = 1LLU << i;
			*ipv6_pkts_mask ^= temp_mask;
		}
	}
	printf("\n%s: arp_pkts_mask = %" PRIu64 ", ipv4_pkts_mask = %" PRIu64
				 ", ipv6_pkts_mask =%" PRIu64 ", pkt-type = %x, sam_mac = %d\n",
				 __FUNCTION__, *arp_pkts_mask, *ipv4_pkts_mask, *ipv6_pkts_mask,
				 ethtype, same_mac);
}

void
protocol_handler_recv(struct rte_mbuf **pkts_burst, uint16_t nb_rx,
					l2_phy_interface_t *port)
{
	uint8_t i;
	uint64_t pkts_mask = 0;	//RTE_LEN2MASK(nb_rx, uint64_t);
	uint64_t arp_pkts_mask = 0;	//RTE_LEN2MASK(nb_rx, uint64_t);
	uint64_t ipv4_pkts_mask = 0;	//RTE_LEN2MASK(nb_rx, uint64_t);
	uint64_t ipv6_pkts_mask = 0;	//RTE_LEN2MASK(nb_rx, uint64_t);

	/*Check the mac address of every single packet and unset the bits in the packet mask
	 *for those packets which are not destined to this host
	 */
	for (i = 0; i < nb_rx; i++) {
		l2_check_mac(pkts_burst, port, i, &pkts_mask, &arp_pkts_mask,
					 &ipv4_pkts_mask, &ipv6_pkts_mask);
	}
	if (nb_rx) {
		if (arp_pkts_mask) {
			proto_list[ARP_VAL]->func(pkts_burst, nb_rx,
							arp_pkts_mask, port);
			printf
					("=================After ARP ==================\n");
		}
		if (ipv4_pkts_mask) {
			printf
					("=================Calling IPV4 L3 RX ==================\n");
			printf("====nb_rx:%u, ipv4_pkts_mask: %lu\n\n", nb_rx,
						 ipv4_pkts_mask);
			proto_list[IPv4_VAL]->func(pkts_burst, nb_rx,
							 ipv4_pkts_mask, port);
		}
		if (ipv6_pkts_mask) {
			printf
					("=================Calling IPV6 L3 RX ==================\n");
			printf("====nb_rx:%u, ipv6_pkts_mask: %lu\n\n", nb_rx,
						 ipv6_pkts_mask);
			proto_list[IPv6_VAL]->func(pkts_burst, nb_rx,
							 ipv6_pkts_mask, port);
		}
	}
}

#if 0
switch (qid) {
case 1:
	{
#if 0
		printf
				("=====================ENTERED ARP CASE================\n");
		while (cur->type != ETHER_TYPE_ARP && cur != NULL) {
			cur = cur->next;
		}
		if (cur != NULL) {
			//printf("L2 PROTO TEST-14=================================\n");
			printf
					("==============\nARPARPARPARP  \n=======================\n");
			cur->func(pkts_burst, nb_rx, pkts_mask, portid);
		}
#endif
		proto_list[ARP_VAL]->func(pkts_burst, nb_rx, arp_pkts_mask,
						portid);
		break;
	}
case 0:
	{
#if 0
		while (cur->type != ETHER_TYPE_IPv4 && cur != NULL) {
			cur = cur->next;
		}
		if (cur != NULL) {
			//printf("L2 PROTO TEST-15=================================\n");
			//printf("==============\nPkts mask in while calling IPv4 %d \n=======================\n",ipv4_pkts_mask);
			cur->func(pkts_burst, nb_rx, ipv4_pkts_mask, portid);
		}
		break;
#endif
		//      printf("=========Inside switch==============\n");
		proto_list[IPv4_VAL]->func(pkts_burst, nb_rx, ipv4_pkts_mask,
						 portid);
		break;
	}
	/*     case 2:
		 {
		 while(cur->type != ETHER_TYPE_IPv6  && cur != NULL)
		 {
		 cur = cur->next;
		 }
		 if(cur != NULL)
		 {
		 cur->func(pkts_burst, nb_rx, ipv6_pkts_mask, portid);
		 }
		 break;
		 } */
default:
	{
		rte_exit(EXIT_FAILURE, "Ethertype not found \n");
		break;
	}
}
#endif

/*
 *	L2 Stack Init for future


	void
l2_stack_init(void)
{

}

*/
