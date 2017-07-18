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

/**
 * @file
 * Gateway packet forwarding Implementation.
 *
 * Implementation of gateway packet forwarding, next hop IP and
 * associated processing.
 *
 */

#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_memcpy.h>

#include "gateway.h"
#include "pipeline_common_fe.h"

#define IP_VERSION_4 4
#define IP_VERSION_6 6
#define MAX_PORTS 32

/* Global stats counters used in ARP */
extern uint32_t lib_nd_nh_found;
extern uint32_t lib_arp_nh_found;

struct route_data *p_route_data[MAX_PORTS];
struct nd_route_data *p_nd_route_data[MAX_PORTS];

/**
* VNF is configured with routing info or not
* vnf_gateway = 0: No Routes Added , 1: Routes defined
* Flag is part of the ARPICMP config parameter
*/

/* Initialized for IP Pkt forwarding */
uint32_t vnf_gateway = 0;

/* Initialized number of out ports to route */
uint32_t num_out_ports = 0;

/**
 * Initialize the gateway for routing tables
 *
 * @param void
 *  None
 * @return uint32_t
 * 1 to MAX_PORTS
 */

void gw_init(uint32_t num_ports)
{
     void *p;
     uint32_t size;
     uint32_t i;

     num_out_ports = num_ports;

     for(i = 0; i < num_ports; i++) {
	     /* IPv4 route table */
	     size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct route_data));
	     p = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
	     p_route_data[i] = (struct route_data *)p;

	     /* IPv6 route touble */
	     size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct nd_route_data));
	     p = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
	     p_nd_route_data[i] = (struct nd_route_data *)p;
   }
}
/*
 * Get the the number of ports to route
 * @param void
 *  None
 * @return uint32_t
 *  Number of ports enabled in the VNF
*/

uint32_t gw_get_num_ports(void)
{
	return num_out_ports;
}


/**
 * Check if the gateway is enabled
 *
 * @param void
 *  None
 * @return uint32_t
 *  0: No routes, 1: Route entries available
 */
uint32_t is_gateway(void)
{
	return vnf_gateway;
}


/**
 * Get the next hop ip address and port number for IPv4
 * @param dst_ip_addr
 *  Destination IPv4 address
 * @param dst_port
 *  A pointer to destination port
 * @param nhip
 *  A pointer to next hop ip address
 */

void gw_get_nh_port_ipv4(uint32_t dst_ip_addr,
				uint32_t *dst_port, uint32_t *nhip)
{
	int i;
	uint32_t j;

	*nhip = 0;
	*dst_port = 0xff;

	for(j = 0; j < gw_get_num_ports(); j++){

		for (i = 0; i < p_route_data[j]->route_ent_cnt; i++) {

			if ((p_route_data[j]->route_table[i].nh_mask) ==
					(dst_ip_addr &
					 p_route_data[j]->route_table[i].mask)) {

				*dst_port = p_route_data[j]->route_table[i].port;
				*nhip =  p_route_data[j]->route_table[i].nh;

				lib_arp_nh_found++;
				return;
			}
		}
	}
}

/**
 * Get the next hop ip address and port number for IPv6
 * @param dst_ipv6_addr
 *  Destination IPv6 address
 * @param dst_port
 *  A pointer to destination port
 * @param nhipv6
 *  A pointer to next hop ip address
 */

void gw_get_nh_port_ipv6(uint8_t *dst_ipv6_addr,
					uint32_t *dst_port, uint8_t *nhipv6)
{
    if (!dst_ipv6_addr)
	    return;
    uint32_t j;
    for(j = 0; j < gw_get_num_ports(); j++){

	    if(p_nd_route_data[j]->nd_route_ent_cnt){

		    memset(nhipv6, 0, IPV6_ADD_SIZE);

		    int i=0;
		    uint8_t netmask_ipv6[IPV6_ADD_SIZE], netip_nd[IPV6_ADD_SIZE];
		    uint8_t netip_in[IPV6_ADD_SIZE];
		    uint8_t k = 0, depthflags = 0, depthflags1 = 0;
		    memset(netmask_ipv6, 0, sizeof(netmask_ipv6));
		    memset(netip_nd, 0, sizeof(netip_nd));
		    memset(netip_in, 0, sizeof(netip_in));

		     for (i = 0; i < p_nd_route_data[j]->nd_route_ent_cnt; i++) {

			     convert_prefixlen_to_netmask_ipv6(
					     p_nd_route_data[j]->nd_route_table[i].depth, netmask_ipv6);

			     for (k = 0; k < IPV6_ADD_SIZE; k++) {
				     if (p_nd_route_data[j]->nd_route_table[i].nhipv6[k] &
						     netmask_ipv6[k]) {

					     depthflags++;
					     netip_nd[k] = p_nd_route_data[j]->nd_route_table[i].nhipv6[k];
				     }

				     if (dst_ipv6_addr[k] & netmask_ipv6[k]) {
					     depthflags1++;
					     netip_in[k] = dst_ipv6_addr[k];
				     }
			     }

			     if ((depthflags == depthflags1) &&
					     (memcmp(netip_nd, netip_in, sizeof(netip_nd)) == 0)) {

				     *dst_port = p_nd_route_data[j]->nd_route_table[i].port;

				     lib_nd_nh_found++;

				     rte_mov16(nhipv6, (uint8_t *)
						     &(p_nd_route_data[j]->nd_route_table[i].nhipv6[0]));

				     return;
			     }

		     }

	    }
    }
}

