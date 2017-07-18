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

/* Global stats counters used in ARP */
extern uint32_t lib_nd_nh_found;
extern uint32_t lib_arp_nh_found;

struct route_data *p_route_data;
struct nd_route_data *p_nd_route_data;

/**
* VNF is configured as a gateway or router
* vnf_gateway = 1:gateway(default),0:router
* Flag is part of the ARPICMP config parameter
*/
uint32_t vnf_gateway;

/**
 * Initialize the gateway for routing tables
 *
 * @param void
 *  None
 *
 */

void gw_init(void)
{
     void *p;
     uint32_t size;

     /* IPv4 route table */
     size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct route_data));
     p = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
     p_route_data = (struct route_data *)p;

     /* IPv6 route touble */
     size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct nd_route_data));
     p = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
     p_nd_route_data = (struct nd_route_data *)p;

}

/**
 * Get the next hop ip address and port number for IPv4
 * @param dst_ip_addr
 *  Destination IPv4 address
 * @param src_port
 *  Source port of the packet
 * @param dst_port
 *  A pointer to destination port
 * @param nhip
 *  A pointer to next hop ip address
 */

void gw_get_nh_port_ipv4(uint32_t dst_ip_addr, uint32_t src_port,
				uint32_t *dst_port, uint32_t *nhip)
{
     /* Check if the VNF is configured as a gateway */
     if(p_route_data->route_ent_cnt){
	     int i;
          *nhip = 0;
	     for (i = 0; i < p_route_data->route_ent_cnt; i++) {

	          if ((p_route_data->route_table[i].nh_mask) ==
	                    (dst_ip_addr & p_route_data->route_table[i].mask)) {

	               *dst_port = p_route_data->route_table[i].port;
	               *nhip =  p_route_data->route_table[i].nh;

		       lib_arp_nh_found++;
	               return;
	          }
	     }

	     /* If can't locate in route table, generate using port map */
           if(is_phy_port_privte(src_port)) {
                *dst_port = get_prv_to_pub_port(&dst_ip_addr,
							IP_VERSION_4);
           } else {
                *dst_port = get_pub_to_prv_port(&dst_ip_addr,
       							IP_VERSION_4);
           }

           *nhip = p_route_data->route_table[*dst_port].nh;

     }
     else {
          printf(" Error: Gateway not configured \n");
     }
}

/**
 * Get the next hop ip address and port number for IPv6
 * @param dst_ipv6_addr
 *  Destination IPv6 address
 * @param src_port
 *  Source port of the packet
 * @param dst_port
 *  A pointer to destination port
 * @param nhipv6
 *  A pointer to next hop ip address 
 */

void gw_get_nh_port_ipv6(uint8_t *dst_ipv6_addr, uint32_t src_port,
					uint32_t *dst_port, uint8_t *nhipv6)
{
     if (!dst_ipv6_addr)
          return;

     /* Check if the VNF is configured as a gateway */
     if(p_nd_route_data->nd_route_ent_cnt){

          memset(nhipv6, 0, IPV6_ADD_SIZE);

	     int i=0;
	     uint8_t netmask_ipv6[IPV6_ADD_SIZE], netip_nd[IPV6_ADD_SIZE];
             uint8_t netip_in[IPV6_ADD_SIZE];
	     uint8_t k = 0, l = 0, depthflags = 0, depthflags1 = 0;
	     memset(netmask_ipv6, 0, sizeof(netmask_ipv6));
	     memset(netip_nd, 0, sizeof(netip_nd));
	     memset(netip_in, 0, sizeof(netip_in));


	     for (i = 0; i < p_nd_route_data->nd_route_ent_cnt; i++) {

	          convert_prefixlen_to_netmask_ipv6(
	               p_nd_route_data->nd_route_table[i].depth, netmask_ipv6);

	          for (k = 0; k < IPV6_ADD_SIZE; k++) {
	               if (p_nd_route_data->nd_route_table[i].nhipv6[k] &
				   	netmask_ipv6[k]) {

	                    depthflags++;
	                    netip_nd[k] = p_nd_route_data->nd_route_table[i].nhipv6[k];
	               }
	          }

	          for (l = 0; l < IPV6_ADD_SIZE; l++) {
	               if (dst_ipv6_addr[l] & netmask_ipv6[l]) {
	                    depthflags1++;
	                    netip_in[l] = dst_ipv6_addr[l];
	               }
	          }

	          if ((depthflags == depthflags1) &&
	               (memcmp(netip_nd, netip_in, sizeof(netip_nd)) == 0)) {

	               *dst_port = p_nd_route_data->nd_route_table[i].port;

			  lib_nd_nh_found++;

	               rte_mov16(nhipv6, (uint8_t *)
				   	&(p_nd_route_data->nd_route_table[i].nhipv6[0]));

		       return;
	          }

	     }

	     /* If can't locate in route table, generate using port map */
           if(is_phy_port_privte(src_port)) {
                *dst_port = get_prv_to_pub_port((uint32_t *)dst_ipv6_addr,
       								IP_VERSION_6);
           } else {
                *dst_port = get_pub_to_prv_port((uint32_t *)dst_ipv6_addr,
       								IP_VERSION_6);
           }

           rte_mov16(nhipv6, (uint8_t *)
		   	&(p_nd_route_data->nd_route_table[*dst_port].nhipv6[0]));

     }
     else {
          printf(" Error: Gateway not configured \n");
     }
}

