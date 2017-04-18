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

/****************************************************************************
*
* filename : :l3fwd_main.c
*
*
******************************************************************************/

#include "l3fwd_common.h"
#include "l2_proto.h"
#include "l3fwd_lpm4.h"
#include "l3fwd_lpm6.h"
#include "interface.h"
#include "lib_arp.h"
#include "lib_icmpv6.h"

struct routing_info input_array[] = {
#if MULTIPATH_FEAT
	{IPv4(30, 12, 0, 1), 24, 0, 4,
	 {IPv4(192, 168, 0, 2), IPv4(1, 1, 1, 7), IPv4(120, 0, 0, 2),
		IPv4(30, 40, 50, 60)}, {1, 1, 1, 1} },

	{IPv4(40, 12, 0, 1), 24, 0, 4,
	 {IPv4(192, 168, 0, 2), IPv4(1, 1, 1, 7), IPv4(120, 0, 0, 2),
		IPv4(30, 40, 50, 60)}, {1, 1, 1, 1} },

	{IPv4(50, 12, 0, 1), 24, 0, 4,
	 {IPv4(192, 168, 0, 2), IPv4(1, 1, 1, 7), IPv4(120, 0, 0, 2),
		IPv4(30, 40, 50, 60)}, {1, 1, 1, 1} },

	{IPv4(60, 12, 0, 1), 24, 0, 4,
	 {IPv4(192, 168, 0, 2), IPv4(1, 1, 1, 7), IPv4(120, 0, 0, 2),
		IPv4(30, 40, 50, 60)}, {1, 1, 1, 1} },

	{IPv4(100, 100, 100, 100), 24, 0, 2,
	 {IPv4(120, 0, 0, 2), IPv4(120, 0, 0, 2)}, {1, 1} },	// FIb Path Available

	{IPv4(200, 100, 100, 100), 24, 0, 2,
	 {IPv4(80, 0, 0, 2), IPv4(80, 40, 50, 60)}, {1, 1} },	// Fib path Not Available
#else
	{IPv4(30, 12, 0, 1), 24, 0, 1,
	 {IPv4(192, 168, 0, 2)}, {1} },

	{IPv4(20, 12, 0, 1), 24, 0, 1,
	 {IPv4(120, 0, 0, 2)}, {1} },
#endif
};

struct ipv6_routing_info ipv6_input_array[] = {

	{{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 0, 2,
	 {{10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10},
		{20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20}
		},
	 {1, 1}
	 },

	{{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}, 48, 0, 2,
	 {{10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10},
		{20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20}
		},
	 {1, 1}
	 },
};

void l3fwd_init(void)
{
	printf(" *********** L3  Initialization START ************\n");
	if (lpm_init() == 0) {
		rte_exit(EXIT_FAILURE, "L3 Initialization IPv4 Failed\n");
	}
	if (lpm6_init() == 0) {
		rte_exit(EXIT_FAILURE, "L3 Initialization for IPV6 Failed\n");
	}

	list_add_type(ETHER_TYPE_IPv4, l3fwd_rx_ipv4_packets);
	list_add_type(ETHER_TYPE_IPv6, l3fwd_rx_ipv6_packets);

	l3_protocol_type_add(IPPROTO_ICMP, ip_local_packets_process);
	l3_protocol_type_add(IPPROTO_TCP, ip_forward_deliver);
	l3_protocol_type_add(IPPROTO_UDP, ip_forward_deliver);

	ipv6_l3_protocol_type_add(IPPROTO_ICMPV6, ipv6_local_deliver);
	ipv6_l3_protocol_type_add(IPPROTO_TCP, ipv6_forward_deliver);
	ipv6_l3_protocol_type_add(IPPROTO_UDP, ipv6_forward_deliver);

}

void populate_lpm_routes(void)
{
	populate_lpm4_table_routes();
	//populate_lpm6_table_routes();
}

void populate_lpm4_table_routes(void)
{
	uint8_t i;
	printf
			(" *********** L3 IPV4 Route Initialization START ************\n");
	for (i = 0; i < MAX_ROUTES; i++) {
		if (lpm4_table_route_add(&input_array[i])) {

			printf("Total routes Added# %d\n", i + 1);
		} else {
			rte_exit(EXIT_FAILURE,
				 "L3 route addition failed for the route# %d\n",
				 i);
		}
	}
	printf
			(" *********** L3 IPV4 Route Initialization END ************\n\n");
}

void populate_lpm6_table_routes(void)
{
	uint8_t i;
	printf
			(" *********** L3 IPV6 Route Initialization START ************\n");
	for (i = 0; i < 2; i++) {
		if (lpm6_table_route_add(&ipv6_input_array[i])) {

			printf("Added route # %d\n", i);
		} else {
			rte_exit(EXIT_FAILURE,
				 "L3 route addition failed for the route# %d\n",
				 i);
		}
	}
	printf(" *********** L3 IPV6 Route Initialization END ************\n");
}
