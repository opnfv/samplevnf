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

#include <stdint.h>
#include <stdio.h>
#include "vnf_common.h"
#include "pipeline_arpicmp_be.h"
#ifndef VNF_ACL
#include "lib_arp.h"
#endif

uint8_t in_port_dir_a[PIPELINE_MAX_PORT_IN];
uint8_t prv_to_pub_map[PIPELINE_MAX_PORT_IN];
uint8_t pub_to_prv_map[PIPELINE_MAX_PORT_IN];
uint8_t prv_in_port_a[PIPELINE_MAX_PORT_IN];
uint8_t prv_que_port_index[PIPELINE_MAX_PORT_IN];
uint8_t in_port_egress_prv[PIPELINE_MAX_PORT_IN];

uint8_t get_in_port_dir(uint8_t in_port_id)
{
	return in_port_dir_a[in_port_id];
}

uint8_t is_phy_port_privte(uint16_t phy_port)
{
	return in_port_dir_a[phy_port];
}

uint8_t is_port_index_privte(uint16_t phy_port)
{
	return in_port_egress_prv[phy_port];
}

uint32_t get_prv_to_pub_port(uint32_t *ip_addr, uint8_t type)
{
	uint32_t dest_if = 0xff;

	switch (type) {
	case 4:
	{
		uint32_t nhip;
		nhip = get_nh(ip_addr[0], &dest_if);

		if (nhip)
			return dest_if;
		return 0xff;
	}
	break;
	case 6:
	{
		uint8_t nhipv6[16];
		get_nh_ipv6((uint8_t *)ip_addr, &dest_if, &nhipv6[0]);
		if (dest_if != 0xff)
			return dest_if;
		return 0xff;
	}
	break;
	}
	return 0xff;
}

uint32_t get_pub_to_prv_port(uint32_t *ip_addr, uint8_t type)
{
	uint32_t dest_if = 0xff;

	switch (type) {
	case 4:
	{
		uint32_t nhip;
		nhip = get_nh(ip_addr[0], &dest_if);

		if (nhip)
			return dest_if;
		return 0xff;
	}
	break;
	case 6:
	{
		uint8_t nhipv6[16];
		get_nh_ipv6((uint8_t *)ip_addr, &dest_if, &nhipv6[0]);
		if (dest_if != 0xff)
			return dest_if;
		return 0xff;
	}
	break;
	}
	return 0xff;
}

void show_ports_info(void)
{
	printf("\nin_port_dir_a: %d %d %d %d %d", in_port_dir_a[0],
	in_port_dir_a[1], in_port_dir_a[2], in_port_dir_a[3],
	in_port_dir_a[4]);

	uint8_t i = 0, j = 0;

	printf("\nprv_to_pub_map: ");
	for (i = 0; i < PIPELINE_MAX_PORT_IN; i++) {
		if (prv_to_pub_map[i] != 0xff)
			printf("(%d,%d)  ", i, prv_to_pub_map[i]);
	}

	printf("\npub_to_prv_map: ");
	for (i = 0; i < PIPELINE_MAX_PORT_IN; i++) {
		if (pub_to_prv_map[i] != 0xff)
			printf("(%d,%d)  ", i, pub_to_prv_map[i]);
	}

	printf("\n%d entries in Ports MAC List\n", link_hw_addr_array_idx);
	for (j = 0; j < link_hw_addr_array_idx; j++) {
		struct ether_addr *link_hw_addr = get_link_hw_addr(j);

		for (i = 0; i < 6; i++)
			printf(" %02x ", ((struct ether_addr *)link_hw_addr)->addr_bytes[i]);
		printf("\n");
	}
}

void trim(char *input)
{
	int i, j = 0;
	int len = strlen(input);
	char result[len + 1];

	memset(result, 0, sizeof(result));
	for (i = 0; input[i] != '\0'; i++) {
		if (!isspace(input[i]))
			result[j++] = input[i];
	}

	strncpy(input, result, len);
}
