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

#ifndef _IP_SUBNET_H_
#define _IP_SUBNET_H_

#include <inttypes.h>

struct ip4_subnet {
	uint32_t ip;
	uint8_t prefix; /* always in range [1,32] inclusive */
};

struct ip6_subnet {
	uint8_t ip[16];
	uint8_t prefix; /* always in range [1,128] inclusive */
};

/* Returns number of hosts (assuming that network address and
   broadcast address are both hosts) within the subnet. */
uint32_t ip4_subet_get_n_hosts(const struct ip4_subnet *sn);

/* Allows to get a specific host within a subnet. Note that the
   network address and broadcast address are both considered to
   "hosts". Setting host_index to 0 returns the network address and
   setting the host_index to the last host within the subnet returns
   the broadcast. To get all addresses with the subnet, loop
   host_index from 0 to ip_subnet_get_n_hosts(). */
int ip4_subnet_to_host(const struct ip4_subnet* sn, uint32_t host_index, uint32_t* ret_ip);

/* Check if IP address is a network address (i.e. all bits outside the
   prefix are set to 0). */
int ip4_subnet_is_valid(const struct ip4_subnet* sn);

#endif /* _IP_SUBNET_H_ */
