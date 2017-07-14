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

#include "ip_subnet.h"
#include "prox_assert.h"

uint32_t ip4_subet_get_n_hosts(const struct ip4_subnet *sn)
{
	PROX_ASSERT(sn->prefix <= 32 && sn->prefix >= 1);
	return 1 << (32 - sn->prefix);
}

int ip4_subnet_to_host(const struct ip4_subnet *sn, uint32_t host_index, uint32_t *ret_ip)
{
	PROX_ASSERT(ip4_subnet_is_valid(sn));

	if (host_index >= ip4_subet_get_n_hosts(sn)) {
		return -1;
	}

	*ret_ip = sn->ip + host_index;
	return 0;
}

int ip4_subnet_is_valid(const struct ip4_subnet *sn)
{
	if (sn->prefix == 0) {
		return sn->ip == 0;
	}

	return (sn->ip & ~(((int)(1 << 31)) >> (sn->prefix - 1))) == 0;
}
