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

#ifndef _HASH_ENTRY_TYPES_H_
#define _HASH_ENTRY_TYPES_H_

#include <rte_ether.h>

struct ether_addr_port {
	struct ether_addr 	mac;
	uint8_t                 pad;
	uint8_t	                out_idx;
};

struct next_hop {
	uint32_t                ip_dst;
	uint32_t                mpls;
	union {
		uint64_t               mac_port_8bytes;
		struct ether_addr_port mac_port;
	};
};

struct next_hop6 {
	uint8_t                ip_dst[16];
	uint32_t               mpls;
	union {
		uint64_t               mac_port_8bytes;
		struct ether_addr_port mac_port;
	};
};

struct cpe_data {
	uint16_t qinq_svlan;
	uint16_t qinq_cvlan;
	uint32_t user;
	union {
		uint64_t               mac_port_8bytes;
		struct ether_addr_port mac_port;
		uint8_t                mac_port_b[8];
	};
	uint64_t tsc;
};

struct cpe_key {
	union {
		uint32_t ip;
		uint8_t ip_bytes[4];
	};
	uint32_t gre_id;
} __attribute__((__packed__));

struct qinq_gre_data {
	uint32_t gre_id;
	uint32_t user;
} __attribute__((__packed__));

#endif /* _HASH_ENTRY_TYPES_H_ */
