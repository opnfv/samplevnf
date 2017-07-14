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

#ifndef _QINQ_H_
#define _QINQ_H_

#include <rte_ether.h>

struct my_vlan_hdr {
	uint16_t eth_proto;
	uint16_t vlan_tci;
} __attribute__((packed));

struct vlans {
	struct my_vlan_hdr svlan;
	struct my_vlan_hdr cvlan;
};

struct qinq_hdr {
	struct ether_addr  d_addr;
	struct ether_addr  s_addr;
	struct my_vlan_hdr svlan;
	struct my_vlan_hdr cvlan;
	uint16_t ether_type;
} __attribute__((packed));

#endif /* _QINQ_H_ */
