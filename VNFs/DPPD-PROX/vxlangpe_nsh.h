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

#ifndef _VXLANGPE_NSH_H_
#define _VXLANGPE_NSH_H_

#include <rte_version.h>

struct nsh_hdr {
	uint16_t version :2;
	uint16_t oa_flag :1;
	uint16_t cm_flag :1;
	uint16_t reserved :6;
	uint16_t length :6;
	uint8_t md_type;
	uint8_t next_proto;
	uint32_t sfp_index :24;
	uint32_t sf_index :8;
	uint32_t ctx_1;
	uint32_t ctx_2;
	uint32_t ctx_3;
	uint32_t ctx_4;
} __attribute__((__packed__));

#if RTE_VERSION < RTE_VERSION_NUM(18,5,0,0)
struct vxlan_gpe_hdr {
	uint8_t flag_0;
	uint8_t flag_1;
	uint8_t reserved;
	uint8_t proto;
	uint32_t vni_res;
} __attribute__((__packed__));
#endif
#endif /* _VXLANGPE_NSH_H_ */
