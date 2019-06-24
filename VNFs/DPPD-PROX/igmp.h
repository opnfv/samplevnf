/*
// Copyright (c) 2019 Intel Corporation
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

#ifndef _IGMP_H_
#define _IGMP_H_

#define IGMP_MEMBERSHIP_QUERY		0x11
#define IGMP_MEMBERSHIP_REPORT_V1	0x12
#define IGMP_MEMBERSHIP_REPORT		0x16
#define IGMP_LEAVE_GROUP		0x17

struct igmpv1_hdr {
	uint8_t   type: 4;    /* type */
	uint8_t   version: 4; /* version */
	uint8_t   unused;     /* unused */
	uint16_t  checksum;   /* checksum */
	uint32_t  group_address;   /* group address */
} __attribute__((__packed__));

struct igmpv2_hdr {
	uint8_t   type;          /* type */
	uint8_t   max_resp_time; /* maximum response time */
	uint16_t  checksum;      /* checksum */
	uint32_t  group_address; /* group address */
} __attribute__((__packed__));

struct igmpv3_hdr {
	uint8_t   type;          /* type */
	uint8_t   max_resp_time; /* maximum response time */
	uint16_t  checksum;      /* checksum */
	uint32_t  group_address; /* group address */
	uint8_t   bits: 4;       /* S(suppress router-side processing)QRV(Querier.s Robustness Variable) bits */
	uint8_t   reserved: 4;   /* reserved */
	uint8_t   QQIC;          /* Querier.s Query Interval Code */
	uint16_t  n_src;         /* Number of source addresses */
} __attribute__((__packed__));

struct task_base;
void igmp_join_group(struct task_base *tbase, uint32_t igmp_address);
void igmp_leave_group(struct task_base *tbase);

#endif /* _IGMP_H_ */
