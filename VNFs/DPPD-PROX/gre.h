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

#ifndef _GRE_H_
#define _GRE_H_

#define GRE_CRC_PRESENT     0x10
#define GRE_ROUTING_PRESENT 0x08
#define GRE_KEY_PRESENT     0x04
#define GRE_SEQNUM_PRESENT  0x02
#define GRE_STRICT_ROUTE    0x01

struct gre_hdr {
	uint8_t   recur: 3;   /* recur */
	uint8_t   bits: 5;    /* bits: Checksum, Routing, Key, Sequence Number, strict Route */
	uint8_t   version: 3; /* Version: must be 0 */
	uint8_t   flags: 5;   /* Flags: must be 0 */
	uint16_t  type;       /* Protocol type */
	uint32_t  gre_id;     /* Key ID */
} __attribute__((__packed__));

#endif /* _GRE_H_ */
