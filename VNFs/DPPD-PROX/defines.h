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

#ifndef _DEFINES_H_
#define _DEFINES_H_

// with 3GHz CPU
#define DRAIN_TIMEOUT  __UINT64_C(6000000)             // drain TX buffer every 2ms
#define TERM_TIMEOUT   __UINT64_C(3000000000)          // check if terminated every 1s

/* DRAIN_TIMEOUT should be smaller than TERM_TIMEOUT as TERM_TIMEOUT
   is only checked after DRAIN_TIMEOUT */
#if TERM_TIMEOUT < DRAIN_TIMEOUT
#error TERM_TIMEOUT < DRAIN_TIMEOUT
#endif

#ifndef IPv4_BYTES
#define IPv4_BYTES_FMT  "%d.%d.%d.%d"
#define IPv4_BYTES(addr)                        \
        addr[0],  addr[1],  addr[2],  addr[3]
#endif

#ifndef IPv6_BYTES
#define IPv6_BYTES_FMT	"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define IPv6_BYTES(addr)			\
	addr[0],  addr[1],  addr[2],  addr[3],	\
	addr[4],  addr[5],  addr[6],  addr[7],	\
	addr[8],  addr[9],  addr[10], addr[11],	\
	addr[12], addr[13], addr[14], addr[15]
#endif

#ifndef MAC_BYTES
#define MAC_BYTES_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

#define MAC_BYTES(addr)   \
	addr[0], addr[1], \
	addr[2], addr[3], \
	addr[4], addr[5]
#endif

/* assume cpu byte order is little endian */
#define PKT_TO_LUTQINQ(svlan, cvlan) ((((uint32_t)svlan) & 0x000F) << 4 | (((uint32_t)svlan) & 0xFF00) << 8 | (((uint32_t)cvlan) & 0xFF0F))

#define ROUTE_ERR 254

#endif /* _DEFINES_H_ */
