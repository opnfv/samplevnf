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

#ifndef _ETYPES_H_
#define _ETYPES_H_

#define ETYPE_IPv4	0x0008	/* IPv4 in little endian */
#define ETYPE_IPv6	0xDD86	/* IPv6 in little endian */
#define ETYPE_ARP	0x0608	/* ARP in little endian */
#define ETYPE_VLAN	0x0081	/* 802-1aq - VLAN */
#define ETYPE_MPLSU	0x4788	/* MPLS unicast */
#define ETYPE_MPLSM	0x4888	/* MPLS multicast */
#define ETYPE_8021ad	0xA888	/* Q-in-Q */
#define ETYPE_LLDP	0xCC88	/* Link Layer Discovery Protocol (LLDP) */
#define ETYPE_EoGRE	0x5865	/* EoGRE in little endian */

#endif /* _ETYPES_H_ */
