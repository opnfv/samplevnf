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
#ifndef __INCLUDE_LIB_FTP_ALG_H__
#define __INCLUDE_LIB_FTP_ALG_H__
#include "rte_ether.h"
#include "rte_ct_tcp.h"
/*CT & CGNAT integration to be resolved for this definitions*/
#define META_DATA_OFFSET 128
#define ETHERNET_START (META_DATA_OFFSET + RTE_PKTMBUF_HEADROOM)
#define ETH_HDR_SIZE 14
#define IP_START (ETHERNET_START + ETH_HDR_SIZE)
#define PROTOCOL_START (IP_START + 9)
#define TCP_START (IP_START + IP_V4_HEADER_SIZE)
#define TCP_MIN_HDR_SIZE 20

#define RTE_TCP_PROTO_ID 6
#define RTE_SP_DEFAULT_TTL 64

#define RTE_SYNPROXY_MAX_SPOOFED_PKTS 64

#define RTE_TCP_SYN 0x02
#define RTE_TCP_ACK 0x10
#define RTE_TCP_SYN_ACK (RTE_TCP_SYN | RTE_TCP_ACK)
#define IP_VERSION_4 4
#define IP_VERSION_6 6
#define IPv4_HEADER_SIZE 20
#define IPv6_HEADER_SIZE 40

//#define IPV4 4
//#define IPV6 6
enum ftp_alg_bypass {
	NO_BYPASS,
	BYPASS
};

enum ftp_alg_mode {
	FTP_ALG_PORT,
	FTP_ALG_PASV
};
enum ftp_alg_direction {
	SERVER_IN_PRIVATE,
	SERVER_IN_PUBLIC
};
enum phy_port {
	PRIVATE_PORT,
	PUBLIC_PORT
};

struct ftp_alg_key {
	uint32_t ip_address;
	uint16_t l4port;
	uint8_t filler1;
	uint8_t filler2;
};
struct ftp_alg_table_entry {
	uint32_t ip_address;
	uint16_t l4port;
	uint8_t ftp_alg_mode;
	uint8_t ftp_alg_direction;
	uint32_t session_id;	/*to be checked */
	uint8_t alg_bypass_flag;
	uint8_t dummy;
	uint8_t dummy1;
	//uint32_t napt_entry;/* to be checked*/
} __rte_cache_aligned;

#define FTP_SERVER_PORT				21
#define FTP_PORT_STRING				"PORT"
#define FTP_PORT_PARAMETER_STRING		"PORT %hu,%hu,%hu,%hu,%hu,%hu\r\n"
#define FTP_PORT_PARAMETER_COUNT		6
#define FTP_PORT_RESPONSE_STRING		"200 PORT command successful.\r\n"
#define FTP_PORT_STRING_END_MARKER		'\n'
#define FTP_MAXIMUM_PORT_STRING_LENGTH		60
#define FTP_PASV_STRING				"PASV"
#define FTP_PASV_PARAMETER_STRING		"%d Entering Passive Mode (%hu,%hu,%hu,%hu,%hu,%hu)\r\n"
#define FTP_PASV_PARAMETER_COUNT		7
#define FTP_PASV_STRING_END_MARKER		'\n'	/* not ')' */
#define FTP_PASV_RETURN_CODE			227

void ftp_alg_dpi(
	struct pipeline_cgnapt *p_nat,
	struct pipeline_cgnapt_entry_key *nat_entry_key,
	struct rte_mbuf *pkt,
	struct rte_ct_cnxn_tracker *cgnat_cnxn_tracker,
	int32_t ct_position,
	uint8_t direction);
void lib_ftp_alg_init(void);
extern int8_t rte_ct_ipversion(void *i_hdr);
#endif
