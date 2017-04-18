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

#ifndef _CGNAPT_PCP_H_
#define _CGNAPT_PCP_H_
/**
 * @file
 *
 * PCP-related defines
 */

#include <stdint.h>
#include <rte_ether.h>
#include <rte_udp.h>
#include <rte_pipeline.h>
#include <rte_ip.h>
#include "pipeline_cgnapt_common.h"

void handle_pcp_req(struct rte_mbuf *rx_pkt,
					uint8_t ver,
					void *pipeline_cgnapt_ptr);

void construct_pcp_resp(struct rte_mbuf *rx_pkt,
					struct rte_mbuf *tx_pkt,
					uint8_t ver,
					struct rte_pipeline *rte_p);

void *pipeline_cgnapt_msg_req_pcp_handler(
					__rte_unused struct pipeline *p,
					void *msg);

#ifdef __cplusplus
extern "C" {
#endif

/************************** Constats used in PCP ****************************/
#define PCP_SERVER_PORT 5351

/* PCP Req or Resp */
enum{
	PCP_REQ,
	PCP_RESP,
};
/* PCP life time in seconds */
enum{
	PCP_LONG_LTIME = 30 * 60,
	PCP_SHORT_LTIME = 30,
	MAX_PCP_LIFE_TIME = 120 * 60,
};
/* PCP opcodes */
enum{
	PCP_ANNOUNCE,
	PCP_MAP,
	PCP_PEER,
};

/* PCP result codes */
enum{
	PCP_SUCCESS,
	PCP_UNSUPP_VERSION,
	PCP_NOT_AUTHORIZED,
	PCP_MALFORMED_REQUEST,
	PCP_UNSUPP_OPCODE,
	PCP_UNSUPP_OPTION,
	PCP_MALFORMED_OPTION,
	PCP_NETWORK_FAILURE,
	PCP_NO_RESOURCES,
	PCP_UNSUPP_PROTOCOL,
	PCP_USER_EX_QUOTA,
	PCP_CANNOT_PROVIDE_EXTERNAL,
	PCP_ADDRESS_MISMATCH,
	PCP_EXCESSIVE_REMOTE_PEERS
};

/*
 * @struct
 *
 * PCP request header format
 */
struct pcp_req_hdr {
	uint8_t ver;
	uint8_t opcode:7; //First LSB
	uint8_t req_resp:1;// MSB
	uint16_t res_unuse;
	uint32_t life_time;
	uint32_t cli_ip[4];
} __attribute__((__packed__));

/*
 * @struct
 *
 * PCP response header format
 */
struct pcp_resp_hdr {
	uint8_t ver;
	uint8_t opcode:7; //First LSB
	uint8_t req_resp:1;// MSB
	uint8_t res_unuse;
	uint8_t result_code;
	uint32_t life_time;
	uint32_t epoch_time;
	uint32_t reserve[3];
} __attribute__((__packed__));

/*
 * @struct
 *
 * PCP MAP request header format
 */
struct pcp_map_req {
	uint32_t nonce[3];
	uint8_t protocol;
	uint32_t res_unuse1:24;
	uint16_t int_port;
	uint16_t ext_port;
	uint32_t ext_ip[4];
} __attribute__((__packed__));

/*
 * @struct
 *
 * PCP MAP response header format
 */
struct pcp_map_resp {
	uint32_t nonce[3];
	uint8_t protocol;
	uint32_t res_unuse1:24;
	uint16_t int_port;
	uint16_t ext_port;
	uint32_t ext_ip[4];
} __attribute__((__packed__));

/*
 * @struct
 *
 * PCP PEER request header format
 */
struct pcp_peer_req {
	uint32_t nonce[3];
	uint8_t protocol;
	uint32_t res_unuse1:24;
	uint16_t int_port;
	uint16_t ext_port;
	uint32_t ext_ip[4];
	uint16_t rpeer_port;
	uint16_t res_unuse2;
	uint32_t rpeer_ip[4];
} __attribute__((__packed__));

/*
 * @struct
 *
 * PCP PEER response header format
 */
struct pcp_peer_resp {
	uint32_t nonce[3];
	uint8_t protocol;
	uint32_t res_unuse1:24;
	uint16_t int_port;
	uint16_t ext_port;
	uint32_t ext_ip[4];
	uint16_t rpeer_port;
	uint16_t res_unuse2;
	uint32_t rpeer_ip[4];
} __attribute__((__packed__));

/*
 * @struct
 *
 * Customized IPv4 header of struct ipv4_hdr
 */
struct ipv4 {
	uint8_t  version_ihl;           /**< version and header length */
	uint8_t  type_of_service;       /**< type of service */
	uint16_t total_length;          /**< length of packet */
	uint16_t packet_id;             /**< packet ID */
	uint16_t fragment_offset;       /**< fragmentation offset */
	uint8_t  time_to_live;          /**< time to live */
	uint8_t  next_proto_id;         /**< protocol ID */
	uint16_t hdr_checksum;          /**< header checksum */
	uint32_t src_addr;              /**< source address */
	uint32_t dst_addr;              /**< destination address */
	uint16_t src_port;
	uint16_t dst_port;
} __attribute__((__packed__));

/*
 * @struct
 *
 * Customized IPv6 header of struct ipv6_hdr
 */
struct ipv6 {
	uint32_t vtc_flow;     /**< IP version, traffic class & flow label. */
	uint16_t payload_len;  /**< IP packet length -
				* includes sizeof(ip_header).
				*/
	uint8_t  proto;        /**< Protocol, next header. */
	uint8_t  hop_limits;   /**< Hop limits. */
	uint8_t  src_addr[16]; /**< IP address of source host. */
	uint8_t  dst_addr[16]; /**< IP address of destination host(s). */
	uint16_t src_port;
	uint16_t dst_port;

} __attribute__((__packed__));

/*
 * @struct
 *
 *  To represent the entire pkt data in one structure
 */
struct pcp_pkt {
	struct ether_hdr eth;
	union{
		struct ipv4 ipv4;
		struct ipv6 ipv6;
	};
} __attribute__((__packed__));

/**
 * A structure defining the PCP msg request
 */
struct pipeline_cgnapt_pcp_msg_req {
	enum pipeline_msg_req_type type;
	enum pipeline_cgnapt_msg_req_type subtype;

	/* data */
	uint8_t cmd;
	uint32_t lifetime;
};

/**
 * A structure defining the PCP cmd response message.
 */
struct pipeline_cgnapt_pcp_msg_rsp {
	int status;
};


/* All required offsets */
enum{
	MBUF_HEAD_ROOM = 256,
	ETH_HDR_SZ = 14,
	IPV4_HDR_SZ = 20,
	IPV6_HDR_SZ = 40,
	IPV4_SZ = 4,
	IPV6_SZ = 6,
	TCP_HDR_SZ = 20,
	UDP_HDR_SZ = 8,
	PCP_REQ_RESP_HDR_SZ = 24,
	PCP_MAP_REQ_RESP_SZ = 36,
	PCP_PEER_REQ_RESP_SZ = 56,
};

enum{
	ETH_DST_MAC	= MBUF_HEAD_ROOM,
	ETH_SRC_MAC	= MBUF_HEAD_ROOM + 6,
	PKT_TYPE		= MBUF_HEAD_ROOM + 12,
	IP_OFFSET	= MBUF_HEAD_ROOM + ETH_HDR_SZ,

/* IPV4 Offsets */

	IPV4_PROTOCOL		= MBUF_HEAD_ROOM + ETH_HDR_SZ + 9,
	IPV4_SRC_ADD_OFST	= MBUF_HEAD_ROOM + ETH_HDR_SZ + 12,
	IPV4_DST_ADD_OFST	= MBUF_HEAD_ROOM + ETH_HDR_SZ + 12 + IPV4_SZ,

	IPV4_TCP_OFST		= MBUF_HEAD_ROOM + ETH_HDR_SZ + IPV4_HDR_SZ,
	IPV4_TCP_SRC_PORT_OFST = MBUF_HEAD_ROOM + ETH_HDR_SZ + IPV4_HDR_SZ,
	IPV4_TCP_DST_PORT_OFST = MBUF_HEAD_ROOM + ETH_HDR_SZ + IPV4_HDR_SZ + 2,

	IPV4_UDP_OFST		= MBUF_HEAD_ROOM + ETH_HDR_SZ + IPV4_HDR_SZ,
	IPV4_UDP_SRC_PORT_OFST = MBUF_HEAD_ROOM + ETH_HDR_SZ + IPV4_HDR_SZ,
	IPV4_UDP_DST_PORT_OFST = MBUF_HEAD_ROOM + ETH_HDR_SZ + IPV4_HDR_SZ + 2,

	IPV4_PCP_OFST			 = MBUF_HEAD_ROOM + ETH_HDR_SZ +
					IPV4_HDR_SZ + UDP_HDR_SZ,
	IPV4_PCP_MAP_OFST		 = MBUF_HEAD_ROOM + ETH_HDR_SZ + IPV4_HDR_SZ +
					UDP_HDR_SZ + PCP_REQ_RESP_HDR_SZ,
	IPV4_PCP_PEER_OFST		 = MBUF_HEAD_ROOM + ETH_HDR_SZ + IPV4_HDR_SZ +
					UDP_HDR_SZ + PCP_REQ_RESP_HDR_SZ,

	IPV4_PCP_MAP_PL_LEN = IPV4_HDR_SZ + UDP_HDR_SZ + PCP_REQ_RESP_HDR_SZ +
					PCP_MAP_REQ_RESP_SZ,
	IPV4_PCP_PEER_PL_LEN = IPV4_HDR_SZ + UDP_HDR_SZ + PCP_REQ_RESP_HDR_SZ +
					PCP_PEER_REQ_RESP_SZ,
/* IPV6 Offsets */

	IPV6_PROTOCOL		= MBUF_HEAD_ROOM + ETH_HDR_SZ + 6,
	IPV6_SRC_ADD_OFST	= MBUF_HEAD_ROOM + ETH_HDR_SZ + 8,
	IPV6_DST_ADD_OFST	= MBUF_HEAD_ROOM + ETH_HDR_SZ + 8 + IPV6_SZ,

	IPV6_TCP_OFST		= MBUF_HEAD_ROOM + ETH_HDR_SZ + IPV6_HDR_SZ,
	IPV6_TCP_SRC_PORT_OFST = MBUF_HEAD_ROOM + ETH_HDR_SZ + IPV6_HDR_SZ,
	IPV6_TCP_DST_PORT_OFST = MBUF_HEAD_ROOM + ETH_HDR_SZ + IPV6_HDR_SZ + 2,

	IPV6_UDP_OFST		= MBUF_HEAD_ROOM + ETH_HDR_SZ + IPV6_HDR_SZ,
	IPV6_UCP_SRC_PORT_OFST = MBUF_HEAD_ROOM + ETH_HDR_SZ + IPV6_HDR_SZ,
	IPV6_UCP_DST_PORT_OFST = MBUF_HEAD_ROOM + ETH_HDR_SZ + IPV6_HDR_SZ + 2,

	IPV6_PCP_OFST			 = MBUF_HEAD_ROOM + ETH_HDR_SZ +
					IPV6_HDR_SZ + UDP_HDR_SZ,
	IPV6_PCP_MAP_OFST		 = MBUF_HEAD_ROOM + ETH_HDR_SZ + IPV6_HDR_SZ +
					UDP_HDR_SZ + PCP_REQ_RESP_HDR_SZ,
	IPV6_PCP_PEER_OFST		 = MBUF_HEAD_ROOM + ETH_HDR_SZ + IPV6_HDR_SZ +
					UDP_HDR_SZ + PCP_REQ_RESP_HDR_SZ,

	IPV6_PCP_MAP_PL_LEN = IPV6_HDR_SZ + UDP_HDR_SZ +
				PCP_REQ_RESP_HDR_SZ + PCP_MAP_REQ_RESP_SZ,
	IPV6_PCP_PEER_PL_LEN = IPV6_HDR_SZ + UDP_HDR_SZ +
				PCP_REQ_RESP_HDR_SZ + PCP_PEER_REQ_RESP_SZ,
};

enum{
STATIC_CGNAPT_TIMEOUT = -1,
DYNAMIC_CGNAPT_TIMEOUT = 0,
};

enum PCP_RET {
PCP_INIT_SUCCESS,
PCP_INIT_UNSUCCESS,
PCP_PCP_PKT,
//PCP_PCP_PKT_SUCCESS,
PCP_NOT_PCP_PKT,
PCP_PKT_CORRUPT,
};


uint8_t  _PCP_DEBUG;
uint32_t pcp_success_count;
uint32_t pcp_error_count;
uint32_t pcp_entry_count;
uint32_t pcp_enable;

uint8_t pcp_pool_init;
struct rte_mempool *pcp_mbuf_pool;

enum PCP_RET pcp_init(void);


#ifdef __cplusplus
}
#endif

#endif /* CGNAPT_PCP_H_ */
