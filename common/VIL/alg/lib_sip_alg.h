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

#ifndef __INCLUDE_LIB_ALG_H__
#define __INCLUDE_LIB_ALG_H__

#include "rte_ether.h"

uint16_t sip_session_number;/* SIP session count */
#define IS_STRING_SAME(pStr, strId) (bcmp((pStr), strId, strlen(strId)) == 0)
#define TAG_TO_DATAPOS(str) (strlen(str) + 1)
#define SKIP_SPACES(pStr)		\
{					\
	while (*(char *)(pStr) == ' ')	\
	(char *)(pStr)++;		\
}

enum pkt_dir {PRIVATE, PUBLIC};

/* enum for  SIP Call direction - NAT ALG */
enum sip_alg_call_direction {
	SIP_CALL_INCOMING, /* Incoming call public to private */
	SIP_CALL_OUTGOING /* Outgoing call private to public */
};

/* enum of  SIP port type - NAT ALG */
enum sip_alg_port_type {
	SIP_UDP, /* SIP SDP port 5460 */
	SIP_RTP, /* RTP port number */
	SIP_RTCP /* RTCP port number */
};

/*
 * Data structure for NAT SIP ALG table key
 * Key - IP address & L4 port number.
 */
struct sip_alg_key {
	/*
	 *  IP address based on direction.
	 *  outgoing - public IP, incoming - destinatio IP of pkt
	 */
	uint32_t ip_address;
	uint16_t l4port; /* SIP SDP, RTP, RTCP port number */
	uint8_t filler1;
	uint8_t filler2;
};

/*
 * Data structure for NAT SIP ALG table entry.
 * Placeholder for storing SIP ALG entries.
 */
struct sip_alg_table_entry {
	uint32_t ip_address;
	/*
	 * IP address based on direction.
	 * outgoing - public IP, incoming - destinatio IP of pkt
	 */
	uint16_t l4port; /* SIP UDP (5061), RTP, RTCP port number */
	uint8_t sip_alg_call_direction;
	/* Call incoming (pub to prv) or outgoing (prv to pub) */
	uint8_t sip_alg_call_id[100];/* unique identfier for a SIP call */
	uint8_t l4port_type;/* SIP_UDP or RTP or RTCP */
	uint8_t filler1;
	uint16_t filler2;
	uint32_t filler3;
} __rte_cache_aligned;


/* Function declarations */

/**
 * To initalize SIP ALG library and should be called-
 * - before other SIP ALG library funcitons
 * @param params
 * pipeline parameter structure pointer
 * @param app
 * pipeline application conext structure pointer
 * @return
 * void return
 */
void lib_sip_alg_init(void);

/**
 * Main SIP ALG DPI function for processing SIP ALG functionlity
 * @param pkt
 * mbuf packet pointer
 * @param pkt_direction
 * Indicates whether pkt is from PRIVATE or PUBLIC direction
 * @param modIp
 * NAPT tranlated IP address based on direction
 * @param modL4Port
 * NAPT translated L4 port based on direction
 * @param pubIP
 * Original IP address before translation
 * @param pubL4Port
 * Original L4 port before translation
 * @param modRtpPort
 * RTP port
 * @param modRtcpPort
 * RTCP port
 * @return
 * 0 means success, -1 means failure
 */
int sip_alg_dpi(struct rte_mbuf *pkt, enum pkt_dir pkt_direction,
		uint32_t modIp, uint16_t modL4Port,
		uint32_t pubIp, uint16_t pubL4Port,
		uint16_t modRtpPort, uint16_t modRtcpPort);

/**
 * To get audio ports from SIP Packet
 * @param pkt
 * mbuf packet pointer
 * @param rtpPort
 * rtp port in parameter
 * @param rtcpPort
 * rtcp port in parameter
 * @return
 * 0 means success, -1 means failre
 */
int natSipAlgGetAudioPorts(
	struct rte_mbuf *pkt,
	uint16_t *rtpPort,
	uint16_t *rtcp_port);
int natSipAlgMsgFieldPos(
	char *pData,
	const char *pIdStr,
	int *pos,
	int searchLen);
int natSipAlgMsgFieldPosFindCrlf(
	char *pData,
	const char *pIdStr,
	int *pPos,
	int searchLen);
int natSipAlgMsgFieldPosFindSpace(
	char *pData,
	const char *pIdStr,
	int *pPos,
	int searchLen);
int remove_sip_alg_entry(
	uint32_t ipaddr,
	uint16_t portid);

#endif
