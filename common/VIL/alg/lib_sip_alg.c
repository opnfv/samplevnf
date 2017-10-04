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
/*Sriramajeyam*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <math.h>

#include <app.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_table_lpm.h>
#include <rte_table_hash.h>
#include <rte_pipeline.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cycles.h>

#include "pipeline_actions_common.h"
#include "hash_func.h"
#include "lib_sip_alg.h"
#include "vnf_common.h"
#include "pipeline_common_be.h"

#define SIP_ALG_SIP "SIP"
#define SIP_ALG_200_OK "200 OK"
#define SIP_ALG_INVITE "INVITE"
#define SIP_ALG_BYE "BYE"
#define SIP_ALG_TRYING "100 Trying"
#define SIP_ALG_RINGING "180 Ringing"
#define SIP_ALG_ACK "ACK"
#define SIP_ALG_CONTACT "Contact"
#define SIP_ALG_CONTENT_LEN "Content-Length"
#define SIP_ALG_VIA "Via"
#define SIP_ALG_FROM "From"
#define SIP_ALG_TO "To"
#define SIP_ALG_CALLID "Call-ID"
#define SIP_ALG_RTP "RTP"
#define SIP_ALG_RTCP "a=RTCP"
#define SIP_ALG_CANCEL "CANCEL"
#define SIP_ALG_CONTYPE "Content-Type"
#define SIP_ALG_APPSDP "application/sdp"
#define SIP_ALG_CSEQ "CSeq"
#define SIP_ALG_AUDIO "m=audio"
#define SIP_ALG_DOUBLE_CRLF "\r\n\r\n"
#define SIP_ALG_CRLF "\r\n"
#define SIP_ALG_AT "@"
#define SIP_ALG_GREAT ">"
#define SIP_ALG_OWNER "o="
#define SIP_ALG_IPV4 "IP4"
#define SIP_ALG_CONN "c="
#define SIP_ALG_REMOTE_PARTY_ID "Remote-Party-ID"
#define SIP_ALG_SPACE " "
#define SIP_ALG_SEMICOLON ";"

#define SIP_DEFAULT_L4PORT 5060

#define SIP_ALG_INVITE_MSGTYPE 1
#define SIP_ALG_BYE_MSGTYPE 2
#define SIP_ALG_200_OK_INVITE_MSGTYPE 3
#define SIP_ALG_200_OK_BYE_MSGTYPE 4
#define SIP_ALG_TRYING_RINGING_MSGTYPE 5
#define SIP_ALG_ACK_MSGTYPE 6

#define MAX_NUM_SIP_ALG_ENTRIES 16384

#define SIP_ALG_VIA_FIELD_IPADDR   14
#define SIP_ALG_CTAC_FIELD_IPADDR  7

#define ADDRESS_PORT_STRING   1
#define PORT_STRING           2

#define MAX_ADDR_PORT_SIZE 30
#define MAX_ADDR_SIZE 20
#define MAX_PORT_SIZE 10
#define MAX_SIP_UDP_MSG_SIZE 2000

#define ALG_DEBUG 0

enum { FALSE, TRUE };

struct rte_mempool *lib_alg_pktmbuf_tx_pool;

struct rte_mbuf *lib_alg_pkt;

static struct rte_hash_parameters sip_alg_hash_params = {
	.name = NULL,
	.entries = MAX_NUM_SIP_ALG_ENTRIES,
	.reserved = 0,
	.key_len = sizeof(struct sip_alg_key),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
	.extra_flag = 1,
};

struct rte_hash *sip_alg_hash_table;

struct sip_alg_table_entry *sip_alg_table[MAX_NUM_SIP_ALG_ENTRIES];

char *sip_alg_process(struct rte_mbuf *pkt,
					uint16_t pkt_direction, uint16_t call_direction,
					uint16_t msgType, uint32_t modIp,
					uint16_t modL4Port, uint32_t pubIp,
					uint16_t pubL4Port, uint16_t modRtpPort,
					uint16_t modRtcpPort, uint16_t *diffModSipLen);
char *getSipCallIdStr(char *pMsg);
char *natSipAlgModifyPayloadAddrPort(char *pSipMsg, char **pSipMsgEnd,
						 uint32_t oldStrLen, uint32_t *diffLen,
						 uint32_t pub_ip, uint16_t pub_port,
						 uint32_t type);
char *natSipAlgAdjustMsg(char *pSipMsg, char **pSipMsgEnd,
			 uint32_t newStrLen, uint32_t oldStrLen);

// This method will be called from other VNF to initialize SIP lib
// Make an API out of it
void lib_sip_alg_init(void)
{
	char *s = rte_zmalloc(NULL, 64, RTE_CACHE_LINE_SIZE);;
	int socketid = 0;
	/* create ipv4 hash */
	if(!s){
		printf("NAT SIP ALG Init failed\n");
		return;
	}
	snprintf(s, strlen(s), "ipv4_sip_alg_hash_%d", socketid);
	printf("NAT SIP ALG initialization ...\n");

	/* SIP ALG hash table initialization */
	sip_alg_hash_params.socket_id = SOCKET_ID_ANY;
	sip_alg_hash_params.name = s;
	sip_alg_hash_table = rte_hash_create(&sip_alg_hash_params);

	if (sip_alg_hash_table == NULL) {
		printf("SIP ALG rte_hash_create failed. socket %d ...\n",
					 sip_alg_hash_params.socket_id);
		rte_exit(0, "SIP ALG rte_hash_create failed");
	} else {
		printf("sip_alg_hash_table %p\n\n", (void *)sip_alg_hash_table);
	}

}

char *itoa(long n);
char itoa_buf[25];
char *itoa(long n)
{
	int len = n == 0 ? 1 : floor(log10l(labs(n))) + 1;

	if (n < 0)
		len++;		/* room for negative sign '-' */

	snprintf(itoa_buf, len + 1, "%ld", n);
        return (char *)&itoa_buf;
}

struct sip_alg_table_entry *retrieve_sip_alg_entry(
			struct sip_alg_key *alg_key);

struct sip_alg_table_entry *retrieve_sip_alg_entry(
			struct sip_alg_key *alg_key)
{
	struct sip_alg_table_entry *sip_alg_data = NULL;

	int ret = rte_hash_lookup(sip_alg_hash_table, alg_key);

	if (ret < 0) {
		#ifdef ALGDBG
			printf("alg-hash lookup failed ret %d, "
					"EINVAL %d, ENOENT %d\n",
					 ret, EINVAL, ENOENT);
		#endif
	} else {
		sip_alg_data = sip_alg_table[ret];
		return sip_alg_data;
	}

	return NULL;
}

//int remove_sip_alg_entry(uint32_t ipaddr, uint16_t portid);
int remove_sip_alg_entry(uint32_t ipaddr, uint16_t portid)
{
	struct sip_alg_key alg_key;
	void *sip_alg_entry_data;
	int ret;

	alg_key.l4port = portid;
	alg_key.ip_address = ipaddr;
	alg_key.filler1 = 0;
	alg_key.filler2 = 0;

	if (ALG_DEBUG)
		printf("remove_sip_entry ip %x, port %d\n", alg_key.ip_address,
					 alg_key.l4port);

	ret = rte_hash_lookup(sip_alg_hash_table, &alg_key);
	if (ret < 0) {
		if (ALG_DEBUG)
			printf("removesipalgentry: "
				"rtehashlookup failed with error %d",
					 ret);
		return -1;
	}

	sip_alg_entry_data = sip_alg_table[ret];

	free(sip_alg_entry_data);
	rte_hash_del_key(sip_alg_hash_table, &alg_key);

	return 0;
}

/*
 * Function for populating SIP ALG entry. return 0 - success &
 * return -1 - failure
 */
int populate_sip_alg_entry(uint32_t ipaddr, uint16_t portid,
				 char *sip_call_id, uint8_t call_direction,
				 enum sip_alg_port_type port_type);
int populate_sip_alg_entry(uint32_t ipaddr, uint16_t portid,
				 char *sip_call_id, uint8_t call_direction,
				 enum sip_alg_port_type port_type)
{
	struct sip_alg_key alg_key;

	alg_key.l4port = portid;
	alg_key.ip_address = ipaddr;
	alg_key.filler1 = 0;
	alg_key.filler2 = 0;
	int ret;

	if (ALG_DEBUG)
		printf("populate_sip_alg_entry port %d, ip %x\n",
					 alg_key.l4port, alg_key.ip_address);

	struct sip_alg_table_entry *new_alg_data =
			retrieve_sip_alg_entry(&alg_key);

	if (new_alg_data) {
		if (ALG_DEBUG)
			printf("sip_alg_entry exists ip%x, port %d\n",
						 alg_key.ip_address, alg_key.l4port);
		return 0;
	}

	new_alg_data = NULL;
	new_alg_data = (struct sip_alg_table_entry *)
			malloc(sizeof(struct sip_alg_table_entry));
	if (new_alg_data == NULL) {
		printf("populate sip alg entry: allocation failed\n");
		return -1;
	}

	new_alg_data->l4port = portid;
	new_alg_data->ip_address = ipaddr;
	new_alg_data->l4port_type = port_type;
	new_alg_data->sip_alg_call_direction = call_direction;
	strcpy((char *)new_alg_data->sip_alg_call_id, (char *)sip_call_id);
	new_alg_data->filler1 = 0;
	new_alg_data->filler2 = 0;
	new_alg_data->filler3 = 0;

	ret = rte_hash_add_key(sip_alg_hash_table, &alg_key);
	if (ret < 0) {
		printf("populate sip - rte_hash_add_key_data ERROR %d\n", ret);
		free(new_alg_data);
		return -1;
	}

	sip_alg_table[ret] = new_alg_data;

	if (ALG_DEBUG) {
		printf("SIP_ALG: table update - ip=%x on port=%d ret=%d\n",
					 alg_key.ip_address, portid, ret);
	}
	return 0;
}

int sip_alg_dpi(struct rte_mbuf *pkt, enum pkt_dir pkt_direction,
		uint32_t modIp, uint16_t modL4Port,
		uint32_t pubIp, uint16_t pubL4Port,
		uint16_t modRtpPort, uint16_t modRtcpPort)
{
	uint16_t msgType = 0;
	enum sip_alg_call_direction call_direction = 0;
	uint32_t ip_address = 0;
	uint16_t port = 0;
	int ret = 0;
	struct ipv4_hdr *ip_h;
	struct ether_hdr *eth_h = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	struct udp_hdr *udp_h;
	char *pSipMsg = NULL;
	struct sip_alg_table_entry *sip_alg_entry;
	char *sip_call_id = NULL;
	int pos = 0;
	struct sip_alg_key alg_key;
	uint16_t diffModSipLen = 0;

	ip_h = (struct ipv4_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	udp_h = (struct udp_hdr *)((char *)ip_h + sizeof(struct ipv4_hdr));
	pSipMsg = ((char *)udp_h + sizeof(struct udp_hdr));

	if (ALG_DEBUG) {
	printf("%s: packet length(%u), buffer length(%u)\n", __func__,
		rte_pktmbuf_pkt_len(pkt), pkt->buf_len);
	printf("%s: last segment addr(%p %p)\n", __func__,
		rte_pktmbuf_lastseg(pkt), pkt);
	printf("%s: data len(%u, %u)\n", __func__, rte_pktmbuf_data_len(pkt),
		rte_pktmbuf_data_len(rte_pktmbuf_lastseg(pkt)));
	printf("%s: buffer addr(%p), data_off(%u), nb_segs(%u)\n", __func__,
		pkt->buf_addr, pkt->data_off, pkt->nb_segs);
	}

	if (IS_STRING_SAME(pSipMsg, SIP_ALG_INVITE)) {
		/* find the call id position in the message */
		if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_CALLID, &pos, 0) ==
				TRUE)
			sip_call_id =
					getSipCallIdStr(pSipMsg + pos +
							TAG_TO_DATAPOS(SIP_ALG_CALLID));
			if (!sip_call_id) {
				printf("sip_call_id returned is NULL\n");
				return 0;
			}

		if (ALG_DEBUG)
			printf("sipalgdpi: %d call id %s\n", __LINE__,
						 sip_call_id);

		if (pkt_direction == PRIVATE) {
			call_direction = SIP_CALL_OUTGOING;
			ip_address = rte_bswap32(ip_h->src_addr);
			port = rte_bswap16(udp_h->src_port);
		} else if (pkt_direction == PUBLIC) {
			call_direction = SIP_CALL_INCOMING;
			ip_address = pubIp;
			port = pubL4Port;
		}

		if (ALG_DEBUG)
			printf("0=>sip_alg_dpi: pkt_dir(%d), call_dir(%d), "
						"ipaddr(%x) port(%x)\n",
					 pkt_direction, call_direction, ip_address, port);

		/* add 3 entries in ALG table for SIP, RTP, RTCP */
		ret = populate_sip_alg_entry(ip_address, port,
							 sip_call_id, call_direction,
							 SIP_UDP);
		if (ret < 0) {
			printf("sipalgdpi:populate SIP alg UDP entry failed\n");
			return 0;
		}
		if (modRtpPort != 0) {
			ret = populate_sip_alg_entry(ip_address, modRtpPort,
								 sip_call_id,
								 call_direction, SIP_RTP);
			if (ret < 0) {
				printf("sipalgdpi: "
					"populate SIP alg entry RTP failed\n");
				return 0;
			}
		}
		if (modRtcpPort != 0) {
			ret = populate_sip_alg_entry(ip_address, modRtcpPort,
								 sip_call_id,
								 call_direction, SIP_RTCP);
			if (ret < 0) {
				printf("sipalgdpi: "
				"populate SIP alg entry RTCP failed\n");
				return 0;
			}
		}

/* Call ALG packet process function for checking & payload modification */
		pSipMsg =
				sip_alg_process(pkt, pkt_direction, call_direction,
						SIP_ALG_INVITE_MSGTYPE, modIp, modL4Port, 0,
						0, modRtpPort, modRtcpPort, &diffModSipLen);
	} else {
	/*
	 * not SIP INVITE, could be SIP response 200 OK invite, 100 trying,
	 * 180 ringing or BYE or 200 OK BYe
	 */
		/* retrieve ALG entry from SIP ALG table */
		if (pkt_direction == PRIVATE) {
			alg_key.ip_address = rte_bswap32(ip_h->src_addr);
			alg_key.l4port = rte_bswap16(udp_h->src_port);
		} else {
			alg_key.ip_address = pubIp;
			alg_key.l4port = pubL4Port;
		}

		alg_key.filler1 = 0;
		alg_key.filler2 = 0;
		sip_alg_entry = retrieve_sip_alg_entry(&alg_key);

		if (ALG_DEBUG) {
			printf("%s: sip_alg_entry_ptr(%p)\n", __func__,
						 sip_alg_entry);
			printf("1=>%s: pkt_dir(%d), modIp(%x),modL4Port(%x), "
		"modRtpPort(%x), modRtcpPort(%x), pubIp(%x), pubL4Port(%x)\n",
					 __func__, pkt_direction, modIp, modL4Port,
					 modRtpPort, modRtcpPort, pubIp, pubL4Port);
		}

		if (sip_alg_entry) {
			call_direction = sip_alg_entry->sip_alg_call_direction;
			if (IS_STRING_SAME(pSipMsg, SIP_ALG_BYE) ||
					IS_STRING_SAME(pSipMsg, SIP_ALG_CANCEL)) {
				msgType = SIP_ALG_BYE_MSGTYPE;

				goto sipAlgProcess;
			} else if (IS_STRING_SAME(pSipMsg, SIP_ALG_ACK)) {
				msgType = SIP_ALG_ACK_MSGTYPE;

				goto sipAlgProcess;
			}

			pSipMsg += 8;
		/* checking if its OK or Trying or Ringing */
			if (IS_STRING_SAME(pSipMsg, SIP_ALG_200_OK)) {
			/* check CSEQ. Based on that update the msg type */
				if (natSipAlgMsgFieldPos
						(pSipMsg, SIP_ALG_CSEQ, &pos, 0) == TRUE) {
					char *pBye;

					pBye =
							pSipMsg + pos +
							TAG_TO_DATAPOS(SIP_ALG_CSEQ);
					SKIP_SPACES(pBye);
					/* skip the number field */
					while (*pBye != ' ')
						pBye++;
					SKIP_SPACES(pBye);
					if (IS_STRING_SAME(pBye, SIP_ALG_BYE)
							||
							(IS_STRING_SAME
							 (pBye, SIP_ALG_CANCEL)))
						msgType =
								SIP_ALG_200_OK_BYE_MSGTYPE;

					else
						msgType =
							SIP_ALG_200_OK_INVITE_MSGTYPE;
				}
			} else if (IS_STRING_SAME(pSipMsg, SIP_ALG_TRYING) ||
					 IS_STRING_SAME(pSipMsg, SIP_ALG_RINGING)) {
				msgType = SIP_ALG_TRYING_RINGING_MSGTYPE;
			}

 sipAlgProcess:
			if (ALG_DEBUG)
				printf("2=>%s: pkt_dir(%d), call_dir(%d), "
				"msgType(%d), modIp(%x), modL4Port(%x), "
				" modRtpPort(%x), modRtcpPort(%x)\n",
						 __func__, pkt_direction, call_direction,
						 msgType, modIp, modL4Port, modRtpPort,
						 modRtcpPort);
			/* Call SIP alg processing for further processing. */
			pSipMsg =
					sip_alg_process(pkt, pkt_direction, call_direction,
							msgType, modIp, modL4Port, pubIp,
							pubL4Port, modRtpPort, modRtcpPort,
							&diffModSipLen);
		} else
			pSipMsg = NULL;
	}

	if (ALG_DEBUG)
		printf("%s: Before IP total length(%u), udp length(%u)\n", __func__,
		rte_bswap16(ip_h->total_length), rte_bswap16(udp_h->dgram_len));
	/*
	 * need to modify mbuf & modified length of payload in the IP/UDP
	 * header length fields and return to CGNAT for transmitting
	 */
	uint16_t len = 0;
	if (diffModSipLen > 0) {
		len = rte_bswap16(udp_h->dgram_len);
		len += diffModSipLen;
		udp_h->dgram_len = rte_bswap16(len);

		len = rte_bswap16(ip_h->total_length);
		len += diffModSipLen;
		ip_h->total_length = rte_bswap16(len);

		if (rte_pktmbuf_append(pkt, diffModSipLen) == NULL)
			printf("%s: pktmbuf_append returns NULL", __func__);

	}

	if (ALG_DEBUG)
		printf("%s: After IP total length(%u), udp length(%u), "
		"diffModSipLen(%u)\n", __func__,
		rte_bswap16(ip_h->total_length),
		rte_bswap16(udp_h->dgram_len),
		diffModSipLen);

	if (pSipMsg != NULL)
		return 1;
	else
		return 0;
}

char *sip_alg_process(struct rte_mbuf *pkt, uint16_t pkt_direction,
					uint16_t call_direction, uint16_t msgType, uint32_t modIp,
					uint16_t modL4Port, uint32_t pubIp, uint16_t pubL4Port,
					uint16_t modRtpPort, uint16_t modRtcpPort,
					uint16_t *diffModSipLen)
{
	struct ipv4_hdr *ip_h;
	struct ether_hdr *eth_h = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	struct udp_hdr *udp_h;
	char *pSipMsg, *pStr, *pEndPtr;
	int pos;
	/* diff between old & new modified field len */
	uint32_t diffLen, addrPortLen;
	int sdpMsgLen = 0;
	int sip_msg_len = 0;

	ip_h = (struct ipv4_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	udp_h = (struct udp_hdr *)((char *)ip_h + sizeof(struct ipv4_hdr));
	pSipMsg = ((char *)udp_h + sizeof(struct udp_hdr));
	char *pTmpSipMsg = pSipMsg;
	char *pStartSipMsg = pSipMsg;

	sip_msg_len =
			rte_bswap16(ip_h->total_length) - sizeof(struct ipv4_hdr) -
			sizeof(struct udp_hdr);

	if (natSipAlgMsgFieldPos(pTmpSipMsg, SIP_ALG_CONTENT_LEN, &pos, 0) ==
			TRUE)
		pTmpSipMsg += (pos + TAG_TO_DATAPOS(SIP_ALG_CONTENT_LEN));
	else {
		printf("sip_alg_process: Invalid Content Length\n");
		return NULL;
	}

	SKIP_SPACES(pTmpSipMsg);
	int sdpDataLen = strtol(pTmpSipMsg, &pStr, 10);

	natSipAlgMsgFieldPosFindCrlf(pTmpSipMsg, SIP_ALG_DOUBLE_CRLF, &pos, 0);
	pTmpSipMsg += (pos + strlen(SIP_ALG_DOUBLE_CRLF));

	if (sdpDataLen != 0)
		if (natSipAlgMsgFieldPos
				(pTmpSipMsg, SIP_ALG_REMOTE_PARTY_ID, &pos, 0) == TRUE) {
			pTmpSipMsg += pos + strlen(SIP_ALG_REMOTE_PARTY_ID);
			/* move further to CRLF which is the end of SIP msg */
			natSipAlgMsgFieldPosFindCrlf(pTmpSipMsg,
								 SIP_ALG_DOUBLE_CRLF, &pos,
								 0);
			pTmpSipMsg += (pos + strlen(SIP_ALG_DOUBLE_CRLF));
		}

	int sipMsgLen = (pTmpSipMsg - pSipMsg);

	if ((sipMsgLen + sdpDataLen) > strlen(pSipMsg))
		return NULL;

	char *pSipMsgEnd = pSipMsg + sipMsgLen + sdpDataLen;

	if (ALG_DEBUG)
		printf("%s: pSipMsg: %p, pSipMsgEnd: %p, sipMsgLen: %d, "
				"sdpDataLen: %d totalSipMsgLen: %d\n",
				 __func__, pSipMsg, pSipMsgEnd, sipMsgLen, sdpDataLen,
				 sip_msg_len);

	if (call_direction == SIP_CALL_OUTGOING) {
		if ((msgType == SIP_ALG_INVITE_MSGTYPE)
				|| (msgType == SIP_ALG_ACK_MSGTYPE)) {
			/* Get to Via field IP address/Port to modify */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_VIA, &pos, 0)
					== TRUE) {
				/* advance to IP/Port string */
				pSipMsg +=
						(pos + strlen(SIP_ALG_VIA) +
						 SIP_ALG_VIA_FIELD_IPADDR);
				pTmpSipMsg = pSipMsg;
				/* move pTmp to next field */
				natSipAlgMsgFieldPos(pTmpSipMsg,
								 SIP_ALG_SEMICOLON, &pos,
								 0);
				pTmpSipMsg += pos;
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf("sip_alg_process; No valid VIA field\n");
				return NULL;
			}
			/* Modify VIA field IP addr:port in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);

			*diffModSipLen += diffLen;
/* increase the overall diff between old & mod sip msg */

			/* Advance to "From" field IP addr in payload */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_FROM, &pos, 0)
					== TRUE) {
				pSipMsg += pos;	/* Moving to "From" */
				/* advance to IP/Port string */
				pTmpSipMsg = pSipMsg;
/* move pTmpSipMsg to str ">" which is end of add:port string */
				natSipAlgMsgFieldPos(pTmpSipMsg, SIP_ALG_GREAT,
								 &pos, 0);
				pTmpSipMsg += pos;
				diffLen = pTmpSipMsg - pSipMsg;
/* find "@" from "From" string to ">" string which is start of "addr:port" */
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
/* now its pointing to start of From field "address:port" */
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf
						("sip_alg_process; No valid From field\n");
				return NULL;
			}
			/* Modify "From" field "addr:port" in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);

			*diffModSipLen += diffLen;
/* increase the overall diff between old & mod sip msg */

			/* Advance to Call id field */
			if (natSipAlgMsgFieldPos
					(pSipMsg, SIP_ALG_CALLID, &pos, 0) == TRUE) {
				pSipMsg += pos;
/* moving it to start of string "Call-ID" */
				pTmpSipMsg = pSipMsg;
				/* move tmpSipMsg to next field */
				natSipAlgMsgFieldPosFindCrlf(pTmpSipMsg,
									 SIP_ALG_CRLF, &pos,
									 0);
				pTmpSipMsg += pos;
				diffLen = pTmpSipMsg - pSipMsg;
		/* Move pSipMsg to start of Call id "IP addr" string */
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf("sip_alg_process; "
					" No valid Call Id field\n");
				return NULL;
			}
			/* Modify "Call-id" field "addr:port" in payload */
/* L4 port input is made as 0 as its only addr string modification */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp, 0,
								 ADDRESS_PORT_STRING);

			*diffModSipLen += diffLen;

			/* Advance to "Contact" field */
			if (natSipAlgMsgFieldPos
					(pSipMsg, SIP_ALG_CONTACT, &pos, 0) == TRUE) {
				pSipMsg += pos;
				/* move tmpMsg to CRLF */
				pTmpSipMsg = pSipMsg;
				natSipAlgMsgFieldPosFindCrlf(pTmpSipMsg,
									 SIP_ALG_CRLF, &pos,
									 0);
				pTmpSipMsg += pos;
				/* move sipMsg to addr:port string */
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
				addrPortLen = pTmpSipMsg - pSipMsg;

			} else {
				printf("sip_alg_process; "
					"No valid Call Id field\n");
				return NULL;
			}
			/* Modify "Contact" field "addr:port" in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);

			*diffModSipLen += diffLen;

			if (msgType == SIP_ALG_INVITE_MSGTYPE) {
/* Advance to check content type & get content length (SDP length) */
				if (natSipAlgMsgFieldPos
						(pSipMsg, SIP_ALG_CONTYPE, &pos,
						 0) == TRUE) {
					pSipMsg +=
							(pos +
							 TAG_TO_DATAPOS(SIP_ALG_CONTYPE));
					SKIP_SPACES(pSipMsg);
			/*check the application/sdp type, if not, exit */
					if (!IS_STRING_SAME
							(pSipMsg, SIP_ALG_APPSDP)) {
						printf("sip_alg_process "
						"Invalid Content type\n");
						return NULL;
					}
				} else {
					printf("sip_alg_process; "
						"No valid Content field\n");
					return NULL;
				}

				/* get the SDP content length */
				natSipAlgMsgFieldPos(pSipMsg,
								 SIP_ALG_CONTENT_LEN, &pos,
								 0);
				pSipMsg +=
						(pos + TAG_TO_DATAPOS(SIP_ALG_CONTENT_LEN));
				SKIP_SPACES(pSipMsg);
				sdpMsgLen = strtol(pSipMsg, &pEndPtr, 10);
				if (!sdpMsgLen) {
/* if ACK message, SDP content wont be there.go to ALG process complete */
					if (msgType == SIP_ALG_ACK_MSGTYPE)
						goto sipAlgProcessExit;

					printf("sip_alg_process - "
						"sdpMsgLen is 0\n");
					return NULL;
				}

				/* Advance to SDP data message Owner address */
				if (natSipAlgMsgFieldPos
						(pSipMsg, SIP_ALG_OWNER, &pos,
						 0) == TRUE) {
					pSipMsg += pos;
			/* at start of owner string "o=" */
					pTmpSipMsg = pSipMsg;
					/* move tmmsg to CRLF of owner field */
					natSipAlgMsgFieldPosFindCrlf(pSipMsg,
									 SIP_ALG_CRLF,
									 &pos,
									 0);
					pTmpSipMsg += pos;
/* start of CRLF "/r/n" */
/* move pSipMsg to IP address string in owner field */
					natSipAlgMsgFieldPos(pSipMsg,
									 SIP_ALG_IPV4, &pos,
									 0);
					pSipMsg += (pos + strlen(SIP_ALG_IPV4));
					SKIP_SPACES(pSipMsg);
/* after skipping spaces, pSip at start of addr */
					addrPortLen = pTmpSipMsg - pSipMsg;
				} else {
					printf("sip_alg_processing: "
						"Invalid Owner field\n");
					return NULL;
				}
/* Modify "Owner" field "addr" in payload.  Input L4 port as 0 */
				pSipMsg =
						natSipAlgModifyPayloadAddrPort(pSipMsg,
									 &pSipMsgEnd,
									 addrPortLen,
									 &diffLen,
									 modIp, 0,
								 ADDRESS_PORT_STRING);

				*diffModSipLen += diffLen;
				sdpMsgLen += diffLen;
/* need to adjust the SDP msg len as modification done. */

/* Advance to Connection information to modify IP address */
				if (natSipAlgMsgFieldPos
						(pSipMsg, SIP_ALG_CONN, &pos,
						 0) == TRUE) {
					pSipMsg += pos;
					pTmpSipMsg = pSipMsg;
					/* move tmmsg to CRLF of owner field */
					natSipAlgMsgFieldPosFindCrlf(pSipMsg,
									 SIP_ALG_CRLF,
										 &pos,
										 0);
					pTmpSipMsg += pos;
			/* start of CRLF "/r/n" */
			/* move pSipMsg to IP address string in owner field */
					natSipAlgMsgFieldPos(pSipMsg,
									 SIP_ALG_IPV4, &pos,
									 0);
					pSipMsg += (pos + strlen(SIP_ALG_IPV4));
					SKIP_SPACES(pSipMsg);
/* after skipping spaces, pSip at start of addr */
					addrPortLen = pTmpSipMsg - pSipMsg;
				} else {
					printf("sip_alg_processing: "
						"Invalid Owner field\n");
					return NULL;
				}
/* Modify "Connection" field "addr" in payload.  Input L4 port as 0 */
				pSipMsg =
						natSipAlgModifyPayloadAddrPort(pSipMsg,
									 &pSipMsgEnd,
									 addrPortLen,
									 &diffLen,
									 modIp, 0,
								 ADDRESS_PORT_STRING);

				*diffModSipLen += diffLen;
				sdpMsgLen += diffLen;
/* need to adjust the SDP msg len as modification done. */

				/* Advance to RTP audio port */
				if (natSipAlgMsgFieldPos
						(pSipMsg, SIP_ALG_AUDIO, &pos,
						 0) == TRUE) {
					pSipMsg +=
							(pos +
							 TAG_TO_DATAPOS(SIP_ALG_AUDIO));
					SKIP_SPACES(pSipMsg);
					pTmpSipMsg = pSipMsg;
					natSipAlgMsgFieldPosFindSpace
							(pTmpSipMsg, SIP_ALG_SPACE, &pos,
							 0);
					pTmpSipMsg += pos;
					addrPortLen = pTmpSipMsg - pSipMsg;
				}

/* Modify "RTP Audio" port in payload. pass pub_ip as 0. */
				pSipMsg =
						natSipAlgModifyPayloadAddrPort(pSipMsg,
									 &pSipMsgEnd,
									 addrPortLen,
									 &diffLen, 0,
									 modRtpPort,
									 PORT_STRING);

				*diffModSipLen += diffLen;
				sdpMsgLen += diffLen;
/* need to adjust the SDP msg len as modification done. */

				/* Advance to RTCP control port, if its there */
				if (natSipAlgMsgFieldPos
						(pSipMsg, SIP_ALG_RTCP, &pos,
						 0) == TRUE) {
					pSipMsg +=
							(pos +
							 TAG_TO_DATAPOS(SIP_ALG_RTCP));
					SKIP_SPACES(pSipMsg);
					pTmpSipMsg = pSipMsg;
					natSipAlgMsgFieldPosFindSpace
							(pTmpSipMsg, SIP_ALG_SPACE, &pos,
							 0);
					pTmpSipMsg += pos;
					addrPortLen = pTmpSipMsg - pSipMsg;

/* Modify "RTP Audio" port in payload. pass pub_ip as 0. */
					pSipMsg =
							natSipAlgModifyPayloadAddrPort
							(pSipMsg, &pSipMsgEnd, addrPortLen,
							 &diffLen, 0, modRtcpPort,
							 PORT_STRING);

					*diffModSipLen += diffLen;
					sdpMsgLen += diffLen;
/* need to adjust the SDP msg len as modification done. */
				}
			}
/* with this SIP payload modification is complete for outbound invite message */
		} else if ((msgType == SIP_ALG_TRYING_RINGING_MSGTYPE)
				 || (msgType == SIP_ALG_200_OK_INVITE_MSGTYPE)) {
			/* Get to Via field IP address/Port to modify */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_VIA, &pos, 0)
					== TRUE) {
				/* advance to IP/Port string */
				pSipMsg +=
						(pos + strlen(SIP_ALG_VIA) +
						 SIP_ALG_VIA_FIELD_IPADDR);
				pTmpSipMsg = pSipMsg;
				/* move pTmp to next field */
				natSipAlgMsgFieldPos(pTmpSipMsg,
								 SIP_ALG_SEMICOLON, &pos,
								 0);
				pTmpSipMsg += pos;
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf("sip_alg_process; No valid VIA field\n");
				return NULL;
			}
			/* Modify VIA field IP addr:port in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);
			*diffModSipLen = diffLen;

			/* Advance to "From" field IP addr in payload */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_FROM, &pos, 0)
					== TRUE) {
				pSipMsg += pos;	/* Moving to "From" */
				/* advance to IP/Port string */
				pTmpSipMsg = pSipMsg;
/* move pTmpSipMsg to str ">" which is end of add:port string */
				natSipAlgMsgFieldPos(pTmpSipMsg, SIP_ALG_GREAT,
								 &pos, 0);
				pTmpSipMsg += pos;
				//diffLen = pTmpSipMsg - pSipMsg;
/* find "@" from "From" string to ">" string which is start of "addr:port" */
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
/* now its pointing to start of From field "address:port" */
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf
						("sip_alg_process; No valid From field\n");
				return NULL;
			}
			/* Modify "From" field "addr:port" in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);

			*diffModSipLen += diffLen;
/* increase the overall diff between old & mod sip msg */

			/* Advance to Call id field */
			if (natSipAlgMsgFieldPos
					(pSipMsg, SIP_ALG_CALLID, &pos, 0) == TRUE) {
				pSipMsg += pos;
/* moving it to start of string "Call-ID" */
				pTmpSipMsg = pSipMsg;
				/* move tmpSipMsg to next field */
				natSipAlgMsgFieldPosFindCrlf(pTmpSipMsg,
									 SIP_ALG_CRLF, &pos,
									 0);
				pTmpSipMsg += pos;
				//diffLen = pTmpSipMsg - pSipMsg;
		/* Move pSipMsg to start of Call id "IP addr" string */
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf("sip_alg_process; "
					"No valid Call Id field\n");
				return NULL;
			}
			/* Modify "Call-id" field "addr" in payload */
/* L4 port input is made as 0 as its only addr string modification */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp, 0,
								 ADDRESS_PORT_STRING);

			*diffModSipLen += diffLen;

		} else if (pkt_direction == PRIVATE
				 && msgType == SIP_ALG_BYE_MSGTYPE) {
			/* change via, from, call-id and contact field */

			/* Get to Via field IP address to modify */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_VIA, &pos, 0)
					== TRUE) {
				/* advance to IP/Port string */
				pSipMsg +=
						(pos + strlen(SIP_ALG_VIA) +
						 SIP_ALG_VIA_FIELD_IPADDR);
				pTmpSipMsg = pSipMsg;
				/* move pTmp to next field */
				natSipAlgMsgFieldPos(pTmpSipMsg,
								 SIP_ALG_SEMICOLON, &pos,
								 0);
				pTmpSipMsg += pos;
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf("sip_alg_process; No valid VIA field\n");
				return NULL;
			}
			/* Modify VIA field IP addr in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp, 0,
								 ADDRESS_PORT_STRING);
			*diffModSipLen = diffLen;

			/* Advance to "From" field IP addr in payload */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_FROM, &pos, 0)
					== TRUE) {
				pSipMsg += pos;	/* Moving to "From" */
				/* advance to IP/Port string */
				pTmpSipMsg = pSipMsg;
/* move pTmpSipMsg to str ">" which is end of add:port string */
				natSipAlgMsgFieldPos(pTmpSipMsg, SIP_ALG_GREAT,
								 &pos, 0);
				pTmpSipMsg += pos;
				diffLen = pTmpSipMsg - pSipMsg;
/* find "@" from "From" string to ">" string which is start of "addr:port" */
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
/* now its pointing to start of From field "address:port" */
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf
						("sip_alg_process; No valid From field\n");
				return NULL;
			}
			/* Modify "From" field "addr:port" in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);

			*diffModSipLen += diffLen;
/* increase the overall diff between old & mod sip msg */

			/* Advance to Call id field */
			if (natSipAlgMsgFieldPos
					(pSipMsg, SIP_ALG_CALLID, &pos, 0) == TRUE) {
				pSipMsg += pos;
/* moving it to start of string "Call-ID" */
				pTmpSipMsg = pSipMsg;
				/* move tmpSipMsg to next field */
				natSipAlgMsgFieldPosFindCrlf(pTmpSipMsg,
									 SIP_ALG_CRLF, &pos,
									 0);
				pTmpSipMsg += pos;
				diffLen = pTmpSipMsg - pSipMsg;
		/* Move pSipMsg to start of Call id "IP addr" string */
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf("sip_alg_process; "
					"No valid Call Id field\n");
				return NULL;
			}
			/* Modify "Call-id" field "addr:port" in payload */
	/* L4 port input is made as 0 as its only addr string modification */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp, 0,
								 ADDRESS_PORT_STRING);

			*diffModSipLen += diffLen;

			/* Advance to "Contact" field */
			if (natSipAlgMsgFieldPos
					(pSipMsg, SIP_ALG_CONTACT, &pos, 0) == TRUE) {
				pSipMsg += pos;
				/* move tmpMsg to semicolon */
				pTmpSipMsg = pSipMsg;
				natSipAlgMsgFieldPosFindCrlf(pTmpSipMsg,
					SIP_ALG_CRLF, &pos, 0);
				pTmpSipMsg += pos;
				/* move sipMsg to addr:port string */
				int flag = 0;
				if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT,
						&pos, 0) == FALSE)
					flag = 1;

				if (flag)
					goto SipMsgAdvance2;
				pSipMsg += pos + 1;
				addrPortLen = pTmpSipMsg - pSipMsg;

			} else {
				printf("sip_alg_process; "
					"No valid Call Id field\n");
				return NULL;
			}
			/* Modify "Contact" field "addr:port" in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);

			*diffModSipLen += diffLen;
		} else if (pkt_direction == PUBLIC
				 && msgType == SIP_ALG_BYE_MSGTYPE) {
			/*
			 * Modify Bye URL (if its BYE), To field,
			 * Call-Id if call triggered from private, then modify
			 */

			/* need to modify address:Port in Bye message string. */
			natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos, 0);
			pSipMsg += pos + 1;
			pTmpSipMsg = pSipMsg;
			natSipAlgMsgFieldPosFindSpace(pTmpSipMsg, SIP_ALG_SPACE,
									&pos, 0);
			pTmpSipMsg += pos;
			addrPortLen = pTmpSipMsg - pSipMsg;
			/* modify the "addr:port" in Bye message line */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);
			*diffModSipLen += diffLen;
/* increase the overall diff between old & mod sip msg */

			/* Advance to 'To" field */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_TO, &pos, 0)
					== TRUE) {
				pSipMsg += pos;
				pTmpSipMsg = pSipMsg;
				natSipAlgMsgFieldPos(pTmpSipMsg, SIP_ALG_GREAT,
								 &pos, 0);
				pTmpSipMsg += pos;
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
				addrPortLen = pTmpSipMsg - pSipMsg;
				pSipMsg =
						natSipAlgModifyPayloadAddrPort(pSipMsg,
									 &pSipMsgEnd,
									 addrPortLen,
									 &diffLen,
									 modIp,
									 modL4Port,
								 ADDRESS_PORT_STRING);
				*diffModSipLen += diffLen;
/* increase the overall diff between old & mod sip msg */
			}

			/* check for Call-Id. */
			if (natSipAlgMsgFieldPos
					(pSipMsg, SIP_ALG_CALLID, &pos, 0) == TRUE) {
				pSipMsg += pos;
/* moving it to start of string "Call-ID" */
				pTmpSipMsg = pSipMsg;
				/* move tmpSipMsg to next field */
				natSipAlgMsgFieldPosFindCrlf(pTmpSipMsg,
									 SIP_ALG_CRLF, &pos,
									 0);
				pTmpSipMsg += pos;
				//diffLen = pTmpSipMsg - pSipMsg;
		/* Move pSipMsg to start of Call id "IP addr" string */
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf("sip_alg_process; "
					"No valid Call Id field\n");
				return NULL;
			}
			/* Modify "Call-id" field "addr" in payload */
	/* L4 port input is made as 0 as its only addr string modification */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp, 0,
								 ADDRESS_PORT_STRING);

			*diffModSipLen += diffLen;
		} else if (pkt_direction == PRIVATE
				 && (msgType == SIP_ALG_200_OK_BYE_MSGTYPE)) {
			/*
			 *  Need to modify To field, Call-Id,
			 * Contact if call triggered from private, then modify
			 */
		/* Get to To field IP address to modify */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_TO, &pos, 0)
					== TRUE) {
				pSipMsg += pos;	/* Moving to "From" */
				/* advance to IP/Port string */
				pTmpSipMsg = pSipMsg;
/* move pTmpSipMsg to str ">" which is end of add:port string */
				natSipAlgMsgFieldPos(pTmpSipMsg, SIP_ALG_GREAT,
								 &pos, 0);
				pTmpSipMsg += pos;
				diffLen = pTmpSipMsg - pSipMsg;
/* find "@" from "From" string to ">" string which is start of "addr:port" */
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
/* now its pointing to start of From field "address:port" */
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf
						("sip_alg_process; no valid from field\n");
				return NULL;
			}
			/* Modify "From" field "addr:port" in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);

			*diffModSipLen = diffLen;
/* increase the overall diff between old & mod sip msg */

			/* Advance to "Contact" field */
			if (natSipAlgMsgFieldPos
					(pSipMsg, SIP_ALG_CONTACT, &pos, 0) == TRUE) {
				pSipMsg += pos;
				/* move tmpMsg to CRLF */
				pTmpSipMsg = pSipMsg;
				natSipAlgMsgFieldPosFindCrlf(pTmpSipMsg,
									 SIP_ALG_CRLF, &pos,
									 0);
				pTmpSipMsg += pos;
				/* move sipMsg to addr:port string */
				int flag = 0;
				if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT,
					&pos, 0) == FALSE)
					flag = 1;

				if (flag)
					goto SipMsgAdvance2;
				pSipMsg += pos + 1;
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf("sip_alg_process; "
					"No valid Call Id field\n");
				return NULL;
			}
			/* Modify "Contact" field "addr:port" in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);

			*diffModSipLen += diffLen;
		} else if (pkt_direction == PUBLIC
				 && (msgType == SIP_ALG_200_OK_BYE_MSGTYPE)) {
			/* change via and from field, call-id field */

			/* Get to Via field IP address to modify */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_VIA, &pos, 0)
					== TRUE) {
				/* advance to IP/Port string */
				pSipMsg +=
						(pos + strlen(SIP_ALG_VIA) +
						 SIP_ALG_VIA_FIELD_IPADDR);
				pTmpSipMsg = pSipMsg;
				/* move pTmp to next field */
				natSipAlgMsgFieldPos(pTmpSipMsg,
								 SIP_ALG_SEMICOLON, &pos,
								 0);
				pTmpSipMsg += pos;
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf("sip_alg_process; No valid VIA field\n");
				return NULL;
			}
			/* Modify VIA field IP addr in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp, 0,
								 ADDRESS_PORT_STRING);
			*diffModSipLen = diffLen;

			/* Advance to "From" field IP addr in payload */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_FROM, &pos, 0)
					== TRUE) {
				pSipMsg += pos;	/* Moving to "From" */
				/* advance to IP/Port string */
				pTmpSipMsg = pSipMsg;
/* move pTmpSipMsg to str ">" which is end of add:port string */
				natSipAlgMsgFieldPos(pTmpSipMsg, SIP_ALG_GREAT,
								 &pos, 0);
				pTmpSipMsg += pos;
				diffLen = pTmpSipMsg - pSipMsg;
/* find "@" from "From" string to ">" string which is start of "addr:port" */
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
/* now its pointing to start of From field "address:port" */
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf
						("sip_alg_process; No valid From field\n");
				return NULL;
			}
			/* Modify "From" field "addr:port" in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);

			*diffModSipLen += diffLen;

			/* check for Call-Id. */
			if (natSipAlgMsgFieldPos
					(pSipMsg, SIP_ALG_CALLID, &pos, 0) == TRUE) {
				pSipMsg += pos;
				/* Call id 'addr" need to modified. */
				pTmpSipMsg = pSipMsg;
				natSipAlgMsgFieldPosFindCrlf(pTmpSipMsg,
									 SIP_ALG_CRLF, &pos,
									 0);
				pTmpSipMsg += pos;
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
				addrPortLen = pTmpSipMsg - pSipMsg;
				/* modify call id "addr" */
				pSipMsg =
						natSipAlgModifyPayloadAddrPort(pSipMsg,
									 &pSipMsgEnd,
									 addrPortLen,
									 &diffLen,
									 modIp, 0,
								 ADDRESS_PORT_STRING);

				*diffModSipLen += diffLen;
/* increase the overall diff between old & mod sip msg */
			} else {
				printf("sip_alg_process; "
					"no valid Call-id field\n");
				return NULL;
			}
/* increase the overall diff between old & mod sip msg */
		}
	} else if (call_direction == SIP_CALL_INCOMING) {
		if ((msgType == SIP_ALG_INVITE_MSGTYPE)
				|| (msgType == SIP_ALG_ACK_MSGTYPE)) {
			/* need to modify Invite RL, TO field */
			/* move to Invite RL IP address string */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos, 0)
					== TRUE) {
				pSipMsg += pos + 1;
				pTmpSipMsg = pSipMsg;
				natSipAlgMsgFieldPos(pTmpSipMsg, SIP_ALG_SIP,
								 &pos, 0);
				pTmpSipMsg += (pos - 1);
/* pointing to space before SIP/2.0 */
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf
						("sip_alg_process: %d Invalid Invite RL\n",
						 __LINE__);
				return NULL;
			}
			/* modify Invite RL URI in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);
			*diffModSipLen += diffLen;
/* increase the overall diff between old & mod sip msg */

			/* Advance to 'To" field */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_TO, &pos, 0)
					== TRUE) {
				pSipMsg += pos;
				pTmpSipMsg = pSipMsg;
				natSipAlgMsgFieldPos(pTmpSipMsg, SIP_ALG_GREAT,
								 &pos, 0);
				pTmpSipMsg += pos;
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf("sip_alg_processing; "
					"%d Invalid To field\n",
						 __LINE__);
				return NULL;
			}
			/* Modify TO field IP addr:port in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);
			*diffModSipLen += diffLen;
/* increase the overall diff between old & mod sip msg */
		} else if ((msgType == SIP_ALG_TRYING_RINGING_MSGTYPE)
				 || (msgType == SIP_ALG_200_OK_INVITE_MSGTYPE)) {
			/* Need to modify TO field */
			/* Advance to 'To" field */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_TO, &pos, 0)
					== TRUE) {
				pSipMsg += pos;
				pTmpSipMsg = pSipMsg;
				natSipAlgMsgFieldPos(pTmpSipMsg, SIP_ALG_GREAT,
								 &pos, 0);
				pTmpSipMsg += pos;
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
				addrPortLen = pTmpSipMsg - pSipMsg;
				pSipMsg =
						natSipAlgModifyPayloadAddrPort(pSipMsg,
								 &pSipMsgEnd,
								 addrPortLen,
								 &diffLen,
								 modIp,
								 modL4Port,
							 ADDRESS_PORT_STRING);
				*diffModSipLen += diffLen;
/* increase the overall diff between old & mod sip msg */
			}
			if (msgType == SIP_ALG_200_OK_INVITE_MSGTYPE) {
/* need to modify Contact, Remote-Party Id, SDP O=IN, C=IN, Audio Port */
				/* Advance to "Contact" field */

				if (natSipAlgMsgFieldPos
						(pSipMsg, SIP_ALG_CONTACT, &pos,
						 0) == TRUE) {
					pSipMsg += pos;
					/* move tmpMsg to CRLF */
					pTmpSipMsg = pSipMsg;
					natSipAlgMsgFieldPos(pTmpSipMsg,
									 SIP_ALG_SEMICOLON,
									 &pos, 0);
					pTmpSipMsg += pos;
					/* move sipMsg to addr:port string */
					int flag = 0;
					if (natSipAlgMsgFieldPos(pSipMsg,
									 SIP_ALG_AT, &pos,
									 30) == FALSE)
						flag = 1;

					if (flag)
						goto SipMsgAdvance;

					pSipMsg += pos + 1;
					addrPortLen = pTmpSipMsg - pSipMsg;
				} else {
					printf("sip_alg_process; "
					"No valid Call Id field\n");
					return NULL;
				}
			/* Modify "Contact" field "addr:port" in payload */
				pSipMsg =
						natSipAlgModifyPayloadAddrPort(pSipMsg,
								 &pSipMsgEnd,
								 addrPortLen,
								 &diffLen,
								 modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);

				*diffModSipLen += diffLen;
SipMsgAdvance:
				/* advance to Remote-Party Id */
				pTmpSipMsg = pSipMsg;
				if (natSipAlgMsgFieldPos
						(pSipMsg, SIP_ALG_REMOTE_PARTY_ID, &pos,
						 0) == TRUE) {
					pSipMsg += pos +
							strlen(SIP_ALG_REMOTE_PARTY_ID);
					pTmpSipMsg = pSipMsg;
					natSipAlgMsgFieldPos(pTmpSipMsg,
									 SIP_ALG_GREAT,
									 &pos, 0);
					pTmpSipMsg += pos;
					natSipAlgMsgFieldPos(pSipMsg,
									 SIP_ALG_AT, &pos,
									 0);
					pSipMsg += pos + 1;
					addrPortLen = pTmpSipMsg - pSipMsg;
					/* modify the field */
					pSipMsg =
							natSipAlgModifyPayloadAddrPort
							(pSipMsg, &pSipMsgEnd, addrPortLen,
							 &diffLen, modIp, modL4Port,
							 ADDRESS_PORT_STRING);
					diffModSipLen += diffLen;
				} else {
					printf("sip_alg_process: "
					"Remote-party-id is not in the msg\n");
					pSipMsg = pTmpSipMsg;
				}

				/* Advance to SDP data message Owner address */
				if (natSipAlgMsgFieldPos
						(pSipMsg, SIP_ALG_OWNER, &pos,
						 0) == TRUE) {
					pSipMsg += pos;
				/* at start of owner string "o=" */
					pTmpSipMsg = pSipMsg;
					/* move tmmsg to CRLF of owner field */
					natSipAlgMsgFieldPosFindCrlf(pSipMsg,
									 SIP_ALG_CRLF,
									 &pos,
									 0);
					pTmpSipMsg += pos;
					/* start of CRLF "/r/n" */
/* move pSipMsg to IP address string in owner field */
					natSipAlgMsgFieldPos(pSipMsg,
									 SIP_ALG_IPV4, &pos,
									 0);
					pSipMsg += (pos + strlen(SIP_ALG_IPV4));
					SKIP_SPACES(pSipMsg);
/* after skipping spaces, pSip at start of addr */
					addrPortLen = pTmpSipMsg - pSipMsg;
				} else {
					printf("sip_alg_processing: "
						"Invalid Owner field\n");
					return NULL;
				}
/* Modify "Owner" field "addr" in payload.  Input L4 port as 0 */
				pSipMsg =
						natSipAlgModifyPayloadAddrPort(pSipMsg,
							 &pSipMsgEnd,
							 addrPortLen,
							 &diffLen,
							 modIp, 0,
							 ADDRESS_PORT_STRING);

				*diffModSipLen += diffLen;
				sdpMsgLen += diffLen;
		/* update the sdpMsgLen after modification */

		/* Advance to Connection information to modify IP address */
				if (natSipAlgMsgFieldPos
						(pSipMsg, SIP_ALG_CONN, &pos,
						 0) == TRUE) {
					pSipMsg += pos;
					pTmpSipMsg = pSipMsg;
					/* move tmmsg to CRLF of owner field */
					natSipAlgMsgFieldPosFindCrlf(pSipMsg,
									SIP_ALG_CRLF,
									&pos,
									 0);
					pTmpSipMsg += pos;
			/* start of CRLF "/r/n" */
			/* move pSipMsg to IP address string in owner field */
					natSipAlgMsgFieldPos(pSipMsg,
									 SIP_ALG_IPV4, &pos,
									 0);
					pSipMsg += (pos + strlen(SIP_ALG_IPV4));
					SKIP_SPACES(pSipMsg);
/* after skipping spaces, pSip at start of addr */
					addrPortLen = pTmpSipMsg - pSipMsg;
				} else {
					printf("sip_alg_processing: "
						"Invalid Connection field\n");
					return NULL;
				}
/* Modify "Connection" field "addr" in payload.  Input L4 port as 0 */
				pSipMsg =
						natSipAlgModifyPayloadAddrPort(pSipMsg,
									 &pSipMsgEnd,
									 addrPortLen,
									 &diffLen,
									 modIp, 0,
								 ADDRESS_PORT_STRING);

				*diffModSipLen += diffLen;
				sdpMsgLen += diffLen;
/* update the sdpMsgLen after modification */

				/* Advance to RTP audio port */
				if (natSipAlgMsgFieldPos
						(pSipMsg, SIP_ALG_AUDIO, &pos,
						 0) == TRUE) {
					pSipMsg +=
							(pos + strlen(SIP_ALG_AUDIO));
					SKIP_SPACES(pSipMsg);
					pTmpSipMsg = pSipMsg;
					natSipAlgMsgFieldPosFindSpace
							(pTmpSipMsg, SIP_ALG_SPACE, &pos,
							 0);
					pTmpSipMsg += pos;
					addrPortLen = pTmpSipMsg - pSipMsg;
				}

/* Modify "RTP Audio" port in payload. pass pub_ip as 0. */
				pSipMsg =
						natSipAlgModifyPayloadAddrPort(pSipMsg,
									 &pSipMsgEnd,
									 addrPortLen,
									 &diffLen, 0,
									 modRtpPort,
									 PORT_STRING);

				*diffModSipLen += diffLen;
				sdpMsgLen += diffLen;
/* update the sdpMsgLen after modification */
			}
		} else if (pkt_direction == PUBLIC
				 && msgType == SIP_ALG_BYE_MSGTYPE) {
			/* Modify Bye URL (if its BYE), To field */

			/* need to modify address:Port in Bye message string. */
			natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos, 0);
			pSipMsg += pos + 1;
			pTmpSipMsg = pSipMsg;
			natSipAlgMsgFieldPosFindSpace(pTmpSipMsg, SIP_ALG_SPACE,
									&pos, 0);
			pTmpSipMsg += pos;
			addrPortLen = pTmpSipMsg - pSipMsg;
			/* modify the "addr:port" in Bye message line */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);
			*diffModSipLen += diffLen;
/* increase the overall diff between old & mod sip msg */

			/* Advance to 'To" field */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_TO, &pos, 0)
					== TRUE) {
				pSipMsg += pos;
				pTmpSipMsg = pSipMsg;
				natSipAlgMsgFieldPos(pTmpSipMsg, SIP_ALG_GREAT,
								 &pos, 0);
				pTmpSipMsg += pos;
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
				addrPortLen = pTmpSipMsg - pSipMsg;
				pSipMsg =
						natSipAlgModifyPayloadAddrPort(pSipMsg,
								 &pSipMsgEnd,
								 addrPortLen,
								 &diffLen,
								 modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);
				*diffModSipLen += diffLen;
/* increase the overall diff between old & mod sip msg */
			} else {
				printf
						("sip_alg_processing: Invalid TO field\n");
				return NULL;
			}
		} else if (pkt_direction == PRIVATE
				 && msgType == SIP_ALG_BYE_MSGTYPE) {
			/* change via and from field */

			/* Get to Via field IP address to modify */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_VIA, &pos, 0)
					== TRUE) {
				/* advance to IP/Port string */
				pSipMsg +=
						(pos + strlen(SIP_ALG_VIA) +
						 SIP_ALG_VIA_FIELD_IPADDR);
				pTmpSipMsg = pSipMsg;
				/* move pTmp to next field */
				natSipAlgMsgFieldPos(pTmpSipMsg,
								 SIP_ALG_SEMICOLON, &pos,
								 0);
				pTmpSipMsg += pos;
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf("sip_alg_process; No valid VIA field\n");
				return NULL;
			}
			/* Modify VIA field IP addr in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp, 0,
								 ADDRESS_PORT_STRING);
			*diffModSipLen = diffLen;

			/* Advance to "From" field IP addr in payload */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_FROM, &pos, 0)
					== TRUE) {
				pSipMsg += pos;	/* Moving to "From" */
				/* advance to IP/Port string */
				pTmpSipMsg = pSipMsg;
/* move pTmpSipMsg to str ">" which is end of add:port string */
				natSipAlgMsgFieldPos(pTmpSipMsg, SIP_ALG_GREAT,
								 &pos, 0);
				pTmpSipMsg += pos;
				diffLen = pTmpSipMsg - pSipMsg;
/* find "@" from "From" string to ">" string which is start of "addr:port" */
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
/* now its pointing to start of From field "address:port" */
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf
						("sip_alg_process; No valid From field\n");
				return NULL;
			}
			/* Modify "From" field "addr:port" in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);

			*diffModSipLen += diffLen;
/* increase the overall diff between old & mod sip msg */
		} else if (pkt_direction == PRIVATE
				 && msgType == SIP_ALG_200_OK_BYE_MSGTYPE) {
			/* change via and from field */

			/* Get to Via field IP address to modify */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_VIA, &pos, 0)
					== TRUE) {
				/* advance to IP/Port string */
				pSipMsg +=
						(pos + strlen(SIP_ALG_VIA) +
						 SIP_ALG_VIA_FIELD_IPADDR);
				pTmpSipMsg = pSipMsg;
				/* move pTmp to next field */
				natSipAlgMsgFieldPos(pTmpSipMsg,
								 SIP_ALG_SEMICOLON, &pos,
								 0);
				pTmpSipMsg += pos;
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf("sip_alg_process; No valid VIA field\n");
				return NULL;
			}
			/* Modify VIA field IP addr in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp, 0,
								 ADDRESS_PORT_STRING);
			*diffModSipLen = diffLen;

			/* Advance to "From" field IP addr in payload */
			if (natSipAlgMsgFieldPos(pSipMsg,
				SIP_ALG_FROM, &pos, 0) == TRUE) {
				pSipMsg += pos;	/* Moving to "From" */
				/* advance to IP/Port string */
				pTmpSipMsg = pSipMsg;
/* move pTmpSipMsg to str ">" which is end of add:port string */
				natSipAlgMsgFieldPos(pTmpSipMsg, SIP_ALG_GREAT,
								 &pos, 0);
				pTmpSipMsg += pos;
				diffLen = pTmpSipMsg - pSipMsg;
/* find "@" from "From" string to ">" string which is start of "addr:port" */
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
/* now its pointing to start of From field "address:port" */
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf
						("sip_alg_process; No valid From field\n");
				return NULL;
			}
			/* Modify "From" field "addr:port" in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);

			*diffModSipLen += diffLen;
/* increase the overall diff between old & mod sip msg */
		} else if (pkt_direction == PUBLIC
				 && msgType == SIP_ALG_200_OK_BYE_MSGTYPE) {
			/* Get to To field IP address to modify */
			if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_TO, &pos, 0)
					== TRUE) {
				pSipMsg += pos;	/* Moving to "From" */
				/* advance to IP/Port string */
				pTmpSipMsg = pSipMsg;
/* move pTmpSipMsg to str ">" which is end of add:port string */
				natSipAlgMsgFieldPos(pTmpSipMsg, SIP_ALG_GREAT,
								 &pos, 0);
				pTmpSipMsg += pos;
				diffLen = pTmpSipMsg - pSipMsg;
/* find "@" from "From" string to ">" string which is start of "addr:port" */
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
/* now its pointing to start of From field "address:port" */
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf
						("sip_alg_process; no valid from field\n");
				return NULL;
			}
			/* Modify "From" field "addr:port" in payload */
			pSipMsg = natSipAlgModifyPayloadAddrPort(pSipMsg,
							 &pSipMsgEnd,
							 addrPortLen,
							 &diffLen, modIp,
							 modL4Port,
							 ADDRESS_PORT_STRING);

			*diffModSipLen = diffLen;
/* increase the overall diff between old & mod sip msg */

			/* Advance to "Contact" field */
			if (natSipAlgMsgFieldPos
					(pSipMsg, SIP_ALG_CONTACT, &pos, 0) == TRUE) {
				pSipMsg += pos;
				/* move tmpMsg to CRLF */
				pTmpSipMsg = pSipMsg;
				natSipAlgMsgFieldPosFindCrlf(pTmpSipMsg,
								 SIP_ALG_CRLF, &pos,
									 0);
				pTmpSipMsg += pos;
				/* move sipMsg to addr:port string */
				natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AT, &pos,
								 0);
				pSipMsg += pos + 1;
				addrPortLen = pTmpSipMsg - pSipMsg;
			} else {
				printf("sip_alg_process; "
					"No valid Call Id field\n");
				return NULL;
			}
			/* Modify "Contact" field "addr:port" in payload */
			pSipMsg =
					natSipAlgModifyPayloadAddrPort(pSipMsg, &pSipMsgEnd,
								 addrPortLen,
								 &diffLen, modIp,
								 modL4Port,
								 ADDRESS_PORT_STRING);

			*diffModSipLen += diffLen;
		}
	}

SipMsgAdvance2:
/* need to remove the SIP ALG entry if msg is 200 OK BYE response */
	if (call_direction == SIP_CALL_OUTGOING) {
		/* call remove sip alg entry here */
		if (pkt_direction == PRIVATE) {
			if (msgType == SIP_ALG_200_OK_BYE_MSGTYPE) {
				if (remove_sip_alg_entry
						(rte_bswap32(ip_h->src_addr),
						 rte_bswap16(udp_h->src_port)) < 0)
					printf("removesipalgentry failed: "
						"ipaddr %d, portid %d\n",
							 ip_h->src_addr, udp_h->src_port);
			}
		}
	} else {
		if (pkt_direction == PUBLIC) {
			if (msgType == SIP_ALG_200_OK_BYE_MSGTYPE) {
				if (remove_sip_alg_entry(pubIp, pubL4Port) < 0)
					printf("removesipalgentry failed: "
						" ipaddr %d, portid %d\n",
							 pubIp, pubL4Port);
			}
		}
	}

/* adjust SDP msg len (sdpMsgLen) in the content length field of SIP msg */
	if ((sdpMsgLen > 0) && (sdpDataLen > 0)) {
		pSipMsg = pStartSipMsg;
		char *tmpSdpLen = NULL;

		sdpMsgLen += sdpDataLen;
		tmpSdpLen = itoa(sdpMsgLen);
		int tmpStrLen;
		if (tmpSdpLen)
			tmpStrLen = strlen(tmpSdpLen);
		else
			tmpStrLen = 0;

	/* move to Content length field & change the length to sipMsgLen */
		if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_CONTENT_LEN, &pos, 0)
				== TRUE) {
			pSipMsg += (pos + TAG_TO_DATAPOS(SIP_ALG_CONTENT_LEN));
			SKIP_SPACES(pSipMsg);
			pTmpSipMsg = pSipMsg;
			natSipAlgMsgFieldPosFindCrlf(pTmpSipMsg,
								 SIP_ALG_DOUBLE_CRLF, &pos,
								 0);
			pTmpSipMsg += pos;
			SKIP_SPACES(pSipMsg);
			diffLen = pTmpSipMsg - pSipMsg;
			natSipAlgAdjustMsg(pSipMsg, &pSipMsgEnd, tmpStrLen,
						 diffLen);
			strncpy(pSipMsg, tmpSdpLen, tmpStrLen);
		} else {
			printf("sip_alg_process: Invalid Content Length\n");
			return NULL;
		}
	}

 sipAlgProcessExit:
	/* need to return toe start of the SIP msg */
	return pStartSipMsg;
}

/*
 * Function to Fetch RTP & RTCP port & return. Invoked by CGNAT
 * while adding NAPT entry for RTP & RTCP
 */
int natSipAlgGetAudioPorts(struct rte_mbuf *pkt, uint16_t *rtpPort,
				 uint16_t *rtcpPort)
{
	struct ipv4_hdr *ip_h;
	struct ether_hdr *eth_h = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	struct udp_hdr *udp_h;
	char *pSipMsg, *pEndPtr;
	int pos, sdpMsgLen;

	ip_h = (struct ipv4_hdr *)((char *)eth_h + sizeof(struct ether_hdr));
	udp_h = (struct udp_hdr *)((char *)ip_h + sizeof(struct ipv4_hdr));
	pSipMsg = ((char *)udp_h + sizeof(struct udp_hdr));

	/* Advance to check content type & get content length (SDP length) */
	if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_CONTYPE, &pos, 0) == FALSE)
		return -1;

	pSipMsg += (pos + TAG_TO_DATAPOS(SIP_ALG_CONTYPE));
	SKIP_SPACES(pSipMsg);

	/*check the application/sdp type, if not, exit */
	if (!IS_STRING_SAME(pSipMsg, SIP_ALG_APPSDP)) {
		printf("sip_alg_getAudioPort Invalid Content type\n");
		return -1;
	}

	/* get the SDP content length */
	natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_CONTENT_LEN, &pos, 0);
	pSipMsg += (pos + TAG_TO_DATAPOS(SIP_ALG_CONTENT_LEN));
	SKIP_SPACES(pSipMsg);
	sdpMsgLen = strtol(pSipMsg, &pEndPtr, 10);
	if (!sdpMsgLen) {
		printf("sipAlggetAudioport - sdpMsgLen is 0\n");
		return -1;
	}

	/* advance to RTP audio port */
	if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_AUDIO, &pos, 0) ==
			TRUE) {
		pSipMsg += (pos + TAG_TO_DATAPOS(SIP_ALG_AUDIO));
		SKIP_SPACES(pSipMsg);
		*rtpPort = strtol(pSipMsg, &pEndPtr, 10);
	} else
		*rtpPort = 0;

	/* advance to RTCP audio control port */
	if (natSipAlgMsgFieldPos(pSipMsg, SIP_ALG_RTCP, &pos, 0) ==
			TRUE) {
		pSipMsg += (pos + TAG_TO_DATAPOS(SIP_ALG_RTCP));
		SKIP_SPACES(pSipMsg);
		*rtcpPort = strtol(pSipMsg, &pEndPtr, 10);
	} else
		*rtcpPort = 0;

	if (ALG_DEBUG)
		printf(" sipAlgGetAudioPort; rtpPort %d, rtcpPort %d\n",
					 *rtpPort, *rtcpPort);
	return 0;
}

/* function to find SPACES in ALG message */
int
natSipAlgMsgFieldPosFindSpace(char *pData, const char *pIdStr, int *pPos,
						int searchLen)
{
	char *pStart = pData;
	int i = 0;

	if (!pIdStr)
		return FALSE;

	if (!searchLen)
		searchLen = 1500;	/* max default search length */

	while (TRUE) {
		while (*pData != ' ') {
			pData++;
			i++;
		}

		if (i > searchLen) {
			printf("SIP ALG Find Field Pos: "
				"Single message exceeds max len: %d\n",
				searchLen);
			*pPos = searchLen;	/* reaches the end */
			return FALSE;
		}

		if (bcmp(pData, pIdStr, strlen(pIdStr)) == 0)
			break;
	}

	*pPos = pData - pStart;
	return TRUE;
}

/* function to find CRLF in ALG message */
int natSipAlgMsgFieldPosFindCrlf(
	char *pData,
	const char *pIdStr,
	int *pPos,
	int searchLen)
{
	char *pStart = pData;
	int i = 0;

	if (!pIdStr)
		return FALSE;

	if (!searchLen)
		searchLen = 1500;	/* max default search length */

	while (TRUE) {
		while (*pData != '\r' && *(pData + 1) != '\n') {
			pData++;
			i++;
		}
		if (i >= searchLen) {
			printf("SIP ALG Find Field Pos: "
				" Single message exceeds max len: %d\n",
					 searchLen);
			*pPos = searchLen;	/* reaches the end */
			return FALSE;
		}

		if (bcmp(pData, pIdStr, strlen(pIdStr)) == 0)
			break;
	}

	*pPos = pData - pStart;
	return TRUE;
}

/* function to find field position in ALG message */
int natSipAlgMsgFieldPos(char *pData,
	const char *pIdStr,
	int *pPos,
	int searchLen)
{
	char *pStart = pData;
	int i = 0, j = 0;

	if (!pIdStr)
		return FALSE;

	if (!searchLen)
		searchLen = 1500;	/* max default search length */

	while (TRUE) {
		while (*pData != '\r' && *(pData + 1) != '\n') {
			/* skip all space */

			while (*pData == ' ') {
				pData++;
				j++;
			}

			if (*pData == '\r' && *(pData + 1) == '\n')
				break;

			if (bcmp(pData, pIdStr, strlen(pIdStr)) == 0) {
				*pPos = pData - pStart;
				return TRUE;
			}

			pData++;
			j++;

			if (j >= searchLen) {
				*pPos = pData - pStart;
				return FALSE;
			}

		}

		/* advance to next line */

		for (i = 0; i < (searchLen - 1); i++) {
			if (pData[i] == '\r')
				if (pData[i + 1] == '\n')
					break;
		}

		if (i > searchLen) {
			printf("SIP ALG Find Field Pos: "
				"Single message exceeds max len: %d\n",
					 searchLen);
			*pPos = searchLen;	/* reaches the end */
			return FALSE;
		}

		pData += i + 2;
		searchLen -= (i + 2);

		if ((pData[0] == '\r' && pData[1] == '\n') ||
					(searchLen <= 0)) {
			/* reach the end mark \r\n\r\n */

			if (searchLen > 0) {
				pData += 2;
				continue;
			}

			*pPos = pData - pStart;

			return FALSE;
		}
	}

	*pPos = pData - pStart;
	return TRUE;
}

/* get SIP Call id string */
char *getSipCallIdStr(char *pMsg)
{
	char *pStart;
	char *pCallId = NULL;
	int i;

	pStart = pMsg;
	for (i = 0; i < 200; i++) {
		if (*pMsg != '\r')
			pMsg++;
		else
			break;
	}
	if (i >= 200) {
		printf("SIP_ALG: getCallid wrong string format\n");
		return NULL;
	}

	size_t size = RTE_CACHE_LINE_ROUNDUP(pMsg - pStart + 1);

	pCallId = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
	if (!pCallId)
		return NULL;

	bcopy(pStart, pCallId, pMsg - pStart);
	*(pCallId + (pMsg - pStart)) = 0;

	if (ALG_DEBUG)
		printf("%s: %s\n", __func__, pCallId);

	return pCallId;
}

char *natSipAlgModifyPayloadAddrPort(
	char *pSipMsg, char **pSipMsgEnd,
	uint32_t oldStrLen, uint32_t *diffLen,
	uint32_t modIp, uint16_t modPort, uint32_t type)
{
	char addrport[MAX_ADDR_PORT_SIZE];
	struct in_addr ipAddr;
	uint32_t newStrLen = 0;
	char *tmpPort = NULL;

	if (modPort != 0)
		tmpPort = itoa(modPort);

	*diffLen = 0;
	if (type == ADDRESS_PORT_STRING) {
		ipAddr.s_addr = htonl(modIp);
		char *tmpAddr = inet_ntoa(ipAddr);

		if (modPort != 0)	/* for addr:port combo modification */
			sprintf(addrport, "%s:%s", tmpAddr, tmpPort);
		else		/* if only address modification */
			sprintf(addrport, "%s", tmpAddr);

		newStrLen = strlen(addrport);

		if (abs(newStrLen - oldStrLen) > 0) {
		/*
		 * Call the function moving the SIP Msg pointer
		 * to modify the field
		 */
			natSipAlgAdjustMsg(pSipMsg, pSipMsgEnd,
							newStrLen, oldStrLen);
		}

		/* replace the old addr:port with new addr:port */
		strncpy(pSipMsg, addrport, strlen(addrport));
	} else if (type == PORT_STRING) {	/* only port modification */
		if(tmpPort)
		newStrLen = strlen(tmpPort);

		if (abs(newStrLen - oldStrLen) > 0) {
		/*
		 * Call the function moving the SIP msg pointer
		 * to modify the field
		 */
			natSipAlgAdjustMsg(pSipMsg, pSipMsgEnd,
							newStrLen, oldStrLen);
		}

		/* replace the old port with new port */
		if(tmpPort)
		strncpy(pSipMsg, tmpPort, strlen(tmpPort));
	}
	/* output difflen between old str len & modified new str length */
	if (newStrLen > oldStrLen)
		*diffLen = newStrLen - oldStrLen;

	if (tmpPort)
		free(tmpPort);

	return pSipMsg;		/* modified SIP Msg */
}

char *natSipAlgAdjustMsg(char *pSipMsg, char **pSipMsgEnd,
			 uint32_t newStrLen, uint32_t oldStrLen)
{
	char MsgBuffer[MAX_SIP_UDP_MSG_SIZE];

	if (newStrLen > oldStrLen) {
		pSipMsg += oldStrLen;
		int msgLen = *pSipMsgEnd - pSipMsg;

		strncpy(MsgBuffer, pSipMsg, msgLen);
		pSipMsg += (newStrLen - oldStrLen);
		strncpy(pSipMsg, MsgBuffer, msgLen);

		if (ALG_DEBUG)
			printf("natSipAlgAdjustMsg: %u\n", msgLen);

		/* moving output end of SIP MSG by difflen like pSipMsg */
		*pSipMsgEnd += (newStrLen - oldStrLen);
	} else {
		/* Setting space on the oldStr position */
		memset(pSipMsg, ' ', oldStrLen);
	}

	return pSipMsg;
}

/* end of file */
