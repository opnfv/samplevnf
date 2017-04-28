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

#include <rte_mbuf.h>
#include "cgnapt_pcp_be.h"
#include "pipeline_cgnapt_be.h"
#include "pipeline_cgnapt_common.h"

/**
 * @file
 * Pipeline CG-NAPT PCP BE Implementation.
 *
 * Implementation of Pipeline CG-NAPT PCP Back End (BE).
 * Handles PCP requests for both IPv4 & IPv6
 * Constructs PCP responses for both IPv4 & IPv6
 * Provides backend CLI support.
 * Runs on CGNAPT pipeline core
 *
 *
 */

#ifdef PCP_ENABLE

uint32_t pcp_lifetime = 60;
uint8_t pcp_ipv4_format[12] = {	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0xff, 0xff };
/**
 * Function to initialize PCP stuff
 *
 */
enum PCP_RET pcp_init(void)
{
    /* Init of PCP mempool */
	if (!pcp_pool_init) {
		pcp_pool_init = 1;
		pcp_mbuf_pool = rte_pktmbuf_pool_create(
				"pcp_mbuf_pool", 64, 32, 0,
				RTE_MBUF_DEFAULT_BUF_SIZE,
				app_get_socket_id());

		if (pcp_mbuf_pool == NULL) {
			printf("PCP mbuf pool creation failed\n");
			return PCP_INIT_UNSUCCESS;
		}
	}
	printf("In pcp_init: success\n");
	return PCP_INIT_SUCCESS;
}

/**
 * Function to handle PCP CLI commands
 *
 * @param p
 *	Pipieline struct associated with each pipeline
 * @param msg
 *	CLI message enqueued by master thread
 */

void *pipeline_cgnapt_msg_req_pcp_handler(
	__rte_unused struct pipeline *p,
	void *msg)
{

	struct pipeline_cgnapt_pcp_msg_rsp *rsp = msg;
	struct pipeline_cgnapt_pcp_msg_req *req = msg;

	req = msg;
	rsp->status = 0;
	if (req->cmd == CGNAPT_PCP_CMD_STATS) {
		printf("pcp_success_count:%d\n", pcp_success_count);
		printf("pcp_error_count:%d\n", pcp_error_count);
		printf("pcp_entry_count:%d\n", pcp_entry_count);

		return rsp;
	}
	if (req->cmd == CGNAPT_PCP_CMD_PCP_ENABLE) {
		if (req->lifetime) {
			pcp_enable = 1;
			printf("PCP option is enabled\n");
		} else{
			pcp_enable = 0;
			printf("PCP option is disabled\n");
		}
		return rsp;
	}
	if (req->cmd == CGNAPT_PCP_CMD_SET_LIFETIME) {
		pcp_lifetime = req->lifetime;
		printf("pcp_lifetime:%" PRIu32 "\n", pcp_lifetime);
		return rsp;
	}
	if (req->cmd == CGNAPT_PCP_CMD_GET_LIFETIME) {
		printf("pcp_lifetime:%" PRIu32 "\n", pcp_lifetime);
		return rsp;
	}

	printf("CG-NAPT PCP handler called with wrong args %x %x\n",
			 req->cmd, req->lifetime);
	printf("\n");
	return rsp;
}

void clone_data(
	struct rte_mbuf *rx_pkt,
	struct rte_mbuf *tx_pkt);

/**
 * Function to copy Rx pkt data to Tx pkt data
 *
 * @param rx_pkt
 *  Received PCP pkt
 * @param tx_pkt
 *  Transmitting PCP pkt
 */

void clone_data(
	struct rte_mbuf *rx_pkt,
	struct rte_mbuf *tx_pkt)
{
	char *buf1;
	char *buf2;

	buf1 = rte_pktmbuf_mtod(rx_pkt, char *);
	buf2 = rte_pktmbuf_append(tx_pkt, rx_pkt->data_len);

	rte_memcpy(buf2, buf1, rx_pkt->data_len);
}

/**
 * Function to construct L2,L3,L4 in pkt and to send out
 *
 * @param rx_pkt
 *	Received PCP pkt
 * @param tx_pkt
 *	Transmitting PCP pkt
 * @param ver
 *	Version of pkt : IPv4 or IPv6
 * @param p_nat
 *	A pointer to struct rte_pipeline
 */

void construct_pcp_resp(
	struct rte_mbuf *rx_pkt,
	struct rte_mbuf *tx_pkt,
	uint8_t ver, struct rte_pipeline *rte_p)
{
	struct ether_hdr *eth_tx, *eth_rx;
	struct ipv4_hdr *ipv4_tx, *ipv4_rx;
	struct ipv6_hdr *ipv6_tx, *ipv6_rx;
	struct udp_hdr *udp_tx, *udp_rx;
	struct pcp_resp_hdr *pcp_resp;
	struct pcp_req_hdr *pcp_req;

	tx_pkt->port = rx_pkt->port;

	if (ver == 4) {
		pcp_req = (struct pcp_req_hdr *)
				((uint8_t *) rx_pkt + IPV4_PCP_OFST);
		pcp_resp = (struct pcp_resp_hdr *)
				((uint8_t *) tx_pkt + IPV4_PCP_OFST);
	} else {
		pcp_req = (struct pcp_req_hdr *)
				((uint8_t *) rx_pkt + IPV6_PCP_OFST);
		pcp_resp = (struct pcp_resp_hdr *)
				((uint8_t *) tx_pkt + IPV6_PCP_OFST);
	}

	if (pcp_resp->result_code == PCP_SUCCESS) {
		memset(pcp_resp->reserve, 0, 12);
		pcp_success_count++;
	} else {
		memcpy(pcp_resp->reserve, &pcp_req->cli_ip[1], 12);
		pcp_error_count++;
	}

	pcp_resp->req_resp = PCP_RESP;
	pcp_resp->res_unuse = 0x00;
	/* Epoch time */
	pcp_resp->epoch_time = rte_bswap32(time(NULL));

	/* swap L2 identities */
	eth_rx = rte_pktmbuf_mtod(rx_pkt, struct ether_hdr *);
	eth_tx = rte_pktmbuf_mtod(tx_pkt, struct ether_hdr *);

	memcpy(&eth_tx->s_addr, &eth_rx->d_addr, sizeof(struct ether_addr));
	memcpy(&eth_tx->d_addr, &eth_rx->s_addr, sizeof(struct ether_addr));

	/* swap L3 identities */

	if (ver == 4) {
		ipv4_rx = (struct ipv4_hdr *)((uint8_t *) rx_pkt + IP_OFFSET);
		udp_rx = (struct udp_hdr *)((uint8_t *) rx_pkt + IPV4_UDP_OFST);

		ipv4_tx = (struct ipv4_hdr *)((uint8_t *) tx_pkt + IP_OFFSET);
		udp_tx = (struct udp_hdr *)((uint8_t *) tx_pkt + IPV4_UDP_OFST);

		ipv4_tx->src_addr = ipv4_rx->dst_addr;
		ipv4_tx->dst_addr = ipv4_rx->src_addr;

		/* swap L4 identities */

		udp_tx->src_port = udp_rx->dst_port;
		udp_tx->dst_port = udp_rx->src_port;
		udp_tx->dgram_cksum = 0;
		udp_tx->dgram_cksum =
			rte_ipv4_udptcp_cksum(ipv4_tx, (void *)udp_tx);

		ipv4_tx->total_length =
			rte_cpu_to_be_16(pcp_resp->result_code ==
					 PCP_MAP ? IPV4_PCP_MAP_PL_LEN :
					 IPV4_PCP_PEER_PL_LEN);

		ipv4_tx->packet_id = 0xaabb;
		ipv4_tx->fragment_offset = 0x0000;
		ipv4_tx->time_to_live = 64;
		ipv4_tx->next_proto_id = IP_PROTOCOL_UDP;
		ipv4_tx->hdr_checksum = 0;
		ipv4_tx->hdr_checksum = rte_ipv4_cksum(ipv4_tx);

	} else {
		ipv6_rx = (struct ipv6_hdr *)((uint8_t *) rx_pkt + IP_OFFSET);
		udp_rx = (struct udp_hdr *)((uint8_t *) rx_pkt + IPV6_UDP_OFST);

		ipv6_tx = (struct ipv6_hdr *)((uint8_t *) tx_pkt + IP_OFFSET);
		udp_tx = (struct udp_hdr *)((uint8_t *) tx_pkt + IPV6_UDP_OFST);

		memcpy((uint8_t *)&ipv6_tx->src_addr[0],
			(uint8_t *)&ipv6_rx->dst_addr[0], 16);
		memcpy((uint8_t *)&ipv6_tx->dst_addr[0],
			(uint8_t *)&ipv6_rx->src_addr[0], 16);

		/* swap L4 identities */

		udp_tx->src_port = udp_rx->dst_port;
		udp_tx->dst_port = udp_rx->src_port;

		udp_tx->dgram_cksum = 0;
		udp_tx->dgram_cksum =
			rte_ipv6_udptcp_cksum(ipv6_tx, (void *)udp_tx);
		ipv6_tx->payload_len =
			rte_cpu_to_be_16(pcp_resp->result_code ==
					 PCP_MAP ? IPV6_PCP_MAP_PL_LEN :
					 IPV6_PCP_PEER_PL_LEN);

		ipv6_tx->proto = IP_PROTOCOL_UDP;
		ipv6_tx->hop_limits = 64;
	}

	#ifdef PCP_DEBUG
	rte_hexdump(stdout, "Transferring PCP Pkt", tx_pkt, 400);
	#endif

	rte_pipeline_port_out_packet_insert(rte_p, tx_pkt->port, tx_pkt);
}

/**
 * Function to handle PCP requests
 *
 * @param rx_pkt
 *	Received PCP pkt
 * @param ver
 *	Version of pkt : IPv4 or IPv6
 * @param p_nat
 *	A pointer to struct pipeline_cgnapt
 */

void handle_pcp_req(struct rte_mbuf *rx_pkt,
					uint8_t ver,
					void *pipeline_cgnapt_ptr)
{
	struct ipv4_hdr *ipv4 = NULL;
	struct ipv6_hdr *ipv6 = NULL;
	struct udp_hdr *udp_rx = NULL;
	struct pcp_req_hdr *pcp_req = NULL;
	struct pcp_resp_hdr *pcp_resp = NULL;
	struct rte_mbuf *tx_pkt = NULL;
	struct pipeline_cgnapt *p_nat = pipeline_cgnapt_ptr;

	if (pcp_mbuf_pool == NULL)
		printf("handle PCP: PCP pool is NULL\n");
	tx_pkt = rte_pktmbuf_alloc(pcp_mbuf_pool);
	if (tx_pkt == NULL) {
		printf("unable to allocate mem from PCP pool\n");
		return;
	}
	/* clone the pkt */

	clone_data(rx_pkt, tx_pkt);

	#ifdef PCP_DEBUG
	rte_hexdump(stdout, "cloned PCP Pkt", tx_pkt, 400);
	#endif

	if (ver == 4) {
		pcp_req = (struct pcp_req_hdr *)
				((uint8_t *) rx_pkt + IPV4_PCP_OFST);
		pcp_resp = (struct pcp_resp_hdr *)
				((uint8_t *) tx_pkt + IPV4_PCP_OFST);
		udp_rx = (struct udp_hdr *)
				((uint8_t *) rx_pkt + IPV4_UDP_OFST);
	} else {
		pcp_req = (struct pcp_req_hdr *)
				((uint8_t *) rx_pkt + IPV6_PCP_OFST);
		pcp_resp = (struct pcp_resp_hdr *)
				((uint8_t *) tx_pkt + IPV6_PCP_OFST);
		udp_rx = (struct udp_hdr *)
				((uint8_t *) rx_pkt + IPV6_UDP_OFST);
	}

	/* Check for all conditions to drop the packet */

	/* Check the PCP version */

	if (pcp_req->ver != 2) {
		#ifdef PCP_DEBUG
		printf("PCP version mismatch\n");
		#endif
		pcp_resp->result_code = PCP_UNSUPP_VERSION;
		pcp_resp->life_time = rte_bswap32(PCP_LONG_LTIME);
		construct_pcp_resp(rx_pkt, tx_pkt, ver, p_nat->p.p);
		return;
	}

	/* If req msg is less than 2 octects */

	if (rte_bswap16(udp_rx->dgram_len) > 1100) {
		#ifdef PCP_DEBUG
		printf("PCP len > 1000\n");
		#endif
		pcp_resp->result_code = PCP_MALFORMED_REQUEST;
		pcp_resp->life_time = rte_bswap32(PCP_LONG_LTIME);
		construct_pcp_resp(rx_pkt, tx_pkt, ver, p_nat->p.p);
		return;
	}

	/* Silently drop the response pkt */
	if (pcp_req->req_resp == PCP_RESP) {
		#ifdef PCP_DEBUG
		printf("Its PCP Resp\n");
		#endif
		return;
	}

	/* Check for supported PCP opcode */

	if ((pcp_req->opcode != PCP_MAP) && (pcp_req->opcode != PCP_PEER)) {
		#ifdef PCP_DEBUG
		printf("Neither PCP_MAP not PCP_PEER\n");
		#endif
		pcp_resp->result_code = PCP_UNSUPP_OPCODE;
		printf("result code:%d\n", PCP_UNSUPP_OPCODE);
		pcp_resp->life_time = rte_bswap32(PCP_LONG_LTIME);
		construct_pcp_resp(rx_pkt, tx_pkt, ver, p_nat->p.p);
		return;
	}

	/* To check whether options are using in PCP */

	{
		uint8_t *option =
			(uint8_t *) ((uint8_t *) udp_rx + PCP_REQ_RESP_HDR_SZ +
				 PCP_MAP_REQ_RESP_SZ);
		if (*option) {
		#ifdef PCP_DEBUG
		printf("No PCP option support\n");
		#endif
			pcp_resp->result_code = PCP_UNSUPP_OPTION;
			pcp_resp->life_time = rte_bswap32(PCP_LONG_LTIME);
			construct_pcp_resp(rx_pkt, tx_pkt, ver, p_nat->p.p);
			return;
		}
	}

	if (ver == 4) {
		ipv4 = (struct ipv4_hdr *)((uint8_t *) rx_pkt + IP_OFFSET);
		/* Check whether 3rd party host is requesting */
		if (ipv4->src_addr != pcp_req->cli_ip[3]) {

			#ifdef PCP_DEBUG
			printf("PCP client IP & req IP mismatch\n");
			#endif

			printf("src addr:%x req addr:%x\n", ipv4->src_addr,
			pcp_req->cli_ip[3]);

			pcp_resp->result_code = PCP_ADDRESS_MISMATCH;
			pcp_resp->life_time = rte_bswap32(PCP_LONG_LTIME);
			construct_pcp_resp(rx_pkt, tx_pkt, ver, p_nat->p.p);
			return;
		}

	} else {
		ipv6 = (struct ipv6_hdr *)((uint8_t *) rx_pkt + IP_OFFSET);
		/*		5. Check whether 3rd party host is requesting */
		if (memcmp(ipv6->src_addr, pcp_req->cli_ip, IPV6_SZ) != 0) {
		#ifdef PCP_DEBUG
		printf("PCP client IP & req IP mismatch\n");
		#endif

			pcp_resp->result_code = PCP_ADDRESS_MISMATCH;
			pcp_resp->life_time = rte_bswap32(PCP_LONG_LTIME);
			construct_pcp_resp(rx_pkt, tx_pkt, ver, p_nat->p.p);
			return;
		}
	}

	struct pipeline_cgnapt_entry_key key;
	memset(&key, 0, sizeof(struct pipeline_cgnapt_entry_key));
	int pos = 0;

	switch (pcp_req->opcode) {

	case PCP_MAP:
		{
			struct pcp_map_req *map_req;
			struct pcp_map_resp *map_resp;

			/* Not a PCP MAP Request(36) */

			if ((rte_be_to_cpu_16(udp_rx->dgram_len) -
				 sizeof(struct pcp_req_hdr)) <= 35)
				return;

			if (ver == 4) {
				map_req = (struct pcp_map_req *)
						((uint8_t *) rx_pkt +
						IPV4_PCP_MAP_OFST);
				map_resp = (struct pcp_map_resp *)
						((uint8_t *) tx_pkt +
						IPV4_PCP_MAP_OFST);
			} else {
				map_req = (struct pcp_map_req *)
						((uint8_t *) rx_pkt +
						IPV6_PCP_MAP_OFST);
				map_resp = (struct pcp_map_resp *)
						((uint8_t *) tx_pkt +
						IPV6_PCP_MAP_OFST);
			}

			/* 4. Check for supported protocol */

			if (map_req->protocol != IP_PROTOCOL_TCP &&
				map_req->protocol != IP_PROTOCOL_UDP) {
				#ifdef PCP_DEBUG
				printf("PCP Req is neither TCP nor "
				"UDP protocol\n");
				#endif

				pcp_resp->result_code = PCP_UNSUPP_PROTOCOL;
				pcp_resp->life_time =
					rte_bswap32(PCP_LONG_LTIME);
				construct_pcp_resp(rx_pkt, tx_pkt,
					ver, p_nat->p.p);
				return;
			}

			/* Preparing key to search the entry */

			key.pid = rx_pkt->port;
			key.ip = rte_bswap32(pcp_req->cli_ip[3]);
			key.port = rte_bswap16(map_req->int_port);

			#ifdef NAT_ONLY_CONFIG_REQ
			if (nat_only_config_flag)
				key.port = 0xffff;
			#endif

			#ifdef PCP_DEBUG
			rte_hexdump(stdout, "key", &key,
				sizeof(struct pipeline_cgnapt_entry_key));
			#endif

			pos = rte_hash_lookup(napt_common_table, &key);

			/* PCP request for deleting the CGNAPT entry */
			if (rte_bswap32(pcp_req->life_time) == 0) {

				if (pos != -ENOENT) {

				long long int time_out;
				time_out =
					napt_hash_tbl_entries[pos].
					data.timeout;

				/* Check for PCP entry first */
				if (time_out > 0) {
					rte_hash_del_key
						(napt_common_table, &key);
					pcp_resp->life_time = 0;
					pcp_resp->result_code =
						PCP_SUCCESS;
					memset(pcp_resp->reserve, 0, 12);
				#ifdef PCP_DEBUG
				printf("PCP SUCCESS : PCP MAP req for "
				"deleting entry\n");
				#endif

				construct_pcp_resp(rx_pkt, tx_pkt,
					ver, p_nat->p.p);

				return;

				}

				if (time_out == STATIC_CGNAPT_TIMEOUT)
					pcp_resp->life_time = 0xffffffff;
				else if (time_out == DYNAMIC_CGNAPT_TIMEOUT)
					pcp_resp->life_time =
					rte_bswap32(PCP_LONG_LTIME);

				pcp_resp->result_code = PCP_NOT_AUTHORIZED;

				#ifdef PCP_DEBUG
				printf("PCP Failed : Not a PCP request "
				"created entry\n");
				#endif

				construct_pcp_resp(rx_pkt, tx_pkt,
					ver, p_nat->p.p);
				return;

				} else {
				pcp_resp->life_time = 0;
				pcp_resp->result_code = PCP_SUCCESS;
				memset(pcp_resp->reserve, 0, 12);

				#ifdef PCP_DEBUG
				printf("PCP SUCCESS : MAP req entry not "
				"found for deletion\n");
				#endif

				construct_pcp_resp(rx_pkt, tx_pkt,
					ver, p_nat->p.p);
				return;
				}
			}

			/* PCP request for adding the CGNAPT entry */
			struct cgnapt_table_entry *entry = NULL;

			if ((pos == -ENOENT)) {
				uint8_t err = 0;
				entry = add_dynamic_cgnapt_entry(&p_nat->p,
					&key,
					rte_bswap32(pcp_req->life_time) <=
						pcp_lifetime?
					rte_bswap32(pcp_req->life_time):
						pcp_lifetime,
					ver == 4 ?
					CGNAPT_ENTRY_IPV4 :
					CGNAPT_ENTRY_IPV6,
					ipv6->src_addr, &err);
				/* Ignore klocwork issue in above calling */

				/* MAP Err : unable to allocate
				* requested resources
				*/
				if (!entry) {

					#ifdef PCP_DEBUG
					printf("PCP Failure : unable to "
					"create PCP req entry\n");
					#endif

					pcp_resp->result_code =
						PCP_NO_RESOURCES;
					pcp_resp->life_time =
						rte_bswap32(PCP_SHORT_LTIME);
					construct_pcp_resp(rx_pkt, tx_pkt,
						ver, p_nat->p.p);
					return;
				}
				#ifdef PCP_DEBUG
				printf("PCP dynamic entry created "
				"successfully\n");
				#endif

				pcp_entry_count++;
			} else {
				/* Check whether PCP request created
				* entry or not
				*/
				if (napt_hash_tbl_entries[pos].data.
					timeout > 0) {

				napt_hash_tbl_entries[pos].
					data.timeout = pcp_lifetime;

				struct cgnapt_table_entry *p_entry, *s_entry;
				struct pipeline_cgnapt_entry_key s_key;

				p_entry = &napt_hash_tbl_entries[pos];
				entry = &napt_hash_tbl_entries[pos];
				s_key.port = napt_hash_tbl_entries[pos].
						data.pub_port;
				s_key.ip = napt_hash_tbl_entries[pos].
						data.pub_ip;
				s_key.pid = napt_hash_tbl_entries[pos].
						data.pub_phy_port;

				/* Getting ingress or second entry
				* from the table
				*/

				pos = rte_hash_lookup(napt_common_table,
								&s_key);
				s_entry = &napt_hash_tbl_entries[pos];

				/* Enqueue the info to
				* restart the timer
				*/
				timer_thread_enqueue(&key, &s_key,
						p_entry, s_entry,
						(struct pipeline *)p_nat);

			} else {
					// if dynamic
				if (!napt_hash_tbl_entries[pos].
						data.timeout)
					pcp_resp->life_time =
						rte_bswap32(PCP_LONG_LTIME);
				else	// if static entry
					pcp_resp->life_time =
						0xffffffff;

				pcp_resp->result_code =
					PCP_NOT_AUTHORIZED;

				#ifdef PCP_DEBUG
				printf("PCP Failure : Not authorized "
				"to delete entry\n");
				printf("Not a PCP request "
				"created entry\n");
				#endif
				construct_pcp_resp(rx_pkt, tx_pkt,
					ver, p_nat->p.p);
					return;
				}

			}

			/* Fill PCP Resp fields */
			pcp_resp->result_code = PCP_SUCCESS;

			rte_bswap32(pcp_req->life_time) < pcp_lifetime?
			(pcp_resp->life_time = pcp_req->life_time):
			(pcp_resp->life_time = rte_bswap32(pcp_lifetime));

			/* Fill PCP MAP Resp fields */
			memcpy(map_resp->nonce, map_req->nonce, 12);
			map_resp->protocol = map_req->protocol;
			map_resp->res_unuse1 = 0;
			map_resp->int_port = map_req->int_port;

			/* Ignore klockwork issue for below stmt */
			map_resp->ext_port =
				rte_be_to_cpu_16(entry->data.pub_port);
			memcpy(map_resp->ext_ip, pcp_ipv4_format, 12);
			map_resp->ext_ip[3] = rte_bswap32(entry->data.pub_ip);

			construct_pcp_resp(rx_pkt, tx_pkt, ver, p_nat->p.p);
			return;
		}
		break;

	case PCP_PEER:
		{

			/* Not a PCP PEER Request(56) */

			if ((rte_be_to_cpu_16(udp_rx->dgram_len) -
				 sizeof(struct pcp_req_hdr)) <= 55)
				return;

			struct cgnapt_table_entry *p_entry, *s_entry;
			struct pipeline_cgnapt_entry_key s_key;

			struct pcp_peer_req *peer_req;
			struct pcp_peer_resp *peer_resp;

			peer_req =
				(struct pcp_peer_req *)((uint8_t *) rx_pkt +
							IPV4_PCP_PEER_OFST);
			peer_resp =
				(struct pcp_peer_resp *)((uint8_t *) rx_pkt +
							 IPV4_PCP_PEER_OFST);

			/* PEER Err : Creation not supporting */
			if (pcp_req->life_time == 0) {
				pcp_resp->life_time = 0;
				pcp_resp->result_code = PCP_MALFORMED_REQUEST;

				#ifdef PCP_DEBUG
				printf("PCP Failure : PEER creation not "
				"supported\n");
				#endif

				construct_pcp_resp(rx_pkt, tx_pkt, ver,
					p_nat->p.p);
				return;
			}

			/* Preparing key to search the entry */
			key.pid = rx_pkt->port;
			/* For both IPv4 & IPv6, key is last 32 bits
			* due to NAT64
			*/
			key.ip = rte_bswap32(pcp_req->cli_ip[3]);
			key.port = rte_bswap16(peer_req->int_port);

			#ifdef NAT_ONLY_CONFIG_REQ
			if (nat_only_config_flag)
				key.port = 0xffff;
			#endif

			/* PEER Err : If no requested entry is found */
			pos = rte_hash_lookup(napt_common_table, &key);
			if (pos == -ENOENT) {
				pcp_resp->life_time =
					rte_bswap32(PCP_LONG_LTIME);
				pcp_resp->result_code = PCP_MALFORMED_REQUEST;

				#ifdef PCP_DEBUG
				printf("PCP Failure : unable to find entry\n");
				#endif

				construct_pcp_resp(rx_pkt, tx_pkt, ver,
					p_nat->p.p);
				return;
			}
			/*	If requested created entry */

			if (napt_hash_tbl_entries[pos].data.
				timeout > 0) {

			napt_hash_tbl_entries[pos].
				data.timeout = pcp_lifetime;

			p_entry = &napt_hash_tbl_entries[pos];

			s_key.port = napt_hash_tbl_entries[pos].
					data.pub_port;
			s_key.ip = napt_hash_tbl_entries[pos].
					data.pub_ip;
			s_key.pid = napt_hash_tbl_entries[pos].
					data.pub_phy_port;

			/* Getting ingress or second entry
			* from the table
			*/

			pos = rte_hash_lookup(napt_common_table,
				&s_key);
			s_entry = &napt_hash_tbl_entries[pos];

			/* Enqueue the info to restart the timer */
			timer_thread_enqueue(&key, &s_key,
					 p_entry, s_entry,
						 (struct pipeline *)p_nat);

			} else{
					// dynamic entry
				if (!napt_hash_tbl_entries[pos].data.timeout)
					pcp_resp->life_time =
						rte_bswap32(PCP_LONG_LTIME);
				else	// if static entry
					pcp_resp->life_time = 0xffffffff;

					pcp_resp->result_code =
						PCP_NOT_AUTHORIZED;
				#ifdef PCP_DEBUG
				printf("PCP Failure : Not a PCP request "
				"created entry\n");
				#endif
				construct_pcp_resp(rx_pkt, tx_pkt, ver,
					p_nat->p.p);

				return;
			}

			/* PEER Success */
			/* Fill PCP Response */
			rte_bswap16(pcp_req->life_time) < pcp_lifetime?
			(pcp_resp->life_time = pcp_req->life_time):
			(pcp_resp->life_time = rte_bswap32(pcp_lifetime));

			pcp_resp->result_code = PCP_SUCCESS;
			/* Fill PCP PEER Resonse */
			memcpy(peer_resp->nonce, peer_req->nonce, 12);
			peer_resp->protocol = peer_req->protocol;
			peer_resp->res_unuse1 = 0;

			peer_resp->int_port =
				rte_be_to_cpu_16(peer_req->int_port);
			peer_resp->ext_port =
				rte_be_to_cpu_16(peer_req->ext_port);
			memcpy(peer_resp->ext_ip, peer_req->ext_ip, 16);
			memcpy(peer_resp->ext_ip, pcp_ipv4_format, 12);
			peer_resp->ext_ip[3] =
				rte_bswap32(p_entry->data.pub_ip);
			peer_resp->rpeer_port =
				rte_be_to_cpu_16(peer_req->rpeer_port);
			peer_resp->res_unuse2 = 0x0000;
			memcpy(peer_resp->rpeer_ip, peer_req->rpeer_ip, 16);
			construct_pcp_resp(rx_pkt, tx_pkt, ver, p_nat->p.p);
			return;
		}
	default:
		printf("This never hits\n");
	}

}
#endif
