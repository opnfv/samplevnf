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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_byteorder.h>
#include <rte_table_lpm.h>
#include <rte_table_hash.h>
#include <rte_jhash.h>
#include <rte_thash.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_prefetch.h>
#include <rte_table_array.h>
#include "pipeline_loadb_be.h"
#include "pipeline_actions_common.h"
#include "hash_func.h"
#include "pipeline_arpicmp_be.h"
#include "vnf_common.h"
#include "app.h"

#define BYTES_TO_BITS 8
#define ROTATE_15_BITS 15

#define MAX_VNF_THREADS 16

int pkt_burst_cnt;

uint8_t LOADB_DEBUG;
uint8_t total_vnf_threads;
uint32_t phyport_offset;

struct pipeline_loadb {
	struct pipeline p;
	pipeline_msg_req_handler custom_handlers[PIPELINE_LOADB_MSG_REQS];

	uint8_t n_vnf_threads;
	uint8_t n_lb_tuples;
	uint32_t outport_offset;
	uint64_t receivedLBPktCount;
	uint64_t droppedLBPktCount;
	uint8_t links_map[PIPELINE_MAX_PORT_IN];
	uint8_t outport_id[PIPELINE_MAX_PORT_IN];
	uint8_t n_prv_Q;
	uint8_t n_pub_Q;
	uint8_t pipeline_num;
} __rte_cache_aligned;

uint8_t default_rss_key[] = {
	0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
	0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
	0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
	0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
	0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
};

static void *pipeline_loadb_msg_req_custom_handler(struct pipeline *p,
							 void *msg);

static pipeline_msg_req_handler handlers[] = {
	[PIPELINE_MSG_REQ_PING] =
		pipeline_msg_req_ping_handler,
	[PIPELINE_MSG_REQ_STATS_PORT_IN] =
		pipeline_msg_req_stats_port_in_handler,
	[PIPELINE_MSG_REQ_STATS_PORT_OUT] =
		pipeline_msg_req_stats_port_out_handler,
	[PIPELINE_MSG_REQ_STATS_TABLE] =
		pipeline_msg_req_stats_table_handler,
	[PIPELINE_MSG_REQ_PORT_IN_ENABLE] =
		pipeline_msg_req_port_in_enable_handler,
	[PIPELINE_MSG_REQ_PORT_IN_DISABLE] =
		pipeline_msg_req_port_in_disable_handler,
	[PIPELINE_MSG_REQ_CUSTOM] =
		pipeline_loadb_msg_req_custom_handler,

};

static void *pipeline_loadb_msg_req_entry_dbg_handler(struct pipeline *,
									void *msg);

static pipeline_msg_req_handler custom_handlers[] = {
	[PIPELINE_LOADB_MSG_REQ_ENTRY_DBG] =
			pipeline_loadb_msg_req_entry_dbg_handler,
};

/*
 * LOADB table
 */
struct loadb_table_entry {
	struct rte_pipeline_table_entry head;
} __rte_cache_aligned;

void *pipeline_loadb_msg_req_custom_handler(struct pipeline *p, void *msg)
{
	struct pipeline_loadb *p_lb = (struct pipeline_loadb *)p;
	struct pipeline_custom_msg_req *req = msg;
	pipeline_msg_req_handler f_handle;

	f_handle = (req->subtype < PIPELINE_LOADB_MSG_REQS) ?
			p_lb->custom_handlers[req->subtype] :
			pipeline_msg_req_invalid_handler;

	if (f_handle == NULL)
		f_handle = pipeline_msg_req_invalid_handler;

	return f_handle(p, req);
}

uint32_t lb_pkt_print_count;

uint8_t calculate_lb_thread_prv(struct rte_mbuf *pkt, void *arg)
{
	uint32_t hash_key[2], hash_ipv4;
	uint32_t temp1, temp2, temp3;
	uint8_t thread;
	struct pipeline_loadb_in_port_h_arg *ap = arg;
	struct pipeline_loadb *p_loadb = (struct pipeline_loadb *) ap->p;
	uint8_t nthreads = p_loadb->n_vnf_threads;
	union rte_thash_tuple tuple;

	uint32_t *src_addr;
	uint32_t *dst_addr;
	uint16_t *src_port;
	uint16_t *dst_port;
	uint8_t *protocol;
	struct lb_pkt *lb_pkt = (struct lb_pkt *)
			RTE_MBUF_METADATA_UINT8_PTR(pkt, MBUF_HDR_ROOM);

	if (rte_be_to_cpu_16(lb_pkt->eth.ether_type) == ETHER_TYPE_IPv6) {
		src_addr = (uint32_t *)&lb_pkt->ipv6_port.ipv6.src_addr;
		dst_addr = (uint32_t *)&lb_pkt->ipv6_port.ipv6.dst_addr;
		src_port = &lb_pkt->ipv6_port.src_port;
		dst_port = &lb_pkt->ipv6_port.dst_port;
		protocol = &lb_pkt->ipv6_port.ipv6.proto;
	} else {
		src_addr = &lb_pkt->ipv4_port.ipv4.src_addr;
		dst_addr = &lb_pkt->ipv4_port.ipv4.dst_addr;
		src_port = &lb_pkt->ipv4_port.src_port;
		dst_port = &lb_pkt->ipv4_port.dst_port;
		protocol = &lb_pkt->ipv4_port.ipv4.next_proto_id;
	}

	switch (p_loadb->n_lb_tuples) {

	case 0:
		/* Write */
		/* Egress */
	if (rte_be_to_cpu_16(lb_pkt->eth.ether_type) == ETHER_TYPE_IPv6)
		temp1 = rte_bswap32(dst_addr[3]) ^ *dst_port;
	else
		temp1 = *dst_addr ^ *dst_port;

			temp2 = (temp1 >> 24) ^ (temp1 >> 16) ^
				(temp1 >> 8) ^ temp1;

			temp3 = (temp2 >> 4) ^ (temp2 & 0xf);

			/* To select the thread */
			thread = temp3 % nthreads;
			/* To select the Q */
			thread = ap->in_port_id + (p_loadb->p.n_ports_in *
				(thread + 1) - p_loadb->p.n_ports_in);
		return thread;

	case 1:
		/* Write */
		/* Egress */
		if (rte_be_to_cpu_16(lb_pkt->eth.ether_type) == ETHER_TYPE_IPv6)
			hash_key[0] = rte_bswap32(dst_addr[3]);
		else
			hash_key[0] = rte_bswap32(*dst_addr);

		/* Compute */
		hash_ipv4 = rte_jhash(&hash_key[0], 4, 0);

		/* To select the thread */
		thread = (hash_ipv4 % nthreads);

		/* To select the Q */
		thread = ap->in_port_id + (p_loadb->p.n_ports_in *
				(thread + 1) - p_loadb->p.n_ports_in);

		if (LOADB_DEBUG > 3)
			printf("thread: %u  hash: %x  hash_key: %x\n",
				thread, hash_ipv4, hash_key[0]);
		return thread;

	case 2:
		/* Write */
		/* Egress */
		if (rte_be_to_cpu_16(lb_pkt->eth.ether_type) ==
			ETHER_TYPE_IPv6) {
			hash_key[0] = rte_bswap32(dst_addr[3]);
			hash_key[1] = *dst_port << 16;
		} else{
			hash_key[0] = rte_bswap32(*dst_addr);
			hash_key[1] = *dst_port << 16;
		}
		/* Compute */
		hash_ipv4 = rte_jhash(&hash_key[0], 6, 0);

		/* To select the thread */
		thread = (hash_ipv4 % nthreads);

		/* To select the Q */
		thread = ap->in_port_id + (p_loadb->p.n_ports_in *
				(thread + 1) - p_loadb->p.n_ports_in);

		if (LOADB_DEBUG > 3) {
			printf("public_addr: %x public_port: %x\n",
				hash_key[0], *dst_port);
			printf("thread: %u  hash: %x  hash_key0: %x  "
				"hash_key1: %x\n", thread, hash_ipv4,
				hash_key[0], hash_key[1]);
		}
		return thread;

	case 3:
		printf("Invalid n_lb_tuples: %d\n", p_loadb->n_lb_tuples);
		return 0;

	case 4:
		/* Write */
		if (rte_be_to_cpu_16(lb_pkt->eth.ether_type) ==
			ETHER_TYPE_IPv6) {
			tuple.v4.src_addr = rte_bswap32(src_addr[3]);
			tuple.v4.dst_addr = rte_bswap32(dst_addr[3]);
			tuple.v4.sport = *src_port;
			tuple.v4.dport = *dst_port;
		} else{
			tuple.v4.src_addr = rte_bswap32(*src_addr);
			tuple.v4.dst_addr = rte_bswap32(*dst_addr);
			tuple.v4.sport = *src_port;
			tuple.v4.dport = *dst_port;
		}
		/* Compute */
		hash_ipv4 = rte_softrss((uint32_t *)&tuple,
				RTE_THASH_V4_L4_LEN,
				default_rss_key);
		/* Egress */

		/* To select the thread */
		thread = (hash_ipv4 % nthreads);

		/* To select the Q */
		thread = ap->in_port_id + (p_loadb->p.n_ports_in *
				(thread + 1) - p_loadb->p.n_ports_in);

		if (LOADB_DEBUG > 3) {
			printf("src_addr: %x dst_addr: %x src_port: %x "
			"dst_port: %x\n", tuple.v4.src_addr, tuple.v4.dst_addr,
			tuple.v4.sport, tuple.v4.dport);
			printf("thread: %u  hash: %x\n", thread, hash_ipv4);
		}

		return thread;

	case 5:

		if (rte_be_to_cpu_16(lb_pkt->eth.ether_type) ==
			ETHER_TYPE_IPv6) {
			/* point to last 32 bits of IPv6 addresses*/
			src_addr += 3;
			dst_addr += 3;
		}

		/* Compute */
		temp1 = *src_addr ^ *dst_addr ^ *src_port ^
			*dst_port ^ *protocol;

		temp2 = (temp1 >> 24) ^ (temp1 >> 16) ^ (temp1 >> 8) ^ temp1;
		temp3 = (temp2 >> 4) ^ (temp2 & 0xf);

		/* Egress */

		/* To select the thread */
		thread = (temp3 % nthreads);

		/* To select the Q */
		thread = ap->in_port_id + (p_loadb->p.n_ports_in *
				(thread + 1) - p_loadb->p.n_ports_in);

		if (LOADB_DEBUG > 3) {
			printf("thread: %u  temp1: %x  temp2: %x  temp3: %x\n",
				thread, temp1, temp2, temp3);
			printf("src_addr: %x dst_addr: %x src_port: %x "
			"dst_port: %x protocol: %x\n", *src_addr, *dst_addr,
			*src_port, *dst_port, *protocol);
		}
		return thread;

	default:
		printf("Invalid n_lb_tuples: %d\n", p_loadb->n_lb_tuples);
		return 0;

	}
}

uint8_t calculate_lb_thread_pub(struct rte_mbuf *pkt, void *arg)
{
	uint32_t hash_key[2], hash_ipv4;
	uint32_t temp1, temp2, temp3;
	uint8_t thread;
	struct pipeline_loadb_in_port_h_arg *ap = arg;
	struct pipeline_loadb *p_loadb = (struct pipeline_loadb *) ap->p;
	uint8_t nthreads = p_loadb->n_vnf_threads;
	union rte_thash_tuple tuple;

	uint32_t *src_addr;
	uint32_t *dst_addr;
	uint16_t *src_port;
	uint16_t *dst_port;
	uint8_t *protocol;
	struct lb_pkt *lb_pkt = (struct lb_pkt *)
				RTE_MBUF_METADATA_UINT8_PTR(pkt,
					MBUF_HDR_ROOM);

	if (rte_be_to_cpu_16(lb_pkt->eth.ether_type) == ETHER_TYPE_IPv6) {
		src_addr = (uint32_t *)&lb_pkt->ipv6_port.ipv6.src_addr;
		dst_addr = (uint32_t *)&lb_pkt->ipv6_port.ipv6.dst_addr;
		src_port = &lb_pkt->ipv6_port.src_port;
		dst_port = &lb_pkt->ipv6_port.dst_port;
		protocol = &lb_pkt->ipv6_port.ipv6.proto;
	} else {
		src_addr = &lb_pkt->ipv4_port.ipv4.src_addr;
		dst_addr = &lb_pkt->ipv4_port.ipv4.dst_addr;
		src_port = &lb_pkt->ipv4_port.src_port;
		dst_port = &lb_pkt->ipv4_port.dst_port;
		protocol = &lb_pkt->ipv4_port.ipv4.next_proto_id;
	}

	switch (p_loadb->n_lb_tuples) {

	case 0:
		/* Write */
						 /* Ingress */
			temp1 = *src_addr ^ *src_port;
			temp2 = (temp1 >> 24) ^ (temp1 >> 16) ^
				(temp1 >> 8) ^ temp1;
			temp3 = (temp2 >> 4) ^ (temp2 & 0xf);

			/* To select the thread */
			thread = temp3 % nthreads;
			/* To select the Q */
			thread = ap->in_port_id + (p_loadb->p.n_ports_in *
				(thread + 1) - p_loadb->p.n_ports_in);

			return thread;

	case 1:
		/* Write */
				/* Ingress */
			hash_key[0] = rte_bswap32(*src_addr);

			/* Compute */
			hash_ipv4 = rte_jhash(&hash_key[0], 4, 0);

			/* To select the thread */
			thread = hash_ipv4 % nthreads;
			/* To select the Q */
			thread = ap->in_port_id + (p_loadb->p.n_ports_in *
				(thread + 1) - p_loadb->p.n_ports_in);

		if (LOADB_DEBUG > 3)
			printf("thread: %u  hash: %x  hash_key: %x\n",
				thread, hash_ipv4, hash_key[0]);
		return thread;

	case 2:
		/* Write */
				/* Ingress */
			hash_key[0] = rte_bswap32(*src_addr);
			hash_key[1] = *src_port << 16;

			/* Compute */
			hash_ipv4 = rte_jhash(&hash_key[0], 6, 0);

			/* To select the thread */
			thread = hash_ipv4 % nthreads;
			/* To select the Q */
			thread = ap->in_port_id + (p_loadb->p.n_ports_in *
				(thread + 1) - p_loadb->p.n_ports_in);

		if (LOADB_DEBUG > 3) {
			printf("thread: %u  hash: %x  hash_key0: %x  "
			"hash_key1: %x\n", thread, hash_ipv4,
			hash_key[0], hash_key[1]);
			printf("public_addr: %x public_port: %x\n",
			hash_key[0], *src_port);
		}
		return thread;

	case 3:
		printf("Invalid n_lb_tuples: %d\n", p_loadb->n_lb_tuples);
		return 0;

	case 4:
		/* Write */
		tuple.v4.src_addr = rte_bswap32(*src_addr);
		tuple.v4.dst_addr = rte_bswap32(*dst_addr);
		tuple.v4.sport = *src_port;
		tuple.v4.dport = *dst_port;

		/* Compute */
		hash_ipv4 = rte_softrss((uint32_t *)&tuple,
				RTE_THASH_V4_L4_LEN, default_rss_key);

			/* Ingress */
			/* To select the thread */
			thread = hash_ipv4 % nthreads;
			/* To select the Q */
			thread = ap->in_port_id + (p_loadb->p.n_ports_in *
				(thread + 1) - p_loadb->p.n_ports_in);

		if (LOADB_DEBUG > 3) {
			printf("src_addr: %x dst_addr: %x src_port: %x "
				"dst_port: %x\n", tuple.v4.src_addr,
			tuple.v4.dst_addr, tuple.v4.sport, tuple.v4.dport);

			printf("thread: %u  hash: %x\n", thread, hash_ipv4);
		}
		return thread;

	case 5:

		if (rte_be_to_cpu_16(lb_pkt->eth.ether_type) ==
			ETHER_TYPE_IPv6) {
			/* point to last 32 bits of IPv6 addresses*/
			src_addr += 3;
			dst_addr += 3;
		}

		/* Compute */
		temp1 = *src_addr ^ *dst_addr ^ *src_port ^
			*dst_port ^ *protocol;
		temp2 = (temp1 >> 24) ^ (temp1 >> 16) ^
			(temp1 >> 8) ^ temp1;
		temp3 = (temp2 >> 4) ^ (temp2 & 0xf);

			/* To select the thread */
			thread = temp3 % nthreads;
			/* To select the Q */
			thread = ap->in_port_id + (p_loadb->p.n_ports_in *
				(thread + 1) - p_loadb->p.n_ports_in);

		if (LOADB_DEBUG > 3) {
			printf("src_addr: %x dst_addr: %x src_port: %x "
			"dst_port: %x protocol: %x\n", *src_addr, *dst_addr,
			*src_port, *dst_port, *protocol);

			printf("thread: %u  temp1: %x  temp2: %x  temp3: %x\n",
				thread, temp1, temp2, temp3);
		}

		return thread;

	default:
		printf("Invalid n_lb_tuples: %d\n", p_loadb->n_lb_tuples);
		return 0;

	}
}

static inline void
pkt_work_loadb_key_prv(
	struct rte_mbuf *pkt,
	__rte_unused uint32_t pkt_num,
	void *arg)
{
	struct pipeline_loadb_in_port_h_arg *ap = arg;
	struct pipeline_loadb *p_loadb = (struct pipeline_loadb *)ap->p;
	uint32_t outport_offset = p_loadb->outport_offset;

	struct lb_pkt *lb_pkt = (struct lb_pkt *)
				RTE_MBUF_METADATA_UINT8_PTR(pkt,
				MBUF_HDR_ROOM);
	uint32_t *out_port = RTE_MBUF_METADATA_UINT32_PTR(pkt,
				outport_offset);

	#ifdef MY_LOADB_DBG_PRINT
	if (LOADB_DEBUG == 3)
		printf("Start pkt_work_loadb_key\n");
	#endif

	if ((LOADB_DEBUG > 2) && (lb_pkt_print_count < 10)) {
		print_pkt1(pkt);
		lb_pkt_print_count++;
		printf("\nEth Typ %x, Prot %x, ETH_TYPE_ARP %x, "
			"ETH_TYPE_IPV4 %x, IP_PROTOCOL_ICMP %x\n",
			rte_be_to_cpu_16(lb_pkt->eth.ether_type),
			lb_pkt->ipv4_port.ipv4.next_proto_id, ETH_TYPE_ARP,
			ETH_TYPE_IPV4, IP_PROTOCOL_ICMP);
	}

		/* Write */
		*out_port = calculate_lb_thread_prv(pkt, arg);

	p_loadb->receivedLBPktCount++;

	#ifdef MY_LOADB_DBG_PRINT
	if (LOADB_DEBUG == 3)
		printf("End pkt_work_loadb_key\n");
	#endif
}

static inline void
pkt_work_loadb_key_pub(
	struct rte_mbuf *pkt,
	__rte_unused uint32_t pkt_num,
	void *arg)
{
	struct pipeline_loadb_in_port_h_arg *ap = arg;
	struct pipeline_loadb *p_loadb = (struct pipeline_loadb *)ap->p;
	uint32_t outport_offset = p_loadb->outport_offset;

	struct lb_pkt *lb_pkt = (struct lb_pkt *)
				RTE_MBUF_METADATA_UINT8_PTR(pkt,
				MBUF_HDR_ROOM);
	uint32_t *out_port = RTE_MBUF_METADATA_UINT32_PTR(pkt,
				outport_offset);

	#ifdef MY_LOADB_DBG_PRINT
	if (LOADB_DEBUG == 3)
		printf("Start pkt_work_loadb_key\n");
	#endif

	if ((LOADB_DEBUG > 2) && (lb_pkt_print_count < 10)) {
		print_pkt1(pkt);
		lb_pkt_print_count++;
		printf("\nEth Typ %x, Prot %x, ETH_TYPE_ARP %x, "
			"ETH_TYPE_IPV4 %x, IP_PROTOCOL_ICMP %x\n",
			rte_be_to_cpu_16(lb_pkt->eth.ether_type),
			lb_pkt->ipv4_port.ipv4.next_proto_id, ETH_TYPE_ARP,
			ETH_TYPE_IPV4, IP_PROTOCOL_ICMP);
	}

		/* Write */
		*out_port = calculate_lb_thread_pub(pkt, arg);

	p_loadb->receivedLBPktCount++;
#ifdef MY_LOADB_DBG_PRINT
	if (LOADB_DEBUG == 3)
		printf("End pkt_work_loadb_key\n");
#endif
}

static inline void
pkt4_work_loadb_key_prv(
	struct rte_mbuf **pkt,
	__rte_unused uint32_t pkt_num,
	void *arg)
{
	struct pipeline_loadb_in_port_h_arg *ap = arg;
	struct pipeline_loadb *p_loadb = (struct pipeline_loadb *)ap->p;
	uint32_t outport_offset = p_loadb->outport_offset;

	uint32_t *out_port0 = RTE_MBUF_METADATA_UINT32_PTR(pkt[0],
				outport_offset);
	uint32_t *out_port1 = RTE_MBUF_METADATA_UINT32_PTR(pkt[1],
				outport_offset);
	uint32_t *out_port2 = RTE_MBUF_METADATA_UINT32_PTR(pkt[2],
				outport_offset);
	uint32_t *out_port3 = RTE_MBUF_METADATA_UINT32_PTR(pkt[3],
				outport_offset);

	struct lb_pkt *lb_pkt0 = (struct lb_pkt *)
				RTE_MBUF_METADATA_UINT8_PTR(pkt[0],
					MBUF_HDR_ROOM);
	struct lb_pkt *lb_pkt1 = (struct lb_pkt *)
				RTE_MBUF_METADATA_UINT8_PTR(pkt[1],
					MBUF_HDR_ROOM);
	struct lb_pkt *lb_pkt2 = (struct lb_pkt *)
				RTE_MBUF_METADATA_UINT8_PTR(pkt[2],
					MBUF_HDR_ROOM);
	struct lb_pkt *lb_pkt3 = (struct lb_pkt *)
				RTE_MBUF_METADATA_UINT8_PTR(pkt[3],
					MBUF_HDR_ROOM);

	#ifdef MY_LOADB_DBG_PRINT
	if (LOADB_DEBUG == 3)
		printf("Start pkt4_work_loadb_key\n");
	#endif

	if ((LOADB_DEBUG > 2) && (lb_pkt_print_count < 10)) {
		print_pkt1(pkt[0]);
		lb_pkt_print_count++;

		printf("\nEth Typ %x, Prot %x\n",
			rte_be_to_cpu_16(lb_pkt0->eth.ether_type),
			lb_pkt0->ipv4_port.ipv4.next_proto_id);

		print_pkt1(pkt[1]);
		lb_pkt_print_count++;

		printf("\nEth Typ %x, Prot %x\n",
			rte_be_to_cpu_16(lb_pkt1->eth.ether_type),
			lb_pkt1->ipv4_port.ipv4.next_proto_id);

		print_pkt1(pkt[2]);
		lb_pkt_print_count++;

		printf("\nEth Typ %x, Prot %x\n",
			rte_be_to_cpu_16(lb_pkt2->eth.ether_type),
			lb_pkt2->ipv4_port.ipv4.next_proto_id);

		print_pkt1(pkt[3]);
		lb_pkt_print_count++;

		printf("\nEth Typ %x, Prot %x\n",
			rte_be_to_cpu_16(lb_pkt3->eth.ether_type),
			lb_pkt3->ipv4_port.ipv4.next_proto_id);
	}
		*out_port0 = calculate_lb_thread_prv(pkt[0], arg);
		*out_port1 = calculate_lb_thread_prv(pkt[1], arg);
		*out_port2 = calculate_lb_thread_prv(pkt[2], arg);
		*out_port3 = calculate_lb_thread_prv(pkt[3], arg);

	p_loadb->receivedLBPktCount += 4;

	#ifdef MY_LOADB_DBG_PRINT
	if (LOADB_DEBUG == 3)
		printf("End pkt4_work_loadb_key\n");
	#endif

}

static inline void
pkt4_work_loadb_key_pub(
	struct rte_mbuf **pkt,
	__rte_unused uint32_t pkt_num,
	void *arg)
{
	struct pipeline_loadb_in_port_h_arg *ap = arg;
	struct pipeline_loadb *p_loadb = (struct pipeline_loadb *)ap->p;
	uint32_t outport_offset = p_loadb->outport_offset;

	uint32_t *out_port0 = RTE_MBUF_METADATA_UINT32_PTR(pkt[0],
				outport_offset);
	uint32_t *out_port1 = RTE_MBUF_METADATA_UINT32_PTR(pkt[1],
				outport_offset);
	uint32_t *out_port2 = RTE_MBUF_METADATA_UINT32_PTR(pkt[2],
				outport_offset);
	uint32_t *out_port3 = RTE_MBUF_METADATA_UINT32_PTR(pkt[3],
				outport_offset);

	struct lb_pkt *lb_pkt0 = (struct lb_pkt *)
				RTE_MBUF_METADATA_UINT8_PTR(pkt[0],
					MBUF_HDR_ROOM);
	struct lb_pkt *lb_pkt1 = (struct lb_pkt *)
				RTE_MBUF_METADATA_UINT8_PTR(pkt[1],
					MBUF_HDR_ROOM);
	struct lb_pkt *lb_pkt2 = (struct lb_pkt *)
				RTE_MBUF_METADATA_UINT8_PTR(pkt[2],
					MBUF_HDR_ROOM);
	struct lb_pkt *lb_pkt3 = (struct lb_pkt *)
				RTE_MBUF_METADATA_UINT8_PTR(pkt[3],
					MBUF_HDR_ROOM);

	#ifdef MY_LOADB_DBG_PRINT
	if (LOADB_DEBUG == 3)
		printf("Start pkt4_work_loadb_key\n");
	#endif

	if ((LOADB_DEBUG > 2) && (lb_pkt_print_count < 10)) {
		print_pkt1(pkt[0]);
		lb_pkt_print_count++;

		printf("\nEth Typ %x, Prot %x\n",
			rte_be_to_cpu_16(lb_pkt0->eth.ether_type),
			lb_pkt0->ipv4_port.ipv4.next_proto_id);

		print_pkt1(pkt[1]);
		lb_pkt_print_count++;

		printf("\nEth Typ %x, Prot %x\n",
			rte_be_to_cpu_16(lb_pkt1->eth.ether_type),
			lb_pkt1->ipv4_port.ipv4.next_proto_id);

		print_pkt1(pkt[2]);
		lb_pkt_print_count++;

		printf("\nEth Typ %x, Prot %x\n",
			rte_be_to_cpu_16(lb_pkt2->eth.ether_type),
			lb_pkt2->ipv4_port.ipv4.next_proto_id);

		print_pkt1(pkt[3]);
		lb_pkt_print_count++;

		printf("\nEth Typ %x, Prot %x\n",
			rte_be_to_cpu_16(lb_pkt3->eth.ether_type),
			lb_pkt3->ipv4_port.ipv4.next_proto_id);
	}
		*out_port0 = calculate_lb_thread_prv(pkt[0], arg);
		*out_port1 = calculate_lb_thread_pub(pkt[1], arg);
		*out_port2 = calculate_lb_thread_pub(pkt[2], arg);
		*out_port3 = calculate_lb_thread_pub(pkt[3], arg);

	p_loadb->receivedLBPktCount += 4;
#ifdef MY_LOADB_DBG_PRINT
	if (LOADB_DEBUG == 3)
		printf("End pkt4_work_loadb_key\n");
#endif

}

PIPELINE_LOADB_KEY_PORT_IN_AH(port_in_ah_loadb_key_prv,
				pkt_work_loadb_key_prv,
				pkt4_work_loadb_key_prv);

PIPELINE_LOADB_KEY_PORT_IN_AH(port_in_ah_loadb_key_pub,
				pkt_work_loadb_key_pub,
				pkt4_work_loadb_key_pub);

static int
pipeline_loadb_parse_args(struct pipeline_loadb *p,
				struct pipeline_params *params)
{
	uint32_t outport_offset_present = 0;
	uint32_t n_vnf_threads_present = 0;
	uint32_t pktq_in_prv_present = 0;
	uint32_t prv_que_handler_present = 0;
	uint32_t prv_to_pub_map_present = 0;
	uint8_t n_prv_in_port = 0;
	uint32_t i;

	/* Default number of tuples */
	p->n_lb_tuples = 0;

	if (LOADB_DEBUG > 2)
		printf("LOADB pipeline_loadb_parse_args params->n_args: %d\n",
					 params->n_args);

	for (i = 0; i < params->n_args; i++) {
		char *arg_name = params->args_name[i];
		char *arg_value = params->args_value[i];

		if (LOADB_DEBUG > 2)
			printf("LOADB args[%d]: %s %d, %s\n", i, arg_name,
						 atoi(arg_value), arg_value);

		/* outport_offset = 128 + 8 */
		if (strcmp(arg_name, "outport_offset") == 0) {
			if (outport_offset_present)
				return -1;
			outport_offset_present = 1;

			p->outport_offset = atoi(arg_value);
			if (p->outport_offset <= 0) {
				printf("Outport_offset is invalid\n");
				return -1;
			}
			printf("outport_offset: 0x%x\n", p->outport_offset);
			continue;
		}
		/* n_vnf_threads = 4 */
		if (strcmp(arg_name, "n_vnf_threads") == 0) {
			if (n_vnf_threads_present)
				return -1;
			n_vnf_threads_present = 1;

			p->n_vnf_threads = atoi(arg_value);

			total_vnf_threads += p->n_vnf_threads;

			if ((p->n_vnf_threads <= 0)
					|| (total_vnf_threads > MAX_VNF_THREADS)) {
				printf("n_vnf_threads : MIN->0 MAX->16\n");
				return -1;
			}
			printf("n_vnf_threads    : 0x%x\n", p->n_vnf_threads);
			printf("total_vnf_threads: 0x%x\n", total_vnf_threads);
			continue;
		}

				/* pktq_in_prv */
		if (strcmp(arg_name, "pktq_in_prv") == 0) {
			if (pktq_in_prv_present) {
				printf("Duplicate pktq_in_prv ... "
				"parse failed..\n\n");
				return -1;
			}
			pktq_in_prv_present = 1;

			int rxport = 0, j = 0;
			char phy_port_num[8];
			char *token = strtok(arg_value, "RXQ");
			while (token) {
				j = 0;
				while ((j < 7) && (token[j] != '.')) {
					phy_port_num[j] = token[j];
					j++;
				}
				phy_port_num[j] = '\0';
				rxport =  atoi(phy_port_num);
				printf("token: %s, phy_port_str: %s, "
					"phy_port_num %d\n",
				token, phy_port_num, rxport);
				prv_in_port_a[n_prv_in_port++] = rxport;
				// set rxport egress
				if (rxport < 0xff){
                                       if(rxport < PIPELINE_MAX_PORT_IN)
					in_port_dir_a[rxport] = 1;
                                }
				token = strtok(NULL, "RXQ");
			}

			if (n_prv_in_port == 0) {
				printf("VNF common parse error - "
				"no prv RX phy port\n");
				return -1;
			}
			continue;
		}

				/* pktq_in_prv_handler */

		if (strcmp(arg_name, "prv_que_handler") == 0) {

			if (prv_que_handler_present) {
				printf("Duplicate pktq_in_prv ..\n\n");
				return -1;
			}
			prv_que_handler_present = 1;
			n_prv_in_port = 0;

			char *token;
			int rxport = 0;
			/* get the first token */
			token = strtok(arg_value, "(");
			token = strtok(token, ")");
			token = strtok(token, ",");
			printf("***** prv_que_handler *****\n");
                        if (token)
										printf("string is :%s\n", token);

			if (token)
				//printf("string is null\n");
			printf("string is :%s\n", token);

			/* walk through other tokens */
			while (token != NULL) {
				printf(" %s\n", token);
				rxport =  atoi(token);
				prv_que_port_index[n_prv_in_port++] = rxport;
				if (rxport < 0xff){
                                  if(rxport < PIPELINE_MAX_PORT_IN)
					in_port_egress_prv[rxport] = 1;
                                }
				p->n_prv_Q++;
				token = strtok(NULL, ",");
			}

			if (n_prv_in_port == 0) {
			printf("VNF common parse err - no prv RX phy port\n");
			return -1;
			}

			continue;
			}
		/* prv_to_pub_map */
		if (strcmp(arg_name, "prv_to_pub_map") == 0) {
			if (prv_to_pub_map_present) {
				printf("Duplicated prv_to_pub_map ... "
					"parse failed ...\n");
				return -1;
			}
			prv_to_pub_map_present = 1;

			 int rxport = 0, txport = 0, j = 0, k = 0;
			 char rx_phy_port_num[5];
			 char tx_phy_port_num[5];
			 char *token = strtok(arg_value, "(");
			while (token) {
				j = 0;
				while ((j < 4) && (token[j] != ',')) {
					rx_phy_port_num[j] = token[j];
					j++;
				}
				rx_phy_port_num[j] = '\0';
				rxport =  atoi(rx_phy_port_num);

				j++;
				k = 0;
				while ((k < 4) && (token[j+k] != ')')) {
					tx_phy_port_num[k] = token[j+k];
					k++;
				}
				 tx_phy_port_num[k] = '\0';
				 txport =  atoi(tx_phy_port_num);

			printf("token: %s,rx_phy_port_str: %s, phy_port_num "
			"%d, tx_phy_port_str: %s, tx_phy_port_num %d\n",
			token, rx_phy_port_num, rxport,
			tx_phy_port_num, txport);
                         if(rxport < PIPELINE_MAX_PORT_IN)
			if ((rxport >= PIPELINE_MAX_PORT_IN) ||
				(txport >= PIPELINE_MAX_PORT_IN) ||
				(in_port_dir_a[rxport] != 1)) {
				printf("CG-NAPT parse error - "
				"incorrect prv-pub translation. Rx %d, "
				"Tx %d, Rx Dir %d\n", rxport, txport,
				in_port_dir_a[rxport]);

				return -1;
			}
			if (rxport < 0xff){
                              if (rxport < PIPELINE_MAX_PORT_IN)
				prv_to_pub_map[rxport] = txport;
						 }
                       if (txport < 0xff)
                            if(txport < PIPELINE_MAX_PORT_IN)
				pub_to_prv_map[txport] = rxport;
			token = strtok(NULL, "(");
		}

			continue;
		}
		/* Set number of tuples if available in config file */
		if (strcmp(arg_name, "n_lb_tuples") == 0) {
			p->n_lb_tuples = atoi(arg_value);
			printf("n_lb_tuples: 0x%x\n", p->n_lb_tuples);
		}

		/* loadb_debug */
		if (strcmp(arg_name, "loadb_debug") == 0) {
			LOADB_DEBUG = atoi(arg_value);
			continue;
		}

		/* any other Unknown argument return -1 */
	}			/* for */

	/* Check that mandatory arguments are present */
	if ((n_vnf_threads_present == 0) || (outport_offset_present == 0))
		return -1;

	return 0;

}

int check_loadb_thread(
	struct app_params *app,
	struct pipeline_params *params,
	int32_t n_vnf_threads)
{
	uint32_t i;
	int pipeline_num = 0;
	int count = 0;
	int dont_care = sscanf(params->name, "PIPELINE%d", &pipeline_num);
	if (dont_care != 1)
		return -1;
	/* changed from pipeline_num+1 to +2 */
	for (i = pipeline_num + 2; i < app->n_pipelines; i++) {
		struct app_pipeline_params *p = &app->pipeline_params[i];
		if (!strncmp(p->type, "LOADB", strlen(p->type)))
			break;
		count++;
	}
	if (n_vnf_threads != count)
		return -1;
	return 0;

}

static void *pipeline_loadb_init(
	struct pipeline_params *params,
	__rte_unused void *arg)
	/* arg is app parameter (struct app_params *app) */
	/*save it for use in port in handler */
{
	struct pipeline *p;
	struct pipeline_loadb *p_loadb;
	uint32_t size, i, in_ports_arg_size;

	/* Check input arguments */
	if ((params == NULL) ||
			(params->n_ports_in == 0) || (params->n_ports_out == 0))
		return NULL;

	/* Memory allocation */
	size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct pipeline_loadb));
	p = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
	p_loadb = (struct pipeline_loadb *)p;
	if (p == NULL)
		return NULL;

	strcpy(p->name, params->name);
	p->log_level = params->log_level;

	PLOG(p, HIGH, "LOADB");

	p_loadb->n_vnf_threads = 0;
	p_loadb->outport_offset = 0;
	p_loadb->receivedLBPktCount = 0;
	p_loadb->droppedLBPktCount = 0;
	for (i = 0; i < PIPELINE_MAX_PORT_IN; i++) {
		p_loadb->links_map[i] = 0xff;
	}
	p_loadb->pipeline_num = 0xff;
	p_loadb->n_prv_Q = 0;
	p_loadb->n_pub_Q = 0;

	/* Parse arguments */

	if (pipeline_loadb_parse_args(p_loadb, params))
		return NULL;

	/* Pipeline */
	{
		struct rte_pipeline_params pipeline_params = {
			.name = "LOADB",
			.socket_id = params->socket_id,
			.offset_port_id = 0,
		};

		p->p = rte_pipeline_create(&pipeline_params);
		if (p->p == NULL) {
			rte_free(p);
			return NULL;
		}

		printf("Loadb p->p %p, socket %d\n", p->p,
					 pipeline_params.socket_id);
	}

	/* Memory allocation for in_port_h_arg */
	in_ports_arg_size =
			RTE_CACHE_LINE_ROUNDUP((sizeof(struct pipeline_loadb_in_port_h_arg))
					 * (params->n_ports_in));
	struct pipeline_loadb_in_port_h_arg *ap =
			(struct pipeline_loadb_in_port_h_arg *)
		rte_zmalloc(NULL,
			in_ports_arg_size,
			RTE_CACHE_LINE_SIZE);
	if (ap == NULL)
		return NULL;

	printf("ap pointer %p\n", ap);

	/* Input ports */
	p->n_ports_in = params->n_ports_in;
	for (i = 0; i < p->n_ports_in; i++) {
		/* passing our loadb pipeline in call back arg */
		(ap[i]).p = p_loadb;
		(ap[i]).in_port_id = i;

		struct rte_pipeline_port_in_params port_params = {
			.ops =
					pipeline_port_in_params_get_ops(&params->port_in
									[i]),
			.arg_create =
					pipeline_port_in_params_convert(&params->port_in
									[i]),
		/* Public in-port handler */
			.f_action = NULL,
			.arg_ah = &(ap[i]),
			.burst_size = params->port_in[i].burst_size,
		};

		/* Private in-port handler */
		if (is_port_index_privte(i)) {/* Multiport changes*/
			printf("LOADB %d port is Prv\n", i);
			port_params.f_action = port_in_ah_loadb_key_prv;
		} else{
			printf("LOADB %d port is Pub\n", i);
			port_params.f_action = port_in_ah_loadb_key_pub;
		}

		int status = rte_pipeline_port_in_create(p->p,
							 &port_params,
							 &p->port_in_id[i]);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}

	}

		p_loadb->n_pub_Q = p_loadb->p.n_ports_in - p_loadb->n_prv_Q;
		printf("LOADB : n_prv_Q - %d  n_pub_Q - %d\n",
				p_loadb->n_prv_Q, p_loadb->n_pub_Q);

		for (i = 0; i <  p->n_ports_in; i++) {
			printf("is_port_index_privte(%d): %d\n", i,
				is_port_index_privte(i));
			printf("is_phy_port_privte(%d): %d\n", i,
				is_phy_port_privte(i));
			printf("action handler of %d:%p\n", i,
				p_loadb->p.p->ports_in[i].f_action);
		}

	/* Output ports */
	p->n_ports_out = params->n_ports_out;
	for (i = 0; i < p->n_ports_out; i++) {
		struct rte_pipeline_port_out_params port_params = {
			.ops =
					pipeline_port_out_params_get_ops(&params->port_out
									 [i]),
			.arg_create =
					pipeline_port_out_params_convert(&params->port_out
									 [i]),
			.f_action = NULL,
			.arg_ah = NULL,
		};

		int status = rte_pipeline_port_out_create(p->p,
								&port_params,
								&p->port_out_id[i]);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}

		printf("Outport p->port_out_id[%d] %p\n", i,
					 &p->port_out_id[i]);
	}

	int pipeline_num = 0;
	int dont_care = sscanf(params->name, "PIPELINE%d", &pipeline_num);
	if (dont_care != 1) {
		printf("Unable to read pipeline number\n");
		return NULL;
	}
	p_loadb->pipeline_num = pipeline_num;
#if 0
	set_outport_id(pipeline_num, p, lb_outport_id);
	set_phy_outport_map(pipeline_num, p_loadb->links_map);

	set_port_to_loadb_map(pipeline_num);

	register_loadb_to_arp(pipeline_num, p, app);
#endif
	register_pipeline_Qs(p_loadb->pipeline_num, p);
	set_link_map(p_loadb->pipeline_num, p, p_loadb->links_map);
	//set_outport_id(p_loadb->pipeline_num, p, p_loadb->outport_id);

	/* Tables */
	p->n_tables = 1;
	{

		struct rte_table_array_params table_array_params = {
			.n_entries = MAX_VNF_THREADS,
			.offset = p_loadb->outport_offset,
		};
		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_array_ops,
			.arg_create = &table_array_params,
			.f_action_hit = NULL,
			.f_action_miss = NULL,
			.arg_ah = p_loadb,
			.action_data_size = 0,
		};

		int status;

		status = rte_pipeline_table_create(p->p,
							 &table_params,
							 &p->table_id[0]);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}
	}			/* Tables */

	/* Connecting input ports to tables */
	for (i = 0; i < p->n_ports_in; i++) {
		int status = rte_pipeline_port_in_connect_to_table(
				p->p,
				p->port_in_id[i],
				p->table_id[0]);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}
	}

	/* Enable input ports */
	for (i = 0; i < p->n_ports_in; i++) {
		int status = rte_pipeline_port_in_enable(p->p,
							 p->port_in_id[i]);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}
	}

	/* Initialize table entries */
	{
		for (i = 0; i < MAX_VNF_THREADS; i++) {
			struct rte_table_array_key key = {
				.pos = i,
			};
			struct loadb_table_entry entry;
			entry.head.action = RTE_PIPELINE_ACTION_PORT;

			if (i < p->n_ports_out) {
				entry.head.port_id = p->port_out_id[i];
				printf("\ni %d, p->port_out_id[%d] %d", i, i,
						p->port_out_id[i]);
			} else {
				/* First CGNAPT thread */
				entry.head.port_id = p->port_out_id[0];
				entry.head.action = RTE_PIPELINE_ACTION_DROP;
			}

			struct rte_pipeline_table_entry *entry_ptr;
			int key_found, status;
			status = rte_pipeline_table_entry_add(
					p->p,
					p->table_id[0],
					&key,
					(struct rte_pipeline_table_entry *)
					&entry,
					&key_found,
					&entry_ptr);
			if (status) {
				rte_pipeline_free(p->p);
				rte_free(p);
				return NULL;
			}
		}
	}
	/* Add default entry to tables */
	{
		struct rte_pipeline_table_entry default_entry = {
			.action = RTE_PIPELINE_ACTION_PORT,
			/* LB by default forward to 1st cgnat thread */
			.port_id = p->port_out_id[0],
		};

		struct rte_pipeline_table_entry *default_entry_ptr;

		int status = rte_pipeline_table_default_entry_add(
				p->p,
				p->table_id[0],
				&default_entry,
				&default_entry_ptr);

		if (status) {
			rte_pipeline_free(p->p);
			rte_free(p);
			return NULL;
		}

	}

	/* Check pipeline consistency */
	if (rte_pipeline_check(p->p) < 0) {
		rte_pipeline_free(p->p);
		rte_free(p);
		return NULL;
	}

	/* Message queues */
	p->n_msgq = params->n_msgq;
	for (i = 0; i < p->n_msgq; i++)
		p->msgq_in[i] = params->msgq_in[i];
	for (i = 0; i < p->n_msgq; i++)
		p->msgq_out[i] = params->msgq_out[i];

	/* Message handlers */
	memcpy(p->handlers, handlers, sizeof(p->handlers));
	memcpy(p_loadb->custom_handlers,
				 custom_handlers, sizeof(p_loadb->custom_handlers));

	return p;
}

static int pipeline_loadb_free(void *pipeline)
{
	struct pipeline *p = (struct pipeline *)pipeline;

	/* Check input arguments */
	if (p == NULL)
		return -1;

	/* Free resources */
	rte_pipeline_free(p->p);
	rte_free(p);
	return 0;
}

static int
pipeline_loadb_track(void *pipeline,
				 __rte_unused uint32_t port_in, uint32_t *port_out)
{
	struct pipeline *p = (struct pipeline *)pipeline;

	/* Check input arguments */
	if ((p == NULL) || (port_in >= p->n_ports_in) || (port_out == NULL))
		return -1;

	if (p->n_ports_in == 1) {
		*port_out = 0;
		return 0;
	}

	return -1;
}

static int pipeline_loadb_timer(void *pipeline)
{
	struct pipeline *p = (struct pipeline *)pipeline;

	pipeline_msg_req_handle(p);
	rte_pipeline_flush(p->p);

	return 0;
}

void *pipeline_loadb_msg_req_entry_dbg_handler(struct pipeline *p, void *msg)
{
	struct pipeline_loadb_entry_dbg_msg_rsp *rsp = msg;
	uint8_t *Msg = msg;
	struct pipeline_loadb *p_loadb = (struct pipeline_loadb *)p;

	rsp->status = 0;

	printf("LoadB debug handler called with args %x %x, offset %d\n",
				 Msg[LOADB_DBG_CMD_OFST], Msg[LOADB_DBG_CMD_OFST + 1],
				 LOADB_DBG_CMD_OFST);

	if (Msg[LOADB_DBG_CMD_OFST] == LOADB_DBG_CMD_STATS_SHOW) {
		printf("\nLoadB Packet Stats: Received %" PRIu64 "\n",
					 p_loadb->receivedLBPktCount);
		return rsp;
	}
	if (Msg[LOADB_DBG_CMD_OFST] == LOADB_DBG_CMD_STATS_CLEAR) {
		printf("\nLoadB Packet Stats: Received %" PRIu64 "\n",
					 p_loadb->receivedLBPktCount);
		p_loadb->receivedLBPktCount = 0;
		return rsp;
	}

	if (Msg[LOADB_DBG_CMD_OFST] == LOADB_DBG_CMD_DBG_LEVEL) {
		LOADB_DEBUG = Msg[LOADB_DBG_CMD_OFST + 1];
		printf("LOADB Debug level set to %d\n", LOADB_DEBUG);
		lb_pkt_print_count = 0;
		return rsp;
	}
	if (Msg[LOADB_DBG_CMD_OFST] == LOADB_DBG_CMD_DBG_SHOW) {
		printf("\nLoadB DBG Level: %u\n", LOADB_DEBUG);
		return rsp;
	}
	if (Msg[LOADB_DBG_CMD_OFST] == LOADB_DBG_CMD_IF_STATS) {
		printf("\n");
		uint8_t i, j;

		for (i = 0; i < p->n_ports_in; i++) {
			struct rte_eth_stats stats;
			rte_eth_stats_get(p_loadb->links_map[i], &stats);
			if (is_phy_port_privte(i))
				printf("Private Port Stats %d\n", i);
			else
				printf("Public Port Stats  %d\n", i);
			printf("\n\tipackets : %" PRIu64 "\n\topackets : %"
						 PRIu64 "\n\tierrors  : %" PRIu64
						 "\n\toerrors  : %" PRIu64 "\n\trx_nombuf: %"
						 PRIu64 "\n", stats.ipackets, stats.opackets,
						 stats.ierrors, stats.oerrors, stats.rx_nombuf);
			if (is_phy_port_privte(i))
				printf("Private Q: ");
			else
				printf("Public  Q: ");
			for (j = 0; j < RTE_ETHDEV_QUEUE_STAT_CNTRS; j++)
				printf(" %" PRIu64 ", %" PRIu64 "|",
							 stats.q_ipackets[j],
							 stats.q_opackets[j]);

			printf("\n\n");

		}
		return rsp;
	}

	return rsp;

}

struct pipeline_be_ops pipeline_loadb_be_ops = {
	.f_init = pipeline_loadb_init,
	.f_free = pipeline_loadb_free,
	.f_run = NULL,
	.f_timer = pipeline_loadb_timer,
	.f_track = pipeline_loadb_track,
};
