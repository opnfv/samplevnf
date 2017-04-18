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
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>

#include "rte_ct_tcp.h"


/*
 * OVERVIEW:
 * This module will behave as a proxy between an initiator (external client)
 * and listener (internal server).
 * (1) Proxy receives SYN from initiator, replies with spoofed SYN-ACK message
 *     No packet is sent to the lister at this time.
 * (2) Proxy receives ACK from the initiator, so the connection request is
 *     considred valid. Proxy sends a spoofed SYN message to the listener.
 * (3) Proxy receives SYN-ACK message from listener. Proxy replies to listener
 *     with a spoofed ACK message. The connection is considered established.
 * (4) Traffic is exchanged between initiator and listener. Sequence and
 *     ack numbers translated appropriately by proxy.
 */

/*
 * DETAILS, when SynProxy on:
 * (1) receive initial SYN from client
 *    call CT, all new connections assigned spoofed (random) SEQ number
 *    packet re-purposed as SYN-ACK back to client with spoofed SEQ
 *    -> change ethernet, IP, and TCP headers, put on appropriate output ring
 * (2) receive ACK packet from client
 *    connection request now considered valid
 *    packet re-purposed as SYN to server, using SEQ from original SYN
 *    -> change TCP header, put on output ring originally targetted
 * (3) receive SYN-ACK packet from server
 *    connection now ESTABLISHED
 *    compute SEQ difference between spoofed SEQ and real server SEQ
 *    packet re-purposed as ACK to server
 *    -> change ethernet, IP, and TCP headers, put on appropriate output ring
 * (4) all further packets flow normally, except SEQ and ACK numbers must be
 *    modified by SEQ diff (SEQ in server->client direction, ACK and SACK in
 *    client->server direction)
 *
 */

#define META_DATA_OFFSET 128
#define ETHERNET_START (META_DATA_OFFSET + RTE_PKTMBUF_HEADROOM)
#define ETH_HDR_SIZE 14
#define IP_START (ETHERNET_START + ETH_HDR_SIZE)
#define PROTOCOL_START (IP_START + 9)
#define IP_V4_HEADER_SIZE 20
#define IP_V6_HEADER_SIZE 40
#define TCP_START (IP_START + IP_V4_HEADER_SIZE)
#define TCP_MIN_HDR_SIZE 20

#define RTE_TCP_PROTO_ID 6
#define RTE_SP_DEFAULT_TTL 64

#define RTE_SYNPROXY_MAX_SPOOFED_PKTS 64

#define RTE_TCP_SYN 0x02
#define RTE_TCP_ACK 0x10
#define RTE_TCP_SYN_ACK (RTE_TCP_SYN | RTE_TCP_ACK)

#define RTE_SP_DEFAULT_WINDOW 29200
#define RTE_CT_DEBUG_SPOOFED_SEQ 0
#define RTE_DPDK_IS_16_4 0

#define IP_VERSION_4 4
#define IP_VERSION_6 6


/* default TCP options */
/* TODO: need to set in config file */

struct rte_synproxy_options default_ipv4_synproxy_options = {
	.options = RTE_SP_OPTIONS_MSS |
			RTE_SP_OPTIONS_SACK_PERM |
			RTE_SP_OPTIONS_WINDOW_SCALE,
	.mss = 1460,
	.window_scale = 7,
	.initial_window = RTE_SP_DEFAULT_WINDOW
};


struct rte_synproxy_options default_ipv6_synproxy_options = {
	.options = RTE_SP_OPTIONS_MSS |
			RTE_SP_OPTIONS_SACK_PERM |
			RTE_SP_OPTIONS_WINDOW_SCALE,
	.mss = 1440,
	.window_scale = 7,
	.initial_window = RTE_SP_DEFAULT_WINDOW
};

/* IP/TCP header print for debugging */
static __rte_unused void
rte_ct_synproxy_print_pkt_info(struct rte_mbuf *pkt)
{
	struct ipv4_hdr *ihdr4 = (struct ipv4_hdr *)
		RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);
	__rte_unused struct tcp_hdr *thdr = (struct tcp_hdr *)
		RTE_MBUF_METADATA_UINT32_PTR(pkt, TCP_START);
	uint32_t packet_length = rte_pktmbuf_pkt_len(pkt);

	printf("\npacket length %u, ip length %u\n", packet_length,
		rte_bswap16(ihdr4->total_length));
	rte_pktmbuf_dump(stdout, pkt, 80);
}

static inline void
rte_sp_incremental_tcp_chksum_update_32(
	uint32_t num_before,	/* in Intel order, not network order */
	uint32_t num_after,	/* in Intel order, not network order */

	uint16_t *chksum)	/* network order, e.g. pointer into header */
{
	uint32_t sum;

	sum = ~rte_bswap16(*chksum) & 0xffff;
	num_before = ~num_before;
	sum += (num_before >> 16) + (num_before & 0xffff);
	sum += (num_after >> 16) + (num_after & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	*chksum = rte_bswap16(~sum & 0xffff);
}



static inline uint32_t
rte_sp_get_random_seq_number(void)
{
	return rte_get_tsc_cycles(); /* low 32 bits of timestamp*/
}


static int8_t rte_ct_ipversion(void *i_hdr)
{
	uint8_t *ihdr = (uint8_t *)i_hdr;
	int8_t hdr_chk = *ihdr;

	hdr_chk = hdr_chk >> 4;
	if (hdr_chk == IP_VERSION_4 || hdr_chk == IP_VERSION_6)
		return hdr_chk;
	else
		return -1;
}

static inline void
rte_synproxy_adjust_pkt_length(struct rte_mbuf *pkt)
{
	uint16_t pkt_length = 0;
	int ip_hdr_size_bytes = rte_ct_get_IP_hdr_size(pkt);
	void *iphdr = RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);

	if (ip_hdr_size_bytes == IP_V4_HEADER_SIZE) {
		struct ipv4_hdr *ihdr4 = (struct ipv4_hdr *)iphdr;

		pkt_length = rte_bswap16(ihdr4->total_length) + ETH_HDR_SIZE;
	} else if (ip_hdr_size_bytes == IP_V6_HEADER_SIZE) {
		struct ipv6_hdr *ihdr6 = (struct ipv6_hdr *)iphdr;

		pkt_length = rte_bswap16(ihdr6->payload_len) +
			IP_V6_HEADER_SIZE + ETH_HDR_SIZE;
	}
	uint16_t mbuf_pkt_length = rte_pktmbuf_pkt_len(pkt);

	if (pkt_length == mbuf_pkt_length)
		return;

	if (pkt_length < mbuf_pkt_length) {
		rte_pktmbuf_trim(pkt, mbuf_pkt_length - pkt_length);
		return;
	}

	/* pkt_length > mbuf_pkt_length */
	rte_pktmbuf_append(pkt, pkt_length - mbuf_pkt_length);
}

static void
rte_synproxy_build_ipv4_header(
	struct ipv4_hdr *hdr4,
	uint32_t src_addr,
	uint32_t dst_addr,
	uint16_t tcp_length)
{
	/* TODO: consider interface re-work, too many rte_bswapxx */
	/* options are not supported, so header size is fixed */
	hdr4->version_ihl = 0x45;
	hdr4->type_of_service = 0;
	hdr4->total_length = rte_bswap16(tcp_length + IP_V4_HEADER_SIZE);
	hdr4->packet_id = 0;
	/* set Don't fragment bit, Intel order */
	hdr4->fragment_offset = 0x0040;
	hdr4->time_to_live = RTE_SP_DEFAULT_TTL;
	hdr4->next_proto_id = RTE_TCP_PROTO_ID;
	/* checksum calculated later */
	hdr4->src_addr = rte_bswap32(src_addr);
	hdr4->dst_addr = rte_bswap32(dst_addr);
}


static void
rte_synproxy_build_ipv6_header(
	struct ipv6_hdr *hdr6,
	uint8_t *src_addr,
	uint8_t *dst_addr,
	uint16_t tcp_length)
{
	/* TODO: consider interface re-work, too many rte_bswapxx */
	/* options are not supported, so header size is fixed */
	uint8_t	temp_src[16];
	uint8_t	temp_dst[16];

	hdr6->vtc_flow = 0x60;	/* Intel Order */
	hdr6->payload_len = rte_bswap16(tcp_length);
	hdr6->proto = RTE_TCP_PROTO_ID;
	hdr6->hop_limits = RTE_SP_DEFAULT_TTL;
	/* checksum calculated later */

	/* must copy to temps to avoid overwriting */
	rte_mov16(temp_src, src_addr);
	rte_mov16(temp_dst, dst_addr);
	rte_mov16(hdr6->src_addr, temp_src);
	rte_mov16(hdr6->dst_addr, temp_dst);
}

/* add options specified in t_opts to TCP header in packet. */

static uint16_t
rte_sp_add_tcp_options(struct tcp_hdr *thdr,
		const struct rte_synproxy_options *t_opts)
{
	uint32_t *options_ptr = (uint32_t *)(thdr + 1);
	uint32_t *saved_ptr = options_ptr;
	uint8_t options = t_opts->options;
	uint32_t option_bytes;	/* options built in groups of 4 bytes */

	if (options & RTE_SP_OPTIONS_MSS) {
		option_bytes = (RTE_CT_TCPOPT_MSS << 24) |
			(RTE_CT_TCPOLEN_MSS << 16) | t_opts->mss;
		*options_ptr++ = rte_bswap32(option_bytes);
	}

	if (options & RTE_SP_OPTIONS_TIMESTAMP) {
		/* if both timestamp and sack permitted options,
		 * pack together
		 */
		if (options & RTE_SP_OPTIONS_SACK_PERM)
			option_bytes = (RTE_CT_TCPOPT_SACK_PERM << 24) |
					(RTE_CT_TCPOLEN_SACK_PERM << 16);
		else
			option_bytes = (RTE_CT_TCPOPT_NOP << 24) |
				(RTE_CT_TCPOPT_NOP << 16);

		option_bytes |= (RTE_CT_TCPOPT_TIMESTAMP << 8) |
			RTE_CT_TCPOLEN_TIMESTAMP;
		*options_ptr++ = rte_bswap32(option_bytes);
		*options_ptr++ = rte_bswap32(t_opts->ts_val);
		*options_ptr++ = rte_bswap32(t_opts->ts_echo_reply);
	} else if (options & RTE_SP_OPTIONS_SACK_PERM) {
		option_bytes = (RTE_CT_TCPOPT_NOP << 24) |
			(RTE_CT_TCPOPT_NOP << 16) |
			(RTE_CT_TCPOPT_SACK_PERM << 8) |
			RTE_CT_TCPOLEN_SACK_PERM;
		*options_ptr++ = rte_bswap32(option_bytes);
	}

	if (options & RTE_SP_OPTIONS_WINDOW_SCALE) {
		option_bytes = (RTE_CT_TCPOPT_NOP << 24) |
			(RTE_CT_TCPOPT_WINDOW << 16) |
			(RTE_CT_TCPOLEN_WINDOW << 8) |
			t_opts->window_scale;
		*options_ptr++ = rte_bswap32(option_bytes);
	}

	/* compute the data offset field, which is size of total
	 * TCP header in 32 bit words
	 */
	/* TODO: diff from options ptr to thdr */
	uint16_t data_offset_bytes = (uint16_t)RTE_PTR_DIFF(options_ptr,
			saved_ptr) + sizeof(struct tcp_hdr);
	thdr->data_off = (data_offset_bytes >> 2) << 4;

	return data_offset_bytes;
}

/* Build a TCP header.
 * Note that the the tcp_hdr must be in the appropriate location
 * in an mbuf
 * TODO: consider interface re-work, too many rte_bswapxx
 */
static inline uint16_t
rte_synproxy_build_tcp_header(
	__rte_unused struct rte_mbuf *old_pkt,
	struct tcp_hdr *t_hdr,
	uint16_t src_port,
	uint16_t dst_port,
	uint32_t seq,
	uint32_t ack,
	uint8_t flags,
	const struct rte_synproxy_options *t_opts,
	uint8_t add_options)
{
	t_hdr->src_port = rte_bswap16(src_port);
	t_hdr->dst_port = rte_bswap16(dst_port);
	t_hdr->sent_seq = rte_bswap32(seq);
	t_hdr->recv_ack = rte_bswap32(ack);

	t_hdr->tcp_flags = flags;
	t_hdr->rx_win = t_opts->initial_window;
	/* checksum calculated later */
	t_hdr->tcp_urp = 0;

	/* add tcp header options, if applicable */

	uint16_t new_tcp_hdr_size = TCP_MIN_HDR_SIZE;

	if (add_options)
		new_tcp_hdr_size = rte_sp_add_tcp_options(t_hdr, t_opts);
	else
		t_hdr->data_off = (TCP_MIN_HDR_SIZE >> 2) << 4;

	return new_tcp_hdr_size;
}

static void
rte_synproxy_compute_checksums(void *i_hdr, struct tcp_hdr *t_hdr)
{
	/*
	 * calculate IP and TCP checksums. Note that both checksum
	 * routines requirehecksum fields to be set to zero,
	 * and the the checksum is in the correct
	 * byte order, so no rte_bswap16 is required.
	 */

	/* TODO: look into h/w computation of checksums */

	int8_t hdr_chk = rte_ct_ipversion(i_hdr);

	t_hdr->cksum = 0;

	if (hdr_chk == IP_VERSION_4) {
		struct ipv4_hdr *i4_hdr = (struct ipv4_hdr *)i_hdr;

		i4_hdr->hdr_checksum = 0;
		t_hdr->cksum = rte_ipv4_udptcp_cksum(i4_hdr, t_hdr);
		i4_hdr->hdr_checksum = rte_ipv4_cksum(i4_hdr);
	} else if (hdr_chk == IP_VERSION_6) {
		struct ipv6_hdr *i6_hdr = (struct ipv6_hdr *)i_hdr;

		t_hdr->cksum = rte_ipv6_udptcp_cksum(i6_hdr, t_hdr);
	}
}



/*
 * Building new packet headers:
 * For IPv4 and IPv6 headers, no options and no fragmentation are supported.
 * Header size is fixed.
 * TCP header will (likely) have options, so header size is not fixed.
 * TCP header will be built first, and size used in IP packet size calculation.
 */
void
rte_sp_cvt_to_spoofed_client_synack(struct rte_ct_cnxn_data *cd,
		struct rte_mbuf *old_pkt)
{
	/* old packet is syn from client. Change to a (spoofed)
	 * SYN-ACK to send back
	 */

	int ip_hdr_size_bytes = rte_ct_get_IP_hdr_size(old_pkt);
	void *iphdr = RTE_MBUF_METADATA_UINT32_PTR(old_pkt, IP_START);
	struct tcp_hdr *thdr = (struct tcp_hdr *)
		RTE_MBUF_METADATA_UINT32_PTR(old_pkt, IP_START +
				ip_hdr_size_bytes);
	uint16_t tcp_header_size;

	/* get a spoofed sequence number and save in the connection data */
	uint32_t new_seq = rte_sp_get_random_seq_number();

	if (RTE_CT_DEBUG_SPOOFED_SEQ)
		new_seq = 10; /* something simple to aid debugging */

	cd->ct_protocol.synproxy_data.original_spoofed_seq = new_seq;

	/* build the TCP header, including reversing the port numbers. */
	tcp_header_size = rte_synproxy_build_tcp_header(old_pkt, thdr,
			rte_bswap16(thdr->dst_port),
			rte_bswap16(thdr->src_port),
			new_seq, rte_bswap32(thdr->sent_seq) + 1,
			RTE_TCP_SYN_ACK,
			ip_hdr_size_bytes == IP_V4_HEADER_SIZE ?
			&default_ipv4_synproxy_options :
			&default_ipv6_synproxy_options,	1);

	/* reverse the source and destination addresses in the IP hdr */
	if (ip_hdr_size_bytes == IP_V4_HEADER_SIZE) {
		struct ipv4_hdr *ihdr4 = (struct ipv4_hdr *)iphdr;

		rte_synproxy_build_ipv4_header(ihdr4,
				rte_bswap32(ihdr4->dst_addr),
				rte_bswap32(ihdr4->src_addr), tcp_header_size);

	} else if (ip_hdr_size_bytes == IP_V6_HEADER_SIZE) {
		struct ipv6_hdr *ihdr6 = (struct ipv6_hdr *)iphdr;

		rte_synproxy_build_ipv6_header(ihdr6,
				(uint8_t *)ihdr6->dst_addr,
				(uint8_t *)ihdr6->src_addr, tcp_header_size);
	}
	rte_synproxy_adjust_pkt_length(old_pkt);
	/* compute checksums */
	rte_synproxy_compute_checksums(iphdr, thdr);

}


void
rte_sp_cvt_to_spoofed_server_syn(struct rte_ct_cnxn_data *cd,
		struct rte_mbuf *old_pkt)
{
	/* old packet is ACK from client. Change to (spoofed)
	 * SYN to send to server
	 */

	int ip_hdr_size_bytes = rte_ct_get_IP_hdr_size(old_pkt);
	void *iphdr = RTE_MBUF_METADATA_UINT32_PTR(old_pkt, IP_START);
	struct tcp_hdr *thdr = (struct tcp_hdr *)
		RTE_MBUF_METADATA_UINT32_PTR(old_pkt, IP_START
				+ ip_hdr_size_bytes);
	uint16_t tcp_header_size;

	tcp_header_size = rte_synproxy_build_tcp_header(old_pkt, thdr,
			rte_bswap16(thdr->src_port),
			rte_bswap16(thdr->dst_port),
			rte_bswap32(thdr->sent_seq) - 1, 0,
			RTE_TCP_SYN,
			&cd->ct_protocol.synproxy_data.cnxn_options, 1);

	if (ip_hdr_size_bytes == IP_V4_HEADER_SIZE) {
		struct ipv4_hdr *ihdr4 = (struct ipv4_hdr *)iphdr;

		rte_synproxy_build_ipv4_header(ihdr4,
				rte_bswap32(ihdr4->src_addr),
				rte_bswap32(ihdr4->dst_addr), tcp_header_size);
	} else if (ip_hdr_size_bytes == IP_V6_HEADER_SIZE) {
		struct ipv6_hdr *ihdr6 = (struct ipv6_hdr *)iphdr;

		rte_synproxy_build_ipv6_header(ihdr6,
				(uint8_t *)ihdr6->src_addr,
				(uint8_t *)ihdr6->dst_addr, tcp_header_size);
	}

	rte_synproxy_adjust_pkt_length(old_pkt);
	/* compute checksums */
	rte_synproxy_compute_checksums(iphdr, thdr);

}

void
rte_sp_cvt_to_spoofed_server_ack(struct rte_ct_cnxn_data *cd,
		struct rte_mbuf *old_pkt)
{
	/* old packet is SYN-ACK from server. Change to spoofed ACK and
	 * send back to server
	 */

	int ip_hdr_size_bytes = rte_ct_get_IP_hdr_size(old_pkt);
	void *iphdr = RTE_MBUF_METADATA_UINT32_PTR(old_pkt, IP_START);
	struct tcp_hdr *thdr = (struct tcp_hdr *)
		RTE_MBUF_METADATA_UINT32_PTR(old_pkt, IP_START +
				ip_hdr_size_bytes);

	/* read real seq out of SYN-ACK from server, and save the delta from
	 * the spoofed one
	 */
	uint32_t real_seq = rte_bswap32(thdr->sent_seq);
	uint16_t tcp_header_size;

	cd->ct_protocol.synproxy_data.seq_diff =
		real_seq - cd->ct_protocol.synproxy_data.original_spoofed_seq;

	/* reverse the source and destination addresses */
	tcp_header_size = rte_synproxy_build_tcp_header(old_pkt, thdr,
			rte_bswap16(thdr->dst_port),
			rte_bswap16(thdr->src_port),
			rte_bswap32(thdr->recv_ack),
			rte_bswap32(thdr->sent_seq) + 1, RTE_TCP_ACK,
			&cd->ct_protocol.synproxy_data.cnxn_options, 0);

	/* reverse the source and destination addresses in the IP hdr */
	if (ip_hdr_size_bytes == IP_V4_HEADER_SIZE) {
		struct ipv4_hdr *ihdr4 = (struct ipv4_hdr *)iphdr;

		rte_synproxy_build_ipv4_header(ihdr4,
				rte_bswap32(ihdr4->dst_addr),
				rte_bswap32(ihdr4->src_addr), tcp_header_size);

	} else if (ip_hdr_size_bytes == IP_V6_HEADER_SIZE) {
		struct ipv6_hdr *ihdr6 = (struct ipv6_hdr *)iphdr;

		rte_synproxy_build_ipv6_header(ihdr6,
				(uint8_t *)ihdr6->dst_addr,
				(uint8_t *)ihdr6->src_addr, tcp_header_size);
	}
	rte_synproxy_adjust_pkt_length(old_pkt);
	/* compute checksums */
	rte_synproxy_compute_checksums(iphdr, thdr);
}

/*
 * if running synproxy and both halves of the proxied connection has been
 * established, need adjust the seq or ack value of the packet.
 * The value is adjusted by the difference between the spoofed server
 * initial sequence number and the real server sequence number.
 * In the client -> server direction, the ack must be increased by the
 * difference before the window check.
 * In the server -> client direction, the seq must be decreased by the
 * difference after the window check.
 */


void
rte_sp_adjust_server_seq_after_window_check(
	struct rte_ct_cnxn_data *cd,
	__rte_unused void *i_hdr,
	struct tcp_hdr *thdr,
	enum rte_ct_pkt_direction dir)
{
	uint32_t num_before, num_after;

	if (!cd->ct_protocol.synproxy_data.cnxn_established)
		return;

	if (dir == RTE_CT_DIR_ORIGINAL)
		return; /*wrong direction */


	/* update appropriate number (seq or ack) in header */
	num_before = rte_bswap32(thdr->sent_seq);
	num_after = num_before - cd->ct_protocol.synproxy_data.seq_diff;
	thdr->sent_seq = rte_bswap32(num_after);

	rte_sp_incremental_tcp_chksum_update_32(num_before, num_after,
			&thdr->cksum);
}


static void
rte_sp_adjust_client_sack_entries(
	struct tcp_hdr *thdr,
	uint32_t diff)
{
	uint32_t num_before, num_after;
	uint32_t *sack_ptr;
	uint8_t  sack_blk_size;
	uint16_t dataoff_in_bytes = (thdr->data_off & 0xf0) >> 2;
	uint16_t length = dataoff_in_bytes - sizeof(struct tcp_hdr);

	if (!length)
		return;

	uint8_t *options_ptr = (uint8_t *)(thdr + 1);

	while (length > 0) {
		uint8_t opcode = *options_ptr;
		uint8_t opsize = options_ptr[1];
		int i;

		switch (opcode) {

		case RTE_CT_TCPOPT_EOL:
			return; /* end of options */

		case RTE_CT_TCPOPT_NOP: /* Ref: RFC 793 section 3.1 */
			length--;
			options_ptr++;
			continue;

		case RTE_CT_TCPOPT_SACK:
			/*
			 * SACK (selective ACK) contains a block of 1 to 4
			 * entries of 8 bytes each. Each entry is a pair of
			 * 32 bit numbers. This block follows the usual 2
			 * bytes for opcode and opsize. Thus, the entire SACK
			 * option must be 10, 18, 26 or 34 bytes long.
			 */

			sack_blk_size = opsize - 2;
			/* start of entries */
			sack_ptr = (uint32_t *)(options_ptr + 2);
			/* count of 32 bit elements */
			int num_acks = sack_blk_size >> 2;

			if (unlikely(sack_blk_size > 32 ||
						((sack_blk_size & 0x3) != 0))) {
				printf("Sack block parsing failure\n");
				return;
			}

			for (i = 0; i < num_acks; i++) {
				num_before = rte_bswap32(*sack_ptr);
				num_after = num_before + diff;
				*sack_ptr = rte_bswap32(num_after);
				sack_ptr++;
				rte_sp_incremental_tcp_chksum_update_32(
						num_before,
						num_after,
						&thdr->cksum);
			}

			return;
		default:
			break;
		}
		if ((opsize < 2) || (opsize > length)) {
			printf("ERROR!, opsize %i, length %i\n",
				opsize, length);
			return;
		}

		options_ptr += opsize;
		length -= opsize;
	}
}

void
rte_sp_adjust_client_ack_before_window_check(
	struct rte_ct_cnxn_data *cd,
	 __rte_unused void *i_hdr,
	struct tcp_hdr *thdr,
	enum rte_ct_pkt_direction dir)
{
	uint32_t num_before, num_after;

	if (!cd->ct_protocol.synproxy_data.cnxn_established)
		return;

	if (dir != RTE_CT_DIR_ORIGINAL)
		return; /*wrong direction */


	/* first update appropriate number (seq or ack) in header */
	num_before = rte_bswap32(thdr->recv_ack);
	num_after = num_before + cd->ct_protocol.synproxy_data.seq_diff;
	thdr->recv_ack = rte_bswap32(num_after);
	rte_sp_incremental_tcp_chksum_update_32(num_before,
			num_after, &thdr->cksum);

	/* update SACK entries in header if any */

	if (1) { /* TODO: check if sack permitted before calling */
		rte_sp_adjust_client_sack_entries(thdr,
				cd->ct_protocol.synproxy_data.seq_diff);
		/* note that tcp hdr checksum adjusted in above sack
		 * entries routine call
		 */
	}
}




/* parse the tcp header options, if any, and save interesting ones */
static void
rte_sp_parse_tcp_options(
	uint8_t *options_ptr,
	uint16_t length,
	struct rte_synproxy_options *t_opts)
{
	int opsize;

	t_opts->options = 0;

	while (length > 0) {
		uint8_t opcode = *options_ptr++;

		if (opcode == RTE_CT_TCPOPT_EOL)
			return;

		if (opcode == RTE_CT_TCPOPT_NOP) {
			length--;
			continue; /* skip adjustments at loop bottom */
		}

		opsize = *options_ptr++;

		if (unlikely(opsize < 2 || opsize > length)) {
			/* TODO: Change printf to log */
			printf("parsing error, opsize: %i, length: %i\n",
				opsize, length);
			return;
		}

		switch (opcode) {

		case RTE_CT_TCPOPT_MSS:
			if (opsize == RTE_CT_TCPOLEN_MSS) {
				uint16_t *mss_ptr = (uint16_t *)options_ptr;

				t_opts->mss = rte_bswap16(*mss_ptr);
				t_opts->options |= RTE_SP_OPTIONS_MSS;
			}
			break;

		case RTE_CT_TCPOPT_WINDOW:
			if (opsize == RTE_CT_TCPOLEN_WINDOW) {
				t_opts->window_scale = RTE_MIN(*options_ptr,
						RTE_CT_MAX_TCP_WINDOW_SCALE);
				t_opts->options |= RTE_SP_OPTIONS_WINDOW_SCALE;
			}
			break;

		case RTE_CT_TCPOPT_TIMESTAMP:
			if (opsize == RTE_CT_TCPOLEN_TIMESTAMP) {
				uint32_t *ts_val_ptr = (uint32_t *)options_ptr;
				uint32_t *ts_ecr_ptr =
					(uint32_t *)(options_ptr + 4);
				t_opts->ts_val = rte_bswap32(*ts_val_ptr);
				t_opts->ts_echo_reply =
					rte_bswap32(*ts_ecr_ptr);
				t_opts->options |= RTE_SP_OPTIONS_TIMESTAMP;
			}
			break;

		case RTE_CT_TCPOPT_SACK_PERM:
			if (opsize == RTE_CT_TCPOLEN_SACK_PERM)
				t_opts->options |= RTE_SP_OPTIONS_SACK_PERM;
			break;

		default:
			break;
		}

		options_ptr += opsize - 2;
		length -= opsize;

	}
}

/* parse the tcp header options, if any, and save interesting ones in t_opts */
void
rte_sp_parse_options(struct rte_mbuf *pkt, struct rte_ct_cnxn_data *cd)
{
	/*uint16_t ip_hdr_length = rte_sp_get_ip_header_size(pkt);
	 * skip over IPv4 or IPv6 header
	 */
	int ip_hdr_length = rte_ct_get_IP_hdr_size(pkt);
	struct tcp_hdr *thdr = (struct tcp_hdr *)
		RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START + ip_hdr_length);
	uint8_t *opt_ptr = RTE_MBUF_METADATA_UINT8_PTR(pkt,
			(IP_START + ip_hdr_length + sizeof(struct tcp_hdr)));

	struct rte_synproxy_options *t_opts =
		&cd->ct_protocol.synproxy_data.cnxn_options;
	int length_in_bytes =
		((thdr->data_off & 0xf0) >> 2) - sizeof(struct tcp_hdr);

	rte_sp_parse_tcp_options(opt_ptr, length_in_bytes, t_opts);
	t_opts->initial_window = thdr->rx_win;
}




struct rte_mbuf *
rte_ct_get_buffered_synproxy_packets(
	struct rte_ct_cnxn_tracker *ct)
{
	struct rte_mbuf *trkr_list = ct->buffered_pkt_list;

	ct->buffered_pkt_list = NULL;
	return trkr_list;
}



void rte_ct_enable_synproxy(struct rte_ct_cnxn_tracker *ct)
{
	ct->misc_options.synproxy_enabled = 1;
	printf("rte_ct_enable_synproxy = %d\n",
			ct->misc_options.synproxy_enabled);
}

void rte_ct_disable_synproxy(struct rte_ct_cnxn_tracker *ct)
{
	ct->misc_options.synproxy_enabled = 0;
	//printf("rte_ct_disable_synproxy = %d\n",
	//		ct->misc_options.synproxy_enabled);
}

void
rte_ct_buffer_packet(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_ct_cnxn_data *cd,
	struct rte_mbuf *pkt)
{
	/*
	 * Add packet to list of buffered packets for the connection.
	 * List is built in reverse of order received by adding to front.
	 * List will later be reversed to maintain order of arrival.
	 */

	struct rte_mbuf **next = (struct rte_mbuf **)
		RTE_MBUF_METADATA_UINT64_PTR(pkt,
				ct->pointer_offset);
	*next = cd->ct_protocol.synproxy_data.buffered_pkt_list;
	cd->ct_protocol.synproxy_data.buffered_pkt_list = pkt;
}

void
rte_ct_release_buffered_packets(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_ct_cnxn_data *cd)
{
	struct rte_mbuf *cnxn_list =
		cd->ct_protocol.synproxy_data.buffered_pkt_list;

	if (cnxn_list == NULL)
		return;

	cd->ct_protocol.synproxy_data.buffered_pkt_list = NULL;

	struct rte_mbuf *trkr_list = ct->buffered_pkt_list;

	if (trkr_list == NULL)
		return;
	/*
	 * walk the cnxn_list, and add to front of trkr_list, reversing order
	 * and thus restoring orginal order. Order between different
	 * connections is irrelevant.
	 */
	while (cnxn_list != NULL) {
		struct rte_mbuf *old_next;

		struct rte_mbuf **next = (struct rte_mbuf **)
			RTE_MBUF_METADATA_UINT64_PTR(cnxn_list,
					ct->pointer_offset);

		old_next = *next;	/* save next cd packet */
		*next = trkr_list;/* make this cd packet point to ct list */
		trkr_list = cnxn_list;/* make the cd packet head of ct list */
		cnxn_list = old_next;	/* advance along cd list */
	}
	ct->buffered_pkt_list = trkr_list;
}
