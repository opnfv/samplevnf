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

#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include <inttypes.h>
#include "rte_ct_tcp.h"
#include "rte_cnxn_tracking.h"

/* uint32_t CT_DEBUG = 1; */ /* Can be used to conditionally turn of debug */
#define CT_DEBUG 0
#define STATE_TRACKING 0
#define RTE_CT_ASSERT 0

/* constants for mbuff manipulation */
#define META_DATA_OFFSET 128
#define RTE_PKTMBUF_HEADROOM 128	/* where is this defined ? */
#define ETHERNET_START (META_DATA_OFFSET + RTE_PKTMBUF_HEADROOM)
#define ETH_HDR_SIZE 14
#define IP_START (ETHERNET_START + ETH_HDR_SIZE)

#define IPv4_HEADER_SIZE 20
#define IPv6_HEADER_SIZE 40

#define IP_VERSION_4 4
#define IP_VERSION_6 6

#define rte_after(seq2, seq1) rte_before(seq1, seq2)
static inline uint8_t rte_before(uint32_t seq1, uint32_t seq2)
{
	return (int32_t) (seq1 - seq2) < 0;
}

/* short state names for defining state table */

#define ctNO RTE_CT_TCP_NONE
#define ctSS RTE_CT_TCP_SYN_SENT
#define ctSR RTE_CT_TCP_SYN_RECV
#define ctES RTE_CT_TCP_ESTABLISHED
#define ctFW RTE_CT_TCP_FIN_WAIT
#define ctCW RTE_CT_TCP_CLOSE_WAIT
#define ctLA RTE_CT_TCP_LAST_ACK
#define ctTW RTE_CT_TCP_TIME_WAIT
#define ctCL RTE_CT_TCP_CLOSE
#define ctS2 RTE_CT_TCP_SYN_SENT_2
#define ctIV RTE_CT_TCP_MAX
#define ctIG RTE_CT_TCP_IGNORE

static const uint8_t rte_ct_tcp_state_table[2][6][RTE_CT_TCP_MAX] = {
	{			/* "client" direction, i.e. first SYN sent */
	 /* ctNO, ctSS, ctSR, ctES, ctFW, ctCW, ctLA, ctTW, ctCL, ctS2 */
	 /* syn */ {ctSS, ctSS, ctIG, ctIG, ctIG, ctIG, ctIG, ctSS, ctSS,
				ctS2},

	 /* ctNO, ctSS, ctSR, ctES, ctFW, ctCW, ctLA, ctTW, ctCL, ctS2 */
	 /* synack */ {ctIV, ctIV, ctSR, ctIV, ctIV, ctIV, ctIV, ctIV, ctIV,
					 ctSR},

	 /* ctNO, ctSS, ctSR, ctES, ctFW, ctCW, ctLA, ctTW, ctCL, ctS2 */
	 /* fin */ {ctIV, ctIV, ctFW, ctFW, ctLA, ctLA, ctLA, ctTW, ctCL,
				ctIV},
	 /* ctNO, ctSS, ctSR, ctES, ctFW, ctCW, ctLA, ctTW, ctCL, ctS2 */
	 /* ack */ {ctES, ctIV, ctES, ctES, ctCW, ctCW, ctTW, ctTW, ctCL,
				ctIV},

	 /* ctNO, ctSS, ctSR, ctES, ctFW, ctCW, ctLA, ctTW, ctCL, ctS2 */
	 /* rst */ {ctIV, ctCL, ctCL, ctCL, ctCL, ctCL, ctCL, ctCL, ctCL,
				ctCL},
	 /* ill */ {ctIV, ctIV, ctIV, ctIV, ctIV, ctIV, ctIV, ctIV, ctIV, ctIV}
	 },

	{			/* "server" direction */
	 /* ctNO, ctSS, ctSR, ctES, ctFW, ctCW, ctLA, ctTW, ctCL, ctS2 */
	 /* syn */ {ctIV, ctS2, ctIV, ctIV, ctIV, ctIV, ctIV, ctSS, ctIV,
				ctS2},

	 /* ctNO, ctSS, ctSR, ctES, ctFW, ctCW, ctLA, ctTW, ctCL, ctS2 */
	 /* synack */ {ctIV, ctSR, ctIG, ctIG, ctIG, ctIG, ctIG, ctIG, ctIG,
					 ctSR},

	 /* ctNO, ctSS, ctSR, ctES, ctFW, ctCW, ctLA, ctTW, ctCL, ctS2 */
	 /* fin */ {ctIV, ctIV, ctFW, ctFW, ctLA, ctLA, ctLA, ctTW, ctCL,
				ctIV},

	 /* ctNO, ctSS, ctSR, ctES, ctFW, ctCW, ctLA, ctTW, ctCL, ctS2 */
	 /* ack */ {ctIV, ctIG, ctSR, ctES, ctCW, ctCW, ctTW, ctTW, ctCL,
				ctIG},

	 /* ctNO, ctSS, ctSR, ctES, ctFW, ctCW, ctLA, ctTW, ctCL, ctS2 */
	 /* rst */ {ctIV, ctCL, ctCL, ctCL, ctCL, ctCL, ctCL, ctCL, ctCL,
				ctCL},
	 /* ill */ {ctIV, ctIV, ctIV, ctIV, ctIV, ctIV, ctIV, ctIV, ctIV, ctIV}
	 }
};

/* What TCP flags are set from RST/SYN/FIN/ACK. */
enum rte_tcp_flag {
	RTE_CT_TCP_SYN_FLAG,
	RTE_CT_TCP_SAK_FLAG,	/* SYN ACK */
	RTE_CT_TCP_FIN_FLAG,
	RTE_CT_TCP_ACK_FLAG,
	RTE_CT_TCP_RST_FLAG,
	RTE_CT_TCP_ILL_FLAG,
};

static uint8_t rte_ct_tcp_flags_to_state_table_index[16] = {
	/* A R S F */
	RTE_CT_TCP_ILL_FLAG,	/* 0 0 0 0 */
	RTE_CT_TCP_FIN_FLAG,	/* 0 0 0 1 */
	RTE_CT_TCP_SYN_FLAG,	/* 0 0 1 0 */
	RTE_CT_TCP_ILL_FLAG,	/* 0 0 1 1 */
	RTE_CT_TCP_RST_FLAG,	/* 0 1 0 0 */
	RTE_CT_TCP_RST_FLAG,	/* 0 1 0 1 */
	RTE_CT_TCP_RST_FLAG,	/* 0 1 1 0 */
	RTE_CT_TCP_ILL_FLAG,	/* 0 1 1 1 */

	RTE_CT_TCP_ACK_FLAG,	/* 1 0 0 0 */
	RTE_CT_TCP_FIN_FLAG,	/* 1 0 0 1 */
	RTE_CT_TCP_SAK_FLAG,	/* 1 0 1 0 */
	RTE_CT_TCP_ILL_FLAG,	/* 1 0 1 1 */
	RTE_CT_TCP_RST_FLAG,	/* 1 1 0 0 */
	RTE_CT_TCP_ILL_FLAG,	/* 1 1 0 1 */
	RTE_CT_TCP_RST_FLAG,	/* 1 1 1 0 */
	RTE_CT_TCP_ILL_FLAG,	/* 1 1 1 1 */
};

static inline uint8_t
rte_ct_get_index(uint8_t tcp_flags)
{
	uint8_t important_flags;

	tcp_flags &= 0x3f;	/* clear off optional flags */
	important_flags = ((tcp_flags & 0x10) >> 1) | (tcp_flags & 7);
	/* should be _pext_u32(tcp_flags, 0x17) */

	if (unlikely((tcp_flags == 0) || (tcp_flags == 0x3f)))
		/* these known as null and christmas tree respectively */
		return RTE_CT_TCP_ILL_FLAG;

	return rte_ct_tcp_flags_to_state_table_index[important_flags];

}

static inline int
rte_ct_either_direction_has_flags(struct rte_ct_cnxn_data *cd, uint8_t flags)
{
	return ((cd->ct_protocol.tcp_ct_data.seen[0].flags | cd->
		 ct_protocol.tcp_ct_data.seen[1].flags) & flags) != 0;
}

static inline uint32_t rte_ct_seq_plus_length(struct rte_mbuf *pkt,
		uint8_t ip_hdr_size)
{
	uint16_t pkt_length = 0;
	struct tcp_hdr *tcpheader =
			(struct tcp_hdr *)RTE_MBUF_METADATA_UINT32_PTR(pkt,
								 (IP_START +
									ip_hdr_size));
	uint32_t tcp_hdr_size = (tcpheader->data_off & 0xf0) >> 2;

	void *ip_hdr = RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);

	if (ip_hdr_size == IPv4_HEADER_SIZE) {
		struct ipv4_hdr *ihdr = (struct ipv4_hdr *)ip_hdr;

		pkt_length = rte_bswap16(ihdr->total_length);
	}
	if (ip_hdr_size == IPv6_HEADER_SIZE) {
		struct ipv6_hdr *ihdr = (struct ipv6_hdr *)ip_hdr;

		pkt_length = rte_bswap16(ihdr->payload_len) + IPv6_HEADER_SIZE;
	}

	/*
	 * Return sequence number plus the length of TCP segment (payload).
	 * SYN & FIN are each considered one byte, but it is illegal
	 * to have them together in one header (checked elsewhere)
	*/


	return rte_bswap32(tcpheader->sent_seq) +
			pkt_length - ip_hdr_size - tcp_hdr_size +
			((tcpheader->tcp_flags & (RTE_CT_TCPHDR_SYN | RTE_CT_TCPHDR_FIN)) !=
			 0 ? 1 : 0);

}

static void
rte_ct_check_for_scaling_and_sack_perm(
	struct rte_mbuf *pkt,
	struct rte_ct_tcp_state *state,
	uint8_t ip_hdr_size)
{

	struct tcp_hdr *tcpheader =
			(struct tcp_hdr *)RTE_MBUF_METADATA_UINT32_PTR(pkt,
								 (IP_START +
									ip_hdr_size));
	uint32_t dataoff_in_bytes = (tcpheader->data_off & 0xf0) >> 2;
	uint32_t length = dataoff_in_bytes - sizeof(struct tcp_hdr);

	state->scale = 0;
	state->flags = 0;

	if (length == 0)
		/* no header options */
		return;
	uint8_t *options_ptr =
			RTE_MBUF_METADATA_UINT8_PTR(pkt,
					(IP_START + ip_hdr_size +
					 sizeof(struct tcp_hdr)));

	while (length > 0) {
		uint8_t option = *options_ptr;
		uint8_t opsize = options_ptr[1];
		/* opsize reset for NOPs below */

		switch (option) {

		case RTE_CT_TCPOPT_EOL:
			/* end of options */
			return;

		case RTE_CT_TCPOPT_NOP:
			options_ptr++;
			length--;
			continue;

		case RTE_CT_TCPOPT_SACK_PERM:
			if (opsize == RTE_CT_TCPOLEN_SACK_PERM)
				state->flags |= RTE_CT_TCP_FLAG_SACK_PERM;
			break;

		case RTE_CT_TCPOPT_WINDOW:
			if (opsize == RTE_CT_TCPOLEN_WINDOW) {
				state->scale =
						RTE_MIN(options_ptr[2],
							RTE_CT_MAX_TCP_WINDOW_SCALE);
				state->flags |= RTE_CT_TCP_FLAG_WINDOW_SCALE;
			}
			break;

		default:
			break;

		}

		if ((opsize < 2) || (opsize > length)) {
			/* something wrong */
			printf("scaling_and_sack_perm:something wrong\n");
			return;
		}
		options_ptr += opsize;
		length -= opsize;

	}
}

static void
rte_ct_tcpdisplay_hdr(struct tcp_hdr *tcpheader)
{
	printf("Tcp header: src_port=%d", rte_bswap16(tcpheader->src_port));
	printf(", dst_port=%d", rte_bswap16(tcpheader->dst_port));
	printf(", sent_seq=%u", rte_bswap32(tcpheader->sent_seq));
	printf(", recv_ack=%u", rte_bswap32(tcpheader->recv_ack));
	printf(",data_off=%d", tcpheader->data_off / 16);
	printf(",tcp_flags=%02x", tcpheader->tcp_flags);
	printf(", rx_win=%d\n", rte_bswap16(tcpheader->rx_win));

}

static inline void
rte_ct_clear_cnxn_data(__rte_unused struct rte_ct_cnxn_tracker *ct,
		struct rte_ct_cnxn_data *cd,
		__rte_unused struct rte_mbuf *pkt)
{
	/* clear all tcp connection data, then set up individual fields */

	memset(&cd->ct_protocol.tcp_ct_data, 0,
				 sizeof(cd->ct_protocol.tcp_ct_data));
	cd->ct_protocol.tcp_ct_data.last_index = RTE_CT_TCP_ILL_FLAG;

}

enum rte_ct_packet_action
rte_ct_tcp_new_connection(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_ct_cnxn_data *cd,
	struct rte_mbuf *pkt,
	int	use_synproxy,
	uint8_t ip_hdr_size)
{
	struct tcp_hdr *tcpheader =
		(struct tcp_hdr *)RTE_MBUF_METADATA_UINT32_PTR(pkt,
				(IP_START + ip_hdr_size));

	enum rte_ct_tcp_states new_state;
	uint8_t index;
	struct rte_ct_tcp_state *sender =
		&cd->ct_protocol.tcp_ct_data.seen[RTE_CT_DIR_ORIGINAL];
	struct rte_ct_tcp_state *receiver =
		&cd->ct_protocol.tcp_ct_data.seen[RTE_CT_DIR_REPLY];
	uint16_t win;

	 if (CT_DEBUG)
		rte_ct_tcpdisplay_hdr(tcpheader);

	index = rte_ct_get_index(tcpheader->tcp_flags);
	new_state = rte_ct_tcp_state_table[0][index][RTE_CT_TCP_NONE];

	if (unlikely(new_state >= RTE_CT_TCP_MAX)) {
		if (CT_DEBUG)
			printf("invalid new state with flags %02x\n",
					tcpheader->tcp_flags);
		return RTE_CT_DROP_PACKET;
	}
	/*
	 * A normal connection starts with a SYN packet. However, it is possible
	 * that an onginging connection has been routed here somehow. Support
	 * for these connections is optional.
	 */

	if (unlikely((new_state != RTE_CT_TCP_SYN_SENT
					&& ct->misc_options.tcp_loose == 0))) {
		/* Not a standard connection start and not supporting
		 * onging connections. */
		return RTE_CT_DROP_PACKET;
	}

	if (CT_DEBUG)
		printf(" new connection with state %s\n",
					 rte_ct_tcp_names[new_state]);

	/* clear all tcp connection data, then set up individual fields */
	rte_ct_clear_cnxn_data(ct, cd, pkt);
	cd->ct_protocol.tcp_ct_data.state = new_state;

	sender->end = sender->maxend = rte_ct_seq_plus_length(pkt, ip_hdr_size);
	win = rte_bswap16(tcpheader->rx_win);
	sender->maxwin = RTE_MAX(win, (uint32_t)1);

	if (likely(new_state == RTE_CT_TCP_SYN_SENT)) {
		/* check for window scaling and selective ACK */
		rte_ct_check_for_scaling_and_sack_perm(pkt, sender,
				ip_hdr_size);

		cd->ct_protocol.synproxy_data.synproxied = use_synproxy;

		if (use_synproxy) {
			/*
			 * new connection from client using synproxy. The proxy
			 * must send back a SYN-ACK
			 */


			if (CT_DEBUG > 2)
				printf("synproxy sending SYN-ACK to client\n");

			return RTE_CT_SEND_CLIENT_SYNACK;
		}
	} else {
		/*
		 * An ongoing connection. Make a very liberal connection since
		 * all the original set up data is lost. Assume SACK and
		 * liberal window checking to handle unknown window scaling.
		 */

		sender->maxend += sender->maxwin;
		sender->flags = receiver->flags =
				(RTE_CT_TCP_FLAG_SACK_PERM | RTE_CT_TCP_FLAG_BE_LIBERAL);
	}

	if (CT_DEBUG > 0) {
		printf("tcp_new: sender end=%u maxend=%u maxwin=%u scale=%i",
				sender->end, sender->maxend, sender->maxwin,
				sender->scale);
		printf(" receiver end=%u maxend=%u maxwin=%u scale=%i\n",
				receiver->end, receiver->maxend,
				receiver->maxwin,
				receiver->scale);
	}

	return RTE_CT_OPEN_CONNECTION;
}

static uint32_t
rte_ct_tcp_sack(struct rte_mbuf *pkt, uint8_t ip_hdr_size)
{
	struct tcp_hdr *tcpheader =
		(struct tcp_hdr *)RTE_MBUF_METADATA_UINT32_PTR(pkt,
				(IP_START +
				 ip_hdr_size));
	uint16_t dataoff_in_bytes = (tcpheader->data_off & 0xf0) >> 2;
	uint16_t length = dataoff_in_bytes - sizeof(struct tcp_hdr);
	uint32_t sack = rte_bswap32(tcpheader->recv_ack);

	if (unlikely(!length))
		return sack;

	uint8_t *options_ptr = RTE_MBUF_METADATA_UINT8_PTR(pkt,
			(IP_START + ip_hdr_size + sizeof(struct tcp_hdr)));

	while (length > 0) {
		uint8_t opcode = *options_ptr;
		uint8_t opsize = options_ptr[1];
		int i;
		uint32_t *sack_ptr;

		switch (opcode) {
		case RTE_CT_TCPOPT_TIMESTAMP:
			/* common "solo" option, check first */
			break;

		case RTE_CT_TCPOPT_EOL:
			return sack;	/* end of options */

		case RTE_CT_TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			options_ptr++;
			continue;

		case RTE_CT_TCPOPT_SACK:
			/*
			 * SACK (selective ACK) contains a block of
			 * 1 to 4 entries of 8 bytes each.
			 *  Each entry is a pair of 32 bit numbers.
			 * This block follows the usual 2
			 * bytes for opcode and opsize. Thus,
			 * the entire SACK option must be 10, 18,
			 * 26 or 34 bytes long.
			 */
			if ((opsize >= (RTE_CT_TCPOLEN_PER_SACK_ENTRY + 2)) &&
					((opsize - 2) %
					 RTE_CT_TCPOLEN_PER_SACK_ENTRY) == 0) {
				/* skip over opcode and size, and point to
				 * 2nd 32 bits in entry */
				options_ptr += 6;
				for (i = 0; i < (opsize - 2); i +=
						RTE_CT_TCPOLEN_PER_SACK_ENTRY) {
					sack_ptr =
						(uint32_t *) &options_ptr[i];
					uint32_t ack = rte_bswap32(*sack_ptr);

					if (rte_after(ack, sack))
						sack = ack;
				}
				return sack;
			}
			break;
		default:
			break;
		}
		if ((opsize < 2) || (opsize > length)) {
			printf("rte_ct_tcp_sack: something wrong, opsize %i,",
					opsize);
			printf(" length %i\n", length);
			return sack;
		}
		options_ptr += opsize;
		length -= opsize;
	}
	return sack;
}

/*
 * if this is a retransmission of last packet, increment retransmission count,
 * otherwise record this as last packet.
 */
static inline void
rte_ct_check_for_retransmissions(
	struct rte_ct_tcp *state,
	uint8_t dir,
	uint32_t seq,
	uint32_t ack,
	uint32_t end,
	uint16_t win)
{
	if (state->last_dir == dir
			&& state->last_seq == seq
			&& state->last_ack == ack
			&& state->last_end == end && state->last_win == win)
		state->retrans++;
	else {
		state->last_dir = dir;
		state->last_seq = seq;
		state->last_ack = ack;
		state->last_end = end;
		state->last_win = win;
		state->retrans = 0;
	}
}

/*
 * Verify that the sequence number in the given packet is within the valid
 * range at this point in the connection
 */
static uint8_t
rte_ct_tcp_in_window(
	struct rte_ct_cnxn_data *cd,
	struct rte_ct_cnxn_tracker *ct,
	struct rte_ct_tcp *state,
	enum rte_ct_pkt_direction dir,
	uint8_t index,
	struct rte_mbuf *pkt,
	uint8_t ip_hdr_size)
{
	struct rte_ct_tcp_state *sender = &state->seen[dir];
	struct rte_ct_tcp_state *receiver = &state->seen[!dir];
	uint32_t seq, ack, sack, end, win, swin;
	uint8_t in_recv_win, tcp_flags;
	enum rte_ct_packet_action res;

	void *iphdr = RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);
	struct tcp_hdr *tcpheader =
		(struct tcp_hdr *)RTE_MBUF_METADATA_UINT32_PTR(pkt,
				(IP_START + ip_hdr_size));

	if (cd->ct_protocol.synproxy_data.synproxied)
		rte_sp_adjust_client_ack_before_window_check(cd, iphdr,
				tcpheader, dir);


	seq = rte_bswap32(tcpheader->sent_seq);
	ack = sack = rte_bswap32(tcpheader->recv_ack);
	win = rte_bswap16(tcpheader->rx_win);
	end = rte_ct_seq_plus_length(pkt, ip_hdr_size);
	tcp_flags = tcpheader->tcp_flags;

	if (receiver->flags & RTE_CT_TCP_FLAG_SACK_PERM)
		sack = rte_ct_tcp_sack(pkt, ip_hdr_size);

	if (unlikely(sender->maxwin == 0)) {
		/* First packet for sender, initialize data.  */
		if (tcp_flags & RTE_CT_TCPHDR_SYN) {
			/*
			 * SYN-ACK in reply to a SYN
			 * or SYN from reply direction in simultaneous open.
			 */
			sender->end = sender->maxend = end;
			sender->maxwin = RTE_MAX(win, (uint32_t)1);

			rte_ct_check_for_scaling_and_sack_perm(pkt, sender,
					ip_hdr_size);

			/*
			 * RFC 1323: Both sides must send Window Scale option
			 * to enable scaling in either direction.
			 */
			if ((sender->
					 flags & receiver->flags &
					 RTE_CT_TCP_FLAG_WINDOW_SCALE) == 0)
				sender->scale = receiver->scale = 0;

			if (!(tcp_flags & RTE_CT_TCPHDR_ACK))
				/* Simultaneous open */
				return 1;
		} else {
			/*
			 * In the middle of a connection with no setup data.
			 * Use available data from the packet.
			 */
			sender->end = end;
			swin = win << sender->scale;
			sender->maxwin = (swin == 0 ? 1 : swin);
			sender->maxend = end + sender->maxwin;
			/*
			 * We haven't seen traffic in the other direction yet
			 * but we have to tweak window tracking to pass III
			 * and IV until that happens.
			 */
			if (receiver->maxwin == 0)
				receiver->end = receiver->maxend = sack;
		}
	}
	/* if sender unititialized */
	else if (((cd->ct_protocol.tcp_ct_data.state == RTE_CT_TCP_SYN_SENT &&
			 dir == RTE_CT_DIR_ORIGINAL) ||
			(cd->ct_protocol.tcp_ct_data.state == RTE_CT_TCP_SYN_RECV &&
			 dir == RTE_CT_DIR_REPLY)) && rte_after(end, sender->end)) {
		/*
		 * RFC 793: "if a TCP is reinitialized ... then it need
		 * not wait at all; it must only be sure to use sequence
		 * numbers larger than those recently used."
		 */
		sender->end = sender->maxend = end;
		sender->maxwin = RTE_MAX(win, (uint32_t)1);

		rte_ct_check_for_scaling_and_sack_perm(pkt, sender,
				ip_hdr_size);
	}
	/* If no ACK, just pretend there was.  */
	if (!(tcp_flags & RTE_CT_TCPHDR_ACK) ||
			(((tcp_flags & RTE_CT_TCPHDR_RST_ACK) ==
				RTE_CT_TCPHDR_RST_ACK) && (ack == 0))) {
		/* Bad TCP Stacks */
		ack = sack = receiver->end;
	}

	if ((tcp_flags & RTE_CT_TCPHDR_RST) && seq == 0 &&
			cd->ct_protocol.tcp_ct_data.state == RTE_CT_TCP_SYN_SENT)
		/* RST sent answering SYN. */
		seq = end = sender->end;

	/* Is the ending sequence in the receive window (if available)? */
	in_recv_win = !receiver->maxwin ||
			rte_after(end, sender->end - receiver->maxwin - 1);

	if (rte_before(seq, sender->maxend + 1) && in_recv_win &&
			rte_before(sack, receiver->end + 1) &&
			rte_after(sack,
				receiver->end - RTE_MAX(sender->maxwin,
					(uint32_t)RTE_MAX_ACKWIN_CONST) - 1)) {
		/*
		 * Apply window scaling (RFC 1323). Only valid if both
		 * directions sent this option in a SYN packet,
		 * so ignore until not a SYN packet. Scale will be
		 * set to zero if connection set up but no valid scale is there.
		 */
		if (!(tcp_flags & RTE_CT_TCPHDR_SYN))
			win <<= sender->scale;

		/* Update sender data. */
		swin = win + (sack - ack);
		sender->maxwin = RTE_MAX(sender->maxwin, swin);

		if (rte_after(end, sender->end)) {
			sender->end = end;
			sender->flags |= RTE_CT_TCP_FLAG_DATA_UNACKNOWLEDGED;
		}

		if (tcp_flags & RTE_CT_TCPHDR_ACK) {
			if (!(sender->flags & RTE_CT_TCP_FLAG_MAXACK_SET)) {
				sender->maxack = ack;
				sender->flags |= RTE_CT_TCP_FLAG_MAXACK_SET;
			} else if (rte_after(ack, sender->maxack))
				sender->maxack = ack;
		}

		/* Update receiver data. */
		if (receiver->maxwin != 0 && rte_after(end, sender->maxend))
			receiver->maxwin += end - sender->maxend;

		if (rte_after(sack + win, receiver->maxend - 1))
			receiver->maxend = sack + RTE_MAX(win, (uint32_t)1);

		if (ack == receiver->end)
			receiver->flags &= ~RTE_CT_TCP_FLAG_DATA_UNACKNOWLEDGED;

		/* If this packet has an ACK, it may be a retransmission.  */
		if (index == RTE_CT_TCP_ACK_FLAG)
			rte_ct_check_for_retransmissions(state, dir, seq, ack,
							 end, win);
		res = 1;
	} else {
		res = (sender->flags & RTE_CT_TCP_FLAG_BE_LIBERAL ||
					 ct->misc_options.tcp_be_liberal);
	}

	if (CT_DEBUG) {
		if (!res) {
			/* CT_DEBUG = 0; */
			printf("tcp_in_window FAILED for %p\n", cd);
			printf("rte_before(%u, %u + 1) is %d\n",
						 seq, sender->maxend + 1,
						 rte_before(seq, sender->maxend + 1));
			printf("!%u ||  rte_after(%u, %u - %u - 1) is %d\n",
						 receiver->maxwin, end, sender->end,
						 receiver->maxwin, in_recv_win);
			printf("rte_before(%u, %u + 1) is %d\n", sack,
						 receiver->end, rte_before(sack,
							 receiver->end + 1));
			printf
					("rte_after(%u,(%u - RTE_MAX(%u, %u) - 1))) is%d\n",
					 sack, receiver->end, sender->maxwin,
					 RTE_MAX_ACKWIN_CONST, rte_after(sack,
						 receiver->end - RTE_MAX(sender->maxwin,
							 (uint32_t)RTE_MAX_ACKWIN_CONST)
						 - 1));

		}
	}
	if (cd->ct_protocol.synproxy_data.synproxied)
		rte_sp_adjust_server_seq_after_window_check(cd, iphdr,
				tcpheader, dir);
	return res;
}

/*for the given two FSM states,return the one with the smallest timeout value*/
static inline uint8_t
rte_ct_choose_min_timeout_state(
	struct rte_ct_cnxn_tracker *ct,
	uint8_t state1,
	uint8_t state2)
{
	if (ct->ct_timeout.tcptimeout.tcp_timeouts[state1] <
			ct->ct_timeout.tcptimeout.tcp_timeouts[state2])
		return state1;
	else
		return state2;
}


/* Returns verdict for packet */
enum rte_ct_packet_action
rte_ct_verify_tcp_packet(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_ct_cnxn_data *cd,
	struct rte_mbuf *pkt,
	uint8_t key_was_flipped,
	uint8_t ip_hdr_size)
{
	struct tcp_hdr *tcpheader = (struct tcp_hdr *)
			RTE_MBUF_METADATA_UINT32_PTR(pkt, (IP_START + ip_hdr_size));

	enum rte_ct_tcp_states new_state, old_state;
	enum rte_ct_pkt_direction dir;
	uint8_t index;

	/* state whose timeout value will be used. In odd cases,
	 * not always current state */
	uint8_t timeout_state;

	dir = (cd->key_is_client_order == !key_was_flipped);

	if (cd->ct_protocol.synproxy_data.synproxied &&
		cd->ct_protocol.synproxy_data.half_established &&
		!cd->ct_protocol.synproxy_data.cnxn_established &&
		dir == RTE_CT_DIR_ORIGINAL) {
		/*
		 * Packet from client, but only client side of this connection
		 * has been set up. Buffer packet until server side of
		 * connection complete.
		 */
		rte_ct_buffer_packet(ct, cd, pkt);
		return RTE_CT_HIJACK;
	}

	uint32_t recv_ack = rte_bswap32(tcpheader->recv_ack);
	uint32_t sent_seq = rte_bswap32(tcpheader->sent_seq);

	int check_window = 1;
	enum rte_ct_packet_action return_action = RTE_CT_FORWARD_PACKET;

	/*  rte_ct_tcpdisplay_hdr(tcpheader); */

	old_state = cd->ct_protocol.tcp_ct_data.state;
	index = rte_ct_get_index(tcpheader->tcp_flags);
	new_state = rte_ct_tcp_state_table[dir][index][old_state];

	if (new_state == RTE_CT_TCP_MAX) {
		if (CT_DEBUG) {
			printf("!!!!invalid state transition from %s ",
					rte_ct_tcp_names[old_state]);
			printf("with flags 0x%02x\n",
					tcpheader->tcp_flags);
		}

		ct->counters->pkts_drop_invalid_state++;
		return RTE_CT_DROP_PACKET;
	}

	if (STATE_TRACKING && new_state != old_state)
		printf(" new state %s\n", rte_ct_tcp_names[new_state]);

	switch (new_state) {

	case RTE_CT_TCP_ESTABLISHED:

		if (cd->ct_protocol.synproxy_data.synproxied &&
				!cd->ct_protocol.synproxy_data.half_established &&
				(old_state == RTE_CT_TCP_SYN_RECV)) {
			/*
			 * During synproxy setup, ESTABLISHED state entered by
			 * ACK arriving from client. The proxy must now send a
			 * spoofed SYN to the server.
			 * Reset the state to RTE_CT_TCP_SYN_SENT.
			 */

			if (STATE_TRACKING) {
				printf(" synproxy first half-cnxn complete,");
				printf(" new state %s\n",
					rte_ct_tcp_names[RTE_CT_TCP_SYN_SENT]);
			}
			cd->ct_protocol.synproxy_data.half_established = true;

			rte_sp_cvt_to_spoofed_server_syn(cd, pkt);
			rte_ct_clear_cnxn_data(ct, cd, pkt);
			cd->ct_protocol.tcp_ct_data.state = RTE_CT_TCP_SYN_SENT;

			struct rte_ct_tcp_state *sender =
				&cd->ct_protocol.tcp_ct_data.
				seen[RTE_CT_DIR_ORIGINAL];
			uint16_t win = rte_bswap16(tcpheader->rx_win);

			sender->end = sender->maxend =
				rte_ct_seq_plus_length(pkt, ip_hdr_size);
			sender->maxwin = RTE_MAX(win, (uint32_t)1);
			rte_ct_check_for_scaling_and_sack_perm(pkt, sender,
					ip_hdr_size);
			/* TODO seq number code */
			rte_ct_set_cnxn_timer_for_tcp(ct, cd,
					RTE_CT_TCP_SYN_SENT);
			return RTE_CT_SEND_SERVER_SYN;
		}


	case RTE_CT_TCP_SYN_RECV:

		if (cd->ct_protocol.synproxy_data.synproxied &&
				cd->ct_protocol.synproxy_data.half_established &&
				!cd->ct_protocol.synproxy_data.cnxn_established) {
			/*
			 * The reply SYN/ACK has been received from the server.
			 * The connection can now be considered established,
			 * even though an ACK stills needs to be sent to
			 * the server.
			 */

			if (!rte_ct_tcp_in_window(cd, ct,
						&cd->ct_protocol.tcp_ct_data,
						dir, index, pkt, ip_hdr_size)) {
				ct->counters->pkts_drop_outof_window++;
				return RTE_CT_DROP_PACKET;
			}

			if (STATE_TRACKING) {
				printf("synproxy full cnxn complete,");
				printf(" new state %s\n", rte_ct_tcp_names
						[RTE_CT_TCP_ESTABLISHED]);
			}

			/*
			 * Convert the packet to an ack to return to the server.
			 * This routine also saves the real sequence number
			 * from the server.
			 */

			rte_sp_cvt_to_spoofed_server_ack(cd, pkt);

			index = rte_ct_get_index(tcpheader->tcp_flags);

			if (!rte_ct_tcp_in_window(cd, ct,
					&cd->ct_protocol.tcp_ct_data,
					!dir, index, pkt, ip_hdr_size)) {
				ct->counters->pkts_drop_outof_window++;
				return RTE_CT_DROP_PACKET;
			}

			/* good packets, OK to update state */

			cd->ct_protocol.tcp_ct_data.state =
				RTE_CT_TCP_ESTABLISHED;
			ct->counters->sessions_established++;
			cd->ct_protocol.synproxy_data.cnxn_established = true;
			cd->ct_protocol.tcp_ct_data.last_index = index;
			cd->ct_protocol.tcp_ct_data.last_dir = !dir;

			rte_ct_set_cnxn_timer_for_tcp(ct, cd,
					RTE_CT_TCP_ESTABLISHED);
			rte_ct_release_buffered_packets(ct, cd);

			return RTE_CT_SEND_SERVER_ACK;
		}

	case RTE_CT_TCP_SYN_SENT:

		/*
		 * A connection that is actively closed goes to TIME-WAIT state.
		 * It can be re-opened (before it times out) by a SYN packet.
		 */

		if (old_state < RTE_CT_TCP_TIME_WAIT)
			break;
		/*
		 * Due to previous check and state machine transitions,
		 * old state must be RTE_CT_TCP_TIME_WAIT or RTE_CT_TCP_CLOSE .
		 * Need to re-open connection.
		 */

		return RTE_CT_REOPEN_CNXN_AND_FORWARD_PACKET;

	case RTE_CT_TCP_IGNORE:

		/*
		 * Ignored packets usually mean the connection data is
		 * out of sync with client/server. Ignore, but forward
		 * these packets since they may be valid for the connection.
		 * If the ignored packet is invalid, the receiver will send
		 * an RST which should get the connection entry back in sync.
		 */

		/*
		 * However, if connection is running synproxy and the full
		 * connection is not yet established, there is no where
		 * for test packets to go so drop these packets.
		 */

		if (cd->ct_protocol.synproxy_data.synproxied &&
				!cd->ct_protocol.synproxy_data.cnxn_established)
			return RTE_CT_DROP_PACKET;

		if (index == RTE_CT_TCP_SAK_FLAG &&
				cd->ct_protocol.tcp_ct_data.last_index ==
				RTE_CT_TCP_SYN_FLAG
				&& cd->ct_protocol.tcp_ct_data.last_dir != dir
				&& recv_ack == cd->ct_protocol.tcp_ct_data.last_end) {
			/*
			 * SYN/ACK in reply direction acknowledging a SYN
			 * earlier ignored as invalid.Client and server in sync,
			 * but connection tracker is not. Use previous values
			 * to get back in sync.
			 */

			struct rte_ct_tcp_state *last_seen =
					&cd->ct_protocol.tcp_ct_data.seen[cd->ct_protocol.
										tcp_ct_data.
										last_dir];

			/* reset new and old states to what they should
			 * have been */
			old_state = RTE_CT_TCP_SYN_SENT;
			new_state = RTE_CT_TCP_SYN_RECV;

			last_seen->end = cd->ct_protocol.tcp_ct_data.last_end;
			last_seen->maxend =
					cd->ct_protocol.tcp_ct_data.last_end;
			last_seen->maxwin =
				RTE_MAX(cd->ct_protocol.tcp_ct_data.last_win,
						(uint32_t)1);
			last_seen->scale =
					cd->ct_protocol.tcp_ct_data.last_wscale;
			cd->ct_protocol.tcp_ct_data.last_flags &=
					~RTE_CT_EXP_CHALLENGE_ACK;
			last_seen->flags =
					cd->ct_protocol.tcp_ct_data.last_flags;
			memset(&cd->ct_protocol.tcp_ct_data.seen[dir], 0,
						 sizeof(struct rte_ct_tcp_state));
			break;
		}

		cd->ct_protocol.tcp_ct_data.last_index = index;
		cd->ct_protocol.tcp_ct_data.last_dir = dir;
		cd->ct_protocol.tcp_ct_data.last_seq = sent_seq;
		cd->ct_protocol.tcp_ct_data.last_end =
			rte_ct_seq_plus_length(pkt, ip_hdr_size);
		cd->ct_protocol.tcp_ct_data.last_win =
			rte_bswap16(tcpheader->rx_win);

		/*
		 * An orinal SYN. Client and the server may be in sync, but
		 * the tracker is not . Annotate
		 * the TCP options and let the packet go through. If it is a
		 * valid SYN packet, the server will reply with a SYN/ACK, and
		 * then we'll get in sync. Otherwise, the server potentially
		 * responds with a challenge ACK if implementing RFC5961.
		 */
		if (index == RTE_CT_TCP_SYN_FLAG &&
				dir == RTE_CT_DIR_ORIGINAL) {
			struct rte_ct_tcp_state seen;

			/* call following to set "flag" and "scale" fields */
			rte_ct_check_for_scaling_and_sack_perm(pkt, &seen,
					ip_hdr_size);

			/* only possible flags set for scling and sack */
			cd->ct_protocol.tcp_ct_data.last_flags = seen.flags;
			cd->ct_protocol.tcp_ct_data.last_wscale =
			(seen.flags & RTE_CT_TCP_FLAG_WINDOW_SCALE) == 0 ?
					0 : seen.scale;

			/*
			 * Mark the potential for RFC5961 challenge ACK,
			 * this pose a special problem for LAST_ACK state
			 * as ACK is intrepretated as ACKing last FIN.
			 */
			if (old_state == RTE_CT_TCP_LAST_ACK)
				cd->ct_protocol.tcp_ct_data.last_flags |=
					RTE_CT_EXP_CHALLENGE_ACK;
		}
		return RTE_CT_FORWARD_PACKET;

	case RTE_CT_TCP_TIME_WAIT:
		/*
		 * RFC5961 compliance cause stack to send "challenge-ACK" in
		 * response to unneeded SYNs. Do not treat this as acking
		 * last FIN.
		 */
		if (old_state == RTE_CT_TCP_LAST_ACK &&
				index == RTE_CT_TCP_ACK_FLAG &&
				cd->ct_protocol.tcp_ct_data.last_dir != dir &&
				cd->ct_protocol.tcp_ct_data.last_index ==
				RTE_CT_TCP_SYN_FLAG
				&& (cd->ct_protocol.tcp_ct_data.
			last_flags & RTE_CT_EXP_CHALLENGE_ACK)) {
			/* Detected RFC5961 challenge ACK */
			cd->ct_protocol.tcp_ct_data.last_flags &=
				~RTE_CT_EXP_CHALLENGE_ACK;
			return RTE_CT_FORWARD_PACKET;	/* Don't change state */
		}
		break;

	case RTE_CT_TCP_CLOSE:

		if (index == RTE_CT_TCP_RST_FLAG) {
			/*
			 * Can only transition to CLOSE state with an RST,
			 * but can remain in
			 * CLOSE state with ACK, FIN, or RST. Do special checks.
			 */

			if ((cd->ct_protocol.tcp_ct_data.seen[!dir].flags &
						RTE_CT_TCP_FLAG_MAXACK_SET) &&
					rte_before(sent_seq, cd->ct_protocol.
					tcp_ct_data.seen[!dir].maxack)) {

				ct->counters->pkts_drop_invalid_rst++;
				/* Invalid RST  */
				return RTE_CT_DROP_PACKET;
			}

			if (((cd->connstatus == RTE_SEEN_REPLY_CONN &&
						cd->ct_protocol.tcp_ct_data.last_index ==
							RTE_CT_TCP_SYN_FLAG) ||
				(cd->connstatus != RTE_ASSURED_CONN &&
				cd->ct_protocol.tcp_ct_data.last_index ==
							RTE_CT_TCP_ACK_FLAG)) &&
				recv_ack ==
					cd->ct_protocol.tcp_ct_data.last_end) {
				/* RST sent to invalid SYN or ACK previously
				 * let through */
				check_window = 0;
			}
		}
		break;

	default:
		break;
	}

	if (likely(check_window)) {
		if (unlikely(!rte_ct_tcp_in_window(cd, ct,
						&cd->ct_protocol.tcp_ct_data,
						dir, index,
						pkt, ip_hdr_size))) {
			ct->counters->pkts_drop_outof_window++;
			return RTE_CT_DROP_PACKET;
		}
	}

	if (new_state == RTE_CT_TCP_ESTABLISHED &&
			old_state != RTE_CT_TCP_ESTABLISHED)
		/* only increment for first state transition to established */
		/* synproxy established count handled elswhere */
		ct->counters->sessions_established++;
	/* From this point on, all packets are in-window */
	cd->ct_protocol.tcp_ct_data.last_index = index;
	cd->ct_protocol.tcp_ct_data.last_dir = dir;

	if (index == RTE_CT_TCP_SAK_FLAG)
		cd->connstatus = RTE_SEEN_REPLY_CONN;

	timeout_state = new_state;

	if (cd->ct_protocol.tcp_ct_data.retrans >=
			ct->misc_options.tcp_max_retrans)
		timeout_state =
			rte_ct_choose_min_timeout_state(ct, timeout_state,
					RTE_CT_TCP_RETRANS);
	else if (rte_ct_either_direction_has_flags(cd,
				RTE_CT_TCP_FLAG_DATA_UNACKNOWLEDGED))
		timeout_state =
			rte_ct_choose_min_timeout_state(ct, timeout_state,
					RTE_CT_TCP_UNACK);

	if (cd->connstatus != RTE_SEEN_REPLY_CONN) {
		if (tcpheader->tcp_flags & RTE_CT_TCPHDR_RST) {
			/*
			 * if only reply seen is RST, there is not an
			 * established connection, so just destroy
			 * connection now.
			 */

			return RTE_CT_DESTROY_CNXN_AND_FORWARD_PACKET;
		}
		/* ESTABLISHED without SEEN_REPLY, i.e. mid-connection
			 pickup with loose=1. Avoid large ESTABLISHED timeout. */
		if (new_state == RTE_CT_TCP_ESTABLISHED)
			timeout_state = rte_ct_choose_min_timeout_state(ct,
					timeout_state,
					RTE_CT_TCP_UNACK);

	} else if (cd->connstatus != RTE_ASSURED_CONN &&
			 (old_state == RTE_CT_TCP_SYN_RECV
				|| old_state == RTE_CT_TCP_ESTABLISHED)
			 && new_state == RTE_CT_TCP_ESTABLISHED)
		cd->connstatus = RTE_ASSURED_CONN;

	cd->ct_protocol.tcp_ct_data.state = new_state;
	rte_ct_set_cnxn_timer_for_tcp(ct, cd, timeout_state);

	return return_action;
}
