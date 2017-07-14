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

#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_eth_ctrl.h>

#include "log.h"
#include "genl4_stream_tcp.h"
#include "prox_assert.h"
#include "mbuf_utils.h"

static uint64_t tcp_retx_timeout(const struct stream_ctx *ctx)
{
	uint64_t delay = token_time_tsc_until_full(&ctx->token_time_other);

	return delay + ctx->stream_cfg->tsc_timeout;
}

static uint64_t tcp_resched_timeout(const struct stream_ctx *ctx)
{
	uint64_t delay = token_time_tsc_until_full(&ctx->token_time);

	return delay;
}

static void tcp_retx_timeout_start(struct stream_ctx *ctx, uint64_t *next_tsc)
{
	uint64_t now = rte_rdtsc();

	*next_tsc = tcp_retx_timeout(ctx);
	ctx->sched_tsc = now + *next_tsc;
}

static int tcp_retx_timeout_occured(const struct stream_ctx *ctx, uint64_t now)
{
	return ctx->sched_tsc < now;
}

static void tcp_retx_timeout_resume(const struct stream_ctx *ctx, uint64_t now, uint64_t *next_tsc)
{
	*next_tsc = ctx->sched_tsc - now;
}

static void tcp_set_retransmit(struct stream_ctx *ctx)
{
	ctx->retransmits++;
}

struct tcp_option {
	uint8_t kind;
	uint8_t len;
} __attribute__((packed));

void stream_tcp_create_rst(struct rte_mbuf *mbuf, struct l4_meta *l4_meta, struct pkt_tuple *tuple)
{
	struct tcp_hdr *tcp = (struct tcp_hdr *)l4_meta->l4_hdr;
	struct ipv4_hdr *ip = ((struct ipv4_hdr *)tcp) - 1;

	ip->src_addr = tuple->dst_addr;
	ip->dst_addr = tuple->src_addr;

	tcp->dst_port = tuple->src_port;
	tcp->src_port = tuple->dst_port;

	ip->total_length = rte_bswap16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr));
	tcp->tcp_flags = TCP_RST_FLAG;
	tcp->data_off = ((sizeof(struct tcp_hdr) / 4) << 4);
	rte_pktmbuf_pkt_len(mbuf) = l4_meta->payload - rte_pktmbuf_mtod(mbuf, uint8_t *);
	rte_pktmbuf_data_len(mbuf) = l4_meta->payload - rte_pktmbuf_mtod(mbuf, uint8_t *);
}

static void create_tcp_pkt(struct stream_ctx *ctx, struct rte_mbuf *mbuf, uint8_t tcp_flags, int data_beg, int data_len)
{
	uint8_t *pkt;

	const struct peer_action *act = &ctx->stream_cfg->actions[ctx->cur_action];
	const struct stream_cfg *stream_cfg = ctx->stream_cfg;

	pkt = rte_pktmbuf_mtod(mbuf, uint8_t *);
	rte_memcpy(pkt, stream_cfg->data[act->peer].hdr, stream_cfg->data[act->peer].hdr_len);

	struct ipv4_hdr *l3_hdr = (struct ipv4_hdr*)&pkt[stream_cfg->data[act->peer].hdr_len - sizeof(struct ipv4_hdr)];
	struct tcp_hdr *l4_hdr = (struct tcp_hdr *)&pkt[stream_cfg->data[act->peer].hdr_len];

	l3_hdr->src_addr = ctx->tuple->dst_addr;
	l3_hdr->dst_addr = ctx->tuple->src_addr;
	l3_hdr->next_proto_id = IPPROTO_TCP;

	l4_hdr->src_port = ctx->tuple->dst_port;
	l4_hdr->dst_port = ctx->tuple->src_port;

	uint32_t tcp_len = sizeof(struct tcp_hdr);
	uint32_t tcp_payload_len = 0;
	uint32_t seq_len = 0;
	struct tcp_option *tcp_op;

	if (tcp_flags & TCP_RST_FLAG) {
		tcp_flags |= TCP_RST_FLAG;
		seq_len = 1;
	}
	else if (tcp_flags & TCP_SYN_FLAG) {
		tcp_flags |= TCP_SYN_FLAG;
		/* Window scaling */

		/* TODO: make options come from the stream. */
		tcp_op = (struct tcp_option *)(l4_hdr + 1);

		tcp_op->kind = 2;
		tcp_op->len = 4;
		*(uint16_t *)(tcp_op + 1) = rte_bswap16(1460); /* TODO: Save this in this_mss */

		tcp_len += 4;
		seq_len = 1;

		ctx->seq_first_byte = ctx->ackd_seq + 1;
	}
	else if (tcp_flags & TCP_FIN_FLAG) {
		tcp_flags |= TCP_FIN_FLAG;
		seq_len = 1;
	}

	if (tcp_flags & TCP_ACK_FLAG) {
		l4_hdr->recv_ack = rte_bswap32(ctx->recv_seq);
		tcp_flags |= TCP_ACK_FLAG;
	}
	else
		l4_hdr->recv_ack = 0;

	uint16_t l4_payload_offset = stream_cfg->data[act->peer].hdr_len + tcp_len;

	if (data_len) {
		seq_len = data_len;
		plogx_dbg("l4 payload offset = %d\n", l4_payload_offset);
		rte_memcpy(pkt + l4_payload_offset, stream_cfg->data[act->peer].content + data_beg, data_len);
	}

	l4_hdr->sent_seq = rte_bswap32(ctx->next_seq);
	l4_hdr->tcp_flags = tcp_flags; /* SYN */
	l4_hdr->rx_win = rte_bswap16(0x3890); // TODO: make this come from stream (config)
	//l4_hdr->cksum = ...;
	l4_hdr->tcp_urp = 0;
	l4_hdr->data_off = ((tcp_len / 4) << 4); /* Highest 4 bits are TCP header len in units of 32 bit words */

	/* ctx->next_seq = ctx->ackd_seq + seq_len; */
	ctx->next_seq += seq_len;

	/* No payload after TCP header. */
	rte_pktmbuf_pkt_len(mbuf)  = l4_payload_offset + data_len;
	rte_pktmbuf_data_len(mbuf) = l4_payload_offset + data_len;

	l3_hdr->total_length = rte_bswap16(sizeof(struct ipv4_hdr) + tcp_len + data_len);
	plogdx_dbg(mbuf, NULL);

	plogx_dbg("put tcp packet with flags: %s%s%s, (len = %d, seq = %d, ack =%d)\n",
		  tcp_flags & TCP_SYN_FLAG? "SYN ":"",
		  tcp_flags & TCP_ACK_FLAG? "ACK ":"",
		  tcp_flags & TCP_FIN_FLAG? "FIN ":"",
		  data_len, rte_bswap32(l4_hdr->sent_seq), rte_bswap32(l4_hdr->recv_ack));
}

/* Get the length of the reply associated for the next packet. Note
   that the packet will come from the other peer. In case the next
   packet belongs to the current peer (again), the reply length will
   be that of an empty TCP packet (i.e. the ACK). */
uint16_t stream_tcp_reply_len(struct stream_ctx *ctx)
{
	if (stream_tcp_is_ended(ctx))
		return 0;
	else if (ctx->tcp_state != ESTABLISHED) {
		if (ctx->tcp_state == SYN_SENT || ctx->tcp_state == LISTEN) {
			/* First packet received is a SYN packet. In
			   the current implementation this packet
			   contains the TCP option field to set the
			   MSS. For this, add 4 bytes. */
			return ctx->stream_cfg->data[!ctx->peer].hdr_len + sizeof(struct tcp_hdr) + 4;
		}
		return ctx->stream_cfg->data[!ctx->peer].hdr_len + sizeof(struct tcp_hdr);
	}
	else if (ctx->stream_cfg->actions[ctx->cur_action].peer == ctx->peer) {
		/* The reply _could_ (due to races, still possibly
		   receive an old ack) contain data. This means that
		   in some cases, the prediction of the reply size
		   will be an overestimate. */
		uint32_t data_beg = ctx->next_seq - ctx->seq_first_byte;
		const struct peer_action *act = &ctx->stream_cfg->actions[ctx->cur_action];

		uint32_t remaining_len = act->len - (data_beg - act->beg);

		if (remaining_len == 0) {
			if (ctx->cur_action + 1 != ctx->stream_cfg->n_actions) {
				if (ctx->stream_cfg->actions[ctx->cur_action + 1].peer == ctx->peer)
					return ctx->stream_cfg->data[ctx->peer].hdr_len + sizeof(struct tcp_hdr);
				else {
					uint32_t seq_beg = ctx->recv_seq - ctx->other_seq_first_byte;
					uint32_t end = ctx->stream_cfg->actions[ctx->cur_action + 1].beg +
						ctx->stream_cfg->actions[ctx->cur_action + 1].len;
					uint32_t remaining = end - seq_beg;
					uint16_t data_len = remaining > 1460? 1460: remaining;

					return ctx->stream_cfg->data[!ctx->peer].hdr_len + sizeof(struct tcp_hdr) + data_len;
				}
			}
			else {
				return ctx->stream_cfg->data[ctx->peer].hdr_len + sizeof(struct tcp_hdr);
			}
		}
		else {
			return ctx->stream_cfg->data[ctx->peer].hdr_len + sizeof(struct tcp_hdr);
		}
	}
	else if (ctx->stream_cfg->actions[ctx->cur_action].peer != ctx->peer) {
		uint32_t seq_beg = ctx->recv_seq - ctx->other_seq_first_byte;
		uint32_t end = ctx->stream_cfg->actions[ctx->cur_action].beg +
			ctx->stream_cfg->actions[ctx->cur_action].len;
		uint32_t remaining = end - seq_beg;
		uint16_t data_len = remaining > 1460? 1460: remaining;

		return ctx->stream_cfg->data[!ctx->peer].hdr_len + sizeof(struct tcp_hdr) + data_len;
	}
	else
		return ctx->stream_cfg->data[ctx->peer].hdr_len + sizeof(struct tcp_hdr);
}

static void stream_tcp_proc_in_order_data(struct stream_ctx *ctx, struct l4_meta *l4_meta, int *progress_seq)
{
	plogx_dbg("Got data with seq %d (as expected), with len %d\n", ctx->recv_seq, l4_meta->len);

	if (!l4_meta->len)
		return;

	const struct peer_action *act = &ctx->stream_cfg->actions[ctx->cur_action];
	enum l4gen_peer peer = act->peer;
	/* Since we have received the expected sequence number, the start address will not exceed the cfg memory buffer. */
	uint8_t *content = ctx->stream_cfg->data[peer].content;
	uint32_t seq_beg = ctx->recv_seq - ctx->other_seq_first_byte;
	uint32_t end = ctx->stream_cfg->actions[ctx->cur_action].beg + ctx->stream_cfg->actions[ctx->cur_action].len;
	uint32_t remaining = end - seq_beg;

	if (l4_meta->len > remaining) {
		plogx_err("Provided data is too long:\n");
		plogx_err("action.beg = %d, action.len = %d", act->beg, act->len);
		plogx_err("tcp seq points at %d in action, l4_meta->len = %d\n", seq_beg, l4_meta->len);
	}
	else {
		if (memcmp(content + seq_beg, l4_meta->payload, l4_meta->len) == 0) {
			plogx_dbg("Good payload in %d: %u -> %u\n", ctx->cur_action, ctx->recv_seq, l4_meta->len);
			ctx->recv_seq += l4_meta->len;
			ctx->cur_pos[peer] += l4_meta->len;
			/* Move forward only when this was the last piece of data within current action (i.e. end of received data == end of action data). */
			if (seq_beg + l4_meta->len == act->beg + act->len) {
				plogx_dbg("Got last piece in action %d\n", ctx->cur_action);
				ctx->cur_action++;
			}
			else {
				plogx_dbg("Got data from %d with len %d, but waiting for more (tot len = %d)!\n", seq_beg, l4_meta->len, act->len);
			}
			*progress_seq = 1;
			ctx->flags |= STREAM_CTX_F_NEW_DATA;
		}
		else {
			plogx_err("ackable = %d, ackd = %d\n", ctx->ackable_data_seq ,ctx->ackd_seq);
			plogx_err("Bad payload action[%d]{.len = %d, .peer  = %s}\n", ctx->cur_action, act->len, peer == PEER_SERVER? "s" : "c");
			plogx_err("   pkt payload len = %d, beginning at %u\n", l4_meta->len, seq_beg);
			/* plogx_err("   Payload starts %zu bytes after beginning of l4_hdr\n", l4_meta->payload - l4_meta->l4_hdr); */

			plogx_err("   payload[0-3] = %02x %02x %02x %02x\n",
				  l4_meta->payload[0],
				  l4_meta->payload[1],
				  l4_meta->payload[2],
				  l4_meta->payload[3]);
			plogx_err("   expect[0-3]  = %02x %02x %02x %02x\n",
				  content[seq_beg + 0],
				  content[seq_beg + 1],
				  content[seq_beg + 2],
				  content[seq_beg + 3]);
		}
	}
}

static int stream_tcp_proc_in(struct stream_ctx *ctx, struct l4_meta *l4_meta)
{
	struct tcp_hdr *tcp = NULL;
	int got_syn = 0;
	int got_ack = 0;
	int got_fin = 0;
	int got_rst = 0;

	tcp = (struct tcp_hdr *)l4_meta->l4_hdr;

	got_syn = tcp->tcp_flags & TCP_SYN_FLAG;
	got_ack = tcp->tcp_flags & TCP_ACK_FLAG;
	got_fin = tcp->tcp_flags & TCP_FIN_FLAG;
	got_rst = tcp->tcp_flags & TCP_RST_FLAG;
	plogx_dbg("TCP, flags: %s%s%s, (len = %d, seq = %d, ack =%d)\n", got_syn? "SYN ":"", got_ack? "ACK ":"", got_fin? "FIN " : "", l4_meta->len, rte_bswap32(tcp->sent_seq), rte_bswap32(tcp->recv_ack));

	if (got_syn)
		ctx->flags |= STREAM_CTX_F_TCP_GOT_SYN;
	if (got_fin)
		ctx->flags |= STREAM_CTX_F_TCP_GOT_FIN;

	int progress_ack = 0, progress_seq = 0;

	/* RST => other side wants to terminate due to
	   inconsitent state (example: delay of retransmit of
	   last ACK while other side already closed the
	   connection. The other side will accept the packet
	   as a beginning of a new connection but there will
	   be no SYN. ) */
	if (got_rst) {
		plogx_dbg("got rst\n");
		ctx->flags |= STREAM_CTX_F_TCP_ENDED;
		return -1;
	}

	if (got_ack) {
		uint32_t ackd_seq = rte_bswap32(tcp->recv_ack);

		if (ackd_seq > ctx->ackd_seq) {
			plogx_dbg("Got ACK for outstanding data, from %d to %d\n", ctx->ackd_seq, ackd_seq);
			ctx->ackd_seq = ackd_seq;
			plogx_dbg("ackable data = %d\n", ctx->ackable_data_seq);
			/* Ackable_data_seq set to byte after
			   current action. */
			if (ctx->ackable_data_seq == ctx->ackd_seq) {
				/* Due to retransmit in
				   combination with late acks,
				   is is possible to ack
				   future data. In this case,
				   the assumption that data
				   was lost is not true and
				   the next seq is moved
				   forward. */
				if (ctx->next_seq < ctx->ackable_data_seq) {
					ctx->next_seq = ctx->ackable_data_seq;
				}

				ctx->ackable_data_seq = 0;
				const struct stream_cfg *stream_cfg = ctx->stream_cfg;
				const struct peer_action *act = &stream_cfg->actions[ctx->cur_action];

				ctx->cur_pos[act->peer] += act->len;
				ctx->cur_action++;
				plogx_dbg("Moving to next action %u\n", ctx->ackd_seq);
			}
			progress_ack = 1;
		}
		else {
			plogx_dbg("Old data acked: acked = %d, ackable =%d\n", ackd_seq, ctx->ackd_seq);
		}
	}

	uint32_t seq = rte_bswap32(tcp->sent_seq);

	/* update recv_seq. */
	if (got_syn) {
		/* When a syn is received, immediately reset recv_seq based on seq from packet. */
		ctx->recv_seq = seq + 1;
		/* Syn packets have length 1, so the first real data will start after that. */
		ctx->other_seq_first_byte = seq + 1;
		progress_seq = 1;
	}
	else if (got_fin) {
		if (ctx->recv_seq == seq) {
			plogx_dbg("Got fin with correct seq\n");
			ctx->recv_seq = seq + 1;
			progress_seq = 1;
		}
		else {
			plogx_dbg("Got fin but incorrect seq\n");
		}
	}
	else {
		/* Only expect in-order packets. */
		if (ctx->recv_seq == seq) {
			stream_tcp_proc_in_order_data(ctx, l4_meta, &progress_seq);
		}
		else if (ctx->recv_seq < seq) {
			plogx_dbg("Future data received (got = %d, expected = %d), missing data! (data ignored)\n", seq, ctx->recv_seq);
		}
		else {
			plogx_dbg("Old data received again (state = %s)\n", tcp_state_to_str(ctx->tcp_state));
			plogx_dbg("expecting seq %d, got seq %d, len = %d\n",ctx->recv_seq, seq, l4_meta->len);
			plogx_dbg("ackd_seq = %d, next_seq = %d, action = %d\n", ctx->ackd_seq, ctx->next_seq, ctx->cur_action);
		}
	}

	/* parse options */
	if (((tcp->data_off >> 4)*4) > sizeof(struct tcp_hdr)) {
		struct tcp_option *tcp_op = (struct tcp_option *)(tcp + 1);
		uint8_t *payload = (uint8_t *)tcp + ((tcp->data_off >> 4)*4);

		do {
			if (tcp_op->kind == 2 && tcp_op->len == 4) {
				uint16_t mss = rte_bswap16(*(uint16_t *)(tcp_op + 1));
				ctx->other_mss = mss;
			}

			tcp_op = (struct tcp_option *)(((uint8_t*)tcp_op) + tcp_op->len);
		} while (((uint8_t*)tcp_op) < payload);
	}

	if (progress_ack || progress_seq) {
		ctx->same_state = 0;
		ctx->flags |= STREAM_CTX_F_LAST_RX_PKT_MADE_PROGRESS;
	}
	else {
		ctx->flags &= ~STREAM_CTX_F_LAST_RX_PKT_MADE_PROGRESS;
	}
	return 0;
}

static int stream_tcp_proc_out_closed(struct stream_ctx *ctx, struct rte_mbuf *mbuf, uint64_t *next_tsc)
{
	uint64_t wait_tsc = token_time_tsc_until_full(&ctx->token_time);

	if (wait_tsc != 0) {
		*next_tsc = wait_tsc;
		return -1;
	}

	/* create SYN packet in mbuf, return 0. goto SYN_SENT, set timeout */
	ctx->tcp_state = SYN_SENT;

	/* Initialize: */
	ctx->next_seq = 99;
	ctx->ackd_seq = 99;

	create_tcp_pkt(ctx, mbuf, TCP_SYN_FLAG, 0, 0);
	token_time_take(&ctx->token_time, mbuf_wire_size(mbuf));
	*next_tsc = tcp_retx_timeout(ctx);
	return 0;
}

static int stream_tcp_proc_out_listen(struct stream_ctx *ctx, struct rte_mbuf *mbuf, uint64_t *next_tsc)
{
	uint64_t wait_tsc = token_time_tsc_until_full(&ctx->token_time);

	if (wait_tsc != 0) {
		*next_tsc = wait_tsc;
		return -1;
	}

	if (!(ctx->flags & STREAM_CTX_F_TCP_GOT_SYN)) {
		// TODO: keep connection around at end to catch retransmits from client
		plogx_dbg("Got packet while listening without SYN (will send RST)\n");
		pkt_tuple_debug(ctx->tuple);

		ctx->flags |= STREAM_CTX_F_TCP_ENDED;
		create_tcp_pkt(ctx, mbuf, TCP_RST_FLAG, 0, 0);
		token_time_take(&ctx->token_time, mbuf_wire_size(mbuf));
		*next_tsc = tcp_retx_timeout(ctx);
		return 0;
	}

	/* if syn received _now_, send ack + syn. goto SYN_RECEIVED. */
	plogx_dbg("Got packet while listen\n");

	ctx->next_seq = 200;
	ctx->ackd_seq = 200;

	ctx->tcp_state = SYN_RECEIVED;

	create_tcp_pkt(ctx, mbuf, TCP_SYN_FLAG | TCP_ACK_FLAG, 0, 0);
	token_time_take(&ctx->token_time, mbuf_wire_size(mbuf));
	*next_tsc = tcp_retx_timeout(ctx);
	return 0;
}

static int stream_tcp_proc_out_syn_sent(struct stream_ctx *ctx, struct rte_mbuf *mbuf, uint64_t *next_tsc)
{
	uint64_t wait_tsc = token_time_tsc_until_full(&ctx->token_time);

	if (wait_tsc != 0) {
		*next_tsc = wait_tsc;
		return -1;
	}

	if (ctx->ackd_seq < ctx->next_seq || !(ctx->flags & STREAM_CTX_F_TCP_GOT_SYN)) {
		plogx_dbg("Retransmit SYN\n");
		/* Did not get packet, send syn again and keep state (waiting for ACK). */
		++ctx->same_state;
		tcp_set_retransmit(ctx);
		return stream_tcp_proc_out_closed(ctx, mbuf, next_tsc);
	}

	plogx_dbg("SYN_SENT and everything ACK'ed\n");
	plogx_dbg("ackd_seq = %d, next_seq = %d\n", ctx->ackd_seq, ctx->next_seq);

	/* If syn received for this stream, send ack and goto
	   ESTABLISHED. If first peer is this peer to send actual
	   data, schedule immediately. */

	ctx->same_state = 0;
	ctx->tcp_state = ESTABLISHED;

	/* third packet of three-way handshake will also contain
	   data. Don't send separate ACK yet. TODO: only send ACK if
	   data has not yet been ACK'ed. */
	if (ctx->stream_cfg->actions[ctx->cur_action].peer == ctx->peer) {
		*next_tsc = tcp_resched_timeout(ctx);
		plogx_dbg("immediately resched (%d)\n", ctx->cur_action);
		return -1;
	}
	else {
		create_tcp_pkt(ctx, mbuf, TCP_ACK_FLAG, 0, 0);
		token_time_take(&ctx->token_time, mbuf_wire_size(mbuf));
		*next_tsc = tcp_retx_timeout(ctx);
	}
	return 0;
}

static int stream_tcp_proc_out_syn_recv(struct stream_ctx *ctx, struct rte_mbuf *mbuf, uint64_t *next_tsc)
{
	uint64_t wait_tsc = token_time_tsc_until_full(&ctx->token_time);

	if (wait_tsc != 0) {
		*next_tsc = wait_tsc;
		return -1;
	}

	if (ctx->ackd_seq == ctx->next_seq) {
		/* Possible from server side with ctx->cur_action == 1
		   if the current packet received had ACK for syn from
		   server to client and also data completing the first
		   action. */

		ctx->same_state = 0;
		ctx->tcp_state = ESTABLISHED;
		if (ctx->stream_cfg->actions[ctx->cur_action].peer != ctx->peer) {
			create_tcp_pkt(ctx, mbuf, TCP_ACK_FLAG, 0, 0);
			token_time_take(&ctx->token_time, mbuf_wire_size(mbuf));
			*next_tsc = tcp_retx_timeout(ctx);
			return 0;
		}
		else {
			/* While at this point, an ACK without data
			   any could be sent by the server, it is not
			   really required because the next pacekt
			   after reschedule will also contain an ACK
			   along with new data.

			   In this implementation, if this is the
			   case, the client is not only expecting an
			   ACK, but also actual data. For this reason,
			   the empty ACK packet should not be sent,
			   otherwise the client will retransmit its
			   data.
			*/

			/* create_tcp_pkt(ctx, mbuf, TCP_ACK_FLAG, 0, 0); */
			/* token_time_take(&ctx->token_time, mbuf_wire_size(mbuf)); */
			*next_tsc = tcp_resched_timeout(ctx);
			return -1;
		}
	}
	else {
		/* Either this portion is executed due to a time-out
		   or due to packet reception, the SYN that has been
		   sent is not yet ACK'ed. So, retransmit the SYN/ACK. */
		plogx_dbg("Retransmit SYN/ACK\n");
		++ctx->same_state;
		tcp_set_retransmit(ctx);
		ctx->next_seq = ctx->ackd_seq;
		create_tcp_pkt(ctx, mbuf, TCP_SYN_FLAG | TCP_ACK_FLAG, 0, 0);
		token_time_take(&ctx->token_time, mbuf_wire_size(mbuf));
		*next_tsc = tcp_retx_timeout(ctx);
		return 0;
	}
}

static int stream_tcp_proc_out_estab_tx(struct stream_ctx *ctx, struct rte_mbuf *mbuf, uint64_t *next_tsc)
{
	uint64_t wait_tsc = token_time_tsc_until_full(&ctx->token_time);

	if (wait_tsc != 0) {
		*next_tsc = wait_tsc;
		return -1;
	}

	const struct peer_action *act = &ctx->stream_cfg->actions[ctx->cur_action];

	if (act->len == 0) {
		plogx_dbg("Closing connection\n");
		/* This would be an ACK combined with FIN. To
		   send a separate ack. keep the state in
		   established, put_ack and expire
		   immediately*/
		plogx_dbg("Moving to FIN_WAIT\n");
		ctx->tcp_state = FIN_WAIT;
		ctx->same_state = 0;
		create_tcp_pkt(ctx, mbuf, TCP_FIN_FLAG | TCP_ACK_FLAG, 0, 0);
		token_time_take(&ctx->token_time, mbuf_wire_size(mbuf));
		*next_tsc = tcp_retx_timeout(ctx);
		return 0;
	}
	/* remaining_len2 will be zero, while in case of
	   act->len == 0, the connection can be closed
	   immediately. */

	plogx_dbg("This peer to send!\n");
	uint32_t outstanding_bytes = ctx->next_seq - ctx->ackd_seq;

	uint32_t data_beg2 = ctx->next_seq - ctx->seq_first_byte;
	uint32_t remaining_len2 = act->len - (data_beg2 - act->beg);

	const uint32_t rx_win = 300000;
	/* If still data to be sent and allowed by outstanding amount */
	if (outstanding_bytes <= rx_win && remaining_len2) {
		plogx_dbg("Outstanding bytes = %d, and remaining_len = %d, next_seq = %d\n", outstanding_bytes, remaining_len2, ctx->next_seq);

		if (ctx->ackable_data_seq == 0) {
			PROX_ASSERT(outstanding_bytes == 0);

			ctx->ackable_data_seq = ctx->next_seq + act->len;
		}
		else
			plogx_dbg("This will not be the first part of the data within an action\n");
	}
	/* still data yet to be acked || still data to be sent but blocked by RX win. */
	else {
		if (ctx->flags & STREAM_CTX_F_MORE_DATA) {
			/* Don't send any packet. */
			ctx->flags &= ~STREAM_CTX_F_MORE_DATA;
			*next_tsc = tcp_retx_timeout(ctx);
			ctx->sched_tsc = rte_rdtsc() + *next_tsc;
			return -1;
		}
		else {
			uint64_t now = rte_rdtsc();

			if ((ctx->flags & STREAM_CTX_F_LAST_RX_PKT_MADE_PROGRESS) && token_time_tsc_until_full(&ctx->token_time_other) != 0) {
				tcp_retx_timeout_start(ctx, next_tsc);
				ctx->flags &= ~STREAM_CTX_F_LAST_RX_PKT_MADE_PROGRESS;
				return -1;
			}
			/* This function might be called due to packet
			   reception. In that case, cancel here and
			   wait until the timeout really occurs before
			   reTX. */
			if (!tcp_retx_timeout_occured(ctx, now)) {
				tcp_retx_timeout_resume(ctx, now, next_tsc);
				return -1;
			}

			ctx->same_state++;
			tcp_set_retransmit(ctx);
			/* This possibly means that now retransmit is resumed half-way in the action. */
			plogx_dbg("Retransmit: outstanding = %d\n", outstanding_bytes);
			plogx_dbg("Assuming %d->%d lost\n", ctx->ackd_seq, ctx->next_seq);
			ctx->next_seq = ctx->ackd_seq;
			plogx_dbg("highest seq from other side = %d\n", ctx->recv_seq);
		}
		/* When STREAM_CTX_F_MORE_DATA is set, real timeouts
		   can't occur. If this is needed, timeouts
		   need to carry additional information. */
	}

	/* The following code will retransmit the same data if next_seq is not moved forward. */
	uint32_t data_beg = ctx->next_seq - ctx->seq_first_byte;
	uint32_t remaining_len = act->len - (data_beg - act->beg);
	uint32_t data_len = remaining_len > ctx->other_mss? ctx->other_mss: remaining_len;
	if (data_len == 0)
		plogx_warn("data_len == 0\n");

	if (remaining_len > ctx->other_mss)
		ctx->flags |= STREAM_CTX_F_MORE_DATA;
	else
		ctx->flags &= ~STREAM_CTX_F_MORE_DATA;

	create_tcp_pkt(ctx, mbuf, TCP_ACK_FLAG, data_beg, data_len);
	token_time_take(&ctx->token_time, mbuf_wire_size(mbuf));
	if (ctx->flags & STREAM_CTX_F_MORE_DATA)
		*next_tsc = tcp_resched_timeout(ctx);
	else
		tcp_retx_timeout_start(ctx, next_tsc);

	return 0;
}

static int stream_tcp_proc_out_estab_rx(struct stream_ctx *ctx, struct rte_mbuf *mbuf, uint64_t *next_tsc)
{
	uint64_t wait_tsc = token_time_tsc_until_full(&ctx->token_time);

	if (wait_tsc != 0) {
		*next_tsc = wait_tsc;
		return -1;
	}

	if (ctx->flags & STREAM_CTX_F_TCP_GOT_FIN) {
		plogx_dbg("Got fin!\n");
		if (1) {
			ctx->tcp_state = LAST_ACK;
			create_tcp_pkt(ctx, mbuf, TCP_FIN_FLAG | TCP_ACK_FLAG, 0, 0);
			token_time_take(&ctx->token_time, mbuf_wire_size(mbuf));
			*next_tsc = tcp_retx_timeout(ctx);
			return 0;
		}
		else {
			ctx->tcp_state = CLOSE_WAIT;
			create_tcp_pkt(ctx, mbuf, TCP_FIN_FLAG, 0, 0);
			token_time_take(&ctx->token_time, mbuf_wire_size(mbuf));
			*next_tsc = tcp_resched_timeout(ctx);
			return 0;
		}
	}

	if (ctx->flags & STREAM_CTX_F_NEW_DATA)
		ctx->flags &= ~STREAM_CTX_F_NEW_DATA;
	else {
		ctx->same_state++;
		tcp_set_retransmit(ctx);
		plogx_dbg("state++ (ack = %d)\n", ctx->recv_seq);
	}

	create_tcp_pkt(ctx, mbuf, TCP_ACK_FLAG, 0, 0);
	token_time_take(&ctx->token_time, mbuf_wire_size(mbuf));
	*next_tsc = tcp_retx_timeout(ctx);
	return 0;
}

static int stream_tcp_proc_out_estab(struct stream_ctx *ctx, struct rte_mbuf *mbuf, uint64_t *next_tsc)
{
	if (ctx->stream_cfg->actions[ctx->cur_action].peer == ctx->peer) {
		return stream_tcp_proc_out_estab_tx(ctx, mbuf, next_tsc);
	}
	else {
		return stream_tcp_proc_out_estab_rx(ctx, mbuf, next_tsc);
	}
}

static int stream_tcp_proc_out_close_wait(struct stream_ctx *ctx, struct rte_mbuf *mbuf, uint64_t *next_tsc)
{
	uint64_t wait_tsc = token_time_tsc_until_full(&ctx->token_time);

	if (wait_tsc != 0) {
		*next_tsc = wait_tsc;
		return -1;
	}

	/* CLOSE_WAIT is an intermediary stage that is only visited
	   when the FIN is sent after ACK'ing the incoming FIN. In any
	   case, it does not matter if there was a packet or not. */
	ctx->tcp_state = LAST_ACK;
	create_tcp_pkt(ctx, mbuf, TCP_ACK_FLAG | TCP_FIN_FLAG, 0, 0);
	token_time_take(&ctx->token_time, mbuf_wire_size(mbuf));
	*next_tsc = tcp_retx_timeout(ctx);
	return 0;
}

static int stream_tcp_proc_out_last_ack(struct stream_ctx *ctx, struct rte_mbuf *mbuf, uint64_t *next_tsc)
{
	if (ctx->ackd_seq == ctx->next_seq) {
		plogx_dbg("Last ACK received\n");
		ctx->flags |= STREAM_CTX_F_TCP_ENDED;
		return -1;
	}
	else {
		uint64_t wait_tsc = token_time_tsc_until_full(&ctx->token_time);

		if (wait_tsc != 0) {
			*next_tsc = wait_tsc;
			return -1;
		}
		if (ctx->flags & STREAM_CTX_F_LAST_RX_PKT_MADE_PROGRESS) {
			ctx->flags &= ~STREAM_CTX_F_LAST_RX_PKT_MADE_PROGRESS;
			*next_tsc = tcp_retx_timeout(ctx);
			return -1;
		}

		plogx_dbg("Retransmit!\n");
		ctx->next_seq = ctx->ackd_seq;
		ctx->same_state++;
		tcp_set_retransmit(ctx);
		create_tcp_pkt(ctx, mbuf, TCP_ACK_FLAG | TCP_FIN_FLAG, 0, 0);
		token_time_take(&ctx->token_time, mbuf_wire_size(mbuf));
		*next_tsc = tcp_retx_timeout(ctx);
		return 0;
	}
}

static int stream_tcp_proc_out_fin_wait(struct stream_ctx *ctx, struct rte_mbuf *mbuf, uint64_t *next_tsc)
{
	uint64_t wait_tsc = token_time_tsc_until_full(&ctx->token_time);

	if (wait_tsc != 0) {
		*next_tsc = wait_tsc;
		return -1;
	}

	if (ctx->ackd_seq == ctx->next_seq) {
		if (ctx->flags & STREAM_CTX_F_TCP_GOT_FIN) {
			ctx->same_state = 0;
			ctx->tcp_state = TIME_WAIT;
			ctx->sched_tsc = rte_rdtsc() + ctx->stream_cfg->tsc_timeout_time_wait;
			plogx_dbg("from FIN_WAIT to TIME_WAIT\n");
			create_tcp_pkt(ctx, mbuf, TCP_ACK_FLAG, 0, 0);
			token_time_take(&ctx->token_time, mbuf_wire_size(mbuf));
			*next_tsc = ctx->stream_cfg->tsc_timeout_time_wait;
			return 0;
		}
		else {
			/* FIN will still need to come */
			*next_tsc = tcp_retx_timeout(ctx);
			return -1;
		}
	}
	else {
		if (ctx->flags & STREAM_CTX_F_LAST_RX_PKT_MADE_PROGRESS) {
			ctx->flags &= ~STREAM_CTX_F_LAST_RX_PKT_MADE_PROGRESS;
			*next_tsc = tcp_retx_timeout(ctx);
			return -1;
		}

		plogx_dbg("Retransmit!\n");
		ctx->same_state++;
		tcp_set_retransmit(ctx);
		ctx->next_seq = ctx->ackd_seq;
		create_tcp_pkt(ctx, mbuf, TCP_FIN_FLAG | TCP_ACK_FLAG, 0, 0);
		token_time_take(&ctx->token_time, mbuf_wire_size(mbuf));
		*next_tsc = tcp_retx_timeout(ctx);
		return 0;
	}
}

static int stream_tcp_proc_out_time_wait(struct stream_ctx *ctx, struct rte_mbuf *mbuf, uint64_t *next_tsc)
{
	if (ctx->sched_tsc < rte_rdtsc()) {
		plogx_dbg("TIME_WAIT expired! for %#x\n", ctx->tuple->dst_addr);
		ctx->flags |= STREAM_CTX_F_TCP_ENDED;
		return -1;
	}
	uint64_t wait_tsc = token_time_tsc_until_full(&ctx->token_time);

	if (wait_tsc != 0) {
		*next_tsc = wait_tsc;
		return -1;
	}

	plogx_dbg("Got packet while in TIME_WAIT (pkt ACK reTX)\n");
	ctx->sched_tsc = rte_rdtsc() + ctx->stream_cfg->tsc_timeout_time_wait;
	create_tcp_pkt(ctx, mbuf, TCP_ACK_FLAG, 0, 0);
	token_time_take(&ctx->token_time, mbuf_wire_size(mbuf));
	*next_tsc = ctx->stream_cfg->tsc_timeout_time_wait;
	return 0;
}

static int stream_tcp_proc_out(struct stream_ctx *ctx, struct rte_mbuf *mbuf, uint64_t *next_tsc)
{
	if (ctx->same_state == 10) {
		ctx->flags |= STREAM_CTX_F_EXPIRED;
		return -1;
	}

	switch (ctx->tcp_state) {
	case CLOSED: /* Client initial state */
		return stream_tcp_proc_out_closed(ctx, mbuf, next_tsc);
	case LISTEN: /* Server starts in this state. */
		return stream_tcp_proc_out_listen(ctx, mbuf, next_tsc);
	case SYN_SENT:
		return stream_tcp_proc_out_syn_sent(ctx, mbuf, next_tsc);
	case SYN_RECEIVED:
		return stream_tcp_proc_out_syn_recv(ctx, mbuf, next_tsc);
	case ESTABLISHED:
		return stream_tcp_proc_out_estab(ctx, mbuf, next_tsc);
	case CLOSE_WAIT:
		return stream_tcp_proc_out_close_wait(ctx, mbuf, next_tsc);
	case LAST_ACK:
		return stream_tcp_proc_out_last_ack(ctx, mbuf, next_tsc);
	case FIN_WAIT:
		return stream_tcp_proc_out_fin_wait(ctx, mbuf, next_tsc);
	case TIME_WAIT:
		return stream_tcp_proc_out_time_wait(ctx, mbuf, next_tsc);
	}

	return -1;
}

/* Return: zero: packet in mbuf is the reply, non-zero: data consumed,
   nothing to send. The latter case might mean that the connection has
   ended, or that a future event has been scheduled. l4_meta =>
   mbuf contains packet to be processed. */
int stream_tcp_proc(struct stream_ctx *ctx, struct rte_mbuf *mbuf, struct l4_meta *l4_meta, uint64_t *next_tsc)
{
	token_time_update(&ctx->token_time, rte_rdtsc());
	token_time_update(&ctx->token_time_other, rte_rdtsc());
	if (l4_meta) {
		int ret;

		token_time_take_clamp(&ctx->token_time_other, mbuf_wire_size(mbuf));
		ret = stream_tcp_proc_in(ctx, l4_meta);
		if (ret)
			return ret;
	}

	return stream_tcp_proc_out(ctx, mbuf, next_tsc);
}

int stream_tcp_is_ended(struct stream_ctx *ctx)
{
	return ctx->flags & STREAM_CTX_F_TCP_ENDED;
}

static void add_pkt_bytes(uint32_t *n_pkts, uint32_t *n_bytes, uint32_t len)
{
	len = (len < 60? 60 : len) + 20 + ETHER_CRC_LEN;

	(*n_pkts)++;
	*n_bytes += len;
}

void stream_tcp_calc_len(struct stream_cfg *cfg, uint32_t *n_pkts, uint32_t *n_bytes)
{
	const uint32_t client_hdr_len = cfg->data[PEER_CLIENT].hdr_len;
	const uint32_t server_hdr_len = cfg->data[PEER_SERVER].hdr_len;

	*n_pkts = 0;
	*n_bytes = 0;

	/* Connection setup */
	add_pkt_bytes(n_pkts, n_bytes, client_hdr_len + sizeof(struct tcp_hdr) + 4); /* SYN */
	add_pkt_bytes(n_pkts, n_bytes, server_hdr_len + sizeof(struct tcp_hdr) + 4); /* SYN/ACK */
	add_pkt_bytes(n_pkts, n_bytes, client_hdr_len + sizeof(struct tcp_hdr)); /* ACK */

	for (uint32_t i = 0; i < cfg->n_actions; ++i) {
		const uint32_t mss = 1440; /* TODO: should come from peer's own mss. */
		uint32_t remaining = cfg->actions[i].len;
		const uint32_t send_hdr_len = cfg->actions[i].peer == PEER_CLIENT? client_hdr_len : server_hdr_len;
		const uint32_t reply_hdr_len = cfg->actions[i].peer == PEER_CLIENT? server_hdr_len : client_hdr_len;

		if (remaining == 0)
			break;

		while (remaining) {
			uint32_t seg = remaining > mss? mss: remaining;
			add_pkt_bytes(n_pkts, n_bytes, send_hdr_len + sizeof(struct tcp_hdr) + seg);
			remaining -= seg;
		}

		add_pkt_bytes(n_pkts, n_bytes, reply_hdr_len + sizeof(struct tcp_hdr));
	}

	/* Connection Tear-down */
	enum l4gen_peer last_peer = cfg->actions[cfg->n_actions - 1].peer;

	const uint32_t init_hdr_len = last_peer == PEER_CLIENT? client_hdr_len : server_hdr_len;
	const uint32_t resp_hdr_len = last_peer == PEER_CLIENT? server_hdr_len : client_hdr_len;

	add_pkt_bytes(n_pkts, n_bytes, init_hdr_len + sizeof(struct tcp_hdr)); /* FIN */
	add_pkt_bytes(n_pkts, n_bytes, resp_hdr_len + sizeof(struct tcp_hdr)); /* FIN/ACK */
	add_pkt_bytes(n_pkts, n_bytes, init_hdr_len + sizeof(struct tcp_hdr)); /* ACK */
}
