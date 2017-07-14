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

#ifndef _GENL4_STREAM_H_
#define _GENL4_STREAM_H_

#include "prox_lua_types.h"
#include "pkt_parser.h"
#include "token_time.h"
#include "quit.h"

enum tcp_state {
	CLOSED,
	LISTEN,
	SYN_SENT,
	SYN_RECEIVED,
	ESTABLISHED,
	CLOSE_WAIT,
	LAST_ACK,
	FIN_WAIT,
	TIME_WAIT
};

static const char *tcp_state_to_str(const enum tcp_state s)
{
	switch(s) {
	case CLOSED:
		return "CLOSED";
	case LISTEN:
		return "LISTEN";
	case SYN_SENT:
		return "SYN_SENT";
	case SYN_RECEIVED:
		return "SYN_RECEIVED";
	case ESTABLISHED:
		return "ESTABLISHED";
	case CLOSE_WAIT:
		return "CLOSE_WAIT";
	case LAST_ACK:
		return "LAST_ACK";
	case FIN_WAIT:
		return "FIN_WAIT";
	case TIME_WAIT:
		return "TIME_WAIT";
	default:
		return "INVALID_STATE";
	}
}

#define STREAM_CTX_F_EXPIRED       0x01
#define STREAM_CTX_F_NEW_DATA      0x02 /* Set on recv to track first ACK of data */
#define STREAM_CTX_F_TCP_ENDED     0x04
#define STREAM_CTX_F_TCP_GOT_SYN   0x08 /* Set only once when syn has been received */
#define STREAM_CTX_F_TCP_GOT_FIN   0x10 /* Set only once when fin has been received */
#define STREAM_CTX_F_MORE_DATA     0x20
#define STREAM_CTX_F_LAST_RX_PKT_MADE_PROGRESS  0x40

/* Run-time structure to management state information associated with current stream_cfg. */
struct stream_ctx {
	enum l4gen_peer         peer;
	uint32_t                cur_action;
	uint32_t                cur_pos[2];
	enum tcp_state          tcp_state;
	struct token_time       token_time;
	struct token_time       token_time_other;
	uint16_t                flags;
	uint16_t                same_state;
	uint32_t                next_seq;
	uint32_t                ackd_seq;
	uint32_t                recv_seq;
	uint32_t                ackable_data_seq;
	uint32_t                seq_first_byte;       /* seq number - seq_first_byte gives offset within content. */
	uint32_t                other_seq_first_byte; /* seq number - seq_first_byte gives offset within content. */
	uint32_t                other_mss;
	uint64_t                sched_tsc;
	uint32_t                retransmits;
	const struct stream_cfg *stream_cfg;          /* Current active steam_cfg */
	struct pkt_tuple        *tuple;
};

struct host_set {
	uint32_t ip;
	uint32_t ip_mask;
	uint16_t port;
	uint16_t port_mask;
};

struct stream_cfg {
	struct peer_data   data[2];
	struct host_set    servers; // Current implementation only allows mask == 0. (i.e. single server)
	struct token_time_cfg tt_cfg[2]; // bytes per period rate
	uint16_t           proto;
	uint64_t           tsc_timeout;
	uint64_t           tsc_timeout_time_wait;
	uint32_t           n_actions;
	uint32_t           n_pkts;
	uint32_t           n_bytes;
	int                (*proc)(struct stream_ctx *meta, struct rte_mbuf *mbuf, struct l4_meta *l4_meta, uint64_t *next_tsc);
	int                (*is_ended)(struct stream_ctx *meta);
	struct peer_action actions[0];
};

static void scale_for_jitter(uint64_t *to_scale)
{
	(*to_scale) *= 2;
}

static void reset_token_times(struct stream_ctx *ctx)
{
	const uint64_t now = rte_rdtsc();
	const struct stream_cfg *cfg = ctx->stream_cfg;
	enum l4gen_peer peer = ctx->peer;

	token_time_init(&ctx->token_time, &cfg->tt_cfg[peer]);
	token_time_reset_full(&ctx->token_time, now);

	token_time_init(&ctx->token_time_other, &cfg->tt_cfg[!peer]);
	scale_for_jitter(&ctx->token_time_other.cfg.bytes_max);
	token_time_reset_full(&ctx->token_time_other, now);
}

static void stream_ctx_init(struct stream_ctx *ctx, enum l4gen_peer peer, struct stream_cfg *cfg, struct pkt_tuple *tuple)
{
	ctx->stream_cfg = cfg;
	ctx->peer = peer;
	ctx->tuple = tuple;

	/* Server's initial state is different from client for
	   TCP. For now, don't use a specific init function for
	   TCP/UDP since there is not a lot of difference and to avoid
	   an additional function pointer. */
	ctx->tcp_state = PEER_CLIENT == peer? CLOSED : LISTEN;
	ctx->other_mss = 536; /* default 536 as per RFC 879 */

	reset_token_times(ctx);
}

static void stream_ctx_reset_move(struct stream_ctx *ctx, struct stream_cfg *cfg)
{
	enum l4gen_peer peer = ctx->peer;
	struct pkt_tuple *tuple = ctx->tuple;

	memset(ctx, 0, sizeof(*ctx));
	stream_ctx_init(ctx, peer, cfg, tuple);
}

static int stream_cfg_calc_max_payload_len(struct stream_cfg *cfg, enum l4gen_peer peer)
{
	const uint32_t l4_hdr_len = cfg->proto == IPPROTO_UDP?
		sizeof(struct udp_hdr) : sizeof(struct tcp_hdr);

	return ETHER_MAX_LEN - ETHER_CRC_LEN - cfg->data[peer].hdr_len - l4_hdr_len;
}

static int stream_cfg_max_n_segments(struct stream_cfg *cfg)
{
	if (cfg->proto == IPPROTO_UDP)
		return 1;

	uint32_t ret = 1;
	uint32_t cur;

	const uint32_t mss = stream_cfg_calc_max_payload_len(cfg, PEER_CLIENT);

	for (uint32_t i = 0; i < cfg->n_actions; ++i) {
		cur = (cfg->actions[i].len + (mss - 1)) / mss;
		ret = ret > cur? ret: cur;
	}

	return ret;
}

static int stream_cfg_verify_action(struct stream_cfg *cfg, struct peer_action *action)
{
	if (cfg->proto == IPPROTO_TCP)
		return 0;

	uint16_t max_payload_len = stream_cfg_calc_max_payload_len(cfg, action->peer);

	PROX_PANIC(action->len > max_payload_len,
		   "Action %zu has length %u while for the maximum action length for UDP connections is limited to %u\n",
		   action - cfg->actions,
		   action->len,
		   max_payload_len);
	return 0;
}

#endif /* _GENL4_STREAM_H_ */
