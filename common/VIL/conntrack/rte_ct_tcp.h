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

#ifndef __INCLUDE_RTE_CT_TCP_H__
#define __INCLUDE_RTE_CT_TCP_H__
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <rte_tcp.h>
#include <rte_port.h>
#include <rte_timer.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_port.h>
#include <rte_byteorder.h>
#include "rte_cnxn_tracking.h"

/* AN INNER, PRIVATE INTERFACE FOR RTE_CNXN_TRACKING */

/* constants for TCP options */

#define RTE_CT_TCPOPT_EOL				0       /* End of options */
#define RTE_CT_TCPOPT_NOP				1       /* Padding */
#define RTE_CT_TCPOPT_MSS				2       /* Segment size negotiating */
#define RTE_CT_TCPOPT_WINDOW		 3       /* Window scaling */
#define RTE_CT_TCPOPT_SACK_PERM	4       /* SACK Permitted */
#define RTE_CT_TCPOPT_SACK			 5       /* SACK Block */
#define RTE_CT_TCPOPT_TIMESTAMP	8       /* RTT estimations */

#define RTE_CT_TCPOLEN_MSS			4
#define RTE_CT_TCPOLEN_WINDOW	 3
#define RTE_CT_TCPOLEN_SACK_PERM      2
#define RTE_CT_TCPOLEN_TIMESTAMP      10
#define RTE_CT_TCPOLEN_PER_SACK_ENTRY 8

#define RTE_CT_TCPOLEN_MSS_ALIGNED			4
#define RTE_CT_TCPOLEN_WINDOW_ALIGNED	 4
#define RTE_CT_TCPOLEN_SACK_PERM_ALIGNED      4
#define RTE_CT_TCPOLEN_TIMESTAMP_ALIGNED      12

#define RTE_CT_MAX_TCP_WINDOW_SCALE  14

#define RTE_SP_OPTIONS_MSS 1
#define RTE_SP_OPTIONS_WINDOW_SCALE 2
#define RTE_SP_OPTIONS_TIMESTAMP 4
#define RTE_SP_OPTIONS_SACK_PERM 8


enum rte_ct_packet_action {
	RTE_CT_OPEN_CONNECTION,
	RTE_CT_DROP_PACKET,
	RTE_CT_FORWARD_PACKET,
	RTE_CT_DESTROY_CNXN_AND_FORWARD_PACKET,
	RTE_CT_REOPEN_CNXN_AND_FORWARD_PACKET,
	RTE_CT_SEND_CLIENT_SYNACK,
	RTE_CT_SEND_SERVER_SYN,
	RTE_CT_SEND_SERVER_ACK,
	RTE_CT_HIJACK
};

enum rte_ct_connstatus {
	RTE_INIT_CONN,
	RTE_SEEN_REPLY_CONN,
	RTE_ASSURED_CONN
};

/* TCP tracking. */

static const char *const rte_ct_tcp_names[] = {
	"NONE",
	"SYN_SENT",
	"SYN_RECV",
	"ESTABLISHED",
	"FIN_WAIT",
	"CLOSE_WAIT",
	"LAST_ACK",
	"TIME_WAIT",
	"CLOSE",
	"SYN_SENT2",
	"RETRANS",
	"UNACK",
	"IGNORE"
};

static const char *const rte_ct_udp_names[] = {
	"NONE_UDP",
	"UNREPLIED",
	"REPLIED"
};

/* Fixme: what about big packets? */
#define RTE_MAX_ACKWIN_CONST			66000

/* Window scaling is advertised by the sender */
#define RTE_CT_TCP_FLAG_WINDOW_SCALE			 0x01

/* SACK is permitted by the sender */
#define RTE_CT_TCP_FLAG_SACK_PERM		0x02

/* This sender sent FIN first */
#define RTE_CT_TCP_FLAG_CLOSE_INIT				 0x04

/* Be liberal in window checking */
#define RTE_CT_TCP_FLAG_BE_LIBERAL				 0x08

/* Has unacknowledged data */
#define RTE_CT_TCP_FLAG_DATA_UNACKNOWLEDGED      0x10

/* The field td_maxack has been set */
#define RTE_CT_TCP_FLAG_MAXACK_SET				 0x20
/* Marks possibility for expected RFC5961 challenge ACK */
#define RTE_CT_EXP_CHALLENGE_ACK		 0x40



/* TCP header flags of interest */
#define RTE_CT_TCPHDR_FIN 0x01
#define RTE_CT_TCPHDR_SYN 0x02
#define RTE_CT_TCPHDR_RST 0x04
#define RTE_CT_TCPHDR_ACK 0x10

#define RTE_CT_TCPHDR_RST_ACK (RTE_CT_TCPHDR_RST | RTE_CT_TCPHDR_ACK)



/* state machine values. Note that order is important as relative checks made */
enum rte_ct_tcp_states {
	RTE_CT_TCP_NONE,
	RTE_CT_TCP_SYN_SENT,
	RTE_CT_TCP_SYN_RECV,
	RTE_CT_TCP_ESTABLISHED,
	RTE_CT_TCP_FIN_WAIT,
	RTE_CT_TCP_CLOSE_WAIT,
	RTE_CT_TCP_LAST_ACK,
	RTE_CT_TCP_TIME_WAIT,
	RTE_CT_TCP_CLOSE,
	RTE_CT_TCP_SYN_SENT_2,
	RTE_CT_TCP_RETRANS,
	RTE_CT_TCP_UNACK,
	RTE_CT_TCP_IGNORE
};

enum rte_ct_udp_states {
	RTE_CT_UDP_NONE,
	RTE_CT_UDP_UNREPLIED,
	RTE_CT_UDP_REPLIED,
	RTE_CT_UDP_MAX
};



#define RTE_CT_TCP_MAX RTE_CT_TCP_UNACK

enum rte_ct_pkt_direction {
	RTE_CT_DIR_ORIGINAL,
	RTE_CT_DIR_REPLY
};

struct rte_ct_tcp_state {
	uint32_t       end;	 /* max of seq + len */
	uint32_t       maxend;      /* max of ack + max(win, 1) */
	uint32_t       maxwin;      /* max(win) */
	uint32_t       maxack;      /* max of ack */
	uint8_t	scale;       /* window scale factor */
	uint8_t	flags;		/* per direction options */
};

struct rte_synproxy_options {
	uint8_t		options;
	uint8_t		window_scale;
	uint16_t	mss;
	uint32_t	ts_val;
	uint32_t	ts_echo_reply;
	uint16_t	initial_window;
};

struct ct_sp_cnxn_data {
	/* buffer client pkt while waiting on server setup,
	 * store in reverse order
	 */
	struct rte_mbuf *buffered_pkt_list;
	uint32_t original_spoofed_seq;
	/* difference between spoofed and real seq from server */
	uint32_t seq_diff;
	struct rte_synproxy_options cnxn_options;
	/* non-zero if this connection created using synproxy */
	uint8_t  synproxied;
	bool	 half_established;
	/* non-zero after both half-connections established */
	bool     cnxn_established;
};

struct rte_ct_tcp {
	struct rte_ct_tcp_state seen[2]; /* connection parms per direction */
	uint8_t state;
	uint8_t	last_dir;       /* Direction of the last packet
					* (TODO: enum ip_conntrack_dir)
					*/
	uint8_t	retrans;	/* Number of retransmitted packets */
	uint8_t	last_index;     /* Index of the last packet */
	uint32_t       last_seq;       /* Last seq number seen in dir */
	uint32_t       last_ack;       /* Last seq number seen opposite dir */
	uint32_t       last_end;       /* Last seq + len */
	uint16_t       last_win;       /* Last window seen in dir */
	/* For SYN packets while we may be out-of-sync */
	uint8_t	last_wscale;    /* Last window scaling factor seen */
	uint8_t	last_flags;     /* Last flags set */
};

/*
 * rte_ct_cnxn_counters holds all the connection-specicif counters.
 * TODO: Make available in public interface
 */

struct rte_ct_cnxn_counters {
	uint64_t packets_received;//Added for CT-NAT
	uint64_t packets_forwarded;
	uint64_t packets_dropped;
};

struct rte_ct_proto {
	struct rte_ct_tcp tcp_ct_data; /* TCP specific data fields*/
	struct ct_sp_cnxn_data synproxy_data;
};


/*
 * rte_ct_cnxn_data contains all the data for a TCP connection. This include
 * state data as necessary for verifying the validity of TCP packets. In
 * addition, it holds data necessary for implementing the TCP timers.
 */

struct rte_ct_cnxn_data {
	/* The timer will be kept as part of the cnxn_data. When it fires, the
	 * pointer to the timer can be cast as the pointer to the cnxn_data
	 */
	struct rte_timer timer; /* !!!!! IMPORTANT: Keep as first field !!!!! */

	struct rte_ct_cnxn_counters counters;

	/* full key stored here to allow the timer to remove the connection */
	/* TODO: Consider storing key signature as well to speed up deletions.*/
	uint32_t key[10];

	struct rte_ct_proto ct_protocol;

	/* the 100 ms timing step that a packet was seen for connection */
	uint64_t expected_timeout;

	/* Abstract states also used for timer values, e.g. RTE_CT_TCP_UNACK*/
	uint8_t state_used_for_timer;

	/* used to compute the "direction" of the packet */
	uint8_t key_is_client_order;
	uint8_t connstatus;
	uint8_t protocol;
	/* used to store the type of packet ipv4 or ipv6 */
	uint8_t type;
	//#ifdef FTP_ALG
	// Bypass flag to indicate that ALG checking is no more needed;
	uint8_t alg_bypass_flag;
	// Can we use key_is_client_order for direction checking
	uint8_t server_direction;
	int16_t tcpSeqdiff;
	// PORT = 0, PASV = 1
	uint8_t ftp_session_type;
	uint32_t tcp_payload_size;
	int16_t  seq_client;
	int16_t  ack_client;
	int16_t  seq_server;
	int16_t  ack_server;
	//#endif
} __rte_cache_aligned;


#define RTE_CT_TCP_MAX_RETRANS 3

struct rte_ct_tcptimeout {
       /* a table of timeouts for each state of TCP */
	uint64_t tcp_timeouts[RTE_CT_TCP_MAX + 1];
};


struct rte_ct_misc_options {
	uint8_t  synproxy_enabled;
	uint32_t tcp_loose;
	uint32_t tcp_be_liberal;
	uint32_t tcp_max_retrans;
};

struct rte_ct_udptimeout {
	uint64_t udp_timeouts[RTE_CT_UDP_MAX + 1];
};

struct rte_ct_timeout {
	struct rte_ct_tcptimeout tcptimeout;
	struct rte_ct_udptimeout udptimeout;
};

struct rte_ct_cnxn_tracker {
	struct rte_hash *rhash;

	/*
	 * Data for bulk hash lookup. Use this memory as temporary space.
	 * Too big for stack (64*16 bytes)
	 */
	uint32_t hash_keys[RTE_HASH_LOOKUP_BULK_MAX][10];

	/* table of pointers to above, for bulk hash lookup */
	void *hash_key_ptrs[RTE_HASH_LOOKUP_BULK_MAX];
	#ifdef CT_CGNAT
	uint32_t positions[RTE_HASH_LOOKUP_BULK_MAX];/*added for ALG*/
	#endif
	/* hash table and timer storage */
	uint32_t num_cnxn_entries;

	/*
	 * pointer to data space used for hash table, "num_cnxn_entries" long.
	 * Memory allocated during initialization.
	 */
	struct rte_ct_cnxn_data *hash_table_entries;
	struct rte_CT_counter_block *counters;

	uint64_t hertz;
	uint64_t timing_cycles_per_timing_step;
	uint64_t timing_100ms_steps;
	uint64_t timing_100ms_steps_previous;
	uint64_t timing_last_time;
	struct rte_ct_timeout ct_timeout;
	struct rte_ct_misc_options misc_options;

	char name[16];
	struct rte_ct_cnxn_data *new_connections[64];
	struct rte_mbuf *buffered_pkt_list;
	int latest_connection;
	/* offset into mbuf where synnproxy can store a pointer */
	uint16_t pointer_offset;
} __rte_cache_aligned;

/*
 * Returns a value stating if this is a valid TCP open connection attempt.
 * If valid, updates cnxn with any data fields it need to save.
 */

enum rte_ct_packet_action
rte_ct_tcp_new_connection(
	struct	rte_ct_cnxn_tracker *inst,
	struct	rte_ct_cnxn_data *cnxn,
	struct	rte_mbuf *pkt,
	int	use_synproxy,
	uint8_t ip_hdr_size);

/*
* Returns a value stating if this is a valid TCP packet for the give connection.
* If valid, updates cnxn with any data fields it need to save.
*/

enum rte_ct_packet_action
rte_ct_verify_tcp_packet(
	struct rte_ct_cnxn_tracker *inst,
	struct rte_ct_cnxn_data *cnxn,
	struct rte_mbuf *pkt,
	uint8_t  key_was_flipped,
	uint8_t ip_hdr_size);

/*
* Returns a value stating if this is a valid UDP open connection attempt.
* If valid, updates cnxn with any data fields it need to save.
*/

uint8_t
rte_ct_udp_new_connection(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_ct_cnxn_data *cd,
	struct rte_mbuf *pkt);

/*
* Returns a value stating if this is a valid UDP packet for the give connection.
* If valid, updates cnxn with any data fields it need to save.
*/

enum rte_ct_packet_action
rte_ct_udp_packet(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_ct_cnxn_data *cd,
	struct rte_mbuf *pkt,
	uint8_t  key_was_flipped);


/*
 * For the given connection, set a timeout based on the given state. If the
 * timer is already set, this call will reset the timer with a new value.
 */

void
rte_ct_set_cnxn_timer_for_tcp(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_ct_cnxn_data *cd,
	uint8_t tcp_state);

void
rte_ct_set_cnxn_timer_for_udp(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_ct_cnxn_data *cd,
	uint8_t tcp_state);

/* Cancel timer associated with the connection. Safe to call if no timer set.*/
void rte_ct_cancel_cnxn_timer(struct rte_ct_cnxn_data *cd);


/*
 * SYNPROXY related routines. Detailed comments are available in
 * rte_ct_synproxy.c where they are implemented.
 */


/* these 3 routines convert a received packet to a different one */

void
rte_sp_cvt_to_spoofed_client_synack(struct rte_ct_cnxn_data *cd,
		struct rte_mbuf *old_pkt);

void
rte_sp_cvt_to_spoofed_server_syn(struct rte_ct_cnxn_data *cd,
		struct rte_mbuf *old_pkt);

void
rte_sp_cvt_to_spoofed_server_ack(struct rte_ct_cnxn_data *cd,
		struct rte_mbuf *old_pkt);

/* These two routines adjust seq or ack numbers,
 * as part of the proxy mechanism
 */

void
rte_sp_adjust_client_ack_before_window_check(
	struct rte_ct_cnxn_data *cd,
	void *i_hdr,
	struct tcp_hdr *thdr,
	enum rte_ct_pkt_direction dir);

void
rte_sp_adjust_server_seq_after_window_check(
	struct rte_ct_cnxn_data *cd,
	void *i_hdr,
	struct tcp_hdr *thdr,
	enum rte_ct_pkt_direction dir);



/* parse tcp options and save in t_opts */
void
rte_sp_parse_options(struct rte_mbuf *pkt, struct rte_ct_cnxn_data *cd);


/* these two routines deal with packet buffering */

void
rte_ct_buffer_packet(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_ct_cnxn_data *cd,
	struct rte_mbuf *pkt);

void
	rte_ct_release_buffered_packets(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_ct_cnxn_data *cd);

#endif /* TCPCONNTRACK_H */
