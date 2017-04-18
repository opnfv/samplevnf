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

#ifndef _CNXN_TRACKING_H
#define _CNXN_TRACKING_H

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>


#include <rte_hash.h>
#include <rte_ether.h>

#include "rte_ct_tcp.h"


/**
 *  @file
 *  Connection Tracker
 *
 *  A Connection Tracker tracks the status of TCP connections. By remembering
 *  keys pieces of data, such as connection state, sequence numbers seen, and
 *  transmission window size, it can determine if a give packet is valid, or
 *  invalid and should be discarded.
 *
 *  The current interface is designed for use with ip_pipeline code.
 */

/*
 * Opaque type definition for an instance of the connection tracker. It is
 * possible to have multiple instances of connection tracking running, on one
 * or more cores. All traffic for a TCP connection must be run through the same
 * rte_ct_cnxn_tracker.
 */

/*
 * The rte_ct_cnxn_tracker is an instance of a connection tracker.
 */
struct rte_ct_cnxn_tracker  __rte_cache_aligned;

extern int rte_CT_hi_counter_block_in_use;

struct rte_CT_counter_block {
 /* as long as a counter doesn't cross cache line, writes are atomic */
	uint64_t current_active_sessions;
	uint64_t sessions_activated;	/* a SYN packet seen, or UDP */
	/* a SYN packet re-opening a connection */
	uint64_t sessions_reactivated;
	/* SYN, SYN/ACK, ACK established a connection */
	uint64_t sessions_established;
	uint64_t sessions_closed;
	uint64_t sessions_timedout;
	uint64_t pkts_forwarded;
	uint64_t pkts_drop;
	uint64_t pkts_drop_invalid_conn;
	uint64_t pkts_drop_invalid_state;
	uint64_t pkts_drop_invalid_rst;
	uint64_t pkts_drop_outof_window;
} __rte_cache_aligned;

struct rte_synproxy_helper {
	uint64_t reply_pkt_mask;
	uint64_t hijack_mask;
	struct rte_mbuf **buffered_pkts_to_forward;
	uint8_t num_buffered_pkts_to_forward;
};

struct rte_CT_helper {
	uint64_t no_new_cnxn_mask;
	uint64_t reply_pkt_mask;
	uint64_t hijack_mask;
	struct rte_mbuf **buffered_pkts_to_forward;
	uint8_t num_buffered_pkts_to_forward;
};

#define MAX_CT_INSTANCES 24 /* max number fw threads, actual usually less*/

extern struct rte_CT_counter_block rte_CT_counter_table[MAX_CT_INSTANCES]
__rte_cache_aligned;

/**
 * Run the connection tracking for 1 to 64 packets.
 *
 * @param ct
 *   Instance of cnxn tracker to use.
 * @param pkts
 *   Table of pointers to mbufs containing packets for connection tracking.
 *   Any packets which are not TCP/IP will be ignnored. A maximum of 64
 *   packets may be processed in a call.
 * @param pkts_mask
 *   Bit map representing which table elements of "pkts" are valid mbuf
 *   pointers, where the least-significant bit of the map represents table
 *   element 0. There must be at least as many elements in the table as the
 *   highest order bit in the map. Valid table entries with a corresponding
 *   0 in the bitmap will be ignored.
 * @param ct_helper
 *   Pointer to rte_CT_helper structure which hold the connection tracker
 *   tracking information.
 *
 * @return
 *   Returns an updated bitmap that reflects which packets are valid and should
 *   be forwarded.
 *   Any bits representing invalid TCP packets are cleared.
 *   Any packets which are not TCP/IP are considered valid for this purpose.
 */

uint64_t
rte_ct_cnxn_tracker_batch_lookup(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_mbuf **pkts,
	uint64_t pkts_mask,
	struct rte_CT_helper *ct_helper);

void
rte_ct_cnxn_tracker_batch_lookup_type(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_mbuf **pkts,
	uint64_t *pkts_mask,
	struct rte_CT_helper *ct_helper,
	uint8_t ip_hdr_size_bytes);


/**
 * Run the connection tracking for 1 to 64 packets.
 *
 * @param ct
 *   Instance of cnxn tracker to use.
 * @param pkts
 *   Table of pointers to mbufs containing packets for connection tracking.
 *   Any packets which are not TCP/IP will be ignnored. A maximum of 64
 *   packets may be processed in a call.
 * @param pkts_mask
 *   Bit map representing which table elements of "pkts" are valid mbuf
 *   pointers, where the least-significant bit of the map represents table
 *   element 0. There must be at least as many elements in the table as the
 *   highest order bit in the map. Valid table entries with a corresponding
 *   0 in the bitmap will be ignored.
 * @param no_new_cnxn_mask
 *   Bit map representing which table elements of "pkts" are should be
 *   considered valid packets only if there is already an existing connection
 *   for this packet (i.e. same ip addresses, tcp/udp ports, and protocol).
 *   This mask must be a subset of "pkts_mask" (including all or none), and
 *   follows the same format. A 1 means must be existing connection, a 0 means
 *   a new connection setup (e.g. TCP SYN packet) is allowed, or this entry
 *   corresponds to a 0 in pkts_mask.
 *
 * @return
 *   Returns an updated bitmap that reflects which packets are valid and should
 *   be forwarded.
 *   Any bits representing invalid TCP packets are cleared.
 *   Any packets which are not TCP/IP are considered valid for this purpose.
 */

uint64_t
rte_ct_cnxn_tracker_batch_lookup_with_new_cnxn_control(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_mbuf **pkts,
	uint64_t pkts_mask,
	uint64_t no_new_cnxn_mask);


/**
* Run the connection tracking for 1 to 64 packets, with support for
* synproxy.
*
* @param ct
*   Instance of cnxn tracker to use.
* @param pkts
*   Table of pointers to mbufs containing packets for connection tracking.
*   Any packets which are not TCP/IP will be ignnored. A maximum of 64
*   packets may be processed in a call.
* @param pkts_mask
*   Bit map representing which table elements of "pkts" are valid mbuf pointers,
*   where the least-significant bit of the map represents table element 0. There
*   must be at least as many elements in the table as the highest order bit in
*   the map. Valid table entries with a corresponding 0 in the bitmap will be
*   ignored.
* @param reply_pkt_mask
*   Bit map representing which table elements of "pkts" have been altered to
*   reply messages for synproxy. These packets, or copies of them must be sent
*   back to the originator. IP and TCP headers have been altered, ethernet
*   header has not
* @return
*   Returns an updated bitmap that reflects which packets are valid and should
*   be forwarded.Any bits representing invalid TCP packets are cleared.
*   Any packets which are not TCP/IP are considered valid for this purpose.
*/


uint64_t
rte_ct_cnxn_tracker_batch_lookup_with_synproxy(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_mbuf **pkts,
	uint64_t pkts_mask,
	struct rte_synproxy_helper *sp_helper);





/**
 * Synproxy might need to buffer client-side packets while the
 * server-side of the proxy is still being set up. The packets
 * are released when the server-side connection is complete.
 * This routine is used to retrieve those packets. Packets are
 * also released in a similar manner if there is a timeout
 * during a synproxy setup. This routine should be called before
 * immediately before any timeout handling, to get the list of
 * packets (if any) to forward, and again immediately after timeout
 * handling  to get the list of  packets (if any) to delete.
 * Calling this routine removes the packets from synproxy.
 *
 * @param new_cnxn_tracker
 *   The connection tracker from which to retrieve the packets
 *
 * @return
 *   a linked list of packets to process, in order. The list is
 *   connected via a pointer stored in the mbuf in the offset
 *   given in the "pointer_offset" parameter to the routine:
 *   "rte_ct_initialize_cnxn_tracker_with_synproxy".
 *   If not packets currently available, returns NULL.
 */

struct rte_mbuf *
rte_ct_get_buffered_synproxy_packets(struct rte_ct_cnxn_tracker *ct);


/**
 * Initialize a connection tracker instance before use.
 *
 * @param new_cnxn_tracker
 *   The connection tracker to initialize, allocated by the user.
 * @param max_connection_count
 *   Maximum number of simultaneous connections supported.
 * @param name
 *  A name to give to this connection tracker, for debug purposes
 *
 * @return
 *   - 0 if successful
 *   - negative if unsuccesful
 */

int
rte_ct_initialize_cnxn_tracker_with_synproxy(
	struct rte_ct_cnxn_tracker *new_cnxn_tracker,
	uint32_t max_connection_count,
	char *name,
	uint16_t pointer_offset);

/**
 * Initialize a connection tracker instance before use with synproxy support.
 *
 * @param new_cnxn_tracker
 *   The connection tracker to initialize, allocated by the user.
 * @param max_connection_count
 *   Maximum number of simultaneous connections supported.
 * @param name
 *  A name to give to this connection tracker, for debug purposes
 * @param pointer_offset
 *  An offset into the mbuf where the connection tracker can store two pointers.
 *
 * @return
 *   - 0 if successful
 *   - negative if unsuccesful
 */

int
rte_ct_initialize_cnxn_tracker(
	struct rte_ct_cnxn_tracker *new_cnxn_tracker,
	uint32_t max_connection_count,
	char *name);


/**
 * Free resources allocated by earlier call to rte_ct_initialize_cnxn_tracker()
 *
 * @param old_cnxn_tracker
 *   The connection tracker previously initialized.
 *
 * @return
 *   - 0 if successful
 *   - < 0 if unsuccesful
 */

int
rte_ct_free_cnxn_tracker_resources(
		struct rte_ct_cnxn_tracker *old_cnxn_tracker);


/**
 * Get size of opaque type rte_ct_cnxn_tracker in order to allocate an instance.
 *
 * @return
 *   Size in bytes of rte_ct_cnxn_tracker type
 */

int
rte_ct_get_cnxn_tracker_size(void);

/**
 * Get address of counters kept by this instance.
 *
 * @param ct
 *   Instance of cnxn tracker.
 *
 */

struct rte_CT_counter_block*
rte_ct_get_counter_address(struct rte_ct_cnxn_tracker *ct);


/**
 * Process a configuration option supported in the config file.
 * If a valid name/value pair, update the cnxn tracker.
 *
 * @param ct
 *   Instance of cnxn tracker.
 *
 * @param name
 *   Name of configuration option.
 *
 * @param value
 *   Value of configuration option.
 *
 * @return
 *   - 0 if successful
 *   - < 0 if unsuccesful
 */

int
rte_ct_set_configuration_options(
	struct rte_ct_cnxn_tracker *ct,
	char *name,
	char *value);

/**
 * Check for expired connection tracking timers, and delete any expired
 * connections. This routine must be called in the loop that processes packets,
 * to ensure that timeouts are handled synchronously with packet processing.
 * More frequent calls means more accurate timing but more overhead.
 *
 * @param ct
 *   Instance of cnxn tracker to check timers.
 *
 */

void
rte_ct_handle_expired_timers(struct rte_ct_cnxn_tracker *ct);


int
rte_ct_get_IP_hdr_size(struct rte_mbuf *pkt);

/**
* Enable synproxy for this connection tracker.
*
* @param ct
*   Instance of cnxn tracker to enable.
*
*/

void
rte_ct_enable_synproxy(struct rte_ct_cnxn_tracker *ct);

/**
* Disable synproxy for this connection tracker.
*
* @param ct
*   Instance of cnxn tracker to disable.
*
*/

void
rte_ct_disable_synproxy(struct rte_ct_cnxn_tracker *ct);
int
rte_ct_initialize_default_timeouts(
		struct rte_ct_cnxn_tracker *new_cnxn_tracker);

uint8_t
rte_ct_create_cnxn_hashkey(
	uint32_t *src_addr,
	uint32_t *dst_addr,
	uint16_t src_port,
	uint16_t dst_port,
	uint8_t proto,
	uint32_t *key,
	uint8_t type);

/* To get timer core id from CGNAPT timer thread*/
#ifdef CT_CGNAT
extern uint32_t get_timer_core_id(void);
uint64_t cgnapt_ct_process(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_mbuf **pkts,
	uint64_t pkts_mask,
	struct rte_CT_helper *ct_helper);
#endif
#endif
