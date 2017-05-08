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

#include <rte_ether.h>
#include <rte_prefetch.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_timer.h>
#include <rte_spinlock.h>
#include "rte_cnxn_tracking.h"
#include "rte_ct_tcp.h"
#include "vnf_common.h"

#define CNXN_TRX_DEBUG 0
#define TESTING_TIMERS 0
#define RTE_CT_TIMER_EXPIRED_DUMP 0

#define META_DATA_OFFSET 128
#define ETHERNET_START (META_DATA_OFFSET + RTE_PKTMBUF_HEADROOM)
#define ETH_HDR_SIZE 14
#define IP_START (ETHERNET_START + ETH_HDR_SIZE)
#define PROTOCOL_START (IP_START + 9)
#define SRC_ADDR_START (IP_START + 12)
#define TCP_START (IP_START + 20)

/* IPV6 changes */
#define PROTOCOL_START_IPV6 (IP_START + 6)
#define SRC_ADDR_START_IPV6 (IP_START + 8)
#define TCP_START_IPV6 (IP_START + 40)

#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17
#define TCP_FW_IPV4_KEY_SIZE 16

#define TCP_FW_IPV6_KEY_SIZE 40

#define IPv4_HEADER_SIZE 20
#define IPv6_HEADER_SIZE 40

#define IP_VERSION_4 4
#define IP_VERSION_6 6
static void
rte_ct_cnxn_tracker_batch_lookup_basic_type(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_mbuf **pkts,
	uint64_t *pkts_mask,
	uint64_t no_new_cnxn_mask,
	uint64_t *reply_pkt_mask,
	uint64_t *hijack_mask,
	uint8_t ip_hdr_size_bytes);

/*
 * Check if the packet is valid for the given connection. "original_direction"
 * is false if the address order need to be "flipped".See create_cnxn_hashkey().
 * True otherwise. Return 0 if the packet is valid, or a negative otherwise.
 */

/* IP/TCP header print for debugging */
static void
rte_ct_cnxn_print_pkt(struct rte_mbuf *pkt, uint8_t type)
{
	int i;
	uint8_t *rd = RTE_MBUF_METADATA_UINT8_PTR(pkt, IP_START);

	printf("\n");
	printf("IP and TCP/UDP headers:\n");

	if (type == IP_VERSION_4) {
		for (i = 0; i < 40; i++) {
			printf("%02x ", rd[i]);
			if ((i & 3) == 3)
				printf("\n");
		}
		printf("\n");
	}

	if (type == IP_VERSION_6) {
		for (i = 0; i < 60; i++) {
			printf("%02x ", rd[i]);
			if ((i & 3) == 3)
				printf("\n");
		}
		printf("\n");
	}

}

static void
rte_cnxn_ip_type(uint8_t *type, struct rte_mbuf *pkt)
{

	int ip_hdr_size_bytes = rte_ct_get_IP_hdr_size(pkt);

	if (ip_hdr_size_bytes == IPv4_HEADER_SIZE)
		*type = IP_VERSION_4;

	if (ip_hdr_size_bytes == IPv6_HEADER_SIZE)
		*type = IP_VERSION_6;
}

static void
rte_ct_print_hashkey(uint32_t *key)
{
	printf("Key: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x \\\n",
				 key[0], key[1], key[2], key[3],
				 key[4], key[5], key[6], key[7], key[8], key[9]);
}

/*
 * Create a hash key consisting of the source address/port, the destination
 * address/ports, and the tcp protocol number. The address/port combos are
 * treated as two 48 bit numbers and sorted. Thus the key is always the
 * same regardless of the direction of the packet. Remembering if the numbers
 * were "flipped" from the order in the packet, and comparing that to whether
 * the original hash key was flipped, tells if this packet is from the same
 * direction as the original sender or the response direction. Returns 1 (true)
 * if the key was left in the original direction.
 */
uint8_t
rte_ct_create_cnxn_hashkey(
	uint32_t *src_addr,
	uint32_t *dst_addr,
	uint16_t src_port,
	uint16_t dst_port,
	uint8_t proto,
	uint32_t *key,
	uint8_t type)
{
	uint8_t hash_order_original_direction = 1;

	key[9] = proto;

	if (type == IP_VERSION_4) {
		uint32_t source = *src_addr;
		uint32_t dest = *dst_addr;

		key[3] = key[4] = key[5] = key[6] = key[7] = key[8] = 0;

		if ((source < dest)
				|| ((source == dest) && (src_port < dst_port))) {
			key[0] = source;
			key[1] = dest;
			key[2] = (src_port << 16) | dst_port;
		} else {
			key[0] = dest;
			key[1] = source;
			key[2] = (dst_port << 16) | src_port;
			hash_order_original_direction = 0;
		}
	}

	if (type == IP_VERSION_6) {
		int ip_cmp = memcmp(src_addr, dst_addr, 16);
		uint32_t *lo_addr;
		uint32_t *hi_addr;

		if ((ip_cmp < 0) || ((ip_cmp == 0) && (src_port < dst_port))) {
			lo_addr = src_addr;
			hi_addr = dst_addr;
			key[8] = (src_port << 16) | dst_port;
		} else {
			lo_addr = dst_addr;
			hi_addr = src_addr;
			key[8] = (dst_port << 16) | src_port;
			hash_order_original_direction = 0;
		}
		key[0] = lo_addr[0];
		key[1] = lo_addr[1];
		key[2] = lo_addr[2];
		key[3] = lo_addr[3];
		key[4] = hi_addr[0];
		key[5] = hi_addr[1];
		key[6] = hi_addr[2];
		key[7] = hi_addr[3];

	}
#ifdef ALGDBG
	 rte_ct_print_hashkey(key);
#endif
	return hash_order_original_direction;
}


int
rte_ct_get_IP_hdr_size(struct rte_mbuf *pkt)
{
	/* NOTE: Only supporting IP headers with no options at this time, so
	 * header is fixed size
	 */
	/* TODO: Need to find defined contstants for start of Ether and
	 * IP headers.
	 */
	uint8_t hdr_chk = RTE_MBUF_METADATA_UINT8(pkt, IP_START);

	hdr_chk = hdr_chk >> 4;

	if (hdr_chk == IP_VERSION_4)
		return IPv4_HEADER_SIZE;

	else if (hdr_chk == IP_VERSION_6)
		return IPv6_HEADER_SIZE;

	else	/* Not IPv4 header with no options, return negative. */
		return -1;
	/*
	 * int ip_hdr_size_bytes = (ihdr->version_ihl & IPV4_HDR_IHL_MASK) *
	 * IPV4_IHL_MULTIPLIER;
	 * return ip_hdr_size_bytes;
	 */
}

static void
rte_ct_set_timer_for_new_cnxn(
		struct rte_ct_cnxn_tracker *ct,
		struct rte_ct_cnxn_data *cd)
{
	cd->state_used_for_timer = RTE_CT_TCP_NONE;
	rte_ct_set_cnxn_timer_for_tcp(ct, cd, RTE_CT_TCP_SYN_SENT);
}

/*
 * The connection data is stored in a hash table which makes use of the bulk
 * lookup optimization provided in DPDK. All of the packets seen in one call
 * to rte_ct_cnxn_tracker_batch_lookup are done in one hash table lookup. The
 * number of packets is the number being processed by the pipeline (default
 * max 32, absolute max 64). For any TCP or UDP packet that does not have
 * an existing (pseudo-)connection in the table (i.e. was a miss on the hash
 * lookup), a new connection must be added.
 *
 * It is possible, for UDP, that the first packet for a (pseudo-)connection and
 * a subsequent packet are in the same batch. This means that when looking for
 * new connections in a batch the first one must add the connection, the
 * second and subsequent (in that batch) that are part of the same connection
 * must use that newly created one, not create another table entry.
 *
 * Any newly created entries are "remembered" in linear table, which is search
 * when processing hash tables misses. All the entries in that table are
 * "forgotten" at the start of a new batch.
 *
 * A linear table may seem slow, but consider:
 * - out of millions of packets/second, this involves at most 64.
 * - this affects only UDP. TCP connections are set up using an acknowledgement
 *   protocl, so would not have multiple packets for new connection in
 *   same batch (TODO)
 * - the number of new connections in a batch would usually be zero, or a low
 *   number like 1
 * - all the data to search through should still be in cache
 */

static inline void
rte_ct_remember_new_connection(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_ct_cnxn_data *entry)
{
	ct->latest_connection++;
	ct->new_connections[ct->latest_connection] = entry;
}

static struct rte_ct_cnxn_data *
rte_ct_search_new_connections(struct rte_ct_cnxn_tracker *ct, uint32_t *key)
{
	int i;

	for (i = 0; i <= ct->latest_connection; i++) {
		uint32_t *cnxn_key = ct->new_connections[i]->key;
		int key_cmp = memcmp(cnxn_key, key,
				sizeof(ct->new_connections[i]->key));

		if (key_cmp == 0)
			return ct->new_connections[i];
	}
	return NULL;
}

static inline void rte_ct_forget_new_connections(struct rte_ct_cnxn_tracker *ct)
{
	ct->latest_connection = -1;
}




static enum rte_ct_packet_action
rte_ct_handle_tcp_lookup(
	struct	rte_ct_cnxn_tracker *ct,
	struct	rte_mbuf *packet,
	uint8_t pkt_num,
	uint8_t	key_is_client_order,
	uint32_t *key,
	int	hash_table_entry,
	int	no_new_cnxn,
	uint8_t ip_hdr_size_bytes)
{
	struct rte_ct_cnxn_data new_cnxn_data;

	memset(&new_cnxn_data, 0, sizeof(struct rte_ct_cnxn_data));
	enum rte_ct_packet_action packet_action;

	#ifdef CT_CGNAT
	int32_t position = hash_table_entry;
	ct->positions[pkt_num] = position;
	#endif

	/* rte_ct_cnxn_print_pkt(packet); */
	if (hash_table_entry >= 0) {
		/*
		 * connection found for this packet.
		 * Check that this is a valid packet for connection
		 */

		struct rte_ct_cnxn_data *entry =
				&ct->hash_table_entries[hash_table_entry];

		packet_action = rte_ct_verify_tcp_packet(ct, entry, packet,
				key_is_client_order, ip_hdr_size_bytes);

		switch (packet_action) {

		case RTE_CT_FORWARD_PACKET:
			entry->counters.packets_forwarded++;
			break;

		case RTE_CT_DROP_PACKET:
			entry->counters.packets_dropped++;
			return RTE_CT_DROP_PACKET;

		case RTE_CT_REOPEN_CNXN_AND_FORWARD_PACKET:
			/* Entry already in hash table, just re-initialize */

			/* Don't use syproxy on re-init, since it
			 * is a valid connection
			 */

			if (rte_ct_tcp_new_connection(ct, &new_cnxn_data,
						packet, 0, ip_hdr_size_bytes) !=
					RTE_CT_DROP_PACKET) {
				rte_memcpy(&entry->ct_protocol.tcp_ct_data,
				&new_cnxn_data.ct_protocol.tcp_ct_data,
				sizeof(new_cnxn_data.ct_protocol.tcp_ct_data));
				rte_ct_set_timer_for_new_cnxn(ct, entry);
				if (ct->counters->sessions_reactivated > 0)
					ct->counters->sessions_reactivated--;
			}

			break;

		case RTE_CT_SEND_SERVER_SYN:
			ct->counters->pkts_forwarded++;
			/* packet modified, send back to original source */
			return RTE_CT_SEND_SERVER_SYN;

		case RTE_CT_SEND_SERVER_ACK:
			ct->counters->pkts_forwarded++;
			/* packet modified, send back to original source */
			return RTE_CT_SEND_SERVER_ACK;

		case RTE_CT_HIJACK:
			ct->counters->pkts_forwarded++;
			/* packet saved with connection, notify VNF
			 * to hijack it
			 */
			return RTE_CT_HIJACK;

		case RTE_CT_DESTROY_CNXN_AND_FORWARD_PACKET:

			/*
			 * Forward the packet because it is "legal", but destroy
			 * the connection by removing it from the hash table and
			 * cancelling any timer. There is a remote possibility
			 * (perhaps impossible?) that a later packet in the same
			 * batch is for this connection. Due to the batch
			 * lookup, which has already happened, the later packet
			 * thinks that the connection is valid. This might cause
			 * a timer to be set. Eventually, it would time out so
			 * the only bug case occurs if the hash table also, in
			 * the same batch, allocates this entry for a new
			 * connection before the above packet is received. The
			 * chances of this happening seem impossibly small but
			 * this case should perhaps be investigated further.
			 */

			if (rte_hash_del_key(ct->rhash, entry->key) >= 0) {
				/*
				 * if rte_hash_del_key >= 0, then the connection
				 * was found in the hash table and removed.
				 * Counters must be updated, and the timer
				 * cancelled. If the result was < 0, then the
				 * connection must have already been deleted,
				 * and it must have been deleted in this batch
				 * of packets processed. Do nothing.
				 */

				ct->counters->sessions_closed++;
				if (ct->counters->current_active_sessions > 0)
					ct->counters->current_active_sessions--;
				rte_ct_cancel_cnxn_timer(entry);
			}
			entry->counters.packets_forwarded++;
			break;

		default:
			break;
		}
	} else {
		/* try to add new connection */
		struct rte_ct_cnxn_data *new_hash_entry;

		if (no_new_cnxn) {
			ct->counters->pkts_drop_invalid_conn++;
			return RTE_CT_DROP_PACKET;
		}

		packet_action = rte_ct_tcp_new_connection(ct, &new_cnxn_data,
				packet,	ct->misc_options.synproxy_enabled,
				ip_hdr_size_bytes);

		if (unlikely(packet_action == RTE_CT_DROP_PACKET)) {
			ct->counters->pkts_drop_invalid_conn++;
			return RTE_CT_DROP_PACKET;
		}

		/* This packet creates a connection . */
		int32_t position = rte_hash_add_key(ct->rhash, key);
		if (position < 0) {
			printf
					("Failed to add new connection to hash table %d, pkt_num:%d\n",
					 position, pkt_num);
			return RTE_CT_DROP_PACKET;
		}
	#ifdef CT_CGNAT
	ct->positions[pkt_num] = position;
	#endif
		new_hash_entry = &ct->hash_table_entries[position];

		/* update fields in new_cnxn_data not set by new_connection */

		memcpy(new_cnxn_data.key, key, sizeof(new_cnxn_data.key));
		new_cnxn_data.key_is_client_order = key_is_client_order;
		new_cnxn_data.protocol = TCP_PROTOCOL;
		rte_cnxn_ip_type(&new_cnxn_data.type, packet);
		rte_memcpy(new_hash_entry, &new_cnxn_data,
				sizeof(struct rte_ct_cnxn_data));
		new_hash_entry->counters.packets_forwarded = 1;
		new_hash_entry->counters.packets_dropped = 0;
		ct->counters->current_active_sessions++;
		ct->counters->sessions_activated++;

		if (packet_action == RTE_CT_SEND_CLIENT_SYNACK) {
			/* this is a synproxied connecton */
			/* must remember mss, window scaling etc. from client */

			rte_sp_parse_options(packet, new_hash_entry);

			/*
			 * update packet to a SYN/ACK directed to the client,
			 * including default header options
			 */

			rte_sp_cvt_to_spoofed_client_synack(new_hash_entry,
					packet);

			/*
			 * run updated packet through connection tracking so
			 * cnxn data updated appropriately and timer set for syn
			 * received state, not syn sent.
			 */
			packet_action = rte_ct_verify_tcp_packet(ct,
					new_hash_entry, packet,
					!key_is_client_order,
					ip_hdr_size_bytes);

			if (unlikely(packet_action != RTE_CT_FORWARD_PACKET)) {
				/* should never get here */
				printf("Serious error in synproxy generating ");
				printf("SYN/ACK\n");
				return RTE_CT_DROP_PACKET;
			}
			ct->counters->pkts_forwarded++;
			/* spoofed packet good to go */
			return RTE_CT_SEND_CLIENT_SYNACK;
		}
		rte_ct_set_timer_for_new_cnxn(ct, new_hash_entry);

	}

	/* TODO: is it possible that earlier packet in this batch caused new
	 * entry to be added for the connection? Seems unlikely, since it
	 * would require multiple packets from the same side of the connection
	 * one after another immediately, and the TCP connection OPEN requires
	 * acknowledgement before further packets. What about simultaneous
	 * OPEN? Only if both sides are on same input port. Is that possible?
	 */
	/* if made it here, packet will be forwarded */
	ct->counters->pkts_forwarded++;
	return RTE_CT_FORWARD_PACKET;
}

static uint64_t
rte_ct_cnxn_tracker_batch_lookup_basic(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_mbuf **pkts,
	uint64_t pkts_mask,
	uint64_t no_new_cnxn_mask,
	uint64_t *reply_pkt_mask,
	uint64_t *hijack_mask)
{
	/* bitmap of packets left to process */
	uint64_t pkts_to_process = pkts_mask;
	/* bitmap of valid packets to return */
	uint64_t valid_packets = pkts_mask;
	uint8_t compacting_map[RTE_HASH_LOOKUP_BULK_MAX];
	/* for pkt, key in originators direction? */
	uint8_t key_orig_dir[RTE_HASH_LOOKUP_BULK_MAX];
	uint32_t packets_for_lookup = 0;
	int32_t positions[RTE_HASH_LOOKUP_BULK_MAX];
	uint32_t i;
	struct rte_ct_cnxn_data new_cnxn_data;

	if (CNXN_TRX_DEBUG > 1) {
		printf("Enter cnxn tracker %p", ct);
		printf(" synproxy batch lookup with packet mask %p\n",
				(void *)pkts_mask);
	}

	rte_ct_forget_new_connections(ct);
	*reply_pkt_mask = 0;
	*hijack_mask = 0;

	/*
	 * Use bulk lookup into hash table for performance reasons. Cannot have
	 * "empty slots" in the bulk lookup,so need to create a compacted table.
	 */

	for (; pkts_to_process;) {
		uint8_t pos = (uint8_t) __builtin_ctzll(pkts_to_process);
		/* bitmask representing only this packet */
		uint64_t pkt_mask = 1LLU << pos;
		/* remove this packet from remaining list */
		pkts_to_process &= ~pkt_mask;

		struct rte_mbuf *pkt = pkts[pos];

		int ip_hdr_size_bytes = rte_ct_get_IP_hdr_size(pkt);

		if (unlikely(ip_hdr_size_bytes < 0)) {
			/* Not IPv4, ignore. */
			continue;
		}

		void *ip_hdr = RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);

		/* TCP and UDP ports at same offset, just use TCP for
		 * offset calculation
		 */
		struct tcp_hdr *thdr =
			(struct tcp_hdr *)RTE_MBUF_METADATA_UINT32_PTR(pkt,
					(IP_START + ip_hdr_size_bytes));
		uint16_t src_port = rte_bswap16(thdr->src_port);
		uint16_t dst_port = rte_bswap16(thdr->dst_port);

		if (ip_hdr_size_bytes == IPv4_HEADER_SIZE) {
			struct ipv4_hdr *ihdr = (struct ipv4_hdr *)ip_hdr;
			uint8_t proto = ihdr->next_proto_id;

			if (!(proto == TCP_PROTOCOL || proto == UDP_PROTOCOL)) {
				/* only tracking TCP and UDP at this time */
				continue;
			}

			/*
			 * Load the addresses and ports, and convert from Intel
			 * to network byte order. Strictly speaking, it is not
			 * necessary to do this conversion, as this data is only
			 * used to create a hash key.
			 */
			uint32_t src_addr = rte_bswap32(ihdr->src_addr);
			uint32_t dst_addr = rte_bswap32(ihdr->dst_addr);

			if (CNXN_TRX_DEBUG > 2) {
				if (CNXN_TRX_DEBUG > 4)
					rte_ct_cnxn_print_pkt(pkt,
							IP_VERSION_4);
			}
			/* need to create compacted table of pointers to pass
			 * to bulk lookup
			 */

			compacting_map[packets_for_lookup] = pos;
			key_orig_dir[packets_for_lookup] =
				rte_ct_create_cnxn_hashkey(&src_addr, &dst_addr,
						src_port, dst_port,
						proto,
						&ct->hash_keys
						[packets_for_lookup][0],
						IP_VERSION_4);
			packets_for_lookup++;
		}

		if (ip_hdr_size_bytes == IPv6_HEADER_SIZE) {
			struct ipv6_hdr *ihdr = (struct ipv6_hdr *)ip_hdr;
			uint8_t proto = ihdr->proto;

			if (!(proto == TCP_PROTOCOL || proto == UDP_PROTOCOL)) {
				/* only tracking TCP and UDP at this time */
				continue;
			}

			if (CNXN_TRX_DEBUG > 2) {
				if (CNXN_TRX_DEBUG > 4)
					rte_ct_cnxn_print_pkt(pkt,
							IP_VERSION_6);
			}

			/* need to create compacted table of pointers to pass
			 * to bulk lookup
			 */

			compacting_map[packets_for_lookup] = pos;
			key_orig_dir[packets_for_lookup] =
				rte_ct_create_cnxn_hashkey(
						(uint32_t *) ihdr->src_addr,
						(uint32_t *) ihdr->dst_addr,
						src_port, dst_port,
						proto,
						&ct->hash_keys
						[packets_for_lookup][0],
						IP_VERSION_6);
			packets_for_lookup++;
		}

	}

	if (unlikely(packets_for_lookup == 0))
		return valid_packets;	/* no suitable packet for lookup */

	/* Clear all the data to make sure no stack garbage is in it */
	memset(&new_cnxn_data, 0, sizeof(struct rte_ct_cnxn_data));

	/* lookup all tcp & udp packets in the connection table */

	int lookup_result =
			rte_hash_lookup_bulk(ct->rhash, (const void **)&ct->hash_key_ptrs,
				 packets_for_lookup, &positions[0]);

	if (unlikely(lookup_result < 0)) {
		/* TODO: change a log */
		printf("Unexpected hash table problem, discarding all packets");
		return 0;	/* unknown error, just discard all packets */
	}
#ifdef ALGDBG
	for (i = 0; i < packets_for_lookup; i++) {
		if (positions[i] >= 0)
		printf("@CT positions[i]= %d, compacting_map[i]= %d\n",
			positions[i], compacting_map[i]);
	}
#endif
	for (i = 0; i < packets_for_lookup; i++) {
		/* index into hash table entries */
		int hash_table_entry = positions[i];
		/* index into packet table of this packet */
		uint8_t pkt_index = compacting_map[i];
		/* bitmask representing only this packet */
		uint64_t pkt_mask = 1LLU << pkt_index;
		uint8_t key_is_client_order = key_orig_dir[i];
		uint32_t *key = ct->hash_key_ptrs[pkt_index];
		uint8_t protocol = *(key + 9);
		struct rte_mbuf *packet = pkts[pkt_index];
		int no_new_cnxn = (pkt_mask & no_new_cnxn_mask) != 0;

		 /* rte_ct_print_hashkey(key); */

		if (protocol == TCP_PROTOCOL) {
			enum rte_ct_packet_action tcp_pkt_action;

			int ip_hdr_size_bytes = rte_ct_get_IP_hdr_size(packet);
			tcp_pkt_action = rte_ct_handle_tcp_lookup(ct, packet,
					pkt_index, key_is_client_order,
					key, hash_table_entry, no_new_cnxn,
					ip_hdr_size_bytes);

			switch (tcp_pkt_action) {

			case RTE_CT_SEND_CLIENT_SYNACK:
			case RTE_CT_SEND_SERVER_ACK:
				/* altered packet or copy must be returned
				 * to originator
				 */
				*reply_pkt_mask |= pkt_mask;
				/* FALL-THROUGH */

			case RTE_CT_SEND_SERVER_SYN:
			case RTE_CT_FORWARD_PACKET:
				break;

			case RTE_CT_HIJACK:
				*hijack_mask |= pkt_mask;
				break;

			default:
				/* bad packet, clear mask to drop */
				valid_packets ^= pkt_mask;
				ct->counters->pkts_drop++;
				break;
			}

			/* rte_ct_cnxn_print_pkt(pkts[pkt_index]); */
		} else {	/* UDP entry */

			if (hash_table_entry >= 0) {
				/*
				 * connection found for this packet. Check that
				 * this is a valid packet for connection
				 */

				struct rte_ct_cnxn_data *entry =
						&ct->hash_table_entries[hash_table_entry];

				if (rte_ct_udp_packet
						(ct, entry, pkts[pkt_index],
						 key_is_client_order)) {
					entry->counters.packets_forwarded++;
					ct->counters->pkts_forwarded++;
				}
			} else {
				/*
				 * connection not found in bulk hash lookup,
				 * but might have been added in this batch
				 */

				struct rte_ct_cnxn_data *recent_entry =
						rte_ct_search_new_connections(ct, key);

				if (recent_entry != NULL) {
					if (rte_ct_udp_packet(ct, recent_entry,
							pkts[pkt_index],
							key_is_client_order)) {
						recent_entry->counters.
							packets_forwarded++;
						ct->counters->pkts_forwarded++;
					}
				} else {
					/* no existing connection, try to add
					 * new one
					 */

					if (no_new_cnxn) {
						/* new cnxn not allowed, clear
						 * mask to drop
						 */
						valid_packets ^= pkt_mask;
						ct->counters->pkts_drop++;
						ct->counters->
						pkts_drop_invalid_conn++;
						continue;
					}

					if (rte_ct_udp_new_connection(ct,
							&new_cnxn_data,
							pkts[pkt_index])) {
						/* This packet creates a
						 * connection .
						 */
						int32_t position =
							rte_hash_add_key(
								ct->rhash, key);

					if (position < 0)
						continue;

						struct rte_ct_cnxn_data
							*new_hash_entry = &ct->
						hash_table_entries[position];

						/*
						 *update fields in new_cnxn_data
						 * not set by "new_connection"
						 */

						memcpy(new_cnxn_data.key, key,
						sizeof(new_cnxn_data.key));

						new_cnxn_data.
							key_is_client_order
							= key_is_client_order;
						new_cnxn_data.protocol =
							UDP_PROTOCOL;
						rte_cnxn_ip_type(
							&new_cnxn_data.type,
							packet);
						rte_memcpy(new_hash_entry,
							&new_cnxn_data,
							sizeof(struct
							rte_ct_cnxn_data));

						new_hash_entry->counters.
							packets_forwarded = 1;
						ct->counters->pkts_forwarded++;
						new_hash_entry->counters.
							packets_dropped = 0;
						ct->counters->pkts_drop = 0;
						ct->counters->
						current_active_sessions++;
						ct->counters->
							sessions_activated++;

						new_hash_entry->
							state_used_for_timer
							= RTE_CT_UDP_NONE;
						rte_ct_set_cnxn_timer_for_udp(
							ct,
							new_hash_entry,
							RTE_CT_UDP_UNREPLIED);

						rte_ct_remember_new_connection(
								ct,
								new_hash_entry);
					}
				}

			}

		}		/* UDP */
	}			/* packets_for_lookup */

	if (CNXN_TRX_DEBUG > 1) {
		printf("Exit cnxn tracker synproxy batch lookup with");
		printf(" packet mask %p\n", (void *)valid_packets);
	}

	return valid_packets;
}

uint64_t
rte_ct_cnxn_tracker_batch_lookup_with_synproxy(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_mbuf **pkts,
	uint64_t pkts_mask,
	struct rte_synproxy_helper *sp_helper)
{
	return rte_ct_cnxn_tracker_batch_lookup_basic(ct, pkts, pkts_mask, 0,
			&sp_helper->reply_pkt_mask, &sp_helper->hijack_mask);
}
#ifdef CT_CGNAT
uint64_t cgnapt_ct_process(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_mbuf **pkts,
	uint64_t pkts_mask,
	struct rte_CT_helper *ct_helper)
{
/* to disable SynProxy for CGNAT */
	rte_ct_disable_synproxy(ct);
	return rte_ct_cnxn_tracker_batch_lookup_basic(ct, pkts, pkts_mask,
					ct_helper->no_new_cnxn_mask,
					&ct_helper->reply_pkt_mask,
					&ct_helper->hijack_mask);
}
#endif/*CT-CGNAT*/
uint64_t
rte_ct_cnxn_tracker_batch_lookup(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_mbuf **pkts,
	uint64_t pkts_mask,
	struct rte_CT_helper *ct_helper)
{

	return rte_ct_cnxn_tracker_batch_lookup_basic(ct, pkts, pkts_mask,
			ct_helper->no_new_cnxn_mask,
			&ct_helper->reply_pkt_mask, &ct_helper->hijack_mask);
}


void rte_ct_cnxn_tracker_batch_lookup_type(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_mbuf **pkts,
	uint64_t *pkts_mask,
	struct rte_CT_helper *ct_helper,
	uint8_t ip_hdr_size_bytes)
{

	rte_ct_cnxn_tracker_batch_lookup_basic_type(ct, pkts, pkts_mask,
			ct_helper->no_new_cnxn_mask,
			&ct_helper->reply_pkt_mask, &ct_helper->hijack_mask,
			ip_hdr_size_bytes);
}



uint64_t
rte_ct_cnxn_tracker_batch_lookup_with_new_cnxn_control(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_mbuf **pkts,
	uint64_t pkts_mask,
	uint64_t no_new_cnxn_mask)
{
	uint64_t dont_care;

	return rte_ct_cnxn_tracker_batch_lookup_basic(ct, pkts, pkts_mask,
			no_new_cnxn_mask,
			&dont_care, &dont_care);
}


int
rte_ct_initialize_default_timeouts(struct rte_ct_cnxn_tracker *new_cnxn_tracker)
{

	/* timer system init */

	uint64_t hertz = rte_get_tsc_hz();

	new_cnxn_tracker->hertz = hertz;
	new_cnxn_tracker->timing_cycles_per_timing_step = hertz / 10;
	new_cnxn_tracker->timing_100ms_steps_previous = 0;
	new_cnxn_tracker->timing_100ms_steps = 0;
	new_cnxn_tracker->timing_last_time = rte_get_tsc_cycles();

	/* timeouts in seconds */
	new_cnxn_tracker->ct_timeout.tcptimeout.tcp_timeouts
		[RTE_CT_TCP_SYN_SENT] = 120 * hertz;
	new_cnxn_tracker->ct_timeout.tcptimeout.tcp_timeouts
		[RTE_CT_TCP_SYN_RECV] = 60 * hertz;
	/* 5 * DAYS */
	new_cnxn_tracker->ct_timeout.tcptimeout.tcp_timeouts
		[RTE_CT_TCP_ESTABLISHED] = 60 * 60 * 24 * 5 * hertz;

	new_cnxn_tracker->ct_timeout.tcptimeout.tcp_timeouts
		[RTE_CT_TCP_FIN_WAIT] = 120 * hertz;
	new_cnxn_tracker->ct_timeout.tcptimeout.tcp_timeouts
		[RTE_CT_TCP_CLOSE_WAIT] = 60 * hertz;
	new_cnxn_tracker->ct_timeout.tcptimeout.tcp_timeouts
		[RTE_CT_TCP_LAST_ACK] = 30 * hertz;
	new_cnxn_tracker->ct_timeout.tcptimeout.tcp_timeouts
		[RTE_CT_TCP_TIME_WAIT] = 120 * hertz;
	new_cnxn_tracker->ct_timeout.tcptimeout.tcp_timeouts
		[RTE_CT_TCP_CLOSE] = 10 * hertz;
	new_cnxn_tracker->ct_timeout.tcptimeout.tcp_timeouts
		[RTE_CT_TCP_SYN_SENT_2] = 120 * hertz;
	new_cnxn_tracker->ct_timeout.tcptimeout.tcp_timeouts
		[RTE_CT_TCP_RETRANS] = 300 * hertz;
	new_cnxn_tracker->ct_timeout.tcptimeout.tcp_timeouts
		[RTE_CT_TCP_UNACK] = 300 * hertz;

	new_cnxn_tracker->ct_timeout.udptimeout.udp_timeouts
		[RTE_CT_UDP_UNREPLIED] = 30 * hertz;
	new_cnxn_tracker->ct_timeout.udptimeout.udp_timeouts
		[RTE_CT_UDP_REPLIED] = 180 * hertz;
	/* miscellaneous init */
	new_cnxn_tracker->misc_options.tcp_max_retrans =
		RTE_CT_TCP_MAX_RETRANS;
	new_cnxn_tracker->misc_options.tcp_loose = 0;
	new_cnxn_tracker->misc_options.tcp_be_liberal = 0;
#ifdef CT_CGNAT
	int i;
	for (i=0; i < RTE_HASH_LOOKUP_BULK_MAX ;i ++ )
			new_cnxn_tracker->positions[i] = -1;
#endif

	return 0;
}

struct rte_CT_counter_block rte_CT_counter_table[MAX_CT_INSTANCES]
__rte_cache_aligned;
int rte_CT_hi_counter_block_in_use = -1;

int
rte_ct_initialize_cnxn_tracker_with_synproxy(
	struct rte_ct_cnxn_tracker *new_cnxn_tracker,
	uint32_t max_connection_count,
	char *name,
	uint16_t pointer_offset)
{
	uint32_t i;
	uint32_t size;
	struct rte_CT_counter_block *counter_ptr;
	/*
	 * TODO: Should number of entries be something like
	 * max_connection_count * 1.1 to allow for unused space
	 * and thus increased performance of hash table, at a cost of memory???
	 */

	new_cnxn_tracker->pointer_offset = pointer_offset;

	memset(new_cnxn_tracker->name, '\0', sizeof(new_cnxn_tracker->name));
	strncpy(new_cnxn_tracker->name, name, strlen(new_cnxn_tracker->name));
	//strcpy(new_cnxn_tracker->name, name);
	/* + (max_connection_count >> 3); */
	uint32_t number_of_entries = max_connection_count;

	size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct rte_ct_cnxn_data) *
			number_of_entries);
	new_cnxn_tracker->hash_table_entries =
		rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
	if (new_cnxn_tracker->hash_table_entries == NULL) {
		printf(" Not enough memory, or invalid arguments\n");
		return -1;
	}
	new_cnxn_tracker->num_cnxn_entries = number_of_entries;

	/* initialize all timers */

	for (i = 0; i < number_of_entries; i++)
		rte_timer_init(&new_cnxn_tracker->hash_table_entries[i].timer);

	/* pointers for temp storage used during bulk hash */
	for (i = 0; i < RTE_HASH_LOOKUP_BULK_MAX; i++)
		new_cnxn_tracker->hash_key_ptrs[i] =
				&new_cnxn_tracker->hash_keys[i][0];

	/*
	 * Now allocate a counter block entry.It appears that the initialization
	 * of these threads is serialized on core 0 so no lock is necessary
	 */

	if (rte_CT_hi_counter_block_in_use == MAX_CT_INSTANCES)
		return -1;

	rte_CT_hi_counter_block_in_use++;
	counter_ptr = &rte_CT_counter_table[rte_CT_hi_counter_block_in_use];

	new_cnxn_tracker->counters = counter_ptr;

	/* set up hash table parameters, then create hash table */
	struct rte_hash_parameters rhash_parms = {
		.name = name,
		.entries = number_of_entries,
		.hash_func = NULL,	/* use default hash */
		.key_len = 40,
		.hash_func_init_val = 0,
		.socket_id = app_get_socket_id(),
		.extra_flag = 1 /*This is needed for TSX memory*/
	};

	new_cnxn_tracker->rhash = rte_hash_create(&rhash_parms);

	return 0;
}

int
rte_ct_initialize_cnxn_tracker(
	struct rte_ct_cnxn_tracker *new_cnxn_tracker,
	uint32_t max_connection_count,
	char *name)
{
	return rte_ct_initialize_cnxn_tracker_with_synproxy(new_cnxn_tracker,
				max_connection_count, name, 0);
}

int
rte_ct_free_cnxn_tracker_resources(struct rte_ct_cnxn_tracker *old_cnxn_tracker)
{
	rte_free(old_cnxn_tracker->hash_table_entries);
	rte_hash_free(old_cnxn_tracker->rhash);
	return 0;
}

int
rte_ct_get_cnxn_tracker_size(void)
{
	return sizeof(struct rte_ct_cnxn_tracker);
}

void
rte_ct_cnxn_timer_expired(struct rte_timer *rt, void *arg);

static void
rte_ct_set_cnxn_timer(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_ct_cnxn_data *cd,
	uint64_t ticks_until_timeout)
{
	/*
	 * pointer to cnxn_data will be stored in timer system as pointer to
	 * rte_timer for later cast back to cnxn_data during timeout handling
	 */

	struct rte_timer *rt = (struct rte_timer *)cd;
	#ifdef CT_CGNAT
	/* execute timeout on timer core */
	uint32_t core_id = get_timer_core_id();
	#else
	/* execute timeout on current core */
	uint32_t core_id = rte_lcore_id();
	#endif
	/* safe to reset since timeouts handled synchronously
	 * by rte_timer_manage
	 */
	int success = rte_timer_reset(rt, ticks_until_timeout, SINGLE, core_id,
			rte_ct_cnxn_timer_expired, ct);

	if (success < 0) {
		/* TODO: Change to log, perhaps something else?
		 * This should not happen
		 */
		printf("CNXN_TRACKER: Failed to set connection timer.\n");
	}
}

/*
 * For the given connection, set a timeout based on the given state. If the
* timer is already set, this call will reset the timer with a new value.
 */

void
rte_ct_set_cnxn_timer_for_tcp(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_ct_cnxn_data *cd,
	uint8_t tcp_state)
{

	cd->expected_timeout =
			(ct->timing_100ms_steps * ct->timing_cycles_per_timing_step) +
			ct->ct_timeout.tcptimeout.tcp_timeouts[tcp_state];

	if (tcp_state == cd->state_used_for_timer) {
		/*
		 * Don't reset timer, too expensive. Instead, determine time
		 * elapsed since start of timer. When this timer expires, the
		 * timer will be reset to the elapsed timer. So if in a state
		 * with a 5 minute timer last sees a packet 4 minutes into the
		 * timer, the timer when expires will be reset to 4 minutes.
		 * This means the timer will then expire 5 minutes after
		 * the last packet.
		 */
		return;
	}

	if (TESTING_TIMERS)
		printf("Set Timer for connection %p and state %s\n", cd,
					 rte_ct_tcp_names[tcp_state]);

	rte_ct_set_cnxn_timer(ct, cd,
						ct->ct_timeout.
						tcptimeout.tcp_timeouts[tcp_state]);
	cd->state_used_for_timer = tcp_state;
}

/*
 * For the given connection, set a timeout based on the given state.
 * If the timer is already set,
 * this call will reset the timer with a new value.
 */

void
rte_ct_set_cnxn_timer_for_udp(
	struct rte_ct_cnxn_tracker *ct,
	struct rte_ct_cnxn_data *cd,
	uint8_t udp_state)
{

	cd->expected_timeout = (ct->timing_cycles_per_timing_step) +
			ct->ct_timeout.udptimeout.udp_timeouts[udp_state];

	if (udp_state == cd->state_used_for_timer) {
		/*
		 * Don't reset timer, too expensive. Instead, determine time
		 * elapsed since start of timer. When this timer expires, the
		 * timer will be reset to the elapsed timer. So if in a state
		 * with a 5 minute timer last sees a packet 4 minutes into the
		 * timer, the timer when expires will be reset to 4 minutes.
		 * This means the timer will then
		 * expire 5 minutes after the last packet.
		 */
		return;
	}

	if (TESTING_TIMERS)
		printf("Set Timer for connection %p and state %s\n", cd,
					 rte_ct_udp_names[udp_state]);
	rte_ct_set_cnxn_timer(ct, cd,
						ct->ct_timeout.
						udptimeout.udp_timeouts[udp_state]);
	cd->state_used_for_timer = udp_state;
}

/* Cancel the timer associated with the connection.
 * Safe to call if no timer set.
 */
	void
rte_ct_cancel_cnxn_timer(struct rte_ct_cnxn_data *cd)
{
	if (TESTING_TIMERS)
		printf("Cancel Timer\n");

	rte_timer_stop(&cd->timer);
}

void
rte_ct_handle_expired_timers(struct rte_ct_cnxn_tracker *ct)
{
	/*
	 * If current time (in 100 ms increments) is different from the
	 * time it was last viewed, then check for and process expired timers.
	 */

	uint64_t new_time = rte_get_tsc_cycles();
	uint64_t time_diff = new_time - ct->timing_last_time;

	if (time_diff >= ct->timing_cycles_per_timing_step) {
		ct->timing_last_time = new_time;
		ct->timing_100ms_steps++;
	}

	if (ct->timing_100ms_steps != ct->timing_100ms_steps_previous) {
		rte_timer_manage();
		ct->timing_100ms_steps_previous = ct->timing_100ms_steps;
	}
}

/* timer has expired. Need to delete connection entry */

void
rte_ct_cnxn_timer_expired(struct rte_timer *rt, void *arg)
{
	/* the pointer to the rte_timer was actually a pointer
	 * to the cnxn data
	 */
	struct rte_ct_cnxn_data *cd = (struct rte_ct_cnxn_data *)rt;
	struct rte_ct_cnxn_tracker *ct = (struct rte_ct_cnxn_tracker *)arg;
	int success = 0;

	/*
	 * Check to see if the timer has "really" expired. If traffic occured
	 * since the timer was set, the timer needs be extended, so that timer
	 * expires the appropriate amount after that last packet.
	 */

	uint64_t current_time = ct->timing_100ms_steps *
		ct->timing_cycles_per_timing_step;

	if (cd->expected_timeout >= current_time) {
		uint64_t time_diff = cd->expected_timeout - current_time;

		rte_ct_set_cnxn_timer(ct, cd, time_diff);
		return;
	}

	if (cd->protocol == TCP_PROTOCOL) {
		if (cd->state_used_for_timer == RTE_CT_TCP_TIME_WAIT ||
				cd->state_used_for_timer == RTE_CT_TCP_CLOSE)
			ct->counters->sessions_closed++;
		else
			ct->counters->sessions_timedout++;
		/* if synproxied connection, free list of buffered
		 * packets if any
		 */

		if (cd->ct_protocol.synproxy_data.synproxied)
			rte_ct_release_buffered_packets(ct, cd);

	} else if (cd->protocol == UDP_PROTOCOL)
		ct->counters->sessions_closed++;
	if (ct->counters->current_active_sessions > 0)
		ct->counters->current_active_sessions--;

	if (RTE_CT_TIMER_EXPIRED_DUMP) {
		uint64_t percent = (cd->counters.packets_dropped * 10000) /
				(cd->counters.packets_forwarded +
				 cd->counters.packets_dropped);

		if (cd->protocol == TCP_PROTOCOL) {
			printf("CnxnTrkr %s, timed-out TCP Connection: %p,",
					ct->name, cd);
			printf(" %s, pkts forwarded %"
				PRIu64 ", pkts dropped %" PRIu64
				", drop%% %u.%u\n",
				rte_ct_tcp_names[cd->state_used_for_timer],
				cd->counters.packets_forwarded,
				cd->counters.packets_dropped,
				(uint32_t) (percent / 100),
				(uint32_t) (percent % 100));
		} else if (cd->protocol == UDP_PROTOCOL) {
			printf("CnxnTrkr %s, Timed-out UDP Connection: %p,",
					ct->name, cd);
			printf(" %s, pkts forwarded %" PRIu64
				", pkts dropped %" PRIu64 ", drop%% %u.%u\n",
				rte_ct_udp_names[cd->state_used_for_timer],
				cd->counters.packets_forwarded,
				cd->counters.packets_dropped,
				(uint32_t) (percent / 100),
				(uint32_t) (percent % 100));
		}
	}

	success = rte_hash_del_key(ct->rhash, &cd->key);

	if (success < 0) {
		/* TODO: change to a log */
		rte_ct_print_hashkey(cd->key);
	}

}

struct rte_CT_counter_block *
rte_ct_get_counter_address(struct rte_ct_cnxn_tracker *ct)
{
	return ct->counters;
}

int
rte_ct_set_configuration_options(struct rte_ct_cnxn_tracker *ct,
		char *name, char *value)
{
	/* check non-time values first */
	int ival = atoi(value);

	/* tcp_loose */
	if (strcmp(name, "tcp_loose") == 0) {
		ct->misc_options.tcp_loose = ival;
		return 0;
	}

	/* tcp_be_liberal */
	if (strcmp(name, "tcp_be_liberal") == 0) {
		ct->misc_options.tcp_be_liberal = ival;
		return 0;
	}

	/* tcp_max_retrans */
	if (strcmp(name, "tcp_max_retrans") == 0) {
		ct->misc_options.tcp_max_retrans = ival;
		return 0;
	}

	uint64_t time_value = ival * ct->hertz;


	/* configuration of timer values */

	/* tcp_syn_sent */
	if (strcmp(name, "tcp_syn_sent") == 0) {
		if (time_value == 0)
			return -1;
		ct->ct_timeout.tcptimeout.tcp_timeouts[RTE_CT_TCP_SYN_SENT] =
			time_value;
		return 0;
	}

	/* tcp_syn_recv */
	if (strcmp(name, "tcp_syn_recv") == 0) {
		if (time_value == 0)
			return -1;
		ct->ct_timeout.tcptimeout.tcp_timeouts[RTE_CT_TCP_SYN_RECV] =
			time_value;
		return 0;
	}

	/* tcp_established */
	if (strcmp(name, "tcp_established") == 0) {
		if (time_value == 0)
			return -1;
		ct->ct_timeout.tcptimeout.tcp_timeouts[RTE_CT_TCP_ESTABLISHED] =
			time_value;
		return 0;
	}

	/* tcp_fin_wait */
	if (strcmp(name, "tcp_fin_wait") == 0) {
		if (time_value == 0)
			return -1;
		ct->ct_timeout.tcptimeout.tcp_timeouts[RTE_CT_TCP_FIN_WAIT] =
			time_value;
		return 0;
	}

	/* tcp_close_wait */
	if (strcmp(name, "tcp_close_wait") == 0) {
		if (time_value == 0)
			return -1;
		ct->ct_timeout.tcptimeout.tcp_timeouts[RTE_CT_TCP_CLOSE_WAIT] =
			time_value;
		return 0;
	}

	/* tcp_last_ack */
	if (strcmp(name, "tcp_last_ack") == 0) {
		if (time_value == 0)
			return -1;
		ct->ct_timeout.tcptimeout.tcp_timeouts[RTE_CT_TCP_LAST_ACK] =
			time_value;
		return 0;
	}

	/* tcp_time_wait */
	if (strcmp(name, "tcp_time_wait") == 0) {
		if (time_value == 0)
			return -1;
		ct->ct_timeout.tcptimeout.tcp_timeouts[RTE_CT_TCP_TIME_WAIT] =
			time_value;
		return 0;
	}

	/* tcp_close */
	if (strcmp(name, "tcp_close") == 0) {
		if (time_value == 0)
			return -1;
		ct->ct_timeout.tcptimeout.tcp_timeouts[RTE_CT_TCP_CLOSE] =
			time_value;
		return 0;
	}

	/* tcp_syn_sent_2 */
	if (strcmp(name, "tcp_syn_sent_2") == 0) {
		if (time_value == 0)
			return -1;
		ct->ct_timeout.tcptimeout.tcp_timeouts[RTE_CT_TCP_SYN_SENT_2] =
			time_value;
		return 0;
	}

	/* tcp_retrans */
	if (strcmp(name, "tcp_retrans") == 0) {
		if (time_value == 0)
			return -1;
		ct->ct_timeout.tcptimeout.tcp_timeouts[RTE_CT_TCP_RETRANS] =
			time_value;
		return 0;
	}

	/* tcp_unack */
	if (strcmp(name, "tcp_unack") == 0) {
		if (time_value == 0)
			return -1;
		ct->ct_timeout.tcptimeout.tcp_timeouts[RTE_CT_TCP_UNACK] =
			time_value;
		return 0;
	}

	/* udp_unreplied */
	if (strcmp(name, "udp_unreplied") == 0) {
		if (time_value == 0)
			return -1;
		ct->ct_timeout.udptimeout.udp_timeouts[RTE_CT_UDP_UNREPLIED] =
			time_value;
		return 0;
	}

	/* udp_replied */
	if (strcmp(name, "udp_replied") == 0) {
		if (time_value == 0)
			return -1;
		ct->ct_timeout.udptimeout.udp_timeouts[RTE_CT_UDP_REPLIED] =
			time_value;
		return 0;
	}
	return 1;
}

static void
rte_ct_cnxn_tracker_batch_lookup_basic_type(
		struct rte_ct_cnxn_tracker *ct,
		struct rte_mbuf **pkts,
		uint64_t *pkts_mask,
		uint64_t no_new_cnxn_mask,
		uint64_t *reply_pkt_mask,
		uint64_t *hijack_mask,
		uint8_t ip_hdr_size_bytes)
{
	/* bitmap of packets left to process */
	uint64_t pkts_to_process = *pkts_mask;
	/* bitmap of valid packets to return */
	uint8_t compacting_map[RTE_HASH_LOOKUP_BULK_MAX];
	/* for pkt, key in originators direction? */
	uint8_t key_orig_dir[RTE_HASH_LOOKUP_BULK_MAX];
	uint32_t packets_for_lookup = 0;
	int32_t positions[RTE_HASH_LOOKUP_BULK_MAX];
	uint32_t i;
	struct rte_ct_cnxn_data new_cnxn_data;
	struct rte_ct_cnxn_data *cnxn_data_entry[RTE_HASH_LOOKUP_BULK_MAX];

	rte_prefetch0(ct->hash_table_entries);

	if (CNXN_TRX_DEBUG > 1) {
		printf("Enter cnxn tracker %p", ct);
		printf(" synproxy batch lookup with packet mask %p\n",
				(void *)*pkts_mask);
	}

	rte_ct_forget_new_connections(ct);
	*reply_pkt_mask = 0;
	*hijack_mask = 0;

	/*
	 * Use bulk lookup into hash table for performance reasons. Cannot have
	 * "empty slots" in the bulk lookup,so need to create a compacted table.
	 */

	switch (ip_hdr_size_bytes) {
	case IPv4_HEADER_SIZE:
		for (; pkts_to_process;) {
			uint8_t pos = (uint8_t) __builtin_ctzll(
					pkts_to_process);
			/* bitmask representing only this packet */
			uint64_t pkt_mask = 1LLU << pos;
			/* remove this packet from remaining list */
			pkts_to_process &= ~pkt_mask;

			struct rte_mbuf *pkt = pkts[pos];


			/* TCP and UDP ports at same offset, just use TCP for
			 * offset calculation
			 */
			struct tcp_hdr *thdr = (struct tcp_hdr *)
				RTE_MBUF_METADATA_UINT32_PTR(pkt,
						(IP_START + ip_hdr_size_bytes));
			uint16_t src_port = rte_bswap16(thdr->src_port);
			uint16_t dst_port = rte_bswap16(thdr->dst_port);

			struct ipv4_hdr *ihdr = (struct ipv4_hdr *)
				RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);
			uint8_t proto = ihdr->next_proto_id;

			if (!(proto == TCP_PROTOCOL || proto == UDP_PROTOCOL)) {
				/* only tracking TCP and UDP at this time */
				continue;
			}

			/*
			 * Load the addresses and ports, and convert from Intel
			 * to network byte order. Strictly speaking, it is not
			 * necessary to do this conversion, as this data is only
			 * used to create a hash key.
			 */
			uint32_t src_addr = rte_bswap32(ihdr->src_addr);
			uint32_t dst_addr = rte_bswap32(ihdr->dst_addr);

			if (CNXN_TRX_DEBUG > 2) {
				if (CNXN_TRX_DEBUG > 4)
					rte_ct_cnxn_print_pkt(pkt,
							IP_VERSION_4);
			}
			/* need to create compacted table of pointers to pass
			 * to bulk lookup
			 */

			compacting_map[packets_for_lookup] = pos;
			key_orig_dir[packets_for_lookup] =
				rte_ct_create_cnxn_hashkey(&src_addr, &dst_addr,
						src_port, dst_port,
						proto,
						&ct->hash_keys
						[packets_for_lookup][0],
						IP_VERSION_4);
			packets_for_lookup++;
		}
		break;
	case IPv6_HEADER_SIZE:
		for (; pkts_to_process;) {
			uint8_t pos = (uint8_t) __builtin_ctzll(
					pkts_to_process);
			/* bitmask representing only this packet */
			uint64_t pkt_mask = 1LLU << pos;
			/* remove this packet from remaining list */
			pkts_to_process &= ~pkt_mask;

			struct rte_mbuf *pkt = pkts[pos];


			void *ip_hdr = RTE_MBUF_METADATA_UINT32_PTR(pkt,
					IP_START);

			/* TCP and UDP ports at same offset, just use TCP for
			 * offset calculation
			 */
			struct tcp_hdr *thdr = (struct tcp_hdr *)
				RTE_MBUF_METADATA_UINT32_PTR(pkt,
						(IP_START + ip_hdr_size_bytes));
			uint16_t src_port = rte_bswap16(thdr->src_port);
			uint16_t dst_port = rte_bswap16(thdr->dst_port);

			struct ipv6_hdr *ihdr = (struct ipv6_hdr *)ip_hdr;
			uint8_t proto = ihdr->proto;

			if (!(proto == TCP_PROTOCOL || proto == UDP_PROTOCOL)) {
				/* only tracking TCP and UDP at this time */
				continue;
			}

			if (CNXN_TRX_DEBUG > 2) {
				if (CNXN_TRX_DEBUG > 4)
					rte_ct_cnxn_print_pkt(pkt,
							IP_VERSION_6);
			}

			/* need to create compacted table of pointers to pass
			 * to bulk lookup
			 */

			compacting_map[packets_for_lookup] = pos;
			key_orig_dir[packets_for_lookup] =
				rte_ct_create_cnxn_hashkey(
						(uint32_t *) ihdr->src_addr,
						(uint32_t *) ihdr->dst_addr,
						src_port, dst_port,
						proto,
						&ct->hash_keys
						[packets_for_lookup][0],
						IP_VERSION_6);
			packets_for_lookup++;
		}
		break;
	default:
		break;
	}
	if (unlikely(packets_for_lookup == 0))
		return;	/* no suitable packet for lookup */

	/* Clear all the data to make sure no stack garbage is in it */
	memset(&new_cnxn_data, 0, sizeof(struct rte_ct_cnxn_data));

	/* lookup all tcp & udp packets in the connection table */

	int lookup_result = rte_hash_lookup_bulk(ct->rhash,
			(const void **)&ct->hash_key_ptrs,
			packets_for_lookup, &positions[0]);

	if (unlikely(lookup_result < 0)) {
		/* TODO: change a log */
		printf("Unexpected hash table problem, discarding all packets");
		*pkts_mask = 0;
		return;	/* unknown error, just discard all packets */
	}

	/* Pre-fetch hash table entries and counters to avoid LLC miss */
	rte_prefetch0(ct->counters);
	for (i = 0; i < packets_for_lookup; i++) {
		struct rte_ct_cnxn_data *entry = NULL;
		int hash_table_entry = positions[i];

		if (hash_table_entry >= 0) {
			/* Entry found for existing UDP/TCP connection */
			entry = &ct->hash_table_entries[hash_table_entry];
			rte_prefetch0(&entry->counters.packets_forwarded);
			rte_prefetch0(entry);
			rte_prefetch0(&entry->key_is_client_order);
		}
		else {
			uint8_t pkt_index = compacting_map[i];
			uint32_t *key = ct->hash_key_ptrs[pkt_index];
			uint8_t protocol = *(key + 9);
			if (protocol == UDP_PROTOCOL) {
				/* Serach in new connections only for UDP */
				entry = rte_ct_search_new_connections(ct, key);
				rte_prefetch0(&entry->counters.packets_forwarded);
				rte_prefetch0(entry);
				rte_prefetch0(&entry->key_is_client_order);
			}
		}
		cnxn_data_entry[i] = entry;
	}

	for (i = 0; i < packets_for_lookup; i++) {
		/* index into hash table entries */
		int hash_table_entry = positions[i];
		/* index into packet table of this packet */
		uint8_t pkt_index = compacting_map[i];
		/* bitmask representing only this packet */
		uint64_t pkt_mask = 1LLU << pkt_index;
		uint8_t key_is_client_order = key_orig_dir[i];
		uint32_t *key = ct->hash_key_ptrs[pkt_index];
		uint8_t protocol = *(key + 9);
		struct rte_mbuf *packet = pkts[pkt_index];
		int no_new_cnxn = (pkt_mask & no_new_cnxn_mask) != 0;

		/* rte_ct_print_hashkey(key); */

		if (protocol == TCP_PROTOCOL) {
			enum rte_ct_packet_action tcp_pkt_action;

			tcp_pkt_action = rte_ct_handle_tcp_lookup(ct, packet,
					pkt_index, key_is_client_order,
					key, hash_table_entry, no_new_cnxn,
					ip_hdr_size_bytes);

			switch (tcp_pkt_action) {

			case RTE_CT_SEND_CLIENT_SYNACK:
			case RTE_CT_SEND_SERVER_ACK:
				/* altered packet or copy must be returned
				 * to originator
				 */
				*reply_pkt_mask |= pkt_mask;
				/* FALL-THROUGH */

			case RTE_CT_SEND_SERVER_SYN:
			case RTE_CT_FORWARD_PACKET:
				break;

			case RTE_CT_HIJACK:
				*hijack_mask |= pkt_mask;
				break;

			default:
				/* bad packet, clear mask to drop */
				*pkts_mask ^= pkt_mask;
				ct->counters->pkts_drop++;
				break;
		}
			/* rte_ct_cnxn_print_pkt(pkts[pkt_index]); */

		} else {	/* UDP entry */

			if (hash_table_entry >= 0) {
				/*
				 * connection found for this packet. Check that
				 * this is a valid packet for connection
				 */

				struct rte_ct_cnxn_data *entry =
					cnxn_data_entry[i];

				if (rte_ct_udp_packet
						(ct, entry, pkts[pkt_index],
						 key_is_client_order)) {
					entry->counters.packets_forwarded++;
					ct->counters->pkts_forwarded++;
				}
			} else {
				/*
				 * connection not found in bulk hash lookup,
				 * but might have been added in this batch
				 */

				struct rte_ct_cnxn_data *recent_entry =
					cnxn_data_entry[i];

				if (recent_entry != NULL) {
					if (rte_ct_udp_packet(ct, recent_entry,
							pkts[pkt_index],
							key_is_client_order)) {
						recent_entry->counters.
							packets_forwarded++;
						ct->counters->pkts_forwarded++;
					}
				} else {
					/* no existing connection, try to add
					 * new one
					 */

					if (no_new_cnxn) {
						/* new cnxn not allowed, clear
						 * mask to drop
						 */
						*pkts_mask ^= pkt_mask;
						ct->counters->pkts_drop++;
						ct->counters->
						pkts_drop_invalid_conn++;
						continue;
					}

					if (rte_ct_udp_new_connection(ct,
					&new_cnxn_data, pkts[pkt_index])) {
						/* This packet creates a
						 * connection
						 */
						int32_t position =
							rte_hash_add_key(ct->
								rhash, key);

					if (position < 0)
						continue;

						struct rte_ct_cnxn_data
							*new_hash_entry = &ct->
						hash_table_entries[position];

						/*
						 *update fields in new_cnxn_data
						 * not set by "new_connection"
						 */

						memcpy(new_cnxn_data.key, key,
						sizeof(new_cnxn_data.key));

						new_cnxn_data.
							key_is_client_order
							= key_is_client_order;
						new_cnxn_data.protocol =
							UDP_PROTOCOL;
						rte_cnxn_ip_type(
							&new_cnxn_data.type,
							packet);
						rte_memcpy(new_hash_entry,
							&new_cnxn_data,
							sizeof(struct
							rte_ct_cnxn_data));

						new_hash_entry->counters.
							packets_forwarded = 1;
						ct->counters->pkts_forwarded++;
						new_hash_entry->counters.
							packets_dropped = 0;
						ct->counters->pkts_drop = 0;
						ct->counters->
						current_active_sessions++;
						ct->counters->
							sessions_activated++;

						new_hash_entry->
							state_used_for_timer
							= RTE_CT_UDP_NONE;
						rte_ct_set_cnxn_timer_for_udp(
							ct,
							new_hash_entry,
							RTE_CT_UDP_UNREPLIED);

						rte_ct_remember_new_connection(
								ct,
								new_hash_entry);
					}
				}

			}

		}		/* UDP */
	}			/* packets_for_lookup */

	if (CNXN_TRX_DEBUG > 1) {
		printf("Exit cnxn tracker synproxy batch lookup with");
		printf(" packet mask %p\n", (void *)*pkts_mask);
	}
}
