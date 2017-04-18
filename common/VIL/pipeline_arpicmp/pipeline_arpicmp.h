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

#ifndef __INCLUDE_PIPELINE_ARPICMP_H__
#define __INCLUDE_PIPELINE_ARPICMP_H__

#include "pipeline.h"
#include "pipeline_arpicmp_be.h"

/*
 * Pipeline type
 */
extern struct pipeline_type pipeline_arpicmp;
//uint16_t verbose_level = 1; /**< should be Silent by default. */
#define MAX_PKT_BURST 512
#define DEF_PKT_BURST 32
/**< Number of packets per burst. */
//uint16_t nb_pkt_per_burst = DEF_PKT_BURST;
typedef uint8_t  portid_t;
typedef uint16_t queueid_t;
typedef uint16_t streamid_t;
/**
 * The data structure associated with a forwarding stream between a receive
 * port/queue and a transmit port/queue.
 */
struct fwd_stream {
	/* "read-only" data */
	/**< port to poll for received packets */
	portid_t   rx_port;
	/**< RX queue to poll on "rx_port" */
	queueid_t  rx_queue;
	/**< forwarding port of received packets */
	portid_t   tx_port;
	/**< TX queue to send forwarded packets */
	queueid_t  tx_queue;
	/**< index of peer ethernet address of packets */
	streamid_t peer_addr;

	/* "read-write" results */
	/**< received packets */
	unsigned int rx_packets;
	/**< received packets transmitted */
	unsigned int tx_packets;
	/**< received packets not forwarded */
	unsigned int fwd_dropped;
	/**< received packets has bad ip checksum */
	unsigned int rx_bad_ip_csum;
	/**< received packets has bad l4 checksum */
	unsigned int rx_bad_l4_csum;
	#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	uint64_t     core_cycles; /**< used for RX and TX processing */
	#endif
	#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	struct pkt_burst_stats rx_burst_stats;
	struct pkt_burst_stats tx_burst_stats;
	#endif
};
/*
 * Forwarding mode operations:
 *   - IO forwarding mode (default mode)
 *     Forwards packets unchanged.
 *
 *   - MAC forwarding mode
 *     Set the source and the destination Ethernet addresses of packets
 *     before forwarding them.
 *
 *   - IEEE1588 forwarding mode
 *     Check that received IEEE1588 Precise Time Protocol (PTP) packets are
 *     filtered and timestamped by the hardware.
 *     Forwards packets unchanged on the same port.
 *     Check that sent IEEE1588 PTP packets are timestamped by the hardware.
 */
typedef void (*port_fwd_begin_t)(portid_t pi);
typedef void (*port_fwd_end_t)(portid_t pi);
typedef void (*packet_fwd_t)(struct fwd_stream *fs);
struct fwd_engine {
	/**< Forwarding mode name. */
	const char       *fwd_mode_name;
	/**< NULL if nothing special to do. */
	port_fwd_begin_t port_fwd_begin;
	/**< NULL if nothing special to do. */
	port_fwd_end_t   port_fwd_end;
	/**< Mandatory. */
	packet_fwd_t     packet_fwd;
};
#define IPV4_ADDR_TO_UINT(ip_addr, ip)			\
do {							\
	if ((ip_addr).family == AF_INET)		\
		(ip) = (ip_addr).addr.ipv4.s_addr;	\
	else {						\
		printf("invalid parameter.\n");		\
		return;					\
	}						\
} while (0)

#define IPV6_ADDR_TO_ARRAY(ip_addr, ip)			\
do {							\
	if ((ip_addr).family == AF_INET6)		\
	(void)rte_memcpy(&(ip),				\
		&((ip_addr).addr.ipv6),			\
		sizeof(struct in6_addr));		\
	else {						\
		printf("invalid parameter.\n");		\
		return;					\
	}						\
} while (0)

void set_pkt_forwarding_mode(const char *fwd_mode_name);
#endif
