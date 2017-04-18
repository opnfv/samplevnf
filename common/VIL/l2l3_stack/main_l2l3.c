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

#ifndef __INCLUDE_MAIN__
#define __INCLUDE_MAIN_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_cpuflags.h>
#include <rte_timer.h>
#include "lib_arp.h"
#include "l2_proto.h"
#include "interface.h"
#include "l3fwd_common.h"
#include "l3fwd_lpm4.h"
#include "l3fwd_lpm6.h"
#define TIMER_RESOLUTION_CYCLES 20000000ULL	/* around 10ms at 2 Ghz */
unsigned lcore_id = 1;
void convert_ipstr_to_numeric(void);
struct sockaddr_in ipaddr1, ipaddr2, ipaddr3, ipaddr4;
uint8_t ipv6_addr0[16] = {
	0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0x10, 0x28, 0x15
};

uint8_t ipv6_addr1[16] = {
	0x12, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0x10, 0x28, 0x15
};

/*{port_id, nrx_queue, ntx_queue, adminstate, promisc}*/
port_config_t portconf[5] = {
	{
		.port_id = 0,
		.nrx_queue = 1,
		.ntx_queue = 1,
		.state = 1,
		.promisc = 1,
		.mempool = {
			.buffer_size = 2048 + sizeof(struct rte_mbuf) +
				RTE_PKTMBUF_HEADROOM,
			.pool_size = 32 * 1024,
			.cache_size = 256,
			.cpu_socket_id = 0,
		},
		.port_conf = {
			.link_speeds = 0,
			.rxmode = {
				.mq_mode = ETH_MQ_RX_NONE,
				.header_split = 0,	/* Header split */
				.hw_ip_checksum = 0,	/* IP checksum offload */
				.hw_vlan_filter = 0,	/* VLAN filtering */
				.hw_vlan_strip = 0,	/* VLAN strip */
				.hw_vlan_extend = 0,	/* Extended VLAN */
				.jumbo_frame = 0,	/* Jumbo frame support */
				.hw_strip_crc = 0,	/* CRC strip by HW */
				.enable_scatter = 0,	/* Scattered packets RX handler */
				.max_rx_pkt_len = 9000,	/* Jumbo frame max packet len */
				.split_hdr_size = 0,	/* Header split buffer size */
			},
			_adv_conf = {
				.rss_conf = {
					.rss_key = NULL,
					.rss_key_len = 40,
					.rss_hf = 0,
				},
			},
			.txmode = {
				.mq_mode = ETH_MQ_TX_NONE,},
			.lpbk_mode = 0,
			.intr_conf = {
				.lsc = 1,
				/**< lsc interrupt feature enabled */
			}
		},
		.rx_conf = {
			.rx_thresh = {
				.pthresh = 8,
				.hthresh = 8,
				.wthresh = 4,
			},
			.rx_free_thresh = 64,
			.rx_drop_en = 0,
			.rx_deferred_start = 0,
		},
		.tx_conf = {
			.tx_thresh = {
				.pthresh = 36,
				.hthresh = 0,
				.wthresh = 0,					=
			},
			.tx_rs_thresh = 0,
			.tx_free_thresh = 0,
			.txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS,
			.tx_deferred_start = 0,
		}
	},
	{
		.port_id = 1,
		.nrx_queue = 1,
		.ntx_queue = 1,
		.state = 1,
		.promisc = 1,
		.mempool = {
			.buffer_size = 2048 + sizeof(struct rte_mbuf) +
				RTE_PKTMBUF_HEADROOM,
			.pool_size = 32 * 1024,
			.cache_size = 256,
			.cpu_socket_id = 0,
		},
		.port_conf = {
			.link_speeds = 0,
			.rxmode = {
				.mq_mode = ETH_MQ_RX_NONE,
				.header_split = 0,	/* Header split */
				.hw_ip_checksum = 0,	/* IP checksum offload */
				.hw_vlan_filter = 0,	/* VLAN filtering */
				.hw_vlan_strip = 0,	/* VLAN strip */
				.hw_vlan_extend = 0,	/* Extended VLAN */
				.jumbo_frame = 0,	/* Jumbo frame support */
				.hw_strip_crc = 0,	/* CRC strip by HW */
				.enable_scatter = 0,	/* Scattered packets RX handler */
				.max_rx_pkt_len = 9000,	/* Jumbo frame max packet len */
				.split_hdr_size = 0,	/* Header split buffer size */
			},
			_adv_conf = {
				.rss_conf = {
					.rss_key = NULL,
					.rss_key_len = 40,
					.rss_hf = 0,
				},
			},
			.txmode = {
				.mq_mode = ETH_MQ_TX_NONE,},
			.lpbk_mode = 0,
			.intr_conf = {
				.lsc = 1,
				/**< lsc interrupt feature enabled */
			}
		},
		.rx_conf = {
			.rx_thresh = {
				.pthresh = 8,
				.hthresh = 8,
				.wthresh = 4,
			},
			.rx_free_thresh = 64,
			.rx_drop_en = 0,
			.rx_deferred_start = 0,
		},
		.tx_conf = {
			.tx_thresh = {
				.pthresh = 36,
				.hthresh = 0,
				.wthresh = 0,					=
			},
			.tx_rs_thresh = 0,
			.tx_free_thresh = 0,
			.txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS,
			.tx_deferred_start = 0,
		}
	},
};

static __attribute__ ((noreturn))
int lcore_mainloop (__attribute__ ((unused))
			 void *arg)
{
	l2_phy_interface_t *port;
	int8_t portid;
	struct rte_mbuf *pkts_burst[IFM_BURST_SIZE];
	uint32_t nb_tx, nb_rx;
	const uint64_t drain_tsc =
			(rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
	uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
	while (1) {
		port = ifm_get_first_port();
		while (port != NULL) {
			rte_timer_manage();
			portid = port->pmdid;
			cur_tsc = rte_rdtsc();
			diff_tsc = cur_tsc - prev_tsc;

			/* call rx function ptr from port, with port.arpq, */
			if (unlikely(diff_tsc > drain_tsc)) {
				if (port->tx_buf_len > 0) {
					RTE_SET_USED(nb_tx);

					//nb_tx = port->transmit_bulk_pkts(port, port->tx_buf, port->tx_buf_len);
					port->tx_buf_len = 0;
				}
				prev_tsc = cur_tsc;
			}
			nb_rx = port->retrieve_bulk_pkts(portid, 0, pkts_burst);
			port->n_rxpkts += nb_rx;
			protocol_handler_recv(pkts_burst, nb_rx, port);
			port = ifm_get_next_port(portid);
			if (port != NULL)
				prev_tsc = cur_tsc;
		}
	}
}

void convert_ipstr_to_numeric(void)
{
	memset(&ipaddr1, '\0', sizeof(struct sockaddr_in));
	ipaddr1.sin_addr.s_addr = inet_addr("30.0.0.10");
	memset(&ipaddr2, '\0', sizeof(struct sockaddr_in));
	ipaddr2.sin_addr.s_addr = inet_addr("120.0.0.10");
}

int main(int argc, char **argv)
{
	int ret = 0;
	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	/* Port init */
	//lib_arp_init();
	ifm_init();
	ifm_configure_ports(portconf);

	//convert_ipstr_to_numeric();
	//ifm_add_ipv4_port(0, ipaddr1.sin_addr.s_addr, 24);
	//ifm_add_ipv4_port(1, ipaddr2.sin_addr.s_addr, 24);
	ifm_add_ipv6_port(0, ipv6_addr0, 96);
	ifm_add_ipv6_port(1, ipv6_addr1, 96);
	print_interface_details();

	//filter_init();
	l3fwd_init();
	create_arp_table();
	create_nd_table();
	populate_lpm_routes();
	/*call the main loop */
	/* launch per-lcore init on every lcore */
	int ii;
	for (ii = 0; ii < 16; ii += 2) {
		printf("%02X%02X ", ipv6_addr0[ii], ipv6_addr0[ii + 1]);
	}
	printf("\n");
	for (ii = 0; ii < 16; ii += 2) {
		printf("%02X%02X ", ipv6_addr1[ii], ipv6_addr1[ii + 1]);
	}
	printf("REMOTE LAUNCH STARTED........\n");
	rte_eal_remote_launch(lcore_mainloop, NULL, lcore_id);
	printf("REMOTE LAUNCH DONE.......\n");
	if (rte_eal_wait_lcore(lcore_id) < 0) {
	}
	return 0;
}
#endif
