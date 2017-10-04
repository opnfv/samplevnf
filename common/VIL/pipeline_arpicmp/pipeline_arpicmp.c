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

#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_etheraddr.h>

#include "app.h"
#include "pipeline_common_fe.h"
#include "pipeline_arpicmp_be.h"
#include "pipeline_arpicmp.h"
#include "vnf_common.h"

#include "app.h"
#include "vnf_common.h"
#include "lib_arp.h"

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_string_fns.h>

uint16_t verbose_level = 1; /**< should be Silent by default. */
uint16_t nb_pkt_per_burst = DEF_PKT_BURST; /**< Number of packets per burst. */

/*
 * Work-around of a compilation error with ICC on invocations of the
 * rte_be_to_cpu_16() function.
 */
#ifdef __GCC__
#define RTE_BE_TO_CPU_16(be_16_v)  rte_be_to_cpu_16((be_16_v))
#define RTE_CPU_TO_BE_16(cpu_16_v) rte_cpu_to_be_16((cpu_16_v))
#else
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
#define RTE_BE_TO_CPU_16(be_16_v)  (be_16_v)
#define RTE_CPU_TO_BE_16(cpu_16_v) (cpu_16_v)
#else
#define RTE_BE_TO_CPU_16(be_16_v) \
	((uint16_t) ((((be_16_v) & 0xFF) << 8) | ((be_16_v) >> 8)))
#define RTE_CPU_TO_BE_16(cpu_16_v) \
	((uint16_t) ((((cpu_16_v) & 0xFF) << 8) | ((cpu_16_v) >> 8)))
#endif
#endif

/*
 * arp add
 */

struct cmd_arp_add_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t arpadd_string;
	uint32_t port_id;
	cmdline_ipaddr_t ip;
	struct ether_addr macaddr;

};

uint16_t str2flowtype(const char *string);
int parse_flexbytes(const char *q_arg, uint8_t *flexbytes,
	 uint16_t max_num);
enum rte_eth_input_set_field str2inset(const char *string);
int app_pipeline_arpicmp_entry_dbg(struct app_params *app,
			uint32_t pipeline_id, uint8_t *msg);


static void
cmd_arp_add_parsed(void *parsed_result,
			 __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_arp_add_result *params = parsed_result;
	uint8_t ipv6[16];

	#if 0
	struct pipeline_arp_icmp_arp_key key;
	key.type = PIPELINE_ARP_ICMP_ARP_IPV4;
	key.key.ipv4.port_id = params->port_id;
	key.key.ipv4.ip = rte_cpu_to_be_32(params->ip.addr.ipv4.s_addr);
	populate_arp_entry(&req->macaddr, rte_bswap32(req->key.key.ipv4.ip),
		req->key.key.ipv4.port_id);
	#endif
	if (params->ip.family == AF_INET) {
		populate_arp_entry(&params->macaddr,
					 rte_cpu_to_be_32(params->ip.addr.
								ipv4.s_addr),
					 params->port_id
					 , STATIC_ARP
				);
	} else {
		memcpy(ipv6, params->ip.addr.ipv6.s6_addr, 16);
		populate_nd_entry(&params->macaddr, ipv6, params->port_id
				, STATIC_ND
				);
	}
}

static cmdline_parse_token_string_t cmd_arp_add_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_add_result, p_string,
			 "p");

static cmdline_parse_token_num_t cmd_arp_add_p =
TOKEN_NUM_INITIALIZER(struct cmd_arp_add_result, p, UINT32);

static cmdline_parse_token_string_t cmd_arp_add_arp_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_add_result, arpadd_string, "arpadd");

static cmdline_parse_token_num_t cmd_arp_add_port_id =
TOKEN_NUM_INITIALIZER(struct cmd_arp_add_result, port_id, UINT32);

static cmdline_parse_token_ipaddr_t cmd_arp_add_ip =
TOKEN_IPADDR_INITIALIZER(struct cmd_arp_add_result, ip);

static cmdline_parse_token_etheraddr_t cmd_arp_add_macaddr =
TOKEN_ETHERADDR_INITIALIZER(struct cmd_arp_add_result, macaddr);

static cmdline_parse_inst_t cmd_arp_add = {
	.f = cmd_arp_add_parsed,
	.data = NULL,
	.help_str = "ARP add",
	.tokens = {
			 (void *)&cmd_arp_add_p_string,
			 (void *)&cmd_arp_add_p,
			 (void *)&cmd_arp_add_arp_string,
			 (void *)&cmd_arp_add_port_id,
			 (void *)&cmd_arp_add_ip,
			 (void *)&cmd_arp_add_macaddr,
			 NULL,
			 },
};

/*
 * arp del
 */

struct cmd_arp_del_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t arp_string;
	uint32_t port_id;
	cmdline_ipaddr_t ip;
};

static void
cmd_arp_del_parsed(void *parsed_result,
			 __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_arp_del_result *params = parsed_result;

	if (params->ip.family == AF_INET) {
		struct arp_key_ipv4 arp_key;
		arp_key.port_id = params->port_id;
		arp_key.ip = rte_cpu_to_be_32(params->ip.addr.ipv4.s_addr);
		arp_key.filler1 = 0;
		arp_key.filler2 = 0;
		arp_key.filler3 = 0;
		struct arp_entry_data *new_arp_data = retrieve_arp_entry(arp_key, STATIC_ARP);
		if(new_arp_data == NULL) {
			/* KW Fix */
			printf("Retrieve arp returned NULL\n");
			return;
		}
		remove_arp_entry(new_arp_data, &arp_key);
	} else {
		struct nd_key_ipv6 nd_key;
		nd_key.port_id = params->port_id;
		memcpy(&nd_key.ipv6[0], params->ip.addr.ipv6.s6_addr, 16);
		nd_key.filler1 = 0;
		nd_key.filler2 = 0;
		nd_key.filler3 = 0;
		struct nd_entry_data *new_nd_data = retrieve_nd_entry(nd_key, STATIC_ND);
		if(new_nd_data == NULL) {
			/* KW Fix */
			printf("Retrieve ND returned NULL\n");
			return;
		}
		remove_nd_entry_ipv6(new_nd_data, &nd_key);
	}
}

static cmdline_parse_token_string_t cmd_arp_del_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_del_result, p_string,
			 "p");

static cmdline_parse_token_num_t cmd_arp_del_p =
TOKEN_NUM_INITIALIZER(struct cmd_arp_del_result, p, UINT32);

static cmdline_parse_token_string_t cmd_arp_del_arp_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_del_result, arp_string, "arpdel");

static cmdline_parse_token_num_t cmd_arp_del_port_id =
TOKEN_NUM_INITIALIZER(struct cmd_arp_del_result, port_id, UINT32);

static cmdline_parse_token_ipaddr_t cmd_arp_del_ip =
TOKEN_IPADDR_INITIALIZER(struct cmd_arp_del_result, ip);

static cmdline_parse_inst_t cmd_arp_del = {
	.f = cmd_arp_del_parsed,
	.data = NULL,
	.help_str = "ARP delete",
	.tokens = {
			 (void *)&cmd_arp_del_p_string,
			 (void *)&cmd_arp_del_p,
			 (void *)&cmd_arp_del_arp_string,
			 (void *)&cmd_arp_del_port_id,
			 (void *)&cmd_arp_del_ip,
			 NULL,
			 },
};

/*
 * arp req
 */

/*Re-uses delete structures*/

static void
cmd_arp_req_parsed(void *parsed_result,
			 __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_arp_del_result *params = parsed_result;
	/*struct app_params *app = data;*/

	struct arp_key_ipv4 key;
/*	int status;*/

/*	key.type = ARP_IPV4;*/
/*	key.key.ipv4.ip = rte_cpu_to_be_32(params->ip.addr.ipv4.s_addr);*/
/*	key.key.ipv4.port_id = params->port_id;*/
	key.ip = rte_cpu_to_be_32(params->ip.addr.ipv4.s_addr);
	key.port_id = params->port_id;
	key.filler1 = 0;
	key.filler2 = 0;
	key.filler3 = 0;

	struct arp_entry_data *arp_data = retrieve_arp_entry(key, STATIC_ARP);

	if (arp_data) {
		if (ARPICMP_DEBUG)
			printf("ARP entry exists for ip 0x%x, port %d\n",
						 params->ip.addr.ipv4.s_addr, params->port_id);
		return;
	}
	/* else request an arp*/
	if (ARPICMP_DEBUG)
		printf("ARP - requesting arp for ip 0x%x, port %d\n",
					 params->ip.addr.ipv4.s_addr, params->port_id);

	request_arp(params->port_id, params->ip.addr.ipv4.s_addr);
	/*give pipeline number too*/
}

static cmdline_parse_token_string_t cmd_arp_req_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_del_result, arp_string, "arpreq");

static cmdline_parse_inst_t cmd_arp_req = {
	.f = cmd_arp_req_parsed,
	.data = NULL,
	.help_str = "ARP request",
	.tokens = {
			 (void *)&cmd_arp_del_p_string,
			 (void *)&cmd_arp_del_p,
			 (void *)&cmd_arp_req_string,
			 (void *)&cmd_arp_del_port_id,
			 (void *)&cmd_arp_del_ip,
			 NULL,
			 },
};

/*
 * arpicmp echo req
 */

/*Re-uses delete structures*/

static void
cmd_icmp_echo_req_parsed(void *parsed_result,
			 __rte_unused struct cmdline *cl,
			 __rte_unused void *data)
{
	struct cmd_arp_del_result *params = parsed_result;

	if (ARPICMP_DEBUG)
		printf("Echo Req Handler ip %x, port %d\n",
					 params->ip.addr.ipv4.s_addr, params->port_id);

	request_echo(params->port_id, params->ip.addr.ipv4.s_addr);
}

static cmdline_parse_token_string_t cmd_icmp_echo_req_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_del_result, arp_string, "icmpecho");

static cmdline_parse_inst_t cmd_icmp_echo_req = {
	.f = cmd_icmp_echo_req_parsed,
	.data = NULL,
	.help_str = "ICMP echo request",
	.tokens = {
			 (void *)&cmd_arp_del_p_string,
			 (void *)&cmd_arp_del_p,
			 (void *)&cmd_icmp_echo_req_string,
			 (void *)&cmd_arp_del_port_id,
			 (void *)&cmd_arp_del_ip,
			 NULL,
			 },
};

/*
 * arp ls
 */

struct cmd_arp_ls_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t arp_string;
	uint32_t ip_type;
};

static void
cmd_arp_ls_parsed(__rte_unused void *parsed_result,
			__rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_arp_ls_result *params = parsed_result;

	if (!params->ip_type) {
		printf("\nARP table ...\n");
		printf("-------------\n");
		print_arp_table();
	} else {
		printf("\nND IPv6 table:\n");
		printf("--------------\n");
		print_nd_table();
	}
}

static cmdline_parse_token_string_t cmd_arp_ls_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_ls_result, p_string,
			 "p");

static cmdline_parse_token_num_t cmd_arp_ls_p =
TOKEN_NUM_INITIALIZER(struct cmd_arp_ls_result, p, UINT32);

static cmdline_parse_token_string_t cmd_arp_ls_arp_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_ls_result, arp_string,
			 "arpls");

static cmdline_parse_token_num_t cmd_arp_ls_ip_type =
TOKEN_NUM_INITIALIZER(struct cmd_arp_ls_result, ip_type, UINT32);

static cmdline_parse_inst_t cmd_arp_ls = {
	.f = cmd_arp_ls_parsed,
	.data = NULL,
	.help_str = "ARP list",
	.tokens = {
			 (void *)&cmd_arp_ls_p_string,
			 (void *)&cmd_arp_ls_p,
			 (void *)&cmd_arp_ls_arp_string,
			 (void *)&cmd_arp_ls_ip_type,
			 NULL,
			 },
};

/*
 * show ports info
 */

struct cmd_show_ports_info_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t arp_string;
};

static void
cmd_show_ports_info_parsed(__rte_unused void *parsed_result,
				 __rte_unused struct cmdline *cl,
				 __rte_unused void *data)
{
	show_ports_info();
}

static cmdline_parse_token_string_t cmd_show_ports_info_string =
TOKEN_STRING_INITIALIZER(struct cmd_arp_ls_result, arp_string,
			 "showPortsInfo");

static cmdline_parse_inst_t cmd_show_ports_info = {
	.f = cmd_show_ports_info_parsed,
	.data = NULL,
	.help_str = "show ports info",
	.tokens = {
			 (void *)&cmd_arp_ls_p_string,
			 (void *)&cmd_arp_ls_p,
			 (void *)&cmd_show_ports_info_string,
			 NULL,
			 },
};

struct cmd_arp_dbg_result {
	cmdline_fixed_string_t arpdbg_str;
	uint32_t flag;
};

cmdline_parse_token_string_t cmd_arp_dbg_string =
	TOKEN_STRING_INITIALIZER(struct cmd_arp_dbg_result, arpdbg_str,
		"arpdbg");
cmdline_parse_token_num_t cmd_arp_dbg_flag =
	TOKEN_NUM_INITIALIZER(struct cmd_arp_dbg_result, flag, UINT32);

static void
cmd_arp_dbg_parse(
		void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__rte_unused void *data)
{
	struct cmd_arp_dbg_result *params = parsed_result;
	if(params)
	{
		set_arpdebug(params->flag);
	}
	else
	{
		printf("%s: Params is NULL",__FUNCTION__);
	}
}

cmdline_parse_inst_t cmd_arp_dbg = {
	.f = cmd_arp_dbg_parse,
	.data = NULL,
	.help_str = "Turn on/off(1/0) arp debug",
	.tokens = {
		(void *)&cmd_arp_dbg_string,
		(void *)&cmd_arp_dbg_flag,
		NULL,
	},
};

struct cmd_arp_timer_result {
	cmdline_fixed_string_t arptimer_str;
	uint32_t arptimer_val;
};

cmdline_parse_token_string_t cmd_arp_timer_string =
	TOKEN_STRING_INITIALIZER(struct cmd_arp_timer_result, arptimer_str,
		"arptimerexpiry");
cmdline_parse_token_num_t cmd_arp_timer_val =
	TOKEN_NUM_INITIALIZER(struct cmd_arp_timer_result, arptimer_val, UINT32);

static void
cmd_arp_timer_parse(
		void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__rte_unused void *data)
{
	struct cmd_arp_timer_result *params = parsed_result;
	if(params)
	{
		set_arptimeout(params->arptimer_val);
	}
	else
	{
		printf("%s: Params is NULL",__FUNCTION__);
	}
}

cmdline_parse_inst_t cmd_arp_timer = {
	.f = cmd_arp_timer_parse,
	.data = NULL,
	.help_str = "Timer expiry val by def 10 sec",
	.tokens = {
		(void *)&cmd_arp_timer_string,
		(void *)&cmd_arp_timer_val,
		NULL,
	},
};

/*
 * Forwarding of packets in I/O mode.
 * Forward packets "as-is".
 * This is the fastest possible forwarding operation, as it does not access
 * to packets data.
 */
	static void
pkt_burst_io_forward(struct fwd_stream *fs)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	uint16_t nb_rx;
	uint16_t nb_tx;

	#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	uint64_t start_tsc;
	uint64_t end_tsc;
	uint64_t core_cycles;
	#endif

	#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	start_tsc = rte_rdtsc();
	#endif

	/*
	 * Receive a burst of packets and forward them.
	 */
	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue, pkts_burst,
			nb_pkt_per_burst);
	if (unlikely(nb_rx == 0))
		return;

	#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->rx_burst_stats.pkt_burst_spread[nb_rx]++;
	#endif

	fs->rx_packets += nb_rx;
	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, nb_rx);
	fs->tx_packets += nb_tx;

	#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->tx_burst_stats.pkt_burst_spread[nb_tx]++;
	#endif

	if (unlikely(nb_tx < nb_rx)) {
		fs->fwd_dropped += (nb_rx - nb_tx);
		do {
			rte_pktmbuf_free(pkts_burst[nb_tx]);
		} while (++nb_tx < nb_rx);
	}

	#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	end_tsc = rte_rdtsc();
	core_cycles = (end_tsc - start_tsc);
	fs->core_cycles = (uint64_t) (fs->core_cycles + core_cycles);
	#endif
}


struct fwd_engine io_fwd_engine = {
	.fwd_mode_name  = "io",
	.port_fwd_begin = NULL,
	.port_fwd_end   = NULL,
	.packet_fwd     = pkt_burst_io_forward,
};

static inline void print_ether_addr(
	const char *what,
	struct ether_addr *eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", what, buf);
}

/*
 * Received a burst of packets.
 */
	static void
pkt_burst_receive(struct fwd_stream *fs)
{
	struct rte_mbuf  *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf  *mb;
	struct ether_hdr *eth_hdr;
	uint16_t eth_type;
	uint64_t ol_flags;
	uint16_t nb_rx;
	uint16_t i, packet_type;
	uint16_t is_encapsulation;

	#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	uint64_t start_tsc;
	uint64_t end_tsc;
	uint64_t core_cycles;
	#endif

	#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	start_tsc = rte_rdtsc();
	#endif

	/*
	 * Receive a burst of packets.
	 */
	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue, pkts_burst,
			nb_pkt_per_burst);
	if (unlikely(nb_rx == 0))
		return;

	#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->rx_burst_stats.pkt_burst_spread[nb_rx]++;
	#endif

	fs->rx_packets += nb_rx;

	/*
	 * Dump each received packet if verbose_level > 0.
	 */
	if (verbose_level > 0)
		printf("port %u/queue %u: received %u packets\n",
				(unsigned int) fs->rx_port,
				(unsigned int) fs->rx_queue,
				(unsigned int) nb_rx);
	for (i = 0; i < nb_rx; i++) {
		mb = pkts_burst[i];
		if (verbose_level == 0) {
			rte_pktmbuf_free(mb);
			continue;
		}
		eth_hdr = rte_pktmbuf_mtod(mb, struct ether_hdr *);
		eth_type = RTE_BE_TO_CPU_16(eth_hdr->ether_type);
		ol_flags = mb->ol_flags;
		packet_type = mb->packet_type;
		is_encapsulation = RTE_ETH_IS_TUNNEL_PKT(packet_type);

		print_ether_addr("  src=", &eth_hdr->s_addr);
		print_ether_addr(" - dst=", &eth_hdr->d_addr);
		printf(" - type=0x%04x - length=%u - nb_segs=%d",
				eth_type, (unsigned int) mb->pkt_len,
				(int)mb->nb_segs);
		if (ol_flags & PKT_RX_RSS_HASH) {
			printf(" - RSS hash=0x%x", (unsigned int)
				mb->hash.rss);
			printf(" - RSS queue=0x%x", (unsigned int)
				fs->rx_queue);
		} else if (ol_flags & PKT_RX_FDIR) {
			printf(" - FDIR matched ");
			if (ol_flags & PKT_RX_FDIR_ID)
				printf("ID=0x%x",
						mb->hash.fdir.hi);
			else if (ol_flags & PKT_RX_FDIR_FLX)
				printf("flex bytes=0x%08x %08x",
					mb->hash.fdir.hi, mb->hash.fdir.lo);
			else
				printf("hash=0x%x ID=0x%x ",
					mb->hash.fdir.hash, mb->hash.fdir.id);
		}
		if (ol_flags & PKT_RX_VLAN_PKT)
			printf(" - VLAN tci=0x%x", mb->vlan_tci);
		if (ol_flags & PKT_RX_QINQ_PKT)
			printf(" - QinQ VLAN tci=0x%x, VLAN tci outer=0x%x",
					mb->vlan_tci, mb->vlan_tci_outer);
		if (mb->packet_type) {
			uint32_t ptype;

			/* (outer) L2 packet type */
			ptype = mb->packet_type & RTE_PTYPE_L2_MASK;
			switch (ptype) {
			case RTE_PTYPE_L2_ETHER:
				printf(" - (outer) L2 type: ETHER");
				break;
			case RTE_PTYPE_L2_ETHER_TIMESYNC:
				printf(" - (outer) L2 type: ETHER_Timesync");
				break;
			case RTE_PTYPE_L2_ETHER_ARP:
				printf(" - (outer) L2 type: ETHER_ARP");
				break;
			case RTE_PTYPE_L2_ETHER_LLDP:
				printf(" - (outer) L2 type: ETHER_LLDP");
				break;
			default:
				printf(" - (outer) L2 type: Unknown");
				break;
			}

			/* (outer) L3 packet type */
			ptype = mb->packet_type & RTE_PTYPE_L3_MASK;
			switch (ptype) {
			case RTE_PTYPE_L3_IPV4:
				printf(" - (outer) L3 type: IPV4");
				break;
			case RTE_PTYPE_L3_IPV4_EXT:
				printf(" - (outer) L3 type: IPV4_EXT");
				break;
			case RTE_PTYPE_L3_IPV6:
				printf(" - (outer) L3 type: IPV6");
				break;
			case RTE_PTYPE_L3_IPV4_EXT_UNKNOWN:
				printf(" - (outer) L3 type: IPV4_EXT_UNKNOWN");
				break;
			case RTE_PTYPE_L3_IPV6_EXT:
				printf(" - (outer) L3 type: IPV6_EXT");
				break;
			case RTE_PTYPE_L3_IPV6_EXT_UNKNOWN:
				printf(" - (outer) L3 type: IPV6_EXT_UNKNOWN");
				break;
			default:
				printf(" - (outer) L3 type: Unknown");
				break;
			}

			/* (outer) L4 packet type */
			ptype = mb->packet_type & RTE_PTYPE_L4_MASK;
			switch (ptype) {
			case RTE_PTYPE_L4_TCP:
				printf(" - (outer) L4 type: TCP");
				break;
			case RTE_PTYPE_L4_UDP:
				printf(" - (outer) L4 type: UDP");
				break;
			case RTE_PTYPE_L4_FRAG:
				printf(" - (outer) L4 type: L4_FRAG");
				break;
			case RTE_PTYPE_L4_SCTP:
				printf(" - (outer) L4 type: SCTP");
				break;
			case RTE_PTYPE_L4_ICMP:
				printf(" - (outer) L4 type: ICMP");
				break;
			case RTE_PTYPE_L4_NONFRAG:
				printf(" - (outer) L4 type: L4_NONFRAG");
				break;
			default:
				printf(" - (outer) L4 type: Unknown");
				break;
			}

			/* packet tunnel type */
			ptype = mb->packet_type & RTE_PTYPE_TUNNEL_MASK;
			switch (ptype) {
			case RTE_PTYPE_TUNNEL_IP:
				printf(" - Tunnel type: IP");
				break;
			case RTE_PTYPE_TUNNEL_GRE:
				printf(" - Tunnel type: GRE");
				break;
			case RTE_PTYPE_TUNNEL_VXLAN:
				printf(" - Tunnel type: VXLAN");
				break;
			case RTE_PTYPE_TUNNEL_NVGRE:
				printf(" - Tunnel type: NVGRE");
				break;
			case RTE_PTYPE_TUNNEL_GENEVE:
				printf(" - Tunnel type: GENEVE");
				break;
			case RTE_PTYPE_TUNNEL_GRENAT:
				printf(" - Tunnel type: GRENAT");
				break;
			default:
				printf(" - Tunnel type: Unknown");
				break;
			}

			/* inner L2 packet type */
			ptype = mb->packet_type & RTE_PTYPE_INNER_L2_MASK;
			switch (ptype) {
			case RTE_PTYPE_INNER_L2_ETHER:
				printf(" - Inner L2 type: ETHER");
				break;
			case RTE_PTYPE_INNER_L2_ETHER_VLAN:
				printf(" - Inner L2 type: ETHER_VLAN");
				break;
			default:
				printf(" - Inner L2 type: Unknown");
				break;
			}
			/* inner L3 packet type */
			ptype = mb->packet_type & RTE_PTYPE_INNER_L3_MASK;
			switch (ptype) {
			case RTE_PTYPE_INNER_L3_IPV4:
				printf(" - Inner L3 type: IPV4");
				break;
			case RTE_PTYPE_INNER_L3_IPV4_EXT:
				printf(" - Inner L3 type: IPV4_EXT");
				break;
			case RTE_PTYPE_INNER_L3_IPV6:
				printf(" - Inner L3 type: IPV6");
				break;
			case RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN:
				printf(" - Inner L3 type: "
					"IPV4_EXT_UNKNOWN");
				break;
			case RTE_PTYPE_INNER_L3_IPV6_EXT:
					printf(" - Inner L3 type: IPV6_EXT");
				break;
			case RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN:
				printf(" - Inner L3 type: "
					"IPV6_EXT_UNKNOWN");
				break;
			default:
				printf(" - Inner L3 type: Unknown");
				break;
			}

			/* inner L4 packet type */
			ptype = mb->packet_type & RTE_PTYPE_INNER_L4_MASK;
			switch (ptype) {
			case RTE_PTYPE_INNER_L4_TCP:
				printf(" - Inner L4 type: TCP");
				break;
			case RTE_PTYPE_INNER_L4_UDP:
				printf(" - Inner L4 type: UDP");
				break;
			case RTE_PTYPE_INNER_L4_FRAG:
				printf(" - Inner L4 type: L4_FRAG");
				break;
			case RTE_PTYPE_INNER_L4_SCTP:
				printf(" - Inner L4 type: SCTP");
				break;
			case RTE_PTYPE_INNER_L4_ICMP:
				printf(" - Inner L4 type: ICMP");
				break;
			case RTE_PTYPE_INNER_L4_NONFRAG:
				printf(" - Inner L4 type: L4_NONFRAG");
				break;
			default:
				printf(" - Inner L4 type: Unknown");
				break;
			}
			printf("\n");
		} else
			printf("Unknown packet type\n");
		if (is_encapsulation) {
			struct ipv4_hdr *ipv4_hdr;
			struct ipv6_hdr *ipv6_hdr;
			struct udp_hdr *udp_hdr;
			uint8_t l2_len;
			uint8_t l3_len;
			uint8_t l4_len;
			uint8_t l4_proto;
			struct  vxlan_hdr *vxlan_hdr;

			l2_len  = sizeof(struct ether_hdr);

			/* Do not support ipv4 option field */
			if (RTE_ETH_IS_IPV4_HDR(packet_type)) {
				l3_len = sizeof(struct ipv4_hdr);
				ipv4_hdr = rte_pktmbuf_mtod_offset(mb,
						struct ipv4_hdr *,
						l2_len);
				l4_proto = ipv4_hdr->next_proto_id;
			} else {
				l3_len = sizeof(struct ipv6_hdr);
				ipv6_hdr = rte_pktmbuf_mtod_offset(mb,
						struct ipv6_hdr *,
						l2_len);
				l4_proto = ipv6_hdr->proto;
			}
			if (l4_proto == IPPROTO_UDP) {
				udp_hdr = rte_pktmbuf_mtod_offset(mb,
						struct udp_hdr *,
						l2_len + l3_len);
				l4_len = sizeof(struct udp_hdr);
				vxlan_hdr = rte_pktmbuf_mtod_offset(mb,
						struct vxlan_hdr *,
						l2_len + l3_len + l4_len);

				printf(" - VXLAN packet: packet type =%d, "
					"Destination UDP port =%d, VNI = %d",
					packet_type,
					RTE_BE_TO_CPU_16(udp_hdr->dst_port),
					rte_be_to_cpu_32(
						vxlan_hdr->vx_vni) >> 8);
			}
		}
		printf(" - Receive queue=0x%x", (unsigned int) fs->rx_queue);
		printf("\n");
		if (ol_flags != 0) {
			unsigned int rxf;
			const char *name;

			for (rxf = 0; rxf < sizeof(mb->ol_flags) * 8; rxf++) {
				if ((ol_flags & (1ULL << rxf)) == 0)
					continue;
				name = rte_get_rx_ol_flag_name(1ULL << rxf);
				if (name == NULL)
					continue;
				printf("  %s\n", name);
			}
		}
		rte_pktmbuf_free(mb);
	}

	#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	end_tsc = rte_rdtsc();
	core_cycles = (end_tsc - start_tsc);
	fs->core_cycles = (uint64_t) (fs->core_cycles + core_cycles);
	#endif
}

struct fwd_engine rx_only_engine = {
	.fwd_mode_name  = "rxonly",
	.port_fwd_begin = NULL,
	.port_fwd_end   = NULL,
	.packet_fwd     = pkt_burst_receive,
};

/* *** SET FORWARDING MODE *** */
struct cmd_set_fwd_mode_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t fwd;
	cmdline_fixed_string_t mode;
};

/*
 * Forwarding engines.
 */
struct fwd_engine *fwd_engines[] = {
	&io_fwd_engine,
	#if 0
	&mac_fwd_engine,
	&mac_retry_fwd_engine,
	&mac_swap_engine,
	&flow_gen_engine,
	#endif
	&rx_only_engine,
	#if 0
	&tx_only_engine,
	&csum_fwd_engine,
	&icmp_echo_engine,
	#ifdef RTE_LIBRTE_IEEE1588
	&ieee1588_fwd_engine,
	#endif
	#endif
	NULL,
};

struct fwd_engine *cur_fwd_eng = &io_fwd_engine; /**< IO mode by default. */

void set_pkt_forwarding_mode(const char *fwd_mode_name)
{
	struct fwd_engine *fwd_eng;
	unsigned int i;

	i = 0;
	while ((fwd_eng = fwd_engines[i]) != NULL) {
		if (!strcmp(fwd_eng->fwd_mode_name, fwd_mode_name)) {
			printf("Set %s packet forwarding mode\n",
					fwd_mode_name);
			cur_fwd_eng = fwd_eng;
			return;
		}
		i++;
	}
	printf("Invalid %s packet forwarding mode\n", fwd_mode_name);
}

static void cmd_set_fwd_mode_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_set_fwd_mode_result *res = parsed_result;

	set_pkt_forwarding_mode(res->mode);
}

cmdline_parse_token_string_t cmd_setfwd_set =
TOKEN_STRING_INITIALIZER(struct cmd_set_fwd_mode_result, set, "set");
cmdline_parse_token_string_t cmd_setfwd_fwd =
TOKEN_STRING_INITIALIZER(struct cmd_set_fwd_mode_result, fwd, "fwd");
cmdline_parse_token_string_t cmd_setfwd_mode =
TOKEN_STRING_INITIALIZER(struct cmd_set_fwd_mode_result, mode,
		"rxonly" /* defined at init */);

cmdline_parse_inst_t cmd_set_fwd_mode = {
	.f = cmd_set_fwd_mode_parsed,
	.data = NULL,
	.help_str = NULL, /* defined at init */
	.tokens = {
		(void *)&cmd_setfwd_set,
		(void *)&cmd_setfwd_fwd,
		(void *)&cmd_setfwd_mode,
		NULL,
	},
};

#if 1

uint16_t str2flowtype(const char *string)
{
	uint8_t i = 0;
	static const struct {
	char str[32];
	uint16_t type;
	} flowtype_str[] = {
		{"raw", RTE_ETH_FLOW_RAW},
		{"ipv4", RTE_ETH_FLOW_IPV4},
		{"ipv4-frag", RTE_ETH_FLOW_FRAG_IPV4},
		{"ipv4-tcp", RTE_ETH_FLOW_NONFRAG_IPV4_TCP},
		{"ipv4-udp", RTE_ETH_FLOW_NONFRAG_IPV4_UDP},
		{"ipv4-sctp", RTE_ETH_FLOW_NONFRAG_IPV4_SCTP},
		{"ipv4-other", RTE_ETH_FLOW_NONFRAG_IPV4_OTHER},
		{"ipv6", RTE_ETH_FLOW_IPV6},
		{"ipv6-frag", RTE_ETH_FLOW_FRAG_IPV6},
		{"ipv6-tcp", RTE_ETH_FLOW_NONFRAG_IPV6_TCP},
		{"ipv6-udp", RTE_ETH_FLOW_NONFRAG_IPV6_UDP},
		{"ipv6-sctp", RTE_ETH_FLOW_NONFRAG_IPV6_SCTP},
		{"ipv6-other", RTE_ETH_FLOW_NONFRAG_IPV6_OTHER},
		{"l2_payload", RTE_ETH_FLOW_L2_PAYLOAD},
	};

	for (i = 0; i < RTE_DIM(flowtype_str); i++) {
		if (!strcmp(flowtype_str[i].str, string))
			return flowtype_str[i].type;
	}
	return RTE_ETH_FLOW_UNKNOWN;
}

int
parse_flexbytes(const char *q_arg, uint8_t *flexbytes, uint16_t max_num)
{
	char s[256];
	const char *p, *p0 = q_arg;
	char *end;
	unsigned long int_fld;
	char *str_fld[max_num];
	int i;
	unsigned int size;
	int ret = -1;

	p = strchr(p0, '(');
	if (p == NULL)
		return -1;
	++p;
	p0 = strchr(p, ')');
	if (p0 == NULL)
		return -1;

	size = p0 - p;
	if (size >= sizeof(s))
		return -1;

	snprintf(s, sizeof(s), "%.*s", size, p);
	ret = rte_strsplit(s, sizeof(s), str_fld, max_num, ',');
	if (ret < 0 || ret > max_num)
		return -1;
	for (i = 0; i < ret; i++) {
		errno = 0;
		int_fld = strtoul(str_fld[i], &end, 0);
		if (errno != 0 || *end != '\0' || int_fld > UINT8_MAX)
			return -1;
		flexbytes[i] = (uint8_t)int_fld;
	}
	return ret;
}

/* *** deal with flow director filter *** */
struct cmd_flow_director_result {
	cmdline_fixed_string_t flow_director_filter;
	uint8_t port_id;
	cmdline_fixed_string_t mode;
	cmdline_fixed_string_t mode_value;
	cmdline_fixed_string_t ops;
	cmdline_fixed_string_t flow;
	cmdline_fixed_string_t flow_type;
	cmdline_fixed_string_t ether;
	uint16_t ether_type;
	cmdline_fixed_string_t src;
	cmdline_ipaddr_t ip_src;
	uint16_t port_src;
	cmdline_fixed_string_t dst;
	cmdline_ipaddr_t ip_dst;
	uint16_t port_dst;
	cmdline_fixed_string_t verify_tag;
	uint32_t verify_tag_value;
	cmdline_ipaddr_t tos;
	uint8_t tos_value;
	cmdline_ipaddr_t proto;
	uint8_t proto_value;
	cmdline_ipaddr_t ttl;
	uint8_t ttl_value;
	cmdline_fixed_string_t vlan;
	uint16_t vlan_value;
	cmdline_fixed_string_t flexbytes;
	cmdline_fixed_string_t flexbytes_value;
	cmdline_fixed_string_t pf_vf;
	cmdline_fixed_string_t drop;
	cmdline_fixed_string_t queue;
	uint16_t  queue_id;
	cmdline_fixed_string_t fd_id;
	uint32_t  fd_id_value;
	cmdline_fixed_string_t mac;
	struct ether_addr mac_addr;
	cmdline_fixed_string_t tunnel;
	cmdline_fixed_string_t tunnel_type;
	cmdline_fixed_string_t tunnel_id;
	uint32_t tunnel_id_value;
};

static void
cmd_flow_director_filter_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_flow_director_result *res = parsed_result;
	struct rte_eth_fdir_filter entry;
	uint8_t flexbytes[RTE_ETH_FDIR_MAX_FLEXLEN];
	char *end;
	unsigned long vf_id;
	int ret = 0;

	if (enable_hwlb) {
		printf("Hash Filter is already Defined !\n");
		printf("Please undefine HWLD flag and define "
			"FDIR_FILTER flag\n");
	return;
	}

	ret = rte_eth_dev_filter_supported(res->port_id, RTE_ETH_FILTER_FDIR);
	if (ret < 0) {
		printf("flow director is not supported on port %u.\n",
				res->port_id);
		return;
	}
	memset(flexbytes, 0, sizeof(flexbytes));
	memset(&entry, 0, sizeof(struct rte_eth_fdir_filter));
#if 0
	if (fdir_conf.mode ==  RTE_FDIR_MODE_PERFECT_MAC_VLAN) {
		if (strcmp(res->mode_value, "MAC-VLAN")) {
			printf("Please set mode to MAC-VLAN.\n");
			return;
		}
	} else if (fdir_conf.mode ==  RTE_FDIR_MODE_PERFECT_TUNNEL) {
		if (strcmp(res->mode_value, "Tunnel")) {
			printf("Please set mode to Tunnel.\n");
			return;
		}
	} else {
		if (strcmp(res->mode_value, "IP")) {
			printf("Please set mode to IP.\n");
			return;
		}
#endif
	{
		entry.input.flow_type = str2flowtype(res->flow_type);
	}

	ret = parse_flexbytes(res->flexbytes_value,
			flexbytes,
			RTE_ETH_FDIR_MAX_FLEXLEN);
	if (ret < 0) {
		printf("error: Cannot parse flexbytes input.\n");
		return;
	}

	switch (entry.input.flow_type) {
	case RTE_ETH_FLOW_FRAG_IPV4:
	case RTE_ETH_FLOW_NONFRAG_IPV4_OTHER:
		entry.input.flow.ip4_flow.proto = res->proto_value;
	case RTE_ETH_FLOW_NONFRAG_IPV4_UDP:
	case RTE_ETH_FLOW_NONFRAG_IPV4_TCP:
		IPV4_ADDR_TO_UINT(res->ip_dst,
				entry.input.flow.ip4_flow.dst_ip);
		IPV4_ADDR_TO_UINT(res->ip_src,
			entry.input.flow.ip4_flow.src_ip);
			entry.input.flow.ip4_flow.tos = res->tos_value;
			entry.input.flow.ip4_flow.ttl = res->ttl_value;
			/* need convert to big endian. */
			entry.input.flow.udp4_flow.dst_port =
				rte_cpu_to_be_16(res->port_dst);
			entry.input.flow.udp4_flow.src_port =
				rte_cpu_to_be_16(res->port_src);
	break;

	case RTE_ETH_FLOW_NONFRAG_IPV4_SCTP:
		IPV4_ADDR_TO_UINT(res->ip_dst,
				entry.input.flow.sctp4_flow.ip.dst_ip);
		IPV4_ADDR_TO_UINT(res->ip_src,
				entry.input.flow.sctp4_flow.ip.src_ip);
		entry.input.flow.ip4_flow.tos = res->tos_value;
		entry.input.flow.ip4_flow.ttl = res->ttl_value;
		/* need convert to big endian. */
		entry.input.flow.sctp4_flow.dst_port =
			rte_cpu_to_be_16(res->port_dst);
		entry.input.flow.sctp4_flow.src_port =
			rte_cpu_to_be_16(res->port_src);
		entry.input.flow.sctp4_flow.verify_tag =
			rte_cpu_to_be_32(res->verify_tag_value);
	break;

	case RTE_ETH_FLOW_FRAG_IPV6:
	case RTE_ETH_FLOW_NONFRAG_IPV6_OTHER:
		entry.input.flow.ipv6_flow.proto = res->proto_value;
	case RTE_ETH_FLOW_NONFRAG_IPV6_UDP:
	case RTE_ETH_FLOW_NONFRAG_IPV6_TCP:
		IPV6_ADDR_TO_ARRAY(res->ip_dst,
			entry.input.flow.ipv6_flow.dst_ip);
		IPV6_ADDR_TO_ARRAY(res->ip_src,
			entry.input.flow.ipv6_flow.src_ip);
		entry.input.flow.ipv6_flow.tc = res->tos_value;
		entry.input.flow.ipv6_flow.hop_limits = res->ttl_value;
		/* need convert to big endian. */
		entry.input.flow.udp6_flow.dst_port =
			rte_cpu_to_be_16(res->port_dst);
		entry.input.flow.udp6_flow.src_port =
			rte_cpu_to_be_16(res->port_src);
	break;

	case RTE_ETH_FLOW_NONFRAG_IPV6_SCTP:
		IPV6_ADDR_TO_ARRAY(res->ip_dst,
			entry.input.flow.sctp6_flow.ip.dst_ip);
		IPV6_ADDR_TO_ARRAY(res->ip_src,
			entry.input.flow.sctp6_flow.ip.src_ip);
		entry.input.flow.ipv6_flow.tc = res->tos_value;
		entry.input.flow.ipv6_flow.hop_limits = res->ttl_value;
		/* need convert to big endian. */
		entry.input.flow.sctp6_flow.dst_port =
			rte_cpu_to_be_16(res->port_dst);
		entry.input.flow.sctp6_flow.src_port =
			rte_cpu_to_be_16(res->port_src);
		entry.input.flow.sctp6_flow.verify_tag =
			rte_cpu_to_be_32(res->verify_tag_value);
	break;
	case RTE_ETH_FLOW_L2_PAYLOAD:
		entry.input.flow.l2_flow.ether_type =
			rte_cpu_to_be_16(res->ether_type);
	break;
	default:
		break;
	}
#if 0
	if (fdir_conf.mode ==  RTE_FDIR_MODE_PERFECT_MAC_VLAN)
		(void)rte_memcpy(&entry.input.flow.mac_vlan_flow.mac_addr,
				&res->mac_addr,
				sizeof(struct ether_addr));

	if (fdir_conf.mode ==  RTE_FDIR_MODE_PERFECT_TUNNEL) {
		(void)rte_memcpy(&entry.input.flow.tunnel_flow.mac_addr,
				&res->mac_addr,
				sizeof(struct ether_addr));
		entry.input.flow.tunnel_flow.tunnel_type =
			str2fdir_tunneltype(res->tunnel_type);
		entry.input.flow.tunnel_flow.tunnel_id =
			rte_cpu_to_be_32(res->tunnel_id_value);
	}
#endif

	(void)rte_memcpy(entry.input.flow_ext.flexbytes,
			flexbytes,
			RTE_ETH_FDIR_MAX_FLEXLEN);

	entry.input.flow_ext.vlan_tci = rte_cpu_to_be_16(res->vlan_value);

	entry.action.flex_off = 0;  /*use 0 by default */
	if (!strcmp(res->drop, "drop"))
		entry.action.behavior = RTE_ETH_FDIR_REJECT;
	else
		entry.action.behavior = RTE_ETH_FDIR_ACCEPT;

	if (!strcmp(res->pf_vf, "pf"))
		entry.input.flow_ext.is_vf = 0;
	else if (!strncmp(res->pf_vf, "vf", 2)) {
		struct rte_eth_dev_info dev_info;

		memset(&dev_info, 0, sizeof(dev_info));
		rte_eth_dev_info_get(res->port_id, &dev_info);
		errno = 0;
		vf_id = strtoul(res->pf_vf + 2, &end, 10);
		if (errno != 0 || *end != '\0' || vf_id >= dev_info.max_vfs) {
			printf("invalid parameter %s.\n", res->pf_vf);
			return;
		}
		entry.input.flow_ext.is_vf = 1;
		entry.input.flow_ext.dst_id = (uint16_t)vf_id;
	} else {
		printf("invalid parameter %s.\n", res->pf_vf);
		return;
	}
	/* set to report FD ID by default */
	entry.action.report_status = RTE_ETH_FDIR_REPORT_ID;
	entry.action.rx_queue = res->queue_id;
	entry.soft_id = res->fd_id_value;
	if (!strcmp(res->ops, "add"))
		ret = rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_FDIR,
				RTE_ETH_FILTER_ADD, &entry);
	else if (!strcmp(res->ops, "del"))
		ret = rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_FDIR,
				RTE_ETH_FILTER_DELETE, &entry);
	else
		ret = rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_FDIR,
				RTE_ETH_FILTER_UPDATE, &entry);
	if (ret < 0)
		printf("flow director programming error: (%s)\n",
				strerror(-ret));
//	fdir_filter_enabled = 1;
}



cmdline_parse_token_string_t cmd_flow_director_filter =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		flow_director_filter, "flow_director_filter");

cmdline_parse_token_num_t cmd_flow_director_port_id =
TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
		port_id, UINT8);


cmdline_parse_token_string_t cmd_flow_director_mode =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		mode, "mode");

cmdline_parse_token_string_t cmd_flow_director_mode_ip =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		mode_value, "IP");

cmdline_parse_token_string_t cmd_flow_director_ops =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		ops, "add#del#update");

cmdline_parse_token_string_t cmd_flow_director_flow =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		flow, "flow");

cmdline_parse_token_string_t cmd_flow_director_flow_type =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		flow_type, "ipv4-other#ipv4-frag#ipv4-tcp#ipv4-udp#ipv4-sctp#"
		"ipv6-other#ipv6-frag#ipv6-tcp#ipv6-udp#ipv6-sctp#l2_payload");

cmdline_parse_token_string_t cmd_flow_director_src =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		src, "src");
cmdline_parse_token_ipaddr_t cmd_flow_director_ip_src =
TOKEN_IPADDR_INITIALIZER(struct cmd_flow_director_result,
		ip_src);
cmdline_parse_token_num_t cmd_flow_director_port_src =
TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
		port_src, UINT16);
cmdline_parse_token_string_t cmd_flow_director_dst =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		dst, "dst");
cmdline_parse_token_ipaddr_t cmd_flow_director_ip_dst =
TOKEN_IPADDR_INITIALIZER(struct cmd_flow_director_result,
		ip_dst);
cmdline_parse_token_num_t cmd_flow_director_port_dst =
TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
		port_dst, UINT16);

cmdline_parse_token_string_t cmd_flow_director_tos =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		tos, "tos");
cmdline_parse_token_num_t cmd_flow_director_tos_value =
TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
		tos_value, UINT8);

cmdline_parse_token_string_t cmd_flow_director_ttl =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		ttl, "ttl");
cmdline_parse_token_num_t cmd_flow_director_ttl_value =
TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
		ttl_value, UINT8);

cmdline_parse_token_string_t cmd_flow_director_vlan =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		vlan, "vlan");
cmdline_parse_token_num_t cmd_flow_director_vlan_value =
TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
		vlan_value, UINT16);
cmdline_parse_token_string_t cmd_flow_director_flexbytes =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		flexbytes, "flexbytes");
cmdline_parse_token_string_t cmd_flow_director_flexbytes_value =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		flexbytes_value, NULL);
cmdline_parse_token_string_t cmd_flow_director_drop =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		drop, "drop#fwd");
cmdline_parse_token_string_t cmd_flow_director_pf_vf =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		pf_vf, NULL);
cmdline_parse_token_string_t cmd_flow_director_queue =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		queue, "queue");
cmdline_parse_token_num_t cmd_flow_director_queue_id =
TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
		queue_id, UINT16);
cmdline_parse_token_string_t cmd_flow_director_fd_id =
TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		fd_id, "fd_id");
cmdline_parse_token_num_t cmd_flow_director_fd_id_value =
TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
		fd_id_value, UINT32);


cmdline_parse_inst_t cmd_add_del_udp_flow_director = {
	.f = cmd_flow_director_filter_parsed,
	.data = NULL,
	.help_str = "add or delete an udp/tcp flow director entry on NIC",
	.tokens = {
		(void *)&cmd_flow_director_filter,
		(void *)&cmd_flow_director_port_id,
		(void *)&cmd_flow_director_mode,
		(void *)&cmd_flow_director_mode_ip,
		(void *)&cmd_flow_director_ops,
		(void *)&cmd_flow_director_flow,
		(void *)&cmd_flow_director_flow_type,
		(void *)&cmd_flow_director_src,
		(void *)&cmd_flow_director_ip_src,
		(void *)&cmd_flow_director_port_src,
		(void *)&cmd_flow_director_dst,
		(void *)&cmd_flow_director_ip_dst,
		(void *)&cmd_flow_director_port_dst,
		(void *)&cmd_flow_director_tos,
		(void *)&cmd_flow_director_tos_value,
		(void *)&cmd_flow_director_ttl,
		(void *)&cmd_flow_director_ttl_value,
		(void *)&cmd_flow_director_vlan,
		(void *)&cmd_flow_director_vlan_value,
		(void *)&cmd_flow_director_flexbytes,
		(void *)&cmd_flow_director_flexbytes_value,
		(void *)&cmd_flow_director_drop,
		(void *)&cmd_flow_director_pf_vf,
		(void *)&cmd_flow_director_queue,
		(void *)&cmd_flow_director_queue_id,
		(void *)&cmd_flow_director_fd_id,
		(void *)&cmd_flow_director_fd_id_value,
		NULL,
	},
};
/* L2 payload*/
cmdline_parse_token_string_t cmd_flow_director_ether =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		ether, "ether");
cmdline_parse_token_num_t cmd_flow_director_ether_type =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
		ether_type, UINT16);

cmdline_parse_inst_t cmd_add_del_l2_flow_director = {
	.f = cmd_flow_director_filter_parsed,
	.data = NULL,
	.help_str = "add or delete a L2 flow director entry on NIC",
	.tokens = {
	(void *)&cmd_flow_director_filter,
	(void *)&cmd_flow_director_port_id,
	(void *)&cmd_flow_director_mode,
	(void *)&cmd_flow_director_mode_ip,
	(void *)&cmd_flow_director_ops,
	(void *)&cmd_flow_director_flow,
	(void *)&cmd_flow_director_flow_type,
	(void *)&cmd_flow_director_ether,
	(void *)&cmd_flow_director_ether_type,
	(void *)&cmd_flow_director_flexbytes,
	(void *)&cmd_flow_director_flexbytes_value,
	(void *)&cmd_flow_director_drop,
	(void *)&cmd_flow_director_pf_vf,
	(void *)&cmd_flow_director_queue,
	(void *)&cmd_flow_director_queue_id,
	(void *)&cmd_flow_director_fd_id,
	(void *)&cmd_flow_director_fd_id_value,
	NULL,
	},
};

#if 1
/* Set hash input set */
struct cmd_set_hash_input_set_result {
	cmdline_fixed_string_t set_hash_input_set;
	uint8_t port_id;
	cmdline_fixed_string_t flow_type;
	cmdline_fixed_string_t inset_field0;
	cmdline_fixed_string_t inset_field1;
	cmdline_fixed_string_t inset_field2;
	cmdline_fixed_string_t inset_field3;
	cmdline_fixed_string_t inset_field4;
	cmdline_fixed_string_t select;
};

enum rte_eth_input_set_field
str2inset(const char *string)
{
	uint16_t i;

	static const struct {
		char str[32];
		enum rte_eth_input_set_field inset;
	} inset_table[] = {
		{"ethertype", RTE_ETH_INPUT_SET_L2_ETHERTYPE},
		{"ovlan", RTE_ETH_INPUT_SET_L2_OUTER_VLAN},
		{"ivlan", RTE_ETH_INPUT_SET_L2_INNER_VLAN},
		{"src-ipv4", RTE_ETH_INPUT_SET_L3_SRC_IP4},
		{"dst-ipv4", RTE_ETH_INPUT_SET_L3_DST_IP4},
		{"ipv4-tos", RTE_ETH_INPUT_SET_L3_IP4_TOS},
		{"ipv4-proto", RTE_ETH_INPUT_SET_L3_IP4_PROTO},
		{"ipv4-ttl", RTE_ETH_INPUT_SET_L3_IP4_TTL},
		{"src-ipv6", RTE_ETH_INPUT_SET_L3_SRC_IP6},
		{"dst-ipv6", RTE_ETH_INPUT_SET_L3_DST_IP6},
		{"ipv6-tc", RTE_ETH_INPUT_SET_L3_IP6_TC},
		{"ipv6-next-header", RTE_ETH_INPUT_SET_L3_IP6_NEXT_HEADER},
		{"ipv6-hop-limits", RTE_ETH_INPUT_SET_L3_IP6_HOP_LIMITS},
		{"udp-src-port", RTE_ETH_INPUT_SET_L4_UDP_SRC_PORT},
		{"udp-dst-port", RTE_ETH_INPUT_SET_L4_UDP_DST_PORT},
		{"tcp-src-port", RTE_ETH_INPUT_SET_L4_TCP_SRC_PORT},
		{"tcp-dst-port", RTE_ETH_INPUT_SET_L4_TCP_DST_PORT},
		{"sctp-src-port", RTE_ETH_INPUT_SET_L4_SCTP_SRC_PORT},
		{"sctp-dst-port", RTE_ETH_INPUT_SET_L4_SCTP_DST_PORT},
		{"sctp-veri-tag", RTE_ETH_INPUT_SET_L4_SCTP_VERIFICATION_TAG},
		{"udp-key", RTE_ETH_INPUT_SET_TUNNEL_L4_UDP_KEY},
		{"gre-key", RTE_ETH_INPUT_SET_TUNNEL_GRE_KEY},
		{"fld-1st", RTE_ETH_INPUT_SET_FLEX_PAYLOAD_1ST_WORD},
		{"fld-2nd", RTE_ETH_INPUT_SET_FLEX_PAYLOAD_2ND_WORD},
		{"fld-3rd", RTE_ETH_INPUT_SET_FLEX_PAYLOAD_3RD_WORD},
		{"fld-4th", RTE_ETH_INPUT_SET_FLEX_PAYLOAD_4TH_WORD},
		{"fld-5th", RTE_ETH_INPUT_SET_FLEX_PAYLOAD_5TH_WORD},
		{"fld-6th", RTE_ETH_INPUT_SET_FLEX_PAYLOAD_6TH_WORD},
		{"fld-7th", RTE_ETH_INPUT_SET_FLEX_PAYLOAD_7TH_WORD},
		{"fld-8th", RTE_ETH_INPUT_SET_FLEX_PAYLOAD_8TH_WORD},
		{"none", RTE_ETH_INPUT_SET_NONE},
	};
	for (i = 0; i < RTE_DIM(inset_table); i++) {
		if (!strcmp(string, inset_table[i].str))
			return inset_table[i].inset;
	}

	return RTE_ETH_INPUT_SET_UNKNOWN;
}

static void
cmd_set_hash_input_set_1_parsed(void *parsed_result,
		__rte_unused struct cmdline *cl,
		__rte_unused void *data)
{
	struct cmd_set_hash_input_set_result *res = parsed_result;
	struct rte_eth_hash_filter_info info;

	if (enable_flow_dir) {
		printf("FDIR Filter is Defined!\n");
		printf("Please undefine FDIR_FILTER flag and define "
			"HWLD flag\n");
		return;
	}

	memset(&info, 0, sizeof(info));
	info.info_type = RTE_ETH_HASH_FILTER_INPUT_SET_SELECT;
	info.info.input_set_conf.flow_type = str2flowtype(res->flow_type);

	info.info.input_set_conf.field[0] = str2inset(res->inset_field0);
	info.info.input_set_conf.inset_size = 1;

	if (!strcmp(res->select, "select"))
		info.info.input_set_conf.op = RTE_ETH_INPUT_SET_SELECT;
	else if (!strcmp(res->select, "add"))
		info.info.input_set_conf.op = RTE_ETH_INPUT_SET_ADD;

	rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_HASH,
		RTE_ETH_FILTER_SET, &info);

	//hash_filter_enabled = 1;
}

static void
cmd_set_hash_input_set_2_parsed(void *parsed_result,
			__rte_unused struct cmdline *cl,
			__rte_unused void *data)
{
	struct cmd_set_hash_input_set_result *res = parsed_result;
	struct rte_eth_hash_filter_info info;

	if (enable_flow_dir) {
		printf("FDIR Filter is Defined!\n");
		printf("Please undefine FDIR_FILTER flag and define "
			"HWLD flag\n");
		return;
	}

	memset(&info, 0, sizeof(info));
	info.info_type = RTE_ETH_HASH_FILTER_INPUT_SET_SELECT;
	info.info.input_set_conf.flow_type = str2flowtype(res->flow_type);

	info.info.input_set_conf.field[0] = str2inset(res->inset_field0);
	info.info.input_set_conf.field[1] = str2inset(res->inset_field1);

	info.info.input_set_conf.inset_size = 2;

	if (!strcmp(res->select, "select"))
		info.info.input_set_conf.op = RTE_ETH_INPUT_SET_SELECT;
	else if (!strcmp(res->select, "add"))
		info.info.input_set_conf.op = RTE_ETH_INPUT_SET_ADD;

	rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_HASH,
		RTE_ETH_FILTER_SET, &info);

	//hash_filter_enabled = 1;
}

#if 0
static void
cmd_set_hash_input_set_3_parsed(void *parsed_result,
		__rte_unused struct cmdline *cl,
		 __rte_unused void *data)
{
	struct cmd_set_hash_input_set_result *res = parsed_result;
	struct rte_eth_hash_filter_info info;

	memset(&info, 0, sizeof(info));
	info.info_type = RTE_ETH_HASH_FILTER_INPUT_SET_SELECT;
	info.info.input_set_conf.flow_type = str2flowtype(res->flow_type);

	info.info.input_set_conf.field[0] = str2inset(res->inset_field0);
	info.info.input_set_conf.field[1] = str2inset(res->inset_field1);
	info.info.input_set_conf.field[2] = str2inset(res->inset_field2);
	info.info.input_set_conf.inset_size = 3;

	if (!strcmp(res->select, "select"))
		info.info.input_set_conf.op = RTE_ETH_INPUT_SET_SELECT;
	else if (!strcmp(res->select, "add"))
		info.info.input_set_conf.op = RTE_ETH_INPUT_SET_ADD;

	rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_HASH,
		RTE_ETH_FILTER_SET, &info);
}
#endif
static void
cmd_set_hash_input_set_4_parsed(void *parsed_result,
			 __rte_unused struct cmdline *cl,
			 __rte_unused void *data)
{
	struct cmd_set_hash_input_set_result *res = parsed_result;
	struct rte_eth_hash_filter_info info;

	if (enable_flow_dir) {
		printf("FDIR Filter is Defined!\n");
		printf("Please undefine FDIR_FILTER flag and define "
			"HWLD flag\n");
		return;
	}

	memset(&info, 0, sizeof(info));
	info.info_type = RTE_ETH_HASH_FILTER_INPUT_SET_SELECT;
	info.info.input_set_conf.flow_type = str2flowtype(res->flow_type);

	info.info.input_set_conf.field[0] = str2inset(res->inset_field0);
	info.info.input_set_conf.field[1] = str2inset(res->inset_field1);
	info.info.input_set_conf.field[2] = str2inset(res->inset_field2);
	info.info.input_set_conf.field[3] = str2inset(res->inset_field3);

	info.info.input_set_conf.inset_size = 4;
	if (!strcmp(res->select, "select"))
		info.info.input_set_conf.op = RTE_ETH_INPUT_SET_SELECT;
	else if (!strcmp(res->select, "add"))
		info.info.input_set_conf.op = RTE_ETH_INPUT_SET_ADD;

	rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_HASH,
		RTE_ETH_FILTER_SET, &info);
	//hash_filter_enabled = 1;
}

#if 0
static void
cmd_set_hash_input_set_5_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_set_hash_input_set_result *res = parsed_result;
	struct rte_eth_hash_filter_info info;

	memset(&info, 0, sizeof(info));
	info.info_type = RTE_ETH_HASH_FILTER_INPUT_SET_SELECT;
	info.info.input_set_conf.flow_type = str2flowtype(res->flow_type);

	info.info.input_set_conf.field[0] = str2inset(res->inset_field0);
	info.info.input_set_conf.field[1] = str2inset(res->inset_field1);
	info.info.input_set_conf.field[2] = str2inset(res->inset_field2);
	info.info.input_set_conf.field[3] = str2inset(res->inset_field3);
	info.info.input_set_conf.field[4] = str2inset(res->inset_field4);

	info.info.input_set_conf.inset_size = 5;
	if (!strcmp(res->select, "select"))
		info.info.input_set_conf.op = RTE_ETH_INPUT_SET_SELECT;
	else if (!strcmp(res->select, "add"))
		info.info.input_set_conf.op = RTE_ETH_INPUT_SET_ADD;
	rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_HASH,
	RTE_ETH_FILTER_SET, &info);
}
#endif

cmdline_parse_token_string_t cmd_set_hash_input_set_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_set_hash_input_set_result,
	set_hash_input_set, "set_hash_input_set");
cmdline_parse_token_num_t cmd_set_hash_input_set_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_set_hash_input_set_result,
	port_id, UINT8);
cmdline_parse_token_string_t cmd_set_hash_input_set_flow_type =
	TOKEN_STRING_INITIALIZER(struct cmd_set_hash_input_set_result,
	flow_type,
	"ipv4-frag#ipv4-tcp#ipv4-udp#ipv4-sctp#ipv4-other#"
	"ipv6-frag#ipv6-tcp#ipv6-udp#ipv6-sctp#ipv6-other#l2_payload");

cmdline_parse_token_string_t cmd_set_hash_input_set_field0 =
	TOKEN_STRING_INITIALIZER(struct cmd_set_hash_input_set_result,
	inset_field0,
	"src-ipv4#src-ipv6#dst-ipv4#dst-ipv6#"
	"udp-src-port#udp-dst-port#tcp-src-port#tcp-dst-port#none");

cmdline_parse_token_string_t cmd_set_hash_input_set_field1 =
	TOKEN_STRING_INITIALIZER(struct cmd_set_hash_input_set_result,
	inset_field1,
	"dst-ipv4#dst-ipv6#"
	"udp-src-port#tcp-src-port#udp-dst-port#tcp-dst-port#none");

cmdline_parse_token_string_t cmd_set_hash_input_set_field2 =
	TOKEN_STRING_INITIALIZER(struct cmd_set_hash_input_set_result,
	inset_field2,
	"udp-src-port#tcp-src-port#none");

cmdline_parse_token_string_t cmd_set_hash_input_set_field3 =
	TOKEN_STRING_INITIALIZER(struct cmd_set_hash_input_set_result,
	inset_field3,
	"udp-dst-port#tcp-dst-port#none");
#if 0
cmdline_parse_token_string_t cmd_set_hash_input_set_field4 =
	TOKEN_STRING_INITIALIZER(struct cmd_set_hash_input_set_result,
	inset_field4, "ipv4-proto#ipv6-next-header#none");
#endif

cmdline_parse_token_string_t cmd_set_hash_input_set_select =
	TOKEN_STRING_INITIALIZER(struct cmd_set_hash_input_set_result,
	select, "select#add");

cmdline_parse_inst_t cmd_set_hash_input_set_1 = {
	.f = cmd_set_hash_input_set_1_parsed,
	.data = NULL,
	.help_str = "set_hash_input_set_1 <port_id> "
	"ipv4|ipv4-frag|ipv4-tcp|ipv4-udp|ipv4-sctp|ipv4-other|"
	"ipv6|ipv6-frag|ipv6-tcp|ipv6-udp|ipv6-sctp|ipv6-other|l2_payload    "
	"src-ipv4|src-ipv6|dst-ipv4|dst-ipv6|"
	"udp-src-port|udp-dst-port|tcp-src-port|tcp-dst-port|none    "
	"select|add",
	.tokens = {
		(void *)&cmd_set_hash_input_set_cmd,
		(void *)&cmd_set_hash_input_set_port_id,
		(void *)&cmd_set_hash_input_set_flow_type,
		(void *)&cmd_set_hash_input_set_field0,
		(void *)&cmd_set_hash_input_set_select,
		NULL,
	},
};

cmdline_parse_inst_t cmd_set_hash_input_set_2 = {
	.f = cmd_set_hash_input_set_2_parsed,
	.data = NULL,
	.help_str = "set_hash_input_set_2 <port_id> "
	"ipv4|ipv4-frag|ipv4-tcp|ipv4-udp|ipv4-sctp|ipv4-other| "
	"ipv6|ipv6-frag|ipv6-tcp|ipv6-udp|ipv6-sctp|ipv6-other|l2_payload "
	"src-ipv4|src-ipv6|dst-ipv4|dst-ipv6| "
	"udp-src-port|udp-dst-port|tcp-src-port|tcp-dst-port|none "
	"udp-src-port|tcp-src-port|udp-dst-port|tcp-dst-port|none "
	"select|add",
	.tokens = {
		(void *)&cmd_set_hash_input_set_cmd,
		(void *)&cmd_set_hash_input_set_port_id,
		(void *)&cmd_set_hash_input_set_flow_type,
		(void *)&cmd_set_hash_input_set_field0,
		(void *)&cmd_set_hash_input_set_field1,
		(void *)&cmd_set_hash_input_set_select,
		NULL,
	},
};

#if 0
cmdline_parse_inst_t cmd_set_hash_input_set_3 = {
	.f = cmd_set_hash_input_set_3_parsed,
	.data = NULL,
	.help_str = "set_hash_input_set_3 <port_id> "
	"ipv4-frag|ipv4-tcp|ipv4-udp|ipv4-sctp|ipv4-other|"
	"ipv6-frag|ipv6-tcp|ipv6-udp|ipv6-sctp|ipv6-other|l2_payload        "
	"ovlan|ivlan|src-ipv4|dst-ipv4|src-ipv6|dst-ipv6|ipv4-tos|ipv4-proto|"
	"ipv6-tc|ipv6-next-header|udp-src-port|udp-dst-port|tcp-src-port|"
	"tcp-dst-port|sctp-src-port|sctp-dst-port|sctp-veri-tag|udp-key|"
	"gre-key|fld-1st|fld-2nd|fld-3rd|fld-4th|fld-5th|fld-6th|"
	"fld-7th|fld-8th|none       "
	"udp-src-port|udp-dst-port|tcp-src-port|tcp-dst-port|none       "
	"select|add",
	.tokens = {
		(void *)&cmd_set_hash_input_set_cmd,
		(void *)&cmd_set_hash_input_set_port_id,
		(void *)&cmd_set_hash_input_set_flow_type,
		(void *)&cmd_set_hash_input_set_field0,
		(void *)&cmd_set_hash_input_set_field1,
		(void *)&cmd_set_hash_input_set_field2,
		(void *)&cmd_set_hash_input_set_select,
		NULL,
	},
};
#endif

cmdline_parse_inst_t cmd_set_hash_input_set_4 = {
	.f = cmd_set_hash_input_set_4_parsed,
	.data = NULL,
	.help_str = "set_hash_input_set_4 <port_id> "
	"ipv4|ipv4-frag|ipv4-tcp|ipv4-udp|ipv4-sctp|ipv4-other|"
	"ipv6|ipv6-frag|ipv6-tcp|ipv6-udp|ipv6-sctp|ipv6-other|l2_payload "
	"src-ipv4|src-ipv6|dst-ipv4|dst-ipv6|"
	"udp-src-port|udp-dst-port|tcp-src-port|tcp-dst-port|none "
	"udp-src-port|tcp-src-port|udp-dst-port|tcp-dst-port|none "
	"udp-src-port|tcp-src-port|dst-ipv4|none    "
	"udp-dst-port|tcp-dst-port|none    "
	"select|add",
	.tokens = {
		(void *)&cmd_set_hash_input_set_cmd,
		(void *)&cmd_set_hash_input_set_port_id,
		(void *)&cmd_set_hash_input_set_flow_type,
		(void *)&cmd_set_hash_input_set_field0,
		(void *)&cmd_set_hash_input_set_field1,
		(void *)&cmd_set_hash_input_set_field2,
		(void *)&cmd_set_hash_input_set_field3,
		(void *)&cmd_set_hash_input_set_select,
		NULL,
	},
};
#if 0
cmdline_parse_inst_t cmd_set_hash_input_set_5 = {
	.f = cmd_set_hash_input_set_5_parsed,
	.data = NULL,
	.help_str = "set_hash_input_set_5 <port_id> "
	"ipv4|ipv4-frag|ipv4-tcp|ipv4-udp|ipv4-sctp|ipv4-other|"
	"ipv6|ipv6-frag|ipv6-tcp|ipv6-udp|ipv6-sctp|ipv6-other|l2_payload    "
	"src-ipv4|src-ipv6|none    "
	"dst-ipv4|dst-ipv6|none    "
	"udp-src-port|tcp-src-port|none    "
	"udp-dst-port|tcp-dst-port|none    "
	"ipv4-proto|ipv6-next-header|none    "
	"select|add",

	.tokens = {
		(void *)&cmd_set_hash_input_set_cmd,
		(void *)&cmd_set_hash_input_set_port_id,
		(void *)&cmd_set_hash_input_set_flow_type,
		(void *)&cmd_set_hash_input_set_field0,
		(void *)&cmd_set_hash_input_set_field1,
		(void *)&cmd_set_hash_input_set_field2,
		(void *)&cmd_set_hash_input_set_field3,
		(void *)&cmd_set_hash_input_set_field4,
		(void *)&cmd_set_hash_input_set_select,
		NULL,
	},
};
#endif
#endif
/* set hash global config */
struct cmd_set_hash_global_config_result {
	cmdline_fixed_string_t set_hash_global_config;
	uint8_t port_id;
	cmdline_fixed_string_t hash_func;
	cmdline_fixed_string_t flow_type;
	cmdline_fixed_string_t enable;
};

static void
cmd_set_hash_global_config_parsed(void *parsed_result,
		__rte_unused struct cmdline *cl,
		__rte_unused void *data)
{
	struct cmd_set_hash_global_config_result *res = parsed_result;
	struct rte_eth_hash_filter_info info;
	uint32_t ftype, idx, offset;
	int ret;

	if (rte_eth_dev_filter_supported(res->port_id,
				RTE_ETH_FILTER_HASH) < 0) {
		printf("RTE_ETH_FILTER_HASH not supported on port %d\n",
				res->port_id);
		return;
	}
	memset(&info, 0, sizeof(info));
	info.info_type = RTE_ETH_HASH_FILTER_GLOBAL_CONFIG;
	if (!strcmp(res->hash_func, "toeplitz"))
		info.info.global_conf.hash_func =
			RTE_ETH_HASH_FUNCTION_TOEPLITZ;
	else if (!strcmp(res->hash_func, "simple_xor"))
		info.info.global_conf.hash_func =
			RTE_ETH_HASH_FUNCTION_SIMPLE_XOR;
	else if (!strcmp(res->hash_func, "default"))
		info.info.global_conf.hash_func =
			RTE_ETH_HASH_FUNCTION_DEFAULT;

	ftype = str2flowtype(res->flow_type);
	idx = ftype / (CHAR_BIT * sizeof(uint32_t));
	offset = ftype % (CHAR_BIT * sizeof(uint32_t));
	info.info.global_conf.valid_bit_mask[idx] |= (1UL << offset);
	if (!strcmp(res->enable, "enable"))
		if(idx < RTE_SYM_HASH_MASK_ARRAY_SIZE)
		info.info.global_conf.sym_hash_enable_mask[idx] |=
			(1UL << offset);
	ret = rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_HASH,
			RTE_ETH_FILTER_SET, &info);
	if (ret < 0)
		printf("Cannot set global hash configurations by port %d\n",
				res->port_id);
	else
		printf("Global hash configurations have been set "
				"succcessfully by port %d\n", res->port_id);
}
cmdline_parse_token_string_t cmd_set_hash_global_config_all =
TOKEN_STRING_INITIALIZER(struct cmd_set_hash_global_config_result,
		set_hash_global_config, "set_hash_global_config");
cmdline_parse_token_num_t cmd_set_hash_global_config_port_id =
TOKEN_NUM_INITIALIZER(struct cmd_set_hash_global_config_result,
		port_id, UINT8);
cmdline_parse_token_string_t cmd_set_hash_global_config_hash_func =
TOKEN_STRING_INITIALIZER(struct cmd_set_hash_global_config_result,
		hash_func, "toeplitz#simple_xor#default");
cmdline_parse_token_string_t cmd_set_hash_global_config_flow_type =
TOKEN_STRING_INITIALIZER(struct cmd_set_hash_global_config_result,
		flow_type,
		"ipv4#ipv4-frag#ipv4-tcp#ipv4-udp#ipv4-sctp#ipv4-other#ipv6#"
		"ipv6-frag#ipv6-tcp#ipv6-udp#ipv6-sctp#ipv6-other#l2_payload");
cmdline_parse_token_string_t cmd_set_hash_global_config_enable =
TOKEN_STRING_INITIALIZER(struct cmd_set_hash_global_config_result,
		enable, "enable#disable");

cmdline_parse_inst_t cmd_set_hash_global_config = {
	.f = cmd_set_hash_global_config_parsed,
	.data = NULL,
	.help_str = "set_hash_global_config port_id "
		"toeplitz|simple_xor|default "
		"ipv4|ipv4-frag|ipv4-tcp|ipv4-udp|ipv4-sctp|ipv4-other|ipv6|"
		"ipv6-frag|ipv6-tcp|ipv6-udp|ipv6-sctp|ipv6-other|l2_payload "
		"enable|disable",
	.tokens = {
		(void *)&cmd_set_hash_global_config_all,
		(void *)&cmd_set_hash_global_config_port_id,
		(void *)&cmd_set_hash_global_config_hash_func,
		(void *)&cmd_set_hash_global_config_flow_type,
		(void *)&cmd_set_hash_global_config_enable,
		NULL,
	},
};

/* *** Set symmetric hash enable per port *** */
struct cmd_set_sym_hash_ena_per_port_result {
	cmdline_fixed_string_t set_sym_hash_ena_per_port;
	cmdline_fixed_string_t enable;
	uint8_t port_id;
};

static void
cmd_set_sym_hash_per_port_parsed(void *parsed_result,
		 __rte_unused struct cmdline *cl,
		 __rte_unused void *data)
{
	struct cmd_set_sym_hash_ena_per_port_result *res = parsed_result;
	struct rte_eth_hash_filter_info info;
	int ret;

	if (rte_eth_dev_filter_supported(res->port_id,
		 RTE_ETH_FILTER_HASH) < 0) {
		printf("RTE_ETH_FILTER_HASH not supported on port: %d\n",
			res->port_id);
		return;
	}

	memset(&info, 0, sizeof(info));
	info.info_type = RTE_ETH_HASH_FILTER_SYM_HASH_ENA_PER_PORT;

	if (!strcmp(res->enable, "enable"))
		info.info.enable = 1;

	ret = rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_HASH,
				 RTE_ETH_FILTER_SET, &info);
	if (ret < 0) {
		printf("Cannot set symmetric hash enable per port on "
			"port %u\n", res->port_id);
		return;
	}
	printf("Symmetric hash has been set to %s on port %u\n",
				 res->enable, res->port_id);
}

cmdline_parse_token_string_t cmd_set_sym_hash_ena_per_port_all =
	TOKEN_STRING_INITIALIZER(struct cmd_set_sym_hash_ena_per_port_result,
	set_sym_hash_ena_per_port, "set_sym_hash_ena_per_port");
cmdline_parse_token_num_t cmd_set_sym_hash_ena_per_port_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_set_sym_hash_ena_per_port_result,
	port_id, UINT8);
cmdline_parse_token_string_t cmd_set_sym_hash_ena_per_port_enable =
	TOKEN_STRING_INITIALIZER(struct cmd_set_sym_hash_ena_per_port_result,
	enable, "enable#disable");

cmdline_parse_inst_t cmd_set_sym_hash_ena_per_port = {
	.f = cmd_set_sym_hash_per_port_parsed,
	.data = NULL,
	.help_str = "set_sym_hash_ena_per_port port_id enable|disable",
	.tokens = {
		(void *)&cmd_set_sym_hash_ena_per_port_all,
		(void *)&cmd_set_sym_hash_ena_per_port_port_id,
		(void *)&cmd_set_sym_hash_ena_per_port_enable,
		NULL,
	},
};
#endif

int
app_pipeline_arpicmp_entry_dbg(struct app_params *app,
					uint32_t pipeline_id, uint8_t *msg)
{
	struct pipeline_arpicmp_entry_dbg_msg_req *req;
	struct pipeline_arpicmp_entry_dbg_msg_rsp *rsp;

	/* Check input arguments */
	if (app == NULL)
		return -1;

	/* Allocate and write request */
	req = app_msg_alloc(app);
	if (req == NULL)
		return -1;

	req->type = PIPELINE_MSG_REQ_CUSTOM;
	req->subtype = PIPELINE_ARPICMP_MSG_REQ_ENTRY_DBG;
	req->data[0] = msg[0];
	req->data[1] = msg[1];

	rsp = app_msg_send_recv(app, pipeline_id, req, MSG_TIMEOUT_DEFAULT);
	if (rsp == NULL)
		return -1;

	/* Read response */
	if (rsp->status) {
		app_msg_free(app, rsp);
		printf("Error rsp->status %d\n", rsp->status);
		return -1;
	}

	/* Free response */
	app_msg_free(app, rsp);

	return 0;
}

/*
 * entry dbg
 */


struct cmd_entry_dbg_result {
	cmdline_fixed_string_t p_string;
	uint32_t p;
	cmdline_fixed_string_t entry_string;
	cmdline_fixed_string_t dbg_string;
	uint8_t cmd;
	uint8_t d1;
};

static void
cmd_entry_dbg_parsed(void *parsed_result,
				 __rte_unused struct cmdline *cl, void *data)
{
	struct cmd_entry_dbg_result *params = parsed_result;
	struct app_params *app = data;
	uint8_t msg[2];
	int status;

	msg[0] = params->cmd;
	msg[1] = params->d1;
	status = app_pipeline_arpicmp_entry_dbg(app, params->p, msg);

	if (status != 0) {
		printf("Dbg Command failed\n");
		return;
	}
}

static cmdline_parse_token_string_t lb_cmd_entry_dbg_p_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_dbg_result, p_string, "p");

static cmdline_parse_token_num_t lb_cmd_entry_dbg_p =
TOKEN_NUM_INITIALIZER(struct cmd_entry_dbg_result, p, UINT32);

static cmdline_parse_token_string_t lb_cmd_entry_dbg_entry_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_dbg_result,
			 entry_string, "txrx");

static cmdline_parse_token_string_t lb_cmd_entry_dbg_dbg_string =
TOKEN_STRING_INITIALIZER(struct cmd_entry_dbg_result, dbg_string,
			 "dbg");

static cmdline_parse_token_num_t lb_cmd_entry_dbg_cmd =
TOKEN_NUM_INITIALIZER(struct cmd_entry_dbg_result, cmd, UINT8);

static cmdline_parse_token_num_t lb_cmd_entry_dbg_d1 =
TOKEN_NUM_INITIALIZER(struct cmd_entry_dbg_result, d1, UINT8);

static cmdline_parse_inst_t lb_cmd_entry_dbg = {
	.f = cmd_entry_dbg_parsed,
	.data = NULL,
	.help_str = "ARPICMP dbg cmd",
	.tokens = {
			 (void *)&lb_cmd_entry_dbg_p_string,
			 (void *)&lb_cmd_entry_dbg_p,
			 (void *)&lb_cmd_entry_dbg_entry_string,
			 (void *)&lb_cmd_entry_dbg_dbg_string,
			 (void *)&lb_cmd_entry_dbg_cmd,
			 (void *)&lb_cmd_entry_dbg_d1,
			 NULL,
	},
};

static cmdline_parse_ctx_t pipeline_cmds[] = {
	(cmdline_parse_inst_t *) &lb_cmd_entry_dbg,
	(cmdline_parse_inst_t *) &cmd_arp_add,
	(cmdline_parse_inst_t *) &cmd_arp_del,
	(cmdline_parse_inst_t *) &cmd_arp_req,
	(cmdline_parse_inst_t *) &cmd_icmp_echo_req,
	(cmdline_parse_inst_t *) &cmd_arp_ls,
	(cmdline_parse_inst_t *) &cmd_show_ports_info,
	/*HWLB cmds*/
	(cmdline_parse_inst_t *) &cmd_set_fwd_mode,
	(cmdline_parse_inst_t *) &cmd_add_del_udp_flow_director,
	(cmdline_parse_inst_t *) &cmd_add_del_l2_flow_director,
	(cmdline_parse_inst_t *) &cmd_set_hash_input_set_1,
	(cmdline_parse_inst_t *) &cmd_set_hash_input_set_2,
/*      (cmdline_parse_inst_t *) & cmd_set_hash_input_set_3,*/
	(cmdline_parse_inst_t *) &cmd_set_hash_input_set_4,
/*      (cmdline_parse_inst_t *) & cmd_set_hash_input_set_5,*/
	(cmdline_parse_inst_t *) &cmd_set_hash_global_config,
	(cmdline_parse_inst_t *) &cmd_set_sym_hash_ena_per_port,
	(cmdline_parse_inst_t *) &cmd_arp_dbg,
	(cmdline_parse_inst_t *) &cmd_arp_timer,
	NULL,
};

static struct pipeline_fe_ops pipeline_arpicmp_fe_ops = {
	.f_init = NULL,
	.f_free = NULL,
	.cmds = pipeline_cmds,
};

struct pipeline_type pipeline_arpicmp = {
	.name = "ARPICMP",
	.be_ops = &pipeline_arpicmp_be_ops,
	.fe_ops = &pipeline_arpicmp_fe_ops,
};
