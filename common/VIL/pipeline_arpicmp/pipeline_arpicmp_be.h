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

#ifndef __INCLUDE_PIPELINE_ARPICMP_BE_H__
#define __INCLUDE_PIPELINE_ARPICMP_BE_H__

#include "pipeline_common_be.h"
#define PIPELINE_ARPICMP_KEY_PORT_IN_AH(f_ah, f_pkt_work, f_pkt4_work)  \
static int                                                              \
f_ah(                                                                   \
	__rte_unused struct rte_pipeline *rte_p,                        \
	struct rte_mbuf **pkts,                                         \
	uint32_t n_pkts,                                                \
	void *arg)                                                      \
{                                                                       \
	uint32_t i, j;                                                  \
									\
	for (j = 0; j < n_pkts; j++)                                    \
		rte_prefetch0(pkts[j]);                                 \
									\
	for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)                   \
		f_pkt4_work(&pkts[i], i, arg);                          \
									\
	for ( ; i < n_pkts; i++)                                        \
		f_pkt_work(pkts[i], i, arg);                            \
									\
									\
	return 0;                                                       \
}

extern struct app_params *myApp;
void print_pkt1(struct rte_mbuf *pkt);
struct ether_addr *get_link_hw_addr(uint8_t out_port);
#ifdef VNF_ACL

#include <rte_pipeline.h>
#include "rte_ether.h"
#include "app.h"

#if (RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN)
// x86 == little endian
// network  == big endian
#define CHECK_ENDIAN_16(x) rte_be_to_cpu_16(x)
#define CHECK_ENDIAN_32(x) rte_be_to_cpu_32(x)
#else
#define CHECK_ENDIAN_16(x) (x)
#define CHECK_ENDIAN_32(x) (x)
#endif


#define MAX_ARP_RT_ENTRY 32
#define MAX_ND_RT_ENTRY 32

#define ND_IPV6_ADDR_SIZE 16	/* 16 Byte of IPv6 Address */

enum {
ARP_FOUND,
ARP_NOT_FOUND,
NH_NOT_FOUND,
};

enum arp_key_type {
	ARP_IPV4,
	/* ND IPv6 */
	ND_IPV6,
};

struct arp_key_ipv4 {
	uint32_t ip;
	uint8_t port_id;
	uint8_t filler1;
	uint8_t filler2;
	uint8_t filler3;
};

/* ND IPv6 */
struct nd_key_ipv6 {
	/*128 Bit of IPv6 Address */
	/*<48bit Network> <16bit Subnet> <64bit Interface> */
	uint8_t ipv6[ND_IPV6_ADDR_SIZE];
	uint8_t port_id;
	uint8_t filler1;
	uint8_t filler2;
	uint8_t filler3;
};

struct arp_key {
	enum arp_key_type type;
	union {
		struct arp_key_ipv4 ipv4;
	} key;
};

struct lib_arp_route_table_entry {
	uint32_t ip;
	uint32_t mask;
	uint32_t port;
	uint32_t nh;
};

struct lib_nd_route_table_entry {
	uint8_t ipv6[16];
	uint8_t depth;
	uint32_t port;
	uint8_t nhipv6[16];
};
extern struct lib_arp_route_table_entry lib_arp_route_table[MAX_ARP_RT_ENTRY];
extern struct lib_nd_route_table_entry  lib_nd_route_table[MAX_ND_RT_ENTRY];

extern uint8_t prv_in_port_a[PIPELINE_MAX_PORT_IN];
extern void convert_prefixlen_to_netmask_ipv6(uint32_t depth,
								uint8_t netmask_ipv6[]);
uint32_t get_nh(uint32_t, uint32_t*);
void get_nh_ipv6(uint8_t ipv6[], uint32_t *port, uint8_t nhipv6[]);

extern uint32_t ARPICMP_DEBUG;


/* ARP entry populated and echo reply recieved */
#define COMPLETE   1
/* ARP entry populated and either awaiting echo reply or stale entry */
#define INCOMPLETE 0

/* ND IPv6 */
extern uint32_t NDIPV6_DEBUG;

/* ICMPv6 entry populated and echo reply recieved */
#define ICMPv6_COMPLETE   1
/* ICMPv6 entry populated and either awaiting echo reply or stale entry */
#define ICMPv6_INCOMPLETE 0

struct arp_entry_data {
	struct ether_addr eth_addr;
	uint8_t port;
	uint8_t status;
	uint32_t ip;
} __attribute__ ((__packed__));

/*ND IPv6*/
struct nd_entry_data {
	struct ether_addr eth_addr;
	uint8_t port;
	uint8_t status;
	uint8_t ipv6[ND_IPV6_ADDR_SIZE];
} __attribute__ ((__packed__));

int get_dest_mac_address(const uint32_t ipaddr, const uint32_t phy_port,
			 struct ether_addr *hw_addr, uint32_t *nhip);
int get_dest_mac_addr(const uint32_t ipaddr, const uint32_t phy_port,
					struct ether_addr *hw_addr);

int get_dest_mac_address_ipv6(uint8_t ipv6addr[], uint32_t phy_port,
						struct ether_addr *hw_addr, uint8_t nhipv6[]);

void lib_arp_request_arp(
	const uint32_t ipaddr,
	const uint32_t phy_port,
	struct rte_pipeline *rte_p);

void print_arp_table(void);
void print_nd_table(void);
void remove_arp_entry(uint32_t ipaddr, uint8_t portid);
void remove_nd_entry_ipv6(uint8_t ipv6addr[], uint8_t portid);
void populate_arp_entry(const struct ether_addr *hw_addr, uint32_t ipaddr,
			uint8_t portid);
/*ND IPv6*/
int populate_nd_entry(const struct ether_addr *hw_addr, uint8_t ip[],
					uint8_t portid);
void request_arp(uint8_t port_id, uint32_t ip, struct rte_pipeline *rte_p);
void request_arp_wrap(uint8_t port_id, uint32_t ip);
void request_echo(unsigned int port_id, uint32_t ip);

void process_arpicmp_pkt(struct rte_mbuf *pkt, uint32_t out_port,
			 uint32_t pkt_num);

struct arp_entry_data *retrieve_arp_entry(const struct arp_key_ipv4 arp_key);
struct nd_entry_data *retrieve_nd_entry(struct nd_key_ipv6 nd_key);

struct nd_entry_data *retrieve_nd_entry(struct nd_key_ipv6 nd_key);

void lib_nd_init(/*struct pipeline_params *params, */ struct app_params *app);
void print_pkt1(struct rte_mbuf *pkt);

#endif

uint8_t lb_outport_id[PIPELINE_MAX_PORT_IN];
struct pipeline *loadb_pipeline[PIPELINE_MAX_PORT_IN];
struct pipeline *all_pipeline[PIPELINE_MAX_PORT_IN];
uint8_t vnf_to_loadb_map[PIPELINE_MAX_PORT_IN];
uint8_t port_to_loadb_map[PIPELINE_MAX_PORT_IN];
uint8_t loadb_pipeline_nums[PIPELINE_MAX_PORT_IN];

#if 0
uint8_t lb_outport_id[PIPELINE_MAX_PORT_IN];
struct pipeline *arp_pipeline[PIPELINE_MAX_PORT_IN];
uint8_t vnf_to_arp_map[PIPELINE_MAX_PORT_IN];
uint8_t port_to_arp_map[PIPELINE_MAX_PORT_IN];
uint8_t arp_pipeline_nums[PIPELINE_MAX_PORT_IN];
#endif

void set_port_to_loadb_map(uint8_t pipeline_num);
uint8_t get_port_to_loadb_map(uint8_t phy_port_id);
/* acts on port_to_loadb_map */

void set_phy_inport_map(uint8_t pipeline_num, uint8_t *map);
void set_phy_outport_map(uint8_t pipeline_num, uint8_t *map);

void set_outport_id(uint8_t pipeline_num, struct pipeline *p, uint8_t *map);
/* acts on lb_outport_id */
uint8_t get_loadb_outport_id(uint8_t actual_phy_port);
/* acts on lb_outport_id */
uint8_t get_vnf_set_num(uint8_t pipeline_num);

void pipelines_port_info(void);
void pipelines_map_info(void);
void register_loadb_to_arp(uint8_t pipeline_num, struct pipeline *p,
				 __rte_unused struct app_params *app);
/* vnf_to_loadb_map[]  and loadb_pipelines[] */
uint8_t SWQ_to_Port_map[128];

extern struct pipeline_be_ops pipeline_arpicmp_be_ops;
void register_pipeline_Qs(uint8_t pipeline_num, struct pipeline *p);
void set_link_map(uint8_t pipeline_num, struct pipeline *p, uint8_t *map);
void set_outport_id(uint8_t pipeline_num, struct pipeline *p, uint8_t *map);
void set_phy_outport_id(uint8_t pipeline_num, struct pipeline *p, uint8_t *map);
void set_phy_inport_id(uint8_t pipeline_num, struct pipeline *p, uint8_t *map);

/*
 * Messages
 */
enum pipeline_arpicmp_msg_req_type {
	PIPELINE_ARPICMP_MSG_REQ_ENTRY_DBG,
	PIPELINE_ARPICMP_MSG_REQS
};

/*
 * MSG ENTRY DBG
 */
struct pipeline_arpicmp_entry_dbg_msg_req {
	enum pipeline_msg_req_type type;
	enum pipeline_arpicmp_msg_req_type subtype;

	/* data */
	uint8_t data[2];
};

/*
 * ARPICMP Entry
 */

struct pipeline_arpicmp_in_port_h_arg {
	struct pipeline_arpicmp *p;
	uint8_t in_port_id;
};

struct pipeline_arpicmp_entry_dbg_msg_rsp {
	int status;
};

#ifdef VNF_ACL

 /* ICMPv6 Header */
struct icmpv6_hdr {
	 uint8_t icmpv6_type;    /* ICMPV6 packet type. */
	 uint8_t icmpv6_code;    /* ICMPV6 packet code. */
	 uint16_t icmpv6_cksum;  /* ICMPV6 packet checksum. */
} __attribute__ ((__packed__));

 /**
  * ICMPV6 Info Header
  */
struct icmpv6_info_hdr {
	 uint16_t icmpv6_ident;  /* ICMPV6 packet identifier. */
	 uint16_t icmpv6_seq_nb; /* ICMPV6 packet sequence number. */
} __attribute__ ((__packed__));

 /**
  * ICMPV6 ND Header
  */
struct icmpv6_nd_hdr {
	 /*ND Advertisement flags */
	 uint32_t icmpv6_reserved;
	 /* bit31-Router, bit30-Solicited, bit29-Override, bit28-bit0 unused */

	 uint8_t target_ipv6[16];  /**< target IPv6 address */
 /*ICMPv6 Option*/
	 uint8_t type;
	 uint8_t length;
	 struct ether_addr link_layer_address;
} __attribute__ ((__packed__));

 /* Icmpv6 types */
 #define ICMPV6_PROTOCOL_ID 58
 #define ICMPV6_ECHO_REQUEST 0x0080
 #define ICMPV6_ECHO_REPLY 0x0081
 #define ICMPV6_NEIGHBOR_SOLICITATION 0x0087
  #define ICMPV6_NEIGHBOR_ADVERTISEMENT 0x0088
 #define IPV6_MULTICAST 0xFF02

 #define NEIGHBOR_SOLICITATION_SET 0x40000000
enum icmpv6_link_layer_Address_type {
	 e_Source_Link_Layer_Address = 1,
	 e_Target_Link_Layer_Address,
	 e_Link_Layer_Address
};

uint8_t is_multicast_ipv6_addr(uint8_t ipv6[]);
struct icmpv6_port_address {
	 uint32_t ipv6[16];
	 uint64_t mac_addr;
};

struct icmpv6_port_address icmpv6_port_addresses[RTE_MAX_ETHPORTS];

 #define MAX_NUM_ICMPv6_ENTRIES 64
 //struct rte_pipeline *myicmpP;
struct rte_mbuf *lib_icmpv6_pkt;
void request_icmpv6_echo(uint32_t port_id, uint8_t ipv6[]);
void request_icmpv6_echo_message(uint16_t port_id, uint8_t ipv6[],
					 struct ether_addr *gw_addr);
void
process_icmpv6_pkt(struct rte_mbuf *pkt, uint32_t out_port, uint32_t pkt_num);

int get_dest_mac_addr_port(const uint32_t ipaddr,
	uint32_t *phy_port, struct ether_addr *hw_addr);

int get_dest_mac_address_ipv6_port(uint8_t ipv6addr[], uint32_t *phy_port,
	struct ether_addr *hw_addr, uint8_t nhipv6[]);
#endif
#endif
