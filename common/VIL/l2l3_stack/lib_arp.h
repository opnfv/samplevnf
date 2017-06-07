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

#ifndef __INCLUDE_LIB_ARP_H__
#define __INCLUDE_LIB_ARP_H__

#include <rte_pipeline.h>
#include "rte_ether.h"
#include "l2_proto.h"
#include "app.h"

#define ND_IPV6_ADDR_SIZE 16	/**< 16 Byte of IPv6 Address. */
#define ND_IPV6_TIMER_EXPIRY 300  /**< in Seconds, Timer for ND IPv6 Expiry */
#define ARP_TIMER_EXPIRY 20	 /**< in Seconds, TIMER for ARP Expiry */
#define TIMER_MILLISECOND 1
#define RTE_LOGTYPE_LIBARP RTE_LOGTYPE_USER1
#define MAX_ND_RT_ENTRY 32
#define MAX_ARP_RT_ENTRY 32
#define NUM_DESC                (get_arp_buf())
#define ARP_BUF_DEFAULT                30000
#define PROBE_TIME             50
#undef L3_STACK_SUPPORT

/**
* A structure for Route table entries of IPv4
*/

struct lib_arp_route_table_entry {
	uint32_t ip;	/**< Ipv4 address*/
	uint32_t mask;	/**< mask */
	uint32_t port;	/**< Physical port */
	uint32_t nh;	/**< next hop */
	uint32_t nh_mask;
};

#define MAX_LOCAL_MAC_ADDRESS	       32
#define MAX_PORTS                      32
struct arp_cache {
        uint32_t nhip[MAX_LOCAL_MAC_ADDRESS];
        struct ether_addr link_hw_laddr[MAX_LOCAL_MAC_ADDRESS];
        uint32_t num_nhip;
};

struct nd_cache {
        uint32_t nhip[MAX_LOCAL_MAC_ADDRESS][16];
        struct ether_addr link_hw_laddr[MAX_LOCAL_MAC_ADDRESS];
        uint32_t num_nhip;
};

/**
* A structure for Route table entires of IPv6
*
*/
struct lib_nd_route_table_entry {
	uint8_t ipv6[16];	/**< Ipv6 address */
	uint8_t depth;		/**< Depth */
	uint32_t port;		/**< Port */
	uint8_t nhipv6[16];	/**< next hop Ipv6 */
};

uint8_t arp_cache_dest_mac_present(uint32_t out_port);
uint8_t nd_cache_dest_mac_present(uint32_t out_port);
extern struct lib_nd_route_table_entry lib_nd_route_table[MAX_ND_RT_ENTRY];
extern struct lib_arp_route_table_entry lib_arp_route_table[MAX_ARP_RT_ENTRY];
extern struct ether_addr *get_local_link_hw_addr(uint8_t out_port, uint32_t nhip);
extern struct ether_addr *get_nd_local_link_hw_addr(uint8_t out_port, uint8_t nhip[]);
extern struct arp_cache arp_local_cache[MAX_PORTS];
extern void prefetch(void);
extern void update_nhip_access(uint8_t);
uint32_t get_arp_buf(void);
uint32_t get_nd_buf(void);

enum {
	ARP_FOUND,
	ARP_NOT_FOUND,
	NH_NOT_FOUND,
};

enum arp_key_type {
	ARP_IPV4,
	ND_IPV6,
};

struct arp_key_ipv4 {
	uint32_t ip;	 /**< IP address */
	uint8_t port_id; /**< Port id */
	uint8_t filler1; /**< filler 1, for better hash key */
	uint8_t filler2; /**< filler 2, for better hash key */
	uint8_t filler3; /**< filler 3, for better hash key */
};

/**
* IPv6
*/
struct nd_key_ipv6 {
	uint8_t ipv6[ND_IPV6_ADDR_SIZE]; /**< 128 Bit of IPv6 Address*/
	uint8_t port_id;		 /**< Port id */
	uint8_t filler1;
	uint8_t filler2;
	uint8_t filler3;
};

/**
* Arp Key
*/
struct arp_key {
	enum arp_key_type type;
	union {
		struct arp_key_ipv4 ipv4;
	} key;	/**< Key of type arp key Ipv4 */
};

/**
* call back function parameter pair remove nd entry
*
*/

struct nd_timer_key {
	uint8_t ipv6[ND_IPV6_ADDR_SIZE];   /**< IPv6 address */
	uint8_t port_id;		 /**< Port id */
} __rte_cache_aligned;

/**
* call back function parameter remove arp entry
*
*/
struct arp_timer_key {
	uint32_t ip;	 /**< Ip address */
	uint8_t port_id; /**< Port id */
} __rte_cache_aligned;

extern uint32_t ARPICMP_DEBUG;

enum {
	INCOMPLETE,
	COMPLETE,
	PROBE,
	STALE
};
#define USED_TIME	5
//#define COMPLETE   1 /**< ARP entry populated and echo reply recieved. */
//#define INCOMPLETE 0 /**< ARP entry populated and either awaiting echo reply or stale entry. */

extern uint32_t NDIPV6_DEBUG;  /**< ND IPv6 */

#define ICMPv6_COMPLETE   1 /**< ICMPv6 entry populated and echo reply recieved. */
#define ICMPv6_INCOMPLETE 0 /**< ICMPv6 entry populated and either awaiting echo reply or stale entry. */
#define STATIC_ARP 1			/**< Static ARP Entry. */
#define DYNAMIC_ARP 0			/**< Dynamic ARP Entry. */
#define STATIC_ND 1			/**< Static ND Entry. */
#define DYNAMIC_ND 0			/**< Dynamic ND Entry. */

/**
* A structure is used to defined the ARP entry data
* This structure is used as a input parameters for entry of ARP data
*/

struct arp_entry_data {
	struct ether_addr eth_addr; /**< ethernet address */
	uint32_t ip;				/**< IP address */
	uint8_t port;				/**< Port */
	uint8_t status;				/**< Status of entry */
	uint8_t mode;				/**< Mode */
	uint8_t retry_count;			/**< retry count for ARP*/
	struct rte_timer *timer;    /**< Timer Associated with ARP*/
	struct arp_timer_key *timer_key;
        rte_rwlock_t queue_lock;    /** queue lock */
	struct rte_mbuf **buf_pkts;
	uint32_t num_pkts;
	uint64_t n_confirmed;
} __attribute__ ((packed));

/**
* A structure is used to defined the table for arp entry data
* This structure is used to maintain the arp entry data
*/

struct table_arp_entry_data {
	uint8_t eth_addr[6];	 /**< Ethernet address */
	uint8_t port;		 /**< port */
	uint8_t status;		 /**< status of entry */
	uint32_t ip;		 /**< Ip address */
} __attribute__ ((packed));

/**
* A structure is used to define the ND entry data for IPV6
* This structure is used as a input parameters  for ND entry data
*/

struct nd_entry_data {
	struct ether_addr eth_addr;		/**< Ethernet address */
	uint8_t port;				/**< port */
	uint8_t status;				/**< statusof the entry */
	uint8_t mode;				/**< Mode */
	uint8_t ipv6[ND_IPV6_ADDR_SIZE];  /**< Ipv6 address */
	uint8_t retry_count;			/**< retry count for ARP*/
	struct rte_timer *timer;		/**< Timer */
	struct nd_timer_key *timer_key;
        rte_rwlock_t queue_lock;    /** queue lock */
	struct rte_mbuf **buf_pkts;
	uint32_t num_pkts;
	uint64_t n_confirmed;
} __attribute__ ((packed));

/**
* A structure is used to define the table for ND entry data
* This structure is used to maintain ND entry data
*
*/

struct table_nd_entry_data {
	uint8_t eth_addr[6];		 /**< Ethernet address */
	uint8_t port;			 /**< Port */
	uint8_t status;			 /**< status of Entry */
	uint8_t ipv6[ND_IPV6_ADDR_SIZE]; /**< IPv6 address */
	struct rte_timer *timer;	 /**< Timer */
} __attribute__ ((packed));

struct arp_data {
	struct lib_arp_route_table_entry
            lib_arp_route_table[MAX_ARP_RT_ENTRY];
	uint8_t lib_arp_route_ent_cnt;
	struct lib_nd_route_table_entry
            lib_nd_route_table[MAX_ARP_RT_ENTRY];
	uint8_t lib_nd_route_ent_cnt;
	struct arp_cache arp_local_cache[MAX_PORTS];
	struct nd_cache nd_local_cache[MAX_PORTS];
	struct ether_addr link_hw_addr[MAX_LOCAL_MAC_ADDRESS];
	uint32_t link_hw_addr_array_idx;
	uint8_t arp_cache_hw_laddr_valid[MAX_LOCAL_MAC_ADDRESS];
	uint8_t nd_cache_hw_laddr_valid[MAX_LOCAL_MAC_ADDRESS];
	uint64_t update_tsc[MAX_LOCAL_MAC_ADDRESS];
} __rte_cache_aligned;

/**
* To get the destination MAC address andnext hop for the ip address  and outgoing port
* @param1 ip addr
* IP address for which MAC address is needed.
* @param2 phy_port
*  Physical Port
* @param3 ether_addr
* pointer to the ether_addr, This gets update with valid MAC addresss
* @Param4 next nhip
* Gets the next hop IP by Ip address and physical port
* @return
* 0 if failure, and 1 if success
*/
struct arp_entry_data *get_dest_mac_addr_port(const uint32_t ipaddr,
				 uint32_t *phy_port, struct ether_addr *hw_addr);

/**
* To get the destination mac address for IPV6 address
* @param ipv6addr
* IPv6 address which need the destination mac adress
* @param Phy_Port
* physical prt
* @param ether_addr
* pointer to the ether_address, This gets update with valid mac address
* @param Nhipv6[]
* Gets the next hop ipv6 address by ipv6 address and physical port
* @return
* 0 if failure, 1 ifsuccess
*/

struct nd_entry_data *get_dest_mac_address_ipv6_port(uint8_t ipv6addr[], uint32_t *phy_port,
					 struct ether_addr *hw_addr,
					 uint8_t nhipv6[]);
int arp_queue_unresolved_packet(struct arp_entry_data * arp_data,
                        struct rte_mbuf * m);
extern void arp_send_buffered_pkts(struct arp_entry_data *ret_arp_data,struct ether_addr *hw_addr, uint8_t port_id);

int nd_queue_unresolved_packet(struct nd_entry_data *nd_data,
                        struct rte_mbuf * m);
extern void nd_send_buffered_pkts(struct nd_entry_data *ret_nd_data,struct ether_addr *hw_addr, uint8_t port_id);

/**
* To get hardware link address
* @param out_port
* out going  port
*/

struct ether_addr *get_link_hw_addr(uint8_t out_port);

/**
* This prints the Arp Table
* @param void
*
*/
void print_arp_table(void);

/**
* This prints the ND table
* @param void
*
*/
void print_nd_table(void);

/**
* This removes arp entry from Table
* @param ipaddr
* Ipv4 address
* @param portid
* Port id
*/
void remove_arp_entry(struct arp_entry_data *ret_arp_data, void *arg);

/**
* Removes ND entry from Nd Table
* @Param ipv6addr[]
* Ipv6 address
* @Param portid
* Port id
*/

void remove_nd_entry_ipv6(struct nd_entry_data *ret_nd_data, void *arg);

/**
* Populate arp entry in arp Table
* @param ether_addr
* Ethernet address
* @param ipaddr
* Ipv4 adress
* @Param portid
* port id
* @Param mode
* Mode
*/
void populate_arp_entry(const struct ether_addr *hw_addr, uint32_t ipaddr,
			uint8_t portid, uint8_t mode);

/**
* Populate ND entry in ND Table
* @param ether_addr
* Ethernet address
* @param ip[]
* Ipv6 adress
* @Param portid
* port id
* @Param mode
* Mode
*/

void populate_nd_entry(const struct ether_addr *hw_addr, uint8_t ip[],
					 uint8_t portid, uint8_t mode);

/**
* To send ARp request
* @Param port_id
* port id
@ Param IP
* Ip address
*/

void request_arp(uint8_t port_id, uint32_t ip);

/**
* TO send echo request
* @param port_id
* Port id
* @Param ip
* Ip address
*/
struct rte_mbuf *request_echo(uint32_t port_id, uint32_t ip);

/**
* To send icmpv6 echo request
* @Param port_id
* Port id
* @Param ipv6
* ipv6 address
*/
struct rte_mbuf *request_icmpv6_echo(uint8_t ipv6[], l2_phy_interface_t *port);

/**
* To request ND
* @Param ipv6
* ipv6 address
* @Param port
* pointer to port
*/
struct rte_mbuf *request_nd(uint8_t ipv6[], l2_phy_interface_t *port);

/**
* To process te ARP and ICMP packets
* @Param Pkt
* Packets to be processed
* @Param pkt_num
* packet number
* @Param portid
* port id
*/
void process_arpicmp_pkt(struct rte_mbuf *pkt, l2_phy_interface_t *port);

/**
* IPv4
* Validate if key-value pair already exists in the hash table for given key - IPv4
* @Param arp_key
* Arp key to validate entry
*/
struct arp_entry_data *retrieve_arp_entry(const struct arp_key_ipv4 arp_key, uint8_t mode);

/**
* ND IPv6
* Validate if key-value pair already exists in the hash table for given key - ND IPv6
* @Param nd_key
* Nd key to validate Nd entry
*/

struct nd_entry_data *retrieve_nd_entry(struct nd_key_ipv6 nd_key, uint8_t mode);

/**
* Setsup Arp Initilization
*/
//void lib_arp_init(void);
void lib_arp_init(struct pipeline_params *params, struct app_params *app);
#if 0
void set_port_to_loadb_map(uint8_t pipeline_num);

/**
* Acts on port_to_loadb_map
*/
uint8_t get_port_to_loadb_map(uint8_t phy_port_id);

void set_phy_inport_map(uint8_t pipeline_num, uint8_t *map);
void set_phy_outport_map(uint8_t pipeline_num, uint8_t *map);

/**
* Acts on lb_outport_id
*/

uint8_t get_loadb_outport_id(uint8_t actual_phy_port);
uint8_t get_vnf_set_num(uint8_t pipeline_num);

void pipelines_port_info(void);
void pipelines_map_info(void);
#endif
/**
* A callback for arp Timer
* @Param rte_timer
* timer pointer
* @Param arg
* arguments to timer
*/
void arp_timer_callback(struct rte_timer *, void *arg);

/**
* A callback for ND timer
* @Param rte_timer
* timer pointer
* @Param arg
* arguments to timer
*/
void nd_timer_callback(struct rte_timer *timer, void *arg);

/**
* To create Arp Table
* @param void
*/
void create_arp_table(void);
/**
* To create ND Table
* @param void
*/
void create_nd_table(void);

/**
* To parse and process the Arp and icmp packets
* @Param pkt
* pkt to process
* @Param pkt_num
* pkt number
* @Param pkt_mask
* packet mask
* @Param port
* pointer to port
*/
void process_arpicmp_pkt_parse(struct rte_mbuf **pkt, uint16_t pkt_num,
						 uint64_t pkt_mask, l2_phy_interface_t *port);

/**
* Sends garp packet
* @Param port
* pointer to port
*/
void send_gratuitous_arp(l2_phy_interface_t *port);
/**
* To set arp debug
* @Param flag
* set 1 unset 0
*/
void set_arpdebug(int flag);
/**
* To set timer for arp entry
* @Param timeout_val
* timer val for arp entry
*/
void set_arptimeout(uint32_t timeout_val);
/**
* To get nexthop for ipv4
* @Param ipv4
* ipv4 address
* @Param
* timeout_val to set
*/
uint32_t get_nh(uint32_t, uint32_t *, struct ether_addr *addr);
/**
* To get nexthop for ipv6
* @Param ipv6
* ipv6 address
* @Param port
* pointer to port
* @Param nhipv6
* next hop ipv6
*/
void get_nh_ipv6(uint8_t ipv6[], uint32_t *port, uint8_t nhipv6[], struct ether_addr *hw_addr);
#endif
