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
#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
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
#include <rte_eth_ctrl.h>
#include <rte_errno.h>
#include <rte_port_ethdev.h>
#include <rte_eth_bond.h>
#include <rte_rwlock.h>

#define RTE_LOGTYPE_IFM RTE_LOGTYPE_USER1
#define IFM_SUCCESS  0
#define IFM_FAILURE -1
/*
 * IFM Ether link related macros
 */
#define IFM_ETH_LINK_HALF_DUPLEX    0
#define IFM_ETH_LINK_FULL_DUPLEX    1
#define IFM_ETH_LINK_DOWN           0
#define IFM_ETH_LINK_UP             1
#define IFM_ETH_LINK_FIXED          0

/*
 *  Bonding
 */
#define IFM_SLAVE                   (1<<0)
#define IFM_MASTER                  (1<<1)
#define IFM_BONDED                  (1<<2)
#define IFM_IPV4_ENABLED			(1<<3)
#define IFM_IPV6_ENABLED			(1<<4)

#define IFM_BONDING_MODE_ROUND_ROBIN   0
#define IFM_BONDING_MODE_ACTIVE_BACKUP 1
#define IFM_BONDING_MODE_BALANCE       2
#define IFM_BONDING_MODE_BROADCAST     3
#define IFM_BONDING_MODE_8023AD        4
#define IFM_BONDING_MODE_TLB           5
#define IFM_BONDING_MODE_ALB           6

#define IFM_BALANCE_XMIT_POLICY_LAYER2   0
#define IFM_BALANCE_XMIT_POLICY_LAYER23  1
#define IFM_BALANCE_XMIT_POLICY_LAYER34  2
/*
 * Queue related macros
 */
#define IFM_QUEUE_STAT_CNTRS	16
#define IFM_TX_DEFAULT_Q	0
#define IFM_RX_DEFAULT_Q	0
#define IFM_RX_DESC_DEFAULT	128
#define IFM_TX_DESC_DEFAULT	512
#define IFM_BURST_SIZE		32
#define IFM_BURST_TX_WAIT_US	1
#define IFM_BURST_TX_RETRIES	64
#define BURST_TX_DRAIN_US	100

/*
 * Misc
 */
#define IFM_IFNAME_LEN			16
#define IFM_CLIENT_NAME		20
#define IFM_MAX_CLIENT			10

#define IFM_ETHER_ADDR_SIZE	6
#define IFM_IPV6_ADDR_SIZE	16

#define IFM_DEBUG_CONFIG        (1<<0)
#define IFM_DEBUG_RXTX          (1<<1)
#define IFM_DEBUG_LOCKS         (1<<2)
#define IFM_DEBUG		(1<<4)
#define IFM_MAX_PORTARR_SZ 64
#define IFM_MAX_PORTARR_SZ 64
/**
 * Mempool configuration details:
 * Stores the mempool configuration information for the port.
 */
struct mempool_config {
	uint32_t pool_size;/**< The number of elements in the mempool.*/
	uint32_t buffer_size;
				 /**< The size of an element*/
	uint32_t cache_size;
				 /**< Cache size */
	uint32_t cpu_socket_id;
				 /**< The socket identifier in the case of NUMA.*/
} __rte_cache_aligned;

/**
 * Port configuration:
 * Stores the configuration information for the port.
 * This structure is used during port and tx/rx queue setup.
 */
typedef struct _port_config_ {
	uint8_t port_id;			/**< port id or pmd id to be configured */
	int nrx_queue;				/**< no of rx queues */
	int ntx_queue;				/**< no of tx queues */
	uint32_t tx_buf_size;
	uint32_t state;				/**< noshut/shut the admin state of the port*/
	uint32_t promisc;			/**< enable/diable promisc mode*/
	struct mempool_config mempool;
						/**< Mempool configurations */
	struct rte_eth_conf port_conf;
						/**< port configuration */
	struct rte_eth_rxconf rx_conf;
						/**< rx queue configurations */
	struct rte_eth_txconf tx_conf;
						/**< tx queue configurations */
} port_config_t;

/**
 * Port statistics:
 * if_stats structure is a member variable of structure l2_phy_interface_t.
 * Used to maintain stats retreived from rte_eth_stats structure.
 */
typedef struct _if_stats_ {
	uint64_t rx_npkts;/**< Total number of successfully received packets.*/
	uint64_t tx_npkts;/**< Total number of successfully transmitted bytes. */
	uint64_t rx_bytes;/**< Total number of successfully received bytes.*/
	uint64_t tx_bytes;/**< Total number of successfully transmitted bytes.*/
	uint64_t rx_missed_pkts;
						 /**< no of packets dropped by hw due because rx queues are full*/
	uint64_t rx_err_pkts;/**< Total number of erroneous received packets. */
	uint64_t rx_nobuf_fail;/**< Total number of RX mbuf allocation failures. */
	uint64_t tx_failed_pkts;/**< Total number of failed transmitted packets.*/
	uint64_t q_rxpkts[IFM_QUEUE_STAT_CNTRS];/**< Total number of queue RX packets.*/
	uint64_t q_txpkts[IFM_QUEUE_STAT_CNTRS];/**< Total number of queue TX packets.*/
	uint64_t q_rx_bytes[IFM_QUEUE_STAT_CNTRS];
						 /**< Total number of successfully received queue bytes.*/
	uint64_t q_tx_bytes[IFM_QUEUE_STAT_CNTRS];
						 /**< Total number of successfully transmitted queue bytes.*/
	uint64_t q_rx_pkt_drop[IFM_QUEUE_STAT_CNTRS];
								/**<Total number of queue packets received that are dropped.*/
} __rte_cache_aligned if_stats;
/**
 * structure to store bond port information
 */
struct bond_port {
	uint8_t bond_portid;
					/**<portid of the bond port.*/
	uint8_t socket_id;
				/**<socketid of the port.*/
	uint8_t mode;
				 /**<mode config.*/
	uint8_t xmit_policy;
					/**<xmit policy for this port.*/
	uint32_t internal_ms;
					 /**<in frequency.*/
	uint32_t link_up_delay_ms;
				 /**<frequency of informing linkup delay.*/
	uint32_t link_down_delay_ms;
						/**<frequency of informing linkdown delay.*/
	uint8_t primary;
			/**<primary port of this bond.*/
	uint8_t slaves[RTE_MAX_ETHPORTS];
					 /**<list of slaves*/
	int slave_count;
		 /**<slave count.*/
	uint8_t active_slaves[RTE_MAX_ETHPORTS];
					 /**<list of active slaves.*/
	int active_slave_count;
			/**<cnt of active slave.*/
} __rte_cache_aligned;

/**
 * Physical port details:
 * Used to store information about configured port.
 * Most of the member variables in this structure are populated
 * from struct rte_eth_dev_info
 */
typedef struct _l2_phy_interface_ {
	struct _l2_phy_interface_ *next;				 /**< pointer to physical interface list */
	uint8_t pmdid;							 /**< populated from rth_eth_dev_info */
	unsigned int if_index;						 /**< populated from rth_eth_dev_info */
	char ifname[IFM_IFNAME_LEN];					 /**< populated from rth_eth_dev_info */
	uint16_t mtu;							 /**< mtu value - configurable */
	uint8_t macaddr[IFM_ETHER_ADDR_SIZE];				/**< Ether addr*/
	uint32_t promisc;						 /**< promisc mode - configurable*/
	uint32_t flags;							 /**< Used for link bonding */
	/* Link status */
	uint32_t link_speed;						 /**< line speed */
	uint16_t link_duplex:1;						 /**< duplex mode */
	uint16_t link_autoneg:1;					 /**< auto negotiation*/
	uint16_t link_status:1;						 /**< operational status */
	uint16_t admin_status:1;					 /**< Admin status of a port*/
	/* queue details */
	struct rte_mempool *mempool;					 /**< HW Q*/
	uint32_t min_rx_bufsize;					 /**< rx buffer size supported */
	uint32_t max_rx_pktlen;						 /**< max size of packet*/
	uint16_t max_rx_queues;						 /**< max number of rx queues supported */
	uint16_t max_tx_queues;						 /**< max number queues supported*/
	uint64_t n_rxpkts;						 /**< number of packets received */
	uint64_t n_txpkts;						 /**< number of packets transmitted */
	if_stats stats;							 /**< port stats - populated from rte_eth_ifstats */
	 uint16_t(*retrieve_bulk_pkts) (uint8_t, uint16_t, struct rte_mbuf **);
										/**< pointer to read packets*/
	 uint16_t(*transmit_bulk_pkts) (struct _l2_phy_interface_ *, struct rte_mbuf **, uint64_t);
								/**< pointer to transmit the bulk of packets */
	int (*transmit_single_pkt) (struct _l2_phy_interface_ *, struct rte_mbuf *);
								/**< pointer to transmit the a single packet*/
	struct rte_eth_dev_tx_buffer *tx_buffer;
	uint64_t tx_buf_len;						 /**< number of packets in tx_buf */
	void *ipv4_list;						 /**< pointer to ip list */
	void *ipv6_list;			/**< pointer to ipv6 list */
	struct bond_port *bond_config;			/**< pointer to bond info*/
	port_config_t port_config;
} __rte_cache_aligned l2_phy_interface_t;

/**
 * Port IPv4 address details:
 * Used to maintain IPv4 information of a port.
 */
typedef struct _ipv4list_ {
	struct _ipv4list_ *next;/**< pointer to IPv4 list */
	uint32_t ipaddr;	/**< Configured ipv4 address */
	unsigned int addrlen;	/**< subnet mask or addrlen */
	unsigned int mtu;	/**< IPv6 mtu*/
	l2_phy_interface_t *port;
				/**< pointer to a port on which this ipaddr is configured*/
} ipv4list_t;

/**
 * Port IPv6 address details:
 * Used to maintain IPv6 information of a port.
 */
typedef struct _ipv6list_ {
	struct _ipv6list_ *next;			 /**< Ptr IPv6 list */
	uint8_t ipaddr[IFM_IPV6_ADDR_SIZE];		 /**< Configured ipv6 address */
	unsigned int addrlen;				 /**< subnet mask or addrlen*/
	unsigned int mtu;				/**< IPv6 mtu*/
	l2_phy_interface_t *port;			 /**< ptr to a port on whicch ipv6 addr is configured*/
} ipv6list_t;

/**
 * Interface Manager client details:
 * Maintains information about clients who registered for link status update.
 * Stores callback function to be called in case of link state change.
 */
typedef struct _ifm_client_ {
	uint32_t clientid;					 /**< unique client id identifies the client used for indexing*/
	void (*cb_linkupdate) (uint8_t, unsigned int);
								 /**< callback function to be triggered during an event*/
} __rte_cache_aligned ifm_client;

/**
 * Interface manager global structure:
 * IFM main structure has pointer configured port list.
 */
typedef struct _interface_main_ {
	l2_phy_interface_t *port_list[IFM_MAX_PORTARR_SZ];
	uint32_t nport_configured;			 /**< no of ports sucessfully configured during PCI probe*/
	uint32_t nport_intialized;			 /**< no of ports sucessfully initialized through ifm_init*/
	uint8_t nclient;				 /**< no of clients registered for Interface manager events*/
	ifm_client if_client[IFM_MAX_CLIENT];		 /**< Array of interface manager client details*/
} __rte_cache_aligned interface_main_t;

/**
 * Init function of Interface manager. Calls port_setup function for every port.
 *
 * @param *pconfig
 *   A pointer to port_config_t contains port configuration.
 *
 * @returns
 *    IFM_SUCCESS - On success.
 *    IFM_FAILURE - On Failure.
 */
int ifm_configure_ports(port_config_t *pconfig);

/**
 * Returns first port from port list.
 *
 * @param
 *     None
 *
 * @returns
 *    On success - Returns a pointer to first port in the list of
 *                 type l2_phy_interface_t.
 *    NULL - On Failure.
 */
l2_phy_interface_t *ifm_get_first_port(void);

/**
 * Get a port from the physical port list which is next node to
 * the given portid in the list.
 *
 * @param portid
 *   A pmdid of port.
 *
 * @returns
 *    On success - Returns a pointer to next port in the list of
 *                 type l2_phy_interface_t.
 *    NULL - On Failure.
 */
l2_phy_interface_t *ifm_get_next_port(uint8_t port_id);

/**
 * Get a pointer to port for the given portid from the physical port list.
 *
 * @param portid
 *   A pmd id of the port.
 *
 * @returns
 *    On success - returns pointer to l2_phy_interface_t.
 *    NULL - On Failure.
 */
l2_phy_interface_t *ifm_get_port(uint8_t);

/**
 * Get a pointer to port for the given port name from the physical port list.
 *
 * @param name
 *   Name of the port
 *
 * @returns
 *    On success - returns pointer to l2_phy_interface_t.
 *    NULL - On Failure.
 */
l2_phy_interface_t *ifm_get_port_by_name(const char *name);
/**
 * Removes given port from the physical interface list.
 *
 * @params
 *   portid - pmd_id of port.
 * @returns
 *   none
 */
void ifm_remove_port_details(uint8_t portid);

/**
 * Adds give port to the begining of physical interface list.
 *
 * @param l2_phy_interface_t *
 *  pointer to l2_phy_interface_t.
 * @returns
 *   none
 */
void ifm_add_port_to_port_list(l2_phy_interface_t *);

/**
 * Checks whether the global physical port list is NULL.
 *
 * @returns
 *     0 - On success.
 *     1 - On Failure.
 */
int is_port_list_null(void);

/**
 * Configures the device port. Also sets tx and rx queue.
 * Populates port structure and adds it physical interface list.
 *
 * @param portconfig
 *   Contains configuration about rx queue, tx queue.
 *
 * @returns
 *    IFM_SUCCESS - On success.
 *    IFM_FAILURE - On Failure.
 */
int ifm_port_setup(uint8_t port_id, port_config_t *);

/**
 * Initializes interface manager main structure
 * @params
 *   none
 * @returns
 *   none
 */
void ifm_init(void);

/**
 * Returns number of ports initialized during pci probe.
 *
 * @params
 *   void
 *
 * @returns
 *    number of ports initialized - On success.
 *    IFM_FAILURE - On Failure.
 */
int32_t ifm_get_nports_initialized(void);

/**
 * Returns number of ports initialized ifm_init.
 *
 * @params
 *   void
 *
 * @returns
 *    number of ports initialized - On success.
 *    IFM_FAILURE - On Failure.
 */
int32_t ifm_get_nactive_ports(void);

/**
 * Checks whether port is ipv4 enabled.
 *
 * @param portid
 *   A pmd id of the port.
 *
 * @returns
 *    IFM_SUCCESS - On success.
 *    IFM_FAILURE - On Failure.
 */
int32_t ifm_chk_port_ipv4_enabled(uint8_t port_id);

/**
 * Checks whether port is ipv6 enabled.
 *
 * @param portid
 *   A pmd id of the port.
 *
 * @returns
 *    IFM_SUCCESS - On success.
 *    IFM_FAILURE - On Failure.
 */
int32_t ifm_chk_port_ipv6_enabled(uint8_t port_id);

/**
 * Remove ipv4 address from the given port.
 *
 * @param portid
 *   A pmd id of the port.
 * @param ipaddr
 *   ipv4 address to be removed
 * @param addrlen
 *   ipv4 address length
 *
 * @returns
 *     IFM_SUCCESS - On success.
 *    IFM_FAILURE - On Failure.
 */
int16_t ifm_remove_ipv4_port(uint8_t port_id, uint32_t ipaddr,
						uint32_t addrlen);

/**
 * Remove ipv6 address from the given port.
 *
 * @param portid
 *   A pmd id of the port.
 * @param ip6addr
 *   ipv4 address to be removed
 * @param addrlen
 *   ipv4 address length
 *
 * @returns
 *     IFM_SUCCESS - On success.
 *    IFM_FAILURE - On Failure.
 */
int16_t ifm_remove_ipv6_port(uint8_t port_id, uint32_t ip6addr,
						uint32_t addrlen);

/**
 * Add ipv4 address to the given port.
 *
 * @param portid
 *   A pmd id of the port.
 * @param ipaddr
 *   ipv4 address to be configured
 * @param addrlen
 *   ipv4 address length
 *
 * @returns
 *     IFM_SUCCESS - On success.
 *    IFM_FAILURE - On Failure.
 */
int16_t ifm_add_ipv4_port(uint8_t port_id, uint32_t ipaddr, uint32_t addrlen);

/**
 * Add ipv6 address to the given port.
 *
 * @param portid
 *   A pmd id of the port.
 * @param ip6addr
 *   ipv6 address to be configured
 * @param addrlen
 *   ipv4 address length
 *
 * @returns
 *     IFM_SUCCESS - On success.
 *    IFM_FAILURE - On Failure.
 */
int8_t ifm_add_ipv6_port(uint8_t port_id, uint8_t ip6addr[], uint32_t addrlen);

/**
 * Buffers the packet in the tx quueue.
 *
 * @param *port
 *   pointer to the port.
 * @param *tx_pkts
 *   packet to be transmitted
 *
 * @returns
 *     number of packets transmitted
 */
int ifm_transmit_single_pkt(l2_phy_interface_t *port,
					struct rte_mbuf *tx_pkts);

/**
 * Transmit the packet
 *
 * @param *port
 *   pointer to the port.
 * @param *tx_pkts
 *   packets to be transmitted
 * @param npkts
 *   number of packets to be transmitted
 *
 * @returns
 *     number of packets transmitted
 */
uint16_t ifm_transmit_bulk_pkts(l2_phy_interface_t *, struct rte_mbuf **tx_pkts,
				uint64_t npkts);

/**
 * Receive burst of 32 packets
 *
 * @param portid
 *   From which port we need to read packets
 * @param qid
 *   From which port we need to read packets
 * @param npkts
 *   mbuf in which read packets will be placed
 *
 * @returns
 *     number of packets read
 */
uint16_t ifm_receive_bulk_pkts(uint8_t port_id, uint16_t qid,
						 struct rte_mbuf **rx_pkts);

/**
 * Enable or disable promiscmous mode
 *
 * @param portid
 *   pmd id of the port
 * @param enable
 *   1 - enable, IFM_SUCCESS - disable
 *
 * @returns
 *   none
 */
void ifm_set_port_promisc(uint8_t port_id, uint8_t enable);

/**
 * Enable or disable promiscmous mode
 *
 * @param portid
 *   pmd id of the port
 * @param enable
 *   1 - enable, 0 - disable
 *
 * @returns
 *   none
 */
void ifm_set_l2_interface_mtu(uint8_t port_id, uint16_t mtu);

/**
 * Set MTU value for the port
 *
 * @param portid
 *   pmd id of the port
 * @param mtu
 *   MTU value
 *
 * @returns
 *   none
 */
void ifm_update_linkstatus(uint8_t port_id, uint16_t linkstatus);

/**
 * Register for link state event
 *
 * @param clientid
 *   Unique number identifies client.
 * @param cb_linkupdate
 *   Callback function which has to be called at time of event
 *
 * @returns
 *   none
 */
void ifm_register_for_linkupdate(uint32_t clientid,
				 void (*cb_linkupdate) (uint8_t, unsigned int));

/**
 * Callback which is triggered at the time of link state change which in turn triggers registered
 * clients callback
 *
 * @param portid
 *   pmd id of the port
 * @param type
 *   lsi event type
 * @param
 *   Currently not used
 *
 * @returns
 *   none
 */
void lsi_event_callback(uint8_t port_id, enum rte_eth_event_type type,
			void *param);
/*
 * Prints list of interfaces
 * @param vois
 */
void print_interface_details(void);
/*
 * Creates bond interface
 * @Param name
 *	name of bond port
 * @Param mode
 *	mode
 * @Param portconf
 *	port configuration to be applied
 * @returns 0 on success and 1 on failure
 */
int ifm_bond_port_create(const char *name, int mode, port_config_t *portconf);
/*
 * Deletes bond interface
 * @Param name
 *	name of bond port
 * @returns 0 on success and 1 on failure
 */
int ifm_bond_port_delete(const char *name);
/*
 * Addes a port as slave to bond
 * @Param bonded_port_id
 *	bond port id
 * @Param slave_port_id
 *	slave port s port id
 * @returns 0 on success and 1 on failure
 */
int ifm_add_slave_port(uint8_t bonded_port_id, uint8_t slave_port_id);
/*
 * Removes a port as slave to bond
 * @Param bonded_port_id
 *	bond port id
 * @Param slave_port_id
 *	slave port s port id
 * @returns 0 on success and 1 on failure
 */
int ifm_remove_slave_port(uint8_t bonded_port_id, uint8_t slave_port_id);
/*
 * Sets bond port 's mode
 * @Param bonded_port_id
 *      bond port id
 * @Param mode
 *      mode 0 ... 5
 * @returns 0 on success and 1 on failure
 */
int set_bond_mode(uint8_t bonded_port_id, uint8_t mode);
/*
 * Get bond port 's mode
 * @Param bonded_port_id
 *      bond port id
 * @returns mode value or -1 on failure
 */
int get_bond_mode(uint8_t bonded_port_id);
/*
 * Set a slave port to bond
 * @Param bonded_port_id
 *	bond port id
 * @Param slave_port_id
 *	slave port s port id
 * @returns 0 on success and 1 on failure
 */
int set_bond_primary(uint8_t bonded_port_id, uint8_t slave_port_id);
/*
 * Get primary port of the bond
 * @Param bonded_port_id
 *	bond port id
 * @returns port id of primary on success and 1 on failure
 */
int get_bond_primary_port(uint8_t bonded_port_id);
/*
 * Get slave count for the bond
 * @Param bonded_port_id
 *	bond port id
 * @returns slave count on success and 1 on failure
 */
int get_bond_slave_count(uint8_t bonded_port_id);
/*
 * Get active slave count for the bond
 * @Param bonded_port_id
 *	bond port id
 * @returns active slaves count on success and 1 on failure
 */
int get_bond_active_slave_count(uint8_t bonded_port_id);
/*
 * Get slaves in the bond
 * @Param bonded_port_id
 *	bond port id
 * @Param slaves
 *	array to save slave port
 * @returns 0 on success and 1 on failure
 */
int get_bond_slaves(uint8_t bonded_port_id, uint8_t slaves[RTE_MAX_ETHPORTS]);
/*
 * Get active slaves in the bond
 * @Param bonded_port_id
 *	bond port id
 * @Param slaves
 *	array to save slave port
 * @returns 0 on success and 1 on failure
 */
int get_bond_active_slaves(uint8_t bonded_port_id,
				 uint8_t slaves[RTE_MAX_ETHPORTS]);
/*
 * Sets bond port 's mac address
 * @Param bonded_port_id
 *      bond port id
 * @Param mode
 *      mac_addr - mac addr
 * @returns 0 on success and 1 on failure
 */
int set_bond_mac_address(uint8_t bonded_port_id, struct ether_addr *mac_addr);
/*
 * Sets bond port 's MAC
 * @Param bonded_port_id
 *      bond port id
 * @returns 0 on success and 1 on failure
 */
int reset_bond_mac_addr(uint8_t bonded_port_id);
int get_bond_mac(uint8_t bonded_port_id, struct ether_addr *macaddr);
/*
 * Sets bond port 's policy
 * @Param bonded_port_id
 *      bond port id
 * @Param policy
 *      xmit policy
 * @returns 0 on success and 1 on failure
 */
int set_bond_xmitpolicy(uint8_t bonded_port_id, uint8_t policy);
/*
 * Get bond port 's xmit policy
 * @Param bonded_port_id
 *      bond port id
 * @returns xmit policy value or -1 on failure
 */
int get_bond_xmitpolicy(uint8_t bonded_port_id);
/*
 * Sets bond port 's monitor frequency
 * @Param bonded_port_id
 *      bond port id
 * @Param internal_ms
 *      frequency in ms
 * @returns 0 on success and 1 on failure
 */
int set_bond_link_montitor_frequency(uint8_t bonded_port_id,
						 uint32_t internal_ms);
/*
 * Get bond port 's monitor frequency
 * @Param bonded_port_id
 *      bond port id
 * @returns frequency value or -1 on failure
 */
int get_bond_link_monitor_frequency(uint8_t bonded_port_id);
/*
 * Sets bond port 's link down delay
 * @Param bonded_port_id
 *      bond port id
 * @Param delay_ms
 *      delay time in ms
 * @returns 0 on success and 1 on failure
 */
int set_bond_linkdown_delay(uint8_t bonded_port_id, uint32_t delay_ms);
/*
 * Get bond port 's link down delay
 * @Param bonded_port_id
 *      bond port id
 * @returns delay ms value or -1 on failure
 */
int get_bond_link_down_delay(uint8_t bonded_port_id);
/*
 * Sets bond port 's link up delay
 * @Param bonded_port_id
 *      bond port id
 * @Param delay_ms
 *      delay time in ms
 * @returns 0 on success and 1 on failure
 */
int set_bond_linkup_delay(uint8_t bonded_port_id, uint32_t delay_ms);
/*
 * Get bond port 's link up delay
 * @Param bonded_port_id
 *      bond port id
 * @returns delay ms value or -1 on failure
 */
int get_bond_link_up_delay(uint8_t bonded_port_id);
/*
 * Print port s statistics
 * @Param void
 * @returns void
 */
void print_stats(void);
/*
 * Gets information about port
 * @Param port_id
 *	portid of the port
 * @param port_info
 *      port to address to copy port info
 * @returns 0 on success otherwise -1
 */
int ifm_get_port_info(uint8_t port_id, l2_phy_interface_t *port_info);
/*
 * Gets information about next port of given portid
 * @Param port_id
 *	portid of the port
 * @param port_info
 *      port to address to copy port info
 * @returns 0 on success otherwise -1
 */
int ifm_get_next_port_info(uint8_t port_id, l2_phy_interface_t *port_info);
/*
 * Enable ifm debug
 * @Param dbg value
 *	Debug- 1(port config),2(port RXTX),3(hle LOCKS),4(GENERALDEBUG)
 * @param flag
 *      Enable 1, disable 0
 * @returns 0 on success otherwise -1
 */
void config_ifm_debug(int dbg, int flag);
#endif
