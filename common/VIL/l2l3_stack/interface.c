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
#include <interface.h>
#include <rte_byteorder.h>
#include <lib_arp.h>
#include <tsx.h>

interface_main_t ifm;
int USE_RTM_LOCKS = 0;
rte_rwlock_t rwlock;
uint8_t ifm_debug;
static int prev_state;

void config_ifm_debug(int dbg, int flag)
{
	switch (dbg) {
	case IFM_DEBUG_CONFIG:
		if (flag) {
			ifm_debug |= IFM_DEBUG_CONFIG;
		} else {
			ifm_debug &= ~IFM_DEBUG_CONFIG;
		}
		break;
	case IFM_DEBUG_RXTX:
		if (flag) {
			ifm_debug |= IFM_DEBUG_RXTX;
		} else {
			ifm_debug &= ~IFM_DEBUG_RXTX;
		}
		break;
	case IFM_DEBUG_LOCKS:
		if (flag) {
			ifm_debug |= IFM_DEBUG_LOCKS;
		} else {
			ifm_debug &= ~IFM_DEBUG_LOCKS;
		}
		break;
	case IFM_DEBUG:
		if (flag) {
			ifm_debug |= IFM_DEBUG;
		} else {
			ifm_debug &= ~IFM_DEBUG;
		}
		break;
	}
}

void ifm_init(void)
{
	int i = 0;
	config_ifm_debug(IFM_DEBUG_CONFIG, 1);
	if (can_use_intel_core_4th_gen_features()) {
		if (ifm_debug & IFM_DEBUG_CONFIG)
			RTE_LOG(INFO, IFM, "TSX not currently supported...\n\r");
		USE_RTM_LOCKS = 0;
	} else {
		if (ifm_debug & IFM_DEBUG_CONFIG)
			RTE_LOG(INFO, IFM, "TSX not supported\n\r");
		USE_RTM_LOCKS = 0;
	}
	if (USE_RTM_LOCKS)
		rtm_init();
	else
		rte_rwlock_init(&rwlock);

	for (i = 0; i < IFM_MAX_PORTARR_SZ; i++) {
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Acquiring WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_lock();
		else
			rte_rwlock_write_lock(&rwlock);

		ifm.port_list[i] = NULL;
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
	}
	ifm.nport_intialized = rte_eth_dev_count();
	ifm.nport_configured = 0;
	RTE_LOG(INFO, IFM, "IFM_INIT: Number of ports initialized during "
		"PCI probing %u.\n\r", ifm.nport_intialized);
}

void ifm_remove_port_details(uint8_t portid)
{
	if (ifm.port_list[portid] != NULL) {
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Acquiring lock %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_lock();
		else
			rte_rwlock_write_lock(&rwlock);
		l2_phy_interface_t *port = ifm.port_list[portid];
		ifm.port_list[portid] = NULL;
		if (ifm_debug & IFM_DEBUG_CONFIG)
			RTE_LOG(INFO, IFM, "%s: NULL set for port %u\n\r",
				__FUNCTION__, portid);
		rte_free(port);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r",
				__FUNCTION__, __LINE__);

		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
	} else {
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM,
				"%s: Failed to remove port details.Port %u info"
				" is already Null.\n\r", __FUNCTION__, portid);
	}
}

l2_phy_interface_t *ifm_get_port(uint8_t port_id)
{
	l2_phy_interface_t *port = NULL;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring lock @ %d\n\r", __FUNCTION__,
			__LINE__);

	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_read_lock(&rwlock);

	port = ifm.port_list[port_id];

	if (port == NULL) {
		/*RTE_LOG(ERR, IFM, "%s: Port %u info not found... configure it first.\n\r",
			 __FUNCTION__, port_id);
		 */
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_read_unlock(&rwlock);
		return NULL;
	}
	if (port->pmdid == port_id) {
		/*RTE_LOG(INFO, IFM, "%s: Port %u found....\n\r",
			 __FUNCTION__, port_id); */
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r",
				__FUNCTION__, __LINE__);

		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_read_unlock(&rwlock);
		return port;
	} else {

/*		RTE_LOG(INFO, IFM,"%s: Mismatch given port %u port in loc %u\n\r",__FUNCTION__,port_id,
				ifm.port_list[port_id]->pmdid);
*/
	}
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r", __FUNCTION__,
			__LINE__);
	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_read_unlock(&rwlock);
	return NULL;
}

l2_phy_interface_t *ifm_get_first_port(void)
{
	l2_phy_interface_t *port = NULL;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring lock @ %d\n\r", __FUNCTION__,
			__LINE__);

	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_read_lock(&rwlock);
	port = ifm.port_list[0];
	if (port == NULL) {
		/*RTE_LOG(ERR, IFM, "%s: Port info not found... configure it first.\n\r",
			 __FUNCTION__); */
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_read_unlock(&rwlock);
		return NULL;
	}
	/*RTE_LOG(ERR, IFM, "%s: Port  %u info is found...%p\n\r",
		 __FUNCTION__, port->pmdid, port); */
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r", __FUNCTION__,
			__LINE__);
	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_read_unlock(&rwlock);
	return port;
}

l2_phy_interface_t *ifm_get_next_port(uint8_t port_id)
{
	l2_phy_interface_t *port = NULL;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring lock @ %d\n\r", __FUNCTION__,
			__LINE__);
	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_read_lock(&rwlock);
	port = ifm.port_list[port_id + 1];
	if (port == NULL) {
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_read_unlock(&rwlock);
		return NULL;
	}
	/*RTE_LOG(ERR, IFM, "%s: Port  %u info is found...\n\r",
		 __FUNCTION__, port_id); */
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r", __FUNCTION__,
			__LINE__);

	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_read_unlock(&rwlock);
	return port;
}

l2_phy_interface_t *ifm_get_port_by_name(const char *name)
{
	l2_phy_interface_t *port = NULL;
	int i;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring lock @ %d\n\r", __FUNCTION__,
			__LINE__);

	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_read_lock(&rwlock);
	for (i = 0; i < RTE_MAX_ETHPORTS && ifm.port_list[i]; i++) {
		port = ifm.port_list[i];
		if (strcmp(name, port->ifname) == 0) {
			if (ifm_debug & IFM_DEBUG_CONFIG)
				RTE_LOG(INFO, IFM, "FOUND! port %u %s\n\r",
					port->pmdid, port->ifname);
			if (ifm_debug & IFM_DEBUG_LOCKS)
				RTE_LOG(INFO, IFM,
					"%s: Releasing lock @ %d\n\r",
					__FUNCTION__, __LINE__);
			if (USE_RTM_LOCKS)
				rtm_unlock();
			else
				rte_rwlock_read_unlock(&rwlock);
			return port;
		}
	}
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r", __FUNCTION__,
			__LINE__);
	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_read_unlock(&rwlock);
	return NULL;
}

void lsi_event_callback(uint8_t port_id, enum rte_eth_event_type type,
			void *param)
{
	struct rte_eth_link link;
	l2_phy_interface_t *port;
	int nclients = ifm.nclient;
	int i;

	RTE_SET_USED(param);
	RTE_SET_USED(type);

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_write_lock(&rwlock);
	}
	rte_eth_link_get(port_id, &link);
	for (i = 0; i < nclients; i++)
		ifm.if_client[i].cb_linkupdate(port_id, link.link_status);
	port = ifm.port_list[port_id];
	if (port == NULL) {
		RTE_LOG(ERR, IFM,
			"%s: Port %u info not found... configure it first.\n\r",
			__FUNCTION__, port_id);
	}
	if (port != NULL && port->pmdid == port_id) {
		if (link.link_status) {
			port->link_status = IFM_ETH_LINK_UP;
			port->link_speed = link.link_speed;
			port->link_duplex = link.link_duplex;
			RTE_LOG(INFO, IFM,
				"EVENT-- PORT %u Link UP - Speed %u Mbps - %s.\n",
				port_id, (unsigned)link.link_speed,
				(link.link_duplex ==
				 ETH_LINK_FULL_DUPLEX) ? ("full-duplex")
				: ("half-duplex"));
			if (port->flags & IFM_MASTER) {
				port->flags |= IFM_BONDED;
				port->bond_config->active_slave_count =
						rte_eth_bond_active_slaves_get(port->pmdid,
									 port->
									 bond_config->
									 active_slaves,
									 RTE_MAX_ETHPORTS);
				struct ether_addr new_mac;
				rte_eth_macaddr_get(port->pmdid,
								(struct ether_addr *)
								&new_mac);
				if (memcmp
						(&new_mac, port->macaddr,
						 sizeof(struct ether_addr))) {
					RTE_LOG(INFO, IFM,
						"Bond port %u MAC has changed.\n\r",
						port->pmdid);
				} else {
					RTE_LOG(INFO, IFM,
						"Bond port %u MAC remains same\n\r",
						port->pmdid);
				}
			}
			if (port->flags & IFM_SLAVE) {
				uint8_t master_portid =
						port->bond_config->bond_portid;
				struct rte_eth_link linkstatus;
				rte_eth_link_get(master_portid, &linkstatus);
				RTE_LOG(INFO, IFM, "Port %u 's Master(%u) status is %u\n\r", port_id,
						master_portid, linkstatus.link_status);
			}
			if (ifm_debug & IFM_DEBUG_LOCKS)
				RTE_LOG(INFO, IFM,
					"%s: Releasing WR lock @ %d\n\r",
					__FUNCTION__, __LINE__);

			if (USE_RTM_LOCKS) {
				rtm_unlock();
			} else {
				rte_rwlock_write_unlock(&rwlock);
			}
			if (port->ipv4_list != NULL) {
				if (ifm_debug & IFM_DEBUG_CONFIG)
					RTE_LOG(INFO, IFM,
						"Sending garp on port %u\n\r",
						port->pmdid);
				if (!prev_state) {
					send_gratuitous_arp(port);
					prev_state = 1;
				}
			}
#if 0
			else {
				if (ifm_debug & IFM_DEBUG_CONFIG)
					RTE_LOG(INFO, IFM,
						"IP is not enabled on port %u, not sending GARP\n\r",
						port->pmdid);
			}
#endif
		} else {
			if (port->flags & IFM_MASTER) {
				port->flags &= ~IFM_BONDED;
				//RTE_LOG(INFO, IFM, "IFM_MASTER port, resetting IFM_BONDED. %u\n\r", port->flags);
			}
			port->link_status = IFM_ETH_LINK_DOWN;
			RTE_LOG(INFO, IFM, "EVENT-- PORT %u is Link DOWN.\n",
				port_id);
			if (port->flags & IFM_SLAVE) {
				struct rte_eth_link linkstatus;
				uint8_t master_portid =
						port->bond_config->bond_portid;
				rte_eth_link_get_nowait(master_portid,
							&linkstatus);
				RTE_LOG(INFO, IFM,
					"Port %u 's Master(%u) status is %u\n\r",
					port_id, master_portid,
					linkstatus.link_status);
			}
			if (ifm_debug & IFM_DEBUG_LOCKS)
				RTE_LOG(INFO, IFM,
					"%s: Releasing WR lock @ %d\n\r",
					__FUNCTION__, __LINE__);
			if (USE_RTM_LOCKS) {
				rtm_unlock();
			} else {
				rte_rwlock_write_unlock(&rwlock);
			}
			prev_state = 0;
		}
	}
	//print_interface_details();
}

void ifm_update_linkstatus(uint8_t port_id, uint16_t linkstatus)
{
	struct rte_eth_link link;
	l2_phy_interface_t *port;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring lock @ %d\n\r", __FUNCTION__,
			__LINE__);

	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_write_lock(&rwlock);
	}
	port = ifm.port_list[port_id];

	if (port == NULL) {
		RTE_LOG(ERR, IFM,
			"%s: Port %u info not found... configure it first.\n\r",
			__FUNCTION__, port_id);
	}
	if (port != NULL && port->pmdid == port_id) {
		rte_eth_link_get(port_id, &link);
		if (linkstatus == IFM_ETH_LINK_UP) {
			port->admin_status = IFM_ETH_LINK_UP;
			if(!link.link_status) {
				if (rte_eth_dev_set_link_up(port_id) < 0) {
					RTE_LOG(INFO, IFM,
							"%s:Port %u admin up is unsuccessful\n\r",
							__FUNCTION__, port->pmdid);
				} else {
					if (ifm_debug & IFM_DEBUG_LOCKS)
						RTE_LOG(INFO, IFM,
								"%s: Releasing lock @ %d\n\r",
								__FUNCTION__, __LINE__);

					if (USE_RTM_LOCKS) {
						rtm_unlock();
					} else {
						rte_rwlock_write_unlock(&rwlock);
					}
					if (ifm_debug & IFM_DEBUG_CONFIG)
						RTE_LOG(INFO, IFM,
								"%s:Port %u admin up...\n\r",
								__FUNCTION__, port->pmdid);
					send_gratuitous_arp(port);
					return;
				}
			}
		} else if (linkstatus == IFM_ETH_LINK_DOWN)
		{
			int status;
			port->admin_status = IFM_ETH_LINK_DOWN;
			/* need to check the following if */
			if(link.link_status) {
				status = rte_eth_dev_set_link_down(port_id);
				if (status < 0)
				{
					rte_panic("(%" PRIu32 "): PMD set link down error %"
							PRId32 "\n", port_id, status);
				}
			}
		}
	}
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r", __FUNCTION__,
			__LINE__);

	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_write_unlock(&rwlock);
	}
}

void ifm_set_l2_interface_mtu(uint8_t port_id, uint16_t mtu)
{
	int ret;
	l2_phy_interface_t *port;
	port = ifm.port_list[port_id];
	if (port == NULL) {
		RTE_LOG(ERR, IFM,
			"%s: Port %u info not found... configure it first.\n\r",
			__FUNCTION__, port_id);
	}

	if (port != NULL && port->pmdid == port_id) {
		ret = rte_eth_dev_set_mtu(port_id, mtu);
		if (ret != 0)
			RTE_LOG(INFO, IFM,
				"set_l2_interface_mtu: Set MTU failed. ret=%d\n",
				ret);
		else {
			if (ifm_debug & IFM_DEBUG_LOCKS)
				RTE_LOG(INFO, IFM,
					"%s: Acquiring lock @ %d\n\r",
					__FUNCTION__, __LINE__);

			if (USE_RTM_LOCKS) {
				rtm_lock();
			} else {
				rte_rwlock_write_lock(&rwlock);
			}
			port->mtu = mtu;
			if (ifm_debug & IFM_DEBUG_LOCKS)
				RTE_LOG(INFO, IFM,
					"%s: Releasing lock @ %d\n\r",
					__FUNCTION__, __LINE__);

			if (USE_RTM_LOCKS) {
				rtm_unlock();
			} else {
				rte_rwlock_write_unlock(&rwlock);
			}
			return;
		}
	}
}

void ifm_set_port_promisc(uint8_t port_id, uint8_t enable)
{
	l2_phy_interface_t *port;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_write_lock(&rwlock);
	}
	port = ifm.port_list[port_id];
	if (port == NULL) {
		RTE_LOG(ERR, IFM,
			"%s: Port %u info not found... configure it first.\n\r",
			__FUNCTION__, port_id);
	}
	if (port != NULL && port->pmdid == port_id) {
		if (enable == 1) {
			rte_eth_promiscuous_enable(port_id);
			port->promisc = 1;
		} else {
			rte_eth_promiscuous_disable(port_id);
			port->promisc = 0;
		}
	}
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_write_unlock(&rwlock);
	}
}

int32_t ifm_get_nactive_ports(void)
{
	return ifm.nport_configured;
}

int32_t ifm_get_nports_initialized(void)
{
	return ifm.nport_intialized;
}

uint16_t ifm_receive_bulk_pkts(uint8_t port_id, uint16_t qid,
						 struct rte_mbuf **rx_pkts)
{
	uint64_t no_of_rcvd_pkt;
	no_of_rcvd_pkt =
			rte_eth_rx_burst(port_id, qid, rx_pkts, IFM_BURST_SIZE);
	if (ifm_debug & IFM_DEBUG_RXTX)
		RTE_LOG(INFO, IFM,
			"ifm_receive_bulk_pkts: port_id %u no_of_rcvd_pkt %lu\n\r",
			port_id, no_of_rcvd_pkt);
	return no_of_rcvd_pkt;
}

uint16_t ifm_transmit_bulk_pkts(l2_phy_interface_t *port,
				struct rte_mbuf **tx_pkts, uint64_t npkts)
{
	uint32_t burst_tx_delay_time = IFM_BURST_TX_WAIT_US;
	uint32_t burst_tx_retry_num = IFM_BURST_TX_RETRIES;
	uint32_t retry;
	uint32_t no_of_tx_pkt;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_read_lock(&rwlock);
	}
	no_of_tx_pkt = rte_eth_tx_burst(port->pmdid, IFM_TX_DEFAULT_Q, tx_pkts,
					npkts);
	if (unlikely(no_of_tx_pkt < npkts)) {
		retry = 0;
		while (no_of_tx_pkt < IFM_BURST_SIZE
					 && retry++ < burst_tx_retry_num) {
			rte_delay_us(burst_tx_delay_time);
			no_of_tx_pkt =
					rte_eth_tx_burst(port->pmdid, IFM_TX_DEFAULT_Q,
							 &tx_pkts[no_of_tx_pkt],
							 IFM_BURST_SIZE - no_of_tx_pkt);
		}
	}
	if (ifm_debug & IFM_DEBUG_RXTX)
		RTE_LOG(INFO, IFM,
			"ifm_transmit_bulk_pkts: no_of_tx_pkt %u\n\r",
			no_of_tx_pkt);
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_read_unlock(&rwlock);
	}
	return no_of_tx_pkt;
}

int ifm_transmit_single_pkt(l2_phy_interface_t *port, struct rte_mbuf *tx_pkts)
{
	uint64_t tx_npkts = 0;
	if (tx_pkts == NULL || port == NULL) {
		RTE_LOG(INFO, IFM,
			"ifm_transmit_single_pkt: tx_pkts and port are NULL ");
		return IFM_FAILURE;
	}
	if (ifm_debug & IFM_DEBUG_RXTX)
		RTE_LOG(INFO, IFM,
			"ifm_transmit_single_pkt: port->pmdid %u\n\r",
			port->pmdid);
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);

	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_read_lock(&rwlock);
	}
	tx_npkts =
			rte_eth_tx_buffer(port->pmdid, IFM_TX_DEFAULT_Q, port->tx_buffer,
						tx_pkts);
	if (ifm_debug & IFM_DEBUG_RXTX)
		RTE_LOG(INFO, IFM,
			"ifm_transmit_single_pkt: port->pmdid %u No of packets buffered %lu\n\r",
			port->pmdid, tx_npkts);
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing RW lock @ %d\n\r",
			__FUNCTION__, __LINE__);

	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_read_unlock(&rwlock);
	}
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);

	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_write_lock(&rwlock);
	}
	port->n_txpkts +=
			rte_eth_tx_buffer_flush(port->pmdid, IFM_TX_DEFAULT_Q,
						port->tx_buffer);
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);

	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_write_unlock(&rwlock);
	}
	if (ifm_debug & IFM_DEBUG_RXTX)
		RTE_LOG(INFO, IFM,
			"ifm_transmit_single_pkt: no of pkts flushed %lu\n\r",
			port->n_txpkts);
	return tx_npkts;
}

int16_t ifm_add_ipv4_port(uint8_t port_id, uint32_t ipaddr, uint32_t addrlen)
{
	l2_phy_interface_t *port;
	ipv4list_t *ipconf;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring lock @ %d\n\r", __FUNCTION__,
			__LINE__);

	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_write_lock(&rwlock);
	}
	port = ifm.port_list[port_id];
	if (port == NULL) {
		RTE_LOG(ERR, IFM,
			"%s: Port %u info not found... configure it first.\n\r",
			__FUNCTION__, port_id);
	}
	if (port != NULL && port->pmdid == port_id) {
		ipconf = (ipv4list_t *) rte_zmalloc(NULL, sizeof(ipv4list_t),
								RTE_CACHE_LINE_SIZE);
		if (ipconf != NULL) {
			ipconf->next = NULL;
			//ipconf->ipaddr = rte_bswap32(ipaddr);
			ipconf->ipaddr = ipaddr;
			ipconf->port = port;
			ipconf->addrlen = addrlen;
			if (port->ipv4_list == NULL)
				port->flags |= IFM_IPV4_ENABLED;
			ipconf->next = (ipv4list_t *) port->ipv4_list;
			port->ipv4_list = (ipv4list_t *) ipconf;
			if (ifm_debug & IFM_DEBUG_LOCKS)
				RTE_LOG(INFO, IFM,
					"%s: Releasing lock @ %d\n\r",
					__FUNCTION__, __LINE__);

			if (USE_RTM_LOCKS) {
				rtm_unlock();
			} else {
				rte_rwlock_write_unlock(&rwlock);
			}
			return 0;
		}
	}
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r", __FUNCTION__,
			__LINE__);

	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_write_unlock(&rwlock);
	}
	return -1;
}

int16_t ifm_remove_ipv4_port(uint8_t port_id, uint32_t ipaddr,
						uint32_t addrlen)
{
	l2_phy_interface_t *port;
	ipv4list_t *iplist, *previplist = NULL;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring lock @ %d\n\r", __FUNCTION__,
			__LINE__);

	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_write_lock(&rwlock);
	}
	port = ifm.port_list[port_id];
	if (port == NULL) {
		RTE_LOG(ERR, IFM,
			"%s: Port %u info not found... configure it first.\n\r",
			__FUNCTION__, port_id);
	}
	if (port != NULL && port->pmdid == port_id) {
		if (port->ipv4_list == NULL) {
			if (ifm_debug & IFM_DEBUG_LOCKS)
				RTE_LOG(INFO, IFM,
					"%s: Releasing lock @ %d\n\r",
					__FUNCTION__, __LINE__);

			if (USE_RTM_LOCKS) {
				rtm_unlock();
			} else {
				rte_rwlock_write_unlock(&rwlock);
			}
			return -1;
		}
		iplist = (ipv4list_t *) port->ipv4_list;
		while (iplist != NULL) {
			if (addrlen == iplist->addrlen &&
					memcpy(&iplist->ipaddr, &ipaddr, addrlen)) {
				if (iplist == port->ipv4_list) {
					port->ipv4_list = iplist->next;
				} else {
					if (previplist != NULL)
						previplist->next = iplist->next;
				}
				port->flags &= ~IFM_IPV4_ENABLED;
				rte_free(iplist);
				if (ifm_debug & IFM_DEBUG_LOCKS)
					RTE_LOG(INFO, IFM,
						"%s: Releasing lock @ %d\n\r",
						__FUNCTION__, __LINE__);

				if (USE_RTM_LOCKS) {
					rtm_unlock();
				} else {
					rte_rwlock_write_unlock(&rwlock);
				}
				return 0;
			} else {
				previplist = iplist;
				iplist = iplist->next;
			}
		}
	}
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r", __FUNCTION__,
			__LINE__);

	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_write_unlock(&rwlock);
	}
	return -1;
}

int8_t ifm_add_ipv6_port(uint8_t port_id, uint8_t ip6addr[], uint32_t addrlen)
{
	l2_phy_interface_t *port;
	ipv6list_t *ip6conf;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring lock @ %d\n\r", __FUNCTION__,
			__LINE__);

	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_write_lock(&rwlock);
	}
	port = ifm.port_list[port_id];
	if (port == NULL) {
		RTE_LOG(ERR, IFM,
			"%s: Port %u info not found... configure it first.\n\r",
			__FUNCTION__, port_id);
	}
	if (port != NULL && port->pmdid == port_id) {
		ip6conf = (ipv6list_t *) rte_zmalloc(NULL, sizeof(ipv6list_t),
								 RTE_CACHE_LINE_SIZE);
		if (ip6conf != NULL) {
			ip6conf->next = NULL;
			memcpy(ip6conf->ipaddr, ip6addr, IFM_IPV6_ADDR_SIZE);
			ip6conf->port = port;
			ip6conf->addrlen = addrlen;

			if (port->ipv6_list == NULL) {
				port->flags |= IFM_IPV6_ENABLED;
			}
			ip6conf->next = (ipv6list_t *) port->ipv6_list;
			port->ipv6_list = (ipv6list_t *) ip6conf;
			if (ifm_debug & IFM_DEBUG_LOCKS)
				RTE_LOG(INFO, IFM,
					"%s: Releasing lock @ %d\n\r",
					__FUNCTION__, __LINE__);

			if (USE_RTM_LOCKS) {
				rtm_unlock();
			} else {
				rte_rwlock_write_unlock(&rwlock);
			}
			return 0;
		}
	}
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r", __FUNCTION__,
			__LINE__);

	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_write_unlock(&rwlock);
	}
	return -1;
}

int16_t ifm_remove_ipv6_port(uint8_t port_id, uint32_t ip6addr,
						uint32_t addrlen)
{
	l2_phy_interface_t *port;
	ipv6list_t *ip6list, *previp6list = NULL;

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring lock @ %d\n\r", __FUNCTION__,
			__LINE__);
	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_write_lock(&rwlock);
	port = ifm.port_list[port_id];
	if (port == NULL) {
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		RTE_LOG(ERR, IFM,
			"%s: Port %u info not found... configure it first.\n\r",
			__FUNCTION__, port_id);
	}
	if (port != NULL && port->pmdid == port_id) {
		if (port->ipv6_list == NULL) {
			if (ifm_debug & IFM_DEBUG_LOCKS)
				RTE_LOG(INFO, IFM,
					"%s: Releasing lock @ %d\n\r",
					__FUNCTION__, __LINE__);

			if (USE_RTM_LOCKS) {
				rtm_unlock();
			} else {
				rte_rwlock_write_unlock(&rwlock);
			}
			return -1;
		}
		ip6list = (ipv6list_t *) port->ipv6_list;
		while (ip6list != NULL) {
			if (addrlen == ip6list->addrlen &&
					memcpy(&ip6list->ipaddr, &ip6addr, addrlen)) {
				if (ip6list == port->ipv6_list) {
					port->ipv6_list = ip6list->next;
				} else {
					if (previp6list != NULL)
						previp6list->next =
								ip6list->next;
				}
				port->flags &= ~IFM_IPV6_ENABLED;
				rte_free(ip6list);
				if (ifm_debug & IFM_DEBUG_LOCKS)
					RTE_LOG(INFO, IFM,
						"%s: Releasing lock @ %d\n\r",
						__FUNCTION__, __LINE__);

				if (USE_RTM_LOCKS) {
					rtm_unlock();
				} else {
					rte_rwlock_write_unlock(&rwlock);
				}
				return 0;
			} else {
				previp6list = ip6list;
				ip6list = ip6list->next;
			}
		}
	}
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r", __FUNCTION__,
			__LINE__);
	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_write_unlock(&rwlock);
	return -1;
}

int32_t ifm_chk_port_ipv4_enabled(uint8_t port_id)
{
	l2_phy_interface_t *port;

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_read_lock(&rwlock);
	port = ifm.port_list[port_id];
	if (port == NULL) {
		RTE_LOG(ERR, IFM,
			"%s: Port %u info not found... configure it first.\n\r",
			__FUNCTION__, port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_read_unlock(&rwlock);
		return IFM_FAILURE;
	}
	if ((port->flags & IFM_IPV4_ENABLED) == 0) {
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_read_unlock(&rwlock);
		return 0;
	} else {
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_read_unlock(&rwlock);
		return 1;
	}
}

int32_t ifm_chk_port_ipv6_enabled(uint8_t port_id)
{
	l2_phy_interface_t *port;

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_read_lock(&rwlock);

	port = ifm.port_list[port_id];
	if (port == NULL) {
		if (ifm_debug & IFM_DEBUG)
			RTE_LOG(ERR, IFM, "%s: Port %u info not found..."
				" configure it first.\n\r",
				__FUNCTION__, port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_read_unlock(&rwlock);
		return IFM_FAILURE;
	}
	if ((port->flags & IFM_IPV6_ENABLED) == 0) {
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_read_unlock(&rwlock);
		return 0;
	} else {
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_read_unlock(&rwlock);
		return 1;
	}
}

void ifm_register_for_linkupdate(uint32_t clientid,
				 void (*cb_linkupdate) (uint8_t, unsigned int))
{
	ifm.if_client[ifm.nclient].cb_linkupdate = cb_linkupdate;
	ifm.if_client[ifm.nclient].clientid = clientid;
	ifm.nclient++;
}

int ifm_port_setup(uint8_t port_id, port_config_t *pconfig)
{
	int status, sock;
	char buf[12];
	struct rte_eth_dev_info dev_info;
	struct rte_eth_link linkstatus;
	l2_phy_interface_t *port = NULL;

	if (!ifm.nport_intialized) {
		RTE_LOG(ERR, IFM, "%s: Failed to configure port %u. 0 ports"
			"were intialized during PCI probe...\n\r",
			__FUNCTION__, port_id);
		return IFM_FAILURE;
	}
	if (ifm_debug & IFM_DEBUG_CONFIG)
		RTE_LOG(INFO, IFM, "%s: Configuring port %u with "
			"nrxq: %u, ntxq: %u\n\r", __FUNCTION__,
			port_id, pconfig->nrx_queue, pconfig->ntx_queue);
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock1 @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_write_lock(&rwlock);

	if (ifm.port_list[port_id] == NULL) {
		ifm.port_list[port_id] =
				(l2_phy_interface_t *) rte_zmalloc(NULL,
									 sizeof
									 (l2_phy_interface_t),
									 RTE_CACHE_LINE_SIZE);
		ifm.port_list[port_id]->pmdid = port_id;
	}
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing WR lock1 @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_write_unlock(&rwlock);

	rte_eth_link_get(port_id, &linkstatus);
	if (linkstatus.link_status) {
		if (ifm_debug & IFM_DEBUG_CONFIG) {
			RTE_LOG(INFO, IFM, "%s: %u is up.Stop it before"
				" reconfiguring.\n\r", __FUNCTION__, port_id);
		}
		rte_eth_dev_stop(port_id);
	}
	/*Configure an Ethernet device. rets 0 on success queue */
	status = rte_eth_dev_configure(port_id, pconfig->nrx_queue,
							 pconfig->ntx_queue, &pconfig->port_conf);
	if (status < 0) {
		ifm_remove_port_details(port_id);
		RTE_LOG(ERR, IFM, "%s: rte_eth_dev_configure is failed"
			"for port %u.\n\r", __FUNCTION__, port_id);
		return IFM_FAILURE;
	}
	status = rte_eth_dev_callback_register(port_id,
								 RTE_ETH_EVENT_INTR_LSC,
								 lsi_event_callback, NULL);
	if (status < 0) {
		ifm_remove_port_details(port_id);
		RTE_LOG(ERR, IFM, "%s: rte_eth_dev_callback_register()"
			" failed for port %u.\n\r", __FUNCTION__, port_id);
		return IFM_FAILURE;
	}
	/*promiscuous mode is enabled set it */
	if (pconfig->promisc)
		rte_eth_promiscuous_enable(port_id);

	sock = rte_eth_dev_socket_id(port_id);
	if (sock == -1)
		RTE_LOG(ERR, IFM, "%s: Warning: rte_eth_dev_socket_id,"
			" port_id value is"
			"out of range %u\n\r", __FUNCTION__, port_id);
	/*Port initialization */
	int ntxqs;
	for (ntxqs = 0; ntxqs < pconfig->ntx_queue; ntxqs++) {
		status = rte_eth_tx_queue_setup(port_id, ntxqs,
						IFM_TX_DESC_DEFAULT, sock,
						&(pconfig->tx_conf));
		if (status < 0) {
			ifm_remove_port_details(port_id);
			RTE_LOG(ERR, IFM, "%s: rte_eth_tx_queue_setup failed"
				" for port %u\n\r", __FUNCTION__, port_id);
			return IFM_FAILURE;
		}
	}
	port = ifm_get_port(port_id);
	if (port == NULL) {
		RTE_LOG(INFO, IFM, "%s: Port is NULL @ %d\n\r", __FUNCTION__,
			__LINE__);
		return IFM_FAILURE;
	}

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock 2 @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_write_lock(&rwlock);

	if (port->tx_buf_len == 0) {
		port->tx_buf_len = RTE_ETH_TX_BUFFER_SIZE(IFM_BURST_SIZE);
	}
	port->tx_buffer = rte_zmalloc_socket("tx_buffer", port->tx_buf_len, 0,
							 rte_eth_dev_socket_id(port_id));

	if (port->tx_buffer == NULL) {
		ifm_remove_port_details(port_id);
		RTE_LOG(ERR, IFM, "%s: Failed to allocate tx buffers for"
			" port %u\n\r", __FUNCTION__, port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock2 %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_FAILURE;
	}
	rte_eth_tx_buffer_init(port->tx_buffer, IFM_BURST_SIZE);

	sprintf(buf, "MEMPOOL%d", port_id);
	port->mempool = rte_mempool_create(buf,
						 pconfig->mempool.pool_size,
						 pconfig->mempool.buffer_size,
						 pconfig->mempool.cache_size,
						 sizeof(struct
							rte_pktmbuf_pool_private),
						 rte_pktmbuf_pool_init, NULL,
						 rte_pktmbuf_init, NULL, sock, 0);
	if (port->mempool == NULL) {
		ifm_remove_port_details(port_id);
		RTE_LOG(ERR, IFM, "%s: rte_mempool_create is failed for port"
			" %u. Error: %s\n\r",
			__FUNCTION__, port_id, rte_strerror(rte_errno));
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock2 %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_FAILURE;
	}
	int nrxqs;
	for (nrxqs = 0; nrxqs < pconfig->nrx_queue; nrxqs++) {
		status = rte_eth_rx_queue_setup(port_id, nrxqs,
						IFM_RX_DESC_DEFAULT, sock,
						&(pconfig->rx_conf),
						port->mempool);
		if (status < 0) {
			ifm_remove_port_details(port_id);
			RTE_LOG(ERR, IFM,
				"%s: rte_eth_rx_queue_setup is failed "
				"for port %u queue %u. Error: %s\n\r",
				__FUNCTION__, port_id, nrxqs,
				rte_strerror(rte_errno));
			if (ifm_debug & IFM_DEBUG_LOCKS)
				RTE_LOG(INFO, IFM,
					"%s: Releasing WR lock2 %d\n\r",
					__FUNCTION__, __LINE__);
			if (USE_RTM_LOCKS)
				rtm_unlock();
			else
				rte_rwlock_write_unlock(&rwlock);
			return IFM_FAILURE;
		}
	}
	/*Start link */
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing WR lock2  @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_write_unlock(&rwlock);
	status = rte_eth_dev_start(port_id);
	if (status < 0) {
		ifm_remove_port_details(port_id);
		RTE_LOG(ERR, IFM, "%s: rte_eth_dev_start is failed for"
			" port %u.\n\r", __FUNCTION__, port_id);
		return IFM_FAILURE;
	}
	rte_delay_ms(5000);
	/*Get device info and populate interface structure */
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock3 @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_write_lock(&rwlock);
	rte_eth_macaddr_get(port_id, (struct ether_addr *)port->macaddr);
	if (pconfig->promisc)
		port->promisc = 1;
	rte_eth_link_get(port_id, &linkstatus);
	/*Link status */
	port->link_duplex = linkstatus.link_duplex;
	port->link_autoneg = linkstatus.link_autoneg;
	port->link_speed = linkstatus.link_speed;
	port->admin_status = pconfig->state;

	/*Get dev_info */
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port_id, &dev_info);
	port->min_rx_bufsize = dev_info.min_rx_bufsize;
	port->max_rx_pktlen = dev_info.max_rx_pktlen;
	port->max_rx_queues = dev_info.max_rx_queues;
	port->max_tx_queues = dev_info.max_tx_queues;
	rte_eth_dev_get_mtu(port_id, &(port->mtu));

	/*Add rx and tx packet function ptrs */
	port->retrieve_bulk_pkts = &ifm_receive_bulk_pkts;
	port->transmit_bulk_pkts = &ifm_transmit_bulk_pkts;
	port->transmit_single_pkt = &ifm_transmit_single_pkt;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing WR3 lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_write_unlock(&rwlock);
	RTE_LOG(INFO, IFM, "%s: Port %u is successfully configured.\n\r",
		__FUNCTION__, port_id);
	return IFM_SUCCESS;
}

int ifm_configure_ports(port_config_t *pconfig)
{
	uint8_t port_id;
	int status = 0;
	if (!ifm.nport_intialized) {
		RTE_LOG(ERR, IFM, "%s, Configuring ports failed. Zero ports "
			"are intialized during PCI probe", __FUNCTION__);
		return IFM_FAILURE;
	}
	if (pconfig == NULL) {
		RTE_LOG(ERR, IFM, "%s, Configuring ports failed. "
			"Param pconfig is NULL\n\r", __FUNCTION__);
		return IFM_FAILURE;
	}

	/*Initialize all ports */
	for (port_id = 0; port_id < ifm.nport_intialized; port_id++) {
		if (ifm_debug & IFM_DEBUG_CONFIG)
			RTE_LOG(INFO, IFM, "Call ifm_port_setup %u\n\r",
				port_id);
		status =
				ifm_port_setup(pconfig[port_id].port_id, &pconfig[port_id]);
		if (status == IFM_SUCCESS)
			ifm.nport_configured++;
	}
	if (!ifm.nport_configured) {
		RTE_LOG(ERR, IFM, "%s: Zero ports are configured\n\r",
			__FUNCTION__);
		return IFM_FAILURE;
	}
	RTE_LOG(INFO, IFM, "%s: Number of ports sucessfully configured:"
		" %d\n\r", __FUNCTION__, ifm.nport_configured);
	return IFM_SUCCESS;
}

void print_interface_details(void)
{
	l2_phy_interface_t *port;
	int i = 0;
	struct sockaddr_in ip;
	printf("\n\r");

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring RW lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_read_lock(&rwlock);

	for (i = 0; i < RTE_MAX_ETHPORTS && ifm.port_list[i]; i++) {
		port = ifm.port_list[i];
		printf(" %u", port->pmdid);
		if (port->ifname && strlen(port->ifname)) {
			printf(" (%s)\t", port->ifname);
		} else
			printf("\t\t");
		printf("MAC:%02x:%02x:%02x:%02x:%02x:%02x Adminstate:%s"
					 " Operstate:%s \n\r",
					 port->macaddr[0], port->macaddr[1],
					 port->macaddr[2], port->macaddr[3],
					 port->macaddr[4], port->macaddr[5],
					 port->admin_status ? "UP" : "DOWN",
					 port->link_status ? "UP" : "DOWN");
		printf("\t\t");
		printf("Speed: %u, %s-duplex\n\r", port->link_speed,
					 port->link_duplex ? "full" : "half");
		printf("\t\t");

		if (port->ipv4_list != NULL) {
			ip.sin_addr.s_addr =
					(unsigned long)((ipv4list_t *) (port->ipv4_list))->
					ipaddr;
			printf("IP: %s/%d", inet_ntoa(ip.sin_addr),
						 ((ipv4list_t *) (port->ipv4_list))->addrlen);
		} else {
			printf("IP: NA");
		}

		printf("\r\n");
		printf("\t\t");
		if (port->ipv6_list != NULL) {
			uint8_t *addr =
					((ipv6list_t *) (port->ipv6_list))->ipaddr;
			printf
					("IPv6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
					 addr[0], addr[1], addr[2], addr[3], addr[4],
					 addr[5], addr[6], addr[7], addr[8], addr[9],
					 addr[10], addr[11], addr[12], addr[13], addr[14],
					 addr[15]);
		} else {
			printf("IPv6: NA");
		}

		if (port->flags & IFM_SLAVE) {
			printf("  IFM_SLAVE ");
			printf(" MasterPort: %u",
						 port->bond_config->bond_portid);
		}
		if (port->flags & IFM_MASTER) {
			printf("  IFM_MASTER ");
			printf("  Mode: %u", port->bond_config->mode);
			printf("  PrimaryPort: %u", port->bond_config->primary);
			printf("\n\r");
			printf("\t\tSlavePortCount: %u",
						 port->bond_config->slave_count);
			printf(" SlavePorts:");
			int i;
			for (i = 0; i < port->bond_config->slave_count; i++) {
				printf(" %u ", port->bond_config->slaves[i]);
			}
			printf(" ActivePortCount: %u",
						 port->bond_config->active_slave_count);
			printf(" ActivePorts:");
			for (i = 0; i < port->bond_config->active_slave_count;
					 i++) {
				printf(" %u ",
							 port->bond_config->active_slaves[i]);
			}
			printf("\n\r");
			printf("\t\t");
			printf("Link_monitor_freq: %u ms ",
						 port->bond_config->internal_ms);
			printf(" Link_up_prop_delay: %u ms ",
						 port->bond_config->link_up_delay_ms);
			printf(" Link_down_prop_delay: %u ms ",
						 port->bond_config->link_down_delay_ms);
			printf("\n\r");
			printf("\t\t");
			printf("Xmit_policy: %u",
						 port->bond_config->xmit_policy);
		}
		printf("\n\r");
		printf("\t\t");
		printf("n_rxpkts: %" PRIu64 " ,n_txpkts: %" PRIu64 " ,",
					 port->n_rxpkts, port->n_txpkts);
		struct rte_eth_stats eth_stats;
		rte_eth_stats_get(port->pmdid, &eth_stats);
		printf("pkts_in: %" PRIu64 " ,", eth_stats.ipackets);
		printf("pkts_out: %" PRIu64 " ", eth_stats.opackets);
		printf("\n\r");
		printf("\t\t");
		printf("in_errs: %" PRIu64 " ,", eth_stats.ierrors);
		printf("in_missed: %" PRIu64 " ,", eth_stats.imissed);
		printf("out_errs: %" PRIu64 " ,", eth_stats.oerrors);
		printf("mbuf_errs: %" PRIu64 " ", eth_stats.rx_nombuf);
		printf("\n\r");
		printf("\n\r");
	}
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing RW lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_read_unlock(&rwlock);
}
