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
#include "tsx.h"
extern interface_main_t ifm;
extern uint8_t ifm_debug;
extern int USE_RTM_LOCKS;
extern rte_rwlock_t rwlock;

int ifm_bond_port_create(const char *name, int mode, port_config_t * portconf)
{
	int port_id;
	l2_phy_interface_t *bond_port;
	if (ifm_debug && IFM_DEBUG_CONFIG)
		RTE_LOG(INFO, IFM, "%s: i/p name %p, mode %d\n\r", __FUNCTION__,
			name, mode);
	if (name == NULL) {
		RTE_LOG(ERR, IFM, "%s: Param name cannot be NULL\n\r",
			__FUNCTION__);
		return IFM_FAILURE;
	}
	if (mode < 0 || mode > 6) {
		RTE_LOG(ERR, IFM, "%s: Param mode should be withing 0 to 6\n\r",
			__FUNCTION__);
		return IFM_FAILURE;
	}
	if (portconf == NULL) {
		RTE_LOG(ERR, IFM, "%s: Param portconf cannot be NULL\n\r",
			__FUNCTION__);
		return IFM_FAILURE;
	}
	bond_port = ifm_get_port_by_name(name);
	if (bond_port == NULL) {
		if (ifm_debug && IFM_DEBUG_CONFIG)
			RTE_LOG(INFO, IFM, "Call ifm_port_setup %s\n\r", name);
		port_id = rte_eth_bond_create(name, mode, 0);
		if (port_id < 0) {
			RTE_LOG(ERR, IFM,
				"%s: Failed to create bond port %s with mode %u\n\r",
				__FUNCTION__, name, mode);
			return IFM_FAILURE;
		}
		RTE_LOG(INFO, IFM,
			"%s: Created bond port %s(%u) on socket %u with "
			"mode %u.\n\r", __FUNCTION__, name, port_id,
			rte_eth_dev_socket_id(port_id), mode);

		bond_port = (l2_phy_interface_t *) rte_zmalloc(NULL,
										 sizeof
										 (l2_phy_interface_t),
										 RTE_CACHE_LINE_SIZE);
		bond_port->pmdid = port_id;
		strncpy(bond_port->ifname, name, IFM_IFNAME_LEN);
		memcpy(&bond_port->port_config, portconf,
					 sizeof(port_config_t));
		bond_port->flags |= IFM_MASTER;
		struct bond_port *bond_info;
		bond_info = (struct bond_port *)rte_zmalloc(NULL,
									sizeof(struct
									 bond_port),
									RTE_CACHE_LINE_SIZE);
		bond_info->socket_id = rte_eth_dev_socket_id(port_id);
		bond_info->mode = mode;
		bond_info->bond_portid = port_id;
		bond_port->bond_config = bond_info;
		if (mode == IFM_BONDING_MODE_8023AD)
			bond_port->tx_buf_len =
					(2 * RTE_ETH_TX_BUFFER_SIZE(IFM_BURST_SIZE)) *
					RTE_MAX_ETHPORTS;
		//ifm_add_port_to_port_list(bond_port);
		ifm.port_list[port_id] = bond_port;
		if (ifm_debug && IFM_DEBUG_CONFIG)
			RTE_LOG(INFO, IFM,
				"%s: Added bond port %s(%u) to port list\n\r",
				__FUNCTION__, name, port_id);
	} else {
		RTE_LOG(INFO, IFM, "%s: Port %s already exists in the"
			" port list\n\r", __FUNCTION__, name);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Acquiring lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_lock();
		else
			rte_rwlock_write_lock(&rwlock);

		if (!(bond_port->flags & IFM_MASTER)) {
			RTE_LOG(ERR, IFM, "%s: Previously port %s was not "
				"configured as Bond port\n\r", __FUNCTION__,
				name);
			if (ifm_debug & IFM_DEBUG_LOCKS)
				RTE_LOG(INFO, IFM,
					"%s: Releasing lock @ %d\n\r",
					__FUNCTION__, __LINE__);
			if (USE_RTM_LOCKS)
				rtm_unlock();
			else
				rte_rwlock_write_unlock(&rwlock);
			return IFM_FAILURE;
		}
		if (bond_port->bond_config->mode != mode) {
			if (rte_eth_bond_mode_set(bond_port->pmdid, mode) < 0) {
				RTE_LOG(ERR, IFM, "%s: rte_eth_bond_mode_set "
					"failed\n\r", __FUNCTION__);
				if (ifm_debug & IFM_DEBUG_LOCKS)
					RTE_LOG(INFO, IFM,
						"%s: Releasing lock @ %d\n\r",
						__FUNCTION__, __LINE__);
				if (USE_RTM_LOCKS)
					rtm_unlock();
				else
					rte_rwlock_write_unlock(&rwlock);
				return IFM_FAILURE;
			}

			bond_port->bond_config->mode =
					rte_eth_bond_mode_get(bond_port->pmdid);
			/* xmit policy may change for based on mode */
			bond_port->bond_config->xmit_policy =
					rte_eth_bond_xmit_policy_get(bond_port->pmdid);
			if (ifm_debug && IFM_DEBUG_CONFIG)
				RTE_LOG(INFO, IFM,
					"%s: Bond port %u mode is updated. Mode %u xmit_policy %u."
					"\n\r", __FUNCTION__, bond_port->pmdid,
					bond_port->bond_config->mode,
					bond_port->bond_config->xmit_policy);
		}
		port_id = bond_port->pmdid;
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Acquiring lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
	}
	return port_id;
}

int ifm_bond_port_delete(const char *name)
{
	l2_phy_interface_t *bond_port;
	if (name == NULL) {
		RTE_LOG(ERR, IFM, "%s: Param name cannot be NULL\n\r",
			__FUNCTION__);
		return IFM_FAILURE;
	}
	bond_port = ifm_get_port_by_name(name);
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_write_lock(&rwlock);
	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port with name %s not"
			" found in the list\n\r", __FUNCTION__, name);
		return IFM_FAILURE;
	}
	if (!(bond_port->flags & IFM_MASTER)) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %s is not "
			"configured is not bond port\n\r", __FUNCTION__, name);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	if (bond_port->bond_config && bond_port->bond_config->slave_count > 0) {
		RTE_LOG(ERR, IFM, "%s: First unbind all slave "
			"ports from the bond port %s\n\r", __FUNCTION__, name);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	int ret;
	ret = rte_eth_bond_free(name);
	if (ret < 0) {
		RTE_LOG(ERR, IFM, "%s: Failed to delete "
			"bond port %s\n\r", __FUNCTION__, name);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	if (ifm_debug & IFM_DEBUG_CONFIG)
		RTE_LOG(INFO, IFM, "%s: Bond port %s deleted successfully\n\r",
			__FUNCTION__, name);

	if (bond_port && bond_port->bond_config != NULL) {
		rte_free(bond_port->bond_config);
		bond_port->bond_config = NULL;
	}
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_write_unlock(&rwlock);
	ifm_remove_port_details(bond_port->pmdid);
	//ifm.port_list[bond_port->pmdid] = NULL;
	return IFM_SUCCESS;
}

int ifm_add_slave_port(uint8_t bonded_port_id, uint8_t slave_port_id)
{
	l2_phy_interface_t *bond_port, *slave_port;
	bond_port = ifm_get_port(bonded_port_id);
	//   bond_port = ifm.port_list[bonded_port_id];
	slave_port = ifm_get_port(slave_port_id);
	// slave_port = ifm.port_list[slave_port_id];
	if (ifm_debug & IFM_DEBUG)
		RTE_LOG(INFO, IFM, "%s: i/p bond id %u, slave id %u\n\r",
			__FUNCTION__, bonded_port_id, slave_port_id);
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_write_lock(&rwlock);
	}
	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	if (slave_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given slave port %u is not available in "
			"port list.\n\r", __FUNCTION__, slave_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	if (bond_port && !(bond_port->flags & IFM_MASTER)) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not configured "
			"as Master port. %u\n\r", __FUNCTION__, bonded_port_id,
			bond_port->flags & IFM_MASTER);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	if (bond_port && bond_port->bond_config
			&& bond_port->bond_config->slave_count == RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, IFM,
			"%s: Failed to bind.Already %u ports are bonded to master port...\n\r ",
			__FUNCTION__, RTE_MAX_ETHPORTS);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	if (slave_port && slave_port->flags & IFM_SLAVE) {
		/* Have to check whether the port is already part of someother bond port */
		if (slave_port->bond_config != NULL) {
			if (bonded_port_id !=
					slave_port->bond_config->bond_portid) {
				RTE_LOG(ERR, IFM,
					"%s: Slave port %u is already part"
					" of other bond port %u.\n\r",
					__FUNCTION__, slave_port_id,
					slave_port->bond_config->bond_portid);
				if (ifm_debug & IFM_DEBUG_LOCKS)
					RTE_LOG(INFO, IFM,
						"%s: Releasing WR lock @ %d\n\r",
						__FUNCTION__, __LINE__);
				if (USE_RTM_LOCKS) {
					rtm_unlock();
				} else {
					rte_rwlock_write_unlock(&rwlock);
				}
				return IFM_FAILURE;
			} else {
				if (ifm_debug & IFM_DEBUG)
					RTE_LOG(INFO, IFM,
						"%s: Slave port %u is already bounded to %u\n\r",
						__FUNCTION__, slave_port_id,
						bonded_port_id);
				if (ifm_debug & IFM_DEBUG_LOCKS)
					RTE_LOG(INFO, IFM,
						"%s: Releasing WR lock @ %d\n\r",
						__FUNCTION__, __LINE__);
				if (USE_RTM_LOCKS) {
					rtm_unlock();
				} else {
					rte_rwlock_write_unlock(&rwlock);
				}
				return IFM_SUCCESS;
			}
		}
	}
	if (bond_port->bond_config && bond_port->bond_config->slave_count &&
			bond_port->link_speed != slave_port->link_speed
			&& bond_port->link_duplex != slave_port->link_duplex) {
		RTE_LOG(ERR, IFM,
			"%s: Error in adding slave port to bond port. Reason speed mismatch\n\r",
			__FUNCTION__);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	if (ifm_debug & IFM_DEBUG)
		RTE_LOG(INFO, IFM, "%s: Slave port %u Master port %u\n\r",
			__FUNCTION__, slave_port_id, bonded_port_id);
	int ret;
	ret = rte_eth_bond_slave_add(bond_port->pmdid, slave_port->pmdid);
	if (ret < 0) {
		RTE_LOG(ERR, IFM, "%s: Failed to add slave port %u to bond "
			"port %u.\n\r", __FUNCTION__, slave_port->pmdid,
			bond_port->pmdid);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	slave_port->flags |= IFM_SLAVE;
	/* Populate bond config information */
	if (bond_port->bond_config) {
		bond_port->bond_config->xmit_policy =
				rte_eth_bond_xmit_policy_get(bond_port->pmdid);
		bond_port->bond_config->internal_ms =
				rte_eth_bond_link_monitoring_get(bond_port->pmdid);
		bond_port->bond_config->link_up_delay_ms =
				rte_eth_bond_link_up_prop_delay_get(bond_port->pmdid);
		bond_port->bond_config->link_down_delay_ms =
				rte_eth_bond_link_down_prop_delay_get(bond_port->pmdid);
		bond_port->bond_config->primary =
				rte_eth_bond_primary_get(bond_port->pmdid);
		bond_port->bond_config->slave_count =
				rte_eth_bond_slaves_get(bond_port->pmdid,
							bond_port->bond_config->slaves,
							RTE_MAX_ETHPORTS);
		bond_port->bond_config->active_slave_count =
				rte_eth_bond_active_slaves_get(bond_port->pmdid,
							 bond_port->bond_config->
							 active_slaves,
							 RTE_MAX_ETHPORTS);
		slave_port->bond_config = bond_port->bond_config;
		if (ifm_debug & IFM_DEBUG)
			RTE_LOG(INFO, IFM, "%s: Slave count is %u\n\r",
				__FUNCTION__,
				bond_port->bond_config->slave_count);
		if (bond_port->bond_config->slave_count == 1) {
			ret =
					ifm_port_setup(bond_port->pmdid,
						 &(bond_port->port_config));
			if (ret < 0) {
				RTE_LOG(ERR, IFM,
					"%s: Failed to start bond port %u.\n\r",
					__FUNCTION__, bond_port->pmdid);
				if (ifm_debug & IFM_DEBUG_LOCKS)
					RTE_LOG(INFO, IFM,
						"%s: Releasing WR lock @ %d\n\r",
						__FUNCTION__, __LINE__);
				if (USE_RTM_LOCKS) {
					rtm_unlock();
				} else {
					rte_rwlock_write_unlock(&rwlock);
				}
				return IFM_FAILURE;
			}
		} else {
			if (ifm_debug & IFM_DEBUG)
				RTE_LOG(INFO, IFM, "%s: Skipping"
					" port setup\n\r", __FUNCTION__);
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
	return IFM_SUCCESS;
}

int ifm_remove_slave_port(uint8_t bonded_port_id, uint8_t slave_port_id)
{
	l2_phy_interface_t *bond_port, *slave_port;

	bond_port = ifm_get_port(bonded_port_id);
	//bond_port = ifm.port_list[bonded_port_id];
	slave_port = ifm_get_port(slave_port_id);
	//slave_port = ifm.port_list[slave_port_id];

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_write_lock(&rwlock);
	}
	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available "
			"in port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_FAILURE;
	}
	if (slave_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given slave port %u is not available "
			"in port list.\n\r", __FUNCTION__, slave_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_FAILURE;
	}
	if (bond_port && !(bond_port->flags & IFM_MASTER)) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not configured "
			"as Master port.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_FAILURE;
	}
	if (slave_port && !(slave_port->flags & IFM_SLAVE)) {
		RTE_LOG(ERR, IFM, "%s: Given slave port %u is not configured"
			" as slave port.\n\r", __FUNCTION__, slave_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_FAILURE;
	}
	int i;
	int found = 0;
	for (i = 0; i < bond_port->bond_config->slave_count; i++) {
		if (slave_port_id == bond_port->bond_config->slaves[i]) {
			found = 1;
			break;
		}
	}
	if (!found) {
		RTE_LOG(ERR, IFM, "%s: Given slave port %u is not binded "
			"with bond port %u\n\r", __FUNCTION__, slave_port_id,
			bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_FAILURE;
	}
	if (rte_eth_bond_slave_remove(bonded_port_id, slave_port_id) < 0) {
		RTE_LOG(ERR, IFM, "%s: Failed to unbind slave port %u"
			" from bond port %u\n\r", __FUNCTION__, slave_port_id,
			bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_FAILURE;
	}
	slave_port->flags &= ~IFM_SLAVE;
	slave_port->bond_config = NULL;
	bond_port->bond_config->primary =
			rte_eth_bond_primary_get(bond_port->pmdid);
	bond_port->bond_config->slave_count =
			rte_eth_bond_slaves_get(bond_port->pmdid,
						bond_port->bond_config->slaves,
						RTE_MAX_ETHPORTS);
	bond_port->bond_config->active_slave_count =
			rte_eth_bond_active_slaves_get(bond_port->pmdid,
						 bond_port->bond_config->
						 active_slaves, RTE_MAX_ETHPORTS);

	if (ifm_debug & IFM_DEBUG)
		RTE_LOG(ERR, IFM, "%s: Unbinded slave port %u from the bond "
			"port %u %d\n\r", __FUNCTION__, slave_port_id,
			bonded_port_id,
			rte_eth_bond_primary_get(bond_port->pmdid));
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_write_unlock(&rwlock);
	return IFM_SUCCESS;
}

int set_bond_mode(uint8_t bonded_port_id, uint8_t mode)
{
	l2_phy_interface_t *bond_port;
	bond_port = ifm_get_port(bonded_port_id);
	//bond_port = ifm.port_list[bonded_port_id];

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_write_lock(&rwlock);
	if(bond_port)
	ifm_remove_port_details(bond_port->pmdid);
	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		return IFM_FAILURE;
	}
	if (bond_port && bond_port->bond_config->mode == mode) {
		if (ifm_debug & IFM_DEBUG)
			RTE_LOG(INFO, IFM,
				"%s: Already bond port is set with the given"
				" mode %u\n\r.", __FUNCTION__, mode);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		ifm_remove_port_details(bond_port->pmdid);
		return IFM_SUCCESS;

	}
	if (rte_eth_bond_mode_set(bond_port->pmdid, mode) < 0) {
		RTE_LOG(ERR, IFM,
			"%s: Failed to set bond mode %u for port id %u\n\r.",
			__FUNCTION__, mode, bond_port->pmdid);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		ifm_remove_port_details(bond_port->pmdid);
		return IFM_FAILURE;
	}

	bond_port->bond_config->mode = rte_eth_bond_mode_get(bond_port->pmdid);
	/* xmit policy may change for based on mode */
	bond_port->bond_config->xmit_policy =
			rte_eth_bond_xmit_policy_get(bond_port->pmdid);
	if (ifm_debug & IFM_DEBUG)
		RTE_LOG(INFO, IFM,
			"%s: Bond port %u mode is updated. Mode %u xmit_policy %u."
			"\n\r.", __FUNCTION__, bond_port->pmdid,
			bond_port->bond_config->mode,
			bond_port->bond_config->xmit_policy);
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_write_unlock(&rwlock);
	ifm_remove_port_details(bond_port->pmdid);
	return IFM_SUCCESS;
}

int get_bond_mode(uint8_t bonded_port_id)
{
	l2_phy_interface_t *bond_port;
	bond_port = ifm_get_port(bonded_port_id);
	//bond_port = ifm.port_list[bonded_port_id];

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_read_lock(&rwlock);
	}
	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_read_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	uint8_t mode = bond_port->bond_config->mode;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_read_unlock(&rwlock);
	}
	return mode;
}

int set_bond_primary(uint8_t bonded_port_id, uint8_t slave_port_id)
{
	l2_phy_interface_t *bond_port;
	l2_phy_interface_t *slave_port;
	bond_port = ifm_get_port(bonded_port_id);
	//  bond_port = ifm.port_list[bonded_port_id];
	slave_port = ifm_get_port(slave_port_id);
	//  slave_port = ifm.port_list[slave_port_id];

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_write_lock(&rwlock);
	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_FAILURE;
	}
	if (slave_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given slave port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_FAILURE;
	}
	int i;
	int found = 0;
	for (i = 0; i < bond_port->bond_config->slave_count; i++) {
		if (slave_port_id == bond_port->bond_config->slaves[i]) {
			found = 1;
			break;
		}
	}
	if (!found) {
		RTE_LOG(ERR, IFM, "%s: Slave port %u is not binded "
			"with bond port %u. Slave port should be binded first\n\r",
			__FUNCTION__, slave_port_id, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_FAILURE;
	}

	if (bond_port->bond_config->primary == slave_port_id) {
		if (ifm_debug & IFM_DEBUG)
			RTE_LOG(INFO, IFM,
				"%s: Already slave port %u is primary for bond port"
				"%u\n\r.", __FUNCTION__, bonded_port_id,
				slave_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_SUCCESS;

	}
	if (rte_eth_bond_primary_set(bond_port->pmdid, slave_port->pmdid) < 0) {
		RTE_LOG(ERR, IFM,
			"%s:Failed to set slave %u as primary for bond port %u\n\r.",
			__FUNCTION__, slave_port->pmdid, bond_port->pmdid);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_FAILURE;
	}

	bond_port->bond_config->primary =
			rte_eth_bond_primary_get(bond_port->pmdid);
	if (ifm_debug & IFM_DEBUG)
		RTE_LOG(INFO, IFM,
			"%s: Primary port is updated as %u for bond port %u",
			__FUNCTION__, bond_port->bond_config->primary,
			bond_port->pmdid);
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_write_unlock(&rwlock);
	return IFM_SUCCESS;
}

int get_bond_primary_port(uint8_t bonded_port_id)
{
	l2_phy_interface_t *bond_port;
	bond_port = ifm_get_port(bonded_port_id);
	//bond_port = ifm.port_list[bonded_port_id];

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_read_lock(&rwlock);
	}
	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_read_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	uint8_t primary = bond_port->bond_config->primary;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_read_unlock(&rwlock);
	}
	return primary;
}

int get_bond_slave_count(uint8_t bonded_port_id)
{
	l2_phy_interface_t *bond_port;
	bond_port = ifm_get_port(bonded_port_id);
	// bond_port = ifm.port_list[bonded_port_id];

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_read_lock(&rwlock);
	}
	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_read_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	uint32_t slave_count = bond_port->bond_config->slave_count;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_read_unlock(&rwlock);
	}
	return slave_count;
}

int get_bond_active_slave_count(uint8_t bonded_port_id)
{
	l2_phy_interface_t *bond_port;
	bond_port = ifm_get_port(bonded_port_id);
	//bond_port = ifm.port_list[bonded_port_id];

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_read_lock(&rwlock);
	}
	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_read_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	uint32_t slave_count = bond_port->bond_config->active_slave_count;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_read_unlock(&rwlock);
	}
	return slave_count;
}

int get_bond_slaves(uint8_t bonded_port_id, uint8_t slaves[RTE_MAX_ETHPORTS])
{
	l2_phy_interface_t *bond_port;
	bond_port = ifm_get_port(bonded_port_id);
	//bond_port = ifm.port_list[bonded_port_id];

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_read_lock(&rwlock);
	}
	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		return IFM_FAILURE;
	}
	memcpy(slaves, bond_port->bond_config->slaves,
				 bond_port->bond_config->slave_count);
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_read_unlock(&rwlock);
	}
	return IFM_SUCCESS;
}

int get_bond_active_slaves(uint8_t bonded_port_id,
				 uint8_t active_slaves[RTE_MAX_ETHPORTS])
{
	l2_phy_interface_t *bond_port;
	bond_port = ifm_get_port(bonded_port_id);
	//bond_port = ifm.port_list[bonded_port_id];

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_read_lock(&rwlock);
	}
	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		return IFM_FAILURE;
	}
	memcpy(active_slaves, bond_port->bond_config->active_slaves,
				 bond_port->bond_config->active_slave_count);
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_read_unlock(&rwlock);
	}
	return IFM_SUCCESS;
}

int set_bond_mac_address(uint8_t bonded_port_id, struct ether_addr *mac_addr)
{
	l2_phy_interface_t *bond_port;
	bond_port = ifm_get_port(bonded_port_id);
	//bond_port = ifm.port_list[bonded_port_id];

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_write_lock(&rwlock);
	}
	if (mac_addr == NULL) {
		RTE_LOG(ERR, IFM, "%s: MAC address cannot be NULL.\n\r",
			__FUNCTION__);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}

	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	if (rte_eth_bond_mac_address_set(bond_port->pmdid, mac_addr) < 0) {
		RTE_LOG(ERR, IFM, "%s: Failed to set MAC addr for port %u\n\r",
			__FUNCTION__, bond_port->pmdid);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	rte_eth_macaddr_get(bond_port->pmdid,
					(struct ether_addr *)bond_port->macaddr);
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_write_unlock(&rwlock);
	}
	return IFM_SUCCESS;
}

int reset_bond_mac_addr(uint8_t bonded_port_id)
{
	l2_phy_interface_t *bond_port;
	bond_port = ifm_get_port(bonded_port_id);
	//   bond_port = ifm.port_list[bonded_port_id];

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_write_lock(&rwlock);
	}
	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	if (rte_eth_bond_mac_address_reset(bond_port->pmdid) < 0) {
		RTE_LOG(ERR, IFM,
			"%s: Failed to reset MAC addr for port %u\n\r",
			__FUNCTION__, bond_port->pmdid);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	rte_eth_macaddr_get(bond_port->pmdid,
					(struct ether_addr *)bond_port->macaddr);
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_write_unlock(&rwlock);
	}
	return IFM_FAILURE;
}

int set_bond_xmitpolicy(uint8_t bonded_port_id, uint8_t policy)
{

	l2_phy_interface_t *bond_port;
	bond_port = ifm_get_port(bonded_port_id);
	//bond_port = ifm.port_list[bonded_port_id];
	int ret = 0;

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_write_lock(&rwlock);
	}
	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	if (bond_port->bond_config->xmit_policy == policy) {
		if (ifm_debug & IFM_DEBUG)
			RTE_LOG(INFO, IFM,
				"%s: For port %u, old policy value and new value are same\n\r",
				__FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_SUCCESS;
	}
	if (rte_eth_bond_xmit_policy_set(bond_port->pmdid, policy) < 0) {
		RTE_LOG(ERR, IFM, "%s: Failed to set policy for port %u\n\r",
			__FUNCTION__, bond_port->pmdid);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	ret = rte_eth_bond_xmit_policy_get(bond_port->pmdid);
	if (ret < 0) {
		if (ifm_debug & IFM_DEBUG)
			RTE_LOG(INFO, IFM,
				"%s: rte_eth_bond_xmit_policy_set failed\n\r",
				__FUNCTION__);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	bond_port->bond_config->xmit_policy = policy;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_write_unlock(&rwlock);
	}
	return IFM_SUCCESS;
}

int get_bond_xmitpolicy(uint8_t bonded_port_id)
{
	l2_phy_interface_t *bond_port;

	bond_port = ifm_get_port(bonded_port_id);

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: RD Acquiring lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_read_lock(&rwlock);
	}
	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s:Releasing RD lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_read_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	uint8_t policy = bond_port->bond_config->xmit_policy;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s:Releasing RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_read_unlock(&rwlock);
	}
	return policy;
}

int set_bond_link_montitor_frequency(uint8_t bonded_port_id,
						 uint32_t internal_ms)
{
	l2_phy_interface_t *bond_port;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_write_lock(&rwlock);
	}
//      bond_port = ifm.port_list[bonded_port_id];
	bond_port = ifm_get_port(bonded_port_id);
	int ret = 0;

	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	if (bond_port->bond_config->internal_ms == internal_ms) {
		if (ifm_debug & IFM_DEBUG)
			RTE_LOG(INFO, IFM,
				"%s: For port %u, old frequency value and new value are same\n\r",
				__FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_SUCCESS;
	}
	if (rte_eth_bond_link_monitoring_set(bond_port->pmdid, internal_ms) < 0) {
		RTE_LOG(ERR, IFM,
			"%s: Failed to set link monitor frequency for port %u\n\r",
			__FUNCTION__, bond_port->pmdid);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	ret = rte_eth_bond_link_monitoring_get(bond_port->pmdid);
	if (ret < 0) {
		if (ifm_debug & IFM_DEBUG)
			RTE_LOG(INFO, IFM,
				"%s: rte_eth_bond_link_monitoring_get failed\n\r",
				__FUNCTION__);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	bond_port->bond_config->internal_ms = internal_ms;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_write_unlock(&rwlock);
	}
	return IFM_SUCCESS;
}

int get_bond_link_monitor_frequency(uint8_t bonded_port_id)
{
	l2_phy_interface_t *bond_port;
//      bond_port = ifm.port_list[bonded_port_id];
	bond_port = ifm_get_port(bonded_port_id);

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s:  Acquiring RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_read_lock(&rwlock);
	}
	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_read_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	uint32_t internal_ms = bond_port->bond_config->internal_ms;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_read_unlock(&rwlock);
	}
	return internal_ms;
}

int set_bond_linkdown_delay(uint8_t bonded_port_id, uint32_t delay_ms)
{
	l2_phy_interface_t *bond_port;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);

	if (USE_RTM_LOCKS) {
		rtm_lock();
	} else {
		rte_rwlock_write_lock(&rwlock);
	}
//      bond_port = ifm.port_list[bonded_port_id];
	bond_port = ifm_get_port(bonded_port_id);
	int delay = 0;

	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);

		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	if (bond_port->bond_config->link_down_delay_ms == delay_ms) {
		if (ifm_debug & IFM_DEBUG)
			RTE_LOG(INFO, IFM,
				"%s: For port %u, old delay value and new value are same\n\r",
				__FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);

		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_SUCCESS;
	}
	if (rte_eth_bond_link_down_prop_delay_set(bond_port->pmdid, delay_ms) <
			0) {
		RTE_LOG(ERR, IFM, "%s: Failed to set delay for port %u\n\r",
			__FUNCTION__, bond_port->pmdid);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);

		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	delay = rte_eth_bond_link_down_prop_delay_get(bond_port->pmdid);
	if (delay < 0) {
		if (ifm_debug & IFM_DEBUG)
			RTE_LOG(INFO, IFM,
				"%s: rte_eth_bond_link_down_prop_delay_get failed\n\r",
				__FUNCTION__);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);

		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_write_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	bond_port->bond_config->link_down_delay_ms = delay;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);

	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_write_unlock(&rwlock);
	}
	return IFM_SUCCESS;
}

int get_bond_link_down_delay(uint8_t bonded_port_id)
{
	l2_phy_interface_t *bond_port;
	//bond_port = ifm.port_list[bonded_port_id];
	bond_port = ifm_get_port(bonded_port_id);
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_read_lock(&rwlock);

	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS) {
			rtm_unlock();
		} else {
			rte_rwlock_read_unlock(&rwlock);
		}
		return IFM_FAILURE;
	}
	uint32_t delay_ms = bond_port->bond_config->link_down_delay_ms;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS) {
		rtm_unlock();
	} else {
		rte_rwlock_read_unlock(&rwlock);
	}
	return delay_ms;

}

int set_bond_linkup_delay(uint8_t bonded_port_id, uint32_t delay_ms)
{
	l2_phy_interface_t *bond_port;
	int delay = 0;
	bond_port = ifm_get_port(bonded_port_id);

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_write_unlock(&rwlock);

	if (bond_port == NULL) {
		RTE_LOG(ERR, IFM, "%s: Given bond port %u is not available in"
			" port list.\n\r", __FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_FAILURE;
	}
	if (bond_port->bond_config->link_up_delay_ms == delay_ms) {
		if (ifm_debug & IFM_DEBUG)
			RTE_LOG(INFO, IFM,
				"%s: For port %u, old delay value and new value are same\n\r",
				__FUNCTION__, bonded_port_id);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_SUCCESS;
	}
	if (rte_eth_bond_link_up_prop_delay_set(bond_port->pmdid, delay_ms) < 0) {
		RTE_LOG(ERR, IFM, "%s: Failed to set delay for port %u\n\r",
			__FUNCTION__, bond_port->pmdid);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);

		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_FAILURE;
	}
	delay = rte_eth_bond_link_up_prop_delay_get(bond_port->pmdid);
	if (delay < 0) {
		RTE_LOG(INFO, IFM,
			"%s: rte_eth_bond_link_up_prop_delay_get failed\n\r",
			__FUNCTION__);
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
				__FUNCTION__, __LINE__);

		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_write_unlock(&rwlock);
		return IFM_FAILURE;
	}
	bond_port->bond_config->link_up_delay_ms = delay;
	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing WR lock @ %d\n\r",
			__FUNCTION__, __LINE__);

	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_write_unlock(&rwlock);
	return IFM_SUCCESS;
}

int get_bond_link_up_delay(uint8_t bonded_port_id)
{
	l2_phy_interface_t *bond_port;
	uint32_t delay_ms;

	bond_port = ifm_get_port(bonded_port_id);

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Acquiring RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_read_lock(&rwlock);
	if (bond_port == NULL) {
		if (ifm_debug & IFM_DEBUG) {
			RTE_LOG(ERR, IFM,
				"%s: Given bond port %u is not available in"
				" port list.\n\r", __FUNCTION__,
				bonded_port_id);
		}
		if (ifm_debug & IFM_DEBUG_LOCKS)
			RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
				__FUNCTION__, __LINE__);
		if (USE_RTM_LOCKS)
			rtm_unlock();
		else
			rte_rwlock_read_unlock(&rwlock);
		return IFM_FAILURE;
	}
	delay_ms = bond_port->bond_config->link_up_delay_ms;

	if (ifm_debug & IFM_DEBUG_LOCKS)
		RTE_LOG(INFO, IFM, "%s: Releasing RD lock @ %d\n\r",
			__FUNCTION__, __LINE__);
	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_read_unlock(&rwlock);
	return delay_ms;
}
