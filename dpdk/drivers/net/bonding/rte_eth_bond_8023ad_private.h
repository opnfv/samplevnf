/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef RTE_ETH_BOND_8023AD_PRIVATE_H_
#define RTE_ETH_BOND_8023AD_PRIVATE_H_

#include <stdint.h>

#include <rte_ether.h>
#include <rte_byteorder.h>
#include <rte_atomic.h>

#include "rte_eth_bond_8023ad.h"

#define BOND_MODE_8023AX_UPDATE_TIMEOUT_MS  100
/** Maximum number of packets to one slave queued in TX ring. */
#define BOND_MODE_8023AX_SLAVE_RX_PKTS        3
/** Maximum number of LACP packets from one slave queued in TX ring. */
#define BOND_MODE_8023AX_SLAVE_TX_PKTS        1
/**
 * Timeouts deffinitions (5.4.4 in 802.1AX documentation).
 */
#define BOND_8023AD_FAST_PERIODIC_MS                900
#define BOND_8023AD_SLOW_PERIODIC_MS              29000
#define BOND_8023AD_SHORT_TIMEOUT_MS               3000
#define BOND_8023AD_LONG_TIMEOUT_MS               90000
#define BOND_8023AD_CHURN_DETECTION_TIMEOUT_MS    60000
#define BOND_8023AD_AGGREGATE_WAIT_TIMEOUT_MS      2000
#define BOND_8023AD_TX_MACHINE_PERIOD_MS            500
#define BOND_8023AD_RX_MARKER_PERIOD_MS            2000

/**
 * Interval of showing warning message from state machines. All messages will
 * be held (and gathered together) to prevent flooding.
 * This is no parto of 802.1AX standard.
 */
#define BOND_8023AD_WARNINGS_PERIOD_MS             1000



/**
 * State machine flags
 */
#define SM_FLAGS_BEGIN                      0x0001
#define SM_FLAGS_LACP_ENABLED               0x0002
#define SM_FLAGS_ACTOR_CHURN                0x0004
#define SM_FLAGS_PARTNER_CHURN              0x0008
#define SM_FLAGS_MOVED                      0x0100
#define SM_FLAGS_PARTNER_SHORT_TIMEOUT      0x0200
#define SM_FLAGS_NTT                        0x0400

#define BOND_LINK_FULL_DUPLEX_KEY           0x01
#define BOND_LINK_SPEED_KEY_10M             0x02
#define BOND_LINK_SPEED_KEY_100M            0x04
#define BOND_LINK_SPEED_KEY_1000M           0x08
#define BOND_LINK_SPEED_KEY_10G             0x10
#define BOND_LINK_SPEED_KEY_20G             0x11
#define BOND_LINK_SPEED_KEY_40G             0x12

#define WRN_RX_MARKER_TO_FAST      0x01
#define WRN_UNKNOWN_SLOW_TYPE      0x02
#define WRN_UNKNOWN_MARKER_TYPE    0x04
#define WRN_NOT_LACP_CAPABLE       0x08
#define WRN_RX_QUEUE_FULL       0x10
#define WRN_TX_QUEUE_FULL       0x20

#define CHECK_FLAGS(_variable, _f) ((_variable) & (_f))
#define SET_FLAGS(_variable, _f) ((_variable) |= (_f))
#define CLEAR_FLAGS(_variable, _f) ((_variable) &= ~(_f))

#define SM_FLAG(_p, _f) (!!CHECK_FLAGS((_p)->sm_flags, SM_FLAGS_ ## _f))
#define SM_FLAG_SET(_p, _f) SET_FLAGS((_p)->sm_flags, SM_FLAGS_ ## _f)
#define SM_FLAG_CLR(_p, _f) CLEAR_FLAGS((_p)->sm_flags, SM_FLAGS_ ## _f)

#define ACTOR_STATE(_p, _f) (!!CHECK_FLAGS((_p)->actor_state, STATE_ ## _f))
#define ACTOR_STATE_SET(_p, _f) SET_FLAGS((_p)->actor_state, STATE_ ## _f)
#define ACTOR_STATE_CLR(_p, _f) CLEAR_FLAGS((_p)->actor_state, STATE_ ## _f)

#define PARTNER_STATE(_p, _f) (!!CHECK_FLAGS((_p)->partner_state, STATE_ ## _f))
#define PARTNER_STATE_SET(_p, _f) SET_FLAGS((_p)->partner_state, STATE_ ## _f)
#define PARTNER_STATE_CLR(_p, _f) CLEAR_FLAGS((_p)->partner_state, STATE_ ## _f)

/** Variables associated with each port (5.4.7 in 802.1AX documentation). */
struct port {
	/**
	 * The operational values of the Actor's state parameters. Bitmask
	 * of port states.
	 */
	uint8_t actor_state;

	/** The operational Actor's port parameters */
	struct port_params actor;

	/**
	 * The operational value of the Actor's view of the current values of
	 * the Partner's state parameters. The Actor sets this variable either
	 * to the value received from the Partner in an LACPDU, or to the value
	 * of Partner_Admin_Port_State. Bitmask of port states.
	 */
	uint8_t partner_state;

	/** The operational Partner's port parameters */
	struct port_params partner;

	/* Additional port parameters not listed in documentation */
	/** State machine flags */
	uint16_t sm_flags;
	enum rte_bond_8023ad_selection selected;

	uint64_t current_while_timer;
	uint64_t periodic_timer;
	uint64_t wait_while_timer;
	uint64_t tx_machine_timer;
	uint64_t tx_marker_timer;
	/* Agregator parameters */
	/** Used aggregator port ID */
	uint16_t aggregator_port_id;

	/** Memory pool used to allocate rings */
	struct rte_mempool *mbuf_pool;

	/** Ring of LACP packets from RX burst function */
	struct rte_ring *rx_ring;

	/** Ring of slow protocol packets (LACP and MARKERS) to TX burst function */
	struct rte_ring *tx_ring;

	/** Timer which is also used as mutex. If is 0 (not running) RX marker
	 * packet might be responded. Otherwise shall be dropped. It is zeroed in
	 * mode 4 callback function after expire. */
	volatile uint64_t rx_marker_timer;

	uint64_t warning_timer;
	volatile uint16_t warnings_to_show;
};

struct mode8023ad_private {
	uint64_t fast_periodic_timeout;
	uint64_t slow_periodic_timeout;
	uint64_t short_timeout;
	uint64_t long_timeout;
	uint64_t aggregate_wait_timeout;
	uint64_t tx_period_timeout;
	uint64_t rx_marker_timeout;
	uint64_t update_timeout_us;
};

/**
 * @internal
 * The pool of *port* structures. The size of the pool
 * is configured at compile-time in the <rte_eth_bond_8023ad.c> file.
 */
extern struct port mode_8023ad_ports[];

/* Forward declaration */
struct bond_dev_private;

/**
 * @internal
 *
 * Get configuration of bonded interface.
 *
 *
 * @param dev Bonded interface
 * @param conf returned configuration
 */
void
bond_mode_8023ad_conf_get(struct rte_eth_dev *dev,
		struct rte_eth_bond_8023ad_conf *conf);

/**
 * @internal
 *
 * Set mode 4 configuration of bonded interface.
 *
 * @pre Bonded interface must be stopped.
 *
 * @param dev Bonded interface
 * @param conf new configuration. If NULL set default configuration.
 */
void
bond_mode_8023ad_setup(struct rte_eth_dev *dev,
		struct rte_eth_bond_8023ad_conf *conf);

/**
 * @internal
 *
 * Enables 802.1AX mode and all active slaves on bonded interface.
 *
 * @param dev Bonded interface
 * @return
 *  0 on success, negative value otherwise.
 */
int
bond_mode_8023ad_enable(struct rte_eth_dev *dev);

/**
 * @internal
 *
 * Disables 802.1AX mode of the bonded interface and slaves.
 *
 * @param dev Bonded interface
 * @return
 *   0 on success, negative value otherwise.
 */
int bond_mode_8023ad_disable(struct rte_eth_dev *dev);

/**
 * @internal
 *
 * Starts 802.3AX state machines management logic.
 * @param dev Bonded interface
 * @return
 *   0 if machines was started, 1 if machines was already running,
 *   negative value otherwise.
 */
int
bond_mode_8023ad_start(struct rte_eth_dev *dev);

/**
 * @internal
 *
 * Stops 802.3AX state machines management logic.
 * @param dev Bonded interface
 * @return
 *   0 if this call stopped state machines, -ENOENT if alarm was not set.
 */
void
bond_mode_8023ad_stop(struct rte_eth_dev *dev);

/**
 * @internal
 *
 * Passes given slow packet to state machines management logic.
 * @param internals Bonded device private data.
 * @param slave_id Slave port id.
 * @param slot_pkt Slow packet.
 */
void
bond_mode_8023ad_handle_slow_pkt(struct bond_dev_private *internals,
	uint8_t slave_id, struct rte_mbuf *pkt);

/**
 * @internal
 *
 * Appends given slave used slave
 *
 * @param dev       Bonded interface.
 * @param port_id   Slave port ID to be added
 *
 * @return
 *  0 on success, negative value otherwise.
 */
void
bond_mode_8023ad_activate_slave(struct rte_eth_dev *dev, uint8_t port_id);

/**
 * @internal
 *
 * Denitializes and removes given slave from 802.1AX mode.
 *
 * @param dev       Bonded interface.
 * @param slave_num Position of slave in active_slaves array
 *
 * @return
 *  0 on success, negative value otherwise.
 */
int
bond_mode_8023ad_deactivate_slave(struct rte_eth_dev *dev, uint8_t slave_pos);

/**
 * Updates state when MAC was changed on bonded device or one of its slaves.
 * @param bond_dev Bonded device
 */
void
bond_mode_8023ad_mac_address_update(struct rte_eth_dev *bond_dev);

#endif /* RTE_ETH_BOND_8023AD_H_ */
