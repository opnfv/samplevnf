/*
// Copyright (c) 2010-2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include <string.h>
#include <stdio.h>

#include <rte_version.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>

#include "prox_malloc.h"
#include "log.h"
#include "quit.h"
#include "stats_port.h"
#include "prox_port_cfg.h"
#include "rw_reg.h"
#include "prox_compat.h"

#if defined(PROX_STATS) && defined(PROX_HW_DIRECT_STATS)

/* Directly access hardware counters instead of going through DPDK. This allows getting
 * specific counters that DPDK does not report or aggregates with other ones.
 */

/* Definitions for IXGBE (taken from PMD) */
#define PROX_IXGBE_MPC(_i)           (0x03FA0 + ((_i) * 4)) /* 8 of these 3FA0-3FBC*/
#define PROX_IXGBE_QBRC_L(_i)        (0x01034 + ((_i) * 0x40)) /* 16 of these */
#define PROX_IXGBE_QBRC_H(_i)        (0x01038 + ((_i) * 0x40)) /* 16 of these */
#define PROX_IXGBE_QPRC(_i)          (0x01030 + ((_i) * 0x40)) /* 16 of these */
#define PROX_IXGBE_GPTC              0x04080
#define PROX_IXGBE_TPR               0x040D0
#define PROX_IXGBE_TORL              0x040C0
#define PROX_IXGBE_TORH              0x040C4
#define PROX_IXGBE_GOTCL             0x04090
#define PROX_IXGBE_GOTCH             0x04094

#define IXGBE_QUEUE_STAT_COUNTERS 16

static void ixgbe_read_stats(uint8_t port_id, struct port_stats_sample* stats, struct port_stats_sample *prev, int last_stat)
{
	uint64_t before, after;
	unsigned i;

	struct rte_eth_dev* dev = &rte_eth_devices[port_id];

	/* WARNING: Assumes hardware address is first field of structure! This may change! */
	struct _dev_hw* hw = (struct _dev_hw *)(dev->data->dev_private);

	stats->no_mbufs = dev->data->rx_mbuf_alloc_failed;

	/* Since we only read deltas from the NIC, we have to add to previous values
	 * even though we actually substract again later to find out the rates!
	 */
	stats->ierrors = prev->ierrors;
	stats->imissed = prev->imissed;
	stats->rx_bytes = prev->rx_bytes;
	stats->rx_tot = prev->rx_tot;
	stats->tx_bytes = prev->tx_bytes;
	stats->tx_tot = prev->tx_tot;

	/* WARNING: In this implementation, we count as imiised only the "no descriptor"
	 * missed packets cases and not the actual receive errors.
	 */
	before = rte_rdtsc();
	for (i = 0; i < 8; i++) {
		stats->imissed += PROX_READ_REG(hw, PROX_IXGBE_MPC(i));
	}

	/* RX stats */
#if 0
	/* This version is equivalent to what ixgbe PMD does. It only accounts for packets
	 * actually received on the host.
	 */
	for (i = 0; i < IXGBE_QUEUE_STAT_COUNTERS; i++) {
		/* ipackets: */
		stats->rx_tot += PROX_READ_REG(hw, PROX_IXGBE_QPRC(i));
		/* ibytes: */
		stats->rx_bytes += PROX_READ_REG(hw, PROX_IXGBE_QBRC_L(i));
		stats->rx_bytes += ((uint64_t)PROX_READ_REG(hw, PROX_IXGBE_QBRC_H(i)) << 32);
	}
#else
	/* This version reports the packets received by the NIC, regardless of whether they
	 * reached the host or not, etc. (no need to add ierrors or imissedto this packet count)
	 */
	stats->rx_tot += PROX_READ_REG(hw, PROX_IXGBE_TPR);
	stats->rx_bytes += PROX_READ_REG(hw, PROX_IXGBE_TORL);
	stats->rx_bytes += ((uint64_t)PROX_READ_REG(hw, PROX_IXGBE_TORH) << 32);
#endif

	/* TX stats */
	/* opackets: */
	stats->tx_tot += PROX_READ_REG(hw, PROX_IXGBE_GPTC);
	/* obytes: */
	stats->tx_bytes += PROX_READ_REG(hw, PROX_IXGBE_GOTCL);
	stats->tx_bytes += ((uint64_t)PROX_READ_REG(hw, PROX_IXGBE_GOTCH) << 32);
	after = rte_rdtsc();
	stats->tsc = (before >> 1) + (after >> 1);
}

#endif

extern int last_stat;
static struct port_stats   port_stats[PROX_MAX_PORTS];
static uint8_t nb_interface;
static uint8_t n_ports;
static int num_xstats[PROX_MAX_PORTS] = {0};
static int num_ixgbe_xstats = 0;

#if RTE_VERSION >= RTE_VERSION_NUM(2,1,0,1)
#define XSTATS_SUPPORT 1
#else
#define XSTATS_SUPPORT 0
#endif

#if XSTATS_SUPPORT
#if RTE_VERSION >= RTE_VERSION_NUM(16,7,0,0)
static struct rte_eth_xstat *eth_xstats[PROX_MAX_PORTS] = {0};
static struct rte_eth_xstat_name *eth_xstat_names[PROX_MAX_PORTS] = {0};
#else
static struct rte_eth_xstats *eth_xstats[PROX_MAX_PORTS] = {0};
static struct rte_eth_xstats *eth_xstat_names[PROX_MAX_PORTS] = {0};
#endif
static int xstat_tpr_offset[PROX_MAX_PORTS] ={0}, xstat_tor_offset[PROX_MAX_PORTS] = {0};
static int tx_pkt_size_offset[PROX_MAX_PORTS][PKT_SIZE_COUNT];
#endif

#if RTE_VERSION >= RTE_VERSION_NUM(16,7,0,0)
static int find_xstats_str(struct rte_eth_xstat_name *xstats, int n, const char *name)
#else
static int find_xstats_str(struct rte_eth_xstats *xstats, int n, const char *name)
#endif
{
	for (int i = 0; i < n; i++) {
		if (strcmp(xstats[i].name, name) == 0)
			return i;
	}

	return -1;
}

void stats_port_init(void)
{
	int potential_ixgbe_warn = 0;
	for (int i = 0; i < PROX_MAX_PORTS; i++) {
		xstat_tpr_offset[i] = -1;
		xstat_tor_offset[i] = -1;
		for (int j = 0; j < PKT_SIZE_COUNT; j++) {
			tx_pkt_size_offset[i][j] = -1;
		}
	}
#if XSTATS_SUPPORT
	nb_interface = prox_last_port_active() + 1;
	n_ports = prox_nb_active_ports();

	for (uint8_t port_id = 0; port_id < nb_interface; ++port_id) {
		if (prox_port_cfg[port_id].active) {
#if RTE_VERSION >= RTE_VERSION_NUM(16,7,0,0)
			num_xstats[port_id] = rte_eth_xstats_get_names(port_id, NULL, 0);
			eth_xstat_names[port_id] = prox_zmalloc(num_xstats[port_id] * sizeof(struct rte_eth_xstat_name), prox_port_cfg[port_id].socket);
			PROX_PANIC(eth_xstat_names[port_id] == NULL, "Error allocating memory for xstats");
			num_xstats[port_id] = rte_eth_xstats_get_names(port_id, eth_xstat_names[port_id], num_xstats[port_id]);
			eth_xstats[port_id] = prox_zmalloc(num_xstats[port_id] * sizeof(struct rte_eth_xstat), prox_port_cfg[port_id].socket);
			PROX_PANIC(eth_xstats[port_id] == NULL, "Error allocating memory for xstats");
#else
			num_xstats[port_id] = rte_eth_xstats_get(port_id, NULL, 0);
			eth_xstats[port_id] = prox_zmalloc(num_xstats[port_id] * sizeof(struct rte_eth_xstats), prox_port_cfg[port_id].socket);
			PROX_PANIC(eth_xstats[port_id] == NULL, "Error allocating memory for xstats");
			eth_xstat_names[port_id] = eth_xstats[port_id];
			num_xstats[port_id] = rte_eth_xstats_get(port_id, eth_xstats[port_id], num_xstats[port_id]);
#endif
			if (!strcmp(prox_port_cfg[port_id].short_name, "ixgbe")) {
				potential_ixgbe_warn = 1;
				xstat_tor_offset[port_id] = find_xstats_str(eth_xstat_names[port_id], num_xstats[port_id], "rx_total_bytes");
				xstat_tpr_offset[port_id] = find_xstats_str(eth_xstat_names[port_id], num_xstats[port_id], "rx_total_packets");
			}
			tx_pkt_size_offset[port_id][PKT_SIZE_64] = find_xstats_str(eth_xstat_names[port_id], num_xstats[port_id], "tx_size_64_packets");
			tx_pkt_size_offset[port_id][PKT_SIZE_65] = find_xstats_str(eth_xstat_names[port_id], num_xstats[port_id], "tx_size_65_to_127_packets");
			tx_pkt_size_offset[port_id][PKT_SIZE_128] = find_xstats_str(eth_xstat_names[port_id], num_xstats[port_id], "tx_size_128_to_255_packets");
			tx_pkt_size_offset[port_id][PKT_SIZE_256] = find_xstats_str(eth_xstat_names[port_id], num_xstats[port_id], "tx_size_256_to_511_packets");
			tx_pkt_size_offset[port_id][PKT_SIZE_512] = find_xstats_str(eth_xstat_names[port_id], num_xstats[port_id], "tx_size_512_to_1023_packets");
			if (0 == strcmp(prox_port_cfg[port_id].short_name, "ixgbe")) {
				tx_pkt_size_offset[port_id][PKT_SIZE_1024] = find_xstats_str(eth_xstat_names[port_id], num_xstats[port_id], "tx_size_1024_to_max_packets");
			} else {
				tx_pkt_size_offset[port_id][PKT_SIZE_1024] = find_xstats_str(eth_xstat_names[port_id], num_xstats[port_id], "tx_size_1024_to_1522_packets");
				tx_pkt_size_offset[port_id][PKT_SIZE_1522] = find_xstats_str(eth_xstat_names[port_id], num_xstats[port_id], "tx_size_1523_to_max_packets");
			}
			plog_info("offset = %d, %d, %d, %d, %d, %d %d\n", tx_pkt_size_offset[port_id][PKT_SIZE_64], tx_pkt_size_offset[port_id][PKT_SIZE_65], tx_pkt_size_offset[port_id][PKT_SIZE_128], tx_pkt_size_offset[port_id][PKT_SIZE_256], tx_pkt_size_offset[port_id][PKT_SIZE_512], tx_pkt_size_offset[port_id][PKT_SIZE_1024], tx_pkt_size_offset[port_id][PKT_SIZE_1522]);
#if RTE_VERSION >= RTE_VERSION_NUM(16,7,0,0)
			prox_free(eth_xstat_names[port_id]);
#endif
			if (num_xstats[port_id] == 0 || eth_xstats[port_id] == NULL) {
				plog_warn("Failed to initialize xstat for port %d, running without xstats\n", port_id);
				num_xstats[port_id] = 0;
			}
		}
	}
	for (uint8_t port_id = 0; port_id < nb_interface; ++port_id) {
		if ((xstat_tor_offset[port_id] != -1) && (xstat_tpr_offset[port_id] != -1)) {
			num_ixgbe_xstats = 2;	// ixgbe PMD supports tor and tpr xstats
			break;
		}
	}
	if ((num_ixgbe_xstats == 0) && (potential_ixgbe_warn))
		plog_warn("Failed to initialize ixgbe xstat, running without ixgbe xstats\n");
#endif
}

static void nic_read_stats(uint8_t port_id)
{
	unsigned is_ixgbe = (0 == strcmp(prox_port_cfg[port_id].short_name, "ixgbe"));

	struct port_stats_sample *stats = &port_stats[port_id].sample[last_stat];

#if defined(PROX_STATS) && defined(PROX_HW_DIRECT_STATS)
	if (is_ixgbe) {
		struct port_stats_sample *prev = &port_stats[port_id].sample[!last_stat];
		ixgbe_read_stats(port_id, stats, prev, last_stat);
		return;
	}
#endif
	uint64_t before, after;

	struct rte_eth_stats eth_stat;

	before = rte_rdtsc();
	rte_eth_stats_get(port_id, &eth_stat);
	after = rte_rdtsc();

	stats->tsc = (before >> 1) + (after >> 1);
	stats->no_mbufs = eth_stat.rx_nombuf;
	stats->ierrors = eth_stat.ierrors;
	stats->imissed = eth_stat.imissed;
	stats->oerrors = eth_stat.oerrors;
	stats->rx_bytes = eth_stat.ibytes;

	/* The goal would be to get the total number of bytes received
	   by the NIC (including overhead). Without the patch
	   (i.e. num_ixgbe_xstats == 0) we can't do this directly with
	   DPDK 2.1 API. So, we report the number of bytes (including
	   overhead) received by the host. */

#if XSTATS_SUPPORT
	if (num_xstats[port_id]) {
		rte_eth_xstats_get(port_id, eth_xstats[port_id], num_xstats[port_id]);
		for (size_t i = 0; i < sizeof(tx_pkt_size_offset[0])/sizeof(tx_pkt_size_offset[0][0]); ++i) {
			if (tx_pkt_size_offset[port_id][i] != -1)
				stats->tx_pkt_size[i] = (eth_xstats[port_id][tx_pkt_size_offset[port_id][i]]).value;
			else
				stats->tx_pkt_size[i] = -1;
		}
	} else {
		for (size_t i = 0; i < sizeof(tx_pkt_size_offset[0])/sizeof(tx_pkt_size_offset[0][0]); ++i) {
			stats->tx_pkt_size[i] = -1;
		}
	}
#endif
	if (is_ixgbe) {
#if XSTATS_SUPPORT
		if (num_ixgbe_xstats) {
			stats->rx_tot = eth_xstats[port_id][xstat_tpr_offset[port_id]].value;
			stats->rx_bytes = eth_xstats[port_id][xstat_tor_offset[port_id]].value;
		} else
#endif
		{
			stats->rx_tot = eth_stat.ipackets + eth_stat.ierrors + eth_stat.imissed;
			/* On ixgbe, the rx_bytes counts bytes
			   received by Host without overhead. The
			   rx_tot counts the number of packets
			   received by the NIC. If we only add 20 *
			   rx_tot to rx_bytes, the result will also
			   take into account 20 * "number of packets
			   dropped by the nic". Note that in case CRC
			   is stripped on ixgbe, the CRC bytes are not
			   counted. */
			if (prox_port_cfg[port_id].requested_rx_offload & DEV_RX_OFFLOAD_CRC_STRIP)
				stats->rx_bytes = eth_stat.ibytes +
					(24 * eth_stat.ipackets - 20 * (eth_stat.ierrors + eth_stat.imissed));
			else
				stats->rx_bytes = eth_stat.ibytes +
					(20 * eth_stat.ipackets - 20 * (eth_stat.ierrors + eth_stat.imissed));
		}
	} else if (strcmp(prox_port_cfg[port_id].short_name, "i40e_vf") == 0) {
		// For I40E VF, imissed already part of received packets
		stats->rx_tot = eth_stat.ipackets;
	} else {
		stats->rx_tot = eth_stat.ipackets + eth_stat.imissed;
	}
	stats->tx_tot = eth_stat.opackets;
	stats->tx_bytes = eth_stat.obytes;
}

void stats_port_reset(void)
{
	for (uint8_t port_id = 0; port_id < nb_interface; ++port_id) {
		if (prox_port_cfg[port_id].active) {
			rte_eth_stats_reset(port_id);
			memset(&port_stats[port_id], 0, sizeof(struct port_stats));
		}
	}
}

void stats_port_update(void)
{
	for (uint8_t port_id = 0; port_id < nb_interface; ++port_id) {
		if (prox_port_cfg[port_id].active) {
			nic_read_stats(port_id);
		}
	}
}

uint64_t stats_port_get_ierrors(void)
{
	uint64_t ret = 0;

	for (uint8_t port_id = 0; port_id < nb_interface; ++port_id) {
		if (prox_port_cfg[port_id].active)
			ret += port_stats[port_id].sample[last_stat].ierrors;
	}
	return ret;
}

uint64_t stats_port_get_imissed(void)
{
	uint64_t ret = 0;

	for (uint8_t port_id = 0; port_id < nb_interface; ++port_id) {
		if (prox_port_cfg[port_id].active)
			ret += port_stats[port_id].sample[last_stat].imissed;
	}
	return ret;
}

uint64_t stats_port_get_rx_packets(void)
{
	uint64_t ret = 0;

	for (uint8_t port_id = 0; port_id < nb_interface; ++port_id) {
		if (prox_port_cfg[port_id].active)
			ret += port_stats[port_id].sample[last_stat].rx_tot;
	}
	return ret;
}

uint64_t stats_port_get_tx_packets(void)
{
	uint64_t ret = 0;

	for (uint8_t port_id = 0; port_id < nb_interface; ++port_id) {
		if (prox_port_cfg[port_id].active)
			ret += port_stats[port_id].sample[last_stat].tx_tot;
	}
	return ret;
}

int stats_get_n_ports(void)
{
	return n_ports;
}

struct port_stats_sample *stats_get_port_stats_sample(uint32_t port_id, int l)
{
	return &port_stats[port_id].sample[l == last_stat];
}

int stats_port(uint8_t port_id, struct get_port_stats *gps)
{
	if (!prox_port_cfg[port_id].active)
		return -1;

	struct port_stats_sample *last = &port_stats[port_id].sample[last_stat];
	struct port_stats_sample *prev = &port_stats[port_id].sample[!last_stat];

	gps->no_mbufs_diff = last->no_mbufs - prev->no_mbufs;
	gps->ierrors_diff = last->ierrors - prev->ierrors;
	gps->imissed_diff = last->imissed - prev->imissed;
	gps->rx_bytes_diff = last->rx_bytes - prev->rx_bytes;
	gps->tx_bytes_diff = last->tx_bytes - prev->tx_bytes;
	gps->rx_pkts_diff = last->rx_tot - prev->rx_tot;
	if (unlikely(prev->rx_tot > last->rx_tot))
		gps->rx_pkts_diff = 0;
	gps->tx_pkts_diff = last->tx_tot - prev->tx_tot;
	if (unlikely(prev->tx_tot > last->tx_tot))
		gps->rx_pkts_diff = 0;
	gps->rx_tot = last->rx_tot;
	gps->tx_tot = last->tx_tot;
	gps->no_mbufs_tot = last->no_mbufs;
	gps->ierrors_tot = last->ierrors;
	gps->imissed_tot = last->imissed;

	gps->last_tsc = last->tsc;
	gps->prev_tsc = prev->tsc;

	return 0;
}
