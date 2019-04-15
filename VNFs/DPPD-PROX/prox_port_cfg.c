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
#include <rte_eth_ring.h>
#include <rte_mbuf.h>
#if (RTE_VERSION >= RTE_VERSION_NUM(17,11,0,0))
#include <rte_bus_vdev.h>
#else
#if (RTE_VERSION > RTE_VERSION_NUM(17,5,0,2))
#include <rte_dev.h>
#else
#if (RTE_VERSION >= RTE_VERSION_NUM(2,1,0,0))
#include <rte_eth_null.h>
#endif
#endif
#endif

#include "prox_port_cfg.h"
#include "prox_globals.h"
#include "log.h"
#include "quit.h"
#include "defaults.h"
#include "toeplitz.h"
#include "defines.h"
#include "prox_cksum.h"
#include "stats_irq.h"
#include "prox_compat.h"

struct prox_port_cfg prox_port_cfg[PROX_MAX_PORTS];
rte_atomic32_t lsc;

int prox_nb_active_ports(void)
{
	int ret = 0;
	for (uint32_t i = 0; i < PROX_MAX_PORTS; ++i) {
		ret += prox_port_cfg[i].active;
	}
	return ret;
}

int prox_last_port_active(void)
{
	int ret = -1;
	for (uint32_t i = 0; i < PROX_MAX_PORTS; ++i) {
		if (prox_port_cfg[i].active) {
			ret = i;
		}
	}
	return ret;
}

#if RTE_VERSION >= RTE_VERSION_NUM(17,11,0,0)
static int lsc_cb(__attribute__((unused)) uint16_t port_id, enum rte_eth_event_type type, __attribute__((unused)) void *param,
	__attribute__((unused)) void *ret_param)
#else
#if RTE_VERSION >= RTE_VERSION_NUM(17,8,0,1)
static int lsc_cb(__attribute__((unused)) uint8_t port_id, enum rte_eth_event_type type, __attribute__((unused)) void *param,
	__attribute__((unused)) void *ret_param)
#else
static void lsc_cb(__attribute__((unused)) uint8_t port_id, enum rte_eth_event_type type, __attribute__((unused)) void *param)
#endif
#endif
{
	if (RTE_ETH_EVENT_INTR_LSC != type) {
#if RTE_VERSION >= RTE_VERSION_NUM(17,8,0,1)
		return -1;
#else
		return;
#endif
	}

	rte_atomic32_inc(&lsc);

#if RTE_VERSION >= RTE_VERSION_NUM(17,8,0,1)
	return 0;
#endif
}

struct prox_pktmbuf_reinit_args {
	struct rte_mempool *mp;
	struct lcore_cfg   *lconf;
};

/* standard mbuf initialization procedure */
void prox_pktmbuf_init(struct rte_mempool *mp, void *opaque_arg, void *_m, unsigned i)
{
	struct rte_mbuf *mbuf = _m;

#if RTE_VERSION >= RTE_VERSION_NUM(1,8,0,0)
	mbuf->tx_offload = CALC_TX_OL(sizeof(struct ether_hdr), sizeof(struct ipv4_hdr));
#else
	mbuf->pkt.vlan_macip.f.l2_len = sizeof(struct ether_hdr);
	mbuf->pkt.vlan_macip.f.l3_len = sizeof(struct ipv4_hdr);
#endif

	rte_pktmbuf_init(mp, opaque_arg, mbuf, i);
}

void prox_pktmbuf_reinit(void *arg, void *start, __attribute__((unused)) void *end, uint32_t idx)
{
	struct prox_pktmbuf_reinit_args *init_args = arg;
	struct rte_mbuf *m;
	char* obj = start;

	obj += init_args->mp->header_size;
	m = (struct rte_mbuf*)obj;

	prox_pktmbuf_init(init_args->mp, init_args->lconf, obj, idx);
}

#define CONFIGURE_TX_OFFLOAD(flag)                                           \
        if (port_cfg->requested_tx_offload & flag)                              {\
		if (port_cfg->disabled_tx_offload & flag)			{\
			plog_info("\t\t%s disabled by configuration\n", #flag);\
                        port_cfg->requested_tx_offload &= ~flag;\
                } else if (port_cfg->dev_info.tx_offload_capa & flag) {\
                        port_cfg->port_conf.txmode.offloads |= flag;\
                        plog_info("\t\t%s enabled on port\n", #flag);\
                } else if (port_cfg->dev_info.tx_queue_offload_capa & flag) {\
                        port_cfg->tx_conf.offloads |= flag;\
                        plog_info("\t\t%s enabled on queue\n", #flag);\
                } else {\
                        port_cfg->requested_tx_offload &= ~flag;\
                        plog_info("\t\t%s disabled as neither port or queue supports it\n", #flag);\
                }\
        } else {\
                plog_info("\t\t%s disabled\n", #flag);\
        }\

#define CONFIGURE_RX_OFFLOAD(flag)                                           \
        if (port_cfg->requested_rx_offload & flag)                              {\
                if (port_cfg->dev_info.rx_offload_capa & flag) {\
                        port_cfg->port_conf.rxmode.offloads |= flag;\
                        plog_info("\t\t%s enabled on port\n", #flag);\
                } else if (port_cfg->dev_info.rx_queue_offload_capa & flag) {\
                        port_cfg->rx_conf.offloads |= flag;\
                        plog_info("\t\t%s enabled on queue\n", #flag);\
                } else {\
                        port_cfg->requested_rx_offload &= ~flag;\
                        plog_info("\t\t%s disabled as neither port or queue supports it\n", #flag);\
                }\
        } else {\
                plog_info("\t\t%s disabled\n", #flag);\
        }\


/* initialize rte devices and check the number of available ports */
void init_rte_dev(int use_dummy_devices)
{
	uint8_t nb_ports, port_id_max;
	int port_id_last;
	struct rte_eth_dev_info dev_info;
	const struct rte_pci_device *pci_dev;

	nb_ports = rte_eth_dev_count();
	/* get available ports configuration */
	PROX_PANIC(use_dummy_devices && nb_ports, "Can't use dummy devices while there are also real ports\n");

	if (use_dummy_devices) {
#if (RTE_VERSION >= RTE_VERSION_NUM(2,1,0,0))
		nb_ports = prox_last_port_active() + 1;
		plog_info("Creating %u dummy devices\n", nb_ports);

		char port_name[32] = "0dummy_dev";
		for (uint32_t i = 0; i < nb_ports; ++i) {
#if (RTE_VERSION > RTE_VERSION_NUM(17,5,0,1))
			rte_vdev_init(port_name, "size=ETHER_MIN_LEN,copy=0");
#else
			eth_dev_null_create(port_name, 0, ETHER_MIN_LEN, 0);
#endif
			port_name[0]++;
		}
#else
	PROX_PANIC(use_dummy_devices, "Can't use dummy devices\n");
#endif
	}
	else if (prox_last_port_active() != -1) {
		PROX_PANIC(nb_ports == 0, "\tError: DPDK could not find any port\n");
		plog_info("\tDPDK has found %u ports\n", nb_ports);
	}

	if (nb_ports > PROX_MAX_PORTS) {
		plog_warn("\tWarning: I can deal with at most %u ports."
		        " Please update PROX_MAX_PORTS and recompile.\n", PROX_MAX_PORTS);

		nb_ports = PROX_MAX_PORTS;
	}
	port_id_max = nb_ports - 1;
	port_id_last = prox_last_port_active();
	PROX_PANIC(port_id_last > port_id_max,
		   "\tError: invalid port(s) specified, last port index active: %d (max index is %d)\n",
		   port_id_last, port_id_max);

	/* Assign ports to PROX interfaces & Read max RX/TX queues per port */
	for (uint8_t port_id = 0; port_id < nb_ports; ++port_id) {
		/* skip ports that are not enabled */
		if (!prox_port_cfg[port_id].active) {
			continue;
		}
		plog_info("\tGetting info for rte dev %u\n", port_id);
		rte_eth_dev_info_get(port_id, &dev_info);
		struct prox_port_cfg* port_cfg = &prox_port_cfg[port_id];
		port_cfg->socket = -1;

		memcpy(&port_cfg->dev_info, &dev_info, sizeof(struct rte_eth_dev_info));
		port_cfg->max_txq = dev_info.max_tx_queues;
		port_cfg->max_rxq = dev_info.max_rx_queues;
		port_cfg->max_rx_pkt_len = dev_info.max_rx_pktlen;
		port_cfg->min_rx_bufsize = dev_info.min_rx_bufsize;

		strncpy(port_cfg->driver_name, dev_info.driver_name, sizeof(port_cfg->driver_name));
		plog_info("\tPort %u : driver='%s' tx_queues=%d rx_queues=%d\n", port_id, !strcmp(port_cfg->driver_name, "")? "null" : port_cfg->driver_name, port_cfg->max_txq, port_cfg->max_rxq);

		if (strncmp(port_cfg->driver_name, "rte_", 4) == 0) {
			strncpy(port_cfg->short_name, prox_port_cfg[port_id].driver_name + 4, sizeof(port_cfg->short_name));
		} else if (strncmp(port_cfg->driver_name, "net_", 4) == 0) {
			strncpy(port_cfg->short_name, prox_port_cfg[port_id].driver_name + 4, sizeof(port_cfg->short_name));
		} else {
			strncpy(port_cfg->short_name, prox_port_cfg[port_id].driver_name, sizeof(port_cfg->short_name));
		}
		char *ptr;
		if ((ptr = strstr(port_cfg->short_name, "_pmd")) != NULL) {
			*ptr = '\x0';
		}

#if RTE_VERSION < RTE_VERSION_NUM(18,5,0,0)
		pci_dev = dev_info.pci_dev;
#else
		if (!dev_info.device)
			continue;
		pci_dev = RTE_DEV_TO_PCI(dev_info.device);
#endif
		if (!pci_dev)
			continue;

		snprintf(port_cfg->pci_addr, sizeof(port_cfg->pci_addr),
			 "%04x:%02x:%02x.%1x", pci_dev->addr.domain, pci_dev->addr.bus, pci_dev->addr.devid, pci_dev->addr.function);
		/* Try to find the device's numa node */
		char buf[1024];
		snprintf(buf, sizeof(buf), "/sys/bus/pci/devices/%s/numa_node", port_cfg->pci_addr);
		FILE* numa_node_fd = fopen(buf, "r");
		if (numa_node_fd) {
			if (fgets(buf, sizeof(buf), numa_node_fd) == NULL) {
				plog_warn("Failed to read numa_node for device %s\n", port_cfg->pci_addr);
			}
			port_cfg->socket = strtol(buf, 0, 0);
			if (port_cfg->socket == -1) {
				plog_warn("System did not report numa_node for device %s\n", port_cfg->pci_addr);
			}
			fclose(numa_node_fd);
		}

		// In DPDK 18.08 vmxnet3 reports it supports IPV4 checksum, but packets does not go through when IPv4 cksum is enabled
		if ((!strcmp(port_cfg->short_name, "vmxnet3")) && (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM)) {
			plog_info("\t\tDisabling IPV4 cksum on vmxnet3\n");
			port_cfg->disabled_tx_offload |= DEV_TX_OFFLOAD_IPV4_CKSUM;
		}
		if ((!strcmp(port_cfg->short_name, "vmxnet3")) && (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM)) {
			plog_info("\t\tDisabling UDP cksum on vmxnet3\n");
			port_cfg->disabled_tx_offload |= DEV_TX_OFFLOAD_UDP_CKSUM;
		}
	}
}

/* Create rte ring-backed devices */
uint8_t init_rte_ring_dev(void)
{
	uint8_t nb_ring_dev = 0;

	for (uint8_t port_id = 0; port_id < PROX_MAX_PORTS; ++port_id) {
		/* skip ports that are not enabled */
		if (!prox_port_cfg[port_id].active) {
			continue;
		}
		struct prox_port_cfg* port_cfg = &prox_port_cfg[port_id];
		if (port_cfg->rx_ring[0] != '\0') {
			plog_info("\tRing-backed port %u: rx='%s' tx='%s'\n", port_id, port_cfg->rx_ring, port_cfg->tx_ring);

			struct rte_ring* rx_ring = rte_ring_lookup(port_cfg->rx_ring);
			PROX_PANIC(rx_ring == NULL, "Ring %s not found for port %d!\n", port_cfg->rx_ring, port_id);
			struct rte_ring* tx_ring = rte_ring_lookup(port_cfg->tx_ring);
			PROX_PANIC(tx_ring == NULL, "Ring %s not found for port %d!\n", port_cfg->tx_ring, port_id);

			int ret = rte_eth_from_rings(port_cfg->name, &rx_ring, 1, &tx_ring, 1, rte_socket_id());
			PROX_PANIC(ret != 0, "Failed to create eth_dev from rings for port %d\n", port_id);

			port_cfg->port_conf.intr_conf.lsc = 0; /* Link state interrupt not supported for ring-backed ports */

			nb_ring_dev++;
		}
	}

	return nb_ring_dev;
}

static void print_port_capa(struct prox_port_cfg *port_cfg)
{
	uint8_t port_id;

	port_id = port_cfg - prox_port_cfg;
	plog_info("\t*** Initializing port %u ***\n", port_id);
	plog_info("\t\tPort name is set to %s\n", port_cfg->name);
	plog_info("\t\tPort max RX/TX queue is %u/%u\n", port_cfg->max_rxq, port_cfg->max_txq);
	plog_info("\t\tPort driver is %s\n", port_cfg->driver_name);
#if RTE_VERSION >= RTE_VERSION_NUM(16,4,0,0)
	plog_info("\t\tSupported speed mask = 0x%x\n", port_cfg->dev_info.speed_capa);
#endif
	if (port_cfg->max_link_speed != UINT32_MAX) {
		plog_info("\t\tHighest link speed capa = %d Mbps\n", port_cfg->max_link_speed);
	}

#if RTE_VERSION >= RTE_VERSION_NUM(18,8,0,1)
	plog_info("\t\tRX offload capa = 0x%lx = ", port_cfg->dev_info.rx_offload_capa);
	if (port_cfg->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_VLAN_STRIP)
		plog_info("VLAN STRIP | ");
	if (port_cfg->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM)
		plog_info("IPV4 CKSUM | ");
	if (port_cfg->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_UDP_CKSUM)
		plog_info("UDP CKSUM | ");
	if (port_cfg->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TCP_CKSUM)
		plog_info("TCP CKSUM | ");
	if (port_cfg->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TCP_LRO)
		plog_info("TCP LRO | ");
	if (port_cfg->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_QINQ_STRIP)
		plog_info("QINQ STRIP | ");
	if (port_cfg->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM)
		plog_info("OUTER_IPV4_CKSUM | ");
	if (port_cfg->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_MACSEC_STRIP)
		plog_info("MACSEC STRIP | ");
	if (port_cfg->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_HEADER_SPLIT)
		plog_info("HEADER SPLIT | ");
	if (port_cfg->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_VLAN_FILTER)
		plog_info("VLAN FILTER | ");
	if (port_cfg->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_VLAN_EXTEND)
		plog_info("VLAN EXTEND | ");
	if (port_cfg->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_JUMBO_FRAME)
		plog_info("JUMBO FRAME | ");
	if (port_cfg->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_CRC_STRIP)
		plog_info("CRC STRIP | ");
	if (port_cfg->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_SCATTER)
		plog_info("SCATTER | ");
	if (port_cfg->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TIMESTAMP)
		plog_info("TIMESTAMP | ");
	if (port_cfg->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_SECURITY)
		plog_info("SECURITY ");
	plog_info("\n");

	plog_info("\t\tTX offload capa = 0x%lx = ", port_cfg->dev_info.tx_offload_capa);
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_VLAN_INSERT)
		plog_info("VLAN INSERT | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM)
		plog_info("IPV4 CKSUM | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM)
		plog_info("UDP CKSUM | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM)
		plog_info("TCP CKSUM | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_SCTP_CKSUM)
		plog_info("SCTP CKSUM | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_TSO)
		plog_info("TCP TS0 | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_TSO)
		plog_info("UDP TSO | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM)
		plog_info("OUTER IPV4 CKSUM | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_QINQ_INSERT)
		plog_info("QINQ INSERT | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_VXLAN_TNL_TSO)
		plog_info("VLAN TNL TSO | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_GRE_TNL_TSO)
		plog_info("GRE TNL TSO | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPIP_TNL_TSO)
		plog_info("IPIP TNL TSO | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_GENEVE_TNL_TSO)
		plog_info("GENEVE TNL TSO | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MACSEC_INSERT)
		plog_info("MACSEC INSERT | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MT_LOCKFREE)
		plog_info("MT LOCKFREE | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MULTI_SEGS)
		plog_info("MULTI SEG | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_SECURITY)
		plog_info("SECURITY | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_TNL_TSO)
		plog_info("UDP TNL TSO | ");
	if (port_cfg->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IP_TNL_TSO)
		plog_info("IP TNL TSO | ");
	plog_info("\n");

	plog_info("\t\trx_queue_offload_capa = 0x%lx\n", port_cfg->dev_info.rx_queue_offload_capa);
	plog_info("\t\ttx_queue_offload_capa = 0x%lx\n", port_cfg->dev_info.tx_queue_offload_capa);
	plog_info("\t\tflow_type_rss_offloads = 0x%lx\n", port_cfg->dev_info.flow_type_rss_offloads);
	plog_info("\t\tdefault RX port conf: burst_size = %d, ring_size = %d, nb_queues = %d\n", port_cfg->dev_info.default_rxportconf.burst_size, port_cfg->dev_info.default_rxportconf.ring_size, port_cfg->dev_info.default_rxportconf.nb_queues);
	plog_info("\t\tdefault TX port conf: burst_size = %d, ring_size = %d, nb_queues = %d\n", port_cfg->dev_info.default_txportconf.burst_size, port_cfg->dev_info.default_txportconf.ring_size, port_cfg->dev_info.default_txportconf.nb_queues);
#endif
}

static void get_max_link_speed(struct prox_port_cfg *port_cfg)
{
	port_cfg->max_link_speed = UINT32_MAX;

#if RTE_VERSION >= RTE_VERSION_NUM(16,4,0,0)
	// virtio and vmxnet3 reports fake max_link_speed
	if (strcmp(port_cfg->short_name, "vmxnet3") && strcmp(port_cfg->short_name, "virtio")) {
		// Get link_speed from highest capability from the port
		// This will be used by gen and lat for extrapolation purposes
		// The negotiated link_speed (as reported by rte_eth_link_get
		// or rte_eth_link_get_nowait) might be reported too late
		// and might result in wrong exrapolation, and hence should not be used
		// for extrapolation purposes
		if (port_cfg->dev_info.speed_capa & ETH_LINK_SPEED_100G)
			port_cfg->max_link_speed = ETH_SPEED_NUM_100G;
		else if (port_cfg->dev_info.speed_capa & ETH_LINK_SPEED_56G)
			port_cfg->max_link_speed = ETH_SPEED_NUM_56G;
		else if (port_cfg->dev_info.speed_capa & ETH_LINK_SPEED_50G)
			port_cfg->max_link_speed = ETH_SPEED_NUM_50G;
		else if (port_cfg->dev_info.speed_capa & ETH_LINK_SPEED_40G)
			port_cfg->max_link_speed = ETH_SPEED_NUM_40G;
		else if (port_cfg->dev_info.speed_capa & ETH_LINK_SPEED_25G)
			port_cfg->max_link_speed = ETH_SPEED_NUM_25G;
		else if (port_cfg->dev_info.speed_capa & ETH_LINK_SPEED_20G)
			port_cfg->max_link_speed = ETH_SPEED_NUM_20G;
		else if (port_cfg->dev_info.speed_capa & ETH_LINK_SPEED_10G)
			port_cfg->max_link_speed = ETH_SPEED_NUM_10G;
		else if (port_cfg->dev_info.speed_capa & ETH_LINK_SPEED_5G)
			port_cfg->max_link_speed = ETH_SPEED_NUM_5G;
		else if (port_cfg->dev_info.speed_capa & ETH_LINK_SPEED_2_5G)
			port_cfg->max_link_speed = ETH_SPEED_NUM_2_5G;
		else if (port_cfg->dev_info.speed_capa & ETH_LINK_SPEED_1G)
			port_cfg->max_link_speed = ETH_SPEED_NUM_1G;
		else if (port_cfg->dev_info.speed_capa & (ETH_LINK_SPEED_100M_HD | ETH_LINK_SPEED_100M))
			port_cfg->max_link_speed = ETH_SPEED_NUM_100M;
		else if (port_cfg->dev_info.speed_capa & (ETH_LINK_SPEED_10M_HD | ETH_LINK_SPEED_10M))
			port_cfg->max_link_speed = ETH_SPEED_NUM_10M;

	}
#endif
}

static void init_port(struct prox_port_cfg *port_cfg)
{
	static char dummy_pool_name[] = "0_dummy";
	struct rte_eth_link link;
	uint8_t port_id;
	int ret;

	get_max_link_speed(port_cfg);
	print_port_capa(port_cfg);
	port_id = port_cfg - prox_port_cfg;
	PROX_PANIC(port_cfg->n_rxq == 0 && port_cfg->n_txq == 0,
		   "\t\t port %u is enabled but no RX or TX queues have been configured", port_id);

	if (port_cfg->n_rxq == 0) {
		/* not receiving on this port */
		plog_info("\t\tPort %u had no RX queues, setting to 1\n", port_id);
		port_cfg->n_rxq = 1;
		uint32_t mbuf_size = TX_MBUF_SIZE;
                if (mbuf_size < port_cfg->min_rx_bufsize + RTE_PKTMBUF_HEADROOM + sizeof(struct rte_mbuf))
                        mbuf_size = port_cfg->min_rx_bufsize + RTE_PKTMBUF_HEADROOM + sizeof(struct rte_mbuf);

		plog_info("\t\tAllocating dummy memory pool on socket %u with %u elements of size %u\n",
			  port_cfg->socket, port_cfg->n_rxd, mbuf_size);
		port_cfg->pool[0] = rte_mempool_create(dummy_pool_name, port_cfg->n_rxd, mbuf_size,
						       0,
						       sizeof(struct rte_pktmbuf_pool_private),
						       rte_pktmbuf_pool_init, NULL,
						       prox_pktmbuf_init, 0,
						       port_cfg->socket, 0);
		PROX_PANIC(port_cfg->pool[0] == NULL, "Failed to allocate dummy memory pool on socket %u with %u elements\n",
			   port_cfg->socket, port_cfg->n_rxd);
		dummy_pool_name[0]++;
	} else {
		// Most pmd should now support setting mtu
		if (port_cfg->mtu + ETHER_HDR_LEN + ETHER_CRC_LEN > port_cfg->max_rx_pkt_len) {
			plog_info("\t\tMTU is too big for the port, reducing MTU from %d to %d\n", port_cfg->mtu, port_cfg->max_rx_pkt_len);
			port_cfg->mtu = port_cfg->max_rx_pkt_len;
		}
		plog_info("\t\tSetting MTU size to %u for port %u ...\n", port_cfg->mtu, port_id);
		ret = rte_eth_dev_set_mtu(port_id, port_cfg->mtu);
		if (ret)
			plog_err("\t\t\trte_eth_dev_set_mtu() failed on port %u: error %d\n", port_id, ret);

		if (port_cfg->n_txq == 0) {
			/* not sending on this port */
			plog_info("\t\tPort %u had no TX queues, setting to 1\n", port_id);
			port_cfg->n_txq = 1;
		}
	}

	if (port_cfg->n_rxq > 1)  {
		// Enable RSS if multiple receive queues
		port_cfg->port_conf.rxmode.mq_mode       		|= ETH_MQ_RX_RSS;
		port_cfg->port_conf.rx_adv_conf.rss_conf.rss_key 	= toeplitz_init_key;
		port_cfg->port_conf.rx_adv_conf.rss_conf.rss_key_len 	= TOEPLITZ_KEY_LEN;
#if RTE_VERSION >= RTE_VERSION_NUM(2,0,0,0)
		port_cfg->port_conf.rx_adv_conf.rss_conf.rss_hf 	= ETH_RSS_IP|ETH_RSS_UDP;
#else
		port_cfg->port_conf.rx_adv_conf.rss_conf.rss_hf 	= ETH_RSS_IPV4|ETH_RSS_NONF_IPV4_UDP;
#endif
	}

	// Make sure that the requested RSS offload is supported by the PMD
#if RTE_VERSION >= RTE_VERSION_NUM(2,0,0,0)
	port_cfg->port_conf.rx_adv_conf.rss_conf.rss_hf &= port_cfg->dev_info.flow_type_rss_offloads;
#endif
	plog_info("\t\t Enabling RSS rss_hf = 0x%lx (requested 0x%llx)\n", port_cfg->port_conf.rx_adv_conf.rss_conf.rss_hf, ETH_RSS_IP|ETH_RSS_UDP);

	// rxmode such as hw src strip
#if RTE_VERSION >= RTE_VERSION_NUM(18,8,0,1)
	CONFIGURE_RX_OFFLOAD(DEV_RX_OFFLOAD_CRC_STRIP);
	CONFIGURE_RX_OFFLOAD(DEV_RX_OFFLOAD_JUMBO_FRAME);
	CONFIGURE_RX_OFFLOAD(DEV_RX_OFFLOAD_VLAN_STRIP);
#else
	if (port_cfg->requested_rx_offload & DEV_RX_OFFLOAD_CRC_STRIP) {
		port_cfg->port_conf.rxmode.hw_strip_crc = 1;
	}
	if (port_cfg->requested_rx_offload & DEV_RX_OFFLOAD_JUMBO_FRAME) {
		port_cfg->port_conf.rxmode.jumbo_frame = 1;
	}
#endif

	// IPV4, UDP, SCTP Checksums
#if RTE_VERSION >= RTE_VERSION_NUM(18,8,0,1)
	CONFIGURE_TX_OFFLOAD(DEV_TX_OFFLOAD_IPV4_CKSUM);
	CONFIGURE_TX_OFFLOAD(DEV_TX_OFFLOAD_UDP_CKSUM);
	CONFIGURE_TX_OFFLOAD(DEV_TX_OFFLOAD_VLAN_INSERT);
#else
	if ((port_cfg->dev_info.tx_offload_capa & (DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM)) == 0) {
		port_cfg->tx_conf.txq_flags |= ETH_TXQ_FLAGS_NOOFFLOADS;
		plog_info("\t\tDisabling TX offloads as pmd reports that it does not support them)\n");
	}
	if (!strcmp(port_cfg->short_name, "vmxnet3")) {
		port_cfg->tx_conf.txq_flags |= ETH_TXQ_FLAGS_NOXSUMSCTP;
		plog_info("\t\tDisabling SCTP offload on port %d as vmxnet3 does not support them\n", port_id);
	}
#endif
	// Multi Segments
#if RTE_VERSION >= RTE_VERSION_NUM(18,8,0,1)
	CONFIGURE_TX_OFFLOAD(DEV_TX_OFFLOAD_MULTI_SEGS);
#else
	if (!strcmp(port_cfg->short_name, "vmxnet3")) {
		port_cfg->tx_conf.txq_flags |= ETH_TXQ_FLAGS_NOMULTSEGS;
		plog_info("\t\tDisabling TX multsegs on port %d as vmxnet3 does not support them\n", port_id);
	} else if (port_cfg->tx_conf.txq_flags & ETH_TXQ_FLAGS_NOMULTSEGS)
		plog_info("\t\tDisabling TX multsegs on port %d\n", port_id);
	else
		plog_info("\t\tEnabling TX multsegs on port %d\n", port_id);

	if (port_cfg->tx_conf.txq_flags & ETH_TXQ_FLAGS_NOOFFLOADS)
		plog_info("\t\tEnabling No TX offloads on port %d\n", port_id);
	else
		plog_info("\t\tTX offloads enabled on port %d\n", port_id);
#endif

	// Refcount
#if RTE_VERSION >= RTE_VERSION_NUM(18,8,0,1)
	CONFIGURE_TX_OFFLOAD(DEV_TX_OFFLOAD_MBUF_FAST_FREE);
#else
	if (port_cfg->tx_conf.txq_flags & ETH_TXQ_FLAGS_NOREFCOUNT)
		plog_info("\t\tEnabling No refcnt on port %d\n", port_id);
	else
		plog_info("\t\tRefcnt enabled on port %d\n", port_id);
#endif

	plog_info("\t\tConfiguring port %u... with %u RX queues and %u TX queues\n",
		  port_id, port_cfg->n_rxq, port_cfg->n_txq);

	PROX_PANIC(port_cfg->n_rxq > port_cfg->max_rxq, "\t\t\tToo many RX queues (configuring %u, max is %u)\n", port_cfg->n_rxq, port_cfg->max_rxq);
	PROX_PANIC(port_cfg->n_txq > port_cfg->max_txq, "\t\t\tToo many TX queues (configuring %u, max is %u)\n", port_cfg->n_txq, port_cfg->max_txq);

	if (!strcmp(port_cfg->short_name, "ixgbe_vf") ||
	    !strcmp(port_cfg->short_name, "virtio") ||
#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
	    !strcmp(port_cfg->short_name, "i40e") ||
#endif
	    !strcmp(port_cfg->short_name, "i40e_vf") ||
	    !strcmp(port_cfg->short_name, "avp") || /* Wind River */
	    !strcmp(port_cfg->driver_name, "") || /* NULL device */
	    !strcmp(port_cfg->short_name, "vmxnet3")) {
		port_cfg->port_conf.intr_conf.lsc = 0;
		plog_info("\t\tDisabling link state interrupt for vmxnet3/VF/virtio (unsupported)\n");
	}

	if (port_cfg->lsc_set_explicitely) {
		port_cfg->port_conf.intr_conf.lsc = port_cfg->lsc_val;
		plog_info("\t\tOverriding link state interrupt configuration to '%s'\n", port_cfg->lsc_val? "enabled" : "disabled");
	}
	if (!strcmp(port_cfg->short_name, "vmxnet3")) {
		if (port_cfg->n_txd < 512) {
			// Vmxnet3 driver requires minimum 512 tx descriptors
			plog_info("\t\tNumber of TX descriptors is set to 512 (minimum required for vmxnet3\n");
			port_cfg->n_txd = 512;
		}
	}

	ret = rte_eth_dev_configure(port_id, port_cfg->n_rxq,
				    port_cfg->n_txq, &port_cfg->port_conf);
	PROX_PANIC(ret < 0, "\t\t\trte_eth_dev_configure() failed on port %u: %s (%d)\n", port_id, strerror(-ret), ret);

	if (port_cfg->port_conf.intr_conf.lsc) {
		rte_eth_dev_callback_register(port_id, RTE_ETH_EVENT_INTR_LSC, lsc_cb, NULL);
	}

	plog_info("\t\tMAC address set to "MAC_BYTES_FMT"\n", MAC_BYTES(port_cfg->eth_addr.addr_bytes));

	/* initialize TX queues first */
	for (uint16_t queue_id = 0; queue_id < port_cfg->n_txq; ++queue_id) {
		plog_info("\t\tSetting up TX queue %u on socket %u with %u desc\n",
			  queue_id, port_cfg->socket, port_cfg->n_txd);
		ret = rte_eth_tx_queue_setup(port_id, queue_id, port_cfg->n_txd,
					     port_cfg->socket, &port_cfg->tx_conf);
		PROX_PANIC(ret < 0, "\t\t\trte_eth_tx_queue_setup() failed on port %u: error %d\n", port_id, ret);
	}

	/* initialize RX queues */
	for (uint16_t queue_id = 0; queue_id < port_cfg->n_rxq; ++queue_id) {
		plog_info("\t\tSetting up RX queue %u on port %u on socket %u with %u desc (pool 0x%p)\n",
			  queue_id, port_id, port_cfg->socket,
			  port_cfg->n_rxd, port_cfg->pool[queue_id]);
		ret = rte_eth_rx_queue_setup(port_id, queue_id,
					     port_cfg->n_rxd,
					     port_cfg->socket, &port_cfg->rx_conf,
					     port_cfg->pool[queue_id]);
		PROX_PANIC(ret < 0, "\t\t\trte_eth_rx_queue_setup() failed on port %u: error %s (%d)\n", port_id, strerror(-ret), ret);
	}

	plog_info("\t\tStarting up port %u ...", port_id);
	ret = rte_eth_dev_start(port_id);

	PROX_PANIC(ret < 0, "\n\t\t\trte_eth_dev_start() failed on port %u: error %d\n", port_id, ret);
	plog_info(" done: ");

	/* Getting link status can be done without waiting if Link
	   State Interrupt is enabled since in that case, if the link
	   is recognized as being down, an interrupt will notify that
	   it has gone up. */
	if (port_cfg->port_conf.intr_conf.lsc)
		rte_eth_link_get_nowait(port_id, &link);
	else
		rte_eth_link_get(port_id, &link);

	port_cfg->link_up = link.link_status;
	port_cfg->link_speed = link.link_speed;

	if (link.link_status) {
		plog_info("Link Up - speed %'u Mbps - %s\n",
			  link.link_speed,
			  (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
			  "full-duplex" : "half-duplex");
	}
	else {
		plog_info("Link Down\n");
	}

	if (port_cfg->promiscuous) {
		rte_eth_promiscuous_enable(port_id);
		plog_info("\t\tport %u in promiscuous mode\n", port_id);
	}

	if (strcmp(port_cfg->short_name, "ixgbe_vf") &&
	    strcmp(port_cfg->short_name, "i40e") &&
	    strcmp(port_cfg->short_name, "i40e_vf") &&
	    strcmp(port_cfg->short_name, "vmxnet3")) {
		for (uint8_t i = 0; i < 16; ++i) {
			ret = rte_eth_dev_set_rx_queue_stats_mapping(port_id, i, i);
			if (ret) {
				plog_info("\t\trte_eth_dev_set_rx_queue_stats_mapping() failed: error %d\n", ret);
			}
			ret = rte_eth_dev_set_tx_queue_stats_mapping(port_id, i, i);
			if (ret) {
				plog_info("\t\trte_eth_dev_set_tx_queue_stats_mapping() failed: error %d\n", ret);
			}
		}
	}
}

void init_port_all(void)
{
	uint8_t max_port_idx = prox_last_port_active() + 1;

	for (uint8_t portid = 0; portid < max_port_idx; ++portid) {
		if (!prox_port_cfg[portid].active) {
			continue;
		}
		init_port(&prox_port_cfg[portid]);
	}
}

void close_ports_atexit(void)
{
	uint8_t max_port_idx = prox_last_port_active() + 1;

	for (uint8_t portid = 0; portid < max_port_idx; ++portid) {
		if (!prox_port_cfg[portid].active) {
			continue;
		}
		rte_eth_dev_close(portid);
	}
}

void init_port_addr(void)
{
	struct prox_port_cfg *port_cfg;

	for (uint8_t port_id = 0; port_id < PROX_MAX_PORTS; ++port_id) {
		if (!prox_port_cfg[port_id].active) {
			continue;
		}
		port_cfg = &prox_port_cfg[port_id];

		switch (port_cfg->type) {
		case PROX_PORT_MAC_HW:
			rte_eth_macaddr_get(port_id, &port_cfg->eth_addr);
			break;
		case PROX_PORT_MAC_RAND:
			eth_random_addr(port_cfg->eth_addr.addr_bytes);
			break;
		case PROX_PORT_MAC_SET:
			break;
		}
	}
}

int port_is_active(uint8_t port_id)
{
	if (port_id > PROX_MAX_PORTS) {
		plog_info("requested port is higher than highest supported port ID (%u)\n", PROX_MAX_PORTS);
		return 0;
	}

	struct prox_port_cfg* port_cfg = &prox_port_cfg[port_id];
	if (!port_cfg->active) {
		plog_info("Port %u is not active\n", port_id);
		return 0;
	}
	return 1;
}
