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

#ifndef _PROX_PORT_CFG_H
#define _PROX_PORT_CFG_H

#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_version.h>
#if RTE_VERSION >= RTE_VERSION_NUM(17,11,0,0)
#include <rte_bus_pci.h>
#endif
#include <rte_pci.h>

#include "prox_globals.h"

enum addr_type {PROX_PORT_MAC_HW, PROX_PORT_MAC_SET, PROX_PORT_MAC_RAND};

#define IPV4_CKSUM	1
#define UDP_CKSUM	2

struct prox_port_cfg {
	struct rte_mempool *pool[32];  /* Rx/Tx mempool */
	size_t pool_size[32];
	uint8_t promiscuous;
	uint8_t lsc_set_explicitely; /* Explicitly enable/disable lsc */
	uint8_t lsc_val;
	uint8_t active;
	int socket;
	uint16_t max_rxq;         /* max number of Tx queues */
	uint16_t max_txq;         /* max number of Tx queues */
	uint16_t n_rxq;           /* number of used Rx queues */
	uint16_t n_txq;           /* number of used Tx queues */
	uint32_t n_rxd;
	uint32_t n_txd;
	uint8_t  link_up;
	uint32_t  link_speed;
	uint32_t  max_link_speed;
	uint32_t  mtu;
	enum addr_type    type;
	struct ether_addr eth_addr;    /* port MAC address */
	char name[MAX_NAME_SIZE];
	char short_name[MAX_NAME_SIZE];
	char driver_name[MAX_NAME_SIZE];
	char rx_ring[MAX_NAME_SIZE];
	char tx_ring[MAX_NAME_SIZE];
	char pci_addr[32];
	struct rte_eth_conf port_conf;
	struct rte_eth_rxconf rx_conf;
	struct rte_eth_txconf tx_conf;
	uint64_t requested_rx_offload;
	uint64_t requested_tx_offload;
	uint64_t disabled_tx_offload;
	struct rte_eth_dev_info dev_info;
	struct {
		int tx_offload_cksum;
	} capabilities;
	uint32_t max_rx_pkt_len;
	uint32_t min_rx_bufsize;
};

extern rte_atomic32_t lsc;

int prox_nb_active_ports(void);
int prox_last_port_active(void);

extern struct prox_port_cfg prox_port_cfg[];

void init_rte_dev(int use_dummy_devices);
uint8_t init_rte_ring_dev(void);
void init_port_addr(void);
void init_port_all(void);
void close_ports_atexit(void);

struct rte_mempool;

void prox_pktmbuf_init(struct rte_mempool *mp, void *opaque_arg, void *_m, unsigned i);
void prox_pktmbuf_reinit(void *arg, void *start, void *end, uint32_t idx);

int port_is_active(uint8_t port_id);

#endif /* __PROX_PORT_CFG_H_ */
