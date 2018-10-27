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
#include <libgen.h>
#include <rte_sched.h>
#include <rte_version.h>

#include "lconf.h"
#include "defaults.h"
#include "defines.h"
#include "prox_cfg.h"
#include "prox_port_cfg.h"
#include "etypes.h"
#include "toeplitz.h"
#include "handle_master.h"
#include "prox_compat.h"

#define TEN_GIGABIT     1250000000
#define QUEUE_SIZES     128
#define NB_PIPES        32768
#define NB_MBUF         4096
#define RING_RX_SIZE    256
#define NB_RX_RING_DESC 256
#define NB_TX_RING_DESC 256

/* 1500000 milliseconds */
#define DEFAULT_CPE_TIMEOUT_MS    1500000

/**/
#if DEFAULT_CPE_TIMEOUT_MS < (DRAIN_TIMEOUT/3000000)
#error DEFAULT_CPE_TIMEOUT_MS too small (needs to be at least 2 ms)
#endif

static const struct rte_eth_conf default_port_conf = {
	.rxmode = {
		.mq_mode        = 0,
		.max_rx_pkt_len = PROX_MTU + ETHER_HDR_LEN + ETHER_CRC_LEN
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
		},
	},
	.intr_conf = {
		.lsc = 1, /* lsc interrupt feature enabled */
	},
};

static const struct rte_eth_rxconf default_rx_conf = {
	.rx_free_thresh = 32,
};

static struct rte_eth_txconf default_tx_conf = {
	.tx_thresh = {
		.pthresh = 32,
		.hthresh = 8,
		.wthresh = 0,
	},
	.tx_free_thresh = 32, /* Use PMD default values */
	.tx_rs_thresh = 32, /* Use PMD default values */
};

static struct rte_sched_port_params port_params_default = {
	.name = "port_0",
	.socket = 0,
	.mtu = 6 + 6 + 4 + 4 + 2 + 1500,
	.rate = 0,
	.frame_overhead = RTE_SCHED_FRAME_OVERHEAD_DEFAULT,
	.n_subports_per_port = 1,
	.n_pipes_per_subport = NB_PIPES,
	.qsize = {QUEUE_SIZES, QUEUE_SIZES, QUEUE_SIZES, QUEUE_SIZES},
	.pipe_profiles = NULL,
	.n_pipe_profiles = 1 /* only one profile */
};

static struct rte_sched_pipe_params pipe_params_default = {
	.tb_rate = TEN_GIGABIT / NB_PIPES,
	.tb_size = 4000000,

	.tc_rate = {TEN_GIGABIT / NB_PIPES, TEN_GIGABIT / NB_PIPES, TEN_GIGABIT / NB_PIPES, TEN_GIGABIT / NB_PIPES},
	.tc_period = 40,

	.wrr_weights = {1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1},
};

static struct rte_sched_subport_params subport_params_default = {
	.tb_rate = TEN_GIGABIT,
	.tb_size = 4000000,
	.tc_rate = {TEN_GIGABIT, TEN_GIGABIT, TEN_GIGABIT, TEN_GIGABIT},
	.tc_period = 40, /* default was 10 */
};

void set_global_defaults(__attribute__((unused)) struct prox_cfg *prox_cfg)
{
}

void set_task_defaults(struct prox_cfg* prox_cfg, struct lcore_cfg* lcore_cfg_init)
{
	prox_cfg->master = RTE_MAX_LCORE;
	handle_ctrl_plane = NULL;

	for (uint32_t i = 0; i < RTE_DIM(prox_cfg->cpe_table_ports); ++i) {
		prox_cfg->cpe_table_ports[i] = -1;
	}

	for (uint8_t lcore_id = 0; lcore_id < RTE_MAX_LCORE; ++lcore_id) {
		struct lcore_cfg *cur_lcore_cfg_init = &lcore_cfg_init[lcore_id];
		cur_lcore_cfg_init->id = lcore_id;
		for (uint8_t task_id = 0; task_id < MAX_TASKS_PER_CORE; ++task_id) {
			struct task_args *targ = &cur_lcore_cfg_init->targs[task_id];
			for (uint8_t port_id = 0; port_id < PROX_MAX_PORTS; ++port_id) {
				targ->rx_port_queue[port_id].port = OUT_DISCARD;
			}
			targ->flags |= TASK_ARG_DROP;
			targ->flags |= TASK_ARG_QINQ_ACL;
			targ->cpe_table_timeout_ms = DEFAULT_CPE_TIMEOUT_MS;
			targ->n_flows = NB_PIPES;
			/* configure default values for QoS (can be overwritten by config) */
			targ->qos_conf.port_params = port_params_default;
			targ->qos_conf.pipe_params[0] = pipe_params_default;
			targ->qos_conf.subport_params[0] = subport_params_default;
			targ->qos_conf.port_params.pipe_profiles = targ->qos_conf.pipe_params;
			targ->qos_conf.port_params.rate = TEN_GIGABIT;
			targ->qinq_tag = ETYPE_8021ad;
			targ->n_concur_conn = 8192*2;

			for (uint8_t port_id = 0; port_id < PROX_MAX_PORTS; ++port_id) {
				targ->tx_port_queue[port_id].port = OUT_DISCARD;
			}

			for (uint8_t i = 0; i < PROX_MAX_PORTS; ++i) {
				targ->mapping[i] = i; // identity
			}

			targ->cbs = ETHER_MAX_LEN;
			targ->ebs = ETHER_MAX_LEN;
			targ->pbs = ETHER_MAX_LEN;

			targ->n_max_rules = 1024;
			targ->ring_size = RING_RX_SIZE;
			targ->nb_cache_mbuf = MAX_PKT_BURST * 4;
			targ->overhead = ETHER_CRC_LEN + 20;

			targ->tunnel_hop_limit = 3;
			targ->ctrl_freq = 1000;
			targ->lb_friend_core = 0xFF;
			targ->n_pkts = 1024*64;
			targ->runtime_flags |= TASK_TX_CRC;
			targ->accuracy_limit_nsec = 5000;
		}
	}
}

void set_port_defaults(void)
{
	for (uint8_t i = 0; i < PROX_MAX_PORTS; ++i ) {
		prox_port_cfg[i].promiscuous = 1;
		prox_port_cfg[i].n_rxd = NB_RX_RING_DESC;
		prox_port_cfg[i].n_txd = NB_TX_RING_DESC;
		prox_port_cfg[i].port_conf = default_port_conf;
		prox_port_cfg[i].tx_conf = default_tx_conf;
		prox_port_cfg[i].rx_conf = default_rx_conf;
		prox_port_cfg[i].rx_ring[0] = '\0';
		prox_port_cfg[i].tx_ring[0] = '\0';
		prox_port_cfg[i].mtu = PROX_MTU;
		prox_port_cfg[i].requested_rx_offload = DEV_RX_OFFLOAD_CRC_STRIP;
		prox_port_cfg[i].requested_tx_offload = DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM;
	}
}
