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

#ifndef _TASK_INIT_H_
#define _TASK_INIT_H_

#include <sys/queue.h>

#include <rte_common.h>
#include <rte_sched.h>
#include <rte_ether.h>
#include "task_base.h"
#include "prox_globals.h"
#include "ip6_addr.h"
#include "flow_iter.h"
#include "parse_utils.h"

struct rte_mbuf;
struct lcore_cfg;

#if MAX_RINGS_PER_TASK < PROX_MAX_PORTS
#error MAX_RINGS_PER_TASK < PROX_MAX_PORTS
#endif

#define TASK_ARG_DROP           0x01
#define TASK_ARG_RX_RING        0x02
#define TASK_ARG_RTE_TABLE      0x08
#define TASK_ARG_LOCAL_LPM      0x10
#define TASK_ARG_QINQ_ACL       0x20
#define TASK_ARG_CTRL_RINGS_P   0x40
#define TASK_ARG_DST_MAC_SET	0x80
#define TASK_ARG_SRC_MAC_SET	0x100
#define	TASK_ARG_DO_NOT_SET_SRC_MAC 0x200
#define	TASK_ARG_DO_NOT_SET_DST_MAC 0x400
#define	TASK_ARG_HW_SRC_MAC 	0x800
#define TASK_ARG_L3		0x1000

#define PROX_MODE_LEN	32

enum protocols {IPV4, ARP, IPV6};

struct qos_cfg {
	struct rte_sched_port_params port_params;
	struct rte_sched_subport_params subport_params[1];
	struct rte_sched_pipe_params pipe_params[1];
};

enum task_mode {NOT_SET, MASTER, QINQ_DECAP4, QINQ_DECAP6,
		QINQ_ENCAP4, QINQ_ENCAP6, GRE_DECAP, GRE_ENCAP,CGNAT, ESP_ENC, ESP_DEC,
};

struct task_args;

struct task_init {
	enum task_mode mode;
	char mode_str[PROX_MODE_LEN];
	char sub_mode_str[PROX_MODE_LEN];
	void (*early_init)(struct task_args *targ);
	void (*init)(struct task_base *tbase, struct task_args *targ);
	int (*handle)(struct task_base *tbase, struct rte_mbuf **mbufs, const uint16_t n_pkts);
	void (*start)(struct task_base *tbase);
	void (*stop)(struct task_base *tbase);
	void (*start_first)(struct task_base *tbase);
	void (*stop_last)(struct task_base *tbase);
	int (*thread_x)(struct lcore_cfg* lconf);
	struct flow_iter flow_iter;
	size_t size;
	uint16_t     flag_req_data; /* flags from prox_shared.h */
	uint64_t     flag_features;
	LIST_ENTRY(task_init) entries;
};

static int task_init_flag_set(struct task_init *task_init, uint64_t flag)
{
	return !!(task_init->flag_features & flag);
}

enum police_action {
        ACT_GREEN = e_RTE_METER_GREEN,
        ACT_YELLOW = e_RTE_METER_YELLOW,
        ACT_RED = e_RTE_METER_RED,
        ACT_DROP = 3,
	ACT_INVALID = 4
};

/* Configuration for task that is only used during startup. */
struct task_args {
	struct task_base       *tbase;
	struct task_init*       task_init;
	struct rte_mempool     *pool;
	char		       pool_name[MAX_NAME_SIZE];
	struct lcore_cfg       *lconf;
	uint32_t               nb_mbuf;
	uint32_t               mbuf_size;
	uint32_t               nb_cache_mbuf;
	uint8_t                nb_slave_threads;
	uint8_t		       nb_worker_threads;
	uint8_t		       worker_thread_id;
	uint8_t		       task;
	uint32_t               id;
	struct core_task_set   core_task_set[MAX_PROTOCOLS];
	struct task_args       *prev_tasks[MAX_RINGS_PER_TASK];
	uint32_t               n_prev_tasks;
	uint32_t               ring_size; /* default is RX_RING_SIZE */
	struct qos_cfg         qos_conf;
	uint32_t               flags;
	uint32_t               runtime_flags;
	uint8_t                nb_txports;
	uint8_t                nb_txrings;
	uint8_t                nb_rxrings;
	uint8_t                tot_rxrings;
	uint8_t                nb_rxports;
	uint32_t               byte_offset;
	uint32_t               gateway_ipv4;
	uint32_t               local_ipv4;
	uint32_t               remote_ipv4;
	uint32_t               arp_timeout;
	uint32_t               arp_update_time;
	struct ipv6_addr       local_ipv6;    /* For IPv6 Tunnel, it's the local tunnel endpoint address */
	struct rte_ring        *rx_rings[MAX_RINGS_PER_TASK];
	struct rte_ring        *tx_rings[MAX_RINGS_PER_TASK];
	struct rte_ring        *ctrl_plane_ring;
	uint32_t               tot_n_txrings_inited;
	struct ether_addr      edaddr;
	struct ether_addr      esaddr;
	struct port_queue      tx_port_queue[PROX_MAX_PORTS];
	struct port_queue      rx_port_queue[PROX_MAX_PORTS];
	/* Used to set up actual task at initialization time. */
	enum task_mode         mode;
	/* Destination output position in hw or sw when using mac learned dest port. */
	uint8_t                mapping[PROX_MAX_PORTS];
	struct rte_table_hash  *cpe_table;
	struct rte_table_hash  *qinq_gre_table;
	struct rte_hash        *cpe_gre_hash;
	struct rte_hash        *qinq_gre_hash;
	struct cpe_data        *cpe_data;
	struct cpe_gre_data    *cpe_gre_data;
	struct qinq_gre_data   *qinq_gre_data;
	uint8_t                tx_opt_ring;
	struct task_args       *tx_opt_ring_task;
	uint32_t               qinq_tag;

#ifdef ENABLE_EXTRA_USER_STATISTICS
	uint32_t               n_users;	// Number of users in user table.
#endif
	uint32_t               n_flows;	// Number of flows used in policing
	uint32_t               cir;
	uint32_t               cbs;
	uint32_t               ebs;
	uint32_t               pir;
	uint32_t               pbs;
	uint32_t               overhead;
	enum police_action     police_act[3][3];
	uint32_t               marking[4];
	uint32_t               n_max_rules;
	uint32_t               random_delay_us;
	uint32_t               delay_us;
	uint32_t               cpe_table_timeout_ms;
	uint32_t               etype;
#ifdef GRE_TP
	uint32_t tb_rate;                /**< Pipe token bucket rate (measured in bytes per second) */
	uint32_t tb_size;                /**< Pipe token bucket size (measured in credits) */
#endif
	uint8_t                tunnel_hop_limit;  /* IPv6 Tunnel - Hop limit */
        uint16_t               lookup_port_mask;  /* Ipv6 Tunnel - Mask applied to UDP/TCP port before lookup */
	uint32_t               ctrl_freq;
	uint8_t                lb_friend_core;
	uint8_t                lb_friend_task;
	/* gen related*/
	uint64_t               rate_bps;
	uint32_t               n_rand_str;
	char                   rand_str[64][64];
	uint32_t               rand_offset[64];
	char                   pcap_file[256];
	uint32_t               accur_pos;
	uint32_t               sig_pos;
	uint32_t               sig;
	uint32_t               lat_pos;
	uint32_t               packet_id_pos;
	uint32_t               latency_buffer_size;
	uint32_t               bucket_size;
	uint32_t               lat_enabled;
	uint32_t               pkt_size;
	uint8_t                pkt_inline[MAX_PKT_SIZE];
	uint32_t               probability;
	char                   nat_table[256];
	uint32_t               use_src;
	char                   route_table[256];
	char                   rules[256];
	char                   dscp[256];
	char                   tun_bindings[256];
	char                   cpe_table_name[256];
	char                   user_table[256];
	uint32_t               n_concur_conn;
	char                   streams[256];
	uint32_t               min_bulk_size;
	uint32_t               max_bulk_size;
	uint32_t               max_setup_rate;
	uint32_t               n_pkts;
	uint32_t               loop;
	uint32_t               flow_table_size;
	char                   dpi_engine_path[256];
	char                   dpi_engine_args[16][256];
	uint32_t               n_dpi_engine_args;
	uint32_t               generator_id;
	uint32_t               accuracy_limit_nsec;
	/* cgnat related */
	uint32_t                     public_ip_count;
	struct public_ip_config_info *public_ip_config_info;
	struct public_entry          *public_entries;
	struct private_flow_entry    *private_flow_entries;
	struct rte_hash              *public_ip_port_hash;
	struct rte_hash              *private_ip_port_hash;
	struct rte_hash              *private_ip_hash;
	struct private_ip_info       *private_ip_info;
	struct rte_ring			**ctrl_rx_rings;
	struct rte_ring			**ctrl_tx_rings;
	int				n_ctrl_rings;
	uint				irq_debug;
	struct task_base *tmaster;
	char sub_mode_str[PROX_MODE_LEN];
};

/* Return the first port that is reachable through the task. If the
   task itself does not send directly to a port, the function will
   search reachable tasks through each outgoing ring */
struct task_args *find_reachable_task_sending_to_port(struct task_args *from);
struct prox_port_cfg *find_reachable_port(struct task_args *from);

struct task_base *init_task_struct(struct task_args *targ);
struct task_init *to_task_init(const char *mode_str, const char *sub_mode_str);
void tasks_list(void);
int task_is_master(struct task_args *targ);

void reg_task(struct task_init* t);

#endif /* _TASK_INIT_H_ */
