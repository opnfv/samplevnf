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
#include <stddef.h>

#include "stats_parser.h"
#include "log.h"
#include "stats.h"
#include "parse_utils.h"
#include "handle_lat.h"
#include "prox_port_cfg.h"
#include "stats_port.h"
#include "stats_mempool.h"
#include "stats_ring.h"
#include "stats_l4gen.h"
#include "stats_latency.h"
#include "stats_global.h"
#include "stats_prio_task.h"
#include "stats_irq.h"

struct stats_path_str {
	const char *str;
	uint64_t (*func)(int argc, const char *argv[]);
};

static int args_to_core_task(const char *core_str, const char *task_str, uint32_t *lcore_id, uint32_t *task_id)
{
	if (parse_list_set(lcore_id, core_str, 1) != 1)
		return -1;
	*task_id = atoi(task_str);

	return 0;
}

static uint64_t sp_task_idle_cycles(int argc, const char *argv[])
{
	struct task_stats_sample *last;
	uint32_t c, t;

	if (args_to_core_task(argv[0], argv[1], &c, &t))
		return -1;
	return stats_get_task_stats_sample(c, t, 1)->tsc;
}

static uint64_t sp_task_rx_packets(int argc, const char *argv[])
{
	struct task_stats_sample *last;
	uint32_t c, t;

	if (args_to_core_task(argv[0], argv[1], &c, &t))
		return -1;
	return stats_get_task_stats_sample(c, t, 1)->rx_pkt_count;
}

static uint64_t sp_task_tx_packets(int argc, const char *argv[])
{
	struct task_stats_sample *last;
	uint32_t c, t;

	if (args_to_core_task(argv[0], argv[1], &c, &t))
		return -1;
	return stats_get_task_stats_sample(c, t, 1)->tx_pkt_count;
}

static uint64_t sp_task_drop_tx_fail(int argc, const char *argv[])
{
	struct task_stats_sample *last;
	uint32_t c, t;

	if (args_to_core_task(argv[0], argv[1], &c, &t))
		return -1;
	return stats_get_task_stats_sample(c, t, 1)->drop_tx_fail;
}

static uint64_t sp_task_drop_tx_fail_prio(int argc, const char *argv[])
{
	struct task_stats_sample *last;
	uint32_t c, t;

	if (args_to_core_task(argv[0], argv[1], &c, &t))
		return -1;
	if (stats_get_prio_task_stats_sample_by_core_task(c, t, 1))
		return stats_get_prio_task_stats_sample_by_core_task(c, t, 1)->drop_tx_fail_prio[atoi(argv[2])];
	else
		return -1;
}

static uint64_t sp_task_rx_prio(int argc, const char *argv[])
{
	struct task_stats_sample *last;
	uint32_t c, t;

	if (args_to_core_task(argv[0], argv[1], &c, &t))
		return -1;
	return stats_get_prio_task_stats_sample_by_core_task(c, t, 1)->rx_prio[atoi(argv[2])];
}

static uint64_t sp_task_max_irq(int argc, const char *argv[])
{
	struct task_stats_sample *last;
	uint32_t c, t;

	if (args_to_core_task(argv[0], argv[1], &c, &t))
		return -1;
	return get_max_irq_stats_by_core_task(c, t);
}

static uint64_t sp_task_irq(int argc, const char *argv[])
{
	struct task_stats_sample *last;
	uint32_t c, t;

	if (args_to_core_task(argv[0], argv[1], &c, &t))
		return -1;
	return get_irq_stats_by_core_task(c, t, atoi(argv[2]));
}

static uint64_t sp_task_drop_discard(int argc, const char *argv[])
{
	struct task_stats_sample *last;
	uint32_t c, t;

	if (args_to_core_task(argv[0], argv[1], &c, &t))
		return -1;
	return stats_get_task_stats_sample(c, t, 1)->drop_discard;
}

static uint64_t sp_task_drop_handled(int argc, const char *argv[])
{
	struct task_stats_sample *last;
	uint32_t c, t;

	if (args_to_core_task(argv[0], argv[1], &c, &t))
		return -1;
	return stats_get_task_stats_sample(c, t, 1)->drop_handled;
}

static uint64_t sp_task_rx_non_dp(int argc, const char *argv[])
{
	struct task_stats_sample *last;
	uint32_t c, t;
	if (args_to_core_task(argv[0], argv[1], &c, &t))
		return -1;
	return stats_get_task_stats_sample(c, t, 1)->rx_non_dp;
}

static uint64_t sp_task_tx_non_dp(int argc, const char *argv[])
{
	struct task_stats_sample *last;
	uint32_t c, t;
	if (args_to_core_task(argv[0], argv[1], &c, &t))
		return -1;
	return stats_get_task_stats_sample(c, t, 1)->tx_non_dp;
}
static uint64_t sp_task_rx_bytes(int argc, const char *argv[])
{
	return -1;
}

static uint64_t sp_task_tx_bytes(int argc, const char *argv[])
{
	return -1;
}

static uint64_t sp_task_tsc(int argc, const char *argv[])
{
	struct task_stats_sample *last;
	uint32_t c, t;

	if (args_to_core_task(argv[0], argv[1], &c, &t))
		return -1;
	return stats_get_task_stats_sample(c, t, 1)->tsc;
}

static uint64_t sp_l4gen_created(int argc, const char *argv[])
{
	struct l4_stats_sample *clast = NULL;

	if (atoi(argv[0]) >= stats_get_n_l4gen())
		return -1;
	clast = stats_get_l4_stats_sample(atoi(argv[0]), 1);
	return clast->stats.tcp_created + clast->stats.udp_created;
}

static uint64_t sp_l4gen_finished(int argc, const char *argv[])
{
	struct l4_stats_sample *clast = NULL;

	if (atoi(argv[0]) >= stats_get_n_l4gen())
		return -1;
	clast = stats_get_l4_stats_sample(atoi(argv[0]), 1);
	return clast->stats.tcp_finished_retransmit + clast->stats.tcp_finished_no_retransmit +
		clast->stats.udp_finished + clast->stats.udp_expired + clast->stats.tcp_expired;
}

static uint64_t sp_l4gen_expire_tcp(int argc, const char *argv[])
{
	struct l4_stats_sample *clast = NULL;

	if (atoi(argv[0]) >= stats_get_n_l4gen())
		return -1;
	clast = stats_get_l4_stats_sample(atoi(argv[0]), 1);
	return 	clast->stats.tcp_expired;
}

static uint64_t sp_l4gen_expire_udp(int argc, const char *argv[])
{
	struct l4_stats_sample *clast = NULL;

	if (atoi(argv[0]) >= stats_get_n_l4gen())
		return -1;
	clast = stats_get_l4_stats_sample(atoi(argv[0]), 1);
	return clast->stats.udp_expired;
}

static uint64_t sp_l4gen_retx(int argc, const char *argv[])
{
	struct l4_stats_sample *clast = NULL;

	if (atoi(argv[0]) >= stats_get_n_l4gen())
		return -1;
	clast = stats_get_l4_stats_sample(atoi(argv[0]), 1);
	return clast->stats.tcp_retransmits;
}

static uint64_t sp_l4gen_tsc(int argc, const char *argv[])
{
	struct l4_stats_sample *clast = NULL;

	if (atoi(argv[0]) >= stats_get_n_l4gen())
		return -1;
	clast = stats_get_l4_stats_sample(atoi(argv[0]), 1);
	return clast->tsc;
}

static uint64_t sp_l4gen_torndown_no_retx(int argc, const char *argv[])
{
	struct l4_stats_sample *clast = NULL;

	if (atoi(argv[0]) >= stats_get_n_l4gen())
		return -1;
	clast = stats_get_l4_stats_sample(atoi(argv[0]), 1);
	return clast->stats.tcp_finished_no_retransmit;
}

static uint64_t sp_l4gen_torndown_retx(int argc, const char *argv[])
{
	struct l4_stats_sample *clast = NULL;

	if (atoi(argv[0]) >= stats_get_n_l4gen())
		return -1;
	clast = stats_get_l4_stats_sample(atoi(argv[0]), 1);
	return clast->stats.tcp_finished_retransmit;
}

static uint64_t sp_l4gen_torndown_udp(int argc, const char *argv[])
{
	struct l4_stats_sample *clast = NULL;

	if (atoi(argv[0]) >= stats_get_n_l4gen())
		return -1;
	clast = stats_get_l4_stats_sample(atoi(argv[0]), 1);
	return clast->stats.udp_finished;
}

static uint64_t sp_l4gen_created_tcp(int argc, const char *argv[])
{
	struct l4_stats_sample *clast = NULL;

	if (atoi(argv[0]) >= stats_get_n_l4gen())
		return -1;
	clast = stats_get_l4_stats_sample(atoi(argv[0]), 1);
	return clast->stats.tcp_created;

}

static uint64_t sp_l4gen_created_udp(int argc, const char *argv[])
{
	struct l4_stats_sample *clast = NULL;

	if (atoi(argv[0]) >= stats_get_n_l4gen())
		return -1;
	clast = stats_get_l4_stats_sample(atoi(argv[0]), 1);
	return clast->stats.udp_created;
}

static uint64_t sp_l4gen_created_all(int argc, const char *argv[])
{
	struct l4_stats_sample *clast = NULL;

	if (atoi(argv[0]) >= stats_get_n_l4gen())
		return -1;
	clast = stats_get_l4_stats_sample(atoi(argv[0]), 1);
	return clast->stats.tcp_created + clast->stats.udp_created;
}

static uint64_t sp_l4gen_created_bundles(int argc, const char *argv[])
{
	struct l4_stats_sample *clast = NULL;

	if (atoi(argv[0]) >= stats_get_n_l4gen())
		return -1;
	clast = stats_get_l4_stats_sample(atoi(argv[0]), 1);
	return clast->stats.bundles_created;
}

static uint64_t sp_latency_min(int argc, const char *argv[])
{
	struct stats_latency *lat_test = NULL;

	if (atoi(argv[0]) >= stats_get_n_latency())
		return -1;
	lat_test = stats_latency_get(atoi(argv[0]));

	if (!lat_test->tot_packets)
		return -1;

	struct time_unit tu = lat_test->min.time;
	return time_unit_to_usec(&tu);
}

static uint64_t sp_mem_used(int argc, const char *argv[])
{
	struct mempool_stats *ms;

	if (atoi(argv[0]) > stats_get_n_mempools())
		return -1;
	ms = stats_get_mempool_stats(atoi(argv[0]));
	return ms->size - ms->free;
}

static uint64_t sp_mem_free(int argc, const char *argv[])
{
	struct mempool_stats *ms;

	if (atoi(argv[0]) > stats_get_n_mempools())
		return -1;
	ms = stats_get_mempool_stats(atoi(argv[0]));
	return ms->free;
}

static uint64_t sp_mem_size(int argc, const char *argv[])
{
	struct mempool_stats *ms;

	if (atoi(argv[0]) > stats_get_n_mempools())
		return -1;
	ms = stats_get_mempool_stats(atoi(argv[0]));
	return ms->size;
}

static uint64_t sp_port_no_mbufs(int argc, const char *argv[])
{
	uint32_t port_id = atoi(argv[0]);
	struct port_stats_sample *ps;

	if (port_id > PROX_MAX_PORTS || !prox_port_cfg[port_id].active)
		return -1;
	ps = stats_get_port_stats_sample(port_id, 1);
	return ps->no_mbufs;
}

static uint64_t sp_port_ierrors(int argc, const char *argv[])
{
	uint32_t port_id = atoi(argv[0]);
	struct port_stats_sample *ps;

	if (port_id > PROX_MAX_PORTS || !prox_port_cfg[port_id].active)
		return -1;
	ps = stats_get_port_stats_sample(port_id, 1);
	return ps->ierrors;
}

static uint64_t sp_port_imissed(int argc, const char *argv[])
{
	uint32_t port_id = atoi(argv[0]);
	struct port_stats_sample *ps;

	if (port_id > PROX_MAX_PORTS || !prox_port_cfg[port_id].active)
		return -1;
	ps = stats_get_port_stats_sample(port_id, 1);
	return ps->imissed;
}

static uint64_t sp_port_oerrors(int argc, const char *argv[])
{
	uint32_t port_id = atoi(argv[0]);
	struct port_stats_sample *ps;

	if (port_id > PROX_MAX_PORTS || !prox_port_cfg[port_id].active)
		return -1;
	ps = stats_get_port_stats_sample(port_id, 1);
	return ps->oerrors;
}

static uint64_t sp_port_rx_packets(int argc, const char *argv[])
{
	uint32_t port_id = atoi(argv[0]);
	struct port_stats_sample *ps;

	if (port_id > PROX_MAX_PORTS || !prox_port_cfg[port_id].active)
		return -1;
	ps = stats_get_port_stats_sample(port_id, 1);
	return ps->rx_tot;
}

static uint64_t sp_port_tx_packets(int argc, const char *argv[])
{
	uint32_t port_id = atoi(argv[0]);
	struct port_stats_sample *ps;

	if (port_id > PROX_MAX_PORTS || !prox_port_cfg[port_id].active)
		return -1;
	ps = stats_get_port_stats_sample(port_id, 1);
	return ps->tx_tot;
}

static uint64_t sp_port_rx_bytes(int argc, const char *argv[])
{
	uint32_t port_id = atoi(argv[0]);
	struct port_stats_sample *ps;

	if (port_id > PROX_MAX_PORTS || !prox_port_cfg[port_id].active)
		return -1;
	ps = stats_get_port_stats_sample(port_id, 1);
	return ps->rx_bytes;
}

static uint64_t sp_port_tx_bytes(int argc, const char *argv[])
{
	uint32_t port_id = atoi(argv[0]);
	struct port_stats_sample *ps;

	if (port_id > PROX_MAX_PORTS || !prox_port_cfg[port_id].active)
		return -1;
	ps = stats_get_port_stats_sample(port_id, 1);
	return ps->tx_bytes;
}

static uint64_t sp_port_tx_packets_64(int argc, const char *argv[])
{
	uint32_t port_id = atoi(argv[0]);
	struct port_stats_sample *ps;

	if (port_id > PROX_MAX_PORTS || !prox_port_cfg[port_id].active)
		return -1;
	ps = stats_get_port_stats_sample(port_id, 1);
	return ps->tx_pkt_size[PKT_SIZE_64];
}

static uint64_t sp_port_tx_packets_65_127(int argc, const char *argv[])
{
	uint32_t port_id = atoi(argv[0]);
	struct port_stats_sample *ps;

	if (port_id > PROX_MAX_PORTS || !prox_port_cfg[port_id].active)
		return -1;
	ps = stats_get_port_stats_sample(port_id, 1);
	return ps->tx_pkt_size[PKT_SIZE_65];
}

static uint64_t sp_port_tx_packets_128_255(int argc, const char *argv[])
{
	uint32_t port_id = atoi(argv[0]);
	struct port_stats_sample *ps;

	if (port_id > PROX_MAX_PORTS || !prox_port_cfg[port_id].active)
		return -1;
	ps = stats_get_port_stats_sample(port_id, 1);
	return ps->tx_pkt_size[PKT_SIZE_128];
}

static uint64_t sp_port_tx_packets_256_511(int argc, const char *argv[])
{
	uint32_t port_id = atoi(argv[0]);
	struct port_stats_sample *ps;

	if (port_id > PROX_MAX_PORTS || !prox_port_cfg[port_id].active)
		return -1;
	ps = stats_get_port_stats_sample(port_id, 1);
	return ps->tx_pkt_size[PKT_SIZE_256];
}

static uint64_t sp_port_tx_packets_512_1023(int argc, const char *argv[])
{
	uint32_t port_id = atoi(argv[0]);
	struct port_stats_sample *ps;

	if (port_id > PROX_MAX_PORTS || !prox_port_cfg[port_id].active)
		return -1;
	ps = stats_get_port_stats_sample(port_id, 1);
	return ps->tx_pkt_size[PKT_SIZE_512];
}

static uint64_t sp_port_tx_packets_1024_1522(int argc, const char *argv[])
{
	uint32_t port_id = atoi(argv[0]);
	struct port_stats_sample *ps;

	if (port_id > PROX_MAX_PORTS || !prox_port_cfg[port_id].active)
		return -1;
	ps = stats_get_port_stats_sample(port_id, 1);
	return ps->tx_pkt_size[PKT_SIZE_1024];
}

static uint64_t sp_port_tx_packets_1523_max(int argc, const char *argv[])
{
	uint32_t port_id = atoi(argv[0]);
	struct port_stats_sample *ps;

	if (port_id > PROX_MAX_PORTS || !prox_port_cfg[port_id].active)
		return -1;
	ps = stats_get_port_stats_sample(port_id, 1);
	return ps->tx_pkt_size[PKT_SIZE_1522];
}

static uint64_t sp_port_tsc(int argc, const char *argv[])
{
	uint32_t port_id = atoi(argv[0]);
	struct port_stats_sample *ps;

	if (port_id > PROX_MAX_PORTS || !prox_port_cfg[port_id].active)
		return -1;
	ps = stats_get_port_stats_sample(port_id, 1);
	return ps->tsc;
}

static uint64_t sp_latency_max(int argc, const char *argv[])
{
	struct stats_latency *lat_test = NULL;

	if (atoi(argv[0]) >= stats_get_n_latency())
		return -1;
	lat_test = stats_latency_get(atoi(argv[0]));

	if (!lat_test->tot_packets)
		return -1;

	struct time_unit tu = lat_test->max.time;
	return time_unit_to_usec(&tu);
}

static uint64_t sp_latency_avg(int argc, const char *argv[])
{
	struct stats_latency *lat_test = NULL;

	if (atoi(argv[0]) >= stats_get_n_latency())
		return -1;
	lat_test = stats_latency_get(atoi(argv[0]));

	if (!lat_test->tot_packets)
		return -1;

	struct time_unit tu = lat_test->avg.time;
	return time_unit_to_usec(&tu);
}

static uint64_t sp_latency_lost(int argc, const char *argv[])
{
	struct stats_latency *lat_test = NULL;

	if (atoi(argv[0]) >= stats_get_n_latency())
		return -1;
	lat_test = stats_latency_get(atoi(argv[0]));

	if (!lat_test->tot_packets)
		return -1;

	return lat_test->lost_packets;
}

static uint64_t sp_latency_tot_lost(int argc, const char *argv[])
{
	struct stats_latency *lat_test = NULL;

	if (atoi(argv[0]) >= stats_get_n_latency())
		return -1;
	lat_test = stats_latency_tot_get(atoi(argv[0]));

	if (!lat_test->tot_packets)
		return -1;

	return lat_test->lost_packets;
}

static uint64_t sp_latency_total(int argc, const char *argv[])
{
	struct stats_latency *lat_test = NULL;

	if (atoi(argv[0]) >= stats_get_n_latency())
		return -1;
	lat_test = stats_latency_get(atoi(argv[0]));

	if (!lat_test->tot_all_packets)
		return -1;

	return lat_test->tot_all_packets;
}

static uint64_t sp_latency_used(int argc, const char *argv[])
{
	struct stats_latency *lat_test = NULL;

	if (atoi(argv[0]) >= stats_get_n_latency())
		return -1;
	lat_test = stats_latency_get(atoi(argv[0]));

	if (!lat_test->tot_all_packets)
		return -1;

	return lat_test->tot_packets;
}

static uint64_t sp_latency_tot_total(int argc, const char *argv[])
{
	struct stats_latency *lat_test = NULL;

	if (atoi(argv[0]) >= stats_get_n_latency())
		return -1;
	lat_test = stats_latency_tot_get(atoi(argv[0]));

	if (!lat_test->tot_all_packets)
		return -1;

	return lat_test->tot_all_packets;
}

static uint64_t sp_latency_tot_used(int argc, const char *argv[])
{
	struct stats_latency *lat_test = NULL;

	if (atoi(argv[0]) >= stats_get_n_latency())
		return -1;
	lat_test = stats_latency_tot_get(atoi(argv[0]));

	if (!lat_test->tot_all_packets)
		return -1;

	return lat_test->tot_packets;
}

static uint64_t sp_latency_tot_min(int argc, const char *argv[])
{
	struct stats_latency *lat_test = NULL;

	if (atoi(argv[0]) >= stats_get_n_latency())
		return -1;
	lat_test = stats_latency_tot_get(atoi(argv[0]));

	if (!lat_test->tot_packets)
		return -1;

	struct time_unit tu = lat_test->min.time;
	return time_unit_to_usec(&tu);
}

static uint64_t sp_latency_tot_max(int argc, const char *argv[])
{
	struct stats_latency *lat_test = NULL;

	if (atoi(argv[0]) >= stats_get_n_latency())
		return -1;
	lat_test = stats_latency_tot_get(atoi(argv[0]));

	if (!lat_test->tot_packets)
		return -1;

	struct time_unit tu = lat_test->max.time;
	return time_unit_to_usec(&tu);
}

static uint64_t sp_latency_tot_avg(int argc, const char *argv[])
{
	struct stats_latency *lat_test = NULL;

	if (atoi(argv[0]) >= stats_get_n_latency())
		return -1;
	lat_test = stats_latency_tot_get(atoi(argv[0]));

	if (!lat_test->tot_packets)
		return -1;

	struct time_unit tu = lat_test->avg.time;
	return time_unit_to_usec(&tu);
}

static uint64_t sp_latency_stddev(int argc, const char *argv[])
{
	struct stats_latency *lat_test = NULL;

	if (atoi(argv[0]) >= stats_get_n_latency())
		return -1;
	lat_test = stats_latency_get(atoi(argv[0]));

	if (!lat_test->tot_packets)
		return -1;

	struct time_unit tu = lat_test->stddev.time;
	return time_unit_to_usec(&tu);
}

static uint64_t sp_ring_used(int argc, const char *argv[])
{
	struct ring_stats *rs = NULL;

	if (atoi(argv[0]) >= stats_get_n_rings())
		return -1;
	rs = stats_get_ring_stats(atoi(argv[0]));
	return rs->size - rs->free;
}

static uint64_t sp_ring_free(int argc, const char *argv[])
{
	struct ring_stats *rs = NULL;

	if (atoi(argv[0]) >= stats_get_n_rings())
		return -1;
	rs = stats_get_ring_stats(atoi(argv[0]));
	return rs->free;
}

static uint64_t sp_ring_size(int argc, const char *argv[])
{
	struct ring_stats *rs = NULL;

	if (atoi(argv[0]) >= stats_get_n_rings())
		return -1;
	rs = stats_get_ring_stats(atoi(argv[0]));
	return rs->size;
}

static uint64_t sp_global_host_rx_packets(int argc, const char *argv[])
{
	return stats_get_global_stats(1)->host_rx_packets;
}

static uint64_t sp_global_host_tx_packets(int argc, const char *argv[])
{
	return stats_get_global_stats(1)->host_tx_packets;
}

static uint64_t sp_global_nics_rx_packets(int argc, const char *argv[])
{
	return stats_get_global_stats(1)->nics_rx_packets;
}

static uint64_t sp_global_nics_tx_packets(int argc, const char *argv[])
{
	return stats_get_global_stats(1)->nics_tx_packets;
}

static uint64_t sp_global_nics_ierrors(int argc, const char *argv[])
{
	return stats_get_global_stats(1)->nics_ierrors;
}

static uint64_t sp_global_nics_imissed(int argc, const char *argv[])
{
	return stats_get_global_stats(1)->nics_imissed;
}

static uint64_t sp_global_tsc(int argc, const char *argv[])
{
	return stats_get_global_stats(1)->tsc;
}

static uint64_t sp_hz(int argc, const char *argv[])
{
	return rte_get_tsc_hz();
}

struct stats_path_str stats_paths[] = {
	{"hz", sp_hz},

	{"global.host.rx.packets", sp_global_host_rx_packets},
	{"global.host.tx.packets", sp_global_host_tx_packets},
	{"global.nics.rx.packets", sp_global_nics_rx_packets},
	{"global.nics.tx.packets", sp_global_nics_tx_packets},
	{"global.nics.ierrrors", sp_global_nics_ierrors},
	{"global.nics.imissed", sp_global_nics_imissed},
	{"global.tsc", sp_global_tsc},

	{"task.core(#).task(#).idle_cycles", sp_task_idle_cycles},
	{"task.core(#).task(#).rx.packets", sp_task_rx_packets},
	{"task.core(#).task(#).tx.packets", sp_task_tx_packets},
	{"task.core(#).task(#).drop.tx_fail", sp_task_drop_tx_fail},
	{"task.core(#).task(#).drop.discard", sp_task_drop_discard},
	{"task.core(#).task(#).drop.handled", sp_task_drop_handled},
	{"task.core(#).task(#).rx.bytes", sp_task_rx_bytes},
	{"task.core(#).task(#).tx.bytes", sp_task_tx_bytes},
	{"task.core(#).task(#).tsc", sp_task_tsc},
	{"task.core(#).task(#).drop.tx_fail_prio(#)", sp_task_drop_tx_fail_prio},
	{"task.core(#).task(#).rx_prio(#)", sp_task_rx_prio},
	{"task.core(#).task(#).max_irq", sp_task_max_irq},
	{"task.core(#).task(#).irq(#)", sp_task_irq},
	{"task.core(#).task(#).rx_non_dp", sp_task_rx_non_dp},
	{"task.core(#).task(#).tx_non_dp", sp_task_tx_non_dp},

	{"port(#).no_mbufs", sp_port_no_mbufs},
	{"port(#).ierrors", sp_port_ierrors},
	{"port(#).imissed", sp_port_imissed},
	{"port(#).oerrors", sp_port_oerrors},
	{"port(#).rx.packets", sp_port_rx_packets},
	{"port(#).tx.packets", sp_port_tx_packets},
	{"port(#).rx.bytes", sp_port_rx_bytes},
	{"port(#).tx.bytes", sp_port_tx_bytes},
	{"port(#).tx.packets_64", sp_port_tx_packets_64},
	{"port(#).tx.packets_65_127", sp_port_tx_packets_65_127},
	{"port(#).tx.packets_128_255", sp_port_tx_packets_128_255},
	{"port(#).tx.packets_256_511", sp_port_tx_packets_256_511},
	{"port(#).tx.packets_512_1023", sp_port_tx_packets_512_1023},
	{"port(#).tx.packets_1024_1522", sp_port_tx_packets_1024_1522},
	{"port(#).tx.packets_1523_max", sp_port_tx_packets_1523_max},
	{"port(#).tsc", sp_port_tsc},

	{"mem(#).used", sp_mem_used},
	{"mem(#).free", sp_mem_free},
	{"mem(#).size", sp_mem_size},

	{"latency(#).min", sp_latency_min},
	{"latency(#).max", sp_latency_max},
	{"latency(#).avg", sp_latency_avg},
	{"latency(#).lost", sp_latency_lost},
	{"latency(#).used", sp_latency_used},
	{"latency(#).total", sp_latency_total},
	{"latency(#).tot.min", sp_latency_tot_min},
	{"latency(#).tot.max", sp_latency_tot_max},
	{"latency(#).tot.avg", sp_latency_tot_avg},
	{"latency(#).tot.lost", sp_latency_tot_lost},
	{"latency(#).tot.used", sp_latency_tot_used},
	{"latency(#).tot.total", sp_latency_tot_total},
	{"latency(#).stddev", sp_latency_stddev},

	{"ring(#).used", sp_ring_used},
	{"ring(#).free", sp_ring_free},
	{"ring(#).size", sp_ring_size},

	{"l4gen(#).created.tcp", sp_l4gen_created_tcp},
	{"l4gen(#).created.udp", sp_l4gen_created_udp},
	{"l4gen(#).created.all", sp_l4gen_created_all},
	{"l4gen(#).created.bundles", sp_l4gen_created_bundles},
	{"l4gen(#).torndown.no_retx", sp_l4gen_torndown_no_retx},
	{"l4gen(#).torndown.retx", sp_l4gen_torndown_retx},
	{"l4gen(#).torndown.udp", sp_l4gen_torndown_udp},
	{"l4gen(#).expired.tcp", sp_l4gen_expire_tcp},
	{"l4gen(#).expired.udp", sp_l4gen_expire_udp},
	{"l4gen(#).created", sp_l4gen_created},
	{"l4gen(#).finished", sp_l4gen_finished},
	{"l4gen(#).retx", sp_l4gen_retx},
	{"l4gen(#).tsc", sp_l4gen_tsc},
};

static int stats_parser_extract_args(char *stats_path, size_t *argc, char **argv)
{
	size_t len = strlen(stats_path);
	size_t j = 0;
	size_t k = 0;
	int state = 0;

	for (size_t i = 0; i < len; ++i) {
		switch (state) {
		case 0:
			if (stats_path[i] == '(') {
				state = 1;
				k = 0;
			}
			else if (stats_path[i] == ')')
				return -1;
			stats_path[j] = stats_path[i];
			j++;
			break;
		case 1:
			if (stats_path[i] == ')') {
				state = 0;
				stats_path[j] = '#';
				j++;
				stats_path[j] = ')';
				j++;
				(*argc)++;
			}
			else {
				argv[*argc][k++] = stats_path[i];
			}
			break;
		}
	}
	if (state == 1)
		return -1;
	stats_path[j] = 0;
	return 0;
}

uint64_t stats_parser_get(const char *stats_path)
{
	size_t stats_path_len;

	char stats_path_cpy[128];

	strncpy(stats_path_cpy, stats_path, sizeof(stats_path_cpy));
	stats_path_len = strlen(stats_path);

	size_t max_argc = 16;
	size_t argc = 0;
	char argv_data[16][16] = {{0}};
	char *argv[16];
	const char *argv_c[16];

	for (size_t i = 0; i < 16; ++i) {
		argv[i] = argv_data[i];
		argv_c[i] = argv_data[i];
	}

	if (stats_parser_extract_args(stats_path_cpy, &argc, argv))
		return -1;

	for (size_t i = 0; i < sizeof(stats_paths)/sizeof(stats_paths[0]); ++i) {
		if (strcmp(stats_paths[i].str, stats_path_cpy) == 0) {
			if (stats_paths[i].func == NULL)
				return -1;
			return stats_paths[i].func(argc, argv_c);
		}
	}

	return -1;
}
