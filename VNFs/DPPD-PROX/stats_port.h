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

#ifndef _STATS_PORT_H_
#define _STATS_PORT_H_

#include <inttypes.h>

enum PKT_SIZE_BIN {
	PKT_SIZE_64,
	PKT_SIZE_65,
	PKT_SIZE_128,
	PKT_SIZE_256,
	PKT_SIZE_512,
	PKT_SIZE_1024,
	PKT_SIZE_1522,
	PKT_SIZE_COUNT,
};

struct port_stats_sample {
	uint64_t tsc;
	uint64_t no_mbufs;
	uint64_t ierrors;
	uint64_t imissed;
	uint64_t oerrors;
	uint64_t rx_tot;
	uint64_t tx_tot;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
	uint64_t tx_pkt_size[PKT_SIZE_COUNT];
};

struct port_stats {
	struct port_stats_sample sample[2];
};

struct get_port_stats {
	uint64_t no_mbufs_diff;
	uint64_t ierrors_diff;
	uint64_t imissed_diff;
	uint64_t rx_bytes_diff;
	uint64_t tx_bytes_diff;
	uint64_t rx_pkts_diff;
	uint64_t tx_pkts_diff;
	uint64_t rx_tot;
	uint64_t tx_tot;
	uint64_t no_mbufs_tot;
	uint64_t ierrors_tot;
	uint64_t imissed_tot;
	uint64_t last_tsc;
	uint64_t prev_tsc;
};

int stats_port(uint8_t port_id, struct get_port_stats *ps);
void stats_port_init(void);
void stats_port_reset(void);
void stats_port_update(void);
uint64_t stats_port_get_ierrors(void);
uint64_t stats_port_get_imissed(void);
uint64_t stats_port_get_rx_packets(void);
uint64_t stats_port_get_tx_packets(void);

int stats_get_n_ports(void);
struct port_stats_sample *stats_get_port_stats_sample(uint32_t port_id, int l);

#endif /* _STATS_PORT_H_ */
