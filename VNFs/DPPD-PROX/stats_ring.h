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

#include "prox_globals.h"

struct rte_ring;
struct prox_port_cfg;

struct ring_stats {
	struct rte_ring	*ring;
	uint32_t	 nb_ports;
	struct prox_port_cfg *port[PROX_MAX_PORTS];
	uint32_t	 free;
	uint32_t	 size;
};

void stats_ring_update(void);
void stats_ring_init(void);

int stats_get_n_rings(void);
struct ring_stats *stats_get_ring_stats(uint32_t i);
