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

#ifndef __INCLUDE_CPU_CORE_MAP_H__
#define __INCLUDE_CPU_CORE_MAP_H__

#include <stdio.h>

#include <rte_lcore.h>

struct cpu_core_map;

struct cpu_core_map *
cpu_core_map_init(uint32_t n_max_sockets,
	uint32_t n_max_cores_per_socket,
	uint32_t n_max_ht_per_core,
	uint32_t eal_initialized);

uint32_t
cpu_core_map_get_n_sockets(struct cpu_core_map *map);

uint32_t
cpu_core_map_get_n_cores_per_socket(struct cpu_core_map *map);

uint32_t
cpu_core_map_get_n_ht_per_core(struct cpu_core_map *map);

int
cpu_core_map_get_lcore_id(struct cpu_core_map *map,
	uint32_t socket_id,
	uint32_t core_id,
	uint32_t ht_id);

void cpu_core_map_print(struct cpu_core_map *map);

void
cpu_core_map_free(struct cpu_core_map *map);

#endif
