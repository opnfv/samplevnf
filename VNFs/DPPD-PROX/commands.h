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

#ifndef _COMMANDS_H_
#define _COMMANDS_H_

#include <inttypes.h>

struct input;

/* command functions */
void start_core_all(int task_id);
void stop_core_all(int task_id);
void start_cores(uint32_t *cores, int count, int task_id);
void stop_cores(uint32_t *cores, int count, int task_id);

void cmd_trace(uint8_t lcore_id, uint8_t task_id, uint32_t nb_packets);
void cmd_dump(uint8_t lcore_id, uint8_t task_id, uint32_t nb_packets, struct input *input, int rx, int tx);
void cmd_mem_stats(void);
void cmd_mem_layout(void);
void cmd_hashdump(uint8_t lcore_id, uint8_t task_id, uint32_t table_id);
void cmd_rx_distr_start(uint32_t lcore_id);
void cmd_rx_distr_stop(uint32_t lcore_id);
void cmd_rx_distr_rst(uint32_t lcore_id);
void cmd_rx_distr_show(uint32_t lcore_id);
void cmd_tx_distr_start(uint32_t lcore_id);
void cmd_tx_distr_stop(uint32_t lcore_id);
void cmd_tx_distr_rst(uint32_t lcore_id);
void cmd_tx_distr_show(uint32_t lcore_id);
void cmd_rx_bw_start(uint32_t lcore_id);
void cmd_tx_bw_start(uint32_t lcore_id);
void cmd_rx_bw_stop(uint32_t lcore_id);
void cmd_tx_bw_stop(uint32_t lcore_id);

void cmd_portinfo(int port_id, char *dst, size_t max_len);
void cmd_port_up(uint8_t port_id);
void cmd_port_down(uint8_t port_id);
void cmd_xstats(uint8_t port_id);
void cmd_thread_info(uint8_t lcore_id, uint8_t task_id);
void cmd_ringinfo(uint8_t lcore_id, uint8_t task_id);
void cmd_ringinfo_all(void);
void cmd_rx_tx_info(void);
void cmd_read_reg(uint8_t port_id, uint32_t id);
void cmd_write_reg(uint8_t port_id, unsigned int id, unsigned int val);
void cmd_set_vlan_filter(uint8_t port_id, unsigned int id, unsigned int val);
void cmd_set_vlan_offload(uint8_t port_id, unsigned int val);
void cmd_get_cache_class(uint32_t lcore_id, uint32_t *set);
void cmd_get_cache_class_mask(uint32_t lcore_id, uint32_t set, uint32_t *val);
void cmd_set_cache_class_mask(uint32_t lcore_id, uint32_t set, uint32_t val);
void cmd_set_cache_class(uint32_t lcore_id, uint32_t set);
void cmd_cache_reset(void);

void cmd_reset_port(uint8_t port_id);
int reconnect_task(uint32_t lcore_id, uint32_t task_id);
int bypass_task(uint32_t lcore_id, uint32_t task_id);

#endif /* _COMMANDS_H_ */
