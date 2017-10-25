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

#ifndef _HANDLE_GEN_H_
#define _HANDLE_GEN_H_

struct unique_id {
	uint8_t  generator_id;
	uint32_t packet_id;
} __attribute__((packed));

static void unique_id_init(struct unique_id *unique_id, uint8_t generator_id, uint32_t packet_id)
{
	unique_id->generator_id = generator_id;
	unique_id->packet_id = packet_id;
}

static void unique_id_get(struct unique_id *unique_id, uint8_t *generator_id, uint32_t *packet_id)
{
	*generator_id = unique_id->generator_id;
	*packet_id = unique_id->packet_id;
}

struct task_base;

void task_gen_set_pkt_count(struct task_base *tbase, uint32_t count);
int task_gen_set_pkt_size(struct task_base *tbase, uint32_t pkt_size);
void task_gen_set_rate(struct task_base *tbase, uint64_t bps);
void task_gen_reset_randoms(struct task_base *tbase);
void task_gen_reset_values(struct task_base *tbase);
int task_gen_set_value(struct task_base *tbase, uint32_t value, uint32_t offset, uint32_t len);
int task_gen_add_rand(struct task_base *tbase, const char *rand_str, uint32_t offset, uint32_t rand_id);

uint32_t task_gen_get_n_randoms(struct task_base *tbase);
uint32_t task_gen_get_n_values(struct task_base *tbase);

#endif /* _HANDLE_GEN_H_ */
