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

#include <rte_version.h>
#include "defaults.h"
#include "task_base.h"
#include "token_time.h"
#include "local_mbuf.h"
#include "random.h"

#if RTE_VERSION < RTE_VERSION_NUM(17,8,0,1)
typedef uint32_t rte_be32_t;
#endif

struct pkt_template {
	uint16_t len;
	uint16_t l2_len;
	uint16_t l3_len;
	uint8_t  *buf;
};

struct unique_id {
	uint8_t  generator_id;
	uint32_t packet_id;
} __attribute__((packed));

/** Per-flow statistics */
struct lat_test_gen {
	uint64_t tot_pkts;
	uint64_t tot_bytes;
};

struct task_gen {
	struct task_base base;
	uint64_t hz;
	uint64_t link_speed;
	struct token_time token_time;
	struct local_mbuf local_mbuf;
	struct pkt_template *pkt_template; /* packet templates used at runtime */
	uint64_t write_duration_estimate; /* how long it took previously to write the time stamps in the packets */
	uint64_t earliest_tsc_next_pkt;
	uint64_t new_rate_bps;
	uint64_t pkt_queue_index;
	uint32_t n_pkts; /* number of packets in pcap */
	uint32_t pkt_idx; /* current packet from pcap */
	uint32_t pkt_count; /* how many pakets to generate */
	uint32_t max_frame_size;
	uint32_t runtime_flags;
	uint16_t lat_pos;
	uint16_t packet_id_pos;
	uint16_t accur_pos;
	uint16_t sig_pos;
	uint32_t sig;
	uint8_t generator_id;
	uint8_t n_rands; /* number of randoms */
	uint8_t min_bulk_size;
	uint8_t max_bulk_size;
	uint8_t lat_enabled;
	uint32_t latency_flow_offset;  /**< Where in packet individual flow identifier is stored */
	uint32_t latency_flow_mask;    /**< Mask to reduce number of simultaneous flows */
	uint8_t  latency_flow_shift;   /**< Right-shift for flow identifier before referencing latency statistics table */
	struct lat_test_gen latency_flow_lt_gen[LATENCY_NUMBER_OF_FLOWS];

	uint8_t runtime_checksum_needed;
	struct {
		struct random state;
		uint32_t rand_mask; /* since the random vals are uniform, masks don't introduce bias  */
		uint32_t fixed_bits; /* length of each random (max len = 4) */
		uint16_t rand_offset; /* each random has an offset*/
		uint8_t rand_len; /* # bytes to take from random (no bias introduced) */
	} rand[64];
	uint64_t accur[64];
	uint64_t pkt_tsc_offset[64];
	struct pkt_template *pkt_template_orig; /* packet templates (from inline or from pcap) */
	struct ether_addr  src_mac;
	uint8_t flags;
	uint8_t cksum_offload;
	struct prox_port_cfg *port;
	uint64_t *bytes_to_tsc;
} __rte_cache_aligned;

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

static uint32_t get_flowid_from_pkt(uint8_t *hdr, uint32_t latency_flow_mask, uint32_t latency_flow_offset, uint8_t latency_flow_shift)
{
	if (latency_flow_mask > 0) {
		uint32_t flowid = rte_be_to_cpu_32(*((rte_be32_t*)(((uint8_t *)hdr) + latency_flow_offset)));
		flowid = (flowid & latency_flow_mask) >> latency_flow_shift;
		if (flowid < LATENCY_NUMBER_OF_FLOWS) {
			return flowid;
		}
	}
	return 0; /* This is also the default in case read flowid>=LATENCY_NUMBER_OF_FLOWS */
}

struct task_base;

void task_gen_set_pkt_count(struct task_base *tbase, uint32_t count);
int task_gen_set_pkt_size(struct task_base *tbase, uint32_t pkt_size, int template_idx);
void task_gen_set_rate(struct task_base *tbase, uint64_t bps);
void task_gen_reset_randoms(struct task_base *tbase);
void task_gen_reset_values(struct task_base *tbase);
int task_gen_set_value(struct task_base *tbase, uint32_t value, uint32_t offset, uint32_t len);
int task_gen_add_rand(struct task_base *tbase, const char *rand_str, uint32_t offset, uint32_t rand_id);

uint32_t task_gen_get_n_randoms(struct task_base *tbase);
uint32_t task_gen_get_n_values(struct task_base *tbase);

#endif /* _HANDLE_GEN_H_ */
