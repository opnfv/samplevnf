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

#ifndef _ELD_H_
#define _ELD_H_

#define PACKET_QUEUE_BITS      14
#define PACKET_QUEUE_SIZE      (1 << PACKET_QUEUE_BITS)
#define PACKET_QUEUE_MASK      (PACKET_QUEUE_SIZE - 1)

#define QUEUE_ID_BITS		(32 - PACKET_QUEUE_BITS)
#define QUEUE_ID_SIZE		(1 << QUEUE_ID_BITS)
#define QUEUE_ID_MASK		(QUEUE_ID_SIZE - 1)

struct early_loss_detect {
	uint32_t entries[PACKET_QUEUE_SIZE];
	uint32_t last_pkt_idx;
};

static void early_loss_detect_reset(struct early_loss_detect *eld)
{
	for (size_t i = 0; i < PACKET_QUEUE_SIZE; i++) {
		eld->entries[i] = -1;
	}
}

static uint32_t early_loss_detect_count_remaining_loss(struct early_loss_detect *eld)
{
	uint32_t queue_id;
	uint32_t n_loss;
	uint32_t n_loss_total = 0;

	/* Need to check if we lost any packet before last packet
	   received Any packet lost AFTER the last packet received
	   cannot be counted.  Such a packet will be counted after both
	   lat and gen restarted */
	queue_id = eld->last_pkt_idx >> PACKET_QUEUE_BITS;
	for (uint32_t i = (eld->last_pkt_idx + 1) & PACKET_QUEUE_MASK; i < PACKET_QUEUE_SIZE; i++) {
		// We ** might ** have received OOO packets; do not count them as lost next time...
		if (queue_id - eld->entries[i] != 0) {
			n_loss = (queue_id - eld->entries[i] - 1) & QUEUE_ID_MASK;
			n_loss_total += n_loss;
		}
	}
	for (uint32_t i = 0; i < (eld->last_pkt_idx & PACKET_QUEUE_MASK); i++) {
		// We ** might ** have received OOO packets; do not count them as lost next time...
		if (eld->entries[i] - queue_id != 1) {
			n_loss = (queue_id - eld->entries[i]) & QUEUE_ID_MASK;
			n_loss_total += n_loss;
		}
	}

	eld->entries[eld->last_pkt_idx & PACKET_QUEUE_MASK] = -1;
	return n_loss_total;
}

static uint32_t early_loss_detect_add(struct early_loss_detect *eld, uint32_t packet_index)
{
	uint32_t old_queue_id, queue_pos, n_loss;

	eld->last_pkt_idx = packet_index;
	queue_pos = packet_index & PACKET_QUEUE_MASK;
	old_queue_id = eld->entries[queue_pos];
	eld->entries[queue_pos] = packet_index >> PACKET_QUEUE_BITS;

	return (eld->entries[queue_pos] - old_queue_id - 1) & QUEUE_ID_MASK;
}

#endif /* _ELD_H_ */
