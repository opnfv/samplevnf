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

#include <rte_cycles.h>

#include "lconf.h"
#include "task_base.h"
#include "task_init.h"
#include "handle_irq.h"
#include "stats_irq.h"
#include "log.h"
#include "unistd.h"
#include "input.h"

#define MAX_INTERRUPT_LENGTH	500000	/* Maximum length of an interrupt is (1 / MAX_INTERRUPT_LENGTH) seconds */
uint64_t irq_bucket_maxtime_micro[] = {1,5,10,50,100,500,1000,5000,10000,50000,100000,500000,UINT64_MAX};
/*
 *	This module is not handling any packets.
 *	It loops on rdtsc() and checks whether it has been interrupted
 *		 for more than (1 / MAX_INTERRUPT_LENGTH) sec.
 *	This is a debugging only task, useful to check if the system h
 *		as been properly configured.
*/

static void update_irq_stats(struct task_irq *task, uint64_t irq)
{
	if (irq > task->stats.max_irq)
		task->stats.max_irq = irq;
	for (uint i = 0; i < IRQ_BUCKETS_COUNT; ++i) {
		if (irq < irq_bucket_maxtime_cycles[i]) {
			task->stats.irq[i]++;
			break;
		}
	}
}

void task_irq_show_stats(struct task_irq *task_irq, struct input *input)
{
	struct irq_bucket *bucket = &task_irq->buffer[!task_irq->task_use_lt];
	if (input->reply) {
		char buf[8192] = {0};
		if (bucket->index == 0) {
			sprintf(buf, "\n");
			input->reply(input, buf, strlen(buf));
			buf[0] = 0;
		}
		for (uint64_t i = 0; i < bucket->index; i++) {
			sprintf(buf + strlen(buf), "%d; %"PRIu64"""; %ld; %ld; %ld; %ld ;",
				task_irq->lcore_id,
				i,
				bucket->info[i].lat,
				bucket->info[i].lat * 1000000 / rte_get_tsc_hz(),
				bucket->info[i].tsc - task_irq->start_tsc,
				(bucket->info[i].tsc - task_irq->start_tsc) * 1000 / rte_get_tsc_hz());
			sprintf(buf+strlen(buf), "\n");
			input->reply(input, buf, strlen(buf));
			buf[0] = 0;
		}
	} else {
		for (uint64_t i = 0; i < bucket->index; i++)
			if (bucket->info[i].lat)
				plog_info("[%d]; Interrupt %"PRIu64": %ld cycles (%ld micro-sec) at %ld cycles (%ld msec)\n",
					  task_irq->lcore_id,
					  i,
					  bucket->info[i].lat,
					  bucket->info[i].lat * 1000000 / rte_get_tsc_hz(),
					  bucket->info[i].tsc - task_irq->start_tsc,
					  (bucket->info[i].tsc - task_irq->start_tsc) * 1000 / rte_get_tsc_hz());
	}
	task_irq->stats_use_lt = !task_irq->task_use_lt;
	bucket->index = 0;
}

static void irq_stop(struct task_base *tbase)
{
	struct task_irq *task = (struct task_irq *)tbase;
	uint32_t i;
	uint32_t lcore_id = rte_lcore_id();
	uint64_t lat, max_lat = 0, tot_lat = 0;
	int bucket_id;
	int n_lat = 0;

	if (task->irq_debug) {
		plog_info("Stopping core %u\n", lcore_id);
		sleep(2);	// Make sure all cores are stopped before starting to write
		plog_info("Core ID; Interrupt (nanosec); Time (msec)\n");
		for (int j = 0; j < 2; j++) {
			// Start dumping the oldest bucket first
			if (task->buffer[0].info[0].tsc < task->buffer[1].info[0].tsc)
				bucket_id = j;
			else
				bucket_id = !j;
			struct irq_bucket *bucket = &task->buffer[bucket_id];
			for (i=0; i< bucket->index;i++) {
				if (bucket->info[i].lat != 0) {
					lat = bucket->info[i].lat * 1000000000 / rte_get_tsc_hz();
					if (max_lat < lat)
						max_lat = lat;
					n_lat++;
					tot_lat += lat;
					plog_info("%d; %ld; %ld\n", lcore_id, lat,
					  	(bucket->info[i].tsc - task->start_tsc) * 1000 / rte_get_tsc_hz());
				}
			}
		}
		if (n_lat)
			tot_lat = tot_lat / n_lat;
		plog_info("Core %u stopped. max lat is %ld and average is %ld\n", lcore_id, max_lat, tot_lat);
	}
}

static inline int handle_irq_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_irq *task = (struct task_irq *)tbase;
	uint64_t tsc1;
	uint64_t index;

	if (task->stats_use_lt != task->task_use_lt)
		task->task_use_lt = task->stats_use_lt;
	struct irq_bucket *bucket = &task->buffer[task->task_use_lt];

	tsc1 = rte_rdtsc();
	if ((tsc1 > task->first_tsc) && (task->tsc != 0)) {
		update_irq_stats(task, tsc1 - task->tsc);
		if (((tsc1 - task->tsc) > task->max_irq) && (bucket->index < MAX_INDEX)) {
			bucket->info[bucket->index].tsc = tsc1;
			bucket->info[bucket->index++].lat = tsc1 - task->tsc;
		}
	}
	task->tsc = tsc1;
	return 0;
}

static void init_task_irq(struct task_base *tbase,
			  __attribute__((unused)) struct task_args *targ)
{
	struct task_irq *task = (struct task_irq *)tbase;
	task->start_tsc = rte_rdtsc();
	task->first_tsc = task->start_tsc + 2 * rte_get_tsc_hz();
	task->lcore_id = targ->lconf->id;
	task->irq_debug = targ->irq_debug;
	// max_irq expressed in cycles
	task->max_irq = rte_get_tsc_hz() / MAX_INTERRUPT_LENGTH;
	plog_info("\tusing irq mode with max irq set to %ld cycles\n", task->max_irq);

	for (uint bucket_id = 0; bucket_id < IRQ_BUCKETS_COUNT - 1; bucket_id++)
		irq_bucket_maxtime_cycles[bucket_id] = rte_get_tsc_hz() * irq_bucket_maxtime_micro[bucket_id] / 1000000;
	irq_bucket_maxtime_cycles[IRQ_BUCKETS_COUNT - 1] = UINT64_MAX;
}

static struct task_init task_init_irq = {
	.mode_str = "irq",
	.init = init_task_irq,
	.handle = handle_irq_bulk,
	.stop = irq_stop,
	.flag_features = TASK_FEATURE_NO_RX,
	.size = sizeof(struct task_irq)
};

static struct task_init task_init_none;

__attribute__((constructor)) static void reg_task_irq(void)
{
	reg_task(&task_init_irq);
}
