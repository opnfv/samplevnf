/*
// Copyright (c) 2010-2018 Intel Corporation
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

#include "handle_softnic.h"
#include "thread_generic.h"

static void init_task_softnic(__attribute__((unused)) struct task_base *tbase,
			      __attribute__((unused)) struct task_args *targ)
{
#ifdef CLASSIF_REMAPPING_TABLE_SIZE
	for (uint32_t ii=0; ii<CLASSIF_REMAPPING_TABLE_SIZE; ii++)
		tbase->aux->remapping_table[ii] = ii;
#endif
}

/** Read entry from mbuf and assign to mbuf metadata 'hash.fdir.hi' field. */
static inline void apply_flexbyte_fdir_xform(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t nb_rx, uint32_t offset, uint32_t shift)
{
	for (uint16_t i = 0; i < nb_rx; ++i) {
		struct rte_mbuf *cur = mbufs[i];
/*		uint32_t classif = rte_be_to_cpu_32(
 *			*(uint32_t *)(rte_pktmbuf_mtod(cur, uint8_t *) + offset)) >> shift;
 *		cur->hash.fdir.hi = RX_PKT_CLASSIF_REMAPPING(tbase, classif);*/
		uint32_t classif = rte_be_to_cpu_32(
			*(uint32_t *)(rte_pktmbuf_mtod(cur, uint8_t *) + offset)) ;
		cur->hash.sched.hi = classif ;
		classif = rte_be_to_cpu_32(
			*(uint32_t *)(rte_pktmbuf_mtod(cur, uint8_t *) + offset+4)) ;
		cur->hash.sched.lo = classif ;
		plog_dbg("Flex Bytes:hw_param: flex_bytes=0x%x, mbuf[%u]->hash.fdir.hi=%u\n",
			 rte_be_to_cpu_32(*(uint32_t *)(rte_pktmbuf_mtod(cur, uint8_t *) + offset)),
			 i, cur->hash.fdir.hi);
	}
}

static inline int handle_softnic_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	int returnvalue;
	struct task_softnic *task = (struct task_softnic *)tbase;
/*
 *	if (tbase->rx_params_hw.flex_width)
		apply_flexbyte_fdir_xform(tbase, tbase->ws_mbuf->mbuf[0] + (RTE_ALIGN_CEIL(tbase->ws_mbuf->idx[0].prod, 2) & WS_MBUF_MASK), n_pkts, tbase->rx_params_hw.flex_offset, tbase->rx_params_hw.flex_shift);
*/
/*	apply_flexbyte_fdir_xform(tbase, mbufs, n_pkts, 80, 0); MOVED THIS FUNCTION IN HANDLE_L2FWD */
	returnvalue = task->base.tx_pkt(&task->base, mbufs, n_pkts, NULL);
	rte_pmd_softnic_run(tbase->tx_params_hw.tx_port_queue->port);
	return returnvalue;
}

static struct task_init task_init_softnic_thrpt_opt = {
	.mode_str = "softnic",
	.init = init_task_softnic,
	.handle = handle_softnic_bulk,
	.thread_x = thread_generic,
	.flag_features = TASK_FEATURE_ZERO_RX|TASK_FEATURE_NEVER_DISCARDS|TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS|TASK_FEATURE_TXQ_FLAGS_NOMULTSEGS|TASK_FEATURE_THROUGHPUT_OPT|TASK_FEATURE_MULTI_RX,
	.size = sizeof(struct task_softnic),
	.mbuf_size = 4096 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM,
};

static struct task_init task_init_softnic_lat_opt = {
	.mode_str = "softnic",
	.sub_mode_str = "latency optimized",
	.init = init_task_softnic,
	.handle = handle_softnic_bulk,
	.thread_x = thread_generic,
	.flag_features = TASK_FEATURE_ZERO_RX|TASK_FEATURE_NEVER_DISCARDS|TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS|TASK_FEATURE_TXQ_FLAGS_NOMULTSEGS|TASK_FEATURE_MULTI_RX,
	.size = sizeof(struct task_softnic),
	.mbuf_size = 4096 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM,
};

__attribute__((constructor)) static void reg_task_softnic(void)
{
	reg_task(&task_init_softnic_thrpt_opt);
	reg_task(&task_init_softnic_lat_opt);
}
