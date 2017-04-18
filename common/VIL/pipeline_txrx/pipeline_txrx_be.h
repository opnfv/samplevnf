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

#ifndef __INCLUDE_PIPELINE_TXRX_BE_H__
#define __INCLUDE_PIPELINE_TXRX_BE_H__

#include "pipeline_common_be.h"
#define PIPELINE_TXRX_KEY_PORT_IN_AH(f_ah, f_pkt_work, f_pkt4_work)     \
static int                                                              \
f_ah(                                                                   \
	__rte_unused struct rte_pipeline *rte_p,                        \
	struct rte_mbuf **pkts,                                         \
	uint32_t n_pkts,                                                \
	void *arg)                                                      \
{                                                                       \
	uint32_t i, j;                                                  \
									\
	for (j = 0; j < n_pkts; j++)                                    \
		rte_prefetch0(pkts[j]);                                 \
									\
	pkt_burst_cnt = 0;                                              \
	for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)                   \
		f_pkt4_work(&pkts[i], i, arg);                          \
									\
	for ( ; i < n_pkts; i++)                                        \
		f_pkt_work(pkts[i], i, arg);                            \
									\
									\
	return 0;                                                       \
}

extern struct pipeline_be_ops pipeline_txrx_be_ops;
/*
 * Messages
 */
enum pipeline_txrx_msg_req_type {
	PIPELINE_TXRX_MSG_REQ_ENTRY_DBG,
	PIPELINE_TXRX_MSG_REQS
};
/*
 * MSG ENTRY DBG
 */
struct pipeline_txrx_entry_dbg_msg_req {
	enum pipeline_msg_req_type type;
	enum pipeline_txrx_msg_req_type subtype;

	/* data */
	uint8_t data[5];
};
/*
 * TXRX Entry
 */

struct pipeline_txrx_in_port_h_arg {
	struct pipeline_txrx *p;
	uint8_t in_port_id;
};

struct pipeline_txrx_entry_dbg_msg_rsp {
	int status;
};

#endif
