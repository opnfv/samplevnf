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

#ifndef _GENL4_STREAM_TCP_H_
#define _GENL4_STREAM_TCP_H_

#include "genl4_stream.h"

int stream_tcp_proc(struct stream_ctx *ctx, struct rte_mbuf *mbuf, struct l4_meta *l4_meta, uint64_t *next_tsc);
int stream_tcp_is_ended(struct stream_ctx *ctx);
uint16_t stream_tcp_reply_len(struct stream_ctx *ctx);
void stream_tcp_calc_len(struct stream_cfg *cfg, uint32_t *n_pkts, uint32_t *n_bytes);

void stream_tcp_create_rst(struct rte_mbuf *mbuf, struct l4_meta *l4_meta, struct pkt_tuple *tuple);

#endif /* _GENL4_STREAM_TCP_H_ */
