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

#ifndef _PREFETCH_H_
#define _PREFETCH_H_

#include <rte_mbuf.h>

static inline void prefetch_nta(volatile void *p)
{
	asm volatile ("prefetchnta %[p]" : [p] "+m" (*(volatile char *)p));
}

#ifdef PROX_PREFETCH_OFFSET
#define PREFETCH0(p)		rte_prefetch0(p)
#define PREFETCH_OFFSET		PROX_PREFETCH_OFFSET
#else
#define PREFETCH0(p)		do {} while (0)
#define PREFETCH_OFFSET		0
#endif

static inline void prefetch_pkts(__attribute__((unused)) struct rte_mbuf **mbufs, __attribute__((unused)) uint16_t n_pkts)
{
#ifdef PROX_PREFETCH_OFFSET
	for (uint16_t j = 0; j < PROX_PREFETCH_OFFSET && j < n_pkts; ++j) {
		PREFETCH0(mbufs[j]);
	}
	for (uint16_t j = PROX_PREFETCH_OFFSET; j < n_pkts; ++j) {
		PREFETCH0(mbufs[j]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j - PROX_PREFETCH_OFFSET], void*));
	}
	for (uint16_t j = n_pkts - PROX_PREFETCH_OFFSET; j < n_pkts; ++j) {
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j], void*));
	}
#endif
}

static inline void prefetch_first(__attribute__((unused)) struct rte_mbuf **mbufs, __attribute__((unused)) uint16_t n_pkts)
{
#ifdef PROX_PREFETCH_OFFSET
	for (uint16_t j = 0; j < PROX_PREFETCH_OFFSET && j < n_pkts; ++j) {
		PREFETCH0(mbufs[j]);
	}
	for (uint16_t j = 1; j < PROX_PREFETCH_OFFSET && j < n_pkts; ++j) {
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j - 1], void *));
	}
#endif
}

#endif /* _PREFETCH_H_ */
