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
#ifndef __INCLUDE_PIPELINE_ACTIONS_COMMON_H__
#define __INCLUDE_PIPELINE_ACTIONS_COMMON_H__

#include <stdint.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_pipeline.h>

#define PIPELINE_PORT_IN_AH(f_ah, f_pkt_work, f_pkt4_work)		\
static int								\
f_ah(									\
	__rte_unused struct rte_pipeline *p,				\
	struct rte_mbuf **pkts,						\
	uint32_t n_pkts,						\
	void *arg)							\
{									\
	uint32_t i;							\
									\
	for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)			\
		f_pkt4_work(&pkts[i], arg);				\
									\
	for ( ; i < n_pkts; i++)					\
		f_pkt_work(pkts[i], arg);				\
									\
	return 0;							\
}

#define PIPELINE_PORT_IN_AH_HIJACK_ALL(f_ah, f_pkt_work, f_pkt4_work) \
static int								\
f_ah(									\
	struct rte_pipeline *p,				\
	struct rte_mbuf **pkts,					\
	uint32_t n_pkts,						\
	void *arg)						\
{									\
	uint64_t pkt_mask = RTE_LEN2MASK(n_pkts, uint64_t);	\
	uint32_t i;							\
									\
	rte_pipeline_ah_packet_hijack(p, pkt_mask);	\
									\
	for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)	\
		f_pkt4_work(&pkts[i], arg);				\
									\
	for ( ; i < n_pkts; i++)				\
		f_pkt_work(pkts[i], arg);			\
									\
	return 0;							\
}

#define PIPELINE_TABLE_AH_HIT(f_ah, f_pkt_work, f_pkt4_work)		\
static int								\
f_ah(									\
	__rte_unused struct rte_pipeline *p,				\
	struct rte_mbuf **pkts,						\
	uint64_t pkts_in_mask,						\
	struct rte_pipeline_table_entry **entries,			\
	void *arg)							\
{									\
	if ((pkts_in_mask & (pkts_in_mask + 1)) == 0) {			\
		uint64_t n_pkts = __builtin_popcountll(pkts_in_mask);	\
		uint32_t i;						\
									\
		for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)		\
			f_pkt4_work(&pkts[i], &entries[i], arg);	\
									\
		for ( ; i < n_pkts; i++)				\
			f_pkt_work(pkts[i], entries[i], arg);		\
	} else								\
		for ( ; pkts_in_mask; ) {				\
			uint32_t pos = __builtin_ctzll(pkts_in_mask);	\
			uint64_t pkt_mask = 1LLU << pos;		\
									\
			pkts_in_mask &= ~pkt_mask;			\
			f_pkt_work(pkts[pos], entries[pos], arg);	\
		}							\
									\
	return 0;							\
}

#define PIPELINE_TABLE_AH_MISS(f_ah, f_pkt_work, f_pkt4_work)		\
static int								\
f_ah(									\
	__rte_unused struct rte_pipeline *p,				\
	struct rte_mbuf **pkts,						\
	uint64_t pkts_in_mask,						\
	struct rte_pipeline_table_entry *entry,				\
	void *arg)							\
{									\
	if ((pkts_in_mask & (pkts_in_mask + 1)) == 0) {			\
		uint64_t n_pkts = __builtin_popcountll(pkts_in_mask);	\
		uint32_t i;						\
									\
		for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)		\
			f_pkt4_work(&pkts[i], entry, arg);		\
									\
		for ( ; i < n_pkts; i++)				\
			f_pkt_work(pkts[i], entry, arg);		\
	} else								\
		for ( ; pkts_in_mask; ) {				\
			uint32_t pos = __builtin_ctzll(pkts_in_mask);	\
			uint64_t pkt_mask = 1LLU << pos;		\
									\
			pkts_in_mask &= ~pkt_mask;			\
			f_pkt_work(pkts[pos], entry, arg);		\
		}							\
									\
	return 0;							\
}

#define PIPELINE_TABLE_AH_HIT_DROP_TIME(f_ah, f_pkt_work, f_pkt4_work)	\
static int								\
f_ah(									\
	struct rte_pipeline *p,						\
	struct rte_mbuf **pkts,						\
	uint64_t pkts_mask,						\
	struct rte_pipeline_table_entry **entries,			\
	void *arg)							\
{									\
	uint64_t pkts_in_mask = pkts_mask;				\
	uint64_t pkts_out_mask = pkts_mask;				\
	uint64_t time = rte_rdtsc();					\
									\
	if ((pkts_in_mask & (pkts_in_mask + 1)) == 0) {			\
		uint64_t n_pkts = __builtin_popcountll(pkts_in_mask);	\
		uint32_t i;						\
									\
		for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4) {		\
			uint64_t mask = f_pkt4_work(&pkts[i],		\
				&entries[i], arg, time);		\
			pkts_out_mask ^= mask << i;			\
		}							\
									\
		for ( ; i < n_pkts; i++) {				\
			uint64_t mask = f_pkt_work(pkts[i],		\
				entries[i], arg, time);			\
			pkts_out_mask ^= mask << i;			\
		}							\
	} else								\
		for ( ; pkts_in_mask; ) {				\
			uint32_t pos = __builtin_ctzll(pkts_in_mask);	\
			uint64_t pkt_mask = 1LLU << pos;		\
			uint64_t mask = f_pkt_work(pkts[pos],		\
				entries[pos], arg, time);		\
									\
			pkts_in_mask &= ~pkt_mask;			\
			pkts_out_mask ^= mask << pos;			\
		}							\
									\
	rte_pipeline_ah_packet_drop(p, pkts_out_mask ^ pkts_mask);	\
									\
	return 0;							\
}

#define PIPELINE_TABLE_AH_MISS_DROP_TIME(f_ah, f_pkt_work, f_pkt4_work)	\
static int								\
f_ah(									\
	struct rte_pipeline *p,						\
	struct rte_mbuf **pkts,						\
	uint64_t pkts_mask,						\
	struct rte_pipeline_table_entry *entry,				\
	void *arg)							\
{									\
	uint64_t pkts_in_mask = pkts_mask;				\
	uint64_t pkts_out_mask = pkts_mask;				\
	uint64_t time = rte_rdtsc();					\
									\
	if ((pkts_in_mask & (pkts_in_mask + 1)) == 0) {			\
		uint64_t n_pkts = __builtin_popcountll(pkts_in_mask);	\
		uint32_t i;						\
									\
		for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4) {		\
			uint64_t mask = f_pkt4_work(&pkts[i],		\
				entry, arg, time);			\
			pkts_out_mask ^= mask << i;			\
		}							\
									\
		for ( ; i < n_pkts; i++) {				\
			uint64_t mask = f_pkt_work(pkts[i], entry, arg, time);\
			pkts_out_mask ^= mask << i;			\
		}							\
	} else								\
		for ( ; pkts_in_mask; ) {				\
			uint32_t pos = __builtin_ctzll(pkts_in_mask);	\
			uint64_t pkt_mask = 1LLU << pos;		\
			uint64_t mask = f_pkt_work(pkts[pos],		\
				entry, arg, time);		\
									\
			pkts_in_mask &= ~pkt_mask;			\
			pkts_out_mask ^= mask << pos;			\
		}							\
									\
	rte_pipeline_ah_packet_drop(p, pkts_out_mask ^ pkts_mask);	\
									\
	return 0;							\
}

#endif
