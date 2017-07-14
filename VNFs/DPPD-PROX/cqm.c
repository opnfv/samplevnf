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

#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

#include "msr.h"
#include "cqm.h"
#include "log.h"
#include "prox_cfg.h"

#define IA32_QM_EVTSEL		0xC8D
#define IA32_QM_CTR		0xC8E
#define IA32_QM_ASSOC		0xC8F
#define IA32_QM_L3CA_START	0xC90
#define IA32_QM_L3CA_END        0xD0F

#define L3_CACHE_OCCUPANCY		1
#define L3_TOTAL_EXTERNAL_BANDWIDTH	2
#define L3_LOCAL_EXTERNAL_BANDWIDTH	3

static struct rdt_features rdt_features;
static int cat_features = 0;

static int stat_core;

struct reg {
	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
};

static void cpuid(struct reg* r, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
	asm volatile("cpuid"
		     : "=a" (r->eax), "=b" (r->ebx), "=c" (r->ecx), "=d" (r->edx)
		     : "a" (a), "b" (b), "c" (c), "d" (d));
}

void read_rdt_info(void)
{
	struct reg r;
	int i;
	uint64_t tmp_rmid;
	int rc;

	cpuid(&r, 0x7, 0x0, 0x0, 0x0);
	if ((r.ebx >> 12) & 1) {
		plog_info("\tRDT-M. Supports Intel RDT Monitoring capability\n");
		rdt_features.rdtm_supported = 1;
	} else {
		plog_info("\tDoes not support Intel RDT Monitoring capability\n");
		return;
	}
	if ((r.ebx >> 15) & 1) {
		plog_info("\tRDT-A. Supports Intel RDT Allocation capability\n");
		rdt_features.rdta_supported = 1;
	} else {
		plog_info("\tDoes not support Intel RDT Allocation capability\n");
	}

	cpuid(&r, 0xf, 0x0, 0x0, 0x0);
	if ((r.edx >> 1) & 1) {
		plog_info("\tSupports L3 Cache Intel RDT Monitoring\n");
		rdt_features.cmt_supported = 1;
	}
	plog_info("\tIntel RDT Monitoring has %d maximum RMID\n", r.ebx);
	rdt_features.rdtm_max_rmid = r.ebx;

	cpuid(&r, 0xf, 0x0, 0x1, 0x0);
	if ((r.edx >> 0) & 1) {
		plog_info("\tSupports L3 occupancy monitoring\n");
		rdt_features.cmt_supported = 1;
	}
	if ((r.edx >> 1) & 1) {
		plog_info("\tSupports L3 Total bandwidth monitoring\n");
		rdt_features.mbm_tot_supported = 1;
	}
	if ((r.edx >> 2) & 1) {
		plog_info("\tSupports L3 Local bandwidth monitoring\n");
		rdt_features.mbm_loc_supported = 1;
	}
	rdt_features.cmt_max_rmid = r.ecx;
	rdt_features.upscaling_factor = r.ebx;
	rdt_features.event_types = r.edx;

	plog_info("\tL3 Cache Intel RDT Monitoring Capability has %d maximum RMID\n", r.ecx);
	plog_info("\tUpscaling_factor = %d\n", rdt_features.upscaling_factor);

	cpuid(&r, 0x10, 0x0, 0x0, 0x0);
	if ((r.ebx >> 1) & 1) {
		plog_info("\tSupports L3 Cache Allocation Technology\n");
		rdt_features.l3_cat_supported = 1;
	}
	if ((r.ebx >> 2) & 1) {
		plog_info("\tSupports L2 Cache Allocation Technology\n");
		rdt_features.l2_cat_supported = 1;
	}
	if ((r.ebx >> 3) & 1) {
		plog_info("\tSupports MBA Allocation Technology\n");
		rdt_features.mba_supported = 1;
	}

	cpuid(&r, 0x10, 0x0, 0x1, 0x0);
	if ((r.ecx >> 2) & 1)
		plog_info("\tCode and Data Prioritization Technology supported\n");
	plog_info("\tL3 Cache Allocation Technology Enumeration Highest COS number = %d\n", r.edx & 0xffff);
	rdt_features.cat_max_rmid = r.edx & 0xffff;
	rdt_features.cat_num_ways = r.eax + 1;

	cpuid(&r, 0x10, 0x0, 0x2, 0x0);
	plog_info("\tL2 Cache Allocation Technology Enumeration COS number = %d\n", r.edx & 0xffff);

	cpuid(&r, 0x10, 0x0, 0x3, 0x0);
	plog_info("\tMemory Bandwidth Allocation Enumeration COS number = %d\n", r.edx & 0xffff);
	rdt_features.mba_max_rmid = r.ecx;
}
int mbm_is_supported(void)
{
	return (rdt_features.rdtm_supported && rdt_features.mbm_tot_supported && rdt_features.mbm_loc_supported);
}

int mba_is_supported(void)
{
	return (rdt_features.rdta_supported && rdt_features.mba_supported);
}

int cmt_is_supported(void)
{
	if ((rdt_features.rdtm_supported || rdt_features.rdta_supported) && (prox_cfg.flags & DSF_DISABLE_CMT)) {
		rdt_features.rdtm_supported = rdt_features.rdta_supported  = 0;
		plog_info("cqm and cat features disabled by config file\n");
	}
	return (rdt_features.rdtm_supported && rdt_features.cmt_supported);
}

int cat_is_supported(void)
{
	if ((rdt_features.rdtm_supported || rdt_features.rdta_supported) && (prox_cfg.flags & DSF_DISABLE_CMT)) {
		rdt_features.rdtm_supported = rdt_features.rdta_supported  = 0;
		plog_info("cqm and cat features disabled by config file\n");
	}
	return (rdt_features.rdta_supported && rdt_features.l3_cat_supported);
}

int rdt_is_supported(void)
{
	return (cmt_is_supported() || cat_is_supported());
}

int rdt_get_features(struct rdt_features* feat)
{
	if (!cmt_is_supported() && !cat_is_supported())
		return 1;

	*feat = rdt_features;
	return 0;
}

int cqm_assoc(uint8_t lcore_id, uint64_t rmid)
{
	uint64_t val = 0;
	int ret = 0;
	ret = msr_read(&val, lcore_id, IA32_QM_ASSOC);
	if (ret != 0) {
		plog_err("Unable to read msr %x on core %u\n", IA32_QM_ASSOC, lcore_id);
	}
	val &= 0x3FFULL;
	plog_dbg("core %u, rmid was %lu, now setting to %lu\n", lcore_id, val, rmid);
	val |= (uint64_t)(rmid & 0x3FFULL);
	ret = msr_write(lcore_id, rmid, IA32_QM_ASSOC);
	if (ret != 0) {
		plog_err("Unable to set msr %x on core %u to value %lx\n", IA32_QM_ASSOC, lcore_id, val);
	}
	return ret;
}

int cqm_assoc_read(uint8_t lcore_id, uint64_t *rmid)
{
	return msr_read(rmid, lcore_id, IA32_QM_ASSOC);
}

void rdt_init_stat_core(uint8_t lcore_id)
{
	stat_core = lcore_id;
}

/* read a specific rmid value using core 0 */
int cmt_read_ctr(uint64_t* ret, uint64_t rmid, uint8_t lcore_id)
{
	uint64_t event_id = L3_CACHE_OCCUPANCY;

	uint64_t es = rmid;
	es = (es << 32) | event_id;

	if (msr_write(lcore_id, es, IA32_QM_EVTSEL) < 0) {
		return 1;
	}

	if (msr_read(ret, lcore_id, IA32_QM_CTR) < 0) {
		return 2;
	}

	return 0;
}

int mbm_read_tot_bdw(uint64_t* ret, uint64_t rmid, uint8_t lcore_id)
{
	uint64_t event_id = L3_TOTAL_EXTERNAL_BANDWIDTH;

	uint64_t es = rmid;
	es = (es << 32) | event_id;

	if (msr_write(lcore_id, es, IA32_QM_EVTSEL) < 0) {
		return 1;
	}

	if (msr_read(ret, lcore_id, IA32_QM_CTR) < 0) {
		return 2;
	}
	return 0;
}

int mbm_read_loc_bdw(uint64_t* ret, uint64_t rmid, uint8_t lcore_id)
{
	uint64_t event_id = L3_LOCAL_EXTERNAL_BANDWIDTH;

	uint64_t es = rmid;
	es = (es << 32) | event_id;

	if (msr_write(lcore_id, es, IA32_QM_EVTSEL) < 0) {
		return 1;
	}

	if (msr_read(ret, lcore_id, IA32_QM_CTR) < 0) {
		return 2;
	}
	return 0;
}

int cat_log_init(uint8_t lcore_id)
{
	uint64_t tmp_rmid;
	int rc, i = 0;
	for (i = 0; i < IA32_QM_L3CA_END - IA32_QM_L3CA_START; i++) {
		rc = msr_read(&tmp_rmid,lcore_id,IA32_QM_L3CA_START + i);
		if (rc < 0) {
			break;
		}
		plog_info("\tAt initialization: Cache allocation set %d (msr %x): mask %lx\n", i, IA32_QM_L3CA_START + i, tmp_rmid);
	}
	return i;
}

int cat_set_class_mask(uint8_t lcore_id, uint32_t set, uint32_t mask)
{
	uint64_t tmp_rmid;
	int rc;
	rc = msr_write(lcore_id, mask, IA32_QM_L3CA_START + set);
	if (rc < 0) {
		plog_err("Failed to write Cache allocation\n");
		return -1;
	}
	return 0;
}

int cat_get_class_mask(uint8_t lcore_id, uint32_t set, uint32_t *mask)
{
	uint64_t tmp_rmid;
	int rc;
	rc = msr_read(&tmp_rmid,lcore_id,IA32_QM_L3CA_START + set);
	if (rc < 0) {
		plog_err("Failed to read Cache allocation\n");
		return -1;
	}
	*mask = tmp_rmid & 0xffffffff;
	return 0;
}

void cat_reset_cache(uint32_t lcore_id)
{
	int rc;
	uint32_t mask = (1 << rdt_features.cat_num_ways) -1;
	for (uint32_t set = 0; set <= rdt_features.cat_max_rmid; set++) {
		rc = msr_write(lcore_id, mask, IA32_QM_L3CA_START + set);
		if (rc < 0) {
			plog_err("Failed to reset Cache allocation\n");
		}
	}
}

int cat_get_num_ways(void)
{
	return rdt_features.cat_num_ways;
}
