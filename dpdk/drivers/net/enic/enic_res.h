/*
 * Copyright 2008-2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright 2007 Nuova Systems, Inc.  All rights reserved.
 *
 * Copyright (c) 2014, Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in
 * the documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _ENIC_RES_H_
#define _ENIC_RES_H_

#include "wq_enet_desc.h"
#include "rq_enet_desc.h"
#include "vnic_wq.h"
#include "vnic_rq.h"

#define ENIC_MIN_WQ_DESCS		64
#define ENIC_MAX_WQ_DESCS		4096
#define ENIC_MIN_RQ_DESCS		64
#define ENIC_MAX_RQ_DESCS		4096

#define ENIC_MIN_MTU			68
#define ENIC_MAX_MTU			9000

#define ENIC_MULTICAST_PERFECT_FILTERS	32
#define ENIC_UNICAST_PERFECT_FILTERS	32

#define ENIC_NON_TSO_MAX_DESC		16
#define ENIC_DEFAULT_RX_FREE_THRESH	32
#define ENIC_TX_POST_THRESH		(ENIC_MIN_WQ_DESCS / 2)

#define ENIC_SETTING(enic, f) ((enic->config.flags & VENETF_##f) ? 1 : 0)

static inline void enic_queue_wq_desc_ex(struct vnic_wq *wq,
	void *os_buf, dma_addr_t dma_addr, unsigned int len,
	unsigned int mss_or_csum_offset, unsigned int hdr_len,
	int vlan_tag_insert, unsigned int vlan_tag,
	int offload_mode, int cq_entry, int sop, int eop, int loopback)
{
	struct wq_enet_desc *desc = vnic_wq_next_desc(wq);
	u8 desc_skip_cnt = 1;
	u8 compressed_send = 0;
	u64 wrid = 0;

	wq_enet_desc_enc(desc,
		(u64)dma_addr | VNIC_PADDR_TARGET,
		(u16)len,
		(u16)mss_or_csum_offset,
		(u16)hdr_len, (u8)offload_mode,
		(u8)eop, (u8)cq_entry,
		0, /* fcoe_encap */
		(u8)vlan_tag_insert,
		(u16)vlan_tag,
		(u8)loopback);

	vnic_wq_post(wq, os_buf, dma_addr, len, sop, eop, desc_skip_cnt,
			(u8)cq_entry, compressed_send, wrid);
}

static inline void enic_queue_wq_desc_cont(struct vnic_wq *wq,
	void *os_buf, dma_addr_t dma_addr, unsigned int len,
	int eop, int loopback)
{
	enic_queue_wq_desc_ex(wq, os_buf, dma_addr, len,
		0, 0, 0, 0, 0,
		eop, 0 /* !SOP */, eop, loopback);
}

static inline void enic_queue_wq_desc(struct vnic_wq *wq, void *os_buf,
	dma_addr_t dma_addr, unsigned int len, int vlan_tag_insert,
	unsigned int vlan_tag, int eop, int loopback)
{
	enic_queue_wq_desc_ex(wq, os_buf, dma_addr, len,
		0, 0, vlan_tag_insert, vlan_tag,
		WQ_ENET_OFFLOAD_MODE_CSUM,
		eop, 1 /* SOP */, eop, loopback);
}

static inline void enic_queue_wq_desc_csum(struct vnic_wq *wq,
	void *os_buf, dma_addr_t dma_addr, unsigned int len,
	int ip_csum, int tcpudp_csum, int vlan_tag_insert,
	unsigned int vlan_tag, int eop, int loopback)
{
	enic_queue_wq_desc_ex(wq, os_buf, dma_addr, len,
		(ip_csum ? 1 : 0) + (tcpudp_csum ? 2 : 0),
		0, vlan_tag_insert, vlan_tag,
		WQ_ENET_OFFLOAD_MODE_CSUM,
		eop, 1 /* SOP */, eop, loopback);
}

static inline void enic_queue_wq_desc_csum_l4(struct vnic_wq *wq,
	void *os_buf, dma_addr_t dma_addr, unsigned int len,
	unsigned int csum_offset, unsigned int hdr_len,
	int vlan_tag_insert, unsigned int vlan_tag, int eop, int loopback)
{
	enic_queue_wq_desc_ex(wq, os_buf, dma_addr, len,
		csum_offset, hdr_len, vlan_tag_insert, vlan_tag,
		WQ_ENET_OFFLOAD_MODE_CSUM_L4,
		eop, 1 /* SOP */, eop, loopback);
}

static inline void enic_queue_wq_desc_tso(struct vnic_wq *wq,
	void *os_buf, dma_addr_t dma_addr, unsigned int len,
	unsigned int mss, unsigned int hdr_len, int vlan_tag_insert,
	unsigned int vlan_tag, int eop, int loopback)
{
	enic_queue_wq_desc_ex(wq, os_buf, dma_addr, len,
		mss, hdr_len, vlan_tag_insert, vlan_tag,
		WQ_ENET_OFFLOAD_MODE_TSO,
		eop, 1 /* SOP */, eop, loopback);
}

struct enic;

int enic_get_vnic_config(struct enic *);
int enic_add_vlan(struct enic *enic, u16 vlanid);
int enic_del_vlan(struct enic *enic, u16 vlanid);
int enic_set_nic_cfg(struct enic *enic, u8 rss_default_cpu, u8 rss_hash_type,
	u8 rss_hash_bits, u8 rss_base_cpu, u8 rss_enable, u8 tso_ipid_split_en,
	u8 ig_vlan_strip_en);
int enic_set_rss_key(struct enic *enic, dma_addr_t key_pa, u64 len);
int enic_set_rss_cpu(struct enic *enic, dma_addr_t cpu_pa, u64 len);
void enic_get_res_counts(struct enic *enic);
void enic_init_vnic_resources(struct enic *enic);
int enic_alloc_vnic_resources(struct enic *);
void enic_free_vnic_resources(struct enic *);

#endif /* _ENIC_RES_H_ */
