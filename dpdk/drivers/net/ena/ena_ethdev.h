/*-
* BSD LICENSE
*
* Copyright (c) 2015-2016 Amazon.com, Inc. or its affiliates.
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* * Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* * Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in
* the documentation and/or other materials provided with the
* distribution.
* * Neither the name of copyright holder nor the names of its
* contributors may be used to endorse or promote products derived
* from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _ENA_ETHDEV_H_
#define _ENA_ETHDEV_H_

#include <rte_pci.h>

#include "ena_com.h"

#define ENA_REGS_BAR	0
#define ENA_MEM_BAR	2

#define ENA_MAX_NUM_QUEUES	128

#define ENA_DEFAULT_TX_SW_DESCS	(1024)
#define ENA_DEFAULT_TX_HW_DESCS	(1024)
#define ENA_DEFAULT_RING_SIZE	(1024)

#define ENA_MIN_FRAME_LEN	64

#define ENA_NAME_MAX_LEN     20
#define ENA_IRQNAME_SIZE     40

#define ENA_PKT_MAX_BUFS     17

#define	ENA_CIRC_COUNT(head, tail, size)				\
	(((uint16_t)((uint16_t)(head) - (uint16_t)(tail))) & ((size) - 1))

#define ENA_CIRC_INC(index, step, size)					\
	((uint16_t)(index) + (uint16_t)(step))
#define	ENA_CIRC_INC_WRAP(index, step, size)				\
	(((uint16_t)(index) + (uint16_t)(step))	& ((size) - 1))

#define	ENA_TX_RING_IDX_NEXT(idx, ring_size)				\
		ENA_CIRC_INC_WRAP(idx, 1, ring_size)
#define	ENA_RX_RING_IDX_NEXT(idx, ring_size)				\
		ENA_CIRC_INC_WRAP(idx, 1, ring_size)

struct ena_adapter;

enum ena_ring_type {
	ENA_RING_TYPE_RX = 1,
	ENA_RING_TYPE_TX = 2,
};

struct ena_tx_buffer {
	struct rte_mbuf *mbuf;
	unsigned int tx_descs;
	unsigned int num_of_bufs;
	struct ena_com_buf bufs[ENA_PKT_MAX_BUFS];
};

struct ena_ring {
	u16 next_to_use;
	u16 next_to_clean;

	enum ena_ring_type type;
	enum ena_admin_placement_policy_type tx_mem_queue_type;
	/* Holds the empty requests for TX OOO completions */
	uint16_t *empty_tx_reqs;
	union {
		struct ena_tx_buffer *tx_buffer_info; /* contex of tx packet */
		struct rte_mbuf **rx_buffer_info; /* contex of rx packet */
	};
	unsigned int ring_size; /* number of tx/rx_buffer_info's entries */

	struct ena_com_io_cq *ena_com_io_cq;
	struct ena_com_io_sq *ena_com_io_sq;

	struct ena_com_rx_buf_info ena_bufs[ENA_PKT_MAX_BUFS]
						__rte_cache_aligned;

	struct rte_mempool *mb_pool;
	unsigned int port_id;
	unsigned int id;
	/* Max length PMD can push to device for LLQ */
	uint8_t tx_max_header_size;
	int configured;
	struct ena_adapter *adapter;
} __rte_cache_aligned;

enum ena_adapter_state {
	ENA_ADAPTER_STATE_FREE    = 0,
	ENA_ADAPTER_STATE_INIT    = 1,
	ENA_ADAPTER_STATE_RUNNING  = 2,
	ENA_ADAPTER_STATE_STOPPED = 3,
	ENA_ADAPTER_STATE_CONFIG  = 4,
};

struct ena_driver_stats {
	rte_atomic64_t ierrors;
	rte_atomic64_t oerrors;
	rte_atomic64_t imcasts;
	rte_atomic64_t rx_nombuf;
};

/* board specific private data structure */
struct ena_adapter {
	/* OS defined structs */
	struct rte_pci_device *pdev;
	struct rte_eth_dev_data *rte_eth_dev_data;
	struct rte_eth_dev *rte_dev;

	struct ena_com_dev ena_dev __rte_cache_aligned;

	/* TX */
	struct ena_ring tx_ring[ENA_MAX_NUM_QUEUES] __rte_cache_aligned;
	int tx_ring_size;

	/* RX */
	struct ena_ring rx_ring[ENA_MAX_NUM_QUEUES] __rte_cache_aligned;
	int rx_ring_size;

	u16 num_queues;
	u16 max_mtu;

	int id_number;
	char name[ENA_NAME_MAX_LEN];
	u8 mac_addr[ETHER_ADDR_LEN];

	void *regs;
	void *dev_mem_base;

	struct ena_driver_stats *drv_stats;
	enum ena_adapter_state state;

};

#endif /* _ENA_ETHDEV_H_ */
