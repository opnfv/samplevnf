/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <rte_common.h>
#include <rte_dev.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_cryptodev_pmd.h>
#include <rte_atomic.h>
#include <rte_prefetch.h>

#include "qat_logs.h"
#include "qat_crypto.h"
#include "adf_transport_access_macros.h"

#define ADF_MAX_SYM_DESC			4096
#define ADF_MIN_SYM_DESC			128
#define ADF_SYM_TX_RING_DESC_SIZE		128
#define ADF_SYM_RX_RING_DESC_SIZE		32
#define ADF_SYM_TX_QUEUE_STARTOFF		2
/* Offset from bundle start to 1st Sym Tx queue */
#define ADF_SYM_RX_QUEUE_STARTOFF		10
#define ADF_ARB_REG_SLOT			0x1000
#define ADF_ARB_RINGSRVARBEN_OFFSET		0x19C

#define WRITE_CSR_ARB_RINGSRVARBEN(csr_addr, index, value) \
	ADF_CSR_WR(csr_addr, ADF_ARB_RINGSRVARBEN_OFFSET + \
	(ADF_ARB_REG_SLOT * index), value)

static int qat_qp_check_queue_alignment(uint64_t phys_addr,
	uint32_t queue_size_bytes);
static int qat_tx_queue_create(struct rte_cryptodev *dev,
	struct qat_queue *queue, uint8_t id, uint32_t nb_desc,
	int socket_id);
static int qat_rx_queue_create(struct rte_cryptodev *dev,
	struct qat_queue *queue, uint8_t id, uint32_t nb_desc,
	int socket_id);
static void qat_queue_delete(struct qat_queue *queue);
static int qat_queue_create(struct rte_cryptodev *dev,
	struct qat_queue *queue, uint32_t nb_desc, uint8_t desc_size,
	int socket_id);
static int adf_verify_queue_size(uint32_t msg_size, uint32_t msg_num,
	uint32_t *queue_size_for_csr);
static void adf_configure_queues(struct qat_qp *queue);
static void adf_queue_arb_enable(struct qat_queue *txq, void *base_addr);
static void adf_queue_arb_disable(struct qat_queue *txq, void *base_addr);

static const struct rte_memzone *
queue_dma_zone_reserve(const char *queue_name, uint32_t queue_size,
			int socket_id)
{
	const struct rte_memzone *mz;
	unsigned memzone_flags = 0;
	const struct rte_memseg *ms;

	PMD_INIT_FUNC_TRACE();
	mz = rte_memzone_lookup(queue_name);
	if (mz != 0) {
		if (((size_t)queue_size <= mz->len) &&
				((socket_id == SOCKET_ID_ANY) ||
					(socket_id == mz->socket_id))) {
			PMD_DRV_LOG(DEBUG, "re-use memzone already "
					"allocated for %s", queue_name);
			return mz;
		}

		PMD_DRV_LOG(ERR, "Incompatible memzone already "
				"allocated %s, size %u, socket %d. "
				"Requested size %u, socket %u",
				queue_name, (uint32_t)mz->len,
				mz->socket_id, queue_size, socket_id);
		return NULL;
	}

	PMD_DRV_LOG(DEBUG, "Allocate memzone for %s, size %u on socket %u",
					queue_name, queue_size, socket_id);
	ms = rte_eal_get_physmem_layout();
	switch (ms[0].hugepage_sz) {
	case(RTE_PGSIZE_2M):
		memzone_flags = RTE_MEMZONE_2MB;
	break;
	case(RTE_PGSIZE_1G):
		memzone_flags = RTE_MEMZONE_1GB;
	break;
	case(RTE_PGSIZE_16M):
		memzone_flags = RTE_MEMZONE_16MB;
	break;
	case(RTE_PGSIZE_16G):
		memzone_flags = RTE_MEMZONE_16GB;
	break;
	default:
		memzone_flags = RTE_MEMZONE_SIZE_HINT_ONLY;
}
#ifdef RTE_LIBRTE_XEN_DOM0
	return rte_memzone_reserve_bounded(queue_name, queue_size,
		socket_id, 0, RTE_CACHE_LINE_SIZE, RTE_PGSIZE_2M);
#else
	return rte_memzone_reserve_aligned(queue_name, queue_size, socket_id,
		memzone_flags, queue_size);
#endif
}

int qat_crypto_sym_qp_setup(struct rte_cryptodev *dev, uint16_t queue_pair_id,
	const struct rte_cryptodev_qp_conf *qp_conf,
	int socket_id)
{
	struct qat_qp *qp;
	int ret;

	PMD_INIT_FUNC_TRACE();

	/* If qp is already in use free ring memory and qp metadata. */
	if (dev->data->queue_pairs[queue_pair_id] != NULL) {
		ret = qat_crypto_sym_qp_release(dev, queue_pair_id);
		if (ret < 0)
			return ret;
	}

	if ((qp_conf->nb_descriptors > ADF_MAX_SYM_DESC) ||
		(qp_conf->nb_descriptors < ADF_MIN_SYM_DESC)) {
		PMD_DRV_LOG(ERR, "Can't create qp for %u descriptors",
				qp_conf->nb_descriptors);
		return -EINVAL;
	}

	if (dev->pci_dev->mem_resource[0].addr == NULL) {
		PMD_DRV_LOG(ERR, "Could not find VF config space "
				"(UIO driver attached?).");
		return -EINVAL;
	}

	if (queue_pair_id >=
			(ADF_NUM_SYM_QPS_PER_BUNDLE *
					ADF_NUM_BUNDLES_PER_DEV)) {
		PMD_DRV_LOG(ERR, "qp_id %u invalid for this device",
				queue_pair_id);
		return -EINVAL;
	}

	/* Allocate the queue pair data structure. */
	qp = rte_zmalloc("qat PMD qp metadata",
			sizeof(*qp), RTE_CACHE_LINE_SIZE);
	if (qp == NULL) {
		PMD_DRV_LOG(ERR, "Failed to alloc mem for qp struct");
		return -ENOMEM;
	}
	qp->mmap_bar_addr = dev->pci_dev->mem_resource[0].addr;
	rte_atomic16_init(&qp->inflights16);

	if (qat_tx_queue_create(dev, &(qp->tx_q),
		queue_pair_id, qp_conf->nb_descriptors, socket_id) != 0) {
		PMD_INIT_LOG(ERR, "Tx queue create failed "
				"queue_pair_id=%u", queue_pair_id);
		goto create_err;
	}

	if (qat_rx_queue_create(dev, &(qp->rx_q),
		queue_pair_id, qp_conf->nb_descriptors, socket_id) != 0) {
		PMD_DRV_LOG(ERR, "Rx queue create failed "
				"queue_pair_id=%hu", queue_pair_id);
		qat_queue_delete(&(qp->tx_q));
		goto create_err;
	}
	adf_configure_queues(qp);
	adf_queue_arb_enable(&qp->tx_q, qp->mmap_bar_addr);
	dev->data->queue_pairs[queue_pair_id] = qp;
	return 0;

create_err:
	rte_free(qp);
	return -EFAULT;
}

int qat_crypto_sym_qp_release(struct rte_cryptodev *dev, uint16_t queue_pair_id)
{
	struct qat_qp *qp =
			(struct qat_qp *)dev->data->queue_pairs[queue_pair_id];

	PMD_INIT_FUNC_TRACE();
	if (qp == NULL) {
		PMD_DRV_LOG(DEBUG, "qp already freed");
		return 0;
	}

	/* Don't free memory if there are still responses to be processed */
	if (rte_atomic16_read(&(qp->inflights16)) == 0) {
		qat_queue_delete(&(qp->tx_q));
		qat_queue_delete(&(qp->rx_q));
	} else {
		return -EAGAIN;
	}

	adf_queue_arb_disable(&(qp->tx_q), qp->mmap_bar_addr);
	rte_free(qp);
	dev->data->queue_pairs[queue_pair_id] = NULL;
	return 0;
}

static int qat_tx_queue_create(struct rte_cryptodev *dev,
	struct qat_queue *queue, uint8_t qp_id,
	uint32_t nb_desc, int socket_id)
{
	PMD_INIT_FUNC_TRACE();
	queue->hw_bundle_number = qp_id/ADF_NUM_SYM_QPS_PER_BUNDLE;
	queue->hw_queue_number = (qp_id%ADF_NUM_SYM_QPS_PER_BUNDLE) +
						ADF_SYM_TX_QUEUE_STARTOFF;
	PMD_DRV_LOG(DEBUG, "TX ring for %u msgs: qp_id %d, bundle %u, ring %u",
		nb_desc, qp_id, queue->hw_bundle_number,
		queue->hw_queue_number);

	return qat_queue_create(dev, queue, nb_desc,
				ADF_SYM_TX_RING_DESC_SIZE, socket_id);
}

static int qat_rx_queue_create(struct rte_cryptodev *dev,
		struct qat_queue *queue, uint8_t qp_id, uint32_t nb_desc,
		int socket_id)
{
	PMD_INIT_FUNC_TRACE();
	queue->hw_bundle_number = qp_id/ADF_NUM_SYM_QPS_PER_BUNDLE;
	queue->hw_queue_number = (qp_id%ADF_NUM_SYM_QPS_PER_BUNDLE) +
						ADF_SYM_RX_QUEUE_STARTOFF;

	PMD_DRV_LOG(DEBUG, "RX ring for %u msgs: qp id %d, bundle %u, ring %u",
		nb_desc, qp_id, queue->hw_bundle_number,
		queue->hw_queue_number);
	return qat_queue_create(dev, queue, nb_desc,
				ADF_SYM_RX_RING_DESC_SIZE, socket_id);
}

static void qat_queue_delete(struct qat_queue *queue)
{
	const struct rte_memzone *mz;
	int status = 0;

	if (queue == NULL) {
		PMD_DRV_LOG(DEBUG, "Invalid queue");
		return;
	}
	mz = rte_memzone_lookup(queue->memz_name);
	if (mz != NULL)	{
		/* Write an unused pattern to the queue memory. */
		memset(queue->base_addr, 0x7F, queue->queue_size);
		status = rte_memzone_free(mz);
		if (status != 0)
			PMD_DRV_LOG(ERR, "Error %d on freeing queue %s",
					status, queue->memz_name);
	} else {
		PMD_DRV_LOG(DEBUG, "queue %s doesn't exist",
				queue->memz_name);
	}
}

static int
qat_queue_create(struct rte_cryptodev *dev, struct qat_queue *queue,
		uint32_t nb_desc, uint8_t desc_size, int socket_id)
{
	uint64_t queue_base;
	void *io_addr;
	const struct rte_memzone *qp_mz;
	uint32_t queue_size_bytes = nb_desc*desc_size;

	PMD_INIT_FUNC_TRACE();
	if (desc_size > ADF_MSG_SIZE_TO_BYTES(ADF_MAX_MSG_SIZE)) {
		PMD_DRV_LOG(ERR, "Invalid descriptor size %d", desc_size);
		return -EINVAL;
	}

	/*
	 * Allocate a memzone for the queue - create a unique name.
	 */
	snprintf(queue->memz_name, sizeof(queue->memz_name), "%s_%s_%d_%d_%d",
		dev->driver->pci_drv.name, "qp_mem", dev->data->dev_id,
		queue->hw_bundle_number, queue->hw_queue_number);
	qp_mz = queue_dma_zone_reserve(queue->memz_name, queue_size_bytes,
			socket_id);
	if (qp_mz == NULL) {
		PMD_DRV_LOG(ERR, "Failed to allocate ring memzone");
		return -ENOMEM;
	}

	queue->base_addr = (char *)qp_mz->addr;
	queue->base_phys_addr = qp_mz->phys_addr;
	if (qat_qp_check_queue_alignment(queue->base_phys_addr,
			queue_size_bytes)) {
		PMD_DRV_LOG(ERR, "Invalid alignment on queue create "
					" 0x%"PRIx64"\n",
					queue->base_phys_addr);
		return -EFAULT;
	}

	if (adf_verify_queue_size(desc_size, nb_desc, &(queue->queue_size))
			!= 0) {
		PMD_DRV_LOG(ERR, "Invalid num inflights");
		return -EINVAL;
	}

	queue->max_inflights = ADF_MAX_INFLIGHTS(queue->queue_size,
					ADF_BYTES_TO_MSG_SIZE(desc_size));
	queue->modulo = ADF_RING_SIZE_MODULO(queue->queue_size);
	PMD_DRV_LOG(DEBUG, "RING size in CSR: %u, in bytes %u, nb msgs %u,"
				" msg_size %u, max_inflights %u modulo %u",
				queue->queue_size, queue_size_bytes,
				nb_desc, desc_size, queue->max_inflights,
				queue->modulo);

	if (queue->max_inflights < 2) {
		PMD_DRV_LOG(ERR, "Invalid num inflights");
		return -EINVAL;
	}
	queue->head = 0;
	queue->tail = 0;
	queue->msg_size = desc_size;

	/*
	 * Write an unused pattern to the queue memory.
	 */
	memset(queue->base_addr, 0x7F, queue_size_bytes);

	queue_base = BUILD_RING_BASE_ADDR(queue->base_phys_addr,
					queue->queue_size);
	io_addr = dev->pci_dev->mem_resource[0].addr;

	WRITE_CSR_RING_BASE(io_addr, queue->hw_bundle_number,
			queue->hw_queue_number, queue_base);
	return 0;
}

static int qat_qp_check_queue_alignment(uint64_t phys_addr,
					uint32_t queue_size_bytes)
{
	PMD_INIT_FUNC_TRACE();
	if (((queue_size_bytes - 1) & phys_addr) != 0)
		return -EINVAL;
	return 0;
}

static int adf_verify_queue_size(uint32_t msg_size, uint32_t msg_num,
	uint32_t *p_queue_size_for_csr)
{
	uint8_t i = ADF_MIN_RING_SIZE;

	PMD_INIT_FUNC_TRACE();
	for (; i <= ADF_MAX_RING_SIZE; i++)
		if ((msg_size * msg_num) ==
				(uint32_t)ADF_SIZE_TO_RING_SIZE_IN_BYTES(i)) {
			*p_queue_size_for_csr = i;
			return 0;
		}
	PMD_DRV_LOG(ERR, "Invalid ring size %d", msg_size * msg_num);
	return -EINVAL;
}

static void adf_queue_arb_enable(struct qat_queue *txq, void *base_addr)
{
	uint32_t arb_csr_offset =  ADF_ARB_RINGSRVARBEN_OFFSET +
					(ADF_ARB_REG_SLOT *
							txq->hw_bundle_number);
	uint32_t value;

	PMD_INIT_FUNC_TRACE();
	value = ADF_CSR_RD(base_addr, arb_csr_offset);
	value |= (0x01 << txq->hw_queue_number);
	ADF_CSR_WR(base_addr, arb_csr_offset, value);
}

static void adf_queue_arb_disable(struct qat_queue *txq, void *base_addr)
{
	uint32_t arb_csr_offset =  ADF_ARB_RINGSRVARBEN_OFFSET +
					(ADF_ARB_REG_SLOT *
							txq->hw_bundle_number);
	uint32_t value;

	PMD_INIT_FUNC_TRACE();
	value = ADF_CSR_RD(base_addr, arb_csr_offset);
	value ^= (0x01 << txq->hw_queue_number);
	ADF_CSR_WR(base_addr, arb_csr_offset, value);
}

static void adf_configure_queues(struct qat_qp *qp)
{
	uint32_t queue_config;
	struct qat_queue *queue = &qp->tx_q;

	PMD_INIT_FUNC_TRACE();
	queue_config = BUILD_RING_CONFIG(queue->queue_size);

	WRITE_CSR_RING_CONFIG(qp->mmap_bar_addr, queue->hw_bundle_number,
			queue->hw_queue_number, queue_config);

	queue = &qp->rx_q;
	queue_config =
			BUILD_RESP_RING_CONFIG(queue->queue_size,
					ADF_RING_NEAR_WATERMARK_512,
					ADF_RING_NEAR_WATERMARK_0);

	WRITE_CSR_RING_CONFIG(qp->mmap_bar_addr, queue->hw_bundle_number,
			queue->hw_queue_number, queue_config);
}
