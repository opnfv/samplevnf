/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2016 IGEL Co., Ltd.
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
 *     * Neither the name of IGEL Co.,Ltd. nor the names of its
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
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#ifdef RTE_LIBRTE_VHOST_NUMA
#include <numaif.h>
#endif

#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_dev.h>
#include <rte_kvargs.h>
#include <rte_virtio_net.h>
#include <rte_spinlock.h>

#include "rte_eth_vhost.h"

#define ETH_VHOST_IFACE_ARG		"iface"
#define ETH_VHOST_QUEUES_ARG		"queues"

static const char *drivername = "VHOST PMD";

static const char *valid_arguments[] = {
	ETH_VHOST_IFACE_ARG,
	ETH_VHOST_QUEUES_ARG,
	NULL
};

static struct ether_addr base_eth_addr = {
	.addr_bytes = {
		0x56 /* V */,
		0x48 /* H */,
		0x4F /* O */,
		0x53 /* S */,
		0x54 /* T */,
		0x00
	}
};

struct vhost_queue {
	rte_atomic32_t allow_queuing;
	rte_atomic32_t while_queuing;
	struct virtio_net *device;
	struct pmd_internal *internal;
	struct rte_mempool *mb_pool;
	uint8_t port;
	uint16_t virtqueue_id;
	uint64_t rx_pkts;
	uint64_t tx_pkts;
	uint64_t missed_pkts;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
};

struct pmd_internal {
	char *dev_name;
	char *iface_name;
	uint16_t max_queues;

	volatile uint16_t once;
};

struct internal_list {
	TAILQ_ENTRY(internal_list) next;
	struct rte_eth_dev *eth_dev;
};

TAILQ_HEAD(internal_list_head, internal_list);
static struct internal_list_head internal_list =
	TAILQ_HEAD_INITIALIZER(internal_list);

static pthread_mutex_t internal_list_lock = PTHREAD_MUTEX_INITIALIZER;

static rte_atomic16_t nb_started_ports;
static pthread_t session_th;

static struct rte_eth_link pmd_link = {
		.link_speed = 10000,
		.link_duplex = ETH_LINK_FULL_DUPLEX,
		.link_status = ETH_LINK_DOWN
};

struct rte_vhost_vring_state {
	rte_spinlock_t lock;

	bool cur[RTE_MAX_QUEUES_PER_PORT * 2];
	bool seen[RTE_MAX_QUEUES_PER_PORT * 2];
	unsigned int index;
	unsigned int max_vring;
};

static struct rte_vhost_vring_state *vring_states[RTE_MAX_ETHPORTS];

static uint16_t
eth_vhost_rx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	struct vhost_queue *r = q;
	uint16_t i, nb_rx = 0;

	if (unlikely(rte_atomic32_read(&r->allow_queuing) == 0))
		return 0;

	rte_atomic32_set(&r->while_queuing, 1);

	if (unlikely(rte_atomic32_read(&r->allow_queuing) == 0))
		goto out;

	/* Dequeue packets from guest TX queue */
	nb_rx = rte_vhost_dequeue_burst(r->device,
			r->virtqueue_id, r->mb_pool, bufs, nb_bufs);

	r->rx_pkts += nb_rx;

	for (i = 0; likely(i < nb_rx); i++) {
		bufs[i]->port = r->port;
		r->rx_bytes += bufs[i]->pkt_len;
	}

out:
	rte_atomic32_set(&r->while_queuing, 0);

	return nb_rx;
}

static uint16_t
eth_vhost_tx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	struct vhost_queue *r = q;
	uint16_t i, nb_tx = 0;

	if (unlikely(rte_atomic32_read(&r->allow_queuing) == 0))
		return 0;

	rte_atomic32_set(&r->while_queuing, 1);

	if (unlikely(rte_atomic32_read(&r->allow_queuing) == 0))
		goto out;

	/* Enqueue packets to guest RX queue */
	nb_tx = rte_vhost_enqueue_burst(r->device,
			r->virtqueue_id, bufs, nb_bufs);

	r->tx_pkts += nb_tx;
	r->missed_pkts += nb_bufs - nb_tx;

	for (i = 0; likely(i < nb_tx); i++)
		r->tx_bytes += bufs[i]->pkt_len;

	for (i = 0; likely(i < nb_tx); i++)
		rte_pktmbuf_free(bufs[i]);
out:
	rte_atomic32_set(&r->while_queuing, 0);

	return nb_tx;
}

static int
eth_dev_configure(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static inline struct internal_list *
find_internal_resource(char *ifname)
{
	int found = 0;
	struct internal_list *list;
	struct pmd_internal *internal;

	if (ifname == NULL)
		return NULL;

	pthread_mutex_lock(&internal_list_lock);

	TAILQ_FOREACH(list, &internal_list, next) {
		internal = list->eth_dev->data->dev_private;
		if (!strcmp(internal->iface_name, ifname)) {
			found = 1;
			break;
		}
	}

	pthread_mutex_unlock(&internal_list_lock);

	if (!found)
		return NULL;

	return list;
}

static int
new_device(struct virtio_net *dev)
{
	struct rte_eth_dev *eth_dev;
	struct internal_list *list;
	struct pmd_internal *internal;
	struct vhost_queue *vq;
	unsigned i;
#ifdef RTE_LIBRTE_VHOST_NUMA
	int newnode, ret;
#endif

	if (dev == NULL) {
		RTE_LOG(INFO, PMD, "Invalid argument\n");
		return -1;
	}

	list = find_internal_resource(dev->ifname);
	if (list == NULL) {
		RTE_LOG(INFO, PMD, "Invalid device name\n");
		return -1;
	}

	eth_dev = list->eth_dev;
	internal = eth_dev->data->dev_private;

#ifdef RTE_LIBRTE_VHOST_NUMA
	ret  = get_mempolicy(&newnode, NULL, 0, dev,
			MPOL_F_NODE | MPOL_F_ADDR);
	if (ret < 0) {
		RTE_LOG(ERR, PMD, "Unknown numa node\n");
		return -1;
	}

	eth_dev->data->numa_node = newnode;
#endif

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		vq = eth_dev->data->rx_queues[i];
		if (vq == NULL)
			continue;
		vq->device = dev;
		vq->internal = internal;
		vq->port = eth_dev->data->port_id;
	}
	for (i = 0; i < eth_dev->data->nb_tx_queues; i++) {
		vq = eth_dev->data->tx_queues[i];
		if (vq == NULL)
			continue;
		vq->device = dev;
		vq->internal = internal;
		vq->port = eth_dev->data->port_id;
	}

	for (i = 0; i < dev->virt_qp_nb * VIRTIO_QNUM; i++)
		rte_vhost_enable_guest_notification(dev, i, 0);

	dev->flags |= VIRTIO_DEV_RUNNING;
	dev->priv = eth_dev;
	eth_dev->data->dev_link.link_status = ETH_LINK_UP;

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		vq = eth_dev->data->rx_queues[i];
		if (vq == NULL)
			continue;
		rte_atomic32_set(&vq->allow_queuing, 1);
	}
	for (i = 0; i < eth_dev->data->nb_tx_queues; i++) {
		vq = eth_dev->data->tx_queues[i];
		if (vq == NULL)
			continue;
		rte_atomic32_set(&vq->allow_queuing, 1);
	}

	RTE_LOG(INFO, PMD, "New connection established\n");

	_rte_eth_dev_callback_process(eth_dev, RTE_ETH_EVENT_INTR_LSC);

	return 0;
}

static void
destroy_device(volatile struct virtio_net *dev)
{
	struct rte_eth_dev *eth_dev;
	struct vhost_queue *vq;
	unsigned i;

	if (dev == NULL) {
		RTE_LOG(INFO, PMD, "Invalid argument\n");
		return;
	}

	eth_dev = (struct rte_eth_dev *)dev->priv;
	if (eth_dev == NULL) {
		RTE_LOG(INFO, PMD, "Failed to find a ethdev\n");
		return;
	}

	/* Wait until rx/tx_pkt_burst stops accessing vhost device */
	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		vq = eth_dev->data->rx_queues[i];
		if (vq == NULL)
			continue;
		rte_atomic32_set(&vq->allow_queuing, 0);
		while (rte_atomic32_read(&vq->while_queuing))
			rte_pause();
	}
	for (i = 0; i < eth_dev->data->nb_tx_queues; i++) {
		vq = eth_dev->data->tx_queues[i];
		if (vq == NULL)
			continue;
		rte_atomic32_set(&vq->allow_queuing, 0);
		while (rte_atomic32_read(&vq->while_queuing))
			rte_pause();
	}

	eth_dev->data->dev_link.link_status = ETH_LINK_DOWN;

	dev->priv = NULL;
	dev->flags &= ~VIRTIO_DEV_RUNNING;

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		vq = eth_dev->data->rx_queues[i];
		if (vq == NULL)
			continue;
		vq->device = NULL;
	}
	for (i = 0; i < eth_dev->data->nb_tx_queues; i++) {
		vq = eth_dev->data->tx_queues[i];
		if (vq == NULL)
			continue;
		vq->device = NULL;
	}

	RTE_LOG(INFO, PMD, "Connection closed\n");

	_rte_eth_dev_callback_process(eth_dev, RTE_ETH_EVENT_INTR_LSC);
}

static int
vring_state_changed(struct virtio_net *dev, uint16_t vring, int enable)
{
	struct rte_vhost_vring_state *state;
	struct rte_eth_dev *eth_dev;
	struct internal_list *list;

	if (dev == NULL) {
		RTE_LOG(ERR, PMD, "Invalid argument\n");
		return -1;
	}

	list = find_internal_resource(dev->ifname);
	if (list == NULL) {
		RTE_LOG(ERR, PMD, "Invalid interface name: %s\n", dev->ifname);
		return -1;
	}

	eth_dev = list->eth_dev;
	/* won't be NULL */
	state = vring_states[eth_dev->data->port_id];
	rte_spinlock_lock(&state->lock);
	state->cur[vring] = enable;
	state->max_vring = RTE_MAX(vring, state->max_vring);
	rte_spinlock_unlock(&state->lock);

	RTE_LOG(INFO, PMD, "vring%u is %s\n",
			vring, enable ? "enabled" : "disabled");

	_rte_eth_dev_callback_process(eth_dev, RTE_ETH_EVENT_QUEUE_STATE);

	return 0;
}

int
rte_eth_vhost_get_queue_event(uint8_t port_id,
		struct rte_eth_vhost_queue_event *event)
{
	struct rte_vhost_vring_state *state;
	unsigned int i;
	int idx;

	if (port_id >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, PMD, "Invalid port id\n");
		return -1;
	}

	state = vring_states[port_id];
	if (!state) {
		RTE_LOG(ERR, PMD, "Unused port\n");
		return -1;
	}

	rte_spinlock_lock(&state->lock);
	for (i = 0; i <= state->max_vring; i++) {
		idx = state->index++ % (state->max_vring + 1);

		if (state->cur[idx] != state->seen[idx]) {
			state->seen[idx] = state->cur[idx];
			event->queue_id = idx / 2;
			event->rx = idx & 1;
			event->enable = state->cur[idx];
			rte_spinlock_unlock(&state->lock);
			return 0;
		}
	}
	rte_spinlock_unlock(&state->lock);

	return -1;
}

static void *
vhost_driver_session(void *param __rte_unused)
{
	static struct virtio_net_device_ops vhost_ops;

	/* set vhost arguments */
	vhost_ops.new_device = new_device;
	vhost_ops.destroy_device = destroy_device;
	vhost_ops.vring_state_changed = vring_state_changed;
	if (rte_vhost_driver_callback_register(&vhost_ops) < 0)
		RTE_LOG(ERR, PMD, "Can't register callbacks\n");

	/* start event handling */
	rte_vhost_driver_session_start();

	return NULL;
}

static int
vhost_driver_session_start(void)
{
	int ret;

	ret = pthread_create(&session_th,
			NULL, vhost_driver_session, NULL);
	if (ret)
		RTE_LOG(ERR, PMD, "Can't create a thread\n");

	return ret;
}

static void
vhost_driver_session_stop(void)
{
	int ret;

	ret = pthread_cancel(session_th);
	if (ret)
		RTE_LOG(ERR, PMD, "Can't cancel the thread\n");

	ret = pthread_join(session_th, NULL);
	if (ret)
		RTE_LOG(ERR, PMD, "Can't join the thread\n");
}

static int
eth_dev_start(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal = dev->data->dev_private;
	int ret = 0;

	if (rte_atomic16_cmpset(&internal->once, 0, 1)) {
		ret = rte_vhost_driver_register(internal->iface_name);
		if (ret)
			return ret;
	}

	/* We need only one message handling thread */
	if (rte_atomic16_add_return(&nb_started_ports, 1) == 1)
		ret = vhost_driver_session_start();

	return ret;
}

static void
eth_dev_stop(struct rte_eth_dev *dev)
{
	struct pmd_internal *internal = dev->data->dev_private;

	if (rte_atomic16_cmpset(&internal->once, 1, 0))
		rte_vhost_driver_unregister(internal->iface_name);

	if (rte_atomic16_sub_return(&nb_started_ports, 1) == 0)
		vhost_driver_session_stop();
}

static int
eth_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
		   uint16_t nb_rx_desc __rte_unused,
		   unsigned int socket_id,
		   const struct rte_eth_rxconf *rx_conf __rte_unused,
		   struct rte_mempool *mb_pool)
{
	struct vhost_queue *vq;

	vq = rte_zmalloc_socket(NULL, sizeof(struct vhost_queue),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (vq == NULL) {
		RTE_LOG(ERR, PMD, "Failed to allocate memory for rx queue\n");
		return -ENOMEM;
	}

	vq->mb_pool = mb_pool;
	vq->virtqueue_id = rx_queue_id * VIRTIO_QNUM + VIRTIO_TXQ;
	dev->data->rx_queues[rx_queue_id] = vq;

	return 0;
}

static int
eth_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
		   uint16_t nb_tx_desc __rte_unused,
		   unsigned int socket_id,
		   const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct vhost_queue *vq;

	vq = rte_zmalloc_socket(NULL, sizeof(struct vhost_queue),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (vq == NULL) {
		RTE_LOG(ERR, PMD, "Failed to allocate memory for tx queue\n");
		return -ENOMEM;
	}

	vq->virtqueue_id = tx_queue_id * VIRTIO_QNUM + VIRTIO_RXQ;
	dev->data->tx_queues[tx_queue_id] = vq;

	return 0;
}

static void
eth_dev_info(struct rte_eth_dev *dev,
	     struct rte_eth_dev_info *dev_info)
{
	struct pmd_internal *internal;

	internal = dev->data->dev_private;
	if (internal == NULL) {
		RTE_LOG(ERR, PMD, "Invalid device specified\n");
		return;
	}

	dev_info->driver_name = drivername;
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = (uint32_t)-1;
	dev_info->max_rx_queues = internal->max_queues;
	dev_info->max_tx_queues = internal->max_queues;
	dev_info->min_rx_bufsize = 0;
}

static void
eth_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	unsigned i;
	unsigned long rx_total = 0, tx_total = 0, tx_missed_total = 0;
	unsigned long rx_total_bytes = 0, tx_total_bytes = 0;
	struct vhost_queue *vq;

	for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS &&
			i < dev->data->nb_rx_queues; i++) {
		if (dev->data->rx_queues[i] == NULL)
			continue;
		vq = dev->data->rx_queues[i];
		stats->q_ipackets[i] = vq->rx_pkts;
		rx_total += stats->q_ipackets[i];

		stats->q_ibytes[i] = vq->rx_bytes;
		rx_total_bytes += stats->q_ibytes[i];
	}

	for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS &&
			i < dev->data->nb_tx_queues; i++) {
		if (dev->data->tx_queues[i] == NULL)
			continue;
		vq = dev->data->tx_queues[i];
		stats->q_opackets[i] = vq->tx_pkts;
		tx_missed_total += vq->missed_pkts;
		tx_total += stats->q_opackets[i];

		stats->q_obytes[i] = vq->tx_bytes;
		tx_total_bytes += stats->q_obytes[i];
	}

	stats->ipackets = rx_total;
	stats->opackets = tx_total;
	stats->imissed = tx_missed_total;
	stats->ibytes = rx_total_bytes;
	stats->obytes = tx_total_bytes;
}

static void
eth_stats_reset(struct rte_eth_dev *dev)
{
	struct vhost_queue *vq;
	unsigned i;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		if (dev->data->rx_queues[i] == NULL)
			continue;
		vq = dev->data->rx_queues[i];
		vq->rx_pkts = 0;
		vq->rx_bytes = 0;
	}
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		if (dev->data->tx_queues[i] == NULL)
			continue;
		vq = dev->data->tx_queues[i];
		vq->tx_pkts = 0;
		vq->tx_bytes = 0;
		vq->missed_pkts = 0;
	}
}

static void
eth_queue_release(void *q)
{
	rte_free(q);
}

static int
eth_link_update(struct rte_eth_dev *dev __rte_unused,
		int wait_to_complete __rte_unused)
{
	return 0;
}

/**
 * Disable features in feature_mask. Returns 0 on success.
 */
int
rte_eth_vhost_feature_disable(uint64_t feature_mask)
{
	return rte_vhost_feature_disable(feature_mask);
}

/**
 * Enable features in feature_mask. Returns 0 on success.
 */
int
rte_eth_vhost_feature_enable(uint64_t feature_mask)
{
	return rte_vhost_feature_enable(feature_mask);
}

/* Returns currently supported vhost features */
uint64_t
rte_eth_vhost_feature_get(void)
{
	return rte_vhost_feature_get();
}

static const struct eth_dev_ops ops = {
	.dev_start = eth_dev_start,
	.dev_stop = eth_dev_stop,
	.dev_configure = eth_dev_configure,
	.dev_infos_get = eth_dev_info,
	.rx_queue_setup = eth_rx_queue_setup,
	.tx_queue_setup = eth_tx_queue_setup,
	.rx_queue_release = eth_queue_release,
	.tx_queue_release = eth_queue_release,
	.link_update = eth_link_update,
	.stats_get = eth_stats_get,
	.stats_reset = eth_stats_reset,
};

static int
eth_dev_vhost_create(const char *name, char *iface_name, int16_t queues,
		     const unsigned numa_node)
{
	struct rte_eth_dev_data *data = NULL;
	struct pmd_internal *internal = NULL;
	struct rte_eth_dev *eth_dev = NULL;
	struct ether_addr *eth_addr = NULL;
	struct rte_vhost_vring_state *vring_state = NULL;
	struct internal_list *list = NULL;

	RTE_LOG(INFO, PMD, "Creating VHOST-USER backend on numa socket %u\n",
		numa_node);

	/* now do all data allocation - for eth_dev structure, dummy pci driver
	 * and internal (private) data
	 */
	data = rte_zmalloc_socket(name, sizeof(*data), 0, numa_node);
	if (data == NULL)
		goto error;

	internal = rte_zmalloc_socket(name, sizeof(*internal), 0, numa_node);
	if (internal == NULL)
		goto error;

	list = rte_zmalloc_socket(name, sizeof(*list), 0, numa_node);
	if (list == NULL)
		goto error;

	/* reserve an ethdev entry */
	eth_dev = rte_eth_dev_allocate(name, RTE_ETH_DEV_VIRTUAL);
	if (eth_dev == NULL)
		goto error;

	eth_addr = rte_zmalloc_socket(name, sizeof(*eth_addr), 0, numa_node);
	if (eth_addr == NULL)
		goto error;
	*eth_addr = base_eth_addr;
	eth_addr->addr_bytes[5] = eth_dev->data->port_id;

	vring_state = rte_zmalloc_socket(name,
			sizeof(*vring_state), 0, numa_node);
	if (vring_state == NULL)
		goto error;

	TAILQ_INIT(&eth_dev->link_intr_cbs);

	/* now put it all together
	 * - store queue data in internal,
	 * - store numa_node info in ethdev data
	 * - point eth_dev_data to internals
	 * - and point eth_dev structure to new eth_dev_data structure
	 */
	internal->dev_name = strdup(name);
	if (internal->dev_name == NULL)
		goto error;
	internal->iface_name = strdup(iface_name);
	if (internal->iface_name == NULL)
		goto error;

	list->eth_dev = eth_dev;
	pthread_mutex_lock(&internal_list_lock);
	TAILQ_INSERT_TAIL(&internal_list, list, next);
	pthread_mutex_unlock(&internal_list_lock);

	rte_spinlock_init(&vring_state->lock);
	vring_states[eth_dev->data->port_id] = vring_state;

	data->dev_private = internal;
	data->port_id = eth_dev->data->port_id;
	memmove(data->name, eth_dev->data->name, sizeof(data->name));
	data->nb_rx_queues = queues;
	data->nb_tx_queues = queues;
	internal->max_queues = queues;
	data->dev_link = pmd_link;
	data->mac_addrs = eth_addr;

	/* We'll replace the 'data' originally allocated by eth_dev. So the
	 * vhost PMD resources won't be shared between multi processes.
	 */
	eth_dev->data = data;
	eth_dev->dev_ops = &ops;
	eth_dev->driver = NULL;
	data->dev_flags =
		RTE_ETH_DEV_DETACHABLE | RTE_ETH_DEV_INTR_LSC;
	data->kdrv = RTE_KDRV_NONE;
	data->drv_name = internal->dev_name;
	data->numa_node = numa_node;

	/* finally assign rx and tx ops */
	eth_dev->rx_pkt_burst = eth_vhost_rx;
	eth_dev->tx_pkt_burst = eth_vhost_tx;

	return data->port_id;

error:
	if (internal)
		free(internal->dev_name);
	rte_free(vring_state);
	rte_free(eth_addr);
	if (eth_dev)
		rte_eth_dev_release_port(eth_dev);
	rte_free(internal);
	rte_free(list);
	rte_free(data);

	return -1;
}

static inline int
open_iface(const char *key __rte_unused, const char *value, void *extra_args)
{
	const char **iface_name = extra_args;

	if (value == NULL)
		return -1;

	*iface_name = value;

	return 0;
}

static inline int
open_queues(const char *key __rte_unused, const char *value, void *extra_args)
{
	uint16_t *q = extra_args;

	if (value == NULL || extra_args == NULL)
		return -EINVAL;

	*q = (uint16_t)strtoul(value, NULL, 0);
	if (*q == USHRT_MAX && errno == ERANGE)
		return -1;

	if (*q > RTE_MAX_QUEUES_PER_PORT)
		return -1;

	return 0;
}

static int
rte_pmd_vhost_devinit(const char *name, const char *params)
{
	struct rte_kvargs *kvlist = NULL;
	int ret = 0;
	char *iface_name;
	uint16_t queues;

	RTE_LOG(INFO, PMD, "Initializing pmd_vhost for %s\n", name);

	kvlist = rte_kvargs_parse(params, valid_arguments);
	if (kvlist == NULL)
		return -1;

	if (rte_kvargs_count(kvlist, ETH_VHOST_IFACE_ARG) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_VHOST_IFACE_ARG,
					 &open_iface, &iface_name);
		if (ret < 0)
			goto out_free;
	} else {
		ret = -1;
		goto out_free;
	}

	if (rte_kvargs_count(kvlist, ETH_VHOST_QUEUES_ARG) == 1) {
		ret = rte_kvargs_process(kvlist, ETH_VHOST_QUEUES_ARG,
					 &open_queues, &queues);
		if (ret < 0)
			goto out_free;

	} else
		queues = 1;

	eth_dev_vhost_create(name, iface_name, queues, rte_socket_id());

out_free:
	rte_kvargs_free(kvlist);
	return ret;
}

static int
rte_pmd_vhost_devuninit(const char *name)
{
	struct rte_eth_dev *eth_dev = NULL;
	struct pmd_internal *internal;
	struct internal_list *list;
	unsigned int i;

	RTE_LOG(INFO, PMD, "Un-Initializing pmd_vhost for %s\n", name);

	/* find an ethdev entry */
	eth_dev = rte_eth_dev_allocated(name);
	if (eth_dev == NULL)
		return -ENODEV;

	internal = eth_dev->data->dev_private;
	if (internal == NULL)
		return -ENODEV;

	list = find_internal_resource(internal->iface_name);
	if (list == NULL)
		return -ENODEV;

	pthread_mutex_lock(&internal_list_lock);
	TAILQ_REMOVE(&internal_list, list, next);
	pthread_mutex_unlock(&internal_list_lock);
	rte_free(list);

	eth_dev_stop(eth_dev);

	rte_free(vring_states[eth_dev->data->port_id]);
	vring_states[eth_dev->data->port_id] = NULL;

	free(internal->dev_name);
	free(internal->iface_name);

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++)
		rte_free(eth_dev->data->rx_queues[i]);
	for (i = 0; i < eth_dev->data->nb_tx_queues; i++)
		rte_free(eth_dev->data->tx_queues[i]);

	rte_free(eth_dev->data->mac_addrs);
	rte_free(eth_dev->data);
	rte_free(internal);

	rte_eth_dev_release_port(eth_dev);

	return 0;
}

static struct rte_driver pmd_vhost_drv = {
	.name = "eth_vhost",
	.type = PMD_VDEV,
	.init = rte_pmd_vhost_devinit,
	.uninit = rte_pmd_vhost_devuninit,
};

PMD_REGISTER_DRIVER(pmd_vhost_drv);
