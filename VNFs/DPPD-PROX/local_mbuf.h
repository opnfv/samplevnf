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

#ifndef _LOCAL_MBUF_H_
#define _LOCAL_MBUF_H_
#define LOCAL_MBUF_COUNT 64

struct local_mbuf {
	struct rte_mempool *mempool;
	uint32_t           n_new_pkts;
	struct rte_mbuf    *new_pkts[LOCAL_MBUF_COUNT];
};

static struct rte_mbuf **local_mbuf_take(struct local_mbuf *local_mbuf, uint32_t count)
{
	PROX_ASSERT(local_mbuf->n_new_pkts >= count);

	const uint32_t start_pos = local_mbuf->n_new_pkts - count;
	struct rte_mbuf **ret = &local_mbuf->new_pkts[start_pos];

	local_mbuf->n_new_pkts -= count;
	return ret;
}

static int local_mbuf_refill(struct local_mbuf *local_mbuf)
{
	const uint32_t fill = LOCAL_MBUF_COUNT - local_mbuf->n_new_pkts;
	struct rte_mbuf **fill_mbuf = &local_mbuf->new_pkts[local_mbuf->n_new_pkts];

	if (rte_mempool_get_bulk(local_mbuf->mempool, (void **)fill_mbuf, fill) < 0)
		return -1;
	local_mbuf->n_new_pkts += fill;
	return 0;
}

/* Ensures that count or more mbufs are available. Returns pointer to
   count allocated mbufs or NULL if not enough mbufs are available. */
static struct rte_mbuf **local_mbuf_refill_and_take(struct local_mbuf *local_mbuf, uint32_t count)
{
	PROX_ASSERT(count <= LOCAL_MBUF_COUNT);
	if (local_mbuf->n_new_pkts >= count)
		return local_mbuf_take(local_mbuf, count);

	if (local_mbuf_refill(local_mbuf) == 0)
		return local_mbuf_take(local_mbuf, count);
	return NULL;
}

#endif /* _LOCAL_MBUF_H_ */
