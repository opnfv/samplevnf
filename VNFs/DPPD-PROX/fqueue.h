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

#ifndef _FQUEUE_H_
#define _FQUEUE_H_

#include <rte_mbuf.h>

#include <inttypes.h>

struct fqueue {
	uint32_t prod;
	uint32_t cons;
	uint32_t mask;
	struct rte_mbuf *entries[0];
};

static uint32_t fqueue_put(struct fqueue *q, struct rte_mbuf **mbufs, uint32_t count)
{
	uint32_t free_entries = q->mask + q->cons - q->prod;
	uint32_t beg = q->prod & q->mask;

	count = count > free_entries? free_entries : count;

	if ((q->prod & q->mask) + count <= q->mask) {
		rte_memcpy(&q->entries[q->prod & q->mask], mbufs, sizeof(mbufs[0]) * count);
		q->prod += count;
	}
	else {
		for (uint32_t i = 0; i < count; ++i) {
			q->entries[q->prod & q->mask] = mbufs[i];
			q->prod++;
		}
	}
	return count;
}

static uint32_t fqueue_get(struct fqueue *q, struct rte_mbuf **mbufs, uint32_t count)
{
	uint32_t entries = q->prod - q->cons;

	count = count > entries? entries : count;

	if ((q->cons & q->mask) + count <= q->mask) {
		rte_memcpy(mbufs, &q->entries[q->cons & q->mask], sizeof(mbufs[0]) * count);
		q->cons += count;
	}
	else {
         	for (uint32_t i = 0; i < count; ++i) {
			mbufs[i] = q->entries[q->cons & q->mask];
			q->cons++;
		}
	}
	return count;
}

static struct fqueue *fqueue_create(uint32_t size, int socket)
{
	size_t mem_size = 0;

	mem_size += sizeof(struct fqueue);
	mem_size += sizeof(((struct fqueue *)(0))->entries[0]) * size;

	struct fqueue *ret = prox_zmalloc(mem_size, socket);

	if (!ret)
		return NULL;

	ret->mask = size - 1;
	return ret;
}

#endif /* _FQUEUE_H_ */
