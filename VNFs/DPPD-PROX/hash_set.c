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

#include <rte_hash_crc.h>
#include <string.h>

#include "prox_malloc.h"
#include "prox_assert.h"
#include "hash_set.h"

#define HASH_SET_ALLOC_CHUNCK 1024
#define HASH_SET_ALLOC_CHUNCK_MEM (sizeof(struct hash_set_entry) * 1024)

struct hash_set_entry {
	uint32_t              crc;
	void                  *data;
	size_t                len;
	struct hash_set_entry *next;
};

struct hash_set {
	uint32_t              n_buckets;
	int                   socket_id;
	struct hash_set_entry *alloc;
	size_t                alloc_count;
	struct hash_set_entry *mem[0];
};

static struct hash_set_entry *hash_set_alloc_entry(struct hash_set *hs)
{
	struct hash_set_entry *ret;

	if (hs->alloc_count == 0) {
		size_t mem_size = HASH_SET_ALLOC_CHUNCK *
			sizeof(struct hash_set_entry);

		hs->alloc = prox_zmalloc(mem_size, hs->socket_id);
		hs->alloc_count = HASH_SET_ALLOC_CHUNCK;
	}

	ret = hs->alloc;
	hs->alloc++;
	hs->alloc_count--;
	return ret;
}

struct hash_set *hash_set_create(uint32_t n_buckets, int socket_id)
{
	struct hash_set *ret;
	size_t mem_size = sizeof(*ret) + sizeof(ret->mem[0]) * n_buckets;

	ret = prox_zmalloc(mem_size, socket_id);
	ret->n_buckets = n_buckets;
	ret->socket_id = socket_id;

	return ret;
}

void *hash_set_find(struct hash_set *hs, void *data, size_t len)
{
	uint32_t crc = rte_hash_crc(data, len, 0);

	struct hash_set_entry *entry = hs->mem[crc % hs->n_buckets];

	while (entry) {
		if (entry->crc == crc && entry->len == len &&
		    memcmp(entry->data, data, len) == 0)
			return entry->data;
		entry = entry->next;
	}
	return NULL;
}

void hash_set_add(struct hash_set *hs, void *data, size_t len)
{
	uint32_t crc = rte_hash_crc(data, len, 0);
	struct hash_set_entry *new = hash_set_alloc_entry(hs);

	new->data = data;
	new->len = len;
	new->crc = crc;

	if (hs->mem[crc % hs->n_buckets]) {
		struct hash_set_entry *entry = hs->mem[crc % hs->n_buckets];
		while (entry->next)
			entry = entry->next;
		entry->next = new;
	}
	else {
		hs->mem[crc % hs->n_buckets] = new;
	}
}
