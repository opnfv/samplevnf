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

#ifndef _HEAP_H_
#define _HEAP_H_

#include <inttypes.h>
#include <stdlib.h>

struct heap_ref {
	struct heap_elem *elem;   /* timer management */
};

struct heap {
	uint64_t n_elems;
	struct heap_elem *top;
	uint64_t n_avail;
	struct heap_elem *avail[0];
};

static uint64_t heap_n_elems(const struct heap *h)
{
	return h->n_elems;
}

static int heap_is_empty(const struct heap *h)
{
	return !h->n_elems;
}

int heap_top_is_lower(struct heap *h, uint64_t prio);

void heap_print(struct heap *h, char *result, size_t buf_len);

struct heap *heap_create(uint32_t max_elems, int socket_id);
void heap_add(struct heap *h, struct heap_ref *ref, uint64_t priority);
void heap_del(struct heap *h, struct heap_ref *del);
struct heap_ref *heap_pop(struct heap *h);

#endif /* _HEAP_H_ */
