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

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <rte_version.h>
#include <rte_prefetch.h>
#include <rte_memory.h>

#include "prox_malloc.h"
#include "prox_assert.h"
#include "heap.h"
#include "log.h"

#include <string.h>
#include <stddef.h>
#include <stdlib.h>

struct heap_elem {
	uint64_t priority;
	struct heap_ref *ref;
	struct heap_elem *prev;
	struct heap_elem *next;
	struct heap_elem *child;
};

struct strl {
	char *str;
	size_t len;
};

int heap_top_is_lower(struct heap *h, uint64_t prio)
{
	return !heap_is_empty(h) && h->top->priority < prio;
}

static int heap_elem_check(struct heap_elem *e, int is_top)
{
	if (!e)
		return 1;
	if (e != e->prev &&
	    e != e->next &&
	    e != e->child)
		return 1;
	else
		return 0;

	if (is_top && e->prev != NULL)
		return 0;
	if (!is_top && e->prev == NULL)
		return 0;

	if (e->next) {
		if (e->next->prev != e)
			return 0;

		if (heap_elem_check(e->next, 0))
			return 1;
		else
			return 0;
	}

	if (e->child) {
		if (e->child->prev != e)
			return 0;

		if (heap_elem_check(e->child, 0))
			return 1;
		else
			return 0;
	}

	return 1;
}

static int heap_elem_in_heap_elem(struct heap_elem *in, struct heap_elem *find)
{
	if (in == find)
		return 1;

	if (in->next) {
		if (heap_elem_in_heap_elem(in->next, find))
			return 1;
	}
	if (in->child) {
		if (heap_elem_in_heap_elem(in->child, find))
			return 1;
	}

	return 0;
}

static int heap_elem_in_heap(struct heap *h, struct heap_elem *e)
{
	if (h->top == NULL)
		return 0;

	return heap_elem_in_heap_elem(h->top, e);
}

static int heap_elem_is_avail(struct heap *h, struct heap_elem *e)
{
	for (uint32_t i = 0; i < h->n_avail; ++i) {
		if (h->avail[i] == e)
			return 1;
	}
	return 0;
}

static uint32_t heap_elem_calc_size(struct heap_elem *e)
{
	int ret = 0;

	if (e)
		ret++;
	else
		return ret;

	if (e->next)
		ret += heap_elem_calc_size(e->next);
	if (e->child)
		ret += heap_elem_calc_size(e->child);
	return ret;
}

static uint32_t heap_calc_size(struct heap *h)
{
	return heap_elem_calc_size(h->top);
}

static void cat_indent(struct strl *s, int indent)
{
	size_t r;

	if (s->len < 50)
		return ;

	for (int i = 0; i < indent; ++i) {
		r = snprintf(s->str, s->len, " ");
		s->str += r;
		s->len -= r;
	}
}

static void cat_priority(struct strl *s, uint64_t priority)
{
	size_t r;

	if (s->len < 50)
		return ;

	r = snprintf(s->str, s->len, "%"PRIu64"\n", priority);
	s->str += r;
	s->len -= r;
}

static void heap_print2(struct heap_elem *e, int indent, struct strl *s)
{
	size_t r;

	cat_indent(s, indent);
	cat_priority(s, e->priority);

	struct heap_elem *child = e->child;

	while (child) {
		heap_print2(child, indent + 1, s);
		child = child->next;
	}
}

static void heap_print3(struct heap_elem *e, char *result, size_t buf_len)
{
	struct strl s;

	s.str = result;
	s.len = buf_len;

	heap_print2(e, 0, &s);
}

void heap_print(struct heap *h, char *result, size_t buf_len)
{
	if (h->n_elems == 0) {
		*result = 0;
		return ;
	}

	heap_print3(h->top, result, buf_len);
}

struct heap *heap_create(uint32_t max_elems, int socket_id)
{
	struct heap *ret;
	size_t mem_size = 0;
	size_t elem_mem = 0;
	struct heap_elem *e;

	/* max_elems + 1 since index start at 1. Store total number of
	   elements in the first entry (which is unused otherwise). */
	mem_size += sizeof(struct heap);
	mem_size += sizeof(((struct heap *)0)->top) * max_elems;
	mem_size = RTE_CACHE_LINE_ROUNDUP(mem_size);
	elem_mem = mem_size;
	mem_size += sizeof(*((struct heap *)0)->top) * max_elems;
	ret = prox_zmalloc(mem_size, socket_id);
	if (!ret)
		return NULL;

	e = (struct heap_elem *)(((uint8_t *)ret) + elem_mem);
	PROX_ASSERT((void *)&e[max_elems] <= (void *)ret + mem_size);

	for (uint32_t i = 0; i < max_elems; ++i) {
		PROX_ASSERT(e->priority == 0);
		PROX_ASSERT(e->ref == 0);
		PROX_ASSERT(e->prev == 0);
		PROX_ASSERT(e->next == 0);
		PROX_ASSERT(e->child == 0);

		ret->avail[ret->n_avail++] = e++;
	}

	PROX_ASSERT(ret->n_elems + ret->n_avail == max_elems);
	return ret;
}

static struct heap_elem *heap_get(struct heap *h)
{
	PROX_ASSERT(h->n_avail);

	return h->avail[--h->n_avail];
}

static void heap_put(struct heap *h, struct heap_elem *e)
{
	h->avail[h->n_avail++] = e;
}

void heap_add(struct heap *h, struct heap_ref *ref, uint64_t priority)
{
	PROX_ASSERT(h);
	PROX_ASSERT(ref);
	PROX_ASSERT(ref->elem == NULL);
	PROX_ASSERT(heap_elem_check(h->top, 1));
	PROX_ASSERT(h->n_elems == heap_calc_size(h));

	if (h->n_elems == 0) {
		h->n_elems++;
		h->top = heap_get(h);

		h->top->priority = priority;
		h->top->ref = ref;
		ref->elem = h->top;
		h->top->prev = NULL;
		h->top->next = NULL;
		h->top->child = NULL;

		PROX_ASSERT(heap_elem_check(h->top, 1));
		PROX_ASSERT(h->n_elems == heap_calc_size(h));
		return ;
	}

	h->n_elems++;
	/* New element becomes new top */
	if (h->top->priority > priority) {
		struct heap_elem *n = heap_get(h);

		n->priority = priority;
		n->ref = ref;
		ref->elem = n;
		n->prev = NULL;
		n->next = NULL;
		n->child = h->top;

		h->top->prev = n;
		h->top = n;
	}
	/* New element is added as first sibling */
	else {
		struct heap_elem *n = heap_get(h);
		n->priority = priority;
		n->ref = ref;
		ref->elem = n;
		n->prev = h->top;
		n->next = h->top->child;
		if (h->top->child)
			h->top->child->prev = n;
		n->child = NULL;
		h->top->child = n;
	}

	PROX_ASSERT(heap_elem_check(h->top, 1));
	PROX_ASSERT(h->n_elems == heap_calc_size(h));
}

static void heap_merge_tops_left(struct heap_elem *left, struct heap_elem *right)
{
	PROX_ASSERT(left->priority <= right->priority);
	PROX_ASSERT(left != right);

	/* right moves down and becomes first child of left. */
	left->next = right->next;
	if (right->next)
		right->next->prev = left;

	right->next = left->child;
	if (left->child)
		left->child->prev = right;

	/* right->prev is now referring to parent since right is the
	   new first child. */
	left->child = right;
}

static void heap_merge_tops_right(struct heap_elem *left, struct heap_elem *right)
{
	PROX_ASSERT(left->priority >= right->priority);
	PROX_ASSERT(left != right);

	/* Left goes down one layer */
	right->prev = left->prev;
	if (left->prev)
		left->prev->next = right;

	left->next = right->child;
	if (right->child)
		right->child->prev = left;

	left->prev = right;
	right->child = left;
}

static struct heap_elem *heap_merge_children(struct heap_elem *e)
{
	struct heap_elem *next = e->next;
	struct heap_elem *tmp;
	struct heap_elem *prev;
	struct heap_elem *first;

	PROX_ASSERT(e);
	int cnt = 0;
	/* TODO: is this really needed? */
	if (!next)
		return e;

	if (e->priority < next->priority)
		first = e;
	else
		first = next;

	/* Forward pass */
	do {
		cnt++;
		tmp = next->next;
		rte_prefetch0(tmp);
		if (e->priority < next->priority) {
			heap_merge_tops_left(e, next);
			prev = e;
			PROX_ASSERT(e->child == next);
		}
		else {
			heap_merge_tops_right(e, next);
			PROX_ASSERT(next->child == e);
			prev = next;
		}

		if (tmp) {
			tmp->prev = prev;
			e = tmp;
			/* Next could be empty, (uneven # children) */
			if (!tmp->next)
				break;
			next = tmp->next;
		}
		else {
			/* Even number of nodes, after breaking set e
			   to the last merged pair top */
			if (e->priority >= next->priority)
				e = next;
			break;
		}
	} while (1);
	/* Backward pass, merge everything with the right until the
	   first child */
	while (first != e) {
		prev = e->prev;

		if (e->priority < prev->priority) {
			heap_merge_tops_right(prev, e);
			if (prev == first) {
				first = e;
				break;
			}
		}
		else {
			heap_merge_tops_left(prev, e);
			e = prev;
		}
	}
	return first;
}

static int heap_elem_first_sibling(const struct heap_elem *e)
{
	return e->prev->child == e;
}

void heap_del(struct heap *h, struct heap_ref *d)
{
	struct heap_elem *del = d->elem;

	PROX_ASSERT(del);
	PROX_ASSERT(heap_elem_in_heap(h, del));
	PROX_ASSERT(!heap_elem_is_avail(h, del));
	PROX_ASSERT(h->n_elems == heap_calc_size(h));
	PROX_ASSERT(heap_elem_check(h->top, 1));
	PROX_ASSERT(h->top->next == NULL);
	PROX_ASSERT(h->top->prev == NULL);

	d->elem = NULL;
	/* Del is at the top */
	if (del->prev == NULL) {
		PROX_ASSERT(del == h->top);
		if (del->child) {
			del->child->prev = NULL;
			h->top = heap_merge_children(del->child);
			PROX_ASSERT(h->top);
		}
		else {
			h->top = NULL;
		}

		h->n_elems--;
		heap_put(h, del);
		PROX_ASSERT(heap_elem_check(h->top, 1));
		PROX_ASSERT(h->n_elems == 0 || h->top != NULL);
		PROX_ASSERT(h->n_elems == heap_calc_size(h));
		return ;
	}
	PROX_ASSERT(del != h->top);

	/* Del is somewhere in a lower layer. If it the first child,
	   need to fix the parent differently. */
	if (heap_elem_first_sibling(del)) {
		del->prev->child = del->next;
		if (del->next)
			del->next->prev = del->prev;
	}
	else {
		del->prev->next = del->next;
		if (del->next)
			del->next->prev = del->prev;
	}

	struct heap_elem *top2 = del->child;

	/* If the node to be deleted has children, there is more work:
	   merge the children into a single heap and merge with
	   top. If there are no children, then the disconnection above
	   is enough. */
	if (top2) {
		top2->prev = NULL;
		top2 = heap_merge_children(top2);

		/* Merge top2 with h->top */
		if (h->top->priority < top2->priority) {
			top2->next = h->top->child;
			top2->prev = h->top;
			if (h->top->child)
				h->top->child->prev = top2;

			h->top->child = top2;
		}
		else {
			h->top->next = top2->child;
			h->top->prev = top2;
			if (top2->child)
				top2->child->prev = h->top;

			top2->child = h->top;
			h->top = top2;
		}

	}
	h->n_elems--;
	heap_put(h, del);

	PROX_ASSERT(heap_elem_check(h->top, 1));
	PROX_ASSERT(h->n_elems == heap_calc_size(h));
}

struct heap_ref *heap_pop(struct heap *h)
{
	if (h->n_elems == 0)
		return NULL;

	struct heap_ref *ret = h->top->ref;

	heap_del(h, h->top->ref);
	return ret;
}
