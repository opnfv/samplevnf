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

#ifndef _FLOW_ITER_H_
#define _FLOW_ITER_H_

struct task_args;

struct flow_iter {
	/* Returns a new iterator pointing to the beginning of the collection. */
	void             (*beg)(struct flow_iter *iter, struct task_args *targ);
	/* Returns non-zero when parameter is pointing past the end of the collection. */
	int              (*is_end)(struct flow_iter *iter, struct task_args *targ);
	/* Moves iterator parameter forward by one. */
	void             (*next)(struct flow_iter *iter, struct task_args *targ);
	/* Access data. */
	uint16_t         (*get_svlan)(struct flow_iter *iter, struct task_args *targ);
	uint16_t         (*get_cvlan)(struct flow_iter *iter, struct task_args *targ);
	uint32_t         (*get_gre_id)(struct flow_iter *iter, struct task_args *targ);
	int              idx;
	uint8_t          data;
};

#endif /* _FLOW_ITER_H_ */
