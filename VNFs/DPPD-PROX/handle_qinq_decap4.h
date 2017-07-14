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

#ifndef _HANDLE_QINQ_DECAP4_H_
#define _HANDLE_QINQ_DECAP4_H_

#include "hash_entry_types.h"

struct rte_table_hash;

struct arp_msg {
	struct cpe_key key;
	struct cpe_data data;
};

void arp_msg_to_str(char *str, struct arp_msg *msg);
int str_to_arp_msg(struct arp_msg *msg, const char *str);

void arp_update_from_msg(struct rte_table_hash * cpe_table, struct arp_msg **msgs, uint16_t n_msgs, uint64_t cpe_timeout);

#endif /* _HANDLE_QINQ_DECAP4_H_ */
