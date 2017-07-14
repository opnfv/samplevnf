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

#ifndef _EXPIRE_CPE_H_
#define _EXPIRE_CPE_H_

#include <rte_table_hash.h>

struct expire_cpe {
	struct rte_table_hash *cpe_table;
	struct cpe_data *cpe_data;
	uint32_t bucket_index;
};

void check_expire_cpe(void *data);

#endif /* _EXPIRE_CPE_H_ */
