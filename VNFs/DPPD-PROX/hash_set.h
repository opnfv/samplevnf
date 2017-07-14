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

#ifndef _HASH_SET_H_
#define _HASH_SET_H_

struct hash_set;

struct hash_set *hash_set_create(uint32_t n_buckets, int socket_id);
void *hash_set_find(struct hash_set *hs, void *data, size_t len);
void hash_set_add(struct hash_set *hs, void *data, size_t len);

#endif /* _HASH_SET_H_ */
