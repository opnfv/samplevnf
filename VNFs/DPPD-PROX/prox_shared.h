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

#ifndef _PROX_SHARED_H_
#define _PROX_SHARED_H_

#include <rte_ether.h>

/* Data can be shared at different levels. The levels are core wide,
   socket wide and system wide. */
int prox_sh_add_system(const char *name, void *data);
int prox_sh_add_socket(const int socket_id, const char *name, void *data);
int prox_sh_add_core(const int core_id, const char *name, void *data);

void *prox_sh_find_system(const char *name);
void *prox_sh_find_socket(const int socket_id, const char *name);
void *prox_sh_find_core(const int core_id, const char *name);

#endif /* _PROX_SHARED_H_ */
