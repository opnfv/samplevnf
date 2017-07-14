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

#ifndef _MAIN_H_
#define _MAIN_H_

#include <rte_version.h>
#include "hash_entry_types.h"
#ifdef RTE_EXEC_ENV_BAREMETAL
#error A linuxapp configuration target is required!
#endif

#if RTE_VERSION < RTE_VERSION_NUM(1,7,0,0)
#error At least Intel(R) DPDK version 1.7.0 is required
#endif

#ifndef __INTEL_COMPILER
#if __GNUC__ == 4 && __GNUC_MINOR__ < 7
#error Only GCC versions 4.7 and above supported
#endif
#endif

struct rte_ring;
// in main.c
extern uint8_t port_status[];
extern struct rte_ring *ctrl_rings[];

#endif /* _MAIN_H_ */
