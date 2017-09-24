/*
// Copyright (c) 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
#ifndef _TSX_H_
#define _RSX_H_
#include <rte_atomic.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

volatile int mutex_val;

rte_atomic64_t naborted;

void hle_init(void);
int hle_lock(void);
int hle_release(void);
int is_hle_locked(void);

void rtm_init(void);
int rtm_lock(void);
int rtm_unlock(void);
int is_rtm_locked(void);

int can_use_intel_core_4th_gen_features(void);

#endif
