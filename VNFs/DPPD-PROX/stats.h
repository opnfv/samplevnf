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

#ifndef _STATS_H_
#define _STATS_H_

#include <rte_atomic.h>

#include "stats_cons.h"
#include "clock.h"
#include "prox_globals.h"
#include "genl4_bundle.h"

void stats_reset(void);
void stats_init(unsigned avg_start, unsigned duration);
void stats_update(uint16_t flag_cons);

#endif /* _STATS_H_ */
