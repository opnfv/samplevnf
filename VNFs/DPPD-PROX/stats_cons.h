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

#ifndef _STATS_CONS_H_
#define _STATS_CONS_H_

#define STATS_CONS_F_TASKS      0x01
#define STATS_CONS_F_LCORE      0x02
#define STATS_CONS_F_PORTS      0x04
#define STATS_CONS_F_MEMPOOLS   0x08
#define STATS_CONS_F_RINGS      0x10
#define STATS_CONS_F_LATENCY    0x20
#define STATS_CONS_F_L4GEN      0x40
#define STATS_CONS_F_GLOBAL     0x80
#define STATS_CONS_F_PRIO_TASKS 0x100
#define STATS_CONS_F_IRQ        0x200
#define STATS_CONS_F_ALL        0x3ff

struct stats_cons {
	void (*init)(void);
	void (*notify)(void);
	void (*refresh)(void); /* Only called if not NULL, used to signal lsc or core stop/start */
	void (*finish)(void);
	uint16_t flags;
};

#endif /* _STATS_CONS_H_ */
