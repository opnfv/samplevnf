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

#ifndef _QUIT_H_
#define _QUIT_H_

#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_debug.h>

#include "display.h"
#include "prox_cfg.h"

/* PROX_PANIC for checks that are possibly hit due to configuration or
   when feature is not implemented. */
/* Restore tty and abort if there is a problem */
#define PROX_PANIC(cond, ...) do {					\
		if (cond) {						\
			plog_info(__VA_ARGS__);				\
			display_end();					\
 			if (prox_cfg.flags & DSF_DAEMON) {		\
                		pid_t ppid = getppid();			\
				plog_info("sending SIGUSR2 to %d\n", ppid);\
				kill(ppid, SIGUSR2);			\
			}						\
			rte_panic("PANIC at %s:%u, callstack:\n",	\
				  __FILE__, __LINE__);			\
		}							\
	} while (0)

#endif /* _QUIT_H_ */
