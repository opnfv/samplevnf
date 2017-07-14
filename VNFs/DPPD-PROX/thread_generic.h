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

#ifndef _THREAD_GENERIC_H_
#define _THREAD_GENERIC_H_

struct lcore_cfg;

/* The generic thread can do everything needed for each of the tasks.
   It is not optimized for any specific case and suggested use is only
   for testing purpose and for tasks that require to run a function
   periodically (i.e. ARP management). More specific "thread_XXX"
   functions should be used to only do the steps only necessary for
   the task. */
int thread_generic(struct lcore_cfg *lconf);

#endif /* _THREAD_GENERIC_H_ */
