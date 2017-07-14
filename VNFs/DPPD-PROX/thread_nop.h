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

#ifndef _THREAD_NOP_H_
#define _THREAD_NOP_H_

struct lcore_cfg;

/* A separate threading function specifically with minimal features is
   supplied to allow testing with minimal overhead. This thread
   function is only used when all tasks on the core use have the
   .thread_x field set to thread_nop. */
int thread_nop(struct lcore_cfg *lconf);

#endif /* _THREAD_NOP_H_ */
