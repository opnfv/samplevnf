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

#ifndef _HANDLE_IMPAIR_H_
#define _HANDLE_IMPAIR_H_

void task_impair_set_delay_us(struct task_base *tbase, uint32_t delay_us, uint32_t random_delay_us);
void task_impair_set_proba_no_drop(struct task_base *tbase, float proba);
void task_impair_set_proba_delay(struct task_base *tbase, float proba);
void task_impair_set_proba_duplicate(struct task_base *tbase, float proba);

#endif /* _HANDLE_IMPAIR_H_ */
