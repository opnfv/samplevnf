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

#define HLE_TRUE 1
#define HLE_FALSE 0

volatile int mutex_val;
/*
 * hle mutex
 * @param void
 */
void hle_mutex(void);
/*
 * To lock instrution
 * @param void
 */
int hle_lock(void);
/*
 * To release held lock
 * @param void
 */
int hle_release(void);
/*
 * To check whether lock is held
 * @param void
 */
int is_locked(void);
