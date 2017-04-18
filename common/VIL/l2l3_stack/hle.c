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
#include "tsx.h"
//#include "hle.h"
#include <xmmintrin.h>

void hle_init(void)
{
	mutex_val = 0;
}

int hle_lock(void)
{
	while (__atomic_exchange_n
				 (&mutex_val, 1, __ATOMIC_ACQUIRE | __ATOMIC_HLE_ACQUIRE))
		_mm_pause();
	return TRUE;
}

int hle_release(void)
{
	__atomic_store_n(&mutex_val, 0,
			 __ATOMIC_RELEASE | __ATOMIC_HLE_RELEASE);
	return TRUE;
}

int is_hle_locked(void)
{
	return (mutex_val == 0) ? FALSE : TRUE;
}
