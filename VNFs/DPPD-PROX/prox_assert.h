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

#ifndef _PROX_ASSERT_H_
#define _PROX_ASSERT_H_

#include <assert.h>
#include "display.h"

#if defined(__KLOCWORK__) || defined(ASSERT)

#ifdef NDEBUG
#error When enabling asserts, NDEBUG must be undefined
#endif

#define PROX_ASSERT(cond) do {			\
		if (!(cond)) {			\
			display_end();		\
			assert(cond);		\
		}				\
	} while (0)
#else
#define PROX_ASSERT(cond) do {} while(0)
#endif

#endif /* _PROX_ASSERT_H_ */
