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

#include <stddef.h>
#include "quit.h"
#include "prox_compat.h"

char *prox_strncpy(char * dest, const char * src, size_t count)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wstringop-truncation"
	strncpy(dest, src, count);
#pragma GCC diagnostic pop
	PROX_PANIC(dest[count - 1] != 0, "\t\tError in strncpy: buffer overrun (%lu bytes)", count);
	return dest;
}
