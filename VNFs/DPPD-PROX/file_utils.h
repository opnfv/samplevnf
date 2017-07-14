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

#ifndef _FILE_UTILS_H_
#define _FILE_UTILS_H_

#include <inttypes.h>
#include <stddef.h>

long file_get_size(const char *path);
int file_read_content(const char *path, uint8_t *mem, size_t beg, size_t len);
const char *file_get_error(void);

#endif /* _FILE_UTILS_H_ */
