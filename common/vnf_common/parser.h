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

#ifndef __INCLUDE_PARSER_H__
#define __INCLUDE_PARSER_H__

int
parser_read_arg_bool(const char *p);

int
parser_read_uint64(uint64_t *value, const char *p);

int
parser_read_uint32(uint32_t *value, const char *p);

int
parse_hex_string(char *src, uint8_t *dst, uint32_t *size);

#endif
