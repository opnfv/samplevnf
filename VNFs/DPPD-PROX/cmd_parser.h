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

#ifndef _CMD_PARSER_H_
#define _CMD_PARSER_H_

#include <stddef.h>

struct input;
void cmd_parser_parse(const char *str, struct input *input);
const char *cmd_parser_cmd(size_t i);
size_t cmd_parser_n_cmd(void);
int task_is_mode_and_submode(uint32_t lcore_id, uint32_t task_id, const char *mode, const char *sub_mode);
int task_is_mode(uint32_t lcore_id, uint32_t task_id, const char *mode);
int task_is_sub_mode(uint32_t lcore_id, uint32_t task_id, const char *sub_mode);

#endif /* _CMD_PARSER_H_ */
