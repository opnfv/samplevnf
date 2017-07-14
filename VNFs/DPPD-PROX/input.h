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

#ifndef _INPUT_H_
#define _INPUT_H_

#include <inttypes.h>

struct input {
	int fd;
	/* Function to be called when data is available on the fd */
	void (*proc_input)(struct input *input);
	void (*reply)(struct input *input, const char *buf, size_t len);
	void (*history)(struct input *input);
};

int reg_input(struct input *in);
void unreg_input(struct input *in);

void input_proc_until(uint64_t deadline);

#endif /* _INPUT_H_ */
