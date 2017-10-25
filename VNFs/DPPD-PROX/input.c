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

#include <rte_cycles.h>
#include <rte_common.h>

#include "clock.h"
#include "input.h"

static struct input *inputs[32];
static int n_inputs;
static int max_input_fd;

int reg_input(struct input *in)
{
	if (n_inputs == sizeof(inputs)/sizeof(inputs[0]))
		return -1;

	for (int i = 0; i < n_inputs; ++i) {
		if (inputs[i] == in)
			return -1;
	}
	inputs[n_inputs++] = in;
	max_input_fd = RTE_MAX(in->fd, max_input_fd);

	return 0;
}

void unreg_input(struct input *in)
{
	int rm, i;

	for (rm = 0; rm < n_inputs; ++rm) {
		if (inputs[rm] == in) {
			break;
		}
	}

	if (rm == n_inputs)
		return ;

	for (i = rm + 1; i < n_inputs; ++i) {
		inputs[i - 1] = inputs[i];
	}

	n_inputs--;
	max_input_fd = 0;
	for (i = 0; i < n_inputs; ++i) {
		max_input_fd = RTE_MAX(inputs[i]->fd, max_input_fd);
	}
}

static int tsc_diff_to_tv(uint64_t beg, uint64_t end, struct timeval *tv)
{
	if (end < beg) {
		return -1;
	}

	uint64_t diff = end - beg;
	tsc_to_tv(tv, diff);
	return 0;
}

void input_proc(void)
{
	struct timeval tv;
	fd_set in_fd;
	int ret = 1;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	while (ret != 0) {
		FD_ZERO(&in_fd);

		for (int i = 0; i < n_inputs; ++i) {
			FD_SET(inputs[i]->fd, &in_fd);
		}

		ret = select(max_input_fd + 1, &in_fd, NULL, NULL, &tv);

		if (ret > 0) {
			for (int i = 0; i < n_inputs; ++i) {
				if (FD_ISSET(inputs[i]->fd, &in_fd)) {
					inputs[i]->proc_input(inputs[i]);
				}
			}
		}
	}
}

void input_proc_until(uint64_t deadline)
{
	struct timeval tv;
	fd_set in_fd;
	int ret = 1;

	/* Keep checking for input until select() returned 0 (timeout
	   occurred before input was read) or current time has passed
	   the deadline (which occurs when time progresses past the
	   deadline between return of select() and the next
	   iteration). */
	while (ret != 0 && tsc_diff_to_tv(rte_rdtsc(), deadline, &tv) == 0) {
		FD_ZERO(&in_fd);

		for (int i = 0; i < n_inputs; ++i) {
			FD_SET(inputs[i]->fd, &in_fd);
		}

		ret = select(max_input_fd + 1, &in_fd, NULL, NULL, &tv);

		if (ret > 0) {
			for (int i = 0; i < n_inputs; ++i) {
				if (FD_ISSET(inputs[i]->fd, &in_fd)) {
					inputs[i]->proc_input(inputs[i]);
				}
			}
		}
	}
}
