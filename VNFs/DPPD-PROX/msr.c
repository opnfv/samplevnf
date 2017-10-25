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

#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#include "msr.h"
#include "log.h"

int msr_fd[RTE_MAX_LCORE];
int n_msr_fd;
int msr_init(void)
{
	char msr_path[1024];

	if (n_msr_fd) {
		return 0;
	}

	for (uint32_t i = 0; i < sizeof(msr_fd)/sizeof(*msr_fd); ++i, n_msr_fd = i) {
		snprintf(msr_path, sizeof(msr_path), "/dev/cpu/%u/msr", i);
		msr_fd[i] = open(msr_path, O_RDWR);
		if (msr_fd[i] < 0) {
			return i == 0? -1 : 0;
		}
	}

	return 0;
}

void msr_cleanup(void)
{
	for (int i = 0; i < n_msr_fd; ++i) {
		close(msr_fd[i]);
	}

	n_msr_fd = 0;
}

int msr_read(uint64_t *ret, int lcore_id, off_t offset)
{
	if (lcore_id > n_msr_fd) {
		return -1;
	}

	if (0 > pread(msr_fd[lcore_id], ret, sizeof(uint64_t), offset)) {
		return -1;
	}

	return 0;
}

int msr_write(int lcore_id, uint64_t val, off_t offset)
{
	if (lcore_id > n_msr_fd) {
		return -1;
	}

	if (sizeof(uint64_t) != pwrite(msr_fd[lcore_id], &val, sizeof(uint64_t), offset)) {
		return -1;
	}
	// plogx_dbg("\t\tmsr_write(core %d, offset %x, val %lx)\n", lcore_id, (int)offset, val);
	return 0;
}
