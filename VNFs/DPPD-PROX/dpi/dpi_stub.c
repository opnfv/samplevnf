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

#include <stdio.h>

#include "dpi.h"

/* The following functions are not a real implementation of a
   DPI. They serve only to create dpi_stub.so which can be loaded into
   prox. */

static int dpi_init(uint32_t thread_count, int argc, const char *argv[])
{
	return 0;
}

size_t dpi_get_flow_entry_size(void) {return 0;}
void flow_data_dpi_flow_expire(void *flow_data) {}
void *dpi_thread_start() {return NULL;}
void dpi_thread_stop(void *opaque) {}
void dpi_finish(void) {}

int dpi_process(void *opaque, struct flow_info *fi, void *flow_data,
		struct dpi_payload *payload, uint32_t results[],
		size_t *result_len)
{
	return 0;
}

static struct dpi_engine dpi_engine = {
	.dpi_init = dpi_init,
	.dpi_get_flow_entry_size = dpi_get_flow_entry_size,
	.dpi_flow_expire = flow_data_dpi_flow_expire,
	.dpi_thread_start = dpi_thread_start,
	.dpi_thread_stop = dpi_thread_stop,
	.dpi_process = dpi_process,
	.dpi_finish = dpi_finish,
	.dpi_print = printf,
};

struct dpi_engine *get_dpi_engine(void)
{
	return &dpi_engine;
}
