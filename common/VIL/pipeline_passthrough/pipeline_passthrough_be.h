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

#ifndef __INCLUDE_PIPELINE_PASSTHROUGH_BE_H__
#define __INCLUDE_PIPELINE_PASSTHROUGH_BE_H__

#include "pipeline_common_be.h"

#define PIPELINE_PASSTHROUGH_DMA_SIZE_MAX                             64

struct pipeline_passthrough_params {
	uint32_t dma_enabled;
	uint32_t dma_dst_offset;
	uint32_t dma_src_offset;
	uint8_t dma_src_mask[PIPELINE_PASSTHROUGH_DMA_SIZE_MAX];
	uint32_t dma_size;

	uint32_t dma_hash_enabled;
	uint32_t dma_hash_offset;
	uint32_t lb_hash_enabled;
};

int
pipeline_passthrough_parse_args(struct pipeline_passthrough_params *p,
	struct pipeline_params *params);

extern struct pipeline_be_ops pipeline_passthrough_be_ops;

#endif
