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

#ifndef __INCLUDE_PIPELINE_H__
#define __INCLUDE_PIPELINE_H__

#include <cmdline_parse.h>

#include "pipeline_be.h"

/*
 * Pipeline type front-end operations
 */

typedef void* (*pipeline_fe_op_init)(struct pipeline_params *params, void *arg);

typedef int (*pipeline_fe_op_free)(void *pipeline);

struct pipeline_fe_ops {
	pipeline_fe_op_init f_init;
	pipeline_fe_op_free f_free;
	cmdline_parse_ctx_t *cmds;
};

/*
 * Pipeline type
 */

struct pipeline_type {
	const char *name;

	/* pipeline back-end */
	struct pipeline_be_ops *be_ops;

	/* pipeline front-end */
	struct pipeline_fe_ops *fe_ops;
};

static inline uint32_t
pipeline_type_cmds_count(struct pipeline_type *ptype)
{
	cmdline_parse_ctx_t *cmds;
	uint32_t n_cmds;

	if (ptype->fe_ops == NULL)
		return 0;

	cmds = ptype->fe_ops->cmds;
	if (cmds == NULL)
		return 0;

	for (n_cmds = 0; cmds[n_cmds]; n_cmds++);

	return n_cmds;
}

int
parse_pipeline_core(uint32_t *socket,
	uint32_t *core,
	uint32_t *ht,
	const char *entry);

#endif
