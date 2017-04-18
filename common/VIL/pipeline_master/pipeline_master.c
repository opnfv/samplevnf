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

#include "pipeline_master.h"
#include "pipeline_master_be.h"

static struct pipeline_fe_ops pipeline_master_fe_ops = {
	.f_init = NULL,
	.f_free = NULL,
	.cmds = NULL,
};

struct pipeline_type pipeline_master = {
	.name = "MASTER",
	.be_ops = &pipeline_master_be_ops,
	.fe_ops = &pipeline_master_fe_ops,
};
