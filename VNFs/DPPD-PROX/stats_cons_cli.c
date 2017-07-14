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

#include "stats.h"
#include "stats_cons_cli.h"
#include "prox_cfg.h"
#include "prox_args.h"
#include "prox_assert.h"
#include "commands.h"

static struct stats_cons stats_cons_cli = {
	.init = stats_cons_cli_init,
	.notify = stats_cons_cli_notify,
	.finish = stats_cons_cli_finish,
	.flags = STATS_CONS_F_ALL,
};

struct stats_cons *stats_cons_cli_get(void)
{
	return &stats_cons_cli;
}

void stats_cons_cli_init(void)
{
}

void stats_cons_cli_notify(void)
{
}

void stats_cons_cli_finish(void)
{
}
