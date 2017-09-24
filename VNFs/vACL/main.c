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

#include "app.h"
#include "pipeline_acl.h"

static struct app_params app;

int
main(int argc, char **argv)
{
	struct mg_context *ctx = NULL;
	rte_openlog_stream(stderr);

	/* Config */
	app_config_init(&app);

	app_config_args(&app, argc, argv);

	if (is_rest_support()) {
		/* initialize the rest api */
		set_vnf_type("VACL");
		ctx = rest_api_init(&app);
	}

	app_config_preproc(&app);

	app_config_parse(&app, app.parser_file);

	app_config_check(&app);

	/* Timer subsystem init*/
	rte_timer_subsystem_init();

	/* Init */
	app_init(&app);

	if (is_rest_support() && (ctx != NULL)) {
		/* rest api's for cgnapt */
		rest_api_acl_init(ctx, &app);
	}

	/* Run-time */
	rte_eal_mp_remote_launch(
		app_thread,
		(void *) &app,
		CALL_MASTER);

	if (is_rest_support() && (ctx != NULL)) {
		mg_stop(ctx);
		printf("Civet server stopped.\n");
	}

	return 0;
}
