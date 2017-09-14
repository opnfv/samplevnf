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

#ifndef __INCLUDE_PIPELINE_CGNAPT_H__
#define __INCLUDE_PIPELINE_CGNAPT_H__

/**
 * @file
 * Pipeline CG-NAPT FE.
 *
 * PipelineCG-NAPT Front End (FE).
 * Runs on the Master pipeline, responsible for CLI commands.
 *
 */

#include "pipeline.h"
#include "pipeline_cgnapt_common.h"
#include <civetweb.h>
#include <json/json.h>

/**
 * Add NAPT rule to the NAPT rule table.
 * Both IPv4 and IPv6 rules can be added.
 *
 * @param app
 *  A pointer to the pipeline app parameters.
 * @param pipeline_id
 *  Pipeline id
 * @param key
 *  A pointer to the NAPT key corresponding to the entry being added.
 * @param entry_params
 *  A pointer to the NAPT entry being added.
 *
 * @return
 *  0 on success, negative on error.
 */
#if 0
int
app_pipeline_cgnapt_add_entry(struct app_params *app,
						uint32_t pipeline_id,
						struct pipeline_cgnapt_entry_key *key,
						struct app_pipeline_cgnapt_entry_params
						*entry_params);
#endif
int app_pipeline_cgnapt_add_entry(
	struct app_params *app,
	uint32_t pipeline_id,
	struct app_pipeline_cgnapt_entry_params *entry_params);
/**
 * Delete NAPT rule from the NAPT rule table.
 * Both IPv4 and IPv6 rules can be added.
 *
 * @param app
 *  A pointer to the pipeline app parameters.
 * @param pipeline_id
 *  Pipeline id
 * @param key
 *  A pointer to the NAPT key corresponding to the entry being added.
 *
 * @return
 *  0 on success, negative on error.
 */
int
app_pipeline_cgnapt_delete_entry(struct app_params *app,
				 uint32_t pipeline_id,
				 struct pipeline_cgnapt_entry_key *key);

/**
 * Add multiple NAPT rule to the NAPT rule table.
 * Both IPv4 and IPv6 rules can be added.
 *
 * @param app
 *  A pointer to the pipeline app parameters.
 * @param pipeline_id
 *  Pipeline id
 * @param entry_params
 *  A pointer to the multiple NAPT entry params being added.
 *
 * @return
 *  0 on success, negative on error.
 */
int app_pipeline_cgnapt_addm_entry(struct app_params *app, uint32_t pipeline_id,
						struct app_pipeline_cgnapt_mentry_params
					 *entry_params);

/**
 * Add Network Specific Prefix for NAT64.
 *
 * @param app
 *  A pointer to the pipeline app parameters.
 * @param pipeline_id
 *  Pipeline id
 * @param nsp
 *  A pointer to NSP being added.
 *
 * @return
 *  0 on success, negative on error.
 */
int
app_pipeline_cgnapt_nsp_add_entry(struct app_params *app,
					uint32_t pipeline_id,
					struct pipeline_cgnapt_nsp_t *nsp);

/**
 * Delete a Network Specific Prefix for NAT64.
 *
 * @param app
 *  A pointer to the pipeline app parameters.
 * @param pipeline_id
 *  Pipeline id
 * @param nsp
 *  A pointer to NSP being deleted.
 *
 * @return
 *  0 on success, negative on error.
 */
int
app_pipeline_cgnapt_nsp_del_entry(struct app_params *app,
					uint32_t pipeline_id,
					struct pipeline_cgnapt_nsp_t *nsp);
#ifdef REST_API_SUPPORT
/* REST api's are defined here */
int cgnapt_cmd_ver_handler(struct mg_connection *conn, void *cbdata);
int cgnapt_stats_handler(struct mg_connection *conn, void *cbdata);
void rest_api_cgnapt_init(struct mg_context *ctx, struct app_params *app);
#endif

/*
 * Pipeline type
 */
extern struct pipeline_type pipeline_cgnapt;

#endif
