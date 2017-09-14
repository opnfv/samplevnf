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

#ifndef __INCLUDE_PIPELINE_VFW_H__
#define __INCLUDE_PIPELINE_VFW_H__

/**
 * @file
 * Pipeline VFW FE.
 *
 * Pipeline VFW Front End (FE).
 * Runs on the Master pipeline, responsible for CLI commands.
 *
 */

#include "pipeline.h"
#include "app.h"
#include "pipeline_vfw_be.h"

#include <civetweb.h>
#include <json/json.h>

/* VFW IPV4 and IPV6 enable flags for debugging (Default both on) */
extern int vfw_ipv4_enabled;
extern int vfw_ipv6_enabled;

/* Number of VFW Rules, default 4 * 1024 */
extern uint32_t vfw_n_rules;
/* VFW Rule Table TRIE - 2 (Active, Standby Global table per ipv4, ipv6 */
extern void *vfw_rule_table_ipv4_active;
extern void *vfw_rule_table_ipv4_standby;
extern void *vfw_rule_table_ipv6_active;
extern void *vfw_rule_table_ipv6_standby;

#define active_rule_table       0
#define standby_rule_table       1
#define vfw_add_command              0
#define vfw_delete_command       1
#define IPV6_32BIT_LENGTH       4

/**
 * Add VFW rule to the VFW rule table.
 * Rules are added standby table.
 * Applyruleset command will activate the change.
 * Both IPv4 and IPv6 rules can be added.
 *
 * @param app
 *  A pointer to the VFW pipeline parameters.
 * @param key
 *  A pointer to the VFW rule to add.
 * @param priority
 *  Priority of the VFW rule.
 * @param port_id
 *  Port ID of the VFW rule.
 * @param action_id
 *  Action ID of the VFW rule. Defined in Action Table.
 *
 * @return
 *  0 on success, negative on error.
 */
int
app_pipeline_vfw_add_rule(struct app_params *app,
                          struct pipeline_vfw_key *key,
                          uint32_t priority,
                          uint32_t port_id, uint32_t action_id);

/**
 * Delete VFW rule from the VFW rule table.
 * Rules deleted from standby tables.
 * Applyruleset command will activate the change.
 * Both IPv4 and IPv6 rules can be deleted.
 *
 * @param app
 *  A pointer to the VFW pipeline parameters.
 * @param key
 *  A pointer to the VFW rule to delete.
 *
 * @return
 *  0 on success, negative on error.
 */
int
app_pipeline_vfw_delete_rule(struct app_params *app,
                            struct pipeline_vfw_key *key);

/**
 * Clear all VFW rules from the VFW rule table.
 * Rules cleared from standby tables.
 * Applyruleset command will activate the change.
 * Both IPv4 and IPv6 rules will be cleared.
 *
 * @param app
 *  A pointer to the VFW pipeline parameters.
 *
 * @return
 *  0 on success, negative on error.
 */
int app_pipeline_vfw_clearrules(struct app_params *app);

/**
 * Add Action to the Action table.
 * Actions are added standby table.
 * Applyruleset command will activate the change.
 *
 * @param app
 *  A pointer to the VFW pipeline parameters.
 * @param key
 *  A pointer to the Action to add.
 *
 * @return
 *  0 on success, negative on error.
 */
int
app_pipeline_action_add(struct app_params *app,
                     struct pipeline_action_key *key);

/**
 * Delete Action from the Action table.
 * Actions are deleted from the standby table.
 * Applyruleset command will activate the change.
 *
 * @param app
 *  A pointer to the VFW pipeline parameters.
 * @param key
 *  A pointer to the Action to delete.
 *
 * @return
 *  0 on success, negative on error.
 */
int
app_pipeline_action_delete(struct app_params *app,
                        struct pipeline_action_key *key);

extern struct pipeline_type pipeline_vfw;

#ifdef REST_API_SUPPORT
/* REST Api's defined here */
int vfw_rules_handler(struct mg_connection *conn, void *cbdata);
int vfw_load_rules_handler(struct mg_connection *conn, void *cbdata);
int vfw_clearrules_handler(struct mg_connection *conn, void *cbdata);
int vfw_stats_handler(struct mg_connection *conn, void *cbdata);
int vfw_clearstats_handler(__rte_unused struct mg_connection *conn,
	 __rte_unused void *cbdata);
int vfw_cmd_ver_handler(struct mg_connection *conn, __rte_unused void *cbdata);
void rest_api_vfw_init(struct mg_context *ctx, struct app_params *app);
#endif

#endif
