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

/*
    This file contain Lua bindings for the DPDK TM API.
*/

#include <string.h>
#include <stdio.h>
#include <rte_version.h>
#include <rte_ethdev.h>

#include "ethdev_tm_api_lua.h"
#include "prox_lua_types.h"

/*
 * *** Lua type support functions  ***
 */

/** Read integer Lua argument from table
 *  @param L     Lua state
 *  @param arg   Lua argument number (must be integer type)
 *  @param k     Lua table key in argument
 *  @return      Integer value from arguments[arg][k]
 */
static uint64_t lua_arg2uint64(lua_State *L, int arg, const char *k)
{
	uint64_t val;
	lua_getfield(L, arg, k);
	if (!lua_isnumber(L, -1)) {
		lua_error(L);
	}
	val = lua_tointeger(L, -1);
	lua_pop(L, 1);
	return val;
}

/** Read integer Lua argument from table
 *  @param L     Lua state
 *  @param arg   Lua argument number (must be integer type)
 *  @param k     Lua table key in argument
 *  @return      Integer value from arguments[arg][k]
 */
static int lua_arg2int(lua_State *L, int arg, const char *k)
{
	int val;
	lua_getfield(L, arg, k);
	if (!lua_isnumber(L, -1)) {
		lua_error(L);
	}
	val = lua_tointeger(L, -1);
	lua_pop(L, 1);
	return val;
}

/** Read integer Lua argument from sub-table
 *  @param L     Lua state
 *  @param arg   Lua argument number (must be integer type)
 *  @param sub   Lua sub-table key
 *  @param k     Lua table key in argument
 *  @return      Integer value from arguments[arg][sub][k]
 */
static uint64_t lua_sub_arg2uint64(lua_State *L, int arg, const char *sub, const char *k)
{
	uint64_t val;

	lua_getfield(L, arg, sub);
	luaL_checktype(L, -1, LUA_TTABLE);
	val = lua_arg2uint64(L, -1, k);
	lua_pop(L, 1);
	return val;
}

/** Read integer Lua argument from sub-table
 *  @param L     Lua state
 *  @param arg   Lua argument number (must be integer type)
 *  @param sub   Pointer to list of sub key arguments
 *  @param sub_num Depth/number of sub-items
 *  @param k     Lua table key in argument
 *  @return      Integer value from arguments[arg][sub][k]
 */
static int lua_sub_arg2int(lua_State *L, int arg, const char **sub, int sub_num, const char *k)
{
	int val, ii;

	lua_getfield(L, arg, sub[0]);
	for (ii=1; ii<sub_num; ii++) /*traverse into sub-tables*/
		lua_getfield(L, -1, sub[ii]);
	luaL_checktype(L, -1, LUA_TTABLE);
	val = lua_arg2int(L, -1, k);
	for (ii=0; ii<sub_num; ii++)
		lua_pop(L, 1);
	return val;
}

/** Check if Lua argument from sub-table exists
 *  @param L     Lua state
 *  @param arg   Lua argument number (must be integer type)
 *  @param sub   Pointer to list of sub key arguments
 *  @param sub_num Depth/number of sub-items
 *  @param k     Lua table key in argument
 *  @return      1 if arguments[arg][sub][k] exists, 0 otherwise
 */
static int lua_sub_arg_exists(lua_State *L, int arg, const char **sub, int sub_num, const char *k)
{
	int val, ii;

	lua_getfield(L, arg, sub[0]);
	for (ii=1; ii<sub_num; ii++) /*traverse into sub-tables*/
		lua_getfield(L, -1, sub[ii]);
	luaL_checktype(L, -1, LUA_TTABLE);
	lua_getfield(L, -1, k);
	val = lua_isnil(L, -1) ? 0 : 1;
	for (ii=0; ii<=sub_num; ii++)
		lua_pop(L, 1);
	return val;
}

/** Read list of integers from Lua argument
 *  @param L     Lua state
 *  @param arg   Lua argument number (must be table type)
 *  @param k     Lua table key in argument
 *  @param list  Pointer to array where to store integers or NULL to dynamically allocate
 *  @param nmin  Minimum number of arguments to expect
 *  @param nmax  Maximum number of arguments to expect
 *  @return      Number of integers found or -1 in case of errors
 */
static int lua_arg2int_array(lua_State *L, int arg, const char *k, int **list,
			     unsigned int nmin, unsigned int nmax)
{
	size_t a_size;

	lua_getfield(L, arg, k);
	luaL_checktype(L, -1, LUA_TTABLE);
	lua_len(L, -1);
	a_size = lua_tointeger(L, -1);
	if (a_size>0 && *list==NULL) {
		*list = malloc(sizeof(*list)*a_size);
		if (*list==NULL)
			return -1;
	}
	lua_pop(L, 1);
	for (unsigned int ii=0; ii<a_size; ii++) {
		if (ii>=nmax) {
			plog_err("Illegal array size(%s), got %zu, excepted max %u\n", k, a_size, nmax);
			lua_error(L);
		}
		lua_pushinteger(L, ii+1);
		lua_gettable(L, -2);
		if (lua_isnil(L, -1)) {
			a_size = ii-1;
			break;
		}
		if (!lua_isnumber(L, -1)) {
			lua_error(L);
		}
		(*list)[ii] = lua_tointeger(L, -1);
		lua_pop(L, 1);
	}
	lua_pop(L, 1);
	if (a_size<nmin) {
		plog_err("Illegal array size(%s), got %zu, excepted at least %u\n", k, a_size, nmin);
		lua_error(L);
	}
	return a_size;
}

/** Read list of integers from Lua argument
 *  @param L     Lua state
 *  @param arg   Lua argument number (must be table type)
 *  @param sub   Pointer to list of sub key arguments
 *  @param sub_num Depth/number of sub-items
 *  @param k     Lua table key in argument
 *  @param list  Pointer to array where to store integers or NULL to dynamically allocate
 *  @param nmin  Minimum number of arguments to expect
 *  @param nmax  Maximum number of arguments to expect
 *  @return      Number of integers found or -1 in case of errors
 */
static int lua_sub_arg2int_array(lua_State *L, int arg, const char **sub, int sub_num,
				 const char *k, int **list,
				 unsigned int nmin, unsigned int nmax)
{
	int ii, a_size;

	lua_getfield(L, arg, sub[0]);
	for (ii=1; ii<sub_num; ii++) /*traverse into sub-tables*/
		lua_getfield(L, -1, sub[ii]);
	luaL_checktype(L, -1, LUA_TTABLE);
	a_size = lua_arg2int_array(L, -1, k, list, nmin, nmax);
	for (ii=0; ii<sub_num; ii++)
		lua_pop(L, 1);
	return a_size;
}

/** Read list of integers from Lua argument, stored in array of uint32_t
 *  @param L     Lua state
 *  @param arg   Lua argument number (must be table type)
 *  @param k     Lua table key in argument
 *  @param list  Pointer to array where to store integers or NULL to dynamically allocate
 *  @param nmin  Minimum number of arguments to expect
 *  @param nmax  Maximum number of arguments to expect
 *  @return      Number of integers found or -1 in case of errors
 */
static int lua_arg2uint32_array(lua_State *L, int arg, const char *k, uint32_t **list,
				unsigned int nmin, unsigned int nmax)
{
	size_t a_size;

	lua_getfield(L, arg, k);
	luaL_checktype(L, -1, LUA_TTABLE);
	lua_len(L, -1);
	a_size = lua_tointeger(L, -1);
	if (a_size>0 && *list==NULL) {
		*list = malloc(sizeof(*list)*a_size);
		if (*list==NULL)
			return -1;
	}
	lua_pop(L, 1);
	for (unsigned int ii=0; ii<a_size; ii++) {
		if (ii>=nmax) {
			plog_err("Illegal array size(%s), got %zu, excepted max %u\n", k, a_size, nmax);
			lua_error(L);
		}
		lua_pushinteger(L, ii+1);
		lua_gettable(L, -2);
		if (lua_isnil(L, -1)) {
			a_size = ii-1;
			break;
		}
		if (!lua_isnumber(L, -1)) {
			lua_error(L);
		}
		(*list)[ii] = lua_tointeger(L, -1);
		lua_pop(L, 1);
	}
	lua_pop(L, 1);
	if (a_size<nmin) {
		plog_err("Illegal array size(%s), got %zu, excepted at least %u\n", k, a_size, nmin);
		lua_error(L);
	}
	return a_size;
}

/** Read list of integers from Lua argument, stored in array of uint32_t
 *  @param L     Lua state
 *  @param arg   Lua argument number (must be table type)
 *  @param sub   Pointer to list of sub key arguments
 *  @param sub_num Depth/number of sub-items
 *  @param k     Lua table key in argument
 *  @param list  Pointer to array where to store integers or NULL to dynamically allocate
 *  @param nmin  Minimum number of arguments to expect
 *  @param nmax  Maximum number of arguments to expect
 *  @return      Number of integers found or -1 in case of errors
 */
static int lua_sub_arg2uint32_array(lua_State *L, int arg, const char **sub, int sub_num,
				    const char *k, uint32_t **list,
				    unsigned int nmin, unsigned int nmax)
{
	int ii, a_size;

	lua_getfield(L, arg, sub[0]);
	for (ii=1; ii<sub_num; ii++) /*traverse into sub-tables*/
		lua_getfield(L, -1, sub[ii]);
	luaL_checktype(L, -1, LUA_TTABLE);
	a_size = lua_arg2uint32_array(L, -1, k, list, nmin, nmax);
	for (ii=0; ii<sub_num; ii++)
		lua_pop(L, 1);
	return a_size;
}

/** Read a number of integer Lua arguments
 *  @param L        Lua state
 *  @param args     List of argument numbers to parse as integers or NULL to use 1 through *nargs*
 *  @param argvals  List of read argument integer values
 *  @param narg     Number of arguments in *args*
 */
static void lua2int_args(lua_State *L, int *args, int *argvals, int nargs)
{
	int ii, a_no;

	for (ii=0; ii<nargs; ii++) {
		if (args)
			a_no = args[ii];
		else
			a_no = ii+1;
		argvals[ii] = luaL_checkint(L, a_no);
		plog_dbg("lua2int_args: ii=%u, a_no=%u, val=%u\n", ii, a_no, argvals[ii]);
	}
}

static void lua_push_uint64_field(lua_State *L, uint64_t val, const char *name)
{
	lua_pushinteger(L, val);
	lua_setfield(L, -2, name);
}

static void lua_push_int_field(lua_State *L, int val, const char *name)
{
	lua_pushinteger(L, val);
	lua_setfield(L, -2, name);
}

static void lua_push_uint64_array_field(lua_State *L, uint64_t *vals, int num_vals, const char *name)
{
	int ii;
	lua_newtable(L);
	for (ii=0; ii<num_vals; ii++) {
		lua_pushinteger(L, ii+1);
		lua_pushinteger(L, vals[ii]);
		lua_settable(L, -3);
	}
	lua_setfield(L, -2, name);
}

static void lua_push_int_array_field(lua_State *L, int *vals, int num_vals, const char *name)
{
	int ii;
	lua_newtable(L);
	for (ii=0; ii<num_vals; ii++) {
		lua_pushinteger(L, ii+1);
		lua_pushinteger(L, vals[ii]);
		lua_settable(L, -3);
	}
	lua_setfield(L, -2, name);
}

/* *** struct rte_tm_capabilities *** */
/** Push rte_tm_capabilities structure onto Lua stack as a table.
*/
static void capabilities2lua_stack(lua_State *L,
				   struct rte_tm_capabilities *caps)
{
	lua_newtable(L);
	lua_push_int_field(L, caps->n_nodes_max, "n_nodes_max");
	lua_push_int_field(L, caps->n_levels_max, "n_levels_max");
	lua_push_int_field(L, caps->non_leaf_nodes_identical, "non_leaf_nodes_identical");
	lua_push_int_field(L, caps->leaf_nodes_identical, "leaf_nodes_identical");
	lua_push_int_field(L, caps->shaper_n_max, "shaper_n_max");
	lua_push_int_field(L, caps->shaper_private_n_max, "shaper_private_n_max");
	lua_push_int_field(L, caps->shaper_private_dual_rate_n_max, "shaper_private_dual_rate_n_max");
	lua_push_uint64_field(L, caps->shaper_private_rate_min, "shaper_private_rate_min");
	lua_push_uint64_field(L, caps->shaper_private_rate_max, "shaper_private_rate_max");
	lua_push_int_field(L, caps->shaper_shared_n_max, "shaper_shared_n_max");
	lua_push_int_field(L, caps->shaper_shared_n_nodes_per_shaper_max, "shaper_shared_n_nodes_per_shaper_max");
	lua_push_int_field(L, caps->shaper_shared_n_shapers_per_node_max, "shaper_shared_n_shapers_per_node_max");
	lua_push_int_field(L, caps->shaper_shared_dual_rate_n_max, "shaper_shared_dual_rate_n_max");
	lua_push_uint64_field(L, caps->shaper_shared_rate_min, "shaper_shared_rate_min");
	lua_push_uint64_field(L, caps->shaper_shared_rate_max, "shaper_shared_rate_max");
	lua_push_int_field(L, caps->shaper_pkt_length_adjust_min, "shaper_pkt_length_adjust_min");
	lua_push_int_field(L, caps->shaper_pkt_length_adjust_max, "shaper_pkt_length_adjust_max");
	lua_push_int_field(L, caps->sched_n_children_max, "sched_n_children_max");
	lua_push_int_field(L, caps->sched_sp_n_priorities_max, "sched_sp_n_priorities_max");
	lua_push_int_field(L, caps->sched_wfq_n_children_per_group_max, "sched_wfq_n_children_per_group_max");
	lua_push_int_field(L, caps->sched_wfq_n_groups_max, "sched_wfq_n_groups_max");
	lua_push_int_field(L, caps->sched_wfq_weight_max, "sched_wfq_weight_max");
	lua_push_int_field(L, caps->cman_head_drop_supported, "cman_head_drop_supported");
	lua_push_int_field(L, caps->cman_wred_context_n_max, "cman_wred_context_n_max");
	lua_push_int_field(L, caps->cman_wred_context_private_n_max, "cman_wred_context_private_n_max");
	lua_push_int_field(L, caps->cman_wred_context_shared_n_max, "cman_wred_context_shared_n_max");
	lua_push_int_field(L, caps->cman_wred_context_shared_n_nodes_per_context_max, "cman_wred_context_shared_n_nodes_per_context_max");
	lua_push_int_field(L, caps->cman_wred_context_shared_n_contexts_per_node_max, "cman_wred_context_shared_n_contexts_per_node_max");
	lua_push_int_array_field(L, caps->mark_vlan_dei_supported, RTE_TM_COLORS, "mark_vlan_dei_supported");
	lua_push_int_array_field(L, caps->mark_ip_ecn_tcp_supported, RTE_TM_COLORS, "mark_ip_ecn_tcp_supported");
	lua_push_int_array_field(L, caps->mark_ip_ecn_sctp_supported, RTE_TM_COLORS, "mark_ip_ecn_sctp_supported");
	lua_push_int_array_field(L, caps->mark_ip_dscp_supported, RTE_TM_COLORS, "mark_ip_dscp_supported");
	lua_push_uint64_field(L, caps->dynamic_update_mask, "dynamic_update_mask");
	lua_push_uint64_field(L, caps->stats_mask, "stats_mask");
}

static struct rte_tm_capabilities *alloc_capabilities(void)
{
	struct rte_tm_capabilities *caps;
	caps = malloc(sizeof(struct rte_tm_capabilities));
	if (caps==NULL) {
		plog_warn("Cannot allocate memory\n");
		return NULL;
	}
	memset(caps, 0, sizeof(*caps));
	return caps;
}

static void free_capabilities(struct rte_tm_capabilities *caps)
{
	free(caps);
}

/* *** struct rte_tm_level_capabilities *** */
/** Push rte_tm_capabilities structure onto Lua stack as a table.
*/
static void level_capabilities2lua_stack(lua_State *L,
					 struct rte_tm_level_capabilities *caps)
{
	lua_newtable(L);
	lua_push_int_field(L, caps->n_nodes_max, "n_nodes_max");
	lua_push_int_field(L, caps->n_nodes_nonleaf_max, "n_nodes_nonleaf_max");
	lua_push_int_field(L, caps->n_nodes_leaf_max, "n_nodes_leaf_max");
	lua_push_int_field(L, caps->non_leaf_nodes_identical, "non_leaf_nodes_identical");
	lua_push_int_field(L, caps->leaf_nodes_identical, "leaf_nodes_identical");
	if (caps->n_nodes_nonleaf_max > 0) {
		/* nonleaf */
		lua_newtable(L);
		lua_push_int_field(L, caps->nonleaf.shaper_private_supported, "shaper_private_supported");
		lua_push_int_field(L, caps->nonleaf.shaper_private_dual_rate_supported, "shaper_private_dual_rate_supported");
		lua_push_uint64_field(L, caps->nonleaf.shaper_private_rate_min, "shaper_private_rate_min");
		lua_push_uint64_field(L, caps->nonleaf.shaper_private_rate_max, "shaper_private_rate_max");
		lua_push_int_field(L, caps->nonleaf.shaper_shared_n_max, "shaper_shared_n_max");
		lua_push_int_field(L, caps->nonleaf.sched_n_children_max, "sched_n_children_max");
		lua_push_int_field(L, caps->nonleaf.sched_sp_n_priorities_max, "sched_sp_n_priorities_max");
		lua_push_int_field(L, caps->nonleaf.sched_wfq_n_children_per_group_max, "sched_wfq_n_children_per_group_max");
		lua_push_int_field(L, caps->nonleaf.sched_wfq_n_groups_max, "sched_wfq_n_groups_max");
		lua_push_int_field(L, caps->nonleaf.sched_wfq_weight_max, "sched_wfq_weight_max");
		lua_push_uint64_field(L, caps->nonleaf.stats_mask, "stats_mask");
		lua_setfield(L, -2, "nonleaf");
	} else {
		/* leaf */
		lua_newtable(L);
		lua_push_int_field(L, caps->leaf.shaper_private_supported, "shaper_private_supported");
		lua_push_int_field(L, caps->leaf.shaper_private_dual_rate_supported, "shaper_private_dual_rate_supported");
		lua_push_uint64_field(L, caps->leaf.shaper_private_rate_min, "shaper_private_rate_min");
		lua_push_uint64_field(L, caps->leaf.shaper_private_rate_max, "shaper_private_rate_max");
		lua_push_int_field(L, caps->leaf.shaper_shared_n_max, "shaper_shared_n_max");
		lua_push_int_field(L, caps->leaf.cman_head_drop_supported, "cman_head_drop_supported");
		lua_push_int_field(L, caps->leaf.cman_wred_context_private_supported, "cman_wred_context_private_supported");
		lua_push_int_field(L, caps->leaf.cman_wred_context_shared_n_max, "cman_wred_context_shared_n_max");
		lua_push_uint64_field(L, caps->leaf.stats_mask, "stats_mask");
		lua_setfield(L, -2, "leaf");
	}
}

static struct rte_tm_level_capabilities *alloc_level_capabilities(void)
{
	struct rte_tm_level_capabilities *caps;
	caps = malloc(sizeof(struct rte_tm_level_capabilities));
	if (caps==NULL) {
		plog_warn("Cannot allocate memory\n");
		return NULL;
	}
	memset(caps, 0, sizeof(*caps));
	return caps;
}

static void free_level_capabilities(struct rte_tm_level_capabilities *caps)
{
	free(caps);
}

/* *** struct rte_tm_node_capabilities *** */
/** Push rte_tm_capabilities structure onto Lua stack as a table.
*/
static void node_capabilities2lua_stack(lua_State *L,
					struct rte_tm_node_capabilities *caps, int is_leaf)
{
	lua_newtable(L);
	lua_push_int_field(L, caps->shaper_private_supported, "shaper_private_supported");
	lua_push_int_field(L, caps->shaper_private_dual_rate_supported, "shaper_private_dual_rate_supported");
	lua_push_int_field(L, caps->shaper_private_rate_min, "shaper_private_rate_min");
	lua_push_int_field(L, caps->shaper_private_rate_max, "shaper_private_rate_max");
	lua_push_int_field(L, caps->shaper_shared_n_max, "shaper_shared_n_max");
	lua_push_uint64_field(L, caps->stats_mask, "stats_mask");
	if (!is_leaf) {
		/* nonleaf */
		lua_newtable(L);
		lua_push_int_field(L, caps->nonleaf.sched_n_children_max, "sched_n_children_max");
		lua_push_int_field(L, caps->nonleaf.sched_sp_n_priorities_max, "sched_sp_n_priorities_max");
		lua_push_int_field(L, caps->nonleaf.sched_wfq_n_children_per_group_max, "sched_wfq_n_children_per_group_max");
		lua_push_int_field(L, caps->nonleaf.sched_wfq_n_groups_max, "sched_wfq_n_groups_max");
		lua_push_int_field(L, caps->nonleaf.sched_wfq_weight_max, "sched_wfq_weight_max");
		lua_setfield(L, -2, "nonleaf");
	} else {
		/* leaf */
		lua_newtable(L);
		lua_push_int_field(L, caps->leaf.cman_head_drop_supported, "cman_head_drop_supported");
		lua_push_int_field(L, caps->leaf.cman_wred_context_private_supported, "cman_wred_context_private_supported");
		lua_push_int_field(L, caps->leaf.cman_wred_context_shared_n_max, "cman_wred_context_shared_n_max");
		lua_setfield(L, -2, "leaf");
	}
}

static struct rte_tm_node_capabilities *alloc_node_capabilities(void)
{
	struct rte_tm_node_capabilities *caps;
	caps = malloc(sizeof(struct rte_tm_node_capabilities));
	if (caps==NULL) {
		plog_warn("Cannot allocate memory\n");
		return NULL;
	}
	memset(caps, 0, sizeof(*caps));
	return caps;
}

static void free_node_capabilities(struct rte_tm_node_capabilities *caps)
{
	free(caps);
}

/* *** struct rte_tm_node_params *** */
static struct rte_tm_node_params *alloc_node_params(void)
{
	struct rte_tm_node_params *params;

	params = malloc(sizeof(*params));
	if (params==NULL) {
		plog_err("Cannot allocate memory for rte_tm_node_params\n");
		return NULL;
	}
	memset(params, 0, sizeof(*params));
	return params;
}

/** Free temperary allocated rte_tm_node_params structure that contained converted Read Lua table argument
 *  @param L        Lua state
 *  @param arg      Lua table
 *  @param params   structure to be freed
 */
static void free_node_params(lua_State *L, int arg, struct rte_tm_node_params *params)
{
	lua_getfield(L, arg, "nonleaf");
	if (lua_isnil(L, -1)) {
		/* leaf */
		if (params->leaf.wred.shared_wred_context_id!=NULL)
			free(params->leaf.wred.shared_wred_context_id);
	} else {
		/* nonleaf */
		if (params->nonleaf.wfq_weight_mode!=NULL)
			free(params->nonleaf.wfq_weight_mode);
	}
	lua_pop(L, 1);
	free(params->shared_shaper_id);
	free(params);
}

/** Read Lua table argument and convert to rte_tm_node_params structure
 *  @param L        Lua state
 *  @param arg      Lua table
 *  @return   rte_tm_node_params structure on success or NULL on failure
 */
static struct rte_tm_node_params *lua2node_params(lua_State *L, int arg)
{
	struct rte_tm_node_params *params;
	uint32_t n_subtable;
	int n_elements;
	const char *subtable_leaf[] = {"leaf"};
	const char *subtable_leaf_wred[] = {"leaf", "wred"};
	const char *subtable_nonleaf[] = {"nonleaf"};
	int is_leaf;

	lua_getfield(L, arg, "nonleaf");
	is_leaf = lua_isnil(L, -1);
	lua_pop(L, 1);

	params = alloc_node_params();
	if (params==NULL)
		return NULL;

	params->shaper_profile_id = lua_arg2int(L, arg, "shaper_profile_id");
	params->shared_shaper_id = NULL;
	params->n_shared_shapers = 0; /* await alloc of shared_shaper_id */
	if (is_leaf) {
		params->leaf.wred.shared_wred_context_id = NULL;

		params->leaf.cman = lua_sub_arg2int(L, arg, subtable_leaf,
						    sizeof(subtable_leaf)/sizeof(subtable_leaf[0]),
						    "cman");
		n_subtable = sizeof(subtable_leaf_wred) / sizeof(subtable_leaf_wred[0]);
		params->leaf.wred.wred_profile_id = lua_sub_arg2int(L, arg, subtable_leaf_wred, n_subtable, "wred_profile_id");
		n_elements = lua_sub_arg2uint32_array(L, arg, subtable_leaf_wred, n_subtable, "shared_wred_context_id", &params->leaf.wred.shared_wred_context_id, 0, -1);
		if (n_elements == -1) {
			free_node_params(L, arg, params);
			return NULL;
		}
		/* If n_shared_wred_contexts isn't specified then number of array elements is used */
		if (lua_sub_arg_exists(L, arg, subtable_leaf_wred, n_subtable,
				"n_shared_wred_contexts"))
			n_elements = lua_sub_arg2int(
				L, arg, subtable_leaf_wred, n_subtable,
				"n_shared_wred_contexts");
		params->leaf.wred.n_shared_wred_contexts = n_elements;
	} else {
		params->nonleaf.wfq_weight_mode = NULL;

		n_subtable = sizeof(subtable_nonleaf) / sizeof(subtable_nonleaf[0]);
		n_elements = lua_sub_arg2int_array(L, arg, subtable_nonleaf,
						   n_subtable,
						   "wfq_weight_mode",
						   &params->nonleaf.wfq_weight_mode, 0, -1);
		if (n_elements == -1) {
			free_node_params(L, arg, params);
			return NULL;
		}
		/* If n_sp_priorities isn't specified then number of array elements is used */
		if (lua_sub_arg_exists(L, arg, subtable_nonleaf, n_subtable,
				"n_sp_priorities"))
			n_elements = lua_sub_arg2int(
					L, arg, subtable_nonleaf, n_subtable,
					"n_sp_priorities");
		params->nonleaf.n_sp_priorities = n_elements;
	}
	n_elements = lua_arg2uint32_array(L, arg, "shared_shaper_id", &params->shared_shaper_id, 0, -1);
	if (n_elements == -1) {
		free_node_params(L, arg, params);
		return NULL;
	}
	/* If n_shared_shapers isn't specified then number of array elements is used */
	lua_getfield(L, arg, "n_shared_shapers");
	if (!lua_isnil(L, -1)) {
		if (!lua_isnumber(L, -1)) {
			lua_error(L);
		}
	}
	lua_pop(L, 1);
	params->n_shared_shapers = n_elements;
	params->stats_mask = lua_arg2uint64(L, arg, "stats_mask");
	return params;
}

/* *** struct rte_tm_wred_params *** */
static struct rte_tm_wred_params *alloc_wred_params(void)
{
	struct rte_tm_wred_params *params;

	params = malloc(sizeof(*params));
	if (params==NULL) {
		plog_err("Cannot allocate memory for rte_tm_wred_params\n");
		return NULL;
	}
	memset(params, 0, sizeof(*params));
	return params;
}

static void free_wred_params(struct rte_tm_wred_params *params)
{
	free(params);
}

/** Read Lua table argument and convert to rte_tm_shaper_params structure
 *  @param L        Lua state
 *  @param arg      Lua table
 *  @return   rte_tm_shaper_params structure on success or NULL on failure
 */
static struct rte_tm_wred_params *lua2wred_params(lua_State *L, int arg)
{
	struct rte_tm_wred_params *params;
	enum rte_tm_color color;
	const char *subtable_wred_profile[RTE_TM_COLORS][2] =
		{{"red_params", "green"},
		 {"red_params", "yellow"},
		 {"red_params", "red"}};
	int sub_num;

	params = alloc_wred_params();
	if (params==NULL)
		return NULL;

	for (color = 0; color < RTE_TM_COLORS; color++) {
		params->red_params[color].min_th = lua_sub_arg2int(L, arg,
			subtable_wred_profile[color], 2, "min_th");
		params->red_params[color].max_th = lua_sub_arg2int(L, arg,
			subtable_wred_profile[color], 2, "max_th");
		params->red_params[color].maxp_inv = lua_sub_arg2int(L, arg,
			subtable_wred_profile[color], 2, "maxp_inv");
		params->red_params[color].wq_log2 = lua_sub_arg2int(L, arg,
			subtable_wred_profile[color], 2, "wq_log2");
	}

	return params;
}

/* *** struct rte_tm_shaper_params *** */
static struct rte_tm_shaper_params *alloc_shaper_params(void)
{
	struct rte_tm_shaper_params *params;

	params = malloc(sizeof(*params));
	if (params==NULL) {
		plog_err("Cannot allocate memory for rte_tm_shaper_params\n");
		return NULL;
	}
	memset(params, 0, sizeof(*params));
	return params;
}

static void free_shaper_params(struct rte_tm_shaper_params *params)
{
	free(params);
}

/** Read Lua table argument and convert to rte_tm_shaper_params structure
 *  @param L        Lua state
 *  @param arg      Lua table
 *  @return   rte_tm_shaper_params structure on success or NULL on failure
 */
static struct rte_tm_shaper_params *lua2shaper_params(lua_State *L, int arg)
{
	struct rte_tm_shaper_params *params;

	params = alloc_shaper_params();
	if (params==NULL)
		return NULL;
	params->committed.rate = lua_sub_arg2uint64(L, arg, "committed", "rate");
	params->committed.size = lua_sub_arg2uint64(L, arg, "committed", "size");
	params->peak.rate = lua_sub_arg2uint64(L, arg, "peak", "rate");
	params->peak.size = lua_sub_arg2uint64(L, arg, "peak", "size");
	params->pkt_length_adjust = lua_arg2uint64(L, arg, "pkt_length_adjust");
	return params;
}

/* *** struct rte_tm_node_stats *** */
/** Push rte_tm_node_stats structure onto Lua stack as a table.
*/
static void node_stats2lua_stack(lua_State *L,
				 struct rte_tm_node_stats *stats)
{
	lua_newtable(L);
	lua_push_uint64_field(L, stats->n_pkts, "n_pkts");
	lua_push_uint64_field(L, stats->n_pkts, "n_pkts");
	lua_push_uint64_field(L, stats->n_bytes, "n_bytes");
	lua_newtable(L);
	lua_push_uint64_array_field(L, stats->leaf.n_pkts_dropped, RTE_TM_COLORS, "n_pkts_dropped");
	lua_push_uint64_array_field(L, stats->leaf.n_bytes_dropped, RTE_TM_COLORS, "n_bytes_dropped");
	lua_push_uint64_field(L, stats->leaf.n_bytes_queued, "n_pkts_queued");
	lua_push_uint64_field(L, stats->leaf.n_bytes_queued, "n_bytes_queued");
	lua_setfield(L, -2, "leaf");
}

/************************************************************/
/* TM API below */
/************************************************************/

/*int rte_tm_get_number_of_leaf_nodes(uint16_t port_id,
	uint32_t *n_leaf_nodes,
	struct rte_tm_error *error);*/
static int l_tm_get_number_of_leaf_nodes(lua_State *L)
{
	int dev_id, ret;
	struct rte_tm_capabilities caps;
	struct rte_tm_level_capabilities level_caps;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	plog_dbg("l_tm_get_number_of_leaf_nodes()\n");

	/* The rte_tm_get_number_of_leaf_nodes returns the Ethernet drivers number
	 * of queues, which is lower than the IPSG TM drivers number of queues. */
#if 0 /* FIXME */
	ret = rte_tm_get_number_of_leaf_nodes(dev_id, &num_leafs, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_get_number_of_leaf_nodes error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
#else
	ret = rte_tm_capabilities_get(dev_id, &caps, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_capabilities_get error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	ret = rte_tm_level_capabilities_get(dev_id, caps.n_levels_max - 1, &level_caps, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_level_capabilities_get error: %u: %s %u\n", tmerr.type, tmerr.message, caps.n_levels_max);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}

#endif
	lua_pushinteger(L, ret);
	lua_pushinteger(L, level_caps.n_nodes_leaf_max);
	return 2;
}

/*int rte_tm_node_type_get(uint16_t port_id,
	uint32_t node_id,
	int *is_leaf,
	struct rte_tm_error *error);*/
static int l_tm_node_type_get(lua_State *L)
{
	int dev_id, node_id, ret, is_leaf;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	node_id = luaL_checkint(L, 2);
	plog_dbg("l_tm_node_type_get()\n");
	ret = rte_tm_node_type_get(dev_id, node_id, &is_leaf, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_node_type_get error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	lua_pushinteger(L, is_leaf);
	return 2;
}

/*int rte_tm_capabilities_get(uint16_t port_id,
	struct rte_tm_capabilities *cap,
	struct rte_tm_error *error);*/
static int l_tm_capabilities_get(lua_State *L)
{
	int dev_id, ret;
	struct rte_tm_capabilities *caps;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	caps = alloc_capabilities();
	if (caps==NULL) {
		lua_pushinteger(L, -ENOMEM);
		return 1;
	}
	plog_dbg("l_tm_capabilities_get()\n");
	ret = rte_tm_capabilities_get(dev_id, caps, &tmerr);
	lua_pushinteger(L, ret);
	capabilities2lua_stack(L, caps);
	free_capabilities(caps);
	return 2;
}

/*int rte_tm_level_capabilities_get(uint16_t port_id,
	uint32_t level_id,
	struct rte_tm_level_capabilities *cap,
	struct rte_tm_error *error);*/
static int l_tm_level_capabilities_get(lua_State *L)
{
	int dev_id, ret;
	uint32_t level_id;
	struct rte_tm_level_capabilities *caps;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	level_id = luaL_checkint(L, 2);
	caps = alloc_level_capabilities();
	if (caps==NULL) {
		lua_pushinteger(L, -ENOMEM);
		return 1;
	}
	plog_dbg("l_tm_level_capabilities_get()\n");
	ret = rte_tm_level_capabilities_get(dev_id, level_id, caps, &tmerr);
	if (ret!=0)
		plog_err("TM rte_tm_level_capabilities_get error: %u: %s\n", tmerr.type, tmerr.message);
	lua_pushinteger(L, ret);
	level_capabilities2lua_stack(L, caps);
	free_level_capabilities(caps);
	return 2;
}

/*int rte_tm_node_capabilities_get(uint16_t port_id,
	uint32_t node_id,
	struct rte_tm_node_capabilities *cap,
	struct rte_tm_error *error);*/
static int l_tm_node_capabilities_get(lua_State *L)
{
	int dev_id, ret, is_leaf;
	uint32_t node_id;
	struct rte_tm_node_capabilities *caps;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	node_id = luaL_checkint(L, 2);
	caps = alloc_node_capabilities();
	if (caps==NULL) {
		lua_pushinteger(L, -ENOMEM);
		return 1;
	}
	ret = rte_tm_node_type_get(dev_id, node_id, &is_leaf, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_node_type_get error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	plog_dbg("l_tm_node_capabilities_get()\n");
	ret = rte_tm_node_capabilities_get(dev_id, node_id, caps, &tmerr);
	if (ret!=0)
		plog_err("TM rte_tm_node_capabilities_get error: %u: %s\n", tmerr.type, tmerr.message);
	lua_pushinteger(L, ret);
	node_capabilities2lua_stack(L, caps, is_leaf);
	free_node_capabilities(caps);
	return 2;
}

/*int rte_tm_wred_profile_add(uint16_t port_id,
	uint32_t wred_profile_id,
	struct rte_tm_wred_params *profile,
	struct rte_tm_error *error);*/
static int l_tm_wred_profile_add(lua_State *L)
{
	int dev_id, ret;
	uint32_t wred_profile_id;
	struct rte_tm_wred_params *profile;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	wred_profile_id = luaL_checkint(L, 2);
	profile = lua2wred_params(L, 3);
	if (profile==NULL) {
		lua_pushinteger(L, -ENOMEM);
		return 1;
	}
	plog_dbg("l_tm_wred_profile_add()\n");
	ret = rte_tm_wred_profile_add(dev_id, wred_profile_id, profile, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_wred_profile_add error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_wred_profile_delete(uint16_t port_id,
	uint32_t wred_profile_id,
	struct rte_tm_error *error);*/
static int l_tm_wred_profile_delete(lua_State *L)
{
	int dev_id, ret;
	uint32_t wred_profile_id;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	wred_profile_id = luaL_checkint(L, 2);

	plog_dbg("l_tm_wred_profile_delete()\n");
	ret = rte_tm_wred_profile_delete(dev_id, wred_profile_id, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_wred_profile_delete error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_shared_wred_context_add_update(uint16_t port_id,
	uint32_t shared_wred_context_id,
	uint32_t wred_profile_id,
	struct rte_tm_error *error);*/
static int l_tm_shared_wred_context_add_update(lua_State *L)
{
	int dev_id, ret;
	uint32_t shared_wred_context_id, wred_profile_id;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	shared_wred_context_id = luaL_checkint(L, 2);
	wred_profile_id = luaL_checkint(L, 3);

	plog_dbg("l_shared_wred_context_add_update()\n");
	ret = rte_tm_shared_wred_context_add_update(dev_id, shared_wred_context_id, wred_profile_id, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_shared_wred_context_add_update error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_shared_wred_context_delete(uint16_t port_id,
	uint32_t shared_wred_context_id,
	struct rte_tm_error *error);*/
static int l_tm_shared_wred_context_delete(lua_State *L)
{
	int dev_id, ret;
	uint32_t shared_wred_context_id;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	shared_wred_context_id = luaL_checkint(L, 2);

	plog_dbg("l_shared_wred_context_delete()\n");
	ret = rte_tm_shared_wred_context_delete(dev_id, shared_wred_context_id, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_shared_wred_context_delete error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_shaper_profile_add(uint16_t port_id,
	uint32_t shaper_profile_id,
	struct rte_tm_shaper_params *profile,
	struct rte_tm_error *error);*/
static int l_tm_shaper_profile_add(lua_State *L)
{
	int dev_id, ret;
	uint32_t shaper_profile_id;
	struct rte_tm_shaper_params *profile;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	shaper_profile_id = luaL_checkint(L, 2);
	profile = lua2shaper_params(L, 3);
	if (profile==NULL) {
		lua_pushinteger(L, -ENOMEM);
		return 1;
	}
	plog_dbg("l_tm_shaper_profile_add()\n");
	ret = rte_tm_shaper_profile_add(dev_id, shaper_profile_id, profile, &tmerr);
	// free_shaper_params(profile);
	if (ret!=0) {
		plog_err("TM rte_tm_shaper_profile_add error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_shaper_profile_delete(uint16_t port_id,
	uint32_t shaper_profile_id,
	struct rte_tm_error *error);*/
static int l_tm_shaper_profile_delete(lua_State *L)
{
	int dev_id, ret;
	uint32_t shaper_profile_id;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	shaper_profile_id = luaL_checkint(L, 2);
	plog_dbg("l_tm_shaper_profile_delete()\n");
	ret = rte_tm_shaper_profile_delete(dev_id, shaper_profile_id, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_shaper_profile_delete error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_shared_shaper_add_update(uint16_t port_id,
	uint32_t shared_shaper_id,
	uint32_t shaper_profile_id,
	struct rte_tm_error *error);*/
static int l_tm_shared_shaper_add_update(lua_State *L)
{
	int dev_id, ret;
	uint32_t shared_shaper_id, shaper_profile_id;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	shared_shaper_id = luaL_checkint(L, 2);
	shaper_profile_id = luaL_checkint(L, 3);
	plog_dbg("l_tm_shared_shaper_add_update()\n");
	ret = rte_tm_shared_shaper_add_update(dev_id, shared_shaper_id, shaper_profile_id, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_shared_shaper_add_update error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_shared_shaper_delete(uint16_t port_id,
	uint32_t shared_shaper_id,
	struct rte_tm_error *error);*/
static int l_tm_shared_shaper_delete(lua_State *L)
{
	int dev_id, ret;
	uint32_t shared_shaper_id;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	shared_shaper_id = luaL_checkint(L, 2);

	plog_dbg("l_tm_shared_shaper_delete()\n");
	ret = rte_tm_shared_shaper_delete(dev_id, shared_shaper_id, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_shared_shaper_delete error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_node_add(uint16_t port_id,
	uint32_t node_id,
	uint32_t parent_node_id,
	uint32_t priority,
	uint32_t weight,
	uint32_t level_id,
	struct rte_tm_node_params *params,
	struct rte_tm_error *error);*/
static int l_tm_node_add(lua_State *L)
{
	int dev_id, ret;
	uint32_t node_id, parent_id, priority, weight, level_id;
	struct rte_tm_node_params *params;
	struct rte_tm_error tmerr;
	struct rte_tm_capabilities caps;
	struct rte_tm_level_capabilities level_caps;

	dev_id = luaL_checkint(L, 1);
	node_id = luaL_checkint(L, 2);
	parent_id = luaL_checkint(L, 3);
	priority = luaL_checkint(L, 4);
	weight = luaL_checkint(L, 5);
	level_id = luaL_checkint(L, 6);
	params = lua2node_params(L, 7);
	if (params == NULL) {
		lua_pushinteger(L, -ENOMEM);
		return 1;
	}
	plog_dbg("l_tm_node_add()\n");
	ret = rte_tm_node_add(dev_id, node_id, parent_id, priority, weight, level_id, params, &tmerr);
	if (ret != 0) {
		plog_err("TM rte_tm_node_add error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_node_delete(uint16_t port_id,
	uint32_t node_id,
	struct rte_tm_error *error);*/
static int l_tm_node_delete(lua_State *L)
{
	int dev_id, ret;
	uint32_t node_id;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	node_id = luaL_checkint(L, 2);

	plog_dbg("l_tm_node_delete()\n");
	ret = rte_tm_node_delete(dev_id, node_id, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_node_delete error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_node_suspend(uint16_t port_id,
	uint32_t node_id,
	struct rte_tm_error *error);*/
static int l_tm_node_suspend(lua_State *L)
{
	int dev_id, ret;
	uint32_t node_id;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	node_id = luaL_checkint(L, 2);

	plog_dbg("l_tm_node_suspend()\n");
	ret = rte_tm_node_suspend(dev_id, node_id, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_node_suspend error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_node_resume(uint16_t port_id,
	uint32_t node_id,
	struct rte_tm_error *error);*/
static int l_tm_node_resume(lua_State *L)
{
	int dev_id, ret;
	uint32_t node_id;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	node_id = luaL_checkint(L, 2);

	plog_dbg("l_tm_node_resume()\n");
	ret = rte_tm_node_resume(dev_id, node_id, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_node_resume error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_hierarchy_commit(uint16_t port_id,
	int clear_on_fail,
	struct rte_tm_error *error);*/
static int l_tm_hierarchy_commit(lua_State *L)
{
	int dev_id, clear_on_fail, ret;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	clear_on_fail = luaL_checkint(L, 2);

	plog_dbg("l_tm_hierarchy_commit()\n");
	ret = rte_tm_hierarchy_commit(dev_id, clear_on_fail, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_hierarchy_commit error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_node_parent_update(uint16_t port_id,
	uint32_t node_id,
	uint32_t parent_node_id,
	uint32_t priority,
	uint32_t weight,
	struct rte_tm_error *error);*/
static int l_tm_node_parent_update(lua_State *L)
{
	int dev_id, ret;
	uint32_t node_id, parent_node_id, priority, weight;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	node_id = luaL_checkint(L, 2);
	parent_node_id = luaL_checkint(L, 3);
	priority = luaL_checkint(L, 4);
	weight = luaL_checkint(L, 5);
	plog_dbg("l_tm_node_parent_update()\n");
	ret = rte_tm_node_parent_update(dev_id, node_id, parent_node_id, priority, weight, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_node_parent_update error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_node_shaper_update(uint16_t port_id,
	uint32_t node_id,
	uint32_t shaper_profile_id,
	struct rte_tm_error *error);*/
static int l_tm_node_shaper_update(lua_State *L)
{
	int dev_id, ret;
	uint32_t node_id, shaper_profile_id;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	node_id = luaL_checkint(L, 2);
	shaper_profile_id = luaL_checkint(L, 3);
	plog_dbg("l_tm_node_shaper_update()\n");
	ret = rte_tm_node_shaper_update(dev_id, node_id, shaper_profile_id, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_node_shaper_update error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_node_shared_shaper_update(uint16_t port_id,
	uint32_t node_id,
	uint32_t shared_shaper_id,
	int add,
	struct rte_tm_error *error);*/
static int l_tm_node_shared_shaper_update(lua_State *L)
{
	int dev_id, add, ret;
	uint32_t node_id, shared_shaper_id;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	node_id = luaL_checkint(L, 2);
	shared_shaper_id = luaL_checkint(L, 3);
	add = luaL_checkint(L, 4);
	plog_dbg("l_tm_node_shared_shaper_update()\n");
	ret = rte_tm_node_shared_shaper_update(dev_id, node_id, shared_shaper_id, add, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_node_shared_shaper_update error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_node_stats_update(uint16_t port_id,
	uint32_t node_id,
	uint64_t stats_mask,
	struct rte_tm_error *error);*/
static int l_tm_node_stats_update(lua_State *L)
{
	int dev_id, ret;
	uint32_t node_id;
	uint64_t mask;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	node_id = luaL_checkint(L, 2);
	mask = luaL_checkinteger(L, 3);
	plog_dbg("l_tm_node_stats_update(), mask=0x%lx\n", mask);
	ret = rte_tm_node_stats_update(dev_id, node_id, mask, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_node_stats_update error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_node_wfq_weight_mode_update(uint16_t port_id,
	uint32_t node_id,
	int *wfq_weight_mode,
	uint32_t n_sp_priorities,
	struct rte_tm_error *error);*/
static int l_tm_node_wfq_weight_mode_update(lua_State *L)
{
	int dev_id, n_elements, ret;
	uint32_t node_id;
	int *wfq_weight_mode = NULL;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	node_id = luaL_checkint(L, 2);
	n_elements = lua_arg2int_array(L, 3, "weight_modes",
				       &wfq_weight_mode, 0, -1);
	if (n_elements == -1) {
		lua_pushinteger(L, -ENOMEM);
		return 1;
	}
	plog_dbg("l_tm_node_wfq_weight_mode_update()\n");
	ret = rte_tm_node_wfq_weight_mode_update(dev_id, node_id, wfq_weight_mode, n_elements, &tmerr);
	free(wfq_weight_mode);
	if (ret!=0) {
		plog_err("TM rte_tm_node_wfq_weight_mode_update error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_node_cman_update(uint16_t port_id,
	uint32_t node_id,
	enum rte_tm_cman_mode cman,
	struct rte_tm_error *error);*/
static int l_tm_node_cman_update(lua_State *L)
{
	int dev_id, cman, ret;
	uint32_t node_id;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	node_id = luaL_checkint(L, 3);
	cman = luaL_checkint(L, 3);
	plog_dbg("l_tm_node_cman_update()\n");
	ret = rte_tm_node_cman_update(dev_id, node_id, cman, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_node_cman_update error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_node_wred_context_update(uint16_t port_id,
	uint32_t node_id,
	uint32_t wred_profile_id,
	struct rte_tm_error *error);*/
static int l_tm_node_wred_context_update(lua_State *L)
{
	int dev_id, ret;
	uint32_t node_id, wred_profile_id;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	node_id = luaL_checkint(L, 2);
	wred_profile_id = luaL_checkint(L, 3);
	plog_dbg("l_tm_node_wred_context_update()\n");
	ret = rte_tm_node_wred_context_update(dev_id, node_id, wred_profile_id, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_node_wred_context_update error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_node_shared_wred_context_update(uint16_t port_id,
	uint32_t node_id,
	uint32_t shared_wred_context_id,
	int add,
	struct rte_tm_error *error);*/
static int l_tm_node_shared_wred_context_update(lua_State *L)
{
	int dev_id, add, ret;
	uint32_t node_id, shared_wred_context_id;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	node_id = luaL_checkint(L, 2);
	shared_wred_context_id = luaL_checkint(L, 3);
	add = luaL_checkint(L, 4);
	plog_dbg("l_tm_node_shared_wred_context_update()\n");
	ret = rte_tm_node_shared_wred_context_update(dev_id, node_id, shared_wred_context_id, add, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_node_shared_wred_context_update error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_node_stats_read(uint16_t port_id,
	uint32_t node_id,
	struct rte_tm_node_stats *stats,
	uint64_t *stats_mask,
	int clear,
	struct rte_tm_error *error);*/
static int l_tm_node_stats_read(lua_State *L)
{
	int dev_id, clear, ret;
	uint32_t node_id;
	uint64_t mask;
	struct rte_tm_node_stats stats;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	node_id = luaL_checkint(L, 2);
	clear = luaL_checkint(L, 3);
	plog_dbg("l_tm_node_stats_read()\n");

	ret = rte_tm_node_stats_read(dev_id, node_id, &stats, &mask, clear, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_node_stats_read error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
		}
	lua_pushinteger(L, ret);
	lua_pushinteger(L, mask);
	node_stats2lua_stack(L, &stats);
	return 3;
}

/*int rte_tm_mark_vlan_dei(uint16_t port_id,
	int mark_green,
	int mark_yellow,
	int mark_red,
	struct rte_tm_error *error);*/
static int l_tm_mark_vlan_dei(lua_State *L)
{
	int dev_id, mark_green, mark_yellow, mark_red, ret;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	mark_green = luaL_checkint(L, 2);
	mark_yellow = luaL_checkint(L, 3);
	mark_red = luaL_checkint(L, 4);
	plog_dbg("l_tm_mark_vlan_dei()\n");
	ret = rte_tm_mark_vlan_dei(dev_id, mark_green, mark_yellow, mark_red, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_mark_vlan_dei error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_mark_ip_ecn(uint16_t port_id,
	int mark_green,
	int mark_yellow,
	int mark_red,
	struct rte_tm_error *error);*/
static int l_tm_mark_ip_ecn(lua_State *L)
{
	int dev_id, mark_green, mark_yellow, mark_red, ret;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	mark_green = luaL_checkint(L, 2);
	mark_yellow = luaL_checkint(L, 3);
	mark_red = luaL_checkint(L, 4);
	plog_dbg("l_tm_mark_ip_ecn()\n");
	ret = rte_tm_mark_ip_ecn(dev_id, mark_green, mark_yellow, mark_red, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_mark_ip_ecn error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

/*int rte_tm_mark_ip_dscp(uint16_t port_id,
	int mark_green,
	int mark_yellow,
	int mark_red,
	struct rte_tm_error *error);*/
static int l_tm_mark_ip_dscp(lua_State *L)
{
	int dev_id, mark_green, mark_yellow, mark_red, ret;
	struct rte_tm_error tmerr;

	dev_id = luaL_checkint(L, 1);
	mark_green = luaL_checkint(L, 2);
	mark_yellow = luaL_checkint(L, 3);
	mark_red = luaL_checkint(L, 4);
	plog_dbg("l_tm_mark_ip_dscp()\n");
	ret = rte_tm_mark_ip_dscp(dev_id, mark_green, mark_yellow, mark_red, &tmerr);
	if (ret!=0) {
		plog_err("TM rte_tm_mark_ip_dscp error: %u: %s\n", tmerr.type, tmerr.message);
		lua_pushinteger(L, -EINVAL);
		return 1;
	}
	lua_pushinteger(L, ret);
	return 1;
}

#define LUA_DECL_FUNC(_lua, _func, _fname)\
	lua_pushcfunction(_lua, _func);   \
	lua_setglobal(_lua, _fname);

/* Setup Lua context and function bindings */
lua_State *ethdev_lua(void)
{
	lua_State *lua;

	lua = ethdev_new_lua_state();

	LUA_DECL_FUNC(lua, l_tm_get_number_of_leaf_nodes, "rte_tm_get_number_of_leaf_nodes");
	LUA_DECL_FUNC(lua, l_tm_node_type_get, "rte_tm_node_type_get");
	LUA_DECL_FUNC(lua, l_tm_capabilities_get, "rte_tm_capabilities_get");
	LUA_DECL_FUNC(lua, l_tm_level_capabilities_get, "rte_tm_level_capabilities_get");
	LUA_DECL_FUNC(lua, l_tm_node_capabilities_get, "rte_tm_node_capabilities_get");
	LUA_DECL_FUNC(lua, l_tm_wred_profile_add, "rte_tm_wred_profile_add");
	LUA_DECL_FUNC(lua, l_tm_wred_profile_delete, "rte_tm_wred_profile_delete");
	LUA_DECL_FUNC(lua, l_tm_shared_wred_context_add_update, "rte_tm_shared_wred_context_add_update");
	LUA_DECL_FUNC(lua, l_tm_shared_wred_context_delete, "rte_tm_shared_wred_context_delete");
	LUA_DECL_FUNC(lua, l_tm_shaper_profile_add, "rte_tm_shaper_profile_add");
	LUA_DECL_FUNC(lua, l_tm_shaper_profile_delete, "rte_tm_shaper_profile_delete");
	LUA_DECL_FUNC(lua, l_tm_shared_shaper_add_update, "rte_tm_shared_shaper_add_update");
	LUA_DECL_FUNC(lua, l_tm_shared_shaper_delete, "rte_tm_shared_shaper_delete");
	LUA_DECL_FUNC(lua, l_tm_node_add, "rte_tm_node_add");
	LUA_DECL_FUNC(lua, l_tm_node_delete, "rte_tm_node_delete");
	LUA_DECL_FUNC(lua, l_tm_node_suspend, "rte_tm_node_suspend");
	LUA_DECL_FUNC(lua, l_tm_node_resume, "rte_tm_node_resume");
	LUA_DECL_FUNC(lua, l_tm_hierarchy_commit, "rte_tm_hierarchy_commit");
	LUA_DECL_FUNC(lua, l_tm_node_parent_update, "rte_tm_node_parent_update");
	LUA_DECL_FUNC(lua, l_tm_node_shaper_update, "rte_tm_node_shaper_update");
	LUA_DECL_FUNC(lua, l_tm_node_shared_shaper_update, "rte_tm_node_shared_shaper_update");
	LUA_DECL_FUNC(lua, l_tm_node_stats_update, "rte_tm_node_stats_update");
	LUA_DECL_FUNC(lua, l_tm_node_wfq_weight_mode_update, "rte_tm_node_wfq_weight_mode_update");
	LUA_DECL_FUNC(lua, l_tm_node_cman_update, "rte_tm_node_cman_update");
	LUA_DECL_FUNC(lua, l_tm_node_wred_context_update, "rte_tm_node_wred_context_update");
	LUA_DECL_FUNC(lua, l_tm_node_shared_wred_context_update, "rte_tm_node_shared_wred_context_update");
	LUA_DECL_FUNC(lua, l_tm_node_stats_read, "rte_tm_node_stats_read");
	LUA_DECL_FUNC(lua, l_tm_mark_vlan_dei, "rte_tm_mark_vlan_dei");
	LUA_DECL_FUNC(lua, l_tm_mark_ip_ecn, "rte_tm_mark_ip_ecn");
	LUA_DECL_FUNC(lua, l_tm_mark_ip_dscp, "rte_tm_mark_ip_dscp");

	return lua;
}
