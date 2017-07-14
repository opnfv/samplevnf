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

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <string.h>
#include <rte_ether.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_acl.h>
#include <rte_version.h>
#include <rte_hash_crc.h>

#include "prox_malloc.h"
#include "etypes.h"
#include "prox_lua.h"
#include "log.h"
#include "quit.h"
#include "defines.h"
#include "prox_globals.h"
#include "prox_lua_types.h"
#include "ip_subnet.h"
#include "hash_entry_types.h"
#include "handle_qinq_encap4.h"
#include "toeplitz.h"
#include "handle_lb_5tuple.h"

#if RTE_VERSION < RTE_VERSION_NUM(1,8,0,0)
#define RTE_CACHE_LINE_SIZE CACHE_LINE_SIZE
#endif

static char error_str[1024];
static char *cur_pos;

const char *get_lua_to_errors(void)
{
	return error_str;
}

static void null_terminate_error(void)
{
	size_t diff = cur_pos - error_str;

	if (diff >= sizeof(error_str) &&
	    error_str[sizeof(error_str) - 1] != 0)
		error_str[sizeof(error_str) - 1] = 0;
}

__attribute__((format(printf, 1, 2))) static void set_err(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	cur_pos = error_str;
	cur_pos += vsnprintf(cur_pos, sizeof(error_str) - (cur_pos - error_str), fmt, ap);
	null_terminate_error();

	va_end(ap);
}

__attribute__((format(printf, 1, 2))) static void concat_err(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	cur_pos += vsnprintf(cur_pos, sizeof(error_str) - (cur_pos - error_str), fmt, ap);
	null_terminate_error();

	va_end(ap);
}

/* Make sure that an element is on the top of the stack (zero on success) */
int lua_getfrom(struct lua_State *L, enum lua_place from, const char *name)
{
	switch (from) {
	case STACK:
		return lua_gettop(L) > 0? 0 : -1;
	case TABLE:
		if (!lua_istable(L, -1)) {
			set_err("Failed to get field '%s' from table (no table)\n", name);
			return -1;
		}

		lua_pushstring(L, name);
		lua_gettable(L, -2);
		if (lua_isnil(L, -1)) {
			set_err("Field '%s' is missing from table\n", name);
			lua_pop(L, 1);
			return -1;
		}
		return 1;
	case GLOBAL:
		lua_getglobal(L, name);
		if (lua_isnil(L, -1)) {
			set_err("Couldn't find global data '%s'\n", name);
			lua_pop(L, 1);
			return -1;
		}
		return 1;
	}
	return -1;
}

int lua_to_ip(struct lua_State *L, enum lua_place from, const char *name, uint32_t *ip)
{
	uint32_t n_entries;
	uint32_t ip_array[4];
	ptrdiff_t v;
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	lua_len(L, -1);
	n_entries = lua_tointeger(L, -1);
	lua_pop(L, 1);

	if (n_entries != 4) {
		set_err("Invalid IPv4 format\n");
		return -1;
	}

	*ip = 0;
	for (int i = 0; i < 4; ++i) {
		lua_pushinteger(L, i + 1);
		lua_gettable(L, -2);
		v = lua_tointeger(L, -1);
		lua_pop(L, 1);
		if (!(v >= 0 && v <= 255)) {
			set_err("Invalid IPv4 format\n");
			return -1;
		}
		*ip |= v << (24 - i*8);
	}

	lua_pop(L, pop);
	return 0;
}

int lua_to_ip6(struct lua_State *L, enum lua_place from, const char *name, uint8_t *ip)
{
	uint32_t n_entries;
	ptrdiff_t v;
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	lua_len(L, -1);
	n_entries = lua_tointeger(L, -1);
	lua_pop(L, 1);

	if (n_entries != 16) {
		set_err("Invalid IPv6 format\n");
		return -1;
	}

	for (int i = 0; i < 16; ++i) {
		lua_pushinteger(L, i + 1);
		lua_gettable(L, -2);
		v = lua_tointeger(L, -1);
		lua_pop(L, 1);
		ip[i] = v;
	}

	lua_pop(L, pop);
	return 0;
}

int lua_to_mac(struct lua_State *L, enum lua_place from, const char *name, struct ether_addr *mac)
{
	uint32_t n_entries;
	uint32_t mac_array[4];
	ptrdiff_t v;
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	lua_len(L, -1);
	n_entries = lua_tointeger(L, -1);
	lua_pop(L, 1);

	if (n_entries != 6) {
		set_err("Invalid MAC format\n");
		return -1;
	}

	for (int i = 0; i < 6; ++i) {
		lua_pushinteger(L, i + 1);
		lua_gettable(L, -2);
		v = lua_tointeger(L, -1);
		lua_pop(L, 1);
		if (!(v >= 0 && v <= 255)) {
			set_err("Invalid MAC format\n");
			return -1;
		}
		mac->addr_bytes[i] = v;
	}

	lua_pop(L, pop);
	return 0;
}

int lua_to_cidr(struct lua_State *L, enum lua_place from, const char *name, struct ip4_subnet *cidr)
{
	uint32_t depth, ip;
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1)) {
		set_err("CIDR is not a table\n");
		return -1;
	}

	if (lua_to_ip(L, TABLE, "ip", &ip) ||
	    lua_to_int(L, TABLE, "depth", &depth)) {
		return -1;
	}
	cidr->ip = ip;
	cidr->prefix = depth;

	lua_pop(L, pop);
	return 0;
}

int lua_to_cidr6(struct lua_State *L, enum lua_place from, const char *name, struct ip6_subnet *cidr)
{
	uint32_t depth;
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1)) {
		set_err("CIDR6 is not a table\n");
		return -1;
	}

	if (lua_to_ip6(L, TABLE, "ip6", cidr->ip) ||
	    lua_to_int(L, TABLE, "depth", &depth)) {
		return -1;
	}
	cidr->prefix = depth;

	lua_pop(L, pop);
	return 0;
}

int lua_to_val_mask(struct lua_State *L, enum lua_place from, const char *name, struct val_mask *val_mask)
{
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1)) {
		set_err("data entry is not a table\n");
		return -1;
	}

	if (lua_to_int(L, TABLE, "val", &val_mask->val) ||
	    lua_to_int(L, TABLE, "mask", &val_mask->mask))
		return -1;

	lua_pop(L, pop);
	return 0;
}

int lua_to_val_range(struct lua_State *L, enum lua_place from, const char *name, struct val_range *val_range)
{
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1)) {
		set_err("data entry is not a table\n");
		return -1;
	}

	if (lua_to_int(L, TABLE, "beg", &val_range->beg) ||
	    lua_to_int(L, TABLE, "end", &val_range->end))
		return -1;

	lua_pop(L, pop);
	return 0;
}

int lua_to_action(struct lua_State *L, enum lua_place from, const char *name, enum acl_action *action)
{
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_isstring(L, -1)) {
		set_err("data entry is not a table\n");
		return -1;
	}

	const char *s = lua_tostring(L, -1);

	if (!strcmp(s, "drop"))
		*action = ACL_DROP;
	else if (!strcmp(s, "allow"))
		*action = ACL_ALLOW;
	else if (!strcmp(s, "rate_limit"))
		*action = ACL_RATE_LIMIT;
	else
		return -1;

	lua_pop(L, pop);
	return 0;
}

int lua_to_string(struct lua_State *L, enum lua_place from, const char *name, char *dst, size_t size)
{
	const char *str;
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_isstring(L, -1)) {
		plog_err("data is not an integer\n");
		return -1;
	}
	str = lua_tostring(L, -1);

	strncpy(dst, str, size);

	lua_pop(L, pop);
	return 0;
}

int lua_to_port(struct lua_State *L, enum lua_place from, const char *name, uint16_t *port)
{
	double tmp = 0;
	int ret;

	ret = lua_to_double(L, from, name, &tmp);
	if (ret == 0)
		*port = tmp;
	return ret;
}

int lua_to_int(struct lua_State *L, enum lua_place from, const char *name, uint32_t *val)
{
	double tmp = 0;
	int ret;

	ret = lua_to_double(L, from, name, &tmp);
	if (ret == 0)
		*val = tmp;
	return ret;
}

int lua_to_double(struct lua_State *L, enum lua_place from, const char *name, double *val)
{
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_isnumber(L, -1)) {
		set_err("data is not a number\n");
		return -1;
	}
	*val = lua_tonumber(L, -1);

	lua_pop(L, pop);
	return 0;
}

int lua_to_routes4_entry(struct lua_State *L, enum lua_place from, const char *name, struct ip4_subnet *cidr, uint32_t *nh_idx)
{
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1)) {
		set_err("Can't read routes4 entry since data is not a table\n");
		return -1;
	}

	if (lua_to_cidr(L, TABLE, "cidr", cidr) ||
	    lua_to_int(L, TABLE, "next_hop_id", nh_idx)) {
		return -1;
	}

	lua_pop(L, pop);
	return 0;
}

int lua_to_next_hop(struct lua_State *L, enum lua_place from, const char *name, uint8_t socket, struct next_hop **nh)
{
	struct next_hop *ret;
	uint32_t next_hop_index;
	uint32_t port_id;
	uint32_t ip;
	uint32_t mpls;
	struct ether_addr mac;
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1)) {
		set_err("Can't read next hop since data is not a table\n");
		return -1;
	}

	ret = prox_zmalloc(sizeof(*ret) * MAX_HOP_INDEX, socket);
	PROX_PANIC(ret == NULL, "Could not allocate memory for next hop\n");

	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (lua_to_int(L, TABLE, "id", &next_hop_index) ||
		    lua_to_int(L, TABLE, "port_id", &port_id) ||
		    lua_to_ip(L, TABLE, "ip", &ip) ||
		    lua_to_mac(L, TABLE, "mac", &mac) ||
		    lua_to_int(L, TABLE, "mpls", &mpls))
			return -1;

		PROX_PANIC(port_id >= PROX_MAX_PORTS, "Port id too high (only supporting %d ports)\n", PROX_MAX_PORTS);
		PROX_PANIC(next_hop_index >= MAX_HOP_INDEX, "Next-hop to high (only supporting %d next hops)\n", MAX_HOP_INDEX);

		ret[next_hop_index].mac_port.out_idx = port_id;
		ret[next_hop_index].ip_dst = ip;

		ret[next_hop_index].mac_port.mac = mac;
		ret[next_hop_index].mpls = mpls;

		lua_pop(L, 1);
	}

	*nh = ret;
	lua_pop(L, pop);
	return 0;
}

int lua_to_next_hop6(struct lua_State *L, enum lua_place from, const char *name, uint8_t socket, struct next_hop6 **nh)
{
	struct next_hop6 *ret;
	uint32_t next_hop_index, port_id, mpls;
	struct ether_addr mac;
	uint8_t ip[16];
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1)) {
		set_err("Data is not a table\n");
		return -1;
	}

	ret = prox_zmalloc(sizeof(*ret) * MAX_HOP_INDEX, socket);
	PROX_PANIC(ret == NULL, "Could not allocate memory for next hop\n");

	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (lua_to_int(L, TABLE, "id", &next_hop_index) ||
		    lua_to_int(L, TABLE, "port_id", &port_id) ||
		    lua_to_ip6(L, TABLE, "ip6", ip) ||
		    lua_to_mac(L, TABLE, "mac", &mac) ||
		    lua_to_int(L, TABLE, "mpls", &mpls))
			return -1;

		PROX_PANIC(port_id >= PROX_MAX_PORTS, "Port id too high (only supporting %d ports)\n", PROX_MAX_PORTS);
		PROX_PANIC(next_hop_index >= MAX_HOP_INDEX, "Next-hop to high (only supporting %d next hops)\n", MAX_HOP_INDEX);

		ret[next_hop_index].mac_port.out_idx = port_id;
		memcpy(ret[next_hop_index].ip_dst,ip, 16);

		ret[next_hop_index].mac_port.mac = mac;
		ret[next_hop_index].mpls = mpls;

		lua_pop(L, 1);
	}

	*nh = ret;
	lua_pop(L, pop);
	return 0;
}

int lua_to_routes4(struct lua_State *L, enum lua_place from, const char *name, uint8_t socket, struct lpm4 *lpm)
{
	struct ip4_subnet dst;
	uint32_t next_hop_index;
	uint32_t n_loaded_rules;
	uint32_t n_tot_rules;
	struct rte_lpm *new_lpm;
	char lpm_name[64];
	int ret;
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	snprintf(lpm_name, sizeof(lpm_name), "IPv4_lpm_s%u", socket);

	if (!lua_istable(L, -1)) {
		set_err("Data is not a table\n");
		return -1;
	}

	lua_len(L, -1);
	n_tot_rules = lua_tointeger(L, -1);
	n_loaded_rules = 0;
	lua_pop(L, 1);
#if RTE_VERSION >= RTE_VERSION_NUM(16,4,0,1)
	struct rte_lpm_config conf;
	conf.max_rules = 2 * n_tot_rules;
	conf.number_tbl8s = 256;
	conf.flags = 0;
	new_lpm = rte_lpm_create(lpm_name, socket, &conf);
#else
	new_lpm = rte_lpm_create(lpm_name, socket, 2 * n_tot_rules, 0);
#endif
	PROX_PANIC(NULL == new_lpm, "Failed to allocate lpm\n");

	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (lua_to_routes4_entry(L, STACK, NULL, &dst, &next_hop_index)) {
			set_err("Failed to read entry while setting up lpm\n");
			return -1;
		}
		ret = rte_lpm_add(new_lpm, dst.ip, dst.prefix, next_hop_index);

		if (ret != 0) {
			set_err("Failed to add (%d) index %u ip %x/%u to lpm\n",
				 ret, next_hop_index, dst.ip, dst.prefix);
		}
		else if (++n_loaded_rules % 10000 == 0) {
			plog_info("Route %d added\n", n_loaded_rules);
		}

		lua_pop(L, 1);
	}

	lpm->rte_lpm = new_lpm;
	lpm->n_used_rules = n_loaded_rules;
	lpm->n_free_rules = 2 * n_tot_rules - n_loaded_rules;

	lua_pop(L, pop);
	return 0;
}

int lua_to_lpm4(struct lua_State *L, enum lua_place from, const char *name, uint8_t socket, struct lpm4 **lpm)
{
	struct lpm4 *ret;
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	ret = prox_zmalloc(sizeof(struct lpm4), socket);

	if (!lua_istable(L, -1)) {
		set_err("Can't read lpm4 since data is not a table\n");
		return -1;
	}

	if (lua_to_routes4(L, TABLE, "routes", socket, ret) ||
	    lua_to_next_hop(L, TABLE, "next_hops", socket, &ret->next_hops)) {
		return -1;
	}

	if (ret->rte_lpm)
		plog_info("Loaded %d routes\n", ret->n_used_rules);

	*lpm = ret;
	lua_pop(L, pop);
	return 0;
}

int lua_to_lpm6(struct lua_State *L, enum lua_place from, const char *name, uint8_t socket, struct lpm6 **lpm)
{
	struct lpm6 *ret;
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1)) {
		set_err("Lpm6 is not a table\n");
		return -1;
	}

	ret = prox_zmalloc(sizeof(struct lpm6), socket);

	if (lua_to_routes6(L, TABLE, "routes6", socket, ret) ||
	    lua_to_next_hop6(L, TABLE, "next_hops6", socket, &ret->next_hops))
		return -1;

	if (ret->rte_lpm6)
		plog_info("Loaded %d routes\n", ret->n_used_rules);

	*lpm = ret;

	lua_pop(L, pop);
	return 0;
}

static int lua_to_lpm6_entry(struct lua_State *L, enum lua_place from, const char *name, struct ip6_subnet *cidr, uint32_t *nh_idx)
{
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1)) {
		set_err("lpm6 entry is not a table\n");
		return -1;
	}
	if (lua_to_cidr6(L, TABLE, "cidr6", cidr) ||
	    lua_to_int(L, TABLE, "next_hop_id", nh_idx)) {
		return -1;
	}

	lua_pop(L, pop);
	return 0;
}

int lua_to_routes6(struct lua_State *L, enum lua_place from, const char *name, uint8_t socket, struct lpm6 *lpm)
{
	struct ip6_subnet dst;
	uint32_t next_hop_index;
	uint32_t n_loaded_rules;
	struct rte_lpm6 *new_lpm;
	struct rte_lpm6_config config;
	uint32_t n_tot_rules;
	char lpm_name[64];
	int ret;
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	snprintf(lpm_name, sizeof(lpm_name), "IPv6_lpm_s%u", socket);

	if (!lua_istable(L, -1)) {
		set_err("Data is not a table\n");
		return -1;
	}

	lua_len(L, -1);
	n_tot_rules = lua_tointeger(L, -1);
	n_loaded_rules = 0;
	lua_pop(L, 1);

	config.max_rules = n_tot_rules;
	config.number_tbl8s = (1 << 16);
	config.flags = 0;

	new_lpm = rte_lpm6_create(lpm_name, socket, &config);
	PROX_PANIC(NULL == new_lpm, "Failed to allocate lpm\n");

	lua_pushnil(L);
	while (lua_next(L, -2)) {

		if (lua_to_lpm6_entry(L, STACK, NULL, &dst, &next_hop_index)) {
			concat_err("Failed to read entry while setting up lpm\n");
			return -1;
		}

		ret = rte_lpm6_add(new_lpm, dst.ip, dst.prefix, next_hop_index);

		if (ret != 0) {
			plog_warn("Failed to add (%d) index %u, %d\n",
				  ret, next_hop_index, dst.prefix);
		}
		else if (++n_loaded_rules % 10000 == 0) {
			plog_info("Route %d added\n", n_loaded_rules);
		}

		lua_pop(L, 1);
	}

	lpm->rte_lpm6 = new_lpm;
	lpm->n_used_rules = n_loaded_rules;
	lpm->n_free_rules = 2 * n_tot_rules - n_loaded_rules;

	lua_pop(L, pop);
	return 0;
}

int lua_to_dscp(struct lua_State *L, enum lua_place from, const char *name, uint8_t socket, uint8_t **dscp)
{
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1)) {
		set_err("DSCP is not a table\n");
		return -1;
	}

	uint32_t dscp_bits, tc, queue;
	int status;
	*dscp = prox_zmalloc(64, socket);
	PROX_PANIC(dscp == NULL, "Error creating dscp table");

	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (lua_to_int(L, TABLE, "dscp", &dscp_bits) ||
		    lua_to_int(L, TABLE, "tc", &tc) ||
		    lua_to_int(L, TABLE, "queue", &queue)) {
			concat_err("Failed to read dscp config\n");
			return -1;
		}

		lua_pop(L, 1);

		(*dscp)[dscp_bits] = tc << 2 | queue;
	}

	lua_pop(L, pop);
	return 0;
}

int lua_to_qinq_gre_map(struct lua_State *L, enum lua_place from, const char *name, uint8_t socket, struct qinq_gre_map **qinq_gre_map)
{
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1)) {
		if (from != STACK)
			set_err("QinQ to gre map is not a table\n");
		else
			set_err("QinQ to gre map %s is not a table\n", name);
		return -1;
	}

	struct qinq_gre_map *ret;
	uint32_t svlan, cvlan;
	uint16_t be_svlan, be_cvlan;
	uint32_t user;
	uint32_t gre_id;

	uint32_t n_entries;
	uint32_t idx = 0;

	lua_len(L, -1);
	n_entries = lua_tointeger(L, -1);
	lua_pop(L, 1);

	size_t mem_size = 0;
	mem_size += sizeof(struct qinq_gre_map);
	mem_size += n_entries * sizeof(struct qinq_gre_entry);

	ret = prox_zmalloc(mem_size, socket);
	PROX_PANIC(ret == NULL, "Error creating gre_qinq map");

	ret->count = n_entries;

	lua_pushnil(L);
	while (lua_next(L, -2)) {

		if (lua_to_int(L, TABLE, "svlan_id", &svlan) ||
		    lua_to_int(L, TABLE, "cvlan_id", &cvlan) ||
		    lua_to_int(L, TABLE, "gre_id", &gre_id) ||
		    lua_to_int(L, TABLE, "user_id", &user)) {
			concat_err("Failed to read user table config\n");
			return -1;
		}

		be_svlan = rte_bswap16((uint16_t)svlan);
		be_cvlan = rte_bswap16((uint16_t)cvlan);

		ret->entries[idx].user = user;
		ret->entries[idx].svlan = be_svlan;
		ret->entries[idx].cvlan = be_cvlan;
		ret->entries[idx].gre_id = gre_id;
		ret->entries[idx].rss = toeplitz_hash((uint8_t *)&be_cvlan, 4);

		plog_dbg("elem %u: be_svlan=%x, be_cvlan=%x, rss_input=%x, rss=%x, gre_id=%x\n",
			 idx, be_svlan, be_cvlan, be_cvlan, ret->entries[idx].rss, gre_id);

		idx++;
		lua_pop(L, 1);
	}

	*qinq_gre_map = ret;

	lua_pop(L, pop);
	return 0;
}

int lua_to_user_table(struct lua_State *L, enum lua_place from, const char *name, uint8_t socket, uint16_t **user_table)
{
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1)) {
		set_err("Data is not a table\n");
		return -1;
	}

	uint32_t svlan, cvlan;
	uint16_t be_svlan, be_cvlan;
	uint32_t user;

	*user_table = prox_zmalloc(0x1000000 * sizeof(uint16_t), socket);
	PROX_PANIC(*user_table == NULL, "Error creating user table");

	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (lua_to_int(L, TABLE, "svlan_id", &svlan) ||
		    lua_to_int(L, TABLE, "cvlan_id", &cvlan) ||
		    lua_to_int(L, TABLE, "user_id", &user)) {
			concat_err("Failed to read user table config\n");
			return -1;
		}

		be_svlan = rte_bswap16((uint16_t)svlan);
		be_cvlan = rte_bswap16((uint16_t)cvlan);

		(*user_table)[PKT_TO_LUTQINQ(be_svlan, be_cvlan)] = user;

		lua_pop(L, 1);
	}

	lua_pop(L, pop);
	return 0;
}

int lua_to_ip6_tun_binding(struct lua_State *L, enum lua_place from, const char *name, uint8_t socket, struct ipv6_tun_binding_table **data)
{
	struct ipv6_tun_binding_table *ret;
	uint32_t n_entries;
	uint32_t idx = 0;
	uint32_t port = 0;
	size_t memsize = 0;
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1)) {
		set_err("Can't read IPv6 tunnel bindings entry since ret is not a table\n");
		return -1;
	}

	lua_len(L, -1);
	n_entries = lua_tointeger(L, -1);
	lua_pop(L, 1);

	memsize = sizeof(struct ipv6_tun_binding_table);
	memsize += n_entries * sizeof(struct ipv6_tun_binding_entry);

	ret = prox_zmalloc(memsize, socket);

	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (lua_to_ip6(L, TABLE, "ip6", ret->entry[idx].endpoint_addr.bytes) ||
		    lua_to_mac(L, TABLE, "mac", &ret->entry[idx].next_hop_mac) ||
		    lua_to_ip(L, TABLE, "ip", &ret->entry[idx].public_ipv4) ||
		    lua_to_int(L, TABLE, "port", &port))
			return -1;

		ret->entry[idx].public_port = port;
		idx++;
		lua_pop(L, 1);
	}
	ret->num_binding_entries = idx;

	plog_info("\tRead %d IPv6 Tunnel Binding entries\n", idx);

	*data = ret;

	lua_pop(L, pop);
	return 0;
}

int lua_to_cpe_table_data(struct lua_State *L, enum lua_place from, const char *name, uint8_t socket, struct cpe_table_data **data)
{
	struct cpe_table_data *ret;
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1)) {
		set_err("Can't read IPv6 tunnel bindings entry since ret is not a table\n");
		return -1;
	}

	/* Each entry in the input table expands to multiple entries
	   depending on the number of hosts within the subnet. For
	   this reason, go through the whole table and find out how
	   many entries will be added in total. */
	struct ip4_subnet cidr;
	uint32_t n_entries = 0;
	uint32_t port_idx, gre_id, svlan, cvlan, user;
	struct ether_addr mac;
	uint32_t idx = 0;

	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (lua_to_cidr(L, TABLE, "cidr", &cidr))
			return -1;
		n_entries += ip4_subet_get_n_hosts(&cidr);
		lua_pop(L, 1);
	}

	ret = prox_zmalloc(sizeof(*ret) + n_entries * sizeof(struct cpe_table_entry), 0);

	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (lua_to_int(L, TABLE, "dest_id", &port_idx) ||
		    lua_to_int(L, TABLE, "gre_id", &gre_id) ||
		    lua_to_int(L, TABLE, "svlan_id", &svlan) ||
		    lua_to_int(L, TABLE, "cvlan_id", &cvlan) ||
		    lua_to_cidr(L, TABLE, "cidr", &cidr) ||
		    lua_to_mac(L, TABLE, "mac", &mac) ||
		    lua_to_int(L, TABLE, "user_id", &user))
			return -1;

		uint32_t n_hosts = ip4_subet_get_n_hosts(&cidr);

		for (uint32_t i = 0; i < n_hosts; ++i) {
			ret->entries[idx].port_idx = port_idx;
			ret->entries[idx].gre_id = gre_id;
			ret->entries[idx].svlan = rte_bswap16(svlan);
			ret->entries[idx].cvlan = rte_bswap16(cvlan);
			ret->entries[idx].eth_addr = mac;
			ret->entries[idx].user = user;

			PROX_PANIC(ip4_subnet_to_host(&cidr, i, &ret->entries[idx].ip), "Invalid host in address\n");
			ret->entries[idx].ip = rte_bswap32(ret->entries[idx].ip);
			idx++;
		}

		lua_pop(L, 1);
	}

	ret->n_entries = n_entries;
	*data = ret;

	lua_pop(L, pop);
	return 0;
}

struct acl4_rule {
	struct rte_acl_rule_data data;
	struct rte_acl_field fields[9];
};

int lua_to_rules(struct lua_State *L, enum lua_place from, const char *name, struct rte_acl_ctx *ctx, uint32_t* n_max_rules, int use_qinq, uint16_t qinq_tag)
{
	int pop;

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1)) {
		set_err("Can't read rules since data is not a table\n");
		return -1;
	}

	struct val_mask svlan, cvlan, ip_proto;
	struct ip4_subnet src_cidr, dst_cidr;
	struct val_range sport, dport;
	enum acl_action action;
	uint32_t n_rules = 0;
	lua_pushnil(L);
	while (lua_next(L, -2)) {
		if (n_rules == *n_max_rules) {
			set_err("Too many rules");
			return -1;
		}
		if (use_qinq) {
			if (lua_to_val_mask(L, TABLE, "svlan_id", &svlan) ||
			    lua_to_val_mask(L, TABLE, "cvlan_id", &cvlan))
				return -1;
		}

		if (lua_to_val_mask(L, TABLE, "ip_proto", &ip_proto) ||
		    lua_to_cidr(L, TABLE, "src_cidr", &src_cidr) ||
		    lua_to_cidr(L, TABLE, "dst_cidr", &dst_cidr) ||
		    lua_to_val_range(L, TABLE, "sport", &sport) ||
		    lua_to_val_range(L, TABLE, "dport", &dport) ||
		    lua_to_action(L, TABLE, "action", &action))
			return -1;

		struct acl4_rule rule;

		rule.data.userdata = action; /* allow, drop or rate_limit */
		rule.data.category_mask = 1;
		rule.data.priority = n_rules++;

		/* Configuration for rules is done in little-endian so no bswap is needed here.. */

		rule.fields[0].value.u8 = ip_proto.val;
		rule.fields[0].mask_range.u8 = ip_proto.mask;
		rule.fields[1].value.u32 = src_cidr.ip;
		rule.fields[1].mask_range.u32 = src_cidr.prefix;

		rule.fields[2].value.u32 = dst_cidr.ip;
		rule.fields[2].mask_range.u32 = dst_cidr.prefix;

		rule.fields[3].value.u16 = sport.beg;
		rule.fields[3].mask_range.u16 = sport.end;

		rule.fields[4].value.u16 = dport.beg;
		rule.fields[4].mask_range.u16 = dport.end;

		if (use_qinq) {
			rule.fields[5].value.u16 = rte_bswap16(qinq_tag);
			rule.fields[5].mask_range.u16 = 0xffff;

			/* To mask out the TCI and only keep the VID, the mask should be 0x0fff */
			rule.fields[6].value.u16 = svlan.val;
			rule.fields[6].mask_range.u16 = svlan.mask;

			rule.fields[7].value.u16 = rte_bswap16(ETYPE_VLAN);
			rule.fields[7].mask_range.u16 = 0xffff;

			rule.fields[8].value.u16 = cvlan.val;
			rule.fields[8].mask_range.u16 = cvlan.mask;
		}
		else {
			/* Reuse first ethertype from vlan to check if packet is IPv4 packet */
			rule.fields[5].value.u16 =  rte_bswap16(ETYPE_IPv4);
			rule.fields[5].mask_range.u16 = 0xffff;

			/* Other fields are ignored */
			rule.fields[6].value.u16 = 0;
			rule.fields[6].mask_range.u16 = 0;
			rule.fields[7].value.u16 = 0;
			rule.fields[7].mask_range.u16 = 0;
			rule.fields[8].value.u16 = 0;
			rule.fields[8].mask_range.u16 = 0;
		}

		rte_acl_add_rules(ctx, (struct rte_acl_rule*) &rule, 1);
		lua_pop(L, 1);
	}

	*n_max_rules -= n_rules;
	lua_pop(L, pop);
	return 0;
}

static inline uint32_t ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len, uint32_t init_val)
{
	const union ipv4_5tuple_host *k;
	uint32_t t;
	const uint32_t *p;

	k = data;
	t = k->proto;
	p = (const uint32_t *)&k->port_src;

	init_val = rte_hash_crc_4byte(t, init_val);
	init_val = rte_hash_crc_4byte(k->ip_src, init_val);
	init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
	init_val = rte_hash_crc_4byte(*p, init_val);
	return (init_val);
}

int lua_to_tuples(struct lua_State *L, enum lua_place from, const char *name, uint8_t socket, struct rte_hash **lookup_hash, uint8_t **out_if)
{
	int pop;
	char s[64];

	if ((pop = lua_getfrom(L, from, name)) < 0)
		return -1;

	if (!lua_istable(L, -1)) {
		plog_err("Can't read rules since data is not a table\n");
		return -1;
	}

	lua_len(L, -1);
	uint32_t n_tot_tuples = lua_tointeger(L, -1);
	lua_pop(L, 1);

	struct rte_hash_parameters ipv4_l3fwd_hash_params = {
		.name = NULL,
		.entries = n_tot_tuples * 4,
		.key_len = sizeof(union ipv4_5tuple_host),
#if RTE_VERSION < RTE_VERSION_NUM(2, 1, 0, 0)
		.bucket_entries = 4,
#endif
		.hash_func = ipv4_hash_crc,
		.hash_func_init_val = 0,
	};

	/* create lb_5tuple hash - same hash is shared between cores on same socket */
	snprintf(s, sizeof(s), "ipv4_l3fwd_hash_%d", socket);
	if ((*lookup_hash = rte_hash_find_existing(s)) == NULL) {
		ipv4_l3fwd_hash_params.name = s;
		ipv4_l3fwd_hash_params.socket_id = socket;
		*lookup_hash = rte_hash_create(&ipv4_l3fwd_hash_params);
		PROX_PANIC(*lookup_hash == NULL, "Unable to create the lb_5tuple hash\n");
	}

	lua_pushnil(L);
	while (lua_next(L, -2)) {
		uint32_t if_out, ip_src, ip_dst, port_src, port_dst, proto;
		union ipv4_5tuple_host newkey;

		if (lua_to_int(L, TABLE, "if_out", &if_out) ||
		    lua_to_int(L, TABLE, "ip_src", &ip_src) ||
		    lua_to_int(L, TABLE, "ip_dst", &ip_dst) ||
		    lua_to_int(L, TABLE, "port_src", &port_src) ||
		    lua_to_int(L, TABLE, "port_dst", &port_dst) ||
		    lua_to_int(L, TABLE, "proto", &proto)) {
			plog_err("Failed to read user table config\n");
			return -1;
		}

		newkey.ip_dst = rte_cpu_to_be_32(ip_dst);
		newkey.ip_src = rte_cpu_to_be_32(ip_src);
		newkey.port_dst = rte_cpu_to_be_16((uint16_t)port_dst);
		newkey.port_src = rte_cpu_to_be_16((uint16_t)port_src);
		newkey.proto = (uint8_t)proto;
		newkey.pad0 = 0;
		newkey.pad1 = 0;

		int32_t ret = rte_hash_add_key(*lookup_hash, (void *) &newkey);
		PROX_PANIC(ret < 0, "Unable to add entry (err code %d)\n", ret);
		(*out_if)[ret] = (uint8_t) if_out;

		lua_pop(L, 1);
	}
	lua_pop(L, pop);
	return 0;
}
