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

#include <string.h>
#include <stdlib.h>

#include "prox_lua.h"
#include "lua_compat.h"
#include "parse_utils.h"

static struct lua_State *lua_instance;

static int l_mask(lua_State *L)
{
	uint32_t val, mask;

	if (lua_gettop(L) != 2) {
		return luaL_error(L, "Expecting 2 argument and got %d\n", lua_gettop(L));
	}
	if (!lua_isnumber(L, -1) || !lua_isnumber(L, -2)) {
		return luaL_error(L, "Expecting (integer, integer) as arguments\n");
	}
	val = lua_tonumber(L, -1);
	mask = lua_tonumber(L, -2);

	lua_pushinteger(L, val & mask);

	return 1;
}

static int l_server_content(lua_State *L)
{
	uint32_t beg, len;

	if (lua_gettop(L) != 2) {
		return luaL_error(L, "Expecting 2 argument and got %d\n", lua_gettop(L));
	}
	if (!lua_isnumber(L, -1) || !lua_isnumber(L, -2)) {
		return luaL_error(L, "Expecting (integer, integer) as arguments\n");
	}
	len = lua_tonumber(L, -1);
	beg = lua_tonumber(L, -2);

	lua_createtable(L, 0, 3);

	lua_pushinteger(L, beg);
	lua_setfield(L, -2, "beg");
	lua_pushinteger(L, len);
	lua_setfield(L, -2, "len");
	lua_pushinteger(L, 0);
	lua_setfield(L, -2, "peer");

	return 1;
}

static int l_client_content(lua_State *L)
{
	uint32_t beg, len;

	if (lua_gettop(L) != 2) {
		return luaL_error(L, "Expecting 2 argument and got %d\n", lua_gettop(L));
	}
	if (!lua_isnumber(L, -1) || !lua_isnumber(L, -2)) {
		return luaL_error(L, "Expecting (integer, integer) as arguments\n");
	}
	len = lua_tonumber(L, -1);
	beg = lua_tonumber(L, -2);

	lua_createtable(L, 0, 3);

	lua_pushinteger(L, beg);
	lua_setfield(L, -2, "beg");
	lua_pushinteger(L, len);
	lua_setfield(L, -2, "len");
	lua_pushinteger(L, 1);
	lua_setfield(L, -2, "peer");

	return 1;
}

static int l_bin_read(lua_State *L)
{
	const char *file_name = lua_tostring(L, -1);
	int beg = lua_tonumber(L, -2);
	int len = lua_gettop(L) == 3? lua_tonumber(L, -3) : -1;

	if (lua_gettop(L) == 2) {
		if (!lua_isnumber(L, -1) || !lua_isstring(L, -2)) {
			return luaL_error(L, "Expecting (string, integer) as arguments\n");
		}

		file_name = lua_tostring(L, -2);
		beg = lua_tonumber(L, -1);
		len = -1;
	}
	else if (lua_gettop(L) == 3) {
		if (!lua_isnumber(L, -1) || !lua_isnumber(L, -2) || !lua_isstring(L, 3)) {
			return luaL_error(L, "Expecting (string, integer, integer) as arguments\n");
		}

		file_name = lua_tostring(L, -3);
		beg = lua_tonumber(L, -2);
		len = lua_tonumber(L, -1);
	}
	else
		return luaL_error(L, "Expecting 2 or 3 arguments\n");

	lua_createtable(L, 0, 3);

	lua_pushstring(L, file_name);
	lua_setfield(L, -2, "file_name");
	lua_pushinteger(L, beg);
	lua_setfield(L, -2, "beg");
	lua_pushinteger(L, len);
	lua_setfield(L, -2, "len");

	return 1;
}

static int l_mac(lua_State *L)
{
	int mac[6];

	if (lua_isstring(L, -1)) {
		const char *arg = lua_tostring(L, -1);
		char arg2[128];
		strncpy(arg2, arg, sizeof(arg2));

		char *p = arg2;
		int count = 0;

		while ((p = strchr(p, ':'))) {
			count++;
			p++;
		}
		p = arg2;
		if (count != 5)
			return luaL_error(L, "Invalid MAC format\n");

		lua_createtable(L, 6, 0);
		for (size_t i = 0; i < 6; ++i) {
			char *n = strchr(p, ':');
			if (n)
				*n = 0;
			if (strlen(p) != 2) {
				return luaL_error(L, "Invalid MAC format\n");
			}

			lua_pushinteger(L, strtol(p, NULL, 16));
			lua_rawseti(L, -2, i + 1);
			p = n + 1;
		}
		return 1;
	}

	return luaL_error(L, "Invalid argument\n");
}

static int l_ip(lua_State *L)
{
	int ip[4];
	if (lua_isnumber(L, -1)) {
		uint32_t arg = lua_tointeger(L, -1);

		ip[0] = arg >> 24 & 0xff;
		ip[1] = arg >> 16 & 0xff;
		ip[2] = arg >>  8 & 0xff;
		ip[3] = arg >>  0 & 0xff;

		lua_createtable(L, 4, 0);
		for (size_t i = 0; i < 4; ++i) {
			lua_pushinteger(L, ip[i]);
			lua_rawseti(L, -2, i + 1);
		}

		return 1;
	}
	if (lua_isstring(L, -1)) {
		const char *arg = lua_tostring(L, -1);

		if (sscanf(arg, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]) != 4) {
			return luaL_error(L, "Invalid IP address format\n");
		}

		lua_createtable(L, 4, 0);
		for (size_t i = 0; i < 4; ++i) {
			lua_pushinteger(L, ip[i]);
			lua_rawseti(L, -2, i + 1);
		}

		return 1;
	}

	return luaL_error(L, "Invalid argument\n");
}

static int l_ip6(lua_State *L)
{
	int ip[16];

	if (!lua_isstring(L, -1)) {
		return luaL_error(L, "Invalid argument type\n");
	}

	const char *arg = lua_tostring(L, -1);
	char arg2[64];
	char *addr_parts[8];
	int n_parts = 0;
	size_t str_len = strlen(arg);
	int next_str = 1;
	int ret;

	strncpy(arg2, arg, sizeof(arg2));

	for (size_t i = 0; i < str_len; ++i) {
		if (next_str) {
			if (n_parts == 8)
				return luaL_error(L, "IPv6 address can't be longer than 16 bytes\n");
			addr_parts[n_parts++] = &arg2[i];
			next_str = 0;

		}
		if (arg2[i] == ':') {
			arg2[i] = 0;
			next_str = 1;
		}
	}

	int omitted = 0;

	for (int i = 0, j = 0; i < n_parts; ++i) {
		if (*addr_parts[i] == 0) {
			if (omitted == 0) {
				return luaL_error(L, "Can omit zeros only once\n");
			}
			omitted = 1;
			j += 8 - n_parts;
		}
		else {
			uint16_t w = strtoll(addr_parts[i], NULL, 16);
			ip[j++] = (w >> 8) & 0xff;
			ip[j++] = w & 0xff;
		}
	}

	lua_createtable(L, 16, 0);
	for (size_t i = 0; i < 16; ++i) {
		lua_pushinteger(L, ip[i]);
		lua_rawseti(L, -2, i + 1);
	}

	return 1;
}

static int l_cidr(lua_State *L)
{
	const char *arg = lua_tostring(L, -1);

	char tmp[128];
	strncpy(tmp, arg, sizeof(tmp));

	char *slash = strchr(tmp, '/');
	*slash = 0;
	slash++;

	lua_createtable(L, 0, 2);
	lua_pushstring(L, "ip");

	lua_pushstring(L, tmp);
	l_ip(L);
	lua_remove(L, -2);

	lua_settable(L, -3);

	lua_pushstring(L, "depth");
	lua_pushinteger(L, atoi(slash));
	lua_settable(L, -3);
	return 1;
}

static int l_cidr6(lua_State *L)
{
	const char *arg = lua_tostring(L, -1);

	char tmp[128];
	strncpy(tmp, arg, sizeof(tmp));

	char *slash = strchr(tmp, '/');
	*slash = 0;
	slash++;

	lua_createtable(L, 0, 2);
	lua_pushstring(L, "ip6");

	lua_pushstring(L, tmp);
	l_ip6(L);
	lua_remove(L, -2);

	lua_settable(L, -3);

	lua_pushstring(L, "depth");
	lua_pushinteger(L, atoi(slash));
	lua_settable(L, -3);
	return 1;
}

static int l_val_mask(lua_State *L)
{
	if (!lua_isinteger(L, -2))
		return luaL_error(L, "Argument 1 is not an integer\n");
	if (!lua_isinteger(L, -1))
		return luaL_error(L, "Argument 2 is not an integer\n");

	uint32_t val = lua_tointeger(L, -2);
	uint32_t mask = lua_tointeger(L, -1);

	lua_createtable(L, 0, 2);
	lua_pushstring(L, "val");
	lua_pushinteger(L, val);
	lua_settable(L, -3);

	lua_pushstring(L, "mask");
	lua_pushinteger(L, mask);
	lua_settable(L, -3);

	return 1;
}

static int l_val_range(lua_State *L)
{
	if (!lua_isinteger(L, -2))
		return luaL_error(L, "Argument 1 is not an integer\n");
	if (!lua_isinteger(L, -1))
		return luaL_error(L, "Argument 2 is not an integer\n");

	uint32_t beg = lua_tointeger(L, -2);
	uint32_t end = lua_tointeger(L, -1);

	lua_createtable(L, 0, 2);
	lua_pushstring(L, "beg");
	lua_pushinteger(L, beg);
	lua_settable(L, -3);

	lua_pushstring(L, "end");
	lua_pushinteger(L, end);
	lua_settable(L, -3);

	return 1;
}

static int l_task_count(lua_State *L)
{
	struct core_task_set cts;
	const char *str;

	if (!lua_isstring(L, -1))
		return luaL_error(L, "Argument 1 is not an string\n");
	str = lua_tostring(L, -1);
	if (parse_task_set(&cts, str))
		return luaL_error(L, "Invalid core task set syntax\n");
	lua_pushinteger(L, cts.n_elems);
	return 1;
}

struct lua_State *prox_lua(void)
{
	if (!lua_instance) {
		lua_instance = luaL_newstate();

		luaL_openlibs(lua_instance);

		lua_pushcfunction(lua_instance, l_ip);
		lua_setglobal(lua_instance, "ip");
		lua_pushcfunction(lua_instance, l_ip6);
		lua_setglobal(lua_instance, "ip6");
		lua_pushcfunction(lua_instance, l_cidr);
		lua_setglobal(lua_instance, "cidr");
		lua_pushcfunction(lua_instance, l_cidr6);
		lua_setglobal(lua_instance, "cidr6");
		lua_pushcfunction(lua_instance, l_mac);
		lua_setglobal(lua_instance, "mac");
		lua_pushcfunction(lua_instance, l_mask);
		lua_setglobal(lua_instance, "mask");
		lua_pushcfunction(lua_instance, l_val_mask);
		lua_setglobal(lua_instance, "val_mask");
		lua_pushcfunction(lua_instance, l_val_range);
		lua_setglobal(lua_instance, "val_range");
		lua_pushcfunction(lua_instance, l_bin_read);
		lua_setglobal(lua_instance, "bin_read");
		lua_pushcfunction(lua_instance, l_client_content);
		lua_setglobal(lua_instance, "client_content");
		lua_pushcfunction(lua_instance, l_server_content);
		lua_setglobal(lua_instance, "server_content");
		lua_pushcfunction(lua_instance, l_task_count);
		lua_setglobal(lua_instance, "task_count");
	}
	return lua_instance;
}
