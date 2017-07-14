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

#ifndef _LUA_COMPAT_H_
#define _LUA_COMPAT_H_

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#if LUA_VERSION_NUM < 503
#include <float.h>
static int lua_isinteger(lua_State *L, int idx)
{
	if (!lua_isnumber(L, idx)) {
		return -1;
	}

	double whole = lua_tonumber(L, idx);
	whole -= lua_tointeger(L, idx);
	return whole < DBL_EPSILON && whole >= -DBL_EPSILON ;
}
#endif

#if LUA_VERSION_NUM < 502
static int lua_len(lua_State *L, int idx)
{
       int len = lua_objlen(L, idx);

       lua_pushnumber(L, len);
       return len;
}
#endif

#endif /* _LUA_COMPAT_H_ */
