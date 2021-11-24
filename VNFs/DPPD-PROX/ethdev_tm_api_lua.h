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

#ifndef __ETHDEV_TM_API_LUA_H_
#define __ETHDEV_TM_API_LUA_H_

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_tm.h>

#include "log.h"
#define ethdev_dbg  plog_dbg
#define ethdev_err  plog_err
#include "prox_lua.h"
#define ethdev_new_lua_state()   prox_lua()

/* Setup Lua context and QoS function bindings */
lua_State *ethdev_lua(void);

#endif /* __ETHDEV_TM_API_LUA_H_ */
