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

#include <stdio.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_version.h>

#include "quit.h"
#include "log.h"
#include "prox_shared.h"
#include "prox_globals.h"

#define INIT_HASH_TABLE_SIZE 8192

struct prox_shared {
	struct rte_hash *hash;
	size_t          size;
};

struct prox_shared sh_system;
struct prox_shared sh_socket[MAX_SOCKETS];
struct prox_shared sh_core[RTE_MAX_LCORE];

static char* get_sh_name(void)
{
	static char name[] = "prox_sh";

	name[0]++;
	return name;
}

struct rte_hash_parameters param = {
	.key_len = 256,
	.hash_func = rte_hash_crc,
	.hash_func_init_val = 0,
	.socket_id = 0,
};

static void prox_sh_create_hash(struct prox_shared *ps, size_t size)
{
	param.entries = size;
	param.name = get_sh_name();
	ps->hash = rte_hash_create(&param);
	PROX_PANIC(ps->hash == NULL, "Failed to create hash table for shared data");
	ps->size = size;
	if (ps->size == INIT_HASH_TABLE_SIZE)
		plog_info("Shared data tracking hash table created with size %zu\n", ps->size);
	else
		plog_info("Shared data tracking hash table grew to %zu\n", ps->size);
}

#if RTE_VERSION >= RTE_VERSION_NUM(2,1,0,0)
static int copy_hash(struct rte_hash *new_hash, struct rte_hash *old_hash)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;

	while (rte_hash_iterate(old_hash, &next_key, &next_data, &iter) >= 0) {
		if (rte_hash_add_key_data(new_hash, next_key, next_data) < 0)
			return -1;
	}

	return 0;
}
#endif

static int prox_sh_add(struct prox_shared *ps, const char *name, void *data)
{
	char key[256] = {0};
	int ret;

	strncpy(key, name, sizeof(key));
	if (ps->size == 0) {
		prox_sh_create_hash(ps, INIT_HASH_TABLE_SIZE);
	}

#if RTE_VERSION >= RTE_VERSION_NUM(2,1,0,0)
	do {
		ret = rte_hash_add_key_data(ps->hash, key, data);
		if (ret < 0) {
			struct rte_hash *old = ps->hash;
			int success;
			do {
				prox_sh_create_hash(ps, ps->size * 2);
				success = !copy_hash(ps->hash, old);
				if (success)
					rte_hash_free(old);
				else
					rte_hash_free(ps->hash);
			} while (!success);
		}
	} while (ret < 0);
#else
		PROX_PANIC(1, "DPDK < 2.1 not fully supported");
#endif
	return 0;
}

static void *prox_sh_find(struct prox_shared *sh, const char *name)
{
#if RTE_VERSION >= RTE_VERSION_NUM(2,1,0,0)
	char key[256] = {0};
	int ret;
	void *data;

	if (!sh->hash)
		return NULL;

	strncpy(key, name, sizeof(key));
	ret = rte_hash_lookup_data(sh->hash, key, &data);
	if (ret >= 0)
		return data;
#else
		PROX_PANIC(1, "DPDK < 2.1 not fully supported");
#endif
	return NULL;
}

int prox_sh_add_system(const char *name, void *data)
{
	return prox_sh_add(&sh_system, name, data);
}

int prox_sh_add_socket(const int socket_id, const char *name, void *data)
{
	if (socket_id >= MAX_SOCKETS)
		return -1;

	return prox_sh_add(&sh_socket[socket_id], name, data);
}

int prox_sh_add_core(const int core_id, const char *name, void *data)
{
	if (core_id >= RTE_MAX_LCORE)
		return -1;

	return prox_sh_add(&sh_core[core_id], name, data);
}

void *prox_sh_find_system(const char *name)
{
	return prox_sh_find(&sh_system, name);
}

void *prox_sh_find_socket(const int socket_id, const char *name)
{
	if (socket_id >= MAX_SOCKETS)
		return NULL;

	return prox_sh_find(&sh_socket[socket_id], name);
}

void *prox_sh_find_core(const int core_id, const char *name)
{
	if (core_id >= RTE_MAX_LCORE)
		return NULL;

	return prox_sh_find(&sh_core[core_id], name);
}
