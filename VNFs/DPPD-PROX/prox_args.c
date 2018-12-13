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

#include <unistd.h>
#include <string.h>

#include <rte_sched.h>
#include <rte_string_fns.h>
#include <rte_version.h>

#include "prox_malloc.h"
#include "version.h"
#include "defines.h"
#include "prox_args.h"
#include "prox_assert.h"
#include "prox_cfg.h"
#include "cfgfile.h"
#include "quit.h"
#include "log.h"
#include "parse_utils.h"
#include "prox_port_cfg.h"
#include "defaults.h"
#include "prox_lua.h"
#include "cqm.h"
#include "prox_compat.h"

#define MAX_RTE_ARGV 64
#define MAX_ARG_LEN  64

struct cfg_depr {
	const char *opt;
	const char *info;
};

/* Helper macro */
#define STR_EQ(s1, s2)	(!strcmp((s1), (s2)))

/* configuration files support */
static int get_rte_cfg(unsigned sindex, char *str, void *data);
static int get_global_cfg(unsigned sindex, char *str, void *data);
static int get_port_cfg(unsigned sindex, char *str, void *data);
static int get_defaults_cfg(unsigned sindex, char *str, void *data);
static int get_cache_set_cfg(unsigned sindex, char *str, void *data);
static int get_var_cfg(unsigned sindex, char *str, void *data);
static int get_lua_cfg(unsigned sindex, char *str, void *data);
static int get_core_cfg(unsigned sindex, char *str, void *data);

static const char *cfg_file = DEFAULT_CONFIG_FILE;
static struct rte_cfg    rte_cfg;
struct prox_cache_set_cfg  prox_cache_set_cfg[PROX_MAX_CACHE_SET];

static char format_err_str[1024];
static const char *err_str = "Unknown error";

static struct cfg_section eal_default_cfg = {
	.name   = "eal options",
	.parser = get_rte_cfg,
	.data   = &rte_cfg,
	.indexp[0]  = 0,
	.nbindex = 1,
	.error  = 0
};

static struct cfg_section port_cfg = {
	.name   = "port #",
	.parser = get_port_cfg,
	.data   = &prox_port_cfg,
	.indexp[0]  = 0,
	.nbindex = 1,
	.error  = 0
};

static struct cfg_section var_cfg = {
	.name   = "variables",
	.parser = get_var_cfg,
	.data   = 0,
	.indexp[0]  = 0,
	.nbindex = 1,
	.error  = 0
};

static struct cfg_section cache_set_cfg = {
	.name   = "cache set #",
	.parser = get_cache_set_cfg,
	.data   = &prox_cache_set_cfg,
	.indexp[0]  = 0,
	.nbindex = 1,
	.error  = 0
};

static struct cfg_section defaults_cfg = {
	.name   = "defaults",
	.parser = get_defaults_cfg,
	.data   = 0,
	.indexp[0]  = 0,
	.nbindex = 1,
	.error  = 0
};

static struct cfg_section settings_cfg = {
	.name   = "global",
	.parser = get_global_cfg,
	.data   = &prox_cfg,
	.indexp[0]  = 0,
	.nbindex = 1,
	.error  = 0
};

static struct cfg_section lua_cfg = {
	.name = "lua",
	.parser = get_lua_cfg,
	.raw_lines = 1,
	.indexp[0] = 0,
	.nbindex = 1,
	.error = 0,
};

static struct cfg_section core_cfg = {
	.name   = "core #",
	.parser = get_core_cfg,
	.data   = lcore_cfg_init,
	.indexp[0]  = 0,
	.nbindex = 1,
	.error  = 0
};

static void set_errf(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vsnprintf(format_err_str, sizeof(format_err_str), format, ap);
	va_end(ap);
	err_str = format_err_str;
}

/* [eal options] parser */
static int get_rte_cfg(__attribute__((unused))unsigned sindex, char *str, void *data)
{
	struct rte_cfg *pconfig = (struct rte_cfg *)data;

	if (str == NULL || pconfig == NULL) {
		return -1;
	}

	char *pkey = get_cfg_key(str);
	if (pkey == NULL) {
		set_errf("Missing key after option");
		return -1;
	}

	if (STR_EQ(str, "-m")) {
		return parse_int(&pconfig->memory, pkey);
	}
	if (STR_EQ(str, "-n")) {
		if (parse_int(&pconfig->force_nchannel, pkey)) {
			return -1;
		}
		if (pconfig->force_nchannel == 0) {
			set_errf("Invalid number of memory channels");
			return -1;
		}
		return 0;
	}
	if (STR_EQ(str, "-r")) {
		if (parse_int(&pconfig->force_nrank, pkey)) {
			return -1;
		}
		if (pconfig->force_nrank == 0 || pconfig->force_nrank > 16) {
			set_errf("Invalid number of memory ranks");
			return -1;
		}
		return 0;
	}
	/* debug options */
	if (STR_EQ(str, "no-pci")) {
		return parse_bool(&pconfig->no_pci, pkey);
	}
	if (STR_EQ(str, "no-hpet")) {
		return parse_bool(&pconfig->no_hpet, pkey);
	}
	if (STR_EQ(str, "no-shconf")) {
		return parse_bool(&pconfig->no_shconf, pkey);
	}
	if (STR_EQ(str, "no-huge")) {
		return parse_bool(&pconfig->no_hugetlbfs, pkey);
	}
	if (STR_EQ(str, "no-output")) {
		return parse_bool(&pconfig->no_output, pkey);
	}

	if (STR_EQ(str, "huge-dir")) {
		if (pconfig->hugedir) {
			free(pconfig->hugedir);
		}
		pconfig->hugedir = strdup(pkey);
		return 0;
	}

	if (STR_EQ(str, "eal")) {
		char eal[MAX_STR_LEN_PROC];
		if (pconfig->eal) {
			free(pconfig->eal);
			pconfig->eal = NULL;
		}
		if (parse_str(eal, pkey, sizeof(eal)))
			return -1;
		pkey = eal;
		strip_spaces(&pkey, 1);
		if (*pkey)
			pconfig->eal = strdup(pkey);
		return 0;
	}

	set_errf("Option '%s' is not known", str);
	return -1;
}

struct cfg_depr global_cfg_depr[] = {
	{"virtualization", "This is now set automatically if needed"},
	{"qinq_tag", "This option is deprecated"},
	{"wait on quit", "This is now set automatically if needed"},
	{"version", ""}
};

const char *get_cfg_dir(void)
{
	static char dir[PATH_MAX];
	size_t end = strlen(cfg_file) - 1;
	while (end > 0 && cfg_file[end] != '/')
		end--;

	strncpy(dir, cfg_file, end);
	return dir;
}

static int get_lua_cfg(__attribute__((unused)) unsigned sindex, __attribute__((unused)) char *str, __attribute__((unused)) void *data)
{
	int status;
	char cwd[1024];
	if (NULL == getcwd(cwd, sizeof(cwd))) {
		set_errf("Failed to get current directory while loading Lua file\n");
		return -1;
	}
	status = chdir(get_cfg_dir());
	if (status) {
		set_errf("Failed to change directory to '%s' while loading Lua file\n", get_cfg_dir());
		return -1;
	}

	struct lua_State *l = prox_lua();

	char str_cpy[1024];
	strncpy(str_cpy, str, sizeof(str_cpy));
	uint32_t len = strlen(str_cpy);
	str_cpy[len++] = '\n';
	str_cpy[len++] = 0;

	status = luaL_loadstring(l, str_cpy);
	if (status) {
		set_errf("Lua error: '%s'\n", lua_tostring(l, -1));
		status = chdir(cwd);
		return -1;
	}

	status = lua_pcall(l, 0, LUA_MULTRET, 0);
	if (status) {
		set_errf("Lua error: '%s'\n", lua_tostring(l, -1));
		status = chdir(cwd);
		return -1;
	}

	status = chdir(cwd);
	if (status) {
		set_errf("Failed to restore current directory to '%s' while loading Lua file\n", cwd);
		return -1;
	}

	return 0;
}

/* [global] parser */
static int get_global_cfg(__attribute__((unused))unsigned sindex, char *str, void *data)
{
	struct prox_cfg *pset = (struct prox_cfg *)data;

	if (str == NULL || pset == NULL) {
		return -1;
	}

	char *pkey = get_cfg_key(str);
	if (pkey == NULL) {
		set_errf("Missing key after option");
		return -1;
	}

	for (uint32_t i = 0; i < RTE_DIM(global_cfg_depr); ++i) {
		if (STR_EQ(str, global_cfg_depr[i].opt)) {
			set_errf("Option '%s' is deprecated%s%s",
				 global_cfg_depr[i].opt, strlen(global_cfg_depr[i].info)? ": ": "", global_cfg_depr[i].info);
			return -1;
		}
	}

	if (STR_EQ(str, "name")) {
		return parse_str(pset->name, pkey, sizeof(pset->name));
	}

	if (STR_EQ(str, "start time")) {
		return parse_int(&pset->start_time, pkey);
	}

	if (STR_EQ(str, "duration time")) {
		return parse_int(&pset->duration_time, pkey);
	}

	if (STR_EQ(str, "shuffle")) {
		return parse_flag(&pset->flags, DSF_SHUFFLE, pkey);
	}
	if (STR_EQ(str, "disable cmt")) {
		return parse_flag(&pset->flags, DSF_DISABLE_CMT, pkey);
	}
	if (STR_EQ(str, "mp rings")) {
		return parse_flag(&pset->flags, DSF_MP_RINGS, pkey);
	}
	if (STR_EQ(str, "enable bypass")) {
		return parse_flag(&pset->flags, DSF_ENABLE_BYPASS, pkey);
	}

	if (STR_EQ(str, "cpe table map")) {
		/* The config defined ports through 0, 1, 2 ... which
		   need to be associated with ports. This is done
		   through defining it using "cpe table map=" */
		return parse_port_name_list((uint32_t*)pset->cpe_table_ports, NULL, PROX_MAX_PORTS, pkey);
	}

	if (STR_EQ(str, "pre cmd")) {
		return system(pkey);
	}

	if (STR_EQ(str, "unique mempool per socket")) {
		return parse_flag(&pset->flags, UNIQUE_MEMPOOL_PER_SOCKET, pkey);
	}

	if (STR_EQ(str, "log buffer size")) {
		if (parse_kmg(&pset->logbuf_size, pkey)) {
			return -1;
		}
		plog_info("Logging to buffer with size = %d\n", pset->logbuf_size);
		return 0;
	}

	set_errf("Option '%s' is not known", str);
	return -1;
}

/* [variable] parser */
static int get_var_cfg(__attribute__((unused)) unsigned sindex, char *str, __attribute__((unused)) void *data)
{
	return add_var(str, get_cfg_key(str), 0);
}

/* [defaults] parser */
static int get_defaults_cfg(__attribute__((unused)) unsigned sindex, char *str, __attribute__((unused)) void *data)
{
	uint32_t val;
	char *pkey;

	pkey = get_cfg_key(str);
	if (pkey == NULL) {
		set_errf("Missing key after option");
		return -1;
	}

	if (STR_EQ(str, "mempool size")) {

		if (parse_kmg(&val, pkey)) {
			return -1;
		}

		for (uint8_t lcore_id = 0; lcore_id < RTE_MAX_LCORE; ++lcore_id) {
			struct lcore_cfg *cur_lcore_cfg_init = &lcore_cfg_init[lcore_id];
			cur_lcore_cfg_init->id = lcore_id;
			for (uint8_t task_id = 0; task_id < MAX_TASKS_PER_CORE; ++task_id) {
				struct task_args *targ = &cur_lcore_cfg_init->targs[task_id];
				targ->nb_mbuf = val;
				targ->id = task_id;
			}
		}
		return 0;
	}

	if (STR_EQ(str, "qinq tag")) {
		for (uint8_t lcore_id = 0; lcore_id < RTE_MAX_LCORE; ++lcore_id) {
			struct lcore_cfg *cur_lcore_cfg_init = &lcore_cfg_init[lcore_id];
			cur_lcore_cfg_init->id = lcore_id;
			for (uint8_t task_id = 0; task_id < MAX_TASKS_PER_CORE; ++task_id) {
				struct task_args *targ = &cur_lcore_cfg_init->targs[task_id];
				parse_int(&targ->qinq_tag, pkey);
			}
		}
		return 0;
	}
	if (STR_EQ(str, "memcache size")) {

		if (parse_kmg(&val, pkey)) {
			return -1;
		}

		for (uint8_t lcore_id = 0; lcore_id < RTE_MAX_LCORE; ++lcore_id) {
			struct lcore_cfg *cur_lcore_cfg_init = &lcore_cfg_init[lcore_id];
			cur_lcore_cfg_init->id = lcore_id;
			for (uint8_t task_id = 0; task_id < MAX_TASKS_PER_CORE; ++task_id) {
				struct task_args *targ = &cur_lcore_cfg_init->targs[task_id];
				targ->nb_cache_mbuf = val;
			}
		}
		return 0;
	}

	set_errf("Option '%s' is not known", str);
	return -1;
}

/* [cache set] parser */
static int get_cache_set_cfg(unsigned sindex, char *str, void *data)
{
	struct prox_cache_set_cfg *cfg = (struct prox_cache_set_cfg *)data;

	uint8_t cur_if = sindex & ~CFG_INDEXED;

	if (cur_if >= PROX_MAX_CACHE_SET) {
		set_errf("Cache set ID is too high (max allowed %d)", PROX_MAX_CACHE_SET - 1 );
		return -1;
	}

	cfg = &prox_cache_set_cfg[cur_if];

	if (str == NULL || data == NULL) {
		return -1;
	}

	char *pkey = get_cfg_key(str);

	if (pkey == NULL) {
		set_errf("Missing key after option");
		return -1;
	}

	if (STR_EQ(str, "mask")) {
                uint32_t val;
                int err = parse_int(&val, pkey);
                if (err) {
                        return -1;
                }
                cfg->mask = val;
                cfg->socket_id = -1;
		plog_info("\tCache set %d has mask %x\n", cur_if, cfg->mask);
                return 0;
	}
        return 0;
}

/* [port] parser */
static int get_port_cfg(unsigned sindex, char *str, void *data)
{
	struct prox_port_cfg *cfg = (struct prox_port_cfg *)data;

	uint8_t cur_if = sindex & ~CFG_INDEXED;

	if (cur_if >= PROX_MAX_PORTS) {
		set_errf("Port ID is too high (max allowed %d)", PROX_MAX_PORTS - 1 );
		return -1;
	}

	cfg = &prox_port_cfg[cur_if];

	if (str == NULL || data == NULL) {
		return -1;
	}

	char *pkey = get_cfg_key(str);

	if (pkey == NULL) {
		set_errf("Missing key after option");
		return -1;
	}

	if (STR_EQ(str, "mac")) {
		if (STR_EQ(pkey, "hardware")) {
			cfg->type = PROX_PORT_MAC_HW;
		}
		else if (STR_EQ(pkey, "random")) {
			cfg->type = PROX_PORT_MAC_RAND;
		}
		else {
			cfg->type = PROX_PORT_MAC_SET;
			if (parse_mac(&cfg->eth_addr, pkey)) {
				return -1;
			}
		}
	}
	else if (STR_EQ(str, "name")) {
		uint32_t val;
		strncpy(cfg->name, pkey, MAX_NAME_SIZE);
		PROX_ASSERT(cur_if < PROX_MAX_PORTS);
		return add_port_name(cur_if, pkey);
	}
	else if (STR_EQ(str, "rx desc")) {
		return parse_int(&cfg->n_rxd, pkey);
	}
	else if (STR_EQ(str, "tx desc")) {
		return parse_int(&cfg->n_txd, pkey);
	}
	else if (STR_EQ(str, "promiscuous")) {
		uint32_t val;
		if (parse_bool(&val, pkey)) {
			return -1;
		}
		cfg->promiscuous = val;
	}
	else if (STR_EQ(str, "lsc")) {
		cfg->lsc_set_explicitely = 1;
		uint32_t val;
		if (parse_bool(&val, pkey)) {
			return -1;
		}
		cfg->lsc_val = val;
	}
#if RTE_VERSION >= RTE_VERSION_NUM(18,8,0,1)
	else if (STR_EQ(str, "disable tx offload")) {
		uint32_t val;
		if (parse_int(&val, pkey)) {
			return -1;
		}
		if (val)
			cfg->disabled_tx_offload = val;
	}
#endif
	else if (STR_EQ(str, "strip crc")) {
		uint32_t val;
		if (parse_bool(&val, pkey)) {
			return -1;
		}
		if (val)
			cfg->requested_rx_offload |= DEV_RX_OFFLOAD_CRC_STRIP;
		else
			cfg->requested_rx_offload &= ~DEV_RX_OFFLOAD_CRC_STRIP;
	}
	else if (STR_EQ(str, "vlan")) {
#if RTE_VERSION >= RTE_VERSION_NUM(18,8,0,1)
		uint32_t val;
		if (parse_bool(&val, pkey)) {
			return -1;
		}
		if (val) {
			cfg->requested_rx_offload |= DEV_RX_OFFLOAD_VLAN_STRIP;
			cfg->requested_tx_offload |= DEV_TX_OFFLOAD_VLAN_INSERT;
		} else {
			cfg->requested_rx_offload &= ~DEV_RX_OFFLOAD_VLAN_STRIP;
			cfg->requested_tx_offload &= ~DEV_TX_OFFLOAD_VLAN_INSERT;
		}
#else
		plog_warn("vlan option not supported : update DPDK at least to 18.08 to support this option\n");
#endif
	}
	else if (STR_EQ(str, "mtu size")) {
		uint32_t val;
		if (parse_int(&val, pkey)) {
			return -1;
		}
		if (val) {
			cfg->mtu = val;
			// A frame of 1526 bytes (1500 bytes mtu, 14 bytes hdr, 4 bytes crc and 8 bytes vlan)
			// should not be considered as a jumbo frame. However rte_ethdev.c considers that
			// the max_rx_pkt_len for a non jumbo frame is 1518
			cfg->port_conf.rxmode.max_rx_pkt_len = cfg->mtu + ETHER_HDR_LEN + ETHER_CRC_LEN;
			if (cfg->port_conf.rxmode.max_rx_pkt_len > ETHER_MAX_LEN) {
				cfg->requested_rx_offload |= DEV_RX_OFFLOAD_JUMBO_FRAME;
			}
		}
	}

	else if (STR_EQ(str, "rss")) {
		uint32_t val;
		if (parse_bool(&val, pkey)) {
			return -1;
		}
		if (val) {
			cfg->port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
			cfg->port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IPV4;
		}
	}
	else if (STR_EQ(str, "rx_ring")) {
		parse_str(cfg->rx_ring, pkey, sizeof(cfg->rx_ring));
	}
	else if (STR_EQ(str, "tx_ring")) {
		parse_str(cfg->tx_ring, pkey, sizeof(cfg->tx_ring));
	}

	return 0;
}

static enum police_action str_to_color(const char *str)
{
	if (STR_EQ(str, "green"))
		return ACT_GREEN;
	if (STR_EQ(str, "yellow"))
		return ACT_YELLOW;
	if (STR_EQ(str, "red"))
		return ACT_RED;
	if (STR_EQ(str, "drop"))
		return ACT_DROP;
	return ACT_INVALID;
}

struct cfg_depr task_cfg_depr[] = {
	{"sig", ""},
};

struct cfg_depr core_cfg_depr[] = {
	{"do sig", ""},
	{"lat", ""},
	{"network side", ""},
};

/* [core] parser */
static int get_core_cfg(unsigned sindex, char *str, void *data)
{
	char *pkey;
	struct lcore_cfg *lconf = (struct lcore_cfg *)data;

	if (str == NULL || lconf == NULL || !(sindex & CFG_INDEXED)) {
		return -1;
	}

	pkey = get_cfg_key(str);
	if (pkey == NULL) {
		set_errf("Missing key after option");
		return -1;
	}

	uint32_t ncore = sindex & ~CFG_INDEXED;
	if (ncore >= RTE_MAX_LCORE) {
		set_errf("Core index too high (max allowed %d)", RTE_MAX_LCORE - 1);
		return -1;
	}

	lconf = &lconf[ncore];

	for (uint32_t i = 0; i < RTE_DIM(core_cfg_depr); ++i) {
		if (STR_EQ(str, core_cfg_depr[i].opt)) {
			set_errf("Option '%s' is deprecated%s%s",
				 core_cfg_depr[i].opt, strlen(core_cfg_depr[i].info)? ": ": "", core_cfg_depr[i].info);
			return -1;
		}
	}

	char buff[128];
	lcore_to_socket_core_ht(ncore, buff, sizeof(buff));
	set_self_var(buff);
	if (STR_EQ(str, "task")) {

		uint32_t val;
		if (parse_int(&val, pkey)) {
			return -1;
		}
		if (val >= MAX_TASKS_PER_CORE) {
			set_errf("Too many tasks for core (max allowed %d)", MAX_TASKS_PER_CORE - 1);
			return -1;
		}
		if (val != lconf->n_tasks_all) {
			set_errf("Task ID skipped or defined twice");
			return -1;
		}

		lconf->active_task = val;

		lconf->targs[lconf->active_task].task = lconf->active_task;

		if (lconf->n_tasks_all < lconf->active_task + 1) {
			lconf->n_tasks_all = lconf->active_task + 1;
		}
		return 0;
	}

	struct task_args *targ = &lconf->targs[lconf->active_task];
	if (STR_EQ(str, "tx ports from routing table")) {
		uint32_t vals[PROX_MAX_PORTS];
		uint32_t n_if;
		if (!(targ->task_init->flag_features & TASK_FEATURE_ROUTING)) {
			set_errf("tx port form route not supported mode %s",  targ->task_init->mode_str);
			return -1;
		}

		if (parse_port_name_list(vals, &n_if, PROX_MAX_PORTS, pkey)) {
			return -1;
		}

		for (uint8_t i = 0; i < n_if; ++i) {
			targ->tx_port_queue[i].port = vals[i];
			targ->nb_txports++;
		}
		targ->runtime_flags |= TASK_ROUTING;
		return 0;
	}
	if (STR_EQ(str, "tx ports from cpe table")) {
		uint32_t vals[PROX_MAX_PORTS];
		int n_remap = -1;
		uint32_t ret;
		uint32_t val;
		char* mapping_str = strstr(pkey, " remap=");

		if (mapping_str != NULL) {
			*mapping_str = 0;
			mapping_str += strlen(" remap=");
			n_remap = parse_remap(targ->mapping, mapping_str);
		}

		if (parse_port_name_list(vals, &ret, PROX_MAX_PORTS, pkey)) {
			return -1;
		}

		if (n_remap != -1 && ret != (uint32_t)n_remap) {
			set_errf("Expected %d remap elements but had %d", n_remap, ret);
			return -1;
		}

		for (uint8_t i = 0; i < ret; ++i) {
			targ->tx_port_queue[i].port = vals[i];

			/* default mapping this case is port0 -> port0 */
			if (n_remap == -1) {
				targ->mapping[vals[i]] = i;
			}
		}

		targ->nb_txports = ret;

		return 0;
	}
	if (STR_EQ(str, "tx cores from routing table")) {
		if (!(targ->task_init->flag_features & TASK_FEATURE_ROUTING)) {
			set_errf("tx port form route not supported mode %s",  targ->task_init->mode_str);
			return -1;
		}

		struct core_task_set *cts = &targ->core_task_set[0];

		if (parse_task_set(cts, pkey))
			return -1;

		if (cts->n_elems > MAX_WT_PER_LB) {
			set_errf("Maximum worker threads allowed is %u but have %u", MAX_WT_PER_LB, cts->n_elems);
			return -1;
		}

		targ->nb_worker_threads = cts->n_elems;
		targ->nb_txrings = cts->n_elems;

		if (targ->nb_txrings > MAX_RINGS_PER_TASK) {
			set_errf("Maximum allowed TX rings is %u but have %u", MAX_RINGS_PER_TASK, targ->nb_txrings);
			return -1;
		}

		targ->runtime_flags |= TASK_ROUTING;
		return 0;
	}
	if (STR_EQ(str, "tx cores from cpe table")) {
		struct core_task_set *core_task_set =  &targ->core_task_set[0];
		int ret, ret2;
		char *mapping_str;

		mapping_str = strstr(pkey, " remap=");
		if (mapping_str == NULL) {
			set_errf("There is no default mapping for tx cores from cpe table. Please specify it through remap=");
			return -1;
		}
		*mapping_str = 0;
		mapping_str += strlen(" remap=");
		ret = parse_remap(targ->mapping, mapping_str);
		if (ret <= 0) {
			return -1;
		}

		struct core_task_set *cts = &targ->core_task_set[0];

		if (parse_task_set(cts, pkey))
			return -1;
		if (cts->n_elems > MAX_RINGS_PER_TASK) {
			set_errf("Maximum cores to route to is %u\n", MAX_RINGS_PER_TASK);
			return -1;
		}

		targ->nb_txrings = cts->n_elems;

		if (ret != targ->nb_txrings) {
			set_errf("Expecting same number of remaps as cores\n", str);
			return -1;
		}
		return 0;
	}

	if (STR_EQ(str, "delay ms")) {
		if (targ->delay_us) {
			set_errf("delay ms and delay us are mutually exclusive\n", str);
			return -1;
		}
		uint32_t delay_ms;
		int rc = parse_int(&delay_ms, pkey);
		targ->delay_us = delay_ms * 1000;
		return rc;
	}
	if (STR_EQ(str, "delay us")) {
		if (targ->delay_us) {
			set_errf("delay ms and delay us are mutually exclusive\n", str);
			return -1;
		}
		return parse_int(&targ->delay_us, pkey);
	}
	if (STR_EQ(str, "random delay us")) {
		return parse_int(&targ->random_delay_us, pkey);
	}
	if (STR_EQ(str, "cpe table timeout ms")) {
		return parse_int(&targ->cpe_table_timeout_ms, pkey);
	}
	if (STR_EQ(str, "ctrl path polling frequency")) {
		int rc = parse_int(&targ->ctrl_freq, pkey);
		if (rc == 0) {
			if (targ->ctrl_freq == 0) {
				set_errf("ctrl frequency must be non null.");
				return -1;
			}
		}
		return rc;
	}

	if (STR_EQ(str, "handle arp")) {
		return parse_flag(&targ->runtime_flags, TASK_CTRL_HANDLE_ARP, pkey);
	}
	if (STR_EQ(str, "fast path handle arp")) {
		return parse_flag(&targ->runtime_flags, TASK_FP_HANDLE_ARP, pkey);
	}
	if (STR_EQ(str, "multiple arp")) {
		return parse_flag(&targ->flags, TASK_MULTIPLE_MAC, pkey);
	}

	/* Using tx port name, only a _single_ port can be assigned to a task. */
	if (STR_EQ(str, "tx port")) {
		if (targ->nb_txports > 0) {
			set_errf("Only one tx port can be defined per task. Use a LB task or routing instead.");
			return -1;
		}

		uint32_t n_if = 0;
		uint32_t ports[PROX_MAX_PORTS];

		if(parse_port_name_list(ports, &n_if, PROX_MAX_PORTS, pkey)) {
			return -1;
		}

		PROX_ASSERT(n_if-1 < PROX_MAX_PORTS);

                for (uint8_t i = 0; i < n_if; ++i) {
                        targ->tx_port_queue[i].port = ports[i];
                        targ->nb_txports++;
                }

		if (n_if > 1) {
			targ->nb_worker_threads = targ->nb_txports;
		}

		return 0;
	}
	if (STR_EQ(str, "rx ring")) {
		uint32_t val;
		int err = parse_bool(&val, pkey);
		if (!err && val && targ->rx_port_queue[0].port != OUT_DISCARD) {
			set_errf("Can't read both from internal ring and external port from the same task. Use multiple tasks instead.");
			return -1;
		}

		return parse_flag(&targ->flags, TASK_ARG_RX_RING, pkey);
	}
	if (STR_EQ(str, "private")) {
		return parse_bool(&targ->use_src, pkey);
	}
	if (STR_EQ(str, "use src ip")) {
		return parse_bool(&targ->use_src, pkey);
	}
	if (STR_EQ(str, "nat table")) {
		return parse_str(targ->nat_table, pkey, sizeof(targ->nat_table));
	}
	if (STR_EQ(str, "rules")) {
		return parse_str(targ->rules, pkey, sizeof(targ->rules));
	}
	if (STR_EQ(str, "route table")) {
		return parse_str(targ->route_table, pkey, sizeof(targ->route_table));
	}
	if (STR_EQ(str, "dscp")) {
		return parse_str(targ->dscp, pkey, sizeof(targ->dscp));
	}
	if (STR_EQ(str, "tun_bindings")) {
		return parse_str(targ->tun_bindings, pkey, sizeof(targ->tun_bindings));
	}
	if (STR_EQ(str, "cpe table")) {
		return parse_str(targ->cpe_table_name, pkey, sizeof(targ->cpe_table_name));
	}
	if (STR_EQ(str, "user table")) {
		return parse_str(targ->user_table, pkey, sizeof(targ->user_table));
	}
	if (STR_EQ(str, "streams")) {
		return parse_str(targ->streams, pkey, sizeof(targ->streams));
	}
	if (STR_EQ(str, "local lpm")) {
		return parse_flag(&targ->flags, TASK_ARG_LOCAL_LPM, pkey);
	}
	if (STR_EQ(str, "drop")) {
		return parse_flag(&targ->flags, TASK_ARG_DROP, pkey);
	}
	if (STR_EQ(str, "loop")) {
		parse_flag(&targ->loop, 1, pkey);
		return parse_flag(&targ->loop, 1, pkey);
	}
	if (STR_EQ(str, "qinq")) {
		return parse_flag(&targ->flags, TASK_ARG_QINQ_ACL, pkey);
	}
	if (STR_EQ(str, "bps")) {
		return parse_u64(&targ->rate_bps, pkey);
	}
	if (STR_EQ(str, "random")) {
		return parse_str(targ->rand_str[targ->n_rand_str++], pkey, sizeof(targ->rand_str[0]));
	}
	if (STR_EQ(str, "rand_offset")) {
		if (targ->n_rand_str == 0) {
			set_errf("No random defined previously (use random=...)");
			return -1;
		}

		return parse_int(&targ->rand_offset[targ->n_rand_str - 1], pkey);
	}
	if (STR_EQ(str, "keep src mac")) {
		return parse_flag(&targ->flags, DSF_KEEP_SRC_MAC, pkey);
	}
	if (STR_EQ(str, "pcap file")) {
		return parse_str(targ->pcap_file, pkey, sizeof(targ->pcap_file));
	}
	if (STR_EQ(str, "pkt inline")) {
		char pkey2[MAX_CFG_STRING_LEN];
		if (parse_str(pkey2, pkey, sizeof(pkey2)) != 0) {
			set_errf("Error while parsing pkt line, too long\n");
			return -1;
		}

		const size_t pkey_len = strlen(pkey2);
		targ->pkt_size = 0;

		for (size_t i = 0; i < pkey_len; ++i) {
			if (pkey2[i] == ' ')
				continue;

			if (i + 1 == pkey_len) {
				set_errf("Incomplete byte at character %z", i);
				return -1;
			}

			uint8_t byte = 0;

			if (pkey2[i] >= '0' && pkey2[i] <= '9') {
				byte = (pkey2[i] - '0') << 4;
			}
			else if (pkey2[i] >= 'a' && pkey2[i] <= 'f') {
				byte = (pkey2[i] - 'a' + 10) << 4;
			}
			else if (pkey2[i] >= 'A' && pkey2[i] <= 'F') {
				byte = (pkey2[i] - 'A' + 10) << 4;
			}
			else {
				set_errf("Invalid character in pkt inline at byte %d (%c)", i, pkey2[i]);
				return -1;
			}

			if (pkey2[i + 1] >= '0' && pkey2[i + 1] <= '9') {
				byte |= (pkey2[i + 1] - '0');
			}
			else if (pkey2[i + 1] >= 'a' && pkey2[i + 1] <= 'f') {
				byte |= (pkey2[i + 1] - 'a' + 10);
			}
			else if (pkey2[i + 1] >= 'A' && pkey2[i + 1] <= 'F') {
				byte |= (pkey2[i + 1] - 'A' + 10);
			}
			else {
				set_errf("Invalid character in pkt inline at byte %d (%c)", i, pkey2[i + 1]);
				return -1;
			}
			if (targ->pkt_size == sizeof(targ->pkt_inline)) {
				set_errf("Inline packet definition can't be longer than %u", sizeof(targ->pkt_inline));
				return -1;
			}

			targ->pkt_inline[targ->pkt_size++] = byte;
			i += 1;
		}

		return 0;
	}
	if (STR_EQ(str, "accuracy limit nsec")) {
		return parse_int(&targ->accuracy_limit_nsec, pkey);
	}
	if (STR_EQ(str, "latency bucket size")) {
		return parse_int(&targ->bucket_size, pkey);
	}
	if (STR_EQ(str, "latency buffer size")) {
		return parse_int(&targ->latency_buffer_size, pkey);
	}
	if (STR_EQ(str, "accuracy pos")) {
		return parse_int(&targ->accur_pos, pkey);
	}
	if (STR_EQ(str, "signature")) {
		return parse_int(&targ->sig, pkey);
	}
	if (STR_EQ(str, "signature pos")) {
		return parse_int(&targ->sig_pos, pkey);
	}
	if (STR_EQ(str, "lat pos")) {
		targ->lat_enabled = 1;
		return parse_int(&targ->lat_pos, pkey);
	}
	if (STR_EQ(str, "packet id pos")) {
		return parse_int(&targ->packet_id_pos, pkey);
	}
	if (STR_EQ(str, "probability")) {
		float probability;
		int rc = parse_float(&probability, pkey);
		if (probability == 0) {
			set_errf("Probability must be != 0\n");
			return -1;
		} else if (probability > 100.0) {
			set_errf("Probability must be < 100\n");
			return -1;
		}
		targ->probability = probability * 10000;
		return rc;
	}
	if (STR_EQ(str, "concur conn")) {
		return parse_int(&targ->n_concur_conn, pkey);
	}
	if (STR_EQ(str, "max setup rate")) {
		return parse_int(&targ->max_setup_rate, pkey);
	}
	if (STR_EQ(str, "pkt size")) {
		return parse_int(&targ->pkt_size, pkey);
	}
	if (STR_EQ(str, "min bulk size")) {
		return parse_int(&targ->min_bulk_size, pkey);
	}
	if (STR_EQ(str, "max bulk size")) {
		return parse_int(&targ->max_bulk_size, pkey);
	}
	if (STR_EQ(str, "rx port")) {
		if (targ->flags & TASK_ARG_RX_RING) {
			set_errf("Can't read both from internal ring and external port from the same task. Use multiple tasks instead.");
			return -1;
		}
		uint32_t vals[PROX_MAX_PORTS];
		uint32_t n_if;

                if (parse_port_name_list(vals, &n_if, PROX_MAX_PORTS, pkey)) {
                        return -1;
                }

                for (uint8_t i = 0; i < n_if; ++i) {
			PROX_ASSERT(vals[i] < PROX_MAX_PORTS);
                        targ->rx_port_queue[i].port = vals[i];
                        targ->nb_rxports++;
                }
		return 0;
	}

	if (STR_EQ(str, "mode")) {
		/* Check deprecated task modes */
		char mode[255];
		int ret = parse_str(mode, pkey, sizeof(mode));
		if (ret)
			return ret;

		for (uint32_t i = 0; i < RTE_DIM(task_cfg_depr); ++i) {
			if (STR_EQ(mode, task_cfg_depr[i].opt)) {
				set_errf("Task mode '%s' is deprecated%s%s",
					 task_cfg_depr[i].opt, strlen(task_cfg_depr[i].info)? ": ": "", task_cfg_depr[i].info);
				return -1;
			}
		}

		/* master is a special mode that is always needed (cannot be turned off) */
		if (STR_EQ(mode, "master")) {
			prox_cfg.master = ncore;
			targ->mode = MASTER;
			if (lconf->n_tasks_all > 1 || targ->task != 0) {
				set_errf("Master core can only have one task\n");
				return -1;
			}
			// Initialize number of tasks to 1 for master, even if no task specified
			lconf->n_tasks_all = 1;
			lconf->active_task = 0;
			lconf->targs[lconf->active_task].task = 0;
			struct task_init* task_init = to_task_init(mode, "");
			if (task_init) {
				targ->mode = task_init->mode;
			}
			targ->task_init = task_init;
			return 0;
		}

		struct task_init* task_init = to_task_init(mode, "");
		if (task_init) {
			targ->mode = task_init->mode;
		}
		else {
			set_errf("Task mode '%s' is invalid", mode);
			tasks_list();
			return -1;
		}
		targ->task_init = task_init;
		return 0;
	}
	if (STR_EQ(str, "users")) {
		return parse_int(&targ->n_flows, pkey);
	}

	if (STR_EQ(str, "mark")) {
		return parse_flag(&targ->runtime_flags, TASK_MARK, pkey);
	}

	if (STR_EQ(str, "mark green")) {
		return parse_int(&targ->marking[0], pkey);
	}

	if (STR_EQ(str, "mark yellow")) {
		return parse_int(&targ->marking[1], pkey);
	}

	if (STR_EQ(str, "mark red")) {
		return parse_int(&targ->marking[2], pkey);
	}

	if (STR_EQ(str, "tx cores")) {
		uint8_t dest_task = 0;
		/* if user did not specify, dest_port is left at default (first type) */
		uint8_t dest_proto = 0;
		uint8_t ctrl = CTRL_TYPE_DP;
		char *task_str = strstr(pkey, "proto=");
		if (task_str) {
			task_str += strlen("proto=");

			if (STR_EQ(task_str, "ipv4")) {
				dest_proto = IPV4;
			}
			else if (STR_EQ(task_str, "arp")) {
				dest_proto = ARP;
			}
			else if (STR_EQ(task_str, "ipv6")) {
				dest_proto = IPV6;
			}
			else {
				set_errf("proto needs to be either ipv4, arp or ipv6");
				return -1;
			}

		}

		task_str = strstr(pkey, "task=");

		if (task_str) {
			--task_str;
			*task_str = 0;
			task_str++;
			task_str += strlen("task=");
			char *task_str_end = strstr(task_str, " ");
			if (task_str_end) {
				*task_str_end = 0;
			}
			if (0 == strlen(task_str)) {
				set_errf("Invalid task= syntax");
				return -1;
			}

			switch (task_str[strlen(task_str) - 1]) {
			case 'p':
				ctrl = CTRL_TYPE_PKT;
				break;
			case 'm':
				ctrl = CTRL_TYPE_MSG;
				break;
			case '\n':
			case 0:
				break;
			default:
				if (task_str[strlen(task_str) -1] < '0' ||
				    task_str[strlen(task_str) -1] > '9') {
					set_errf("Unknown ring type %c.\n",
						 task_str[strlen(task_str) - 1]);
					return -1;
				}
			}

			dest_task = atoi(task_str);
			if (dest_task >= MAX_TASKS_PER_CORE) {
				set_errf("Destination task too high (max allowed %d)", MAX_TASKS_PER_CORE - 1);
				return -1;
			}
		}
		else {
			dest_task = 0;
		}

		struct core_task_set *cts = &targ->core_task_set[dest_proto];

		if (parse_task_set(cts, pkey))
			return -1;

		if (cts->n_elems > MAX_WT_PER_LB) {
			set_errf("Too many worker threads (max allowed %d)", MAX_WT_PER_LB - 1);
			return -1;
		}

		targ->nb_worker_threads = cts->n_elems;
		targ->nb_txrings += cts->n_elems;

		return 0;
	}
	if (STR_EQ(str, "tx crc")) {
		return parse_flag(&targ->runtime_flags, TASK_TX_CRC, pkey);
	}
	if (STR_EQ(str, "ring size")) {
		return parse_int(&targ->ring_size, pkey);
	}
	if (STR_EQ(str, "mempool size")) {
		return parse_kmg(&targ->nb_mbuf, pkey);
	}

	else if (STR_EQ(str, "mbuf size")) {
		return parse_int(&targ->mbuf_size, pkey);
	}
	if (STR_EQ(str, "memcache size")) {
		return parse_kmg(&targ->nb_cache_mbuf, pkey);
	}

	if (STR_EQ(str, "byte offset")) {
		return parse_int(&targ->byte_offset, pkey);
	}

	if (STR_EQ(str, "name")) {
		return parse_str(lconf->name, pkey, sizeof(lconf->name));
	}
	/* MPLS configuration */
	if (STR_EQ(str, "untag mpls")) {
		return parse_flag(&targ->runtime_flags, TASK_MPLS_TAGGING, pkey);
	}

	if (STR_EQ(str, "add mpls")) {
		return parse_flag(&targ->runtime_flags, TASK_MPLS_TAGGING, pkey);
	}

	if (STR_EQ(str, "ether type")) {
		return parse_int(&targ->etype, pkey);
	}

	if (STR_EQ(str, "cache set")) {
		return parse_int(&lconf->cache_set, pkey);
	}

	if (STR_EQ(str, "sub mode")) {
		const char* mode_str = targ->task_init->mode_str;
		const char *sub_mode_str = pkey;

		targ->task_init = to_task_init(mode_str, sub_mode_str);
		if (!targ->task_init) {
			if (strcmp(sub_mode_str, "l3") != 0) {
				set_errf("sub mode %s not supported for mode %s", sub_mode_str, mode_str);
				return -1;
			}
			targ->task_init = to_task_init(mode_str, "");
			if (!targ->task_init) {
				set_errf("sub mode %s not supported for mode %s", sub_mode_str, mode_str);
				return -1;
			}
		}
		if (strcmp(sub_mode_str, "l3") == 0) {
			prox_cfg.flags |= DSF_CTRL_PLANE_ENABLED;
			targ->flags |= TASK_ARG_L3;
			strcpy(targ->sub_mode_str, "l3");
		} else {
			strcpy(targ->sub_mode_str, targ->task_init->sub_mode_str);
		}
		return 0;
	}

	if (STR_EQ(str, "mempool name")) {
		return parse_str(targ->pool_name, pkey, sizeof(targ->pool_name));
	}
	if (STR_EQ(str, "dpi engine")) {
		return parse_str(targ->dpi_engine_path, pkey, sizeof(targ->dpi_engine_path));
	}
	if (STR_EQ(str, "dpi engine arg")) {
		return parse_str(targ->dpi_engine_args[targ->n_dpi_engine_args++], pkey,
				 sizeof(targ->dpi_engine_args[0]));
	}
	if (STR_EQ(str, "dst mac")) { /* destination MAC address to be used for packets */
		if (parse_mac(&targ->edaddr, pkey)) {
			if (STR_EQ(pkey, "no")) {
				targ->flags |= TASK_ARG_DO_NOT_SET_DST_MAC;
				return 0;
			}
			if (STR_EQ(pkey, "packet") == 0)
				return -1;
			else
				return 0;
		}
		targ->flags |= TASK_ARG_DST_MAC_SET;
		return 0;
	}
	if (STR_EQ(str, "src mac")) {
		if (parse_mac(&targ->esaddr, pkey)) {
			if (STR_EQ(pkey, "no")) {
				targ->flags |= TASK_ARG_DO_NOT_SET_SRC_MAC;
				return 0;
			}
			else if (STR_EQ(pkey, "packet"))
				return 0;
			else if (STR_EQ(pkey, "hw")) {
				targ->flags |= TASK_ARG_HW_SRC_MAC;
				return 0;
			} else {
				return -1;
			}
		}
		targ->flags |= TASK_ARG_SRC_MAC_SET;
		return 0;
	}
	if (STR_EQ(str, "gateway ipv4")) { /* Gateway IP address used when generating */
		return parse_ip(&targ->gateway_ipv4, pkey);
	}
	if (STR_EQ(str, "local ipv4")) { /* source IP address to be used for packets */
		return parse_ip(&targ->local_ipv4, pkey);
	}
	if (STR_EQ(str, "remote ipv4")) { /* source IP address to be used for packets */
		return parse_ip(&targ->remote_ipv4, pkey);
	}
        if (STR_EQ(str, "local ipv6")) { /* source IPv6 address to be used for packets */
                return parse_ip6(&targ->local_ipv6, pkey);
        }
	if (STR_EQ(str, "arp timeout"))
		return parse_int(&targ->arp_timeout, pkey);
	if (STR_EQ(str, "arp update time"))
		return parse_int(&targ->arp_update_time, pkey);
	if (STR_EQ(str, "number of packets"))
		return parse_int(&targ->n_pkts, pkey);
	if (STR_EQ(str, "pipes")) {
		uint32_t val;
		int err = parse_int(&val, pkey);
		if (err)
			return -1;
		if (!val || !rte_is_power_of_2(val)) {
			set_errf("Number of pipes has to be power of 2 and not zero");
			return -1;
		}

		targ->qos_conf.port_params.n_pipes_per_subport = val;
		return 0;
	}
	if (STR_EQ(str, "queue size")) {
		uint32_t val;
		int err = parse_int(&val, pkey);
		if (err) {
			return -1;
		}

		targ->qos_conf.port_params.qsize[0] = val;
		targ->qos_conf.port_params.qsize[1] = val;
		targ->qos_conf.port_params.qsize[2] = val;
		targ->qos_conf.port_params.qsize[3] = val;
		return 0;
	}
	if (STR_EQ(str, "subport tb rate")) {
		return parse_int(&targ->qos_conf.subport_params[0].tb_rate, pkey);
	}
	if (STR_EQ(str, "subport tb size")) {
		return parse_int(&targ->qos_conf.subport_params[0].tb_size, pkey);
	}
	if (STR_EQ(str, "subport tc 0 rate")) {
		return parse_int(&targ->qos_conf.subport_params[0].tc_rate[0], pkey);
	}
	if (STR_EQ(str, "subport tc 1 rate")) {
		return parse_int(&targ->qos_conf.subport_params[0].tc_rate[1], pkey);
	}
	if (STR_EQ(str, "subport tc 2 rate")) {
		return parse_int(&targ->qos_conf.subport_params[0].tc_rate[2], pkey);
	}
	if (STR_EQ(str, "subport tc 3 rate")) {
		return parse_int(&targ->qos_conf.subport_params[0].tc_rate[3], pkey);
	}

	if (STR_EQ(str, "subport tc rate")) {
		uint32_t val;
		int err = parse_int(&val, pkey);
		if (err) {
			return -1;
		}

		targ->qos_conf.subport_params[0].tc_rate[0] = val;
		targ->qos_conf.subport_params[0].tc_rate[1] = val;
		targ->qos_conf.subport_params[0].tc_rate[2] = val;
		targ->qos_conf.subport_params[0].tc_rate[3] = val;

		return 0;
	}
	if (STR_EQ(str, "subport tc period")) {
		return parse_int(&targ->qos_conf.subport_params[0].tc_period, pkey);
	}
	if (STR_EQ(str, "pipe tb rate")) {
		return parse_int(&targ->qos_conf.pipe_params[0].tb_rate, pkey);
	}
	if (STR_EQ(str, "pipe tb size")) {
		return parse_int(&targ->qos_conf.pipe_params[0].tb_size, pkey);
	}
	if (STR_EQ(str, "pipe tc rate")) {
		uint32_t val;
		int err = parse_int(&val, pkey);
		if (err) {
			return -1;
		}

		targ->qos_conf.pipe_params[0].tc_rate[0] = val;
		targ->qos_conf.pipe_params[0].tc_rate[1] = val;
		targ->qos_conf.pipe_params[0].tc_rate[2] = val;
		targ->qos_conf.pipe_params[0].tc_rate[3] = val;
		return 0;
	}
	if (STR_EQ(str, "pipe tc 0 rate")) {
		return parse_int(&targ->qos_conf.pipe_params[0].tc_rate[0], pkey);
	}
	if (STR_EQ(str, "pipe tc 1 rate")) {
		return parse_int(&targ->qos_conf.pipe_params[0].tc_rate[1], pkey);
	}
	if (STR_EQ(str, "pipe tc 2 rate")) {
		return parse_int(&targ->qos_conf.pipe_params[0].tc_rate[2], pkey);
	}
	if (STR_EQ(str, "pipe tc 3 rate")) {
		return parse_int(&targ->qos_conf.pipe_params[0].tc_rate[3], pkey);
	}
	if (STR_EQ(str, "pipe tc period")) {
		return parse_int(&targ->qos_conf.pipe_params[0].tc_period, pkey);
	}
	if (STR_EQ(str, "police action")) {
		char *in = strstr(pkey, " io=");
		if (in == NULL) {
			set_errf("Need to specify io colors using io=in_color,out_color\n");
			return -1;
		}
		*in = 0;
		in += strlen(" io=");

		char *out = strstr(in, ",");
		if (out == NULL) {
			set_errf("Output color not specified\n");
		}
		*out = 0;
		out++;

		enum police_action in_color = str_to_color(in);
		enum police_action out_color = str_to_color(out);

		if (in_color == ACT_INVALID) {
			set_errf("Invalid input color %s. Expected green, yellow or red", in);
			return -1;
		}
		if (out_color == ACT_INVALID) {
			set_errf("Invalid output color %s. Expected green, yellow or red", out);
			return -1;
		}
		enum police_action action = str_to_color(pkey);
		if (action == ACT_INVALID) {
			set_errf("Error action %s. Expected green, yellow, red or drop", pkey);
			return -1;
		}
		targ->police_act[in_color][out_color] = action;

		return 0;
	}
	if (STR_EQ(str, "qinq tag")) {
		return parse_int(&targ->qinq_tag, pkey);
	}
	if (STR_EQ(str, "cir")) {
		return parse_int(&targ->cir, pkey);
	}
	if (STR_EQ(str, "cbs")) {
		return parse_int(&targ->cbs, pkey);
	}
	if (STR_EQ(str, "pir")) {
		return parse_int(&targ->pir, pkey);
	}
	if (STR_EQ(str, "pbs")) {
		return parse_int(&targ->pbs, pkey);
	}
	if (STR_EQ(str, "ebs")) {
		return parse_int(&targ->ebs, pkey);
	}
	uint32_t queue_id = 0;
	if (sscanf(str, "queue %d weight", &queue_id) == 1) {
		uint32_t val;
		int err = parse_int(&val, pkey);
		if (err) {
			return -1;
		}
		targ->qos_conf.pipe_params[0].wrr_weights[queue_id] = val;
		return 0;
	}
	if (STR_EQ(str, "classify")) {
		if (!(targ->task_init->flag_features & TASK_FEATURE_CLASSIFY)) {
			set_errf("Classify is not supported in '%s' mode", targ->task_init->mode_str);
			return -1;
		}

		return parse_flag(&targ->runtime_flags, TASK_CLASSIFY, pkey);
	}
	if (STR_EQ(str, "flow table size")) {
		return parse_int(&targ->flow_table_size, pkey);
	}
#ifdef GRE_TP
	if (STR_EQ(str, "tbf rate")) {
		return parse_int(&targ->tb_rate, pkey);
	}
	if (STR_EQ(str, "tbf size")) {
		return parse_int(&targ->tb_size, pkey);
	}
#endif
	if (STR_EQ(str, "max rules")) {
		return parse_int(&targ->n_max_rules, pkey);
	}

        if (STR_EQ(str, "tunnel hop limit")) {
                uint32_t val;
                int err = parse_int(&val, pkey);
                if (err) {
                        return -1;
                }
                targ->tunnel_hop_limit = val;
                return 0;
        }

        if (STR_EQ(str, "lookup port mask")) {
                uint32_t val;
                int err = parse_int(&val, pkey);
                if (err) {
                        return -1;
                }
                targ->lookup_port_mask = val;
                return 0;
        }

	if (STR_EQ(str, "irq debug")) {
		parse_int(&targ->irq_debug, pkey);
		return 0;
	}

	set_errf("Option '%s' is not known", str);
	/* fail on unknown keys */
	return -1;
}

static int str_is_number(const char *in)
{
	int dot_once = 0;

	for (size_t i = 0; i < strlen(in); ++i) {
		if (!dot_once && in[i] == '.') {
			dot_once = 1;
			continue;
		}

		if (in[i] < '0' || in[i] > '9')
			return 0;
	}

	return 1;
}

/* command line parameters parsing procedure */
int prox_parse_args(int argc, char **argv)
{
	int i, opt, ret;
	char *tmp, *tmp2;
	char tmp3[64];

	/* Default settings */
	prox_cfg.flags |= DSF_AUTOSTART | DSF_WAIT_ON_QUIT;
	prox_cfg.ui = PROX_UI_CURSES;

	plog_info("\tCommand line:");
	for (i = 0; i < argc; ++i) {
		plog_info(" %s", argv[i]);
	}
	plog_info("\n");

	while ((opt = getopt(argc, argv, "f:dnzpo:tkuar:emsiw:l:v:q:")) != EOF) {
		switch (opt) {
		case 'f':
			/* path to config file */
			cfg_file = optarg;
			size_t offset = 0;
			for (size_t i = 0; i < strlen(cfg_file); ++i) {
				if (cfg_file[i] == '/') {
					offset = i + 1;
				}
			}

			strncpy(prox_cfg.name, cfg_file + offset, MAX_NAME_SIZE);
			break;
		case 'v':
			plog_set_lvl(atoi(optarg));
			break;
		case 'l':
			prox_cfg.log_name_pid = 0;
			strncpy(prox_cfg.log_name, optarg, MAX_NAME_SIZE);
			break;
		case 'p':
			prox_cfg.log_name_pid = 1;
			break;
		case 'k':
			prox_cfg.use_stats_logger = 1;
			break;
		case 'd':
			prox_cfg.flags |= DSF_DAEMON;
			prox_cfg.ui = PROX_UI_NONE;
			break;
                case 'z':
                        prox_cfg.flags |= DSF_USE_DUMMY_CPU_TOPO;
			prox_cfg.flags |= DSF_CHECK_INIT;
                        break;
		case 'n':
			prox_cfg.flags |= DSF_USE_DUMMY_DEVICES;
			break;
		case 'r':
			if (!str_is_number(optarg) || strlen(optarg) > 11)
				return -1;
			strncpy(prox_cfg.update_interval_str, optarg, sizeof(prox_cfg.update_interval_str));
			break;
		case 'o':
			if (prox_cfg.flags & DSF_DAEMON)
				break;

			if (!strcmp(optarg, "curses")) {
				prox_cfg.ui = PROX_UI_CURSES;
			}
			else if (!strcmp(optarg, "cli")) {
				prox_cfg.ui = PROX_UI_CLI;
			}
			else if (!strcmp(optarg, "none")) {
				prox_cfg.ui = PROX_UI_NONE;
			}
			else {
				plog_err("Invalid local UI '%s', local UI can be 'curses', 'cli' or 'none'.", optarg);
				return -1;
			}
			break;
		case 'q':
			if (luaL_loadstring(prox_lua(), optarg)) {
				set_errf("Lua error: '%s'\n", lua_tostring(prox_lua(), -1));
				return -1;
			}

			if (lua_pcall(prox_lua(), 0, LUA_MULTRET, 0)) {
				set_errf("Lua error: '%s'\n", lua_tostring(prox_lua(), -1));
				return -1;
			}

			break;
		case 'a':
			/* autostart all cores */
			prox_cfg.flags |= DSF_AUTOSTART;
			break;
		case 'e':
			/* don't autostart */
			prox_cfg.flags &= ~DSF_AUTOSTART;
			break;
		case 't':
			prox_cfg.flags |= DSF_LISTEN_TCP;
			break;
		case 'u':
			prox_cfg.flags |= DSF_LISTEN_UDS;
			break;
		case 'm':
			/* list supported task modes and exit */
			prox_cfg.flags |= DSF_LIST_TASK_MODES;
			break;
		case 's':
			/* check configuration file syntax and exit */
			prox_cfg.flags |= DSF_CHECK_SYNTAX;
			break;
		case 'i':
			/* check initialization sequence and exit */
			prox_cfg.flags |= DSF_CHECK_INIT;
			break;
		case 'w':
			tmp = optarg;
			tmp2 = 0;
			if (strlen(tmp) >= 3 &&
			    (tmp2 = strchr(tmp, '='))) {
				*tmp2 = 0;
				tmp3[0] = '$';
				strncpy(tmp3 + 1, tmp, 63);
				plog_info("\tAdding variable: %s = %s\n", tmp3, tmp2 + 1);
				ret = add_var(tmp3, tmp2 + 1, 1);
				if (ret == -2) {
					plog_err("\tFailed to add variable, too many variables defines\n");
					return -1;
				}
				else if(ret == -3) {
					plog_err("\tFailed to add variable, already defined\n");
					return -1;
				}
				break;
			}
			/* fall-through */
		default:
			plog_err("\tUnknown option\n");
			return -1;
		}
	}

	/* reset getopt lib for DPDK */
	optind = 0;

	return 0;
}

static int check_cfg(void)
{
	/* Sanity check */
#define RETURN_IF(cond, err)			\
	if (cond) {				\
		plog_err(err);			\
		return -1;			\
	};

	RETURN_IF(rte_cfg.force_nchannel == 0, "\tError: number of memory channels not specified in [eal options] section\n");
	RETURN_IF(prox_cfg.master >= RTE_MAX_LCORE, "\tError: No master core specified (one core needs to have mode=master)\n");

#undef RETURN_IF

	return 0;
}

static int calc_tot_rxrings(void)
{
	struct lcore_cfg *slconf, *dlconf;
	struct task_args *starg, *dtarg;
	uint32_t dlcore_id;
	uint8_t dtask_id;
	struct core_task ct;

	dlconf = NULL;
	while (core_targ_next_early(&dlconf, &dtarg, 1) == 0) {
		dtarg->tot_rxrings = 0;
	}

	slconf = NULL;
	while (core_targ_next_early(&slconf, &starg, 1) == 0) {
		for (uint8_t idx = 0; idx < MAX_PROTOCOLS; ++idx) {
			for (uint8_t ring_idx = 0; ring_idx < starg->core_task_set[idx].n_elems; ++ring_idx) {
				ct = starg->core_task_set[idx].core_task[ring_idx];
				if (!prox_core_active(ct.core, 0)) {
					set_errf("Core %u is disabled but Core %u task %u is sending to it\n",
						 ct.core, slconf->id, starg->id);
					return -1;
				}

				dlconf = &lcore_cfg_init[ct.core];

				if (ct.task >= dlconf->n_tasks_all) {
					set_errf("Core %u task %u not enabled\n", ct.core, ct.task);
					return -1;
				}

				dtarg = &dlconf->targs[ct.task];

				/* Control rings are not relevant at this point. */
				if (ct.type)
					continue;

				if (!(dtarg->flags & TASK_ARG_RX_RING)) {
					set_errf("Core %u task %u is not expecting to receive through a ring\n",
						 ct.core, ct.task);
					return -1;
				}

				dtarg->tot_rxrings++;
				if (dtarg->tot_rxrings > MAX_RINGS_PER_TASK) {
					set_errf("Core %u task %u is receiving from too many tasks",
						 ct.core, ct.task);
					return -1;
				}
			}
		}
	}

	return 0;
}

static void prox_set_core_mask(void)
{
	struct lcore_cfg *lconf;

	prox_core_clr();
	for (uint8_t lcore_id = 0; lcore_id < RTE_MAX_LCORE; ++lcore_id) {
		lconf = &lcore_cfg_init[lcore_id];
		if (lconf->n_tasks_all > 0 && lconf->targs[0].mode != MASTER) {
			prox_core_set_active(lcore_id);
		}
	}
}

static int is_using_no_drop(void)
{
	uint32_t lcore_id;
	struct lcore_cfg *lconf;
	struct task_args *targs;

	lcore_id = -1;
	while(prox_core_next(&lcore_id, 1) == 0) {
		lconf = &lcore_cfg_init[lcore_id];
		for (uint8_t task_id = 0; task_id < lconf->n_tasks_all; ++task_id) {
			targs = &lconf->targs[task_id];
			if (!(targs->flags & TASK_ARG_DROP))
				return 1;
		}
	}
	return 0;
}

int prox_read_config_file(void)
{
	set_global_defaults(&prox_cfg);
	set_task_defaults(&prox_cfg, lcore_cfg_init);
	set_port_defaults();
	plog_info("=== Parsing configuration file '%s' ===\n", cfg_file);
	struct cfg_file *pcfg = cfg_open(cfg_file);
	if (pcfg == NULL) {
		return -1;
	}

	struct cfg_section* config_sections[] = {
		&lua_cfg          ,
		&var_cfg          ,
		&eal_default_cfg  ,
		&cache_set_cfg    ,
		&port_cfg         ,
		&defaults_cfg     ,
		&settings_cfg     ,
		&core_cfg         ,
		NULL
	};

	for (struct cfg_section** section = config_sections; *section != NULL; ++section) {
		const char* name = (*section)->name;
		size_t len = strlen(name);
		plog_info("\t*** Reading [%s] section%s ***\n", name, name[len - 1] == '#'? "s": "");
		cfg_parse(pcfg, *section);

		if ((*section)->error) {
			plog_err("At line %u, section [%s], entry %u: '%s'\n\t%s\n"
				 , pcfg->err_line, pcfg->err_section, pcfg->err_entry + 1, pcfg->cur_line,
				 strlen(get_parse_err())? get_parse_err() : err_str);
			cfg_close(pcfg); /* cannot close before printing error, print uses internal buffer */
			return -1;
		}
	}

	cfg_close(pcfg);

	prox_set_core_mask();

	if (is_using_no_drop()) {
		prox_cfg.flags &= ~DSF_WAIT_ON_QUIT;
	}

	if (calc_tot_rxrings()) {
		plog_err("Error in configuration: %s\n", err_str);
		return -1;
	}

	return check_cfg();
}

static void failed_rte_eal_init(__attribute__((unused))const char *prog_name)
{
	plog_err("\tError in rte_eal_init()\n");
}

int prox_setup_rte(const char *prog_name)
{
	char *rte_argv[MAX_RTE_ARGV];
	char  rte_arg[MAX_RTE_ARGV][MAX_ARG_LEN];
	char tmp[PROX_CM_STR_LEN];
	/* create mask of used cores */
	plog_info("=== Setting up RTE EAL ===\n");

	if (prox_cfg.flags & DSF_USE_DUMMY_CPU_TOPO) {
		plog_info("Using dummy cpu topology\n");
		snprintf(tmp, sizeof(tmp), "0x1");
	} else {
		prox_core_to_hex(tmp, sizeof(tmp), 0);
		plog_info("\tWorker threads core mask is %s\n", tmp);
		prox_core_to_hex(tmp, sizeof(tmp), 1);
		plog_info("\tWith master core index %u, full core mask is %s\n", prox_cfg.master, tmp);
	}

	/* fake command line parameters for rte_eal_init() */
	int argc = 0;
	rte_argv[argc] = strdup(prog_name);
	sprintf(rte_arg[++argc], "-c%s", tmp);
	rte_argv[argc] = rte_arg[argc];
#if RTE_VERSION >= RTE_VERSION_NUM(1,8,0,0)
	if (prox_cfg.flags & DSF_USE_DUMMY_CPU_TOPO)
		sprintf(rte_arg[++argc], "--master-lcore=%u", 0);
	else
		sprintf(rte_arg[++argc], "--master-lcore=%u", prox_cfg.master);
	rte_argv[argc] = rte_arg[argc];
#else
	/* For old DPDK versions, the master core had to be the first
	   core. */
	uint32_t first_core = -1;

	if (prox_core_next(&first_core, 1) == -1) {
		plog_err("Can't core ID of first core in use\n");
		return -1;
	}
	if (first_core != prox_cfg.master) {
		plog_err("The master core needs to be the first core (master core = %u, first core = %u).\n", first_core, prox_cfg.master);
		return -1;
	}
#endif

	if (rte_cfg.memory) {
		sprintf(rte_arg[++argc], "-m%u", rte_cfg.memory);
		rte_argv[argc] = rte_arg[argc];
	}

	if (rte_cfg.force_nchannel) {
		sprintf(rte_arg[++argc], "-n%u", rte_cfg.force_nchannel);
		rte_argv[argc] = rte_arg[argc];
	}

	if (rte_cfg.force_nrank) {
		sprintf(rte_arg[++argc], "-r%u", rte_cfg.force_nrank);
		rte_argv[argc] = rte_arg[argc];
	}

	if (rte_cfg.no_hugetlbfs) {
		strcpy(rte_arg[++argc], "--no-huge");
		rte_argv[argc] = rte_arg[argc];
	}

	if (rte_cfg.no_pci) {
		strcpy(rte_arg[++argc], "--no-pci");
		rte_argv[argc] = rte_arg[argc];
	}

	if (rte_cfg.no_hpet) {
		strcpy(rte_arg[++argc], "--no-hpet");
		rte_argv[argc] = rte_arg[argc];
	}

	if (rte_cfg.no_shconf) {
		strcpy(rte_arg[++argc], "--no-shconf");
		rte_argv[argc] = rte_arg[argc];
	}

	if (rte_cfg.eal != NULL) {
		char *ptr = rte_cfg.eal;
		char *ptr2;
		while (ptr != NULL) {
			while (isspace(*ptr))
				ptr++;
			ptr2 = ptr;
			ptr = strchr(ptr, ' ');
			if (ptr) {
				*ptr++ = '\0';
			}
			strcpy(rte_arg[++argc], ptr2);
			rte_argv[argc] = rte_arg[argc];
		}
	}

	if (rte_cfg.hugedir != NULL) {
		strcpy(rte_arg[++argc], "--huge-dir");
		rte_argv[argc] = rte_arg[argc];
		rte_argv[++argc] = rte_cfg.hugedir;
	}

	if (rte_cfg.no_output) {
		rte_log_set_global_level(0);
	}
	/* init EAL */
	plog_info("\tEAL command line:");
	if (argc >= MAX_RTE_ARGV) {
		plog_err("too many arguments for EAL\n");
		return -1;
	}

	for (int h = 0; h <= argc; ++h) {
		plog_info(" %s", rte_argv[h]);
	}
	plog_info("\n");

	rte_set_application_usage_hook(failed_rte_eal_init);
	if (rte_eal_init(++argc, rte_argv) < 0) {
		plog_err("\tError in rte_eal_init()\n");
		return -1;
	}
	plog_info("\tEAL Initialized\n");

	if (prox_cfg.flags & DSF_USE_DUMMY_CPU_TOPO)
		return 0;

	/* check if all active cores are in enabled in DPDK */
	for (uint32_t lcore_id = 0; lcore_id < RTE_MAX_LCORE; ++lcore_id) {
		if (lcore_id == prox_cfg.master) {
			if (!rte_lcore_is_enabled(lcore_id))
				return -1;
		}
		else if (rte_lcore_is_enabled(lcore_id) != prox_core_active(lcore_id, 0)) {
			plog_err("\tFailed to enable lcore %u\n", lcore_id);
			return -1;
		}
		else if (lcore_cfg_init[lcore_id].n_tasks_all != 0 && !rte_lcore_is_enabled(lcore_id)) {
			plog_err("\tFailed to enable lcore %u\n", lcore_id);
			return -1;
		}
	}
	return 0;
}
