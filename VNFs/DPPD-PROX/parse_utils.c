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

#include <ctype.h>
#include <stdio.h>
#include <float.h>
#include <math.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>

#include <rte_ether.h>
#include <rte_string_fns.h>

#include "quit.h"
#include "cfgfile.h"
#include "ip6_addr.h"
#include "parse_utils.h"
#include "prox_globals.h"
#include "prox_cfg.h"
#include "log.h"
#include "prox_lua.h"
#include "prox_lua_types.h"

#define MAX_NB_PORT_NAMES PROX_MAX_PORTS
#define MAX_LEN_PORT_NAME 24
#define MAX_LEN_VAR_NAME  24
#define MAX_LEN_VAL       512
#define MAX_NB_VARS       32

#if MAX_WT_PER_LB > MAX_INDEX
#error MAX_WT_PER_LB > MAX_INDEX
#endif

/* The CPU topology of the system is used to parse "socket
   notation". This notation allows to refer to cores on specific
   sockets and the hyper-thread of those cores. The CPU topology is
   loaded only if the socket notation is used at least once. */

struct cpu_topology {
	int socket[MAX_SOCKETS][RTE_MAX_LCORE][2];
	uint32_t n_cores[MAX_SOCKETS];
	uint32_t n_sockets;
};

struct cpu_topology cpu_topo;

struct port_name {
	uint32_t id;
	char     name[MAX_LEN_PORT_NAME];
};

static struct port_name port_names[MAX_NB_PORT_NAMES];
static uint8_t nb_port_names;

struct var {
	uint8_t  cli;
	char     name[MAX_LEN_VAR_NAME];
	char     val[MAX_LEN_VAL];
};

static struct var vars[MAX_NB_VARS];
static uint8_t nb_vars;

static char format_err_str[256];
static const char *err_str = "";

const char *get_parse_err(void)
{
	return err_str;
}

static int read_cpu_topology(void);

static int parse_core(int *socket, int *core, int *ht, const char* str);

static void set_errf(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vsnprintf(format_err_str, sizeof(format_err_str), format, ap);
	va_end(ap);
	err_str = format_err_str;
}

static struct var *var_lookup(const char *name)
{
	for (uint8_t i = 0; i < nb_vars; ++i) {
		if (!strcmp(name, vars[i].name)) {
			return &vars[i];
		}
	}
	return NULL;
}

int parse_single_var(char *val, size_t len, const char *name)
{
	struct var *match;

	match = var_lookup(name);
	if (match) {
		if (strlen(match->val) + 1 > len) {
			set_errf("Variables '%s' with value '%s' is too long\n",
				 match->name, match->val);
			return -1;
		}
		strncpy(val, match->val, len);
		return 0;
	}
	else {
		/* name + 1 to skip leading '$' */
		if (lua_to_string(prox_lua(), GLOBAL, name + 1, val, len) >= 0)
			return 0;
	}

	set_errf("Variable '%s' not defined!", name);
	return 1;
}

/* Replace $... and each occurrence of ${...} with variable values */
int parse_vars(char *val, size_t len, const char *name)
{
	static char result[MAX_CFG_STRING_LEN];
	static char cur_var[MAX_CFG_STRING_LEN];
	char parsed[MAX_CFG_STRING_LEN];
	size_t name_len = strlen(name);
	enum parse_vars_state {NO_VAR, WHOLE_VAR, INLINE_VAR} state = NO_VAR;
	size_t result_len = 0;
	size_t start_var = 0;

	memset(result, 0, sizeof(result));
	PROX_PANIC(name_len > sizeof(result), "\tUnable to parse var %s: too long\n", name);

	for (size_t i = 0; i < name_len; ++i) {
		switch (state) {
		case NO_VAR:
			if (name[i] == '$') {
				if (i != name_len - 1 && name[i + 1] == '{') {
					start_var = i + 2;
					state = INLINE_VAR;
					i = i + 1;
				}
				else if (i == 0 && i != name_len - 1) {
					state = WHOLE_VAR;
				}
				else {
					set_errf("Invalid variable syntax");
					return -1;
				}
			}
			else {
				result[result_len++] = name[i];
			}
			break;
		case INLINE_VAR:
			if (name[i] == '}') {
				cur_var[0] = '$';
				size_t var_len = i - start_var;
				if (var_len == 0) {
					set_errf("Empty variable are not allowed");
					return -1;
				}

				strncpy(&cur_var[1], &name[start_var], var_len);
				cur_var[1 + var_len] = 0;
				if (parse_single_var(parsed, sizeof(parsed), cur_var)) {
					return -1;
				}
				strcpy(&result[result_len], parsed);
				result_len += strlen(parsed);
				state = NO_VAR;
			}
			else if (i == name_len - 1) {
				set_errf("Invalid variable syntax, expected '}'.");
				return -1;
			}
			break;
		case WHOLE_VAR:
			if (i == name_len - 1) {
				return parse_single_var(val, len, name);
			}
			break;
		}
	}
	strncpy(val, result, len);

	return 0;
}

int parse_int_mask(uint32_t *val, uint32_t *mask, const char *str2)
{
	char str[MAX_STR_LEN_PROC];
	char *mask_str;

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	mask_str = strchr(str, '&');

	if (mask_str == NULL) {
		set_errf("Missing '&' when parsing mask");
		return -2;
	}

	*mask_str = 0;

	if (parse_int(val, str))
		return -1;
	if (parse_int(mask, mask_str + 1))
		return -1;

	return 0;
}

int parse_range(uint32_t* lo, uint32_t* hi, const char *str2)
{
	char str[MAX_STR_LEN_PROC];
	char *dash;

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	dash = strstr(str, "-");

	if (dash == NULL) {
		set_errf("Missing '-' when parsing mask");
		return -2;
	}

	*dash = 0;

	if (parse_int(lo, str))
		return -1;
	if (parse_int(hi, dash + 1))
		return -1;

	int64_t tmp = strtol(str, 0, 0);
	if (tmp > UINT32_MAX) {
		set_errf("Integer is bigger than %u", UINT32_MAX);
		return -1;
	}
	if (tmp < 0) {
		set_errf("Integer is negative");
		return -2;
	}

	*lo = tmp;

	tmp = strtol(dash + 1, 0, 0);
	if (tmp > UINT32_MAX) {
		set_errf("Integer is bigger than %u", UINT32_MAX);
		return -1;
	}
	if (tmp < 0) {
		set_errf("Integer is negative");
		return -2;
	}

	*hi = tmp;

	if (*lo > *hi) {
		set_errf("Low boundary is above high boundary in range");
		return -2;
	}

	return 0;
}

int parse_ip(uint32_t *addr, const char *str2)
{
	char str[MAX_STR_LEN_PROC];

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	char *ip_parts[5];

	if (strlen(str) > MAX_STR_LEN_PROC) {
		set_errf("String too long (max supported: %d)", MAX_STR_LEN_PROC);
		return -2;
	}

	if (4 != rte_strsplit(str, strlen(str), ip_parts, 5, '.')) {
		set_errf("Expecting 4 octets in ip.");
		return -1;
	}

	uint32_t val;
	for (uint8_t i = 0; i < 4; ++i) {
		val = atoi(ip_parts[i]);
		if (val > 255) {
			set_errf("Maximum value for octet is 255 but octet %u is %u", i, val);
			return -1;
		}
		*addr = *addr << 8 | val;
	}
	return 0;
}

int parse_ip4_cidr(struct ip4_subnet *val, const char *str2)
{
	char str[MAX_STR_LEN_PROC];
	char *slash;
	int prefix;

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	slash = strstr(str, "/");

	if (slash == NULL) {
		set_errf("Missing '/' when parsing CIDR notation");
		return -2;
	}

	*slash = 0;
	prefix = atoi(slash + 1);
	val->prefix = prefix;

	if (prefix > 32) {
		set_errf("Prefix %d is too big", prefix);
		return -2;
	}
	if (prefix < 1) {
		set_errf("Prefix %d is too small", prefix);
	}
	if (parse_ip(&val->ip, str))
		return -2;

	/* Apply mask making all bits outside the prefix zero */
	val->ip &= ((int)(1 << 31)) >> (prefix - 1);

	return 0;
}

int parse_ip6_cidr(struct ip6_subnet *val, const char *str2)
{
	char str[MAX_STR_LEN_PROC];
	char *slash;
	int prefix;

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	slash = strstr(str, "/");

	if (slash == NULL) {
		set_errf("Missing '/' when parsing CIDR notation");
		return -2;
	}

	*slash = 0;
	prefix = atoi(slash + 1);
	val->prefix = prefix;

	parse_ip6((struct ipv6_addr *)&val->ip, str);

	/* Apply mask making all bits outside the prefix zero */

	int p = 120;
	int cnt = 0;

	while (p >= prefix) {
		val->ip[15-cnt] = 0;
		p -= 8;
		cnt++;
	}

	if (prefix % 8 != 0) {
		val->ip[15-cnt] &= ((int8_t)(1 << 7)) >> ((prefix %8) - 1);
	}

	return 0;
}

int parse_ip6(struct ipv6_addr *addr, const char *str2)
{
	char str[MAX_STR_LEN_PROC];
	char *addr_parts[9];

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	uint8_t ret = rte_strsplit(str, strlen(str), addr_parts, 9, ':');

	if (ret == 9) {
		set_errf("Invalid IPv6 address");
		return -1;
	}

	uint8_t omitted = 0;

	for (uint8_t i = 0, j = 0; i < ret; ++i, ++j) {
		if (*addr_parts[i] == 0) {
			if (omitted == 0) {
				set_errf("Can only omit zeros once");
				return -1;
			}
			omitted = 1;
			j += 8 - ret;
		}
		else {
			uint16_t w = strtoll(addr_parts[i], NULL, 16);
			addr->bytes[j++] = (w >> 8) & 0xff;
			addr->bytes[j] = w & 0xff;
		}
	}
	return 0;
}

int parse_mac(struct ether_addr *ether_addr, const char *str2)
{
	char str[MAX_STR_LEN_PROC];
	char *addr_parts[7];

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	uint8_t ret = rte_strsplit(str, strlen(str), addr_parts, 7, ':');
	if (ret != 6)
		ret = rte_strsplit(str, strlen(str), addr_parts, 7, ' ');

	if (ret != 6) {
		set_errf("Invalid MAC address format");
		return -1;
	}

	for (uint8_t i = 0; i < 6; ++i) {
		if (2 != strlen(addr_parts[i])) {
			set_errf("Invalid MAC address format");
			return -1;
		}
		ether_addr->addr_bytes[i] = strtol(addr_parts[i], NULL, 16);
	}

	return 0;
}

char* get_cfg_key(char *str)
{
	char *pkey = strchr(str, '=');

	if (pkey == NULL) {
		return NULL;
	}
	*pkey++ = '\0';

	/* remove leading spaces */
	while (isspace(*pkey)) {
		pkey++;
	}
	if (*pkey == '\0') { /* an empty key */
		return NULL;
	}

	return pkey;
}

void strip_spaces(char *strings[], const uint32_t count)
{
	for (uint32_t i = 0; i < count; ++i) {
		while (isspace(strings[i][0])) {
			++strings[i];
		}
		size_t len = strlen(strings[i]);

		while (len && isspace(strings[i][len - 1])) {
			strings[i][len - 1] = '\0';
			--len;
		}
	}
}

int is_virtualized(void)
{
	char buf[1024]= "/proc/cpuinfo";
	int virtualized = 0;
	FILE* fd = fopen(buf, "r");
	if (fd == NULL) {
		set_errf("Could not open %s", buf);
		return -1;
	}
	while (fgets(buf, sizeof(buf), fd) != NULL) {
		if ((strstr(buf, "flags") != NULL) && (strstr(buf, "hypervisor") != NULL))
			virtualized = 1;
	}
	fclose(fd);
	return virtualized;
}

static int get_phys_core(uint32_t *dst, int lcore_id)
{
	uint32_t ret;
	char buf[1024];
	snprintf(buf, sizeof(buf), "/sys/devices/system/cpu/cpu%u/topology/thread_siblings_list", lcore_id);
	FILE* ht_fd = fopen(buf, "r");

	if (ht_fd == NULL) {
		set_errf("Could not open cpu topology %s", buf);
		return -1;
	}

	if (fgets(buf, sizeof(buf), ht_fd) == NULL) {
		set_errf("Could not read cpu topology");
		return -1;
	}
	fclose(ht_fd);

	uint32_t list[2] = {-1,-1};
	parse_list_set(list, buf, 2);

	*dst = list[0];

	return 0;
}

static int get_socket(uint32_t core_id, uint32_t *socket)
{
	int ret = -1;
	char buf[1024];
	snprintf(buf, sizeof(buf), "/sys/devices/system/cpu/cpu%u/topology/physical_package_id", core_id);
	FILE* fd = fopen(buf, "r");

	if (fd == NULL) {
		set_errf("%s", buf);
		return -1;
	}

	if (fgets(buf, sizeof(buf), fd) != NULL) {
		ret = atoi(buf);
	}
	fclose(fd);

	if (socket)
		*socket = (ret == -1 ? 0 : ret);

	return 0;
}

int lcore_to_socket_core_ht(uint32_t lcore_id, char *dst, size_t len)
{
	if (cpu_topo.n_sockets == 0) {
		if (read_cpu_topology() == -1) {
			return -1;
		}
	}

	for (uint32_t s = 0; s < cpu_topo.n_sockets; s++) {
		for (uint32_t i = 0; i < cpu_topo.n_cores[s]; ++i) {
			if ((uint32_t)cpu_topo.socket[s][i][0] == lcore_id) {
				snprintf(dst, len, "%us%u", i, s);
				return 0;
			} else if ((uint32_t)cpu_topo.socket[s][i][1] == lcore_id) {
				snprintf(dst, len, "%us%uh", i, s);
				return 0;
			}
		}
	}

	return -1;
}

static int get_lcore_id(uint32_t socket_id, uint32_t core_id, int ht)
{
	if (cpu_topo.n_sockets == 0) {
		if (read_cpu_topology() == -1) {
			return -1;
		}
	}

	if (socket_id == UINT32_MAX)
		socket_id = 0;

	if (socket_id >= MAX_SOCKETS) {
		set_errf("Socket id %d too high (max allowed is %d)", MAX_SOCKETS);
		return -1;
	}
	if (core_id >= RTE_MAX_LCORE) {
		set_errf("Core id %d too high (max allowed is %d)", RTE_MAX_LCORE);
		return -1;
	}
	if (socket_id >= cpu_topo.n_sockets) {
		set_errf("Current CPU topology reported that there are %u CPU sockets, CPU topology = %u socket(s), %u physical cores per socket, %u thread(s) per physical core",
			 cpu_topo.n_sockets, cpu_topo.n_sockets, cpu_topo.n_cores[0], cpu_topo.socket[0][0][1] == -1? 1: 2);
		return -1;
	}
	if (core_id >= cpu_topo.n_cores[socket_id]) {
		set_errf("Core %u on socket %u does not exist, CPU topology = %u socket(s), %u physical cores per socket, %u thread(s) per physical core",
			 core_id, socket_id, cpu_topo.n_sockets, cpu_topo.n_cores[0], cpu_topo.socket[socket_id][0][1] == -1? 1: 2);
		return -1;
	}
	if (cpu_topo.socket[socket_id][core_id][!!ht] == -1) {
		set_errf("Core %u %son socket %u has no hyper-thread, CPU topology = %u socket(s), %u physical cores per socket, %u thread(s) per physical core",
			 core_id, ht ? "(hyper-thread) " : "", socket_id, cpu_topo.n_sockets, cpu_topo.n_cores[0], cpu_topo.socket[socket_id][core_id][1] == -1? 1: 2);

		return -1;
	}
	return cpu_topo.socket[socket_id][core_id][!!ht];
}

/* Returns 0 on success, negative on error. Parses the syntax XsYh
   where sYh is optional. If sY is specified, Y is stored in the
   socket argument. If, in addition, h is specified, *ht is set to
   1. In case the input is only a number, socket and ht are set to
   -1.*/
static int parse_core(int *socket, int *core, int *ht, const char* str)
{
	*socket = -1;
	*core = -1;
	*ht = -1;

	char* end;

	*core = strtol(str, &end, 10);

	if (*end == 's') {
		*socket = 0;
		*ht = 0;

		if (cpu_topo.n_sockets == 0) {
			if (read_cpu_topology() == -1) {
				return -1;
			}
		}

		++end;
		*socket = strtol(end, &end, 10);
		if (*socket >= MAX_SOCKETS) {
			set_errf("Socket id %d too high (max allowed is %d)", *socket, MAX_SOCKETS - 1);
			return -1;
		}

		if (*end == 'h') {
			++end;
			*ht = 1;
		}

		return 0;
	}

	if (*end == 'h') {
		set_errf("Can't find hyper-thread since socket has not been specified");
		return -1;
	}

	return 0;
}

static int parse_task(const char *str, uint32_t *socket, uint32_t *core, uint32_t *task, uint32_t *ht, enum ctrl_type *type)
{
	const char *str_beg = str;
	char *end;

	*core = strtol(str, &end, 10);
	if (str == end) {
		set_errf("Expected number to in core-task definition:\n"
			 "\t(i.e. 5s1t0 for task 0 on core 5 on socket 1)\n"
			 "\tHave: '%s'.", end);
		return -1;
	}

	*task = 0;
	*socket = -1;
	*ht = -1;
	*type = 0;

	str = end;

	if (*str == 's') {
		str++;
		*socket = 0;
		*ht = 0;

		*socket = strtol(str, &end, 10);
		str = end;

		if (*str == 'h') {
			str++;
			*ht = 1;
		}
		if (*str == 't') {
			str++;
			*task = strtol(str, &end, 10);
			str = end;
			if (*str == 'p') {
				*type = CTRL_TYPE_PKT;
				str += 1;
			}
			else if (*str == 'm') {
				*type = CTRL_TYPE_MSG;
				str += 1;
			}
		}
	} else {
		if (*str == 'h') {
			set_errf("Can't find hyper-thread since socket has not been specified");
			return -1;
		}
		if (*str == 't') {
			str++;
			*task = strtol(str, &end, 10);
			str = end;
			if (*str == 'p') {
				*type = CTRL_TYPE_PKT;
				str += 1;
			}
			else if (*str == 'm') {
				*type = CTRL_TYPE_MSG;
				str += 1;
			}
		}
	}
	return str - str_beg;
}

static int core_task_set_add(struct core_task_set *val, uint32_t core, uint32_t task, enum ctrl_type type)
{
	if (val->n_elems == sizeof(val->core_task)/sizeof(val->core_task[0]))
		return -1;

	val->core_task[val->n_elems].core = core;
	val->core_task[val->n_elems].task = task;
	val->core_task[val->n_elems].type = type;
	val->n_elems++;

	return 0;
}

int parse_task_set(struct core_task_set *cts, const char *str2)
{
	char str[MAX_STR_LEN_PROC];

	if (parse_vars(str, sizeof(str), str2))
		return -1;
	cts->n_elems = 0;

	char *str3 = str;
	int ret;

	uint32_t socket_beg, core_beg, task_beg, ht_beg,
		socket_end, core_end, task_end, ht_end;
	enum ctrl_type type_beg, type_end;
	uint32_t task_group_start = -1;

	while (*str3 && *str3 != ' ') {
		if (*str3 == '(') {
			task_group_start = cts->n_elems;
			str3 += 1;
			continue;
		}
		if (*str3 == ')' && *(str3 + 1) == 't') {
			str3 += 2;
			char *end;
			uint32_t t = strtol(str3, &end, 10);
			enum ctrl_type type = 0;
			str3 = end;

			if (*str3 == 'p') {
				type = CTRL_TYPE_PKT;
				str3 += 1;
			}
			else if (*str3 == 'm') {
				type = CTRL_TYPE_MSG;
				str3 += 1;
			}

			for (uint32_t i = task_group_start; i < cts->n_elems; ++i) {
				cts->core_task[i].task = t;
				cts->core_task[i].type = type;
			}
			continue;
		}
		ret = parse_task(str3, &socket_beg, &core_beg, &task_beg, &ht_beg, &type_beg);
		if (ret < 0)
			return -1;
		str3 += ret;
		socket_end = socket_beg;
		core_end = core_beg;
		task_end = task_beg;
		ht_end = ht_beg;
		type_end = type_beg;

		if (*str3 == '-') {
			str3 += 1;
			ret = parse_task(str3, &socket_end, &core_end, &task_end, &ht_end, &type_end);
			if (ret < 0)
				return -1;
			str3 += ret;
		}

		if (*str3 == ',')
			str3 += 1;

		if (socket_end != socket_beg) {
			set_errf("Same socket must be used in range syntax.");
			return -1;
		} else if (ht_beg != ht_end) {
			set_errf("If 'h' syntax is in range, it must be specified everywhere.\n");
			return -1;
		} else if (task_end != task_beg && core_end != core_beg) {
			set_errf("Same task must be used in range syntax when cores are different.\n");
			return -1;
		} else if (task_end < task_beg) {
			set_errf("Task for end of range must be higher than task for beginning of range.\n");
			return -1;
		} else if (type_end != type_beg) {
			set_errf("Task type for end of range must be the same as  task type for beginning.\n");
			return -1;
		} else if (core_end < core_beg) {
			set_errf("Core for end of range must be higher than core for beginning of range.\n");
			return -1;
		}

		for (uint32_t j = core_beg; j <= core_end; ++j) {
			if (socket_beg != UINT32_MAX && ht_beg != UINT32_MAX)
				ret = get_lcore_id(socket_beg, j, ht_beg);
			else
				ret = j;
			if (ret < 0)
				return -1;
			for (uint32_t k = task_beg; k <= task_end; ++k) {
				core_task_set_add(cts, ret, k, type_beg);
			}
		}
	}
	return 0;
}

int parse_list_set(uint32_t *list, const char *str2, uint32_t max_list)
{
	char str[MAX_STR_LEN_PROC];
	char *parts[MAX_STR_LEN_PROC];

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	int n_parts = rte_strsplit(str, strlen(str), parts, MAX_STR_LEN_PROC, ',');
	size_t list_count = 0;

	for (int i = 0; i < n_parts; ++i) {
		char *cur_part = parts[i];
		char *sub_parts[3];
		int n_sub_parts = rte_strsplit(cur_part, strlen(cur_part), sub_parts, 3, '-');
		int socket1, socket2;
		int ht1, ht2;
		int core1, core2;
		int ret = 0;

		if (n_sub_parts == 1) {
			if (parse_core(&socket1, &core1, &ht1, sub_parts[0]))
				return -1;

			socket2 = socket1;
			core2 = core1;
			ht2 = ht1;
		} else if (n_sub_parts == 2) {
			if (parse_core(&socket1, &core1, &ht1, sub_parts[0]))
				return -1;
			if (parse_core(&socket2, &core2, &ht2, sub_parts[1]))
				return -1;
		} else if (n_sub_parts >= 3) {
			set_errf("Multiple '-' characters in range syntax found");
			return -1;
		} else {
			set_errf("Invalid list syntax");
			return -1;
		}

		if (socket1 != socket2) {
			set_errf("Same socket must be used in range syntax");
			return -1;
		}
		else if (ht1 != ht2) {
			set_errf("If 'h' syntax is in range, it must be specified everywhere.");
			return -1;
		}

		for (int cur_core = core1; cur_core <= core2; ++cur_core) {
			int effective_core;

			if (socket1 != -1)
				effective_core = get_lcore_id(socket1, cur_core, ht1);
			else
				effective_core = cur_core;

			if (list_count >= max_list) {
				set_errf("Too many elements in list");
				return -1;
			}
			list[list_count++] = effective_core;
		}
	}

	return list_count;
}

int parse_kmg(uint32_t* val, const char *str2)
{
	char str[MAX_STR_LEN_PROC];

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	char c = str[strlen(str) - 1];
	*val = atoi(str);

	switch (c) {
	case 'G':
		if (*val >> 22)
			return -2;
		*val <<= 10;
	case 'M':
		if (*val >> 22)
			return -2;
		*val <<= 10;
	case 'K':
		if (*val >> 22)
			return -2;
		*val <<= 10;
		break;
	default:
		/* only support optional KMG suffix */
		if (c < '0' || c > '9') {
			set_errf("Unknown syntax for KMG suffix '%c' (expected K, M or G)", c);
			return -1;
		}
	}

	return 0;
}

int parse_bool(uint32_t* val, const char *str2)
{
	char str[MAX_STR_LEN_PROC];

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	if (!strcmp(str, "yes")) {
		*val = 1;
		return 0;
	}
	else if (!strcmp(str, "no")) {
		*val = 0;
		return 0;
	}
	set_errf("Unknown syntax for bool '%s' (expected yes or no)", str);
	return -1;
}

int parse_flag(uint32_t* val, uint32_t flag, const char *str2)
{
	char str[MAX_STR_LEN_PROC];

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	uint32_t tmp;
	if (parse_bool(&tmp, str))
		return -1;

	if (tmp)
		*val |= flag;
	else
		*val &= ~flag;

	return 0;
}

int parse_int(uint32_t* val, const char *str2)
{
	char str[MAX_STR_LEN_PROC];

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	int64_t tmp = strtol(str, 0, 0);
	if (tmp > UINT32_MAX) {
		set_errf("Integer is bigger than %u", UINT32_MAX);
		return -1;
	}
	if (tmp < 0) {
		set_errf("Integer is negative");
		return -2;
	}
	*val = tmp;

	return 0;
}

int parse_float(float* val, const char *str2)
{
	char str[MAX_STR_LEN_PROC];

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	float tmp = strtof(str, 0);
	if ((tmp >= HUGE_VALF) || (tmp <= -HUGE_VALF)) {
		set_errf("Unable to parse float\n");
		return -1;
	}
	*val = tmp;

	return 0;
}

int parse_u64(uint64_t* val, const char *str2)
{
	char str[MAX_STR_LEN_PROC];

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	errno = 0;
	uint64_t tmp = strtoul(str, NULL, 0);
	if (errno != 0) {
		set_errf("Invalid u64 '%s' (%s)", str, strerror(errno));
		return -2;
	}
	*val = tmp;

	return 0;
}

int parse_str(char* dst, const char *str2, size_t max_len)
{
	char str[MAX_STR_LEN_PROC];

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	if (strlen(str) > max_len - 1) {
		set_errf("String too long (%u > %u)", strlen(str), max_len - 1);
		return -2;
	}

	strncpy(dst, str, max_len);
	return 0;
}

int parse_path(char *dst, const char *str, size_t max_len)
{
	if (parse_str(dst, str, max_len))
		return -1;
	if (access(dst, F_OK)) {
                set_errf("Invalid file '%s' (%s)", dst, strerror(errno));
		return -1;
	}
	return 0;
}

int parse_port_name(uint32_t *val, const char *str2)
{
	char str[MAX_STR_LEN_PROC];

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	for (uint8_t i = 0; i < nb_port_names; ++i) {
		if (!strcmp(str, port_names[i].name)) {
			*val = port_names[i].id;
			return 0;
		}
	}
	set_errf("Port with name %s not defined", str);
	return 1;
}

int parse_port_name_list(uint32_t *val, uint32_t* tot, uint8_t max_vals, const char *str2)
{
	char *elements[PROX_MAX_PORTS + 1];
	char str[MAX_STR_LEN_PROC];
	uint32_t cur;
	int ret;

	if (parse_str(str, str2, sizeof(str)))
		return -1;

	ret = rte_strsplit(str, strlen(str), elements, PROX_MAX_PORTS + 1, ',');

	if (ret == PROX_MAX_PORTS + 1 || ret > max_vals) {
		set_errf("Too many ports in port list");
		return -1;
	}

	strip_spaces(elements, ret);
	for (uint8_t i = 0; i < ret; ++i) {
		if (parse_port_name(&cur, elements[i])) {
			return -1;
		}
		val[i] = cur;
	}
	if (tot) {
		*tot = ret;
	}
	return 0;
}

int parse_remap(uint8_t *mapping, const char *str)
{
	char *elements[PROX_MAX_PORTS + 1];
	char *elements2[PROX_MAX_PORTS + 1];
	char str_cpy[MAX_STR_LEN_PROC];
	uint32_t val;
	int ret, ret2;

	if (strlen(str) > MAX_STR_LEN_PROC) {
		set_errf("String too long (max supported: %d)", MAX_STR_LEN_PROC);
		return -2;
	}
	strncpy(str_cpy, str, MAX_STR_LEN_PROC);

	ret = rte_strsplit(str_cpy, strlen(str_cpy), elements, PROX_MAX_PORTS + 1, ',');
	if (ret <= 0) {
		set_errf("Invalid remap syntax");
		return -1;
	}
	else if (ret > PROX_MAX_PORTS) {
		set_errf("Too many remaps");
		return -2;
	}

	strip_spaces(elements, ret);
	for (uint8_t i = 0; i < ret; ++i) {
		ret2 = rte_strsplit(elements[i], strlen(elements[i]), elements2, PROX_MAX_PORTS + 1, '|');
		strip_spaces(elements2, ret2);
		if (ret2 > PROX_MAX_PORTS) {
			set_errf("Too many remaps");
			return -2;
		}
		for (uint8_t j = 0; j < ret2; ++j) {
			if (parse_port_name(&val, elements2[j])) {
				return -1;
			}

			/* This port will be mapped to the i'th
			   element specified before remap=. */
			mapping[val] = i;
		}
	}

	return ret;
}

int add_port_name(uint32_t val, const char *str2)
{
	char str[MAX_STR_LEN_PROC];

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	struct port_name* pn;

	if (nb_port_names == MAX_NB_PORT_NAMES) {
		set_errf("Too many ports defined (can define %d)", MAX_NB_PORT_NAMES);
		return -1;
	}

	for (uint8_t i = 0; i < nb_port_names; ++i) {
		/* each port has to have a unique name*/
		if (!strcmp(str, port_names[i].name)) {
			set_errf("Port with name %s is already defined", str);
			return -2;
		}
	}

	pn = &port_names[nb_port_names];
	strncpy(pn->name, str, sizeof(pn->name));
	pn->id = val;

	++nb_port_names;
	return 0;
}

int set_self_var(const char *str)
{
	for (uint8_t i = 0; i < nb_vars; ++i) {
		if (!strcmp("$self", vars[i].name)) {
			sprintf(vars[i].val, "%s", str);
			return 0;
		}
	}

	struct var *v = &vars[nb_vars];

	strncpy(v->name, "$self", strlen("$self"));
	sprintf(v->val, "%s", str);
	nb_vars++;

	return 0;
}

int add_var(const char* name, const char *str2, uint8_t cli)
{
	struct var* v;

	char str[MAX_STR_LEN_PROC];

	if (parse_vars(str, sizeof(str), str2))
		return -1;

	if (strlen(name) == 0 || strlen(name) == 1) {
		set_errf("Can't define variables with empty name");
		return -1;
	}

	if (name[0] != '$') {
		set_errf("Each variable should start with the $ character");
		return -1;
	}

	if (nb_vars == MAX_NB_VARS) {
		set_errf("Too many variables defined (can define %d)", MAX_NB_VARS);
		return -2;
	}

	for (uint8_t i = 0; i < nb_vars; ++i) {
		if (!strcmp(name, vars[i].name)) {

			/* Variables defined through program arguments
			   take precedence. */
			if (!cli && vars[i].cli) {
				return 0;
			}

			set_errf("Variable with name %s is already defined", name);
			return -3;
		}
	}

	v = &vars[nb_vars];
	PROX_PANIC(strlen(name) > sizeof(v->name), "\tUnable to parse var %s: too long\n", name);
	PROX_PANIC(strlen(str) > sizeof(v->val), "\tUnable to parse var %s=%s: too long\n", name,str);
	strncpy(v->name, name, sizeof(v->name));
	strncpy(v->val, str, sizeof(v->val));
	v->cli = cli;

	++nb_vars;
	return 0;
}

static int read_cores_present(uint32_t *cores, int max_cores, int *res)
{
	FILE* fd = fopen("/sys/devices/system/cpu/present", "r");
	char buf[1024];

	if (fd == NULL) {
		set_errf("Could not opening file /sys/devices/system/cpu/present");
		return -1;
	}

	if (fgets(buf, sizeof(buf), fd) == NULL) {
		set_errf("Could not read cores range");
		return -1;
	}

	fclose(fd);

	int ret = parse_list_set(cores, buf, max_cores);

	if (ret < 0)
		return -1;

	*res = ret;
	return 0;
}

static int set_dummy_topology(void)
{
	int core_count = 0;

	for (int s = 0; s < MAX_SOCKETS; s++) {
		for (int i = 0; i < 32; ++i) {
			cpu_topo.socket[s][i][0] = core_count++;
			cpu_topo.socket[s][i][1] = core_count++;
			cpu_topo.n_cores[s]++;
		}
	}
	cpu_topo.n_sockets = MAX_SOCKETS;
	return 0;
}

static int read_cpu_topology(void)
{
	if (cpu_topo.n_sockets != 0)
		return 0;
	if (prox_cfg.flags & DSF_USE_DUMMY_CPU_TOPO)
		return set_dummy_topology();

	uint32_t cores[RTE_MAX_LCORE];
	int n_cores = 0;

	if (read_cores_present(cores, sizeof(cores)/sizeof(cores[0]), &n_cores) != 0)
		return -1;

	for (int s = 0; s < MAX_SOCKETS; s++) {
		for (int i = 0; i < RTE_MAX_LCORE; ++i) {
			cpu_topo.socket[s][i][0] = -1;
			cpu_topo.socket[s][i][1] = -1;
		}
	}

	for (int i = 0; i < n_cores; ++i) {
		uint32_t socket_id, lcore_id, phys;

		lcore_id = cores[i];
		if (get_socket(lcore_id, &socket_id) != 0)
			return -1;
		if (socket_id >= MAX_SOCKETS) {
			set_errf("Can't read CPU topology due too high socket ID (max allowed is %d)",
				 MAX_SOCKETS);
			return -1;
		}
		if (socket_id >= cpu_topo.n_sockets) {
			cpu_topo.n_sockets = socket_id + 1;
		}
		if (get_phys_core(&phys, lcore_id) != 0)
			return -1;
		if (phys >= RTE_MAX_LCORE) {
			set_errf("Core ID %u too high", phys);
			return -1;
		}

		if (cpu_topo.socket[socket_id][phys][0] == -1) {
			cpu_topo.socket[socket_id][phys][0] = lcore_id;
			cpu_topo.n_cores[socket_id]++;
		}
		else if (cpu_topo.socket[socket_id][phys][1] == -1) {
			cpu_topo.socket[socket_id][phys][1] = lcore_id;
		}
		else {
			set_errf("Too many core siblings");
			return -1;
		}
	}

	/* There can be holes in the cpu_topo description at this
	   point. An example for this is a CPU topology where the
	   lowest core ID of 2 hyper-threads is always an even
	   number. Before finished up this phase, compact all the
	   cores to make the numbers consecutive. */

	for (uint32_t i = 0; i < cpu_topo.n_sockets; ++i) {
		int spread = 0, compact = 0;
		while (cpu_topo.socket[i][spread][0] == -1)
			spread++;

		for (uint32_t c = 0; c < cpu_topo.n_cores[i]; ++c) {
			cpu_topo.socket[i][compact][0] = cpu_topo.socket[i][spread][0];
			cpu_topo.socket[i][compact][1] = cpu_topo.socket[i][spread][1];
			compact++;
			spread++;
			/* Skip gaps */
			while (cpu_topo.socket[i][spread][0] == -1)
				spread++;
		}
	}

	return 0;
}

static int bit_len_valid(uint32_t len, const char *str)
{
	if (len > 32) {
		set_errf("Maximum random length is 32, but length of '%s' is %zu\n", str, len);
		return 0;
	}
	if (len % 8) {
		plog_err("Random should be multiple of 8 long\n");
		return 0;
	}
	if (len == 0) {
		plog_err("Random should be at least 1 byte long\n");
		return 0;
	}
	return -1;
}

int parse_random_str(uint32_t *mask, uint32_t *fixed, uint32_t *len, const char *str)
{
	const size_t len_bits = strlen(str);

	if (!bit_len_valid(len_bits, str))
		return -1;

	*mask = 0;
	*fixed = 0;
	*len = len_bits / 8;

	for (uint32_t j = 0; j < len_bits; ++j) {
		/* Store in the lower bits the value of the rand string (note
		   that these are the higher bits in LE). */
		switch (str[j]) {
		case 'X':
			*mask |= 1 << (len_bits - 1 - j);
			break;
		case '1':
			*fixed |= 1 << (len_bits - 1 - j);
			break;
		case '0':
			break;
		default:
			set_errf("Unexpected %c\n", str[j]);
			return -1;
		}
	}
	return 0;
}
