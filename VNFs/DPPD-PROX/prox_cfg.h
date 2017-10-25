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

#ifndef _PROX_CFG_H
#define _PROX_CFG_H

#include <inttypes.h>

#include "prox_globals.h"

#define PROX_CM_STR_LEN (2 + 2 * sizeof(prox_cfg.core_mask) + 1)
#define PROX_CM_DIM     (RTE_MAX_LCORE/(sizeof(uint64_t) * 8))

#define DSF_AUTOSTART             0x00000001      /* start all cores automatically */
#define DSF_CHECK_INIT            0x00000002      /* check initialization sequence and exit */
#define DSF_CHECK_SYNTAX          0x00000004      /* check configuration file syntax and exit */
#define DSF_SHUFFLE               0x00000008      /* shuffle memory addresses within memory pool */
#define DSF_WAIT_ON_QUIT          0x00000010      /* wait for all cores to stop before exiting */
#define DSF_LISTEN_TCP            0x00000020      /* Listen on TCP port 8474 for input */
#define DSF_LISTEN_UDS            0x00000040      /* Listen on /tmp/prox.sock for input */
#define DSF_DAEMON                0x00000080      /* Run process as Daemon */
#define UNIQUE_MEMPOOL_PER_SOCKET 0x00000100      /* Use Only one mempool per socket, shared between all cores on that socket */
#define DSF_KEEP_SRC_MAC          0x00000200      /* In gen mode, do not overwrite src_mac by mac of physical port */
#define DSF_MP_RINGS              0x00000400      /* Use Multi Producer rings when possible */
#define DSF_USE_DUMMY_DEVICES     0x00000800      /* Instead of relying on real PCI devices, create null devices instead */
#define DSF_USE_DUMMY_CPU_TOPO    0x00001000      /* Instead of relying on the cpu topology, load a cpu toplogy that will work with all cfgs. */
#define DSF_DISABLE_CMT           0x00002000      /* CMT disabled */
#define DSF_LIST_TASK_MODES       0x00004000      /* list supported task modes and exit */
#define DSF_ENABLE_BYPASS         0x00008000      /* Use Multi Producer rings to enable ring bypass */
#define DSF_CTRL_PLANE_ENABLED    0x00010000      /* ctrl plane enabled */

#define MAX_PATH_LEN 1024

enum prox_ui {
	PROX_UI_CURSES,
	PROX_UI_CLI,
	PROX_UI_NONE,
};

struct prox_cfg {
	enum prox_ui    ui;             /* By default, curses is used as a UI. */
	char            update_interval_str[16];
	int             use_stats_logger;
	uint32_t	flags;		/* TGSF_* flags above */
	uint32_t	master;		/* master core to run user interface on */
	uint64_t        core_mask[PROX_CM_DIM]; /* Active cores without master core */
	uint32_t	start_time;	/* if set (not 0), average pps will be calculated starting after start_time seconds */
	uint32_t	duration_time;      /* if set (not 0), prox will exit duration_time seconds after start_time */
	char            name[MAX_NAME_SIZE];
	uint8_t         log_name_pid;
	char            log_name[MAX_PATH_LEN];
	int32_t         cpe_table_ports[PROX_MAX_PORTS];
	uint32_t	logbuf_size;
	uint32_t	logbuf_pos;
	char		*logbuf;
};

extern struct prox_cfg prox_cfg;

int prox_core_active(const uint32_t lcore_id, const int with_master);

/* Returns non-zero if supplied lcore_id is the last active core. The
   first core can be found by setting *lcore_id == -1. The function is
   indented to be used as an interator. */
int prox_core_next(uint32_t *lcore_id, const int with_master);

int prox_core_to_hex(char *dst, const size_t size, const int with_master);

int prox_core_to_str(char *dst, const size_t size, const int with_master);

void prox_core_clr(void);

int prox_core_set_active(const uint32_t lcore_id);

#endif /* __PROX_CFG_H_ */
