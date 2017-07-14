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

#ifndef _DISPLAY_H_
#define _DISPLAY_H_

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>

#include "display_latency.h"
#include "stats_cons.h"
#include "clock.h"

struct display_column {
	char title[32];
	int  offset;
	int  width;
	struct display_page *display_page;
};

struct display_table {
	struct display_column cols[16];
	char title[32];
	int n_cols;
	int offset;
	int width;
};

struct display_page {
	struct display_table tables[8];
	int n_tables;
	int width;
};

struct screen_state {
	unsigned chosen_screen;
	unsigned chosen_page;
	int toggle;
	int pps_unit;
};

struct display_screen {
	void (*draw_frame)(struct screen_state *screen_state);
	void (*draw_stats)(struct screen_state *screen_state);
	int (*get_height)(void);
	const char *title;
};

void display_set_pps_unit(int val);

struct lcore_cfg;
struct task_args;

void display_page_draw_frame(const struct display_page *display_page, int height);
int display_column_get_width(const struct display_column *display_column);
void display_column_init(struct display_column *display_column, const char *title, unsigned width);
struct display_column *display_table_add_col(struct display_table *table);
void display_table_init(struct display_table *table, const char *title);
struct display_table *display_page_add_table(struct display_page *display_page);
void display_page_init(struct display_page *display_page);
__attribute__((format(printf, 3, 4))) void display_column_print(const struct display_column *display_column, int row, const char *fmt, ...);
void display_column_print_core_task(const struct display_column *display_column, int row, struct lcore_cfg *lconf, struct task_args *targ);
void display_column_print_number(const struct display_column *display_column, int row, uint64_t number);

char *print_time_unit_err_usec(char *dst, struct time_unit_err *t);
char *print_time_unit_usec(char *dst, struct time_unit *t);
struct port_queue;
struct rte_ring;
void display_column_port_ring(const struct display_column *display_column, int row, struct port_queue *ports, int port_count, struct rte_ring **rings, int ring_count);

void display_init(void);
void display_end(void);
void display_stats(void);
void display_refresh(void);
void display_print(const char *str);
void display_cmd(const char *cmd, int cmd_len, int cursor_pos);
void display_screen(unsigned screen_id);
void toggle_display_screen(void);
void display_page_up(void);
void display_page_down(void);
void display_print_page(void);
void display_lock(void);
void display_unlock(void);

int display_getch(void);

static struct stats_cons display = {
	.init    = display_init,
	.notify  = display_stats,
	.refresh = display_refresh,
	.finish  = display_end,
	.flags   = STATS_CONS_F_ALL,
};

#endif /* _DISPLAY_H_ */
