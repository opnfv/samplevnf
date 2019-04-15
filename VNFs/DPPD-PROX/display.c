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

#include <curses.h>

#include <rte_cycles.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <signal.h>

#include "display_latency.h"
#include "display_mempools.h"
#include "display_ports.h"
#include "display_priority.h"
#include "display_irq.h"
#include "display_rings.h"
#include "display_pkt_len.h"
#include "display_l4gen.h"
#include "display_tasks.h"
#include "stats_irq.h"
#include "stats_prio_task.h"

#include "cqm.h"
#include "msr.h"
#include "display.h"
#include "log.h"
#include "commands.h"
#include "main.h"
#include "stats.h"
#include "stats_port.h"
#include "stats_latency.h"
#include "stats_global.h"
#include "stats_core.h"
#include "prox_cfg.h"
#include "prox_assert.h"
#include "version.h"
#include "quit.h"
#include "prox_port_cfg.h"

static struct screen_state screen_state = {
	.pps_unit = 1000,
	.chosen_screen = -1,
};

static struct display_screen *display_screens[16];
static struct display_screen *current_screen;
static size_t n_screens;
static size_t longest_title;

void display_set_pps_unit(int val)
{
	screen_state.pps_unit = val;
}

/* Set up the display mutex  as recursive. This enables threads to use
   display_[un]lock() to lock  the display when multiple  calls to for
   instance plog_info() need to be made. */
static pthread_mutex_t disp_mtx = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

static void stats_display_layout(uint8_t in_place);

void display_lock(void)
{
	pthread_mutex_lock(&disp_mtx);
}

void display_unlock(void)
{
	pthread_mutex_unlock(&disp_mtx);
}

/* Advanced text output */
static WINDOW *scr = NULL, *win_txt, *win_general, *win_cmd, *win_stat, *win_title, *win_tabs, *win_help;
static int win_txt_height = 1;
static int title_len;

static uint16_t max_n_lines;

static int cmd_cursor_pos;
static const char *cmd_cmd;
static int cmd_len;

/* Colors used in the interface */
enum colors {
	INVALID_COLOR,
	NO_COLOR,
	RED_ON_BLACK,
	BLACK_ON_CYAN,
	BLACK_ON_GREEN,
	BLACK_ON_WHITE,
	BLACK_ON_YELLOW,
	YELLOW_ON_BLACK,
	WHITE_ON_RED,
	YELLOW_ON_NOTHING,
	GREEN_ON_NOTHING,
	RED_ON_NOTHING,
	BLUE_ON_NOTHING,
	CYAN_ON_NOTHING,
	MAGENTA_ON_NOTHING,
	WHITE_ON_NOTHING,
};

int display_getch(void)
{
	int ret;

	display_lock();
	ret = wgetch(scr);
	display_unlock();

	return ret;
}

void display_cmd(const char *cmd, int cl, int cursor_pos)
{
	cmd_len = cl;
	if (cursor_pos == -1 || cursor_pos > cmd_len)
		cursor_pos = cmd_len;
	cmd_cursor_pos = cursor_pos;
	cmd_cmd = cmd;

	display_lock();
	werase(win_cmd);
	if (cursor_pos < cmd_len) {
		waddnstr(win_cmd, cmd, cursor_pos);
		wbkgdset(win_cmd, COLOR_PAIR(YELLOW_ON_BLACK));
		waddnstr(win_cmd, cmd + cursor_pos, 1);
		wbkgdset(win_cmd, COLOR_PAIR(BLACK_ON_YELLOW));
		waddnstr(win_cmd, cmd + cursor_pos + 1, cmd_len - (cursor_pos + 1));
	}
	else {
		waddnstr(win_cmd, cmd, cmd_len);
		wmove(win_cmd, cursor_pos, 0);
		wbkgdset(win_cmd, COLOR_PAIR(YELLOW_ON_BLACK));
		waddstr(win_cmd, " ");
		wbkgdset(win_cmd, COLOR_PAIR(BLACK_ON_YELLOW));
	}

	wattroff(win_stat, A_UNDERLINE);
	wrefresh(win_cmd);
	display_unlock();
}

static void refresh_cmd_win(void)
{
	display_cmd(cmd_cmd, cmd_len, cmd_cursor_pos);
}

static WINDOW *create_subwindow(int height, int width, int y_pos, int x_pos)
{
	WINDOW *win = subwin(scr, height, width, y_pos, x_pos);
	touchwin(scr);
	return win;
}

/* The limit parameter sets the last column that something can be
   printed. If characters would be printed _past_ the limit, the last
   character printed within the limit will be a '~' to signify that
   the string cut off. The limit parameter will be ignored if its
   value is -1 */
static inline int mvwaddstrv(WINDOW *win, int y, int x, int limit, const char *fmt, va_list ap)
{
	char buf[1024];
	int ret;

	ret = vsnprintf(buf, sizeof(buf), fmt, ap);
	int len = ret;

	wmove(win, y, x);
	if (x > COLS - 1) {
		return 0;
	}

	/* To prevent strings from wrapping, cut the string at the end
	   of the screen. */
	if (x + len > COLS) {
		buf[COLS - 1 - x] = 0;
		len = COLS - x;
	}

	if (limit != -1 && x + len > limit) {
		int new_len = limit - x;

		if (new_len < 0)
			return 0;
		buf[new_len] = '~';
		buf[new_len + 1] = 0;
	}

	waddstr(win, buf);
	return ret;
}

/* Format string capable [mv]waddstr() wrappers */
__attribute__((format(printf, 4, 5))) static inline int mvwaddstrf(WINDOW* win, int y, int x, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = mvwaddstrv(win, y, x, -1, fmt, ap);
	va_end(ap);
	return ret;
}

__attribute__((format(printf, 5, 6))) static inline int mvwaddstrf_limit(WINDOW* win, int y, int x, int limit, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = mvwaddstrv(win, y, x, limit, fmt, ap);
	va_end(ap);
	return ret;
}

// red: link down; Green: link up
static short link_color(const uint8_t if_port)
{
	return COLOR_PAIR(prox_port_cfg[if_port].link_up? GREEN_ON_NOTHING : RED_ON_NOTHING);
}

static void (*ncurses_sigwinch)(int);

static void sigwinch(int in)
{
	if (ncurses_sigwinch)
		ncurses_sigwinch(in);
	refresh();
	stats_display_layout(0);
}

static void set_signal_handler(void)
{
	struct sigaction old;

	sigaction(SIGWINCH, NULL, &old);
	ncurses_sigwinch = old.sa_handler;

	signal(SIGWINCH, sigwinch);
}

void display_column_port_ring(const struct display_column *display_column, int row, struct port_queue *ports, int port_count, struct rte_ring **rings, int ring_count)
{
	if (row >= max_n_lines)
		return;

	int pos = display_column->offset;
	int limit = pos + display_column->width;

	for (int i = 0; i < port_count && pos < limit; i++) {
		wbkgdset(win_stat, link_color(ports[i].port));
		pos += mvwaddstrf_limit(win_stat, row + 2, pos, limit, "%u", ports[i].port);
		wbkgdset(win_stat, COLOR_PAIR(NO_COLOR));

		if (i != port_count - 1)
			pos += mvwaddstrf_limit(win_stat, row + 2, pos, limit, " ");
	}

	for (uint8_t ring_id = 0; ring_id < ring_count && pos < limit; ++ring_id) {
		pos += mvwaddstrf_limit(win_stat, row + 2, pos, limit, "%s", rings[ring_id]->name);
	}
}

static void display_add_screen(struct display_screen *screen)
{
	display_screens[n_screens++] = screen;
	if (longest_title < strlen(screen->title))
		longest_title = strlen(screen->title);
}

static void display_init_screens(void)
{
	if (n_screens)
		return;

	display_add_screen(display_tasks());
	display_add_screen(display_ports());
	display_add_screen(display_mempools());
	display_add_screen(display_latency());
	display_add_screen(display_rings());
	display_add_screen(display_l4gen());
	display_add_screen(display_pkt_len());
	if (stats_get_n_prio_tasks_tot())
		display_add_screen(display_priority());
	if (stats_get_n_irq_tasks())
		display_add_screen(display_irq());
}

void display_init(void)
{
	scr = initscr();
	start_color();
	/* Assign default foreground/background colors to color number -1 */
	use_default_colors();

	init_pair(NO_COLOR,   -1,  -1);
	init_pair(RED_ON_BLACK,     COLOR_RED,  COLOR_BLACK);
	init_pair(BLACK_ON_CYAN,   COLOR_BLACK,  COLOR_CYAN);
	init_pair(BLACK_ON_GREEN,  COLOR_BLACK,  COLOR_GREEN);
	init_pair(BLACK_ON_WHITE,  COLOR_BLACK,  COLOR_WHITE);
	init_pair(BLACK_ON_YELLOW, COLOR_BLACK,  COLOR_YELLOW);
	init_pair(YELLOW_ON_BLACK, COLOR_YELLOW,  COLOR_BLACK);
	init_pair(WHITE_ON_RED,    COLOR_WHITE,  COLOR_RED);
	init_pair(YELLOW_ON_NOTHING,   COLOR_YELLOW,  -1);
	init_pair(GREEN_ON_NOTHING,   COLOR_GREEN,  -1);
	init_pair(RED_ON_NOTHING,   COLOR_RED,  -1);
	init_pair(BLUE_ON_NOTHING,  COLOR_BLUE, -1);
	init_pair(CYAN_ON_NOTHING,  COLOR_CYAN, -1);
	init_pair(MAGENTA_ON_NOTHING,  COLOR_MAGENTA, -1);
	init_pair(WHITE_ON_NOTHING,  COLOR_WHITE, -1);
	/* nodelay(scr, TRUE); */
	noecho();
	curs_set(0);
	/* Create fullscreen log window. When stats are displayed
	   later, it is recreated with appropriate dimensions. */
	win_txt = create_subwindow(0, 0, 0, 0);
	wbkgd(win_txt, COLOR_PAIR(0));

	idlok(win_txt, FALSE);
	/* Get scrolling */
	scrollok(win_txt, TRUE);
	/* Leave cursor where it was */
	leaveok(win_txt, TRUE);

	refresh();

	set_signal_handler();

	max_n_lines = (LINES - 5 - 2 - 3);
	/* core_port_height = max_n_lines < stats_get_n_tasks_tot()? max_n_lines : stats_get_n_tasks_tot(); */

	display_init_screens();
	display_screen(0);
	stats_display_layout(0);
}

static void display_page_recalc_offsets(struct display_page *display_page)
{
	struct display_table *table;
	struct display_column *col;
	int total_offset = 0;

	for (int i = 0; i < display_page->n_tables; ++i) {
		table = &display_page->tables[i];

		if (i != 0)
			total_offset += 1;
		table->offset = total_offset;
		for (int j = 0; j < table->n_cols; ++j) {
			col = &table->cols[j];
			col->offset = total_offset;
			if (j + 1 != table->n_cols)
				total_offset += 1;
			total_offset += col->width;
		}
		table->width = total_offset - table->offset;
	}
}

void display_page_init(struct display_page *display_page)
{
	struct display_table *table;
	struct display_column *col;
	int table_width = 0;
	int table_offset = 0;

	memset(display_page, 0, sizeof(*display_page));
	display_page->n_tables = 0;
	for (size_t i = 0; i < sizeof(display_page->tables)/sizeof(display_page->tables[0]); ++i) {
		table = &display_page->tables[i];
		for (size_t j = 0; j < sizeof(table->cols)/sizeof(table->cols[0]); ++j) {
			col = &table->cols[j];
			col->display_page = display_page;
		}
	}
}

struct display_table *display_page_add_table(struct display_page *display_page)
{
	struct display_table *table = &display_page->tables[display_page->n_tables];

	display_page->n_tables++;
	return table;
}

void display_table_init(struct display_table *table, const char *title)
{
	strcpy(table->title, title);
	table->n_cols = 0;
}

struct display_column *display_table_add_col(struct display_table *table)
{
	struct display_column *col = &table->cols[table->n_cols];

	table->n_cols++;
	return col;
}

void display_column_init(struct display_column *display_column, const char *title, unsigned width)
{
	if (width < strlen(title))
		width = strlen(title);

	strcpy(display_column->title, title);
	display_column->width = width;
	display_page_recalc_offsets(display_column->display_page);
}

int display_column_get_width(const struct display_column *display_column)
{
	return display_column->width;
}

void display_page_draw_frame(const struct display_page *display_page, int height)
{
	const struct display_table *table;
	const struct display_column *col;

	wattron(win_stat, A_BOLD);
	wbkgdset(win_stat, COLOR_PAIR(YELLOW_ON_NOTHING));

	for (int i = 0; i < display_page->n_tables; ++i) {
		table = &display_page->tables[i];

		if (i != 0)
			mvwvline(win_stat, 0, table->offset - 1,  ACS_VLINE, height + 2);

		mvwaddstrf(win_stat, 0, table->offset + table->width / 2 - strlen(table->title) / 2, "%s", table->title);
		for (int j = 0; j < table->n_cols; ++j) {
			col = &table->cols[j];

			if (j != 0)
				mvwvline(win_stat, 1, col->offset - 1, ACS_VLINE, height + 1);
			mvwaddstrf(win_stat, 1, col->offset + col->width / 2 - strlen(col->title) / 2, "%s", col->title);
		}

		if (i + 1 == display_page->n_tables)
			mvwvline(win_stat, 0, table->offset + table->width,  ACS_VLINE, height + 2);
	}
	wbkgdset(win_stat, COLOR_PAIR(NO_COLOR));
	wattroff(win_stat, A_BOLD);
}

void display_column_print(const struct display_column *display_column, int row, const char *fmt, ...)
{
	if (row >= max_n_lines)
		return;

	va_list ap;
	char buffer[128] = {0};
	char *to_print = buffer + 64;

	va_start(ap, fmt);
	int len = vsnprintf(to_print, sizeof(buffer) - 64, fmt, ap);
	va_end(ap);

	int offset = 0;
	/* If column is too long, add ~ at the end. If it is too
	   short, align on the right. */
	if (len > display_column->width) {
		to_print[display_column->width - 1] = '~';
		to_print[display_column->width] = '\0';
	} else {
		int diff = display_column->width - len;

		to_print += len;
		to_print -= display_column->width;
		for (int i = 0; i < diff; i++)
			to_print[i] = ' ';
	}

	mvwaddstrf(win_stat, row + 2, display_column->offset, "%s", to_print);
}

void display_column_print_core_task(const struct display_column *display_column, int row, struct lcore_cfg *lconf, struct task_args *targ)
{
	if (row >= max_n_lines)
		return;

	if (lconf->n_tasks_run == 0) {
		wattron(win_stat, A_BOLD);
		wbkgdset(win_stat, COLOR_PAIR(RED_ON_NOTHING));
	}
	if (targ->id == 0)
		mvwaddstrf(win_stat, row + 2, display_column->offset, "%2u/", lconf->id);
	if (lconf->n_tasks_run == 0) {
		wattroff(win_stat, A_BOLD);
		wbkgdset(win_stat, COLOR_PAIR(NO_COLOR));
	}
	if (!lconf_task_is_running(lconf, targ->id)) {
		wattron(win_stat, A_BOLD);
		wbkgdset(win_stat, COLOR_PAIR(RED_ON_NOTHING));
	}
	mvwaddstrf(win_stat, row + 2, display_column->offset + 3, "%1u", targ->id);
	if (!lconf_task_is_running(lconf, targ->id)) {
		wattroff(win_stat, A_BOLD);
		wbkgdset(win_stat, COLOR_PAIR(NO_COLOR));
	}
}

static void redraw_tabs(unsigned screen_id)
{
	const size_t len = longest_title + 1;

	for (size_t i = 0; i < n_screens; ++i) {
		if (i == screen_id)
			wbkgdset(win_tabs, COLOR_PAIR(BLACK_ON_GREEN));

		mvwaddstrf(win_tabs, 0, i*(len + 3), "%zu ", i+1);
		if (i != screen_id)
			wbkgdset(win_tabs, COLOR_PAIR(GREEN_ON_NOTHING));
		mvwaddstrf(win_tabs, 0, i*(len + 3) + 2, "%s", display_screens[i]->title);
		for (size_t j = strlen(display_screens[i]->title); j < len - 1; ++j)
			mvwaddstrf(win_tabs, 0, i*(len + 3) + 2 + j, " ");
		if (i != screen_id)
			wbkgdset(win_tabs, COLOR_PAIR(NO_COLOR));
		if (i == screen_id)
			wbkgdset(win_tabs, COLOR_PAIR(NO_COLOR));
	}

	wrefresh(win_tabs);
}

static void draw_title(void)
{
	char title_str[128];

	snprintf(title_str, sizeof(title_str), "%s %s: %s", PROGRAM_NAME, VERSION_STR(), prox_cfg.name);

	wbkgd(win_title, COLOR_PAIR(BLACK_ON_GREEN));
	title_len = strlen(title_str);
	mvwaddstrf(win_title, 0, (COLS - title_len)/2, "%s", title_str);

	redraw_tabs(screen_state.chosen_screen);
}

static void draw_general_frame(void)
{
	if (screen_state.toggle == 0) {
		wattron(win_general, A_BOLD);
		wbkgdset(win_general, COLOR_PAIR(MAGENTA_ON_NOTHING));
		mvwaddstrf(win_general, 0, 9, "rx:         tx:          diff:                     rx:          tx:                        %%:");
		mvwaddstrf(win_general, 1, 9, "rx:         tx:          err:                      rx:          tx:          err:          %%:");
		wbkgdset(win_general, COLOR_PAIR(NO_COLOR));

		wbkgdset(win_general, COLOR_PAIR(BLUE_ON_NOTHING));
		mvwaddstrf(win_general, 0, 0, "Host pps ");
		mvwaddstrf(win_general, 1, 0, "NICs pps ");

		wbkgdset(win_general, COLOR_PAIR(CYAN_ON_NOTHING));
		mvwaddstrf(win_general, 0, 56, "avg");
		mvwaddstrf(win_general, 1, 56, "avg");
		wbkgdset(win_general, COLOR_PAIR(NO_COLOR));
		wattroff(win_general, A_BOLD);
	} else {
		wattron(win_general, A_BOLD);
		wbkgdset(win_general, COLOR_PAIR(BLUE_ON_NOTHING));
		mvwaddstrf(win_general, 0, 9, "rx:                   tx:                   rx-tx:                      tx/rx:            rx/tx:");
		mvwaddstrf(win_general, 1, 9, "rx:                   tx:                   err:                        tx/rx:            rx/tx:");
		wbkgdset(win_general, COLOR_PAIR(NO_COLOR));

		wbkgdset(win_general, COLOR_PAIR(CYAN_ON_NOTHING));
		mvwaddstrf(win_general, 0, 0, "Host tot ");
		mvwaddstrf(win_general, 1, 0, "NICs tot ");
		wattroff(win_general, A_BOLD);
	}
}

static void draw_status_bar(void)
{
	wbkgd(win_help, COLOR_PAIR(BLACK_ON_WHITE));
	werase(win_help);
	mvwaddstrf(win_help, 0, 0,
		   "Enter 'help' or command, <ESC> or 'quit' to exit, "
		   "1-%zu to switch screens and 0 to reset stats, '=' to toggle between per-sec and total stats",
		   n_screens);
	wrefresh(win_help);
	mvwin(win_help, LINES - 1, 0);
}

static void draw_log_window(void)
{
	idlok(win_txt, FALSE);
	/* Get scrolling */
	scrollok(win_txt, TRUE);

	/* Leave cursor where it was */
	leaveok(win_txt, TRUE);
	wbkgd(win_txt, COLOR_PAIR(BLACK_ON_CYAN));
	wrefresh(win_txt);
}

static void stats_display_layout(uint8_t in_place)
{
	uint8_t cur_stats_height;

	cur_stats_height = current_screen->get_height();
	cur_stats_height = cur_stats_height > max_n_lines? max_n_lines: cur_stats_height;

	display_lock();
	if (!in_place) {
		// moving existing windows does not work
		delwin(win_txt);
		delwin(win_general);
		delwin(win_title);
		delwin(win_tabs);
		delwin(win_cmd);
		delwin(win_txt);
		delwin(win_help);

		clear();
	}

	if (!in_place) {
		win_stat = create_subwindow(cur_stats_height + 2, 0, 4, 0);
		win_tabs = create_subwindow(1, 0, 1, 0);
		win_general = create_subwindow(2, 0, 2, 0);
		win_title = create_subwindow(1, 0, 0, 0);
		win_cmd = create_subwindow(1, 0, cur_stats_height + 2 + 4,  0);
		win_txt_height = LINES - cur_stats_height - 2 - 3 - 3;
		win_txt = create_subwindow(win_txt_height, 0, cur_stats_height + 4 + 3, 0);
		win_help = create_subwindow(1, 0, LINES - 1, 0);
	}

	draw_title();
	draw_general_frame();
	/* Command line */
	wbkgd(win_cmd, COLOR_PAIR(BLACK_ON_YELLOW));
	idlok(win_cmd, FALSE);
	/* Move cursor at insertion point */
	leaveok(win_cmd, FALSE);

	draw_status_bar();
	draw_log_window();

	/* Draw everything to the screen */
	refresh();
	current_screen->draw_frame(&screen_state);
	display_unlock();

	refresh_cmd_win();
	display_stats();
}

void display_end(void)
{
	pthread_mutex_destroy(&disp_mtx);

	if (scr != NULL) {
		endwin();
	}
}

static void pps_print(WINDOW *dst_scr, int y, int x, uint64_t val, int is_blue)
{
	uint64_t rx_pps_disp = val;
	uint64_t rx_pps_disp_frac = 0;
	uint32_t ten_pow3 = 0;
	static const char *units = " KMG";
	char rx_unit = ' ';

	while (rx_pps_disp > 1000) {
		rx_pps_disp /= 1000;
		rx_pps_disp_frac = (val - rx_pps_disp*1000) / 10;
		val /= 1000;
		ten_pow3++;
	}

	if (ten_pow3 >= strlen(units)) {
		wbkgdset(dst_scr, COLOR_PAIR(RED_ON_NOTHING));
		mvwaddstrf(dst_scr, y, x, "---");
		wbkgdset(dst_scr, COLOR_PAIR(NO_COLOR));
		return;
	}

	rx_unit = units[ten_pow3];

	wattron(dst_scr, A_BOLD);
	if (is_blue) {
		wbkgdset(dst_scr, COLOR_PAIR(BLUE_ON_NOTHING));
	}
	else
		wbkgdset(dst_scr, COLOR_PAIR(CYAN_ON_NOTHING));

	mvwaddstrf(dst_scr, y, x, "%3lu", rx_pps_disp);
	if (rx_unit != ' ') {
		mvwaddstrf(dst_scr, y, x + 3, ".%02lu", rx_pps_disp_frac);
		wattroff(dst_scr, A_BOLD);
		wbkgdset(dst_scr, COLOR_PAIR(WHITE_ON_NOTHING));
		wattron(dst_scr, A_BOLD);
		mvwaddstrf(dst_scr, y, x + 6, "%c", rx_unit);
		wattroff(dst_scr, A_BOLD);
		wbkgdset(dst_scr, COLOR_PAIR(NO_COLOR));
	}
	else {
		mvwaddstrf(dst_scr, y, x + 3, "    ");
	}
	wattroff(dst_scr, A_BOLD);
	wbkgdset(dst_scr, COLOR_PAIR(NO_COLOR));
}

static void display_stats_general_per_sec(void)
{
	struct global_stats_sample *gsl = stats_get_global_stats(1);
	struct global_stats_sample *gsp = stats_get_global_stats(0);

	uint64_t rx_pps = val_to_rate(gsl->host_rx_packets - gsp->host_rx_packets, gsl->tsc - gsp->tsc);
	uint64_t tx_pps = val_to_rate(gsl->host_tx_packets - gsp->host_tx_packets, gsl->tsc - gsp->tsc);
	/* Host: RX, TX, Diff */
	pps_print(win_general, 0, 12, rx_pps, 1);
	pps_print(win_general, 0, 25, tx_pps, 1);

	uint64_t diff = 0;
	if (rx_pps > tx_pps)
		diff = rx_pps - tx_pps;
	pps_print(win_general, 0, 40, diff, 1);

	uint64_t nics_rx_pps = val_to_rate(gsl->nics_rx_packets - gsp->nics_rx_packets, gsl->tsc - gsp->tsc);
	uint64_t nics_tx_pps = val_to_rate(gsl->nics_tx_packets - gsp->nics_tx_packets, gsl->tsc - gsp->tsc);
	uint64_t nics_ierrors = val_to_rate(gsl->nics_ierrors - gsp->nics_ierrors, gsl->tsc - gsp->tsc);
	uint64_t nics_imissed = val_to_rate(gsl->nics_imissed - gsp->nics_imissed, gsl->tsc - gsp->tsc);

	/* NIC: RX, TX, Diff */
	pps_print(win_general, 1, 12, nics_rx_pps, 1);
	pps_print(win_general, 1, 25, nics_tx_pps, 1);
	pps_print(win_general, 1, 40, nics_ierrors + nics_imissed, 1);

	wbkgdset(win_general, COLOR_PAIR(CYAN_ON_NOTHING));
	wattron(win_general, A_BOLD);
	mvwaddstrf(win_general, 0, 103, "%6.2f", tx_pps > rx_pps? 100 : tx_pps * 100.0 / rx_pps);
	wattroff(win_general, A_BOLD);
	wbkgdset(win_general, COLOR_PAIR(NO_COLOR));

	struct global_stats_sample *gsb = stats_get_global_stats_beg();
	if (gsb) {
		uint64_t rx_pps = val_to_rate(gsl->host_rx_packets - gsb->host_rx_packets, gsl->tsc - gsb->tsc);
		uint64_t tx_pps = val_to_rate(gsl->host_tx_packets - gsb->host_tx_packets, gsl->tsc - gsb->tsc);

		uint64_t nics_rx_pps = val_to_rate(gsl->nics_rx_packets - gsb->nics_rx_packets, gsl->tsc - gsb->tsc);
		uint64_t nics_tx_pps = val_to_rate(gsl->nics_tx_packets - gsb->nics_tx_packets, gsl->tsc - gsb->tsc);
		uint64_t nics_ierrors = val_to_rate(gsl->nics_ierrors - gsb->nics_ierrors, gsl->tsc - gsb->tsc);
		uint64_t nics_imissed = val_to_rate(gsl->nics_imissed - gsb->nics_imissed, gsl->tsc - gsb->tsc);

		pps_print(win_general, 0, 64, rx_pps, 0);
		pps_print(win_general, 0, 77, tx_pps, 0);

		pps_print(win_general, 1, 64, nics_rx_pps, 0);
		pps_print(win_general, 1, 77, nics_tx_pps, 0);
		pps_print(win_general, 1, 91, nics_ierrors + nics_imissed, 0);

		wbkgdset(win_general, COLOR_PAIR(CYAN_ON_NOTHING));
		wattron(win_general, A_BOLD);
		uint64_t nics_in = gsl->host_rx_packets - gsb->host_rx_packets + gsl->nics_ierrors - gsb->nics_ierrors + gsl->nics_imissed - gsb->nics_imissed;
		uint64_t nics_out = gsl->host_tx_packets - gsb->host_tx_packets;
		mvwaddstrf(win_general, 1, 103, "%6.2f", nics_out > nics_in?
			   100 : nics_out * 100.0 / nics_in);
		wattron(win_general, A_BOLD);
		wbkgdset(win_general, COLOR_PAIR(NO_COLOR));
	}
}

static void display_stats_general_total(void)
{
	struct global_stats_sample *gsl = stats_get_global_stats(1);

	int64_t diff = (int64_t)gsl->host_rx_packets - gsl->host_tx_packets;
	uint32_t percent;

	/* Host: RX, TX, Diff */
	mvwaddstrf(win_general, 0, 13, "%16lu", gsl->host_rx_packets);
	mvwaddstrf(win_general, 0, 35, "%16lu", gsl->host_tx_packets);
	mvwaddstrf(win_general, 0, 60, "%16"PRId64"", diff);
	if (gsl->host_rx_packets == 0)
		percent = 1000000;
	else
		percent = gsl->host_tx_packets * 1000000 / gsl->host_rx_packets;
	mvwaddstrf(win_general, 0, 88, "%3u.%04u%%", percent / 10000, percent % 10000);
	if (gsl->host_tx_packets == 0)
		percent = 1000000;
	else
		percent = gsl->host_rx_packets * 1000000 / gsl->host_tx_packets;
	mvwaddstrf(win_general, 0, 106, "%3u.%04u%%", percent / 10000, percent % 10000);

	mvwaddstrf(win_general, 1, 13, "%16lu", gsl->nics_rx_packets);
	mvwaddstrf(win_general, 1, 35, "%16lu", gsl->nics_tx_packets);
	mvwaddstrf(win_general, 1, 60, "%16lu", gsl->nics_ierrors + gsl->nics_imissed);
	if (gsl->nics_rx_packets == 0)
		percent = 1000000;
	else
		percent = gsl->nics_tx_packets * 1000000 / gsl->nics_rx_packets;
	mvwaddstrf(win_general, 1, 88, "%3u.%04u%%", percent / 10000, percent % 10000);
	if (gsl->nics_tx_packets == 0)
		percent = 1000000;
	else
		percent = gsl->nics_rx_packets * 1000000 / gsl->nics_tx_packets;
	mvwaddstrf(win_general, 1, 106, "%3u.%04u%%", percent / 10000, percent % 10000);
}

static void display_stats_general(void)
{
	/* moment when stats were gathered. */
	uint64_t cur_tsc = stats_get_last_tsc();
	uint64_t up_time = tsc_to_sec(cur_tsc - stats_global_start_tsc());
	uint64_t up_time2 = tsc_to_sec(cur_tsc - stats_global_beg_tsc());
	uint64_t rem_time = -1;
	char title_str[128] = {0};

	if (stats_global_end_tsc()) {
		uint64_t rem_tsc = stats_global_end_tsc() > cur_tsc? stats_global_end_tsc() - cur_tsc : 0;

		rem_time = tsc_to_sec(rem_tsc);
	}

	if (up_time != up_time2 && cur_tsc >= stats_global_beg_tsc()) {
		if (stats_global_end_tsc())
			snprintf(title_str, sizeof(title_str), "%5lu (%lu) up, %lu rem", up_time, up_time2, rem_time);
		else
			snprintf(title_str, sizeof(title_str), "%5lu (%lu) up", up_time, up_time2);
	}
	else {
		if (stats_global_end_tsc())
			snprintf(title_str, sizeof(title_str), "%5lu up, %lu rem", up_time, rem_time);
		else
			snprintf(title_str, sizeof(title_str), "%5lu up", up_time);
	}

	/* Only print up time information if there is enough space */
	if ((int)((COLS + title_len)/2 + strlen(title_str) + 1) < COLS) {
		mvwaddstrf(win_title, 0, COLS - strlen(title_str), "%s", title_str);
		wrefresh(win_title);
	}

	if (screen_state.toggle == 0)
		display_stats_general_per_sec();
	else
		display_stats_general_total();

	wrefresh(win_general);
}

char *print_time_unit_err_usec(char *dst, struct time_unit_err *t)
{
	uint64_t nsec_total = time_unit_to_nsec(&t->time);

	uint64_t usec = nsec_total/1000;
	uint64_t nsec = nsec_total - usec*1000;

	uint64_t nsec_total_error = time_unit_to_nsec(&t->error);

	uint64_t usec_error = nsec_total_error/1000;
	uint64_t nsec_error = nsec_total_error - usec_error*1000;

	sprintf(dst, "%4"PRIu64".%03"PRIu64" +/- %2"PRIu64".%03"PRIu64"", usec, nsec, usec_error, nsec_error);
	return dst;
}

char *print_time_unit_usec(char *dst, struct time_unit *t)
{
	uint64_t nsec_total = time_unit_to_nsec(t);

	uint64_t usec = nsec_total/1000;
	uint64_t nsec = nsec_total - usec*1000;

	sprintf(dst, "%4"PRIu64".%03"PRIu64"", usec, nsec);
	return dst;
}

void toggle_display_screen(void)
{
	screen_state.toggle = !screen_state.toggle;
	stats_display_layout(0);
}

void display_screen(unsigned screen_id)
{
	if (screen_id >= n_screens) {
		plog_err("Unsupported screen %d\n", screen_id + 1);
		return;
	}

	if (screen_state.chosen_screen == screen_id) {
		stats_display_layout(1);
	}
	else {
		screen_state.chosen_screen = screen_id;
		current_screen = display_screens[screen_id];
		stats_display_layout(0);
	}
}

void display_page_up(void)
{
}

void display_page_down(void)
{
}

void display_refresh(void)
{
	stats_display_layout(1);
}

void display_stats(void)
{
	display_lock();
	current_screen->draw_stats(&screen_state);
	display_stats_general();
	wrefresh(win_stat);
	display_unlock();
}

static char pages[32768] = {0};
static int cur_idx = 0;
static size_t pages_len = 0;

void display_print_page(void)
{
	int n_lines = 0;
	int cur_idx_prev = cur_idx;

	if (cur_idx >= (int)pages_len) {
		return;
	}

	display_lock();
	for (size_t i = cur_idx; i < pages_len; ++i) {
		if (pages[i] == '\n') {
			n_lines++;
			if (n_lines == win_txt_height - 2) {
				pages[i] = 0;
				cur_idx = i + 1;
				break;
			}
		}
	}

	waddstr(win_txt, pages + cur_idx_prev);
	if (cur_idx != cur_idx_prev && cur_idx < (int)pages_len)
		waddstr(win_txt, "\nPRESS ENTER FOR MORE...\n");
	else {
		pages_len = 0;
	}
	wrefresh(win_txt);
	display_unlock();
}

void display_print(const char *str)
{
	display_lock();

	if (scr == NULL) {
		fputs(str, stdout);
		fflush(stdout);
		display_unlock();
		return;
	}

	/* Check if the whole string can fit on the screen. */
	pages_len = strlen(str);
	int n_lines = 0;
	memset(pages, 0, sizeof(pages));
	memcpy(pages, str, pages_len);
	cur_idx = 0;
	for (size_t i = 0; i < pages_len; ++i) {
		if (pages[i] == '\n') {
			n_lines++;
			if (n_lines == win_txt_height - 2) {
				pages[i] = 0;
				cur_idx = i + 1;
				break;
			}
		}
	}

	waddstr(win_txt, pages);
	if (cur_idx != 0)
		waddstr(win_txt, "\nPRESS ENTER FOR MORE...\n");
	else
		pages_len = 0;

	wrefresh(win_txt);
	display_unlock();
}
