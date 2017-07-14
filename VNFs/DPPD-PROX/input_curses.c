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
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "log.h"
#include "input.h"
#include "display.h"
#include "run.h"
#include "cmd_parser.h"
#include "input_curses.h"
#include "histedit.h"

static EditLine *el;
static History *hist;

static struct input input_curses;
static int tabbed;

static void show_history(struct input *input)
{
	HistEvent event;

	history(hist, &event, H_LAST);

	do {
		plog_info("%s", event.str); /* event.str contains newline */
	} while (history(hist, &event, H_PREV) != -1);
}

static int complete(__attribute__((unused)) int ch)
{
	const LineInfo *li;
	size_t len;
	size_t n_match = 0;
	char complete_cmd[128] = {0};
	int complete_cmd_partial = 0;

	li = el_line(el);
	for (size_t i = 0; i < cmd_parser_n_cmd(); ++i) {
		len = li->lastchar - li->buffer;
		if (strncmp(cmd_parser_cmd(i), li->buffer, len) == 0) {
			if (n_match) {
				size_t cur_len = strlen(complete_cmd);
				for (size_t j = 0; j < cur_len; ++j) {
					if (complete_cmd[j] != cmd_parser_cmd(i)[j]) {
						complete_cmd[j] = 0;
						complete_cmd_partial = 1;
						break;
					}
				}
			}
			else {
				strcpy(complete_cmd, cmd_parser_cmd(i));
			}

			n_match++;
		}
	}

	/* Complete only if there are more characters known than
	   currently entered. */
	if (n_match && len < strlen(complete_cmd)) {
		el_deletestr(el, li->cursor - li->buffer);
		el_insertstr(el, complete_cmd);
		if (!complete_cmd_partial)
			el_insertstr(el, " ");

		return CC_REDISPLAY;
	}
	else if (tabbed) {
		int printed = 0;
		for (size_t i = 0; i < cmd_parser_n_cmd(); ++i) {
			len = li->lastchar - li->buffer;
			if (strncmp(cmd_parser_cmd(i), li->buffer, len) == 0) {
				plog_info("%-23s", cmd_parser_cmd(i));
				printed++;
			}
			if (printed == 4) {
				printed = 0;
				plog_info("\n");
			}
		}
		if (printed)
			plog_info("\n");
	}
	else {
		tabbed = 1;
	}

	return CC_REDISPLAY;
}

/* Returns non-zero if stdin is readable */
static int peek_stdin(void)
{
	int tmp;
	fd_set in_fd;
	struct timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = 10000;

	FD_ZERO(&in_fd);
	FD_SET(fileno(stdin), &in_fd);
	tmp = select(fileno(stdin) + 1, &in_fd, NULL, NULL, &tv);
	return FD_ISSET(fileno(stdin), &in_fd);
}

static int get_char(EditLine *e, char *c)
{
	*c = display_getch();

	/* If no characters have been entered, number keys switch the
	   screen and '0' resets stats. This is provided as a
	   fall-back in case F-keys do not function. The keys are
	   intercepted before returning control to libedit. */
	if (*c >= '0' && *c <= '9') {
		const LineInfo *li;

		li = el_line(e);
		if (li->lastchar == li->buffer) {
			if (*c >= '1') {
				display_screen(*c - '0' - 1);
				return 0;
			}
			else {
				cmd_parser_parse("reset stats", &input_curses);
				return 0;
			}
		}
	}
	if (*c == '=') {
		toggle_display_screen();
		return 0;
	}

	/* Escape by itself is the first character used for more
	   complex escape sequences like F-keys. libedit can't be used
	   to detect both ESC as a unitary key and more complex
	   sequences starting ESC at the same time. */
	if (*c == 27 && !peek_stdin()) {
		quit();
		return 0;
	}
	else if (*c != 9) {
		tabbed = 0;
	}

	return 1;
}

static void proc_keyboard(struct input *input)
{
	const char *line;
	const LineInfo *li;
	HistEvent hist_event;
	int len;

	line = el_gets(el, &len);
	li = el_line(el);

	if (len == 0 || line == NULL) {
		display_cmd("", 0, 0);
		return;
	} else if (len > 0) {
		if (len == 1 && line[0] == '\n') {
			display_print_page();
			el_set(el, EL_UNBUFFERED, 0);
			el_set(el, EL_UNBUFFERED, 1);
			return;
		}
		if (line[len-1] == '\n') {
			if (hist) {
				history(hist, &hist_event, H_ENTER, line);
			}

			char *line2 = strndup(line, len);
			line2[len - 1] = 0; /* replace \n */
			cmd_parser_parse(line2, input);
			free(line2);

			el_set(el, EL_UNBUFFERED, 0);
			el_set(el, EL_UNBUFFERED, 1);
			display_cmd("", 0, 0);
			return;
		}
		if (line[len-1] == 4) {
			return; /* should quit*/
		}
	}
	else {
		if (errno) {
                       return;
		}
		display_cmd("", 0, 0);
		return;
	}
	display_cmd(line, len, li->cursor - li->buffer);
}

static int key_f1(__attribute__((unused)) int ch) {display_screen(0); return CC_REDISPLAY;}
static int key_f2(__attribute__((unused)) int ch) {display_screen(1); return CC_REDISPLAY;}
static int key_f3(__attribute__((unused)) int ch) {display_screen(2); return CC_REDISPLAY;}
static int key_f4(__attribute__((unused)) int ch) {display_screen(3); return CC_REDISPLAY;}
static int key_f5(__attribute__((unused)) int ch) {display_screen(4); return CC_REDISPLAY;}
static int key_f6(__attribute__((unused)) int ch) {display_screen(5); return CC_REDISPLAY;}
static int key_f7(__attribute__((unused)) int ch) {display_screen(6); return CC_REDISPLAY;}
static int key_f8(__attribute__((unused)) int ch) {display_screen(7); return CC_REDISPLAY;}
static int key_f9(__attribute__((unused)) int ch) {display_screen(8); return CC_REDISPLAY;}
static int key_f10(__attribute__((unused)) int ch) {display_screen(9); return CC_REDISPLAY;}
static int key_f11(__attribute__((unused)) int ch) {display_screen(10); return CC_REDISPLAY;}
static int key_f12(__attribute__((unused)) int ch) {display_screen(11); return CC_REDISPLAY;}

static int key_page_up(__attribute__((unused)) int ch) {display_page_up(); return CC_REDISPLAY;}
static int key_page_down(__attribute__((unused)) int ch) {display_page_down(); return CC_REDISPLAY;}

static void setup_el(void)
{
	int pty;
	FILE *dev_pty;
	HistEvent hist_event;

	/* Open a pseudo-terminal for use in libedit. This is required
	   since the library checks if it is using a tty. If the file
	   descriptor does not represent a tty, the library disables
	   editing. */

	pty = posix_openpt(O_RDWR);
	/* TODO: On error (posix_openpt() < 0), fall-back to
	   non-libedit implementation. */
	grantpt(pty);
	unlockpt(pty);
	dev_pty = fdopen(pty, "wr");

	el = el_init("", dev_pty, dev_pty, dev_pty);

	el_set(el, EL_EDITOR, "emacs");

	el_set(el, EL_ADDFN, "complete", "Command completion", complete);

	el_set(el, EL_ADDFN, "key_f1", "Switch to screen 1", key_f1);
	el_set(el, EL_ADDFN, "key_f2", "Switch to screen 2", key_f2);
	el_set(el, EL_ADDFN, "key_f3", "Switch to screen 3", key_f3);
	el_set(el, EL_ADDFN, "key_f4", "Switch to screen 4", key_f4);
	el_set(el, EL_ADDFN, "key_f5", "Switch to screen 5", key_f5);
	el_set(el, EL_ADDFN, "key_f6", "Switch to screen 6", key_f6);
	el_set(el, EL_ADDFN, "key_f7", "Switch to screen 7", key_f7);
	el_set(el, EL_ADDFN, "key_f8", "Switch to screen 8", key_f8);
	el_set(el, EL_ADDFN, "key_f9", "Switch to screen 9", key_f5);
	el_set(el, EL_ADDFN, "key_f10", "Switch to screen 10", key_f6);
	el_set(el, EL_ADDFN, "key_f11", "Switch to screen 11", key_f7);
	el_set(el, EL_ADDFN, "key_f12", "Switch to screen 12", key_f8);

	el_set(el, EL_ADDFN, "key_page_up", "Page up", key_page_up);
	el_set(el, EL_ADDFN, "key_page_down", "Page down", key_page_down);

	el_set(el, EL_BIND, "^I", "complete", NULL);
	el_set(el, EL_BIND, "^r", "em-inc-search-prev", NULL);

	el_set(el, EL_BIND, "^[[11~", "key_f1", NULL);
	el_set(el, EL_BIND, "^[[12~", "key_f2", NULL);
	el_set(el, EL_BIND, "^[[13~", "key_f3", NULL);
	el_set(el, EL_BIND, "^[[14~", "key_f4", NULL);
	el_set(el, EL_BIND, "^[[15~", "key_f5", NULL);
	el_set(el, EL_BIND, "^[[17~", "key_f6", NULL);
	el_set(el, EL_BIND, "^[[18~", "key_f7", NULL);
	el_set(el, EL_BIND, "^[[19~", "key_f8", NULL);
	el_set(el, EL_BIND, "^[[20~", "key_f9", NULL);
	el_set(el, EL_BIND, "^[[21~", "key_f10", NULL);
	el_set(el, EL_BIND, "^[[23~", "key_f11", NULL);
	el_set(el, EL_BIND, "^[[24~", "key_f12", NULL);

	el_set(el, EL_BIND, "^[OP", "key_f1", NULL);
	el_set(el, EL_BIND, "^[OQ", "key_f2", NULL);
	el_set(el, EL_BIND, "^[OR", "key_f3", NULL);
	el_set(el, EL_BIND, "^[OS", "key_f4", NULL);

	el_set(el, EL_BIND, "^[[5~", "key_page_up", NULL);
	el_set(el, EL_BIND, "^[[6~", "key_page_down", NULL);

	hist = history_init();
	if (hist) {
		history(hist, &hist_event, H_SETSIZE, 1000);
		el_set(el, EL_HIST, history, hist);
	}
	el_set(el, EL_UNBUFFERED, 1);
	el_set(el, EL_GETCFN, get_char);
}

void reg_input_curses(void)
{
	setup_el();

	input_curses.fd = fileno(stdin);
	input_curses.proc_input = proc_keyboard;
	input_curses.history = show_history;

	reg_input(&input_curses);
}

void unreg_input_curses(void)
{
	history_end(hist);
	el_end(el);

	unreg_input(&input_curses);
}
