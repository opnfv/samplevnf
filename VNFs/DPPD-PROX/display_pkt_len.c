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

#include "prox_globals.h"
#include "display_pkt_len.h"
#include "stats_port.h"
#include "display.h"
#include "defaults.h"
#include "prox_port_cfg.h"
#include "clock.h"

static struct display_page display_page_pkt_len;
static struct display_column *port_col;
static struct display_column *name_col;
static struct display_column *type_col;
static struct display_column *stats_col[PKT_SIZE_COUNT];

const char *titles[] = {
	"64B (#)",
	"65-127B (#)",
	"128-255B (#)",
	"256-511B (#)",
	"512-1023B (#)",
	"1024-1522B (#)",
	"1523B+ (#)",
};

static int port_disp[PROX_MAX_PORTS];
static int n_port_disp;

static void display_pkt_len_draw_frame(struct screen_state *screen_state)
{
	n_port_disp = 0;
	for (uint8_t i = 0; i < PROX_MAX_PORTS; ++i) {
		if (prox_port_cfg[i].active) {
			port_disp[n_port_disp++] = i;
		}
	}

	display_page_init(&display_page_pkt_len);

	struct display_table *port_name = display_page_add_table(&display_page_pkt_len);

	display_table_init(port_name, "Port");
	port_col = display_table_add_col(port_name);
	name_col = display_table_add_col(port_name);
	type_col = display_table_add_col(port_name);

	display_column_init(port_col, "ID", 4);
	display_column_init(name_col, "Name", 8);
	display_column_init(type_col, "Type", 7);

	struct display_table *stats = display_page_add_table(&display_page_pkt_len);

	if (screen_state->toggle == 0)
		display_table_init(stats, "Statistics per second");
	else
		display_table_init(stats, "Total Statistics");

	for (int i = 0; i < PKT_SIZE_COUNT; ++i) {
		stats_col[i] = display_table_add_col(stats);
		display_column_init(stats_col[i], titles[i], 13);
	}

	display_page_draw_frame(&display_page_pkt_len, n_port_disp);

	for (uint8_t i = 0; i < n_port_disp; ++i) {
		const uint32_t port_id = port_disp[i];

		display_column_print(port_col, i, "%4u", port_id);
		display_column_print(name_col, i, "%8s", prox_port_cfg[port_id].name);
		display_column_print(type_col, i, "%7s", prox_port_cfg[port_id].short_name);
	}
}

static void display_pkt_len_draw_stats(struct screen_state *state)
{
	for (uint8_t i = 0; i < n_port_disp; ++i) {
		const uint32_t port_id = port_disp[i];
		struct port_stats_sample *last = stats_get_port_stats_sample(port_id, 1);
		struct port_stats_sample *prev = stats_get_port_stats_sample(port_id, 0);

		uint64_t delta_t = last->tsc - prev->tsc;
		if (delta_t == 0) // This could happen if we just reset the screen => stats will be updated later
			continue;

		if (state->toggle == 0) {
			uint64_t diff;

			for (int j = 0; j < PKT_SIZE_COUNT; ++j) {
				if (last->tx_pkt_size[j] == (uint64_t)-1) {
					display_column_print(stats_col[j], i, "     ---     ");
				} else {
					diff = last->tx_pkt_size[j] - prev->tx_pkt_size[j];
					display_column_print(stats_col[j], i, "%13lu", val_to_rate(diff, delta_t));
				}
			}
		} else {
			for (int j = 0; j < PKT_SIZE_COUNT; ++j) {
				if (last->tx_pkt_size[j] == (uint64_t)-1) {
					display_column_print(stats_col[j], i, "     ---     ");
				} else {
					display_column_print(stats_col[j], i, "%13lu", last->tx_pkt_size[j]);
				}
			}
		}
	}
}

static int display_pkt_len_get_height(void)
{
	return stats_get_n_ports();
}

static struct display_screen display_screen_pkt_len = {
	.draw_frame = display_pkt_len_draw_frame,
	.draw_stats = display_pkt_len_draw_stats,
	.get_height = display_pkt_len_get_height,
	.title = "pkt_len",
};

struct display_screen *display_pkt_len(void)
{
	return &display_screen_pkt_len;
}
