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

#include <rte_ring.h>

#include "display.h"
#include "display_rings.h"
#include "stats_ring.h"
#include "prox_port_cfg.h"

static struct display_page display_page_rings;
static struct display_column *ring_col;
static struct display_column *occup_col;
static struct display_column *free_col;
static struct display_column *size_col;
static struct display_column *sc_col;
static struct display_column *sp_col;

static void display_rings_draw_frame(struct screen_state *state)
{
	const uint32_t n_rings = stats_get_n_rings();
	char sc_val, sp_val;

	display_page_init(&display_page_rings);

	struct display_table *ring_table = display_page_add_table(&display_page_rings);
	struct display_table *stats_table = display_page_add_table(&display_page_rings);

	display_table_init(ring_table, "Name");

	display_table_init(stats_table, "Sampled statistics");

	ring_col = display_table_add_col(ring_table);
	display_column_init(ring_col, "Ring/Port", 11);
	occup_col = display_table_add_col(stats_table);
	display_column_init(occup_col, "Occup (%)", 11);
	free_col = display_table_add_col(stats_table);
	display_column_init(free_col, "Free", 11);
	size_col = display_table_add_col(stats_table);
	display_column_init(size_col, "Size", 11);
	sc_col = display_table_add_col(stats_table);
	display_column_init(sc_col, "SC", 2);
	sp_col = display_table_add_col(stats_table);
	display_column_init(sp_col, "SP", 2);

	display_page_draw_frame(&display_page_rings, n_rings);

	for (uint16_t i = 0; i < n_rings; ++i) {
		struct ring_stats *rs = stats_get_ring_stats(i);

		if (rs->nb_ports == 0) {
			display_column_print(ring_col, i, "%s", rs->ring->name);
		} else {
			char name[64] = {0};
			int offset = 0;

			for (uint32_t j = 0; j < rs->nb_ports; j++)
				offset += sprintf(name + offset, "%s", rs->port[j]->name);
		}

		sc_val = (rs->ring->flags & RING_F_SC_DEQ) ? 'y' : 'n';
		sp_val = (rs->ring->flags & RING_F_SP_ENQ) ? 'y' : 'n';

		display_column_print(sc_col, i, " %c", sc_val);
		display_column_print(sp_col, i, " %c", sp_val);
	}
}

static void display_rings_draw_stats(struct screen_state *state)
{
	const uint32_t n_rings = stats_get_n_rings();

	for (uint32_t i = 0; i < n_rings; ++i) {
		struct ring_stats *rs = stats_get_ring_stats(i);
		uint32_t used = ((rs->size - rs->free)*10000)/rs->size;

		display_column_print(occup_col, i, "%8u.%02u", used/100, used%100);
		display_column_print(free_col, i, "%11u", rs->free);
		display_column_print(size_col, i, "%11u", rs->size);
	}
}

static int display_rings_get_height(void)
{
	return stats_get_n_rings();
}

static struct display_screen display_screen_rings = {
	.draw_frame = display_rings_draw_frame,
	.draw_stats = display_rings_draw_stats,
	.get_height = display_rings_get_height,
	.title = "rings",
};

struct display_screen *display_rings(void)
{
	return &display_screen_rings;
}
