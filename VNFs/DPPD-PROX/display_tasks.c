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

#include "display_tasks.h"
#include "display.h"
#include "prox_globals.h"
#include "stats_task.h"
#include "stats_core.h"
#include "lconf.h"

struct task_stats_disp {
	uint32_t lcore_id;
	uint32_t task_id;
	uint32_t lcore_stat_id;
};

static int col_offset;
static struct task_stats_disp task_stats_disp[RTE_MAX_LCORE * MAX_TASKS_PER_CORE];

static struct display_page display_page_tasks;

static struct display_column *nb_col;
static struct display_column *name_col;
static struct display_column *mode_col;
static struct display_column *rx_name_col;
static struct display_column *tx_name_col;
static struct display_column *idle_col;
static struct display_column *rx_col;
static struct display_column *tx_col;
static struct display_column *tx_fail_col;
static struct display_column *discard_col;
static struct display_column *handled_col;
static struct display_column *cpp_col;
static struct display_column *ghz_col;
static struct display_column *rx_col;
static struct display_column *tx_col;
static struct display_column *tx_fail_col;
static struct display_column *discard_col;
static struct display_column *handled_col;
static struct display_column *occup_col;
static struct display_column *mask_col;
static struct display_column *class_col;
static struct display_column *mbm_tot_col;
static struct display_column *mbm_loc_col;
static struct display_column *frac_col;
static struct display_column *rx_non_dp_col;
static struct display_column *tx_non_dp_col;

static void stats_display_core_task_entry(struct lcore_cfg *lconf, struct task_args *targ, unsigned row)
{
	display_column_print_core_task(nb_col, row, lconf, targ);

	display_column_print(name_col, row, "%s", targ->id == 0 ? lconf->name : "");
	display_column_print(mode_col, row, "%s", targ->task_init->mode_str);

	display_column_port_ring(rx_name_col, row, targ->rx_port_queue, targ->nb_rxports, targ->rx_rings, targ->nb_rxrings);
	display_column_port_ring(tx_name_col, row, targ->tx_port_queue, targ->nb_txports, targ->tx_rings, targ->nb_txrings);
}

static void display_tasks_draw_frame(struct screen_state *state)
{
	const uint32_t n_tasks_tot = stats_get_n_tasks_tot();

	display_page_init(&display_page_tasks);

	struct display_table *core_task = display_page_add_table(&display_page_tasks);
	struct display_table *rx_tx = display_page_add_table(&display_page_tasks);

	display_table_init(core_task, "Core/Task");

	nb_col = display_table_add_col(core_task);
	display_column_init(nb_col, "Nb", 4);
	name_col = display_table_add_col(core_task);
	display_column_init(name_col, "Name", 7);
	mode_col = display_table_add_col(core_task);
	display_column_init(mode_col, "Mode", 9);

	display_table_init(rx_tx, "Port ID/Ring Name");
	rx_name_col = display_table_add_col(rx_tx);
	display_column_init(rx_name_col, "RX", 9);
	tx_name_col = display_table_add_col(rx_tx);
	display_column_init(tx_name_col, "TX", 9);

	struct display_table *stats = display_page_add_table(&display_page_tasks);

	if (state->toggle == 0) {
		display_table_init(stats, "Statistics per second");

		idle_col = display_table_add_col(stats);
		display_column_init(idle_col, "Idle (%)", 5);

		rx_col = display_table_add_col(stats);
		display_column_init(rx_col, "RX (K)", 9);

		tx_col = display_table_add_col(stats);
		display_column_init(tx_col, "TX (K)", 9);

		tx_fail_col = display_table_add_col(stats);
		display_column_init(tx_fail_col, "TX Fail (K)", 9);

		discard_col = display_table_add_col(stats);
		display_column_init(discard_col, "Discard (K)", 9);

		handled_col = display_table_add_col(stats);
		display_column_init(handled_col, "Handled (K)", 9);

		rx_non_dp_col = display_table_add_col(stats);
		display_column_init(rx_non_dp_col, "Rx non DP (K)", 9);

		tx_non_dp_col = display_table_add_col(stats);
		display_column_init(tx_non_dp_col, "Tx non DP (K)", 9);

		if (stats_cpu_freq_enabled()) {
			struct display_table *other = display_page_add_table(&display_page_tasks);

			display_table_init(other, "Other");

			cpp_col = display_table_add_col(other);
			display_column_init(cpp_col, "CPP", 9);

			ghz_col = display_table_add_col(other);
			display_column_init(ghz_col, "Clk (GHz)", 9);
		}
		if (stats_mbm_enabled()) {
			struct display_table *other = display_page_add_table(&display_page_tasks);
			mbm_tot_col = display_table_add_col(other);
			display_column_init(mbm_tot_col, "Tot Bdw(M)", 10);
			mbm_loc_col = display_table_add_col(other);
			display_column_init(mbm_loc_col, "Loc Bdw(M)", 10);
		}
	} else {
		display_table_init(stats, "Total Statistics");

		rx_col = display_table_add_col(stats);
		display_column_init(rx_col, "RX (K)", 14);

		tx_col = display_table_add_col(stats);
		display_column_init(tx_col, "TX (K)", 14);

		tx_fail_col = display_table_add_col(stats);
		display_column_init(tx_fail_col, "TX Fail (K)", 14);

		discard_col = display_table_add_col(stats);
		display_column_init(discard_col, "Discard (K)", 14);

		handled_col = display_table_add_col(stats);
		display_column_init(handled_col, "Handled (K)", 14);

		rx_non_dp_col = display_table_add_col(stats);
		display_column_init(rx_non_dp_col, "RX non DP (K)", 14);

		tx_non_dp_col = display_table_add_col(stats);
		display_column_init(tx_non_dp_col, "TX non DP (K)", 14);

		if (stats_cmt_enabled()) {
			struct display_table *other = display_page_add_table(&display_page_tasks);

			display_table_init(other, "Cache QoS Monitoring");

			occup_col = display_table_add_col(other);
			display_column_init(occup_col, "Occupancy (KB)", 15);

			frac_col = display_table_add_col(other);
			display_column_init(frac_col, "Fraction", 9);
		}
		if (stats_cat_enabled()) {
			struct display_table *other = display_page_add_table(&display_page_tasks);
			mask_col = display_table_add_col(other);
			display_column_init(mask_col, "Cache mask", 10);
			class_col = display_table_add_col(other);
			display_column_init(class_col, "Class", 5);
		}
	}
	display_page_draw_frame(&display_page_tasks, n_tasks_tot);

	uint16_t element_count = 0;

	struct lcore_cfg *lconf = NULL;
	struct task_args *targ;

	while (core_targ_next(&lconf, &targ, 0) == 0) {
		PROX_ASSERT(element_count < RTE_MAX_LCORE * MAX_TASKS_PER_CORE);

		stats_display_core_task_entry(lconf, targ, element_count);

		task_stats_disp[element_count].lcore_id = lconf->id;
		task_stats_disp[element_count].task_id = targ->id;
		task_stats_disp[element_count].lcore_stat_id = stats_lcore_find_stat_id(lconf->id);
		element_count++;
	}
}

static void print_kpps(struct display_column *col, int row, uint64_t nb_pkts, uint64_t delta_t)
{
	nb_pkts *= tsc_hz;
	if (nb_pkts && nb_pkts /100 < delta_t) {
		uint64_t int_part = nb_pkts/delta_t;
		uint64_t frac_part = (nb_pkts - int_part * delta_t) * 1000 /delta_t;
		display_column_print(col, row, "%2lu.%03lu", int_part, frac_part);
	}
	else {
		display_column_print(col, row, "%9lu", nb_pkts / delta_t);
	}
}

static void display_core_task_stats_per_sec(const struct task_stats_disp *t, struct screen_state *state, int row)
{
	struct task_stats_sample *last = stats_get_task_stats_sample(t->lcore_id, t->task_id, 1);
	struct task_stats_sample *prev = stats_get_task_stats_sample(t->lcore_id, t->task_id, 0);

	/* delta_t in units of clock ticks */
	uint64_t delta_t = last->tsc - prev->tsc;

	uint64_t empty_cycles = last->empty_cycles - prev->empty_cycles;

	if (empty_cycles > delta_t) {
		empty_cycles = 10000;
	}
	else {
		empty_cycles = empty_cycles * 10000 / delta_t;
	}

	/* empty_cycles has 2 digits after point, (usefull when only a very small idle time) */

	display_column_print(idle_col, row, "%3lu.%02lu", empty_cycles / 100, empty_cycles % 100);

	// Display per second statistics in Kpps unit
	delta_t *= state->pps_unit;

	print_kpps(rx_col, row, last->rx_pkt_count - prev->rx_pkt_count, delta_t);
	print_kpps(tx_col, row, last->tx_pkt_count - prev->tx_pkt_count, delta_t);
	print_kpps(tx_fail_col, row, last->drop_tx_fail - prev->drop_tx_fail, delta_t);
	print_kpps(discard_col, row, last->drop_discard - prev->drop_discard, delta_t);
	print_kpps(handled_col, row, last->drop_handled - prev->drop_handled, delta_t);
	print_kpps(rx_non_dp_col, row, last->rx_non_dp - prev->rx_non_dp, delta_t);
	print_kpps(tx_non_dp_col, row, last->tx_non_dp - prev->tx_non_dp, delta_t);

	if (stats_cpu_freq_enabled()) {
		uint8_t lcore_stat_id = t->lcore_stat_id;
		struct lcore_stats_sample *clast = stats_get_lcore_stats_sample(lcore_stat_id, 1);
		struct lcore_stats_sample *cprev = stats_get_lcore_stats_sample(lcore_stat_id, 0);

		uint64_t adiff = clast->afreq - cprev->afreq;
		uint64_t mdiff = clast->mfreq - cprev->mfreq;

		uint64_t cpp = 0;

		uint64_t pkt_diff_rx = last->rx_pkt_count - prev->rx_pkt_count;
		uint64_t pkt_diff_tx = last->tx_pkt_count - prev->tx_pkt_count;

		uint64_t pkt_diff = pkt_diff_tx > pkt_diff_rx? pkt_diff_tx : pkt_diff_rx;

		if (pkt_diff && mdiff) {
			cpp = delta_t/pkt_diff*adiff/mdiff/1000;
		}

		uint64_t mhz;
		if (mdiff)
			mhz = tsc_hz*adiff/mdiff/1000000;
		else
			mhz = 0;

		display_column_print(cpp_col, row, "%lu", cpp);
		display_column_print(ghz_col, row, "%lu.%03lu", mhz/1000, mhz%1000);
	}
	if (stats_mbm_enabled()) {
		struct lcore_stats *c = stats_get_lcore_stats(t->lcore_stat_id);
		uint8_t lcore_stat_id = t->lcore_stat_id;
		struct lcore_stats_sample *clast = stats_get_lcore_stats_sample(lcore_stat_id, 1);
		struct lcore_stats_sample *cprev = stats_get_lcore_stats_sample(lcore_stat_id, 0);
		if ((clast->mbm_tot_bytes - cprev->mbm_tot_bytes) >> 20)
			display_column_print(mbm_tot_col, row, "%lu", (clast->mbm_tot_bytes - cprev->mbm_tot_bytes) >> 20);
		else
			display_column_print(mbm_tot_col, row, "0.%03lu", (clast->mbm_tot_bytes - cprev->mbm_tot_bytes) >> 10);
		if( (clast->mbm_loc_bytes - cprev->mbm_loc_bytes) >> 20)
			display_column_print(mbm_loc_col, row, "%lu", (clast->mbm_loc_bytes - cprev->mbm_loc_bytes) >> 20);
		else
			display_column_print(mbm_loc_col, row, "0.%03lu", (clast->mbm_loc_bytes - cprev->mbm_loc_bytes) >> 10);
	}
}

static void display_core_task_stats_tot(const struct task_stats_disp *t, struct screen_state *state, int row)
{
	struct task_stats *ts = stats_get_task_stats(t->lcore_id, t->task_id);

	display_column_print(rx_col, row, "%lu", ts->tot_rx_pkt_count);
	display_column_print(tx_col, row, "%lu", ts->tot_tx_pkt_count);
	display_column_print(tx_fail_col, row, "%lu", ts->tot_drop_tx_fail);
	display_column_print(discard_col, row, "%lu", ts->tot_drop_discard);
	display_column_print(handled_col, row, "%lu", ts->tot_drop_handled);
	display_column_print(rx_non_dp_col, row, "%lu", ts->tot_rx_non_dp);
	display_column_print(tx_non_dp_col, row, "%lu", ts->tot_tx_non_dp);

	if (stats_cmt_enabled()) {
		struct lcore_stats *c = stats_get_lcore_stats(t->lcore_stat_id);
		display_column_print(occup_col, row, "%lu", c->cmt_bytes >> 10);
		display_column_print(frac_col, row, "%3lu.%02lu", c->cmt_fraction/100, c->cmt_fraction%100);
	}
	if (stats_cat_enabled()) {
		struct lcore_stats *c = stats_get_lcore_stats(t->lcore_stat_id);
		display_column_print(mask_col, row, "%x", c->cat_mask);
		display_column_print(class_col, row, "%x", c->class);
	}
}

static void display_tasks_draw_stats(struct screen_state *state)
{
	const uint32_t n_tasks_tot = stats_get_n_tasks_tot();

	for (uint8_t i = 0; i < n_tasks_tot; ++i) {
		const struct task_stats_disp *disp = &task_stats_disp[i];

		if (state->toggle == 0) {
			display_core_task_stats_per_sec(disp, state, i);
		} else {
			display_core_task_stats_tot(disp, state, i);
		}
	}
}

static int display_tasks_get_height(void)
{
	return stats_get_n_tasks_tot();
}

static struct display_screen display_screen_tasks = {
	.draw_frame = display_tasks_draw_frame,
	.draw_stats = display_tasks_draw_stats,
	.get_height = display_tasks_get_height,
	.title = "tasks",
};

struct display_screen *display_tasks(void)
{
	return &display_screen_tasks;
}
