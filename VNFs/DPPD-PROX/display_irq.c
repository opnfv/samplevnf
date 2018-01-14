/*
// Copyright (c) 2010-2018 Intel Corporation
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

#include "display_irq.h"
#include "stats_irq.h"
#include "display.h"
#include "lconf.h"

static struct display_page display_page_irq;
static struct display_column *stats_irq[IRQ_BUCKETS_COUNT];
static struct display_column *stats_max;
static struct display_column *core_col;
static struct display_column *name_col;

static void display_irq_draw_frame(struct screen_state *state)
{
  	uint32_t n_tasks = stats_get_n_irq_tasks();
	struct lcore_cfg *lconf = NULL;
	struct task_args *targ;
	char name[32];
	char *ptr;

	display_page_init(&display_page_irq);

	struct display_table *core_name = display_page_add_table(&display_page_irq);

	display_table_init(core_name, "Core/task");
	core_col = display_table_add_col(core_name);
	name_col = display_table_add_col(core_name);
	display_column_init(core_col, "Nb", 4);
	display_column_init(name_col, "Name", 5);

	struct display_table *stats = display_page_add_table(&display_page_irq);
	if (state->toggle == 0) {
		display_table_init(stats, "Statistics per second");

		char title[64];
		stats_max = display_table_add_col(stats);
		snprintf(title, sizeof(title), " MAXIMUM(mic)");
		display_column_init(stats_max, title, 11);

		stats_irq[0] = display_table_add_col(stats);
		if (irq_bucket_maxtime_micro[0] < 1000)
			snprintf(title, sizeof(title), " %d-%ld mic", 0, irq_bucket_maxtime_micro[0]);
		else
			snprintf(title, sizeof(title), " %d-%ld ms", 0, irq_bucket_maxtime_micro[0] / 1000);
		display_column_init(stats_irq[0], title, 9);
		for (uint i = 1; i < IRQ_BUCKETS_COUNT - 1; ++i) {
			stats_irq[i] = display_table_add_col(stats);
			if (irq_bucket_maxtime_micro[i-1] < 1000)
				snprintf(title, sizeof(title), " %ld-%ld mic", irq_bucket_maxtime_micro[i-1], irq_bucket_maxtime_micro[i]);
			else
				snprintf(title, sizeof(title), " %ld-%ld ms", irq_bucket_maxtime_micro[i-1] / 1000, irq_bucket_maxtime_micro[i] / 1000);
			display_column_init(stats_irq[i], title, 9);
		}
		stats_irq[IRQ_BUCKETS_COUNT - 1] = display_table_add_col(stats);
		if (irq_bucket_maxtime_micro[IRQ_BUCKETS_COUNT - 2] < 1000)
			snprintf(title, sizeof(title), "  > %ld mic ", irq_bucket_maxtime_micro[IRQ_BUCKETS_COUNT - 2]);
		else
			snprintf(title, sizeof(title), " > %ld ms   ", irq_bucket_maxtime_micro[IRQ_BUCKETS_COUNT - 2] / 1000);
		display_column_init(stats_irq[IRQ_BUCKETS_COUNT - 1], title, 9);
	} else {
		display_table_init(stats, "Total statistics");

		char title[64];
		stats_max = display_table_add_col(stats);
		snprintf(title, sizeof(title), " MAXIMUM(mic)");
		display_column_init(stats_max, title, 9);

		stats_irq[0] = display_table_add_col(stats);
		if (irq_bucket_maxtime_micro[0] < 1000)
			snprintf(title, sizeof(title), " %d-%ld   ", 0, irq_bucket_maxtime_micro[0]);
		else
			snprintf(title, sizeof(title), " %d-%ld ms", 0, irq_bucket_maxtime_micro[0] / 1000);
		display_column_init(stats_irq[0], title, 9);
		for (uint i = 1; i < IRQ_BUCKETS_COUNT - 1; ++i) {
			stats_irq[i] = display_table_add_col(stats);
			if (irq_bucket_maxtime_micro[i-1] < 1000)
				snprintf(title, sizeof(title), " %ld-%ld  ", irq_bucket_maxtime_micro[i-1], irq_bucket_maxtime_micro[i]);
			else
				snprintf(title, sizeof(title), " %ld-%ld ms", irq_bucket_maxtime_micro[i-1] / 1000, irq_bucket_maxtime_micro[i] / 1000);
			display_column_init(stats_irq[i], title, 9);
		}
		stats_irq[IRQ_BUCKETS_COUNT - 1] = display_table_add_col(stats);
		if (irq_bucket_maxtime_micro[IRQ_BUCKETS_COUNT - 2] < 1000)
			snprintf(title, sizeof(title), " > %ld ", irq_bucket_maxtime_micro[IRQ_BUCKETS_COUNT - 2]);
		else
			snprintf(title, sizeof(title), " > %ld  ", irq_bucket_maxtime_micro[IRQ_BUCKETS_COUNT - 2] / 1000);
		display_column_init(stats_irq[IRQ_BUCKETS_COUNT - 1], title, 9);
	}

	display_page_draw_frame(&display_page_irq, n_tasks);

	uint32_t count = 0;
	lconf = NULL;
	while (core_targ_next(&lconf, &targ, 0) == 0) {
		if (strcmp(targ->task_init->mode_str, "irq") == 0) {
			display_column_print_core_task(core_col, count, lconf, targ);
			if (targ->id == 0)
				display_column_print(name_col, count, "%s", lconf->name);
			count++;
		}
	}
}

static void display_irq_draw_stats(struct screen_state *state)
{
	struct lcore_cfg *lconf = NULL;
	struct task_args *targ;
	const uint32_t n_stats_irq = stats_get_n_irq_tasks();

	if (state->toggle == 0) {
		for (uint32_t count = 0; count < n_stats_irq; ++count) {
			struct irq_sample *last = get_irq_sample(count, 1);
			struct irq_sample *prev = get_irq_sample(count, 0);

			display_column_print(stats_max, count, "%9lu", (last->max_irq * 1000000L) / rte_get_tsc_hz());
			for (uint i = 0; i < IRQ_BUCKETS_COUNT; ++i) {
				display_column_print(stats_irq[i], count, "%9lu", last->irq[i] - prev->irq[i]);
			}
		}
	} else {
		for (uint32_t count = 0; count < n_stats_irq; ++count) {
			display_column_print(stats_max, count, "%9lu", get_max_irq_stats(count));
			for (uint i = 0; i < IRQ_BUCKETS_COUNT; ++i) {
				display_column_print(stats_irq[i], count, "%9lu", get_irq_stats(count, i));
			}
		}
	}
}

static int display_irq_get_height(void)
{
	return stats_get_n_irq_tasks();
}

static struct display_screen display_screen_irq = {
	.draw_frame = display_irq_draw_frame,
	.draw_stats = display_irq_draw_stats,
	.get_height = display_irq_get_height,
	.title = "irq",
};

struct display_screen *display_irq(void)
{
	return &display_screen_irq;
}
