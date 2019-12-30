/*
// Copyright (c) 2019 Intel Corporation
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

#include <math.h>
#include "handle_lat.h"
#include "display_latency_distr.h"
#include "stats_latency.h"
#include "display.h"
#include "lconf.h"

static struct display_page display_page_latency_distr;
static struct display_column *stats_latency_distr[LAT_BUCKET_COUNT];
static struct display_column *stats_max;
static struct display_column *core_col;
static struct display_column *name_col;
static uint32_t global_min_bucket_id = 0, global_max_bucket_id = LAT_BUCKET_COUNT - 1;
static const uint16_t global_nb_buckets_displayed = 15;
static uint32_t group_size = 9; //LAT_BUCKET_COUNT / global_nb_buckets_displayed;

#define UNIT_INT(i)	(((i) * bucket_unit_nsec)/1000)
#define UNIT_FRACT(i)	((((i) * bucket_unit_nsec) % 1000) / 100)

static void display_latency_distr_draw_frame(struct screen_state *state)
{
  	uint32_t n_tasks = stats_get_n_latency();
	struct lcore_cfg *lconf = NULL;
	struct task_args *targ;
	char name[32];
	char *ptr;

	display_page_init(&display_page_latency_distr);

	struct display_table *core_name = display_page_add_table(&display_page_latency_distr);

	display_table_init(core_name, "Core/task");
	core_col = display_table_add_col(core_name);
	name_col = display_table_add_col(core_name);
	display_column_init(core_col, "Nb", 4);
	display_column_init(name_col, "Name", 5);

	uint32_t bucket_size = stats_get_latency_bucket_size();
	struct display_table *stats = display_page_add_table(&display_page_latency_distr);
	uint32_t bucket_unit_nsec = 1000000000 / (rte_get_tsc_hz() >> bucket_size);
	if (state->toggle == 0) {
		display_table_init(stats, "Statistics per second");
	} else {
		display_table_init(stats, "Total statistics");
	}
	char title[64];
	stats_max = display_table_add_col(stats);
	snprintf(title, sizeof(title), " MAXIMUM(mic)");
	display_column_init(stats_max, title, 11);
	plog_info("Bucket unit is %d nsec, bucket size is %d, freq is %ld\n", bucket_unit_nsec, bucket_size, rte_get_tsc_hz());

	uint32_t i = global_min_bucket_id, first = i, k = 0;
	while ((i < LAT_BUCKET_COUNT) && (i <= global_max_bucket_id)) {
		stats_latency_distr[k] = display_table_add_col(stats);
		if (i < LAT_BUCKET_COUNT - group_size) {
			snprintf(title, sizeof(title), "%d.%01d-%d.%01d", UNIT_INT(i), UNIT_FRACT(i), UNIT_INT(i + group_size), UNIT_FRACT(i + group_size));
		} else {
			snprintf(title, sizeof(title), "> %d.%01d", UNIT_INT(i), UNIT_FRACT(i));
		}
		display_column_init(stats_latency_distr[k++], title, 9);
		i += group_size;
	}
	display_page_draw_frame(&display_page_latency_distr, n_tasks);

	uint32_t count = 0;
	lconf = NULL;
	while (core_targ_next(&lconf, &targ, 0) == 0) {
		if (strcmp(targ->task_init->mode_str, "lat") == 0) {
			display_column_print_core_task(core_col, count, lconf, targ);
			if (targ->id == 0)
				display_column_print(name_col, count, "%s", lconf->name);
			count++;
		}
	}
}

static void display_latency_distr_draw_stats(struct screen_state *state)
{
	const uint32_t n_latency = stats_get_n_latency();
	uint64_t *bucket;
	uint32_t bucket_id = 0, min_bucket_id = LAT_BUCKET_COUNT - 1, max_bucket_id = 0;
	struct time_unit tu;

	for (uint32_t count = 0; count < n_latency; ++count) {
		if (state->toggle == 0)
			tu = stats_latency_get(count)->max.time;
		else
			tu = stats_latency_tot_get(count)->max.time;
		display_column_print(stats_max, count, "%9lu.%03lu", tu.sec * 1000000 + tu.nsec / 1000, tu.nsec % 1000);
	}

	// Calculate min_bucket_id: id of 1st bucket with data for any tasks
	// Calculate max_bucket_id: id of last bucket with data for any tasks
	for (uint i = 0; i < LAT_BUCKET_COUNT; ++i) {
		for (uint32_t count = 0; count < n_latency; ++count) {
			if (state->toggle == 0)
				bucket = stats_latency_get_bucket(count);
			else
				bucket = stats_latency_get_tot_bucket(count);
			if (bucket[i] != 0) {
				min_bucket_id = i;
				break;
			}
		}
		if (min_bucket_id != LAT_BUCKET_COUNT - 1)
			break;
	}

	for (uint i = LAT_BUCKET_COUNT; i > 0; i--) {
		for (uint32_t count = 0; count < n_latency; ++count) {
			if (state->toggle == 0)
				bucket = stats_latency_get_bucket(count);
			else
				bucket = stats_latency_get_tot_bucket(count);
			if (bucket[i - 1] != 0) {
				max_bucket_id = i - 1;
				break;
			}
		}
		if (max_bucket_id)
			break;
	}

	if (max_bucket_id - min_bucket_id + 1 < global_nb_buckets_displayed) {
		max_bucket_id = global_nb_buckets_displayed + min_bucket_id - 1;
	}

	if ((global_min_bucket_id != min_bucket_id) || (global_max_bucket_id != max_bucket_id)) {
		global_min_bucket_id = min_bucket_id;
		global_max_bucket_id = max_bucket_id;
		// Calculate how many buckets must be grouped together
		if (max_bucket_id - min_bucket_id + 1 > global_nb_buckets_displayed)
			group_size = ceil(1.0 * (max_bucket_id - min_bucket_id + 1) / global_nb_buckets_displayed);
		else
			group_size = 1;
		display_latency_distr_draw_frame(state);
		display_renew();
		plog_info("min_bucket_id = %d, max_bucket_id = %d\n", min_bucket_id, max_bucket_id);
	}

	for (uint32_t count = 0; count < n_latency; ++count) {
		if (state->toggle == 0)
			bucket = stats_latency_get_bucket(count);
		else
			bucket = stats_latency_get_tot_bucket(count);
		uint32_t i = min_bucket_id, k = 0;
		uint64_t nb = 0;
		while ((i < LAT_BUCKET_COUNT) && (i <= global_max_bucket_id)){
			for (uint32_t j = 0; j <= group_size; j++)
				if (i + j < LAT_BUCKET_COUNT)
					nb += bucket[i+j];
			display_column_print(stats_latency_distr[k++], count, "%9lu", nb);
			nb = 0;
			i += group_size;
		}
	}
}

static int display_latency_distr_get_height(void)
{
	return stats_get_n_latency();
}

static struct display_screen display_screen_latency_distr = {
	.draw_frame = display_latency_distr_draw_frame,
	.draw_stats = display_latency_distr_draw_stats,
	.get_height = display_latency_distr_get_height,
	.title = "latency_distr",
};

struct display_screen *display_latency_distr(void)
{
	return &display_screen_latency_distr;
}
