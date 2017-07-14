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

#include "display.h"
#include "display_l4gen.h"
#include "stats_l4gen.h"

static struct display_page display_page_l4gen;

static struct display_column *core_col;
static struct display_column *tcp_setup_col;
static struct display_column *udp_setup_col;
static struct display_column *all_setup_col;
static struct display_column *bundles_setup_col;
static struct display_column *tcp_teardown_col;
static struct display_column *tcp_teardown_retx_col;
static struct display_column *udp_teardown_col;
static struct display_column *tcp_expire_col;
static struct display_column *udp_expire_col;
static struct display_column *active_col;
static struct display_column *retx_col;

static void display_l4gen_draw_frame(struct screen_state *state)
{
	const uint32_t n_l4gen = stats_get_n_l4gen();

	display_page_init(&display_page_l4gen);

	struct display_table *core = display_page_add_table(&display_page_l4gen);
	struct display_table *setup_rate = display_page_add_table(&display_page_l4gen);
	struct display_table *teardown_rate = display_page_add_table(&display_page_l4gen);
	struct display_table *expire_rate = display_page_add_table(&display_page_l4gen);
	struct display_table *other = display_page_add_table(&display_page_l4gen);

	display_table_init(core, "Core");
	display_table_init(setup_rate, "Setup rate (flows/s)");
	display_table_init(teardown_rate, "Teardown rate (flows/s)");
	display_table_init(expire_rate, "Expire rate (flows/s)");
	display_table_init(other, "Other");

	core_col = display_table_add_col(core);
	display_column_init(core_col, "Nb", 4);

	tcp_setup_col = display_table_add_col(setup_rate);
	display_column_init(tcp_setup_col, "TCP", 10);
	udp_setup_col = display_table_add_col(setup_rate);
	display_column_init(udp_setup_col, "UDP", 10);
	all_setup_col = display_table_add_col(setup_rate);
	display_column_init(all_setup_col, "TCP + UDP", 9);
	bundles_setup_col = display_table_add_col(setup_rate);
	display_column_init(bundles_setup_col, "Bundles", 9);

	tcp_teardown_col = display_table_add_col(teardown_rate);
	display_column_init(tcp_teardown_col, "TCP w/o reTX", 12);
	tcp_teardown_retx_col = display_table_add_col(teardown_rate);
	display_column_init(tcp_teardown_retx_col, "TCP w/  reTX", 12);
	udp_teardown_col = display_table_add_col(teardown_rate);
	display_column_init(udp_teardown_col, "UDP", 12);

	tcp_expire_col = display_table_add_col(expire_rate);
	display_column_init(tcp_expire_col, "TCP", 10);
	udp_expire_col = display_table_add_col(expire_rate);
	display_column_init(udp_expire_col, "TCP", 10);

	active_col = display_table_add_col(other);
	display_column_init(active_col, "Active (#)", 10);
	retx_col = display_table_add_col(other);
	display_column_init(retx_col, "reTX (/s)", 10);

	display_page_draw_frame(&display_page_l4gen, n_l4gen);

	for (uint16_t i = 0; i < n_l4gen; ++i) {
		struct task_l4_stats *tls = stats_get_l4_stats(i);

		display_column_print(core_col, i, "%2u/%1u", tls->lcore_id, tls->task_id);
	}
}

static void display_l4gen_draw_stats_line(int row, struct l4_stats_sample *clast, struct l4_stats_sample *cprev)
{
	struct l4_stats *last = &clast->stats;
	struct l4_stats *prev = &cprev->stats;

	uint64_t delta_t = clast->tsc - cprev->tsc;

	uint64_t tcp_created = last->tcp_created - prev->tcp_created;
	uint64_t udp_created = last->udp_created - prev->udp_created;

	uint64_t tcp_finished_no_retransmit = last->tcp_finished_no_retransmit - prev->tcp_finished_no_retransmit;
	uint64_t tcp_finished_retransmit = last->tcp_finished_retransmit - prev->tcp_finished_retransmit;
	uint64_t tcp_expired = last->tcp_expired - prev->tcp_expired;
	uint64_t tcp_retransmits = last->tcp_retransmits - prev->tcp_retransmits;
	uint64_t udp_finished = last->udp_finished - prev->udp_finished;
	uint64_t udp_expired = last->udp_expired - prev->udp_expired;
	uint64_t bundles_created = last->bundles_created - prev->bundles_created;

	uint64_t tcp_setup_rate = val_to_rate(tcp_created, delta_t);
	uint64_t udp_setup_rate = val_to_rate(udp_created, delta_t);
	uint64_t all_setup_rate = val_to_rate(tcp_created + udp_created, delta_t);
	uint64_t bundle_setup_rate = val_to_rate(bundles_created, delta_t);

	uint64_t tcp_teardown_rate = val_to_rate(tcp_finished_no_retransmit, delta_t);
	uint64_t tcp_teardown_retx_rate = val_to_rate(tcp_finished_retransmit, delta_t);
	uint64_t udp_teardown_rate = val_to_rate(udp_finished, delta_t);

	uint64_t tcp_expire_rate = val_to_rate(tcp_expired, delta_t);
	uint64_t udp_expire_rate = val_to_rate(udp_expired, delta_t);

	display_column_print(tcp_setup_col, row, "%"PRIu64"", tcp_setup_rate);
	display_column_print(udp_setup_col, row,  "%"PRIu64"", udp_setup_rate);
	display_column_print(all_setup_col, row,  "%"PRIu64"", all_setup_rate);
	display_column_print(bundles_setup_col, row,  "%"PRIu64"", bundle_setup_rate);

	display_column_print(tcp_teardown_col, row, "%"PRIu64"", tcp_teardown_rate);
	display_column_print(tcp_teardown_retx_col, row, "%"PRIu64"", tcp_teardown_retx_rate);
	display_column_print(udp_teardown_col, row, "%"PRIu64"", udp_teardown_rate);

	display_column_print(tcp_expire_col, row, "%"PRIu64"", tcp_expire_rate);
	display_column_print(udp_expire_col, row, "%"PRIu64"", udp_expire_rate);

	uint64_t tot_created = last->tcp_created + last->udp_created;
	uint64_t tot_finished = last->tcp_finished_retransmit + last->tcp_finished_no_retransmit +
		last->udp_finished + last->udp_expired + last->tcp_expired;

	uint64_t active = tot_created - tot_finished;
	uint64_t retx = tcp_retransmits;

	display_column_print(active_col, row, "%10"PRIu64"", active);
	display_column_print(retx_col, row, "%10"PRIu64"", retx);
}

static void display_l4gen_draw_stats(struct screen_state *state)
{
	const uint32_t n_l4gen = stats_get_n_l4gen();

	for (uint16_t i = 0; i < n_l4gen; ++i) {
		struct l4_stats_sample *clast = stats_get_l4_stats_sample(i, 1);
		struct l4_stats_sample *cprev = stats_get_l4_stats_sample(i, 0);

		display_l4gen_draw_stats_line(i, clast, cprev);
	}
}

static int display_l4gen_get_height(void)
{
	return stats_get_n_l4gen();
}

static struct display_screen display_screen_l4gen = {
	.draw_frame = display_l4gen_draw_frame,
	.draw_stats = display_l4gen_draw_stats,
	.get_height = display_l4gen_get_height,
	.title = "l4gen",
};

struct display_screen *display_l4gen(void)
{
	return &display_screen_l4gen;
}
