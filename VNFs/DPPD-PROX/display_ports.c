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

#include <rte_cycles.h>

#include "clock.h"
#include "display_ports.h"
#include "display.h"
#include "stats_port.h"
#include "prox_globals.h"
#include "prox_port_cfg.h"
#include "prox_compat.h"

static struct display_page display_page_ports;
static struct display_column *nb_col;
static struct display_column *name_col;
static struct display_column *type_col;

static struct display_column *no_mbufs_col;
static struct display_column *ierrors_col;
static struct display_column *imissed_col;
static struct display_column *oerrors_col;
static struct display_column *rx_col;
static struct display_column *tx_col;
static struct display_column *rx_bytes_col;
static struct display_column *tx_bytes_col;
static struct display_column *rx_percent_col;
static struct display_column *tx_percent_col;

static int port_disp[PROX_MAX_PORTS];
static int n_port_disp;

static void display_ports_draw_frame(struct screen_state *state)
{
	n_port_disp = 0;
	for (uint8_t i = 0; i < PROX_MAX_PORTS; ++i) {
		if (prox_port_cfg[i].active) {
			port_disp[n_port_disp++] = i;
		}
	}

	const uint32_t n_ports = stats_get_n_ports();
	char name[32];
	char *ptr;

	display_page_init(&display_page_ports);

	struct display_table *port = display_page_add_table(&display_page_ports);
	struct display_table *stats = display_page_add_table(&display_page_ports);

	display_table_init(port, "Port");

	nb_col = display_table_add_col(port);
	name_col = display_table_add_col(port);
	type_col = display_table_add_col(port);

	display_column_init(nb_col, "Nb", 4);
	display_column_init(name_col, "Name", 8);
	display_column_init(type_col, "Type", 7);

	if (state->toggle == 0) {
		display_table_init(stats, "Statistics per second");
		no_mbufs_col = display_table_add_col(stats);
		ierrors_col = display_table_add_col(stats);
		imissed_col = display_table_add_col(stats);
		oerrors_col = display_table_add_col(stats);
		rx_col = display_table_add_col(stats);
		tx_col = display_table_add_col(stats);
		rx_bytes_col = display_table_add_col(stats);
		tx_bytes_col = display_table_add_col(stats);
		rx_percent_col = display_table_add_col(stats);
		tx_percent_col = display_table_add_col(stats);

		display_column_init(no_mbufs_col, "no mbufs (#)", 12);
		display_column_init(ierrors_col, "ierrors (#)", 12);
		display_column_init(imissed_col, "imissed (#)", 12);
		display_column_init(oerrors_col, "oerrors (#)", 12);
		display_column_init(rx_col, "RX (Kpps)", 10);
		display_column_init(tx_col, "TX (Kpps)", 10);
		display_column_init(rx_bytes_col, "RX (Kbps)", 10);
		display_column_init(tx_bytes_col, "TX (Kbps)", 10);
		display_column_init(rx_percent_col, "RX (%)", 8);
		display_column_init(tx_percent_col, "TX (%)", 8);
	} else {
		display_table_init(stats, "Total statistics");
		no_mbufs_col = display_table_add_col(stats);
		ierrors_col = display_table_add_col(stats);
		imissed_col = display_table_add_col(stats);
		oerrors_col = display_table_add_col(stats);
		rx_col = display_table_add_col(stats);
		tx_col = display_table_add_col(stats);

		display_column_init(no_mbufs_col, "no mbufs (#)", 13);
		display_column_init(ierrors_col, "ierrors (#)", 13);
		display_column_init(imissed_col, "imissed (#)", 13);
		display_column_init(oerrors_col, "oerrors (#)", 13);
		display_column_init(rx_col, "RX (#)", 13);
		display_column_init(tx_col, "TX (#)", 13);
	}

	display_page_draw_frame(&display_page_ports, n_port_disp);
	for (uint8_t i = 0; i < n_port_disp; ++i) {
		const uint32_t port_id = port_disp[i];

		display_column_print(nb_col, i, "%u", port_id);
		display_column_print(name_col, i, "%s", prox_port_cfg[port_id].name);
		display_column_print(type_col, i, "%s", prox_port_cfg[port_id].short_name);
	}
}

struct percent {
	uint32_t percent;
	uint32_t part;
};

static struct percent calc_percent(uint64_t val, uint64_t delta_t)
{
	struct percent ret;
	uint64_t normalized = 0;

	if (val == 0) {
		ret.percent = 0;
		ret.part = 0;
	} else if (val < thresh) {
		ret.percent = val * tsc_hz / delta_t / 12500000;
		ret.part = (val * tsc_hz / delta_t / 1250) % 10000;
	} else if (delta_t > tsc_hz) {
		ret.percent = val / (delta_t / tsc_hz) / 12500000;
		ret.part = (val / (delta_t / tsc_hz) / 1250) % 10000;
	} else {
		ret.percent = 0;
		ret.part = 0;
	}
	return ret;
}

static void display_ports_draw_per_sec_stats(void)
{
	for (uint8_t i = 0; i < n_port_disp; ++i) {
		const uint32_t port_id = port_disp[i];
		struct port_stats_sample *last = stats_get_port_stats_sample(port_id, 1);
		struct port_stats_sample *prev = stats_get_port_stats_sample(port_id, 0);

		uint64_t delta_t = last->tsc - prev->tsc;

		/* This could happen if we just reset the screen.
		   stats will be updated later */
		if (delta_t == 0)
			continue;

		uint64_t no_mbufs_rate = val_to_rate(last->no_mbufs - prev->no_mbufs, delta_t);
		uint64_t ierrors_rate = val_to_rate(last->ierrors - prev->ierrors, delta_t);
		uint64_t imissed_rate = val_to_rate(last->imissed - prev->imissed, delta_t);
		uint64_t oerrors_rate = val_to_rate(last->oerrors - prev->oerrors, delta_t);

		uint64_t rx_kbps_rate = val_to_rate((last->rx_bytes - prev->rx_bytes) * 8, delta_t) / 1000;
		uint64_t tx_kbps_rate = val_to_rate((last->tx_bytes - prev->tx_bytes) * 8, delta_t) / 1000;

		uint64_t rx_rate = val_to_rate(last->rx_tot - prev->rx_tot, delta_t) / 1000;
		if (unlikely(prev->rx_tot > last->rx_tot))
			rx_rate = 0;
		uint64_t tx_rate = val_to_rate(last->tx_tot - prev->tx_tot, delta_t) / 1000;
		if (unlikely(prev->tx_tot > last->tx_tot))
			tx_rate = 0;

		/* Take 20 bytes overhead (or 24 if crc strip is enabled) into accound */
		struct percent rx_percent;
		struct percent tx_percent;
		if (strcmp(prox_port_cfg[port_id].short_name, "i40e") == 0) {
			if (prox_port_cfg[port_id].requested_rx_offload & DEV_RX_OFFLOAD_CRC_STRIP) {
				rx_percent = calc_percent(last->rx_bytes - prev->rx_bytes + 24 * (last->rx_tot - prev->rx_tot), delta_t);
				tx_percent = calc_percent(last->tx_bytes - prev->tx_bytes + 24 * (last->tx_tot - prev->tx_tot), delta_t);
			} else {
				rx_percent = calc_percent(last->rx_bytes - prev->rx_bytes + 20 * (last->rx_tot - prev->rx_tot), delta_t);
				tx_percent = calc_percent(last->tx_bytes - prev->tx_bytes + 20 * (last->tx_tot - prev->tx_tot), delta_t);
			}
		} else {
			if (prox_port_cfg[port_id].requested_rx_offload & DEV_RX_OFFLOAD_CRC_STRIP) {
				rx_percent = calc_percent(last->rx_bytes - prev->rx_bytes + 24 * (last->rx_tot - prev->rx_tot), delta_t);
				tx_percent = calc_percent(last->tx_bytes - prev->tx_bytes + 24 * (last->tx_tot - prev->tx_tot), delta_t);
			} else {
				rx_percent = calc_percent(last->rx_bytes - prev->rx_bytes + 20 * (last->rx_tot - prev->rx_tot), delta_t);
				tx_percent = calc_percent(last->tx_bytes - prev->tx_bytes + 20 * (last->tx_tot - prev->tx_tot), delta_t);
			}
		}

		display_column_print(no_mbufs_col, i, "%lu", no_mbufs_rate);
		display_column_print(ierrors_col, i, "%lu", ierrors_rate);
		display_column_print(imissed_col, i, "%lu", imissed_rate);
		display_column_print(oerrors_col, i, "%lu", oerrors_rate);

		display_column_print(rx_bytes_col, i, "%lu", rx_kbps_rate);
		display_column_print(tx_bytes_col, i, "%lu", tx_kbps_rate);
		display_column_print(rx_col, i, "%lu", rx_rate);
		display_column_print(tx_col, i, "%lu", tx_rate);

		display_column_print(rx_percent_col, i, "%3u.%04u", rx_percent.percent, rx_percent.part);
		display_column_print(tx_percent_col, i, "%3u.%04u", tx_percent.percent, tx_percent.part);
	}
}

static void display_ports_draw_total_stats(void)
{
	for (uint8_t i = 0; i < n_port_disp; ++i) {
		const uint32_t port_id = port_disp[i];
		struct port_stats_sample *last = stats_get_port_stats_sample(port_id, 1);

		display_column_print(no_mbufs_col, i, "%lu", last->no_mbufs);
		display_column_print(ierrors_col, i, "%lu", last->ierrors);
		display_column_print(imissed_col, i, "%lu", last->imissed);
		display_column_print(oerrors_col, i, "%lu", last->oerrors);
		display_column_print(rx_col, i, "%lu", last->rx_tot);
		display_column_print(tx_col, i, "%lu", last->tx_tot);
	}
}

static void display_ports_draw_stats(struct screen_state *state)
{
	if (state->toggle == 0)
		display_ports_draw_per_sec_stats();
	else
		display_ports_draw_total_stats();
}

static int display_ports_get_height(void)
{
	return stats_get_n_ports();
}

static struct display_screen display_screen_ports = {
	.draw_frame = display_ports_draw_frame,
	.draw_stats = display_ports_draw_stats,
	.get_height = display_ports_get_height,
	.title = "ports",
};

struct display_screen *display_ports(void)
{
	return &display_screen_ports;
}
