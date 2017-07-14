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

#ifndef _TOKEN_TIME_H_
#define _TOKEN_TIME_H_

#include <rte_cycles.h>
#include <math.h>

#include "prox_assert.h"

struct token_time_cfg {
	uint64_t bpp;
	uint64_t period;
	uint64_t bytes_max;
};

struct token_time {
	uint64_t tsc_last;
	uint64_t tsc_last_bytes;
	uint64_t bytes_now;
	struct token_time_cfg cfg;
};

/* Convert a given fractional bytes per period into bpp with as
   minimal loss of accuracy. */
static struct token_time_cfg token_time_cfg_create(double frac, uint64_t period, uint64_t bytes_max)
{
	struct token_time_cfg ret;

	/* Since period is expressed in units of cycles and it is in
	   most cases set to 1 second (which means its value is <=
	   3*10^9) and 2^64/10^9 > 6148914691 > 2^32). This means that
	   at most, period and frac will be doubled 32 times by the
	   following algorithm. Hence, the total error introduced by
	   the chosen values for bpp and period will be between 0 and
	   1/2^33. Note that since there are more operations that
	   can't overflow, the actual accuracy will probably be
	   lower. */

	/* The reason to limit period by UINT64_MAX/(uint64_t)frac is
	   that at run-time, the token_time_update function will
	   multiply a number that is <= period with bpp. In addition,
	   the token_time_tsc_until function will multiply at most
	   bytes_max with period so make sure that can't overflow. */

	while (period < UINT64_MAX/2 && frac != floor(frac) &&
	       (frac < 2.0f || period < UINT64_MAX/4/(uint64_t)frac) &&
	       (bytes_max == UINT64_MAX || period < UINT64_MAX/2/bytes_max)) {
		period *= 2;
		frac *= 2;
	}

	ret.bpp = floor(frac + 0.5);
	ret.period = period;
	ret.bytes_max = bytes_max;

	return ret;
}

static void token_time_update(struct token_time *tt, uint64_t tsc)
{
	uint64_t new_bytes;
	uint64_t t_diff = tsc - tt->tsc_last;

	/* Since the rate is expressed in tt->bpp, i.e. bytes per
	   period, counters can only be incremented/decremented
	   accurately every period cycles. */

	/* If the last update was more than a period ago, the update
	   can be performed accurately. */
	if (t_diff > tt->cfg.period) {
		/* First add remaining tokens in the last period that
		   was added partially. */
		new_bytes = tt->cfg.bpp - tt->tsc_last_bytes;
		tt->tsc_last_bytes = 0;
		tt->bytes_now += new_bytes;
		t_diff -= tt->cfg.period;
		tt->tsc_last += tt->cfg.period;

		/* If now it turns out that more periods have elapsed,
		   add the bytes for those periods directly. */
		if (t_diff > tt->cfg.period) {
			uint64_t periods = t_diff/tt->cfg.period;

			tt->bytes_now += periods * tt->cfg.bpp;
			t_diff -= tt->cfg.period * periods;
			tt->tsc_last += tt->cfg.period * periods;
		}
	}

	/* At this point, t_diff will be guaranteed to be less
	   than tt->cfg.period. */
	new_bytes = t_diff * tt->cfg.bpp/tt->cfg.period - tt->tsc_last_bytes;
	tt->tsc_last_bytes += new_bytes;
	tt->bytes_now += new_bytes;
	if (tt->bytes_now > tt->cfg.bytes_max)
		tt->bytes_now = tt->cfg.bytes_max;
}

static void token_time_set_bpp(struct token_time *tt, uint64_t bpp)
{
	tt->cfg.bpp = bpp;
}

static void token_time_init(struct token_time *tt, const struct token_time_cfg *cfg)
{
	tt->cfg = *cfg;
}

static void token_time_reset(struct token_time *tt, uint64_t tsc, uint64_t bytes_now)
{
	tt->tsc_last = tsc;
	tt->bytes_now = bytes_now;
	tt->tsc_last_bytes = 0;
}

static void token_time_reset_full(struct token_time *tt, uint64_t tsc)
{
	token_time_reset(tt, tsc, tt->cfg.bytes_max);
}

static int token_time_take(struct token_time *tt, uint64_t bytes)
{
	if (bytes > tt->bytes_now)
		return -1;
	tt->bytes_now -= bytes;
	return 0;
}

static void token_time_take_clamp(struct token_time *tt, uint64_t bytes)
{
	if (bytes > tt->bytes_now)
		tt->bytes_now = 0;
	else
		tt->bytes_now -= bytes;
}

static uint64_t token_time_tsc_until(const struct token_time *tt, uint64_t bytes)
{
	if (tt->bytes_now >= bytes)
		return 0;

	return (bytes - tt->bytes_now) * tt->cfg.period / tt->cfg.bpp;
}

static uint64_t token_time_tsc_until_full(const struct token_time *tt)
{
	return token_time_tsc_until(tt, tt->cfg.bytes_max);
}

#endif /* _TOKEN_TIME_H_ */
