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

#include "clock.h"

#include <stdio.h>
#include <string.h>

#include <rte_cycles.h>

/* Calibrate TSC overhead by reading NB_READ times and take the smallest value.
   Bigger values are caused by external influence and can be discarded. The best
   estimate is the smallest read value. */
#define NB_READ 10000

uint32_t rdtsc_overhead;
uint32_t rdtsc_overhead_stats;

uint64_t thresh;
uint64_t tsc_hz;

/* calculate how much overhead is involved with calling rdtsc. This value has
   to be taken into account where the time spent running a small piece of code
   is measured */
static void init_tsc_overhead(void)
{
	volatile uint32_t min_without_overhead = UINT32_MAX;
	volatile uint32_t min_with_overhead = UINT32_MAX;
	volatile uint32_t min_stats_overhead = UINT32_MAX;
	volatile uint64_t start1, end1;
	volatile uint64_t start2, end2;

	for (uint32_t i = 0; i < NB_READ; ++i) {
		start1 = rte_rdtsc();
		end1   = rte_rdtsc();

		start2 = rte_rdtsc();
		end2   = rte_rdtsc();
		end2   = rte_rdtsc();

		if (min_without_overhead > end1 - start1) {
			min_without_overhead = end1 - start1;
		}

		if (min_with_overhead > end2 - start2) {
			min_with_overhead = end2 - start2;
		}
	}

	rdtsc_overhead = min_with_overhead - min_without_overhead;

	start1 = rte_rdtsc();
	end1   = rte_rdtsc();
	/* forbid the compiler to optimize this dummy variable */
	volatile int dummy = 0;
	for (uint32_t i = 0; i < NB_READ; ++i) {
		start1 = rte_rdtsc();
		dummy += 32;
		end1   = rte_rdtsc();

		if (min_stats_overhead > end2 - start2) {
			min_stats_overhead = end1 - start1;
		}
	}

	rdtsc_overhead_stats = rdtsc_overhead + min_stats_overhead - min_without_overhead;
}

void clock_init(void)
{
	init_tsc_overhead();
	tsc_hz = rte_get_tsc_hz();
	thresh = UINT64_MAX/tsc_hz;
}

uint64_t str_to_tsc(const char *from)
{
	const uint64_t hz = rte_get_tsc_hz();
	uint64_t ret;
	char str[16];

	strncpy(str, from, sizeof(str));

	char *frac = strchr(str, '.');

	if (frac) {
		*frac = 0;
		frac++;
	}

	ret = hz * atoi(str);

	if (!frac)
		return ret;

	uint64_t nsec = 0;
	uint64_t multiplier = 100000000;

	for (size_t i = 0; i < strlen(frac); ++i) {
		nsec += (frac[i] - '0') * multiplier;
		multiplier /= 10;
	}

	/* Wont overflow until CPU freq is ~18.44 GHz */
	ret += hz * nsec/1000000000;

	return ret;
}

uint64_t sec_to_tsc(uint64_t sec)
{
	if (sec < UINT64_MAX/rte_get_tsc_hz())
		return sec * rte_get_tsc_hz();
	else
		return UINT64_MAX;
}

uint64_t msec_to_tsc(uint64_t msec)
{
	if (msec < UINT64_MAX/rte_get_tsc_hz())
		return msec * rte_get_tsc_hz() / 1000;
	else
		return msec / 1000 * rte_get_tsc_hz();
}

uint64_t usec_to_tsc(uint64_t usec)
{
	if (usec < UINT64_MAX/rte_get_tsc_hz())
		return usec * rte_get_tsc_hz() / 1000000;
	else
		return usec / 1000000 * rte_get_tsc_hz();
}

uint64_t nsec_to_tsc(uint64_t nsec)
{
	if (nsec < UINT64_MAX/rte_get_tsc_hz())
		return nsec * rte_get_tsc_hz() / 1000000000;
	else
		return nsec / 1000000000 * rte_get_tsc_hz();
}

uint64_t tsc_to_msec(uint64_t tsc)
{
	if (tsc < UINT64_MAX / 1000) {
		return tsc * 1000 / rte_get_tsc_hz();
	} else {
		return tsc / (rte_get_tsc_hz() / 1000);
	}
}

uint64_t tsc_to_usec(uint64_t tsc)
{
	if (tsc < UINT64_MAX / 1000000) {
		return tsc * 1000000 / rte_get_tsc_hz();
	} else {
		return tsc / (rte_get_tsc_hz() / 1000000);
	}
}

uint64_t tsc_to_nsec(uint64_t tsc)
{
	if (tsc < UINT64_MAX / 1000000000) {
		return tsc * 1000000000 / rte_get_tsc_hz();
	} else {
		return tsc / (rte_get_tsc_hz() / 1000000000);
	}
}

uint64_t tsc_to_sec(uint64_t tsc)
{
	return tsc / rte_get_tsc_hz();
}

struct time_unit tsc_to_time_unit(uint64_t tsc)
{
	struct time_unit ret;
	uint64_t hz = rte_get_tsc_hz();

	ret.sec = tsc/hz;
	ret.nsec = (tsc - ret.sec*hz)*1000000000/hz;

	return ret;
}

uint64_t time_unit_to_usec(struct time_unit *time_unit)
{
	return time_unit->sec * 1000000 + time_unit->nsec/1000;
}

uint64_t time_unit_to_nsec(struct time_unit *time_unit)
{
	return time_unit->sec * 1000000000 + time_unit->nsec;
}

int time_unit_cmp(struct time_unit *left, struct time_unit *right)
{
	if (left->sec < right->sec)
		return -1;
	if (left->sec > right->sec)
		return 1;

	if (left->nsec < right->nsec)
		return -1;
	if (left->nsec > right->nsec)
		return -1;
	return 0;
}

uint64_t freq_to_tsc(uint64_t times_per_sec)
{
	return rte_get_tsc_hz()/times_per_sec;
}

void tsc_to_tv(struct timeval *tv, const uint64_t tsc)
{
	uint64_t hz = rte_get_tsc_hz();
	uint64_t sec = tsc/hz;

	tv->tv_sec = sec;
	tv->tv_usec = ((tsc - sec * hz) * 1000000) / hz;
}

void tv_to_tsc(const struct timeval *tv, uint64_t *tsc)
{
	uint64_t hz = rte_get_tsc_hz();
	*tsc = tv->tv_sec * hz;
	*tsc += tv->tv_usec * hz / 1000000;
}

struct timeval tv_diff(const struct timeval *cur, const struct timeval *next)
{
	uint64_t sec, usec;

	sec = next->tv_sec - cur->tv_sec;
	if (next->tv_usec < cur->tv_usec) {
		usec = next->tv_usec + 1000000 - cur->tv_usec;
		sec -= 1;
	}
	else
		usec = next->tv_usec - cur->tv_usec;

	struct timeval ret = {
		.tv_sec  = sec,
		.tv_usec = usec,
	};

	return ret;
}
