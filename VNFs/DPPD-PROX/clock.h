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

#ifndef _CLOCK_H_
#define _CLOCK_H_

#include <inttypes.h>

extern uint32_t rdtsc_overhead;
extern uint32_t rdtsc_overhead_stats;

void clock_init(void);

struct time_unit {
	uint64_t sec;
	uint64_t nsec;
};

struct time_unit_err {
	struct time_unit time;
	struct time_unit error;
};

extern uint64_t thresh;
extern uint64_t tsc_hz;

static uint64_t val_to_rate(uint64_t val, uint64_t delta_t)
{
	if (val < thresh) {
		return val * tsc_hz / delta_t;
	} else if (val >> 2 < thresh) {
		/* bytes per sec malls into this category ... */
		return ((val >> 2) * tsc_hz) / (delta_t >> 2);
	} else {
		if (delta_t < tsc_hz)
			return UINT64_MAX;
		else
			return val / (delta_t/tsc_hz);
	}
}

/* The precision of the conversion is nano-second. */
uint64_t str_to_tsc(const char *from);
uint64_t sec_to_tsc(uint64_t sec);
uint64_t msec_to_tsc(uint64_t msec);
uint64_t usec_to_tsc(uint64_t usec);
uint64_t nsec_to_tsc(uint64_t nsec);
uint64_t freq_to_tsc(uint64_t times_per_sec);
uint64_t tsc_to_msec(uint64_t tsc);
uint64_t tsc_to_usec(uint64_t tsc);
uint64_t tsc_to_nsec(uint64_t tsc);
uint64_t tsc_to_sec(uint64_t tsc);
struct time_unit tsc_to_time_unit(uint64_t tsc);
uint64_t time_unit_to_usec(struct time_unit *time_unit);
uint64_t time_unit_to_nsec(struct time_unit *time_unit);
int time_unit_cmp(struct time_unit *left, struct time_unit *right);

struct timeval;
void tsc_to_tv(struct timeval *tv, const uint64_t tsc);
void tv_to_tsc(const struct timeval *tv, uint64_t *tsc);
struct timeval tv_diff(const struct timeval *tv1, const struct timeval * tv2);

#endif /* _CLOCK_H_ */
