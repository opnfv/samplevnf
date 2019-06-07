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

#ifndef _HANDLE_LAT_H_
#define _HANDLE_LAT_H_

#include <stdio.h>
#include <math.h>
#include <string.h>

#include "task_base.h"
#include "clock.h"

#define LATENCY_ACCURACY	1
// If ACCURACY_WINDOW is too small, the accuracy for packet N can be received by lat BEFORE
// packet N is received (re-ordering) resulting in accuracy being unused
// 8192 packets is equivalent to 550 micro-seconds at 10Gbps for 64 bytes packets
#define ACCURACY_WINDOW		8192

struct lat_test {
	uint64_t tot_all_pkts;
	uint64_t tot_pkts;
	uint64_t max_lat;
	uint64_t min_lat;
	uint64_t tot_lat;
	unsigned __int128 var_lat; /* variance */
	uint64_t accuracy_limit_tsc;

	uint64_t max_lat_error;
	uint64_t min_lat_error;
	uint64_t tot_lat_error;
	unsigned __int128 var_lat_error;

	uint64_t buckets[128];
	uint64_t bucket_size;
	uint64_t lost_packets;
};

static struct time_unit lat_test_get_accuracy_limit(struct lat_test *lat_test)
{
	return tsc_to_time_unit(lat_test->accuracy_limit_tsc);
}

static struct time_unit_err lat_test_get_avg(struct lat_test *lat_test)
{
	uint64_t tsc;
	uint64_t tsc_error;

	tsc = lat_test->tot_lat/lat_test->tot_pkts;
	tsc_error = lat_test->tot_lat_error/lat_test->tot_pkts;

	struct time_unit_err ret = {
		.time = tsc_to_time_unit(tsc),
		.error = tsc_to_time_unit(tsc_error),
	};

	return ret;
}

static struct time_unit_err lat_test_get_min(struct lat_test *lat_test)
{
	struct time_unit_err ret = {
		.time = tsc_to_time_unit(lat_test->min_lat),
		.error = tsc_to_time_unit(lat_test->min_lat_error),
	};

	return ret;
}

static struct time_unit_err lat_test_get_max(struct lat_test *lat_test)
{
	struct time_unit_err ret = {
		.time = tsc_to_time_unit(lat_test->max_lat),
		.error = tsc_to_time_unit(lat_test->max_lat_error),
	};

	return ret;
}

static struct time_unit_err lat_test_get_stddev(struct lat_test *lat_test)
{
	unsigned __int128 avg_tsc = lat_test->tot_lat/lat_test->tot_pkts;
	unsigned __int128 avg_tsc_squared = avg_tsc * avg_tsc;
	unsigned __int128 avg_squares_tsc = lat_test->var_lat/lat_test->tot_pkts;

	/* The assumption is that variance fits into 64 bits, meaning
	   that standard deviation fits into 32 bits. In other words,
	   the assumption is that the standard deviation is not more
	   than approximately 1 second. */
	uint64_t var_tsc = avg_squares_tsc - avg_tsc_squared;
	uint64_t stddev_tsc = sqrt(var_tsc);

	unsigned __int128 avg_tsc_error = lat_test->tot_lat_error / lat_test->tot_pkts;
	unsigned __int128 avg_tsc_squared_error = 2 * avg_tsc * avg_tsc_error + avg_tsc_error * avg_tsc_error;
	unsigned __int128 avg_squares_tsc_error = lat_test->var_lat_error / lat_test->tot_pkts;

	uint64_t var_tsc_error = avg_squares_tsc_error + avg_tsc_squared_error;

	/* sqrt(a+-b) = sqrt(a) +- (-sqrt(a) + sqrt(a + b)) */

	uint64_t stddev_tsc_error = - stddev_tsc + sqrt(var_tsc + var_tsc_error);

	struct time_unit_err ret = {
		.time = tsc_to_time_unit(stddev_tsc),
		.error = tsc_to_time_unit(stddev_tsc_error),
	};

	return ret;
}

static void _lat_test_histogram_combine(struct lat_test *dst, struct lat_test *src)
{
	for (size_t i = 0; i < sizeof(dst->buckets)/sizeof(dst->buckets[0]); ++i)
		dst->buckets[i] += src->buckets[i];
}

static void lat_test_combine(struct lat_test *dst, struct lat_test *src)
{
	dst->tot_all_pkts += src->tot_all_pkts;

	dst->tot_pkts += src->tot_pkts;

	dst->tot_lat += src->tot_lat;
	dst->tot_lat_error += src->tot_lat_error;

	/* (a +- b)^2 = a^2 +- (2ab + b^2) */
	dst->var_lat += src->var_lat;
	dst->var_lat_error += src->var_lat_error;

	if (src->max_lat > dst->max_lat) {
		dst->max_lat = src->max_lat;
		dst->max_lat_error = src->max_lat_error;
	}
	if (src->min_lat < dst->min_lat) {
		dst->min_lat = src->min_lat;
		dst->min_lat_error = src->min_lat_error;
	}

	if (src->accuracy_limit_tsc > dst->accuracy_limit_tsc)
		dst->accuracy_limit_tsc = src->accuracy_limit_tsc;
	dst->lost_packets += src->lost_packets;

#ifdef LATENCY_HISTOGRAM
	_lat_test_histogram_combine(dst, src);
#endif
}

static void lat_test_reset(struct lat_test *lat_test)
{
	lat_test->tot_all_pkts = 0;
	lat_test->tot_pkts = 0;
	lat_test->max_lat = 0;
	lat_test->min_lat = -1;
	lat_test->tot_lat = 0;
	lat_test->var_lat = 0;
	lat_test->max_lat_error = 0;
	lat_test->min_lat_error = 0;
	lat_test->tot_lat_error = 0;
	lat_test->var_lat_error = 0;
	lat_test->accuracy_limit_tsc = 0;

	lat_test->lost_packets = 0;

	memset(lat_test->buckets, 0, sizeof(lat_test->buckets));
}

static void lat_test_copy(struct lat_test *dst, struct lat_test *src)
{
	if (src->tot_all_pkts)
		memcpy(dst, src, sizeof(struct lat_test));
}

struct task_lat;

struct lat_test *task_lat_get_latency_meassurement(struct task_lat *task);
void task_lat_use_other_latency_meassurement(struct task_lat *task);
void task_lat_set_accuracy_limit(struct task_lat *task, uint32_t accuracy_limit_nsec);

#endif /* _HANDLE_LAT_H_ */
