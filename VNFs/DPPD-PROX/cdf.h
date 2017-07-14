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

struct cdf {
	uint32_t rand_max;
	uint32_t seed;
	uint32_t first_child;
	uint32_t elems[0];
};

struct cdf *cdf_create(uint32_t n_vals, int socket_id);
void cdf_add(struct cdf *cdf, uint32_t len);
int cdf_setup(struct cdf *cdf);

static uint32_t cdf_sample(struct cdf *cdf)
{
	uint32_t left_child, right_child;
	uint32_t rand;

	do {
		rand = rand_r(&cdf->seed);
	} while (rand > cdf->rand_max);

	uint32_t cur = 1;

	while (1) {
		left_child = cur * 2;
		right_child = cur * 2 + 1;
		if (right_child < cdf->elems[0])
			cur = rand > cdf->elems[cur]? right_child : left_child;
		else if (left_child < cdf->elems[0])
			cur = left_child;
		else
			return cur - cdf->first_child;
	}
}
