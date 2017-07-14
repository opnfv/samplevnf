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

/*
  This pseudorandom number generator is based on ref_xorshift128plus,
  as implemented by reference_xorshift.h, which has been obtained
  from https://sourceforge.net/projects/xorshift-cpp/

  The licensing terms for reference_xorshift.h are reproduced below.

  //  Written in 2014 by Ivo Doko (ivo.doko@gmail.com)
  //  based on code written by Sebastiano Vigna (vigna@acm.org)
  //  To the extent possible under law, the author has dedicated
  //  all copyright and related and neighboring rights to this
  //  software to the public domain worldwide. This software is
  //  distributed without any warranty.
  //  See <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#ifndef _RANDOM_H_
#define _RANDOM_H_

#include <rte_cycles.h>

struct random {
  uint64_t state[2];
};

static void random_init_seed(struct random *random)
{
  random->state[0] = rte_rdtsc();
  random->state[1] = rte_rdtsc();
}

static uint64_t random_next(struct random *random)
{
  const uint64_t s0 = random->state[1];
  const uint64_t s1 = random->state[0] ^ (random->state[0] << 23);

  random->state[0] = random->state[1];
  random->state[1] = (s1 ^ (s1 >> 18) ^ s0 ^ (s0 >> 5)) + s0;
  return random->state[1];
}

#endif /* _RANDOM_H_ */
