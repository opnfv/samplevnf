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

#ifndef _HANDLE_LB_NET_H_
#define _HANDLE_LB_NET_H_

#include "defaults.h"

static inline int8_t rss_to_queue(int rss, int nb_queues)
{
        return (rss & ((1 << MAX_RSS_QUEUE_BITS) - 1)) % nb_queues;
}

#endif /* _HANDLE_LB_NET_H_ */
