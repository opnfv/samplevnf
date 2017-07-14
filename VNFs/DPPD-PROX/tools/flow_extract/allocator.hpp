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

#ifndef _ALLOCATOR_H_
#define _ALLOCATOR_H_

#include <cstddef>
#include <inttypes.h>

class Allocator {
public:
	Allocator(size_t size, size_t lowThreshold);
	~Allocator();
	bool lowThresholdReached() const;
	void *alloc(size_t size);
	void reset();
	size_t getFreeSize() const;
private:
	size_t  m_size;
	size_t  m_threshold;
	size_t  m_alloc_offset;
	uint8_t *m_mem;
};

#endif /* _ALLOCATOR_H_ */
