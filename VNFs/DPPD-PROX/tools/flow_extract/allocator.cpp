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

#include <iostream>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define USEHP

using namespace std;

#include "allocator.hpp"

Allocator::Allocator(size_t size, size_t threshold)
	: m_size(size), m_threshold(threshold), m_alloc_offset(0)
{
#ifdef USEHP
	int fd = open("/mnt/huge/hp", O_CREAT | O_RDWR, 0755);
	if (fd < 0) {
		cerr << "Allocator failed to open huge page file descriptor: " << strerror(errno) << endl;
		exit(EXIT_FAILURE);
	}
	m_mem = (uint8_t *)mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (m_mem == MAP_FAILED) {
		perror("mmap");
		unlink("/mnt/huge");
		cerr << "Allocator mmap failed: " << strerror(errno) << endl;
		exit (EXIT_FAILURE);
	}
#else
	m_mem = new uint8_t[size];
#endif
}

Allocator::~Allocator()
{
#ifdef USEHP
	munmap((void *)m_mem, m_size);
#else
	delete[] m_mem;
#endif
}

void *Allocator::alloc(size_t size)
{
	void *ret = &m_mem[m_alloc_offset];

	m_alloc_offset += size;
	return ret;
}

void Allocator::reset()
{
	m_alloc_offset = 0;
}

size_t Allocator::getFreeSize() const
{
	return m_size - m_alloc_offset;
}

bool Allocator::lowThresholdReached() const
{
	return (m_size - m_alloc_offset) < m_threshold;
}
