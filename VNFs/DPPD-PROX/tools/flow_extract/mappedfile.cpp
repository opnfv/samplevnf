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

#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <cerrno>
#include <sys/mman.h>
#include <cstring>

#include "mappedfile.hpp"

static void zeroOutFile(int fd, size_t size)
{
	void *empty = calloc(1, 4096);

	while (size > 4096) {
		write(fd, empty, 4096);
		size -= 4096;
	}
	write(fd, empty, size);
	free(empty);
}

int MappedFile::open(const string& filePath, size_t size)
{
	mappedFileSize = size;

	fd = ::open(filePath.c_str(), O_RDWR | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		cerr << "Failed to open file " << filePath << ":" << strerror(errno) << endl;
		return -1;
	}

	zeroOutFile(fd, size);
	data = mmap(NULL, mappedFileSize, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);

	if (data == MAP_FAILED) {
		cerr << "Failed to map file: " << strerror(errno) << endl;
		return -1;
	}
	return 0;
}

static size_t getFileSize(const string& filePath)
{
	struct stat s;
	if (stat(filePath.c_str(), &s))
		return -1;

	return s.st_size;
}

int MappedFile::open(const string& filePath)
{
	mappedFileSize = getFileSize(filePath);

	fd = ::open(filePath.c_str(), O_RDONLY);
	if (fd < 0) {
		cerr << "Failed to open file " << filePath << ":" << strerror(errno) << endl;
		return -1;
	}

	data = mmap(NULL, mappedFileSize, PROT_READ, MAP_SHARED, fd, 0);

	if (data == MAP_FAILED) {
		cerr << "Failed to map file: " << strerror(errno) << endl;
		return -1;
	}
	return 0;
}

int MappedFile::sync()
{
	if (msync(data, mappedFileSize, MS_SYNC) == -1) {
		cerr << "Failed to sync: " << strerror(errno) << endl;
		return -1;
	}
	return 0;
}


void MappedFile::close()
{
	sync();
	munmap(data, mappedFileSize);
	::close(fd);
}

size_t MappedFile::size() const
{
	return mappedFileSize;
}
