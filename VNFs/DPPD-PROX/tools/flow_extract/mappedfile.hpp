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

#ifndef _MAPPEDFILE_H_
#define _MAPPEDFILE_H_

#include <inttypes.h>
#include <string>

using namespace std;

class MappedFile {
public:
	int open(const string& filePath, size_t size);
	int open(const string& filePath);
	void close();
	int sync();
	uint8_t* getMapBeg() {return (uint8_t *)data;}
	uint8_t* getMapEnd() {return (uint8_t *)data + mappedFileSize;}
	size_t size() const;
private:
	int fd;
	size_t mappedFileSize;
	void *data;
};

#endif /* _MAPPEDFILE_H_ */
