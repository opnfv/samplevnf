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

#ifndef _MEMREADER_H_
#define _MEMREADER_H_

#include <vector>
#include <inttypes.h>

using namespace std;

class Stream3;
class MappedFile;

class MemReader {
public:
	MemReader(MappedFile *file, const vector<size_t> &offsets);
        bool read(Stream3 *stream);
	size_t getTotalLength() const {return totalLength;}
	size_t consumed() const;
private:
	size_t getRangeLengths() const;
        uint32_t getLowestID() const;
	void removeEmptyRanges();
	void readStream(Stream3 *stream, uint32_t id);
	void initRanges(uint8_t *begin, uint8_t *end, const vector<size_t> &offsets);

	size_t totalLength;
	vector<pair <uint8_t *, uint8_t *> > ranges;
};

#endif /* _MEMREADER_H_ */
