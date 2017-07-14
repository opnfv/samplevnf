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

#include "memreader.hpp"
#include "mappedfile.hpp"
#include "stream3.hpp"

MemReader::MemReader(MappedFile *file, const vector<size_t> &offsets)
{
	initRanges(file->getMapBeg(), file->getMapEnd(), offsets);
}

bool MemReader::read(Stream3 *stream)
{
	if (ranges.empty())
		return false;

	readStream(stream, getLowestID());
	removeEmptyRanges();
	return true;
}

uint32_t MemReader::getLowestID() const
{
	uint32_t lowestID = UINT32_MAX;
	uint32_t rangeID;

	for (size_t i = 0; i < ranges.size(); ++i) {
		rangeID = Stream3::getIDFromMem(ranges[i].first);
		if (rangeID < lowestID)
			lowestID = rangeID;
	}
	return lowestID;
}

void MemReader::readStream(Stream3 *stream, uint32_t id)
{
	stream->removeAllPackets();
	stream->setID(id);
	
	size_t len = 0;
	for (size_t i = 0; i < ranges.size(); ++i) {
		if (Stream3::getIDFromMem(ranges[i].first) == id) {
			stream->addFromMemory(ranges[i].first, &len);
			ranges[i].first += len;
		}
	}
}

void MemReader::removeEmptyRanges()
{
	vector<pair <uint8_t *, uint8_t *> > original = ranges;
	size_t destinationIdx = 0;

	for (size_t i = 0; i < original.size(); ++i) {
		if (original[i].first < original[i].second)
			ranges[destinationIdx++] = original[i];
	}
	ranges.resize(destinationIdx);
}

void MemReader::initRanges(uint8_t *begin, uint8_t *end, const vector<size_t> &offsets)
{
	ranges.resize(offsets.size());

	totalLength = 0;
	for (size_t i = 0; i < offsets.size(); ++i) {
		ranges[i].first = begin + offsets[i];
		if (i != offsets.size() - 1)
			ranges[i].second = begin + offsets[i + 1];
		else
			ranges[i].second = end;
		totalLength += ranges[i].second - ranges[i].first;
	}
	removeEmptyRanges();
}

size_t MemReader::getRangeLengths() const
{
	size_t total = 0;

	for (size_t i = 0; i < ranges.size(); ++i) {
		total += ranges[i].second - ranges[i].first;
	}
	return total;
}

size_t MemReader::consumed() const
{
	return totalLength - getRangeLengths();
}
