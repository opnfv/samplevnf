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

#ifndef _STREAMSORTER_H_
#define _STREAMSORTER_H_

#include "stream3.hpp"
#include "flowtable.hpp"
#include "allocator.hpp"

class StreamSorter {
public:
	StreamSorter(size_t flowTableSize, const string& workingDirectory, size_t memoryLimit);
	void sort(const string &inputPcapFile, const string &outputBinFile);
private:
	void sortChunks(const string &inputPcapFilePath);
	void mergeChunks(const string &outputBinFilePath);
	void setTempFileName();
	void processPkt(const PcapPkt &pkt);
	void resetStreams();
	FlowTable<pkt_tuple, uint32_t>::entry* getFlowEntry(const PcapPkt &pkt);
	void flushStreams(ofstream *outputTempFile);
	Stream3 *addNewStream(PcapPkt::L4Proto proto);
	size_t flowTableSize;
	FlowTable<pkt_tuple, uint32_t> *ft;
	vector<size_t> flushOffsets;
	vector<Stream3> streams;
	string tempFilePath;
	const string workingDirectory;
	Allocator allocator;
	uint32_t streamID;
};

#endif /* _STREAMSORTER_H_ */
