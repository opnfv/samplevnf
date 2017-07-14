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
#include <fstream>
#include <cstdlib>

#include "mappedfile.hpp"
#include "memreader.hpp"
#include "streamsorter.hpp"
#include "path.hpp"
#include "allocator.hpp"
#include "pcapreader.hpp"
#include "progress.hpp"

StreamSorter::StreamSorter(size_t flowTableSize, const string& workingDirectory, size_t memoryLimit)
	: flowTableSize(flowTableSize),
	  workingDirectory(workingDirectory),
	  allocator(memoryLimit, 1024*10),
	  streamID(0)
{
}

void StreamSorter::sort(const string &inputPcapFilePath, const string &outputBinFilePath)
{
	setTempFileName();
	sortChunks(inputPcapFilePath);
	mergeChunks(outputBinFilePath);
}

void StreamSorter::sortChunks(const string &inputPcapFilePath)
{
	ofstream outputTempFile;

	outputTempFile.open(tempFilePath.c_str());

	if (!outputTempFile.is_open())
		return ;

	PcapReader pr;
	PcapPkt pkt;

	if (pr.open(inputPcapFilePath)) {
		pr.getError();
		return;
	}
	PcapPkt::allocator = &allocator;

	Progress progress(pr.end());
	uint32_t packetDetail = progress.addDetail("packet count");

	ft = new FlowTable<pkt_tuple, uint32_t>(flowTableSize);
	resetStreams();

	while (pr.read(&pkt)) {
		processPkt(pkt);
		if (progress.couldRefresh()) {
			progress.setProgress(pr.pos());
			progress.setDetail(packetDetail, pr.getPktReadCount());
			progress.refresh();
		}
		if (allocator.lowThresholdReached()) {
			flushStreams(&outputTempFile);
		}
	}
	progress.setProgress();
	progress.setDetail(packetDetail, pr.getPktReadCount());
	progress.refresh(true);

	pr.close();
	flushStreams(&outputTempFile);
	PcapPkt::allocator = NULL;
	outputTempFile.close();
	delete ft;
}

void StreamSorter::resetStreams()
{
	streams.clear();
}

void StreamSorter::flushStreams(ofstream *outputTempFile)
{
	size_t flushCount = 0;
	size_t offset = outputTempFile->tellp();

	Progress progress(streams.size());

	cout << endl;
	progress.setTitle("flush ");
	for (size_t i = 0; i < streams.size(); ++i) {
		if (streams[i].hasFlushablePackets()) {
			streams[i].flush(outputTempFile);
			flushCount++;
		}

		if (progress.couldRefresh()) {
			progress.setProgress(i);
			progress.refresh();
		}
	}
	progress.setProgress();
	progress.refresh(true);

	if (flushCount)
		flushOffsets.push_back(offset);
	allocator.reset();
}

Stream3 *StreamSorter::addNewStream(PcapPkt::L4Proto proto)
{
	streams.push_back(Stream3(streamID++, proto));
	return &streams.back();
}

FlowTable<pkt_tuple, uint32_t>::entry* StreamSorter::getFlowEntry(const PcapPkt &pkt)
{
	FlowTable<pkt_tuple, uint32_t>::entry *a;
	struct pkt_tuple pt = pkt.parsePkt();
	Stream3 *stream = NULL;

	a = ft->lookup(pt.flip());
	if (!a) {
		a = ft->lookup(pt);
		if (!a) {
			stream = addNewStream(pkt.getProto());

			a = ft->insert(pt, stream->getID(), pkt.ts());
		}
	}

	if (a->expired(pkt.ts(), streams[a->value].getTimeout())) {
		ft->remove(a);

		stream = addNewStream(pkt.getProto());

		a = ft->insert(pt, stream->getID(), pkt.ts());
	}
	return a;
}

void StreamSorter::processPkt(const PcapPkt &pkt)
{
	FlowTable<pkt_tuple, uint32_t>::entry *a;

	a = getFlowEntry(pkt);
	a->tv = pkt.ts();
	streams[a->value].addPkt(pkt);
}

void StreamSorter::mergeChunks(const string &outputBinFile)
{
	cout << "merging chunks: " << tempFilePath << " to " << outputBinFile << endl;
	cout << "have " << flushOffsets.size() << " parts to merge" << endl;
	MappedFile tempFile;

	if (tempFile.open(tempFilePath)) {
		cerr << "failed to open temp file" << endl;
		return;
	}
	ofstream file;

	file.open(outputBinFile.c_str());

	if (!file.is_open()) {
		cerr << "failed top open file '" << outputBinFile << "'" << endl;
		return;
	}
	MemReader memReader(&tempFile, flushOffsets);
	Stream3 stream;

	Progress progress(memReader.getTotalLength());

	while (memReader.read(&stream)) {
		stream.flush(&file);
		if (progress.couldRefresh()) {
			progress.setProgress(memReader.consumed());
			progress.refresh();
		}
	}

	progress.setProgress();
	progress.refresh(true);
	tempFile.close();
}

void StreamSorter::setTempFileName()
{
	tempFilePath = Path(workingDirectory).add("/tmp").str();
}
