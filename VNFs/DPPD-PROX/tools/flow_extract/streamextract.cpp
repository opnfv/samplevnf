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

#include <inttypes.h>
#include <string>
#include <cstdio>
#include <iostream>
#include <sys/stat.h>
#include <sys/types.h>
#include <sstream>
#include <set>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <cerrno>
#include <cstdlib>
#include <map>

#include "path.hpp"
#include "bundle.hpp"
#include "stream.hpp"
#include "stream2.hpp"
#include "allocator.hpp"
#include "timestamp.hpp"
#include "streamextract.hpp"
#include "pcapreader.hpp"
#include "pcapwriter.hpp"
#include "flowtable.hpp"
#include "stream3.hpp"
#include "netsocket.hpp"
#include "pcappktref.hpp"
#include "progress.hpp"
#include "mappedfile.hpp"
#include "streamsorter.hpp"

using namespace std;

static bool is_dir(const string& path_dir_out)
{
	struct stat s = { 0 };

	if (stat(path_dir_out.c_str(), &s)) {
		return false;
	}

	return s.st_mode & S_IFDIR;
}

StreamExtract::StreamExtract(const ProgramConfig &cfg)
	: ft2(cfg.flowTableSize),
	  streamSorter(cfg.flowTableSize, cfg.path_dir_out, 1024UL*1024*1024*8),
	  cfg(cfg)
{
}

vector<Bundle> StreamExtract::createBundles(const string& streamPath)
{
	map<uint32_t, Bundle>::iterator iterBundle;
	map<uint32_t, Bundle> bundles;
	set<uint32_t> servers;

	Stream2 s;
	ifstream binIn;

	binIn.open(streamPath.c_str());
	binIn.seekg(0, binIn.end);
	Progress progress(binIn.tellg());
	binIn.seekg(0, binIn.beg);

	while (!s.fromFile(&binIn)) {
		if (progress.couldRefresh()) {
			progress.setProgress(binIn.tellg());
			progress.refresh();
		}
		if (!s.streamHdr.completedTCP)
			continue;
		if (!s.streamHdr.serverHdrLen)
			continue;
		/* The current implementation does not support clients
		   that are also servers. */
		servers.insert(s.streamHdr.serverIP);
		if (servers.find(s.streamHdr.clientIP) != servers.end())
			continue;

		/* Since each application is represented as a path
		   graph (there is only one reply for a given request
		   and only one request after a given reply), each
		   application must run on a unique server. For this
		   reason, check if the socket on the server already
		   is occupied and if so, keep incrementing the socket
		   until the collision is resolved. */
		iterBundle = bundles.find(s.streamHdr.clientIP);

		if (iterBundle == bundles.end()) {
			bundles.insert(make_pair(s.streamHdr.clientIP, Bundle()));
			iterBundle = bundles.find(s.streamHdr.clientIP);
		}

		(*iterBundle).second.addStream(s.streamHdr.streamId, s.getServerNetSocket().port);
	}

	progress.setProgress();
	progress.refresh(true);

	binIn.close();

	vector<Bundle> ret;

	ret.reserve(bundles.size());

	for (map<uint32_t, Bundle>::const_iterator i = bundles.begin(); i != bundles.end(); ++i)
		ret.push_back(i->second);

	return ret;
}

set<uint32_t> StreamExtract::getBundleStreamIDs(const vector<Bundle*>& bundleSamples)
{
	set<uint32_t> streamIDs;

	for (size_t i = 0; i < bundleSamples.size(); ++i) {
		const vector<uint32_t> &bundleStreamIDs = bundleSamples[i]->getStream();

		for (vector<uint32_t>::const_iterator j = bundleStreamIDs.begin(); j != bundleStreamIDs.end(); ++j) {
			streamIDs.insert(*j);
		}
	}

	return streamIDs;
}

static size_t getRandom(size_t limit)
{
	size_t r = rand();
	size_t rand_limit = (RAND_MAX/limit)*limit;

	while (r > rand_limit)
		r = rand();

	return r % limit;
}

static void removeFill(vector<Bundle*> *from, size_t idx)
{
	Bundle *last = from->back();
	from->pop_back();

	if (idx != from->size())
		(*from)[idx] = last;
}

static vector<Bundle*> takeSamples(vector<Bundle>& bundles, size_t sampleCount)
{
	vector<Bundle*> bundleSamples;

	bundleSamples.reserve(bundles.size());

	cout << "Sampling " << sampleCount << " bundles out of " << bundles.size() << endl;
	for (size_t i = 0; i < bundles.size(); ++i)
		bundleSamples.push_back(&bundles[i]);

	srand(1000);
	while (bundleSamples.size() > sampleCount) {
		size_t r = getRandom(bundleSamples.size());
		removeFill(&bundleSamples, r);
	}
	return bundleSamples;
}

static size_t replaceWithRunningTotals(vector<size_t> *streamLength)
{
	size_t runningTotal = 0;
	for (size_t i = 0; i < streamLength->size(); ++i) {
		size_t len = (*streamLength)[i] + sizeof(uint32_t);
		(*streamLength)[i] = runningTotal;
		runningTotal += len;
	}
	return runningTotal;
}

static void printPorts(const vector<Bundle> &bundles)
{
	set<uint32_t> streamIDs;

	for (size_t i = 0; i < bundles.size(); ++i) {
		const vector<uint32_t> &ports = bundles[i].getPorts();

		for (size_t j = 0; j < ports.size(); ++j) {
			if (j + 1 == ports.size())
				cout << ports[j] << ",END" << endl;
			else
				cout << ports[j] << "," << ports[j +1] << endl;
		}
	}
}

string StreamExtract::createStreamPcapFileName(int id)
{
	stringstream ss;

	ss << cfg.path_dir_out << "/s" << id << ".pcap";

	return ss.str();
}

int StreamExtract::writeToPcaps(const string &sourceFilePath, const set<uint32_t> &streamIDs)
{
	set<uint32_t>::const_iterator i = streamIDs.begin();

	MappedFile mappedFile;
	if (mappedFile.open(sourceFilePath)) {
		cerr << "Failed to open file " << sourceFilePath << ":" << strerror(errno) << endl;
		return -1;
	}

	PcapPkt::allocator = NULL;

	Progress progress((uint64_t)mappedFile.getMapEnd() - (uint64_t)mappedFile.getMapBeg());
	cout << "Writing  " << streamIDs.size() << " streams to pcaps" << endl;
	uint8_t *data2 = mappedFile.getMapBeg();
	while (data2 < mappedFile.getMapEnd()) {
		uint32_t id = *reinterpret_cast<uint32_t *>(data2);

		data2 += sizeof(id);
		uint32_t pktCount = *reinterpret_cast<uint32_t *>(data2);
		data2 += sizeof(pktCount);
		Stream s(id, pktCount);
		while (pktCount--) {
			PcapPkt p(data2);

			data2 += p.memSize();
			s.addPkt(p);
		}

		while (i != streamIDs.end() && (*i) < id)
			i++;
		if (i == streamIDs.end())
			break;
		if (*i > id)
			continue;

		const string pcapPath = createStreamPcapFileName(id);

		s.toPcap(pcapPath);
		if (progress.couldRefresh()) {
			progress.setProgress((uint64_t)data2 - (uint64_t)mappedFile.getMapBeg());
			progress.refresh();
			mappedFile.sync();
		}
	}

	progress.setProgress(data2 - mappedFile.getMapBeg());
	progress.refresh(true);

	mappedFile.close();
	return 0;
}

int StreamExtract::writeToLua(const string& binFilePath, const Path &smallFinalBin, const string& luaFilePath, const string &orderedTemp)
{
	vector<Bundle> bundles = createBundles(binFilePath);
	vector<Bundle*> bundleSamples = takeSamples(bundles, cfg.sampleCount);
	set<uint32_t> streamIDs = getBundleStreamIDs(bundleSamples);

	if (cfg.write_pcaps)
		writeToPcaps(orderedTemp, streamIDs);

	ofstream outLua;
	ofstream outSmallBin;
	outLua.open(luaFilePath.c_str());
	outLua << "bf = \""<< smallFinalBin.getFileName() << "\"" << endl;
	outLua << "s = {}\n";
	set<uint32_t>::iterator i = streamIDs.begin();

	set<NetSocket> serverSockets;
	ifstream binIn;
	Stream2 s;

	outSmallBin.open(smallFinalBin.str().c_str());
	binIn.open(binFilePath.c_str());
	while (!s.fromFile(&binIn)) {
		while (i != streamIDs.end() && (*i) < s.streamHdr.streamId)
			i++;
		if (i == streamIDs.end())
			break;
		if (*i > s.streamHdr.streamId)
			continue;
		s.calcOffsets(&outSmallBin);
		s.toFile(&outSmallBin);
		while (serverSockets.find(s.getServerNetSocket()) != serverSockets.end()) {
			NetSocket ns = s.getServerNetSocket();

			ns.port++;
			s.setServerNetSocket(ns);
		}
		serverSockets.insert(s.getServerNetSocket());

		s.toLua(&outLua, "bf", "s");
	}
	binIn.close();

	uint32_t bundleCount = 0;

	outLua << "bundles = {}" << endl;
	for (size_t i = 0; i < bundleSamples.size(); ++i) {
		bundleSamples[i]->toLua(&outLua, "s", ++bundleCount);
	}
	outLua << "return bundles" << endl;
	outLua.close();
	return 0;
}

int StreamExtract::writeFinalBin(const string& sourceFilePath, const string& destFilePath)
{
	MappedFile mappedFile;
	if (mappedFile.open(sourceFilePath)) {
		cerr << "Failed to open file " << sourceFilePath << ":" << strerror(errno) << endl;
		return -1;
	}
	ofstream binOut;

	binOut.open(destFilePath.c_str());
	PcapPkt::allocator = NULL;

	Progress progress((uint64_t)mappedFile.getMapEnd() - (uint64_t)mappedFile.getMapBeg());

	int streamCount = 0;
	uint8_t *data2 = mappedFile.getMapBeg();
	while (data2 < mappedFile.getMapEnd()) {
	        uint32_t id = *reinterpret_cast<uint32_t *>(data2);

		data2 += sizeof(id);
		uint32_t pktCount = *reinterpret_cast<uint32_t *>(data2);
		data2 += sizeof(pktCount);
		Stream s(id, pktCount);
		while (pktCount--) {
        		PcapPkt p(data2);

			data2 += p.memSize();
			s.addPkt(p);
		}
		s.toFile(&binOut);
		streamCount++;
		if (progress.couldRefresh()) {
			progress.setProgress((uint64_t)data2 - (uint64_t)mappedFile.getMapBeg());
			progress.refresh();
			mappedFile.sync();
		}
	}

	progress.setProgress(data2 - mappedFile.getMapBeg());
	progress.refresh(true);

	binOut.close();
	mappedFile.close();
	return 0;
}

int StreamExtract::run()
{
	Path p(cfg.path_dir_out);
	p.mkdir();

	string orderedTemp = p.add("/a").str();

	string finalBin = p.add("/b").str();
	Path smallfinalBin = p.add("/data.bin").str();
	string luaFile = p.add("/cfg.lua").str();

	cout << "Writing to directory '" << p.str() << "'" << endl;
	cout << "Ordered streams '" << orderedTemp << "'" << endl;
	cout << "Final binary output '" << finalBin << "'" << endl;
	cout << "lua file '" << luaFile << "' will contain " << cfg.sampleCount << " bundles" << endl;

	if (cfg.run_first_step) {
		cout << "starting sorting" << endl;
		streamSorter.sort(cfg.path_file_in_pcap, orderedTemp);
		cout << "writing final binary file (converting format)" << endl;
		if (writeFinalBin(orderedTemp, finalBin))
			return -1;
	} else {
		cout << "Skipping first step" << endl;
		if (!Path(finalBin).isFile()) {
			cerr << "File is missing:" << finalBin << endl;
			return -1;
		}
	}
	cout << "writing Lua '" << luaFile << "'" << endl;
	if (writeToLua(finalBin, smallfinalBin, luaFile, orderedTemp))
		return -1;
	return 0;
}
