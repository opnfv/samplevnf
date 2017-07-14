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

#ifndef _STREAMEXTRACT_H_
#define _STREAMEXTRACT_H_

#include <string>
#include <list>
#include <map>
#include <set>

#include "programconfig.hpp"
#include "bundle.hpp"
#include "pcapreader.hpp"
#include "flowtable.hpp"
#include "pcappkt.hpp"
#include "stream3.hpp"
#include "streamsorter.hpp"
#include "path.hpp"

using namespace std;

class StreamExtract {
public:
	/* The size of the flow table determines the number of flows
	   that can be active at a given time. When a flow expires, it
	   is written out to a file and the memory is freed. */
	StreamExtract(const ProgramConfig &cfg);
	int run();
private:
	int writeToPcaps(const string &sourceFilePath, const set<uint32_t> &streamIDs);
	int writeToLua(const string& binFilePath, const Path &smallFinalBin, const string& luaFilePath, const string& orderedTemp);
	int writeFinalBin(const string& sourceFilePath, const string& destFilePath);
	string createStreamPcapFileName(int id);
	vector<Bundle> createBundles(const string& streamPath);
	set<uint32_t> getBundleStreamIDs(const vector<Bundle*>& bundleSamples);
	FlowTable<pkt_tuple, Stream3> ft2;
	StreamSorter streamSorter;
	ProgramConfig cfg;
};

#endif /* _STREAMEXTRACT_H_ */
