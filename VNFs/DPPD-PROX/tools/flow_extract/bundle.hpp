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

#ifndef _BUNDLE_H_
#define _BUNDLE_H_

#include <vector>
#include <inttypes.h>
#include <fstream>

using namespace std;

class Bundle
{
public:
	void addStream(uint32_t streamId, uint32_t port) {streams.push_back(streamId); ports.push_back(port);}
	const vector<uint32_t>& getStream() const {return streams;}
	const vector<uint32_t>& getPorts() const {return ports;}
	void toLua(ofstream *f, const string& streamTableName, uint32_t idx) const;
private:
	vector<uint32_t> streams;
	vector<uint32_t> ports;
};

#endif /* _BUNDLE_H_ */
