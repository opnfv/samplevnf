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

#ifndef _STREAM2_H_
#define _STREAM2_H_

#include <inttypes.h>
#include <fstream>

#include "netsocket.hpp"

using namespace std;

class Stream2 {
public:
	Stream2() : clientServerHdrContent(NULL) {}
	~Stream2() {delete [] clientServerHdrContent;}
	int fromFile(ifstream *f);
	void calcOffsets(ofstream *out);
	void toFile(ofstream *out) const;
	void toLua(ofstream *f, const string& binFileName, const string& streamTableName) const;
	NetSocket getServerNetSocket() const;
	NetSocket getClientNetSocket() const;
	void setServerNetSocket(const NetSocket& netSocket);
	void setClientNetSocket(const NetSocket& netSocket);
	Stream::Header      streamHdr;
private:
	int actionsFromFile(ifstream *f, size_t actionCount);
	int setReferences(ifstream *f);

	uint8_t *clientServerHdrContent;

	uint32_t clientHdrBeg;
	uint32_t serverHdrBeg;
	uint32_t clientContentBeg;
	uint32_t serverContentBeg;

	vector<Stream::ActionEntry> m_actions;
};

#endif /* _STREAM2_H_ */
