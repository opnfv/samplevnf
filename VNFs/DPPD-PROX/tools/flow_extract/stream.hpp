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

#ifndef _STREAM_H_
#define _STREAM_H_

#include <list>
#include <string>
#include <fstream>
#include <cstring>
#include <vector>
#include <cstdlib>
#include <sys/time.h>

#include "pcappktref.hpp"
#include "pcappkt.hpp"
#include "netsocket.hpp"
#include "timestamp.hpp"
#include "halfstream.hpp"

using namespace std;

class PcapReader;

class Stream {
public:
	struct Header {
		uint32_t streamId;
		uint16_t clientHdrLen;
		uint32_t clientContentLen;
		uint16_t serverHdrLen;
		uint32_t serverContentLen;
		uint32_t actionCount;
		uint32_t clientIP;
		uint16_t clientPort;
		uint32_t serverIP;
		uint16_t serverPort;
		double   upRate;
		double   dnRate;
		uint8_t  protocol;
		uint8_t  completedTCP;
 		void     toFile(ofstream *f) const;
		int      fromFile(ifstream *f);
		size_t   getStreamLen() const;
	};
	struct ActionEntry {
		uint8_t peer;
		uint32_t beg;
		uint32_t len;
	} __attribute__((packed));

	Stream(uint32_t id = -1, uint32_t sizeHint = 0);
	void addPkt(const PcapPkt &pkt);
	void toFile(ofstream *f);
	void toPcap(const string& outFile);
	double getRate() const;
	size_t actionCount() const {return m_actions.size();}

private:
	Header getHeader() const;
	void actionsToFile(ofstream *f) const;
	void clientHdrToFile(ofstream *f) const;
	void serverHdrToFile(ofstream *f) const;
	void contentsToFile(ofstream *f, bool isClient) const;
	bool isClient(const PcapPkt &pkt) const;
	size_t pktCount() const;
	struct pkt_tuple m_pt;
	void setTupleFromPkt(const PcapPkt &pkt);
	void addToClient(const PcapPkt &pkt);
	void addToServer(const PcapPkt &pkt);
	void addAction(HalfStream *half, HalfStream::Action::Part p, bool isClientPkt);

	int m_id;
	vector<PcapPkt> m_pkts;
	vector<HalfStream::Action> m_actions;
	HalfStream m_client;
	HalfStream m_server;
	bool m_prevPktIsClient;
};

#endif /* _STREAM_H_ */
