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

#ifndef _STREAM3_H_
#define _STREAM3_H_

#include <inttypes.h>
#include <vector>

#include "pcappkt.hpp"
#include "timestamp.hpp"

using namespace std;
class Allocator;

class Stream3 {
public:
	PcapPkt::L4Proto getProto(void) const {return m_proto;}
	Stream3(uint32_t id, PcapPkt::L4Proto proto);
	Stream3() : m_id(UINT32_MAX), m_proto(PcapPkt::PROTO_UDP), m_pktCount(0), m_flushCount(0) {}
	void addPkt(const PcapPkt& pkt);
	void flush(ofstream *outputFile);
	void addFromMemory(uint8_t *mem, size_t *len);
	static uint32_t getIDFromMem(uint8_t *mem);
	bool hasFlushablePackets() const {return !!m_flushCount;}
	Timestamp getTimeout() const;
	uint32_t getID() const {return m_id;}
	void removeAllPackets();
	void setID(const uint32_t id) {m_id = id;}
private:
	void writeHeader(ofstream *outputFile) const;
	void writePackets(ofstream *outputFile) const;
	void clearPackets();

	uint32_t m_id;
	PcapPkt::L4Proto m_proto;
	vector<PcapPkt *> m_pkts;
	uint32_t m_pktCount;
	uint32_t m_flushCount;
};

#endif /* _STREAM3_H_ */
