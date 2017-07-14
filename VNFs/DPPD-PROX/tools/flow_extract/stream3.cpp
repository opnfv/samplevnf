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

using namespace std;

#include "stream3.hpp"

Stream3::Stream3(uint32_t id, PcapPkt::L4Proto proto)
	: m_id(id), m_proto(proto), m_pktCount(0), m_flushCount(0)
{
}

void Stream3::writeHeader(ofstream *outputFile) const
{
	outputFile->write(reinterpret_cast<const char *>(&m_id), sizeof(m_id));
	outputFile->write(reinterpret_cast<const char *>(&m_flushCount), sizeof(m_flushCount));
}

void Stream3::writePackets(ofstream *outputFile) const
{
	for (size_t i  = 0; i < m_pkts.size(); ++i)
		m_pkts[i]->toFile(outputFile);
}

void Stream3::clearPackets()
{
	for (size_t i = 0; i < m_pkts.size(); ++i)
		delete m_pkts[i];
	m_pkts.clear();
	m_flushCount = 0;
}

void Stream3::flush(ofstream *outputFile)
{
	writeHeader(outputFile);
	writePackets(outputFile);
	clearPackets();
}

void Stream3::addPkt(const PcapPkt& pkt)
{
	m_pkts.push_back(new PcapPkt(pkt));
	m_pktCount++;
	m_flushCount++;
}

Timestamp Stream3::getTimeout() const
{
	uint32_t timeoutMinutes = m_proto == PcapPkt::PROTO_UDP? 10 : 5;

	return Timestamp(timeoutMinutes * 60, 0);
}

uint32_t Stream3::getIDFromMem(uint8_t *mem)
{
	return *reinterpret_cast<uint32_t *>(mem);
}

void Stream3::addFromMemory(uint8_t *mem, size_t *len)
{
	uint32_t n_pkts;

	mem += sizeof(m_id);
	n_pkts = *reinterpret_cast<uint32_t *>(mem);
	mem += sizeof(n_pkts);

	*len = sizeof(m_id) + sizeof(n_pkts);
	for (uint32_t i = 0; i < n_pkts; ++i) {
	        addPkt(PcapPkt(mem));
		mem += m_pkts.back()->memSize();
		*len += m_pkts.back()->memSize();
	}
}

void Stream3::removeAllPackets()
{
	clearPackets();
	m_pktCount = 0;
}
