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
#include <iomanip>
#include <arpa/inet.h>

#include "pcapwriter.hpp"
#include "stream.hpp"

Stream::Stream(uint32_t id, uint32_t sizeHint)
	: m_id(id), m_prevPktIsClient(false)
{
	m_client.pkts.reserve(sizeHint / 2);
	m_server.pkts.reserve(sizeHint / 2);
	m_pkts.reserve(sizeHint);
}

bool Stream::isClient(const PcapPkt &pkt) const
{
	return m_pt == pkt.parsePkt();
}

size_t Stream::pktCount() const
{
	return m_client.pkts.size() + m_server.pkts.size();
}

void Stream::setTupleFromPkt(const PcapPkt &pkt)
{
	m_pt = pkt.parsePkt();
}

void Stream::addPkt(const PcapPkt &pkt)
{
	if (!pktCount())
		setTupleFromPkt(pkt);

	bool isClientPkt = isClient(pkt);
	HalfStream *half;

	if (isClientPkt)
		half = &m_client;
	else
		half = &m_server;

	HalfStream::Action::Part p = half->addPkt(pkt);

	if (p.len) {
		addAction(half, p, isClientPkt);
	}

	m_pkts.push_back(pkt);
}

void Stream::addAction(HalfStream *half, HalfStream::Action::Part p, bool isClientPkt)
{
	if (m_actions.empty() || m_prevPktIsClient != isClientPkt || m_pt.proto_id == IPPROTO_UDP)
		m_actions.push_back(HalfStream::Action(half, p, isClientPkt));
	else
		m_actions.back().addPart(p);
	m_prevPktIsClient = isClientPkt;
}

Stream::Header Stream::getHeader() const
{
	Header h;

	h.streamId = m_id;
	h.clientHdrLen = m_client.hdrLen;
	h.clientContentLen = m_client.contentLen;
	h.serverHdrLen = m_server.hdrLen;
	h.serverContentLen = m_server.contentLen;
	h.actionCount = m_actions.size();
	h.clientIP = m_pt.src_addr;
	h.clientPort = m_pt.src_port;
	h.serverIP = m_pt.dst_addr;
	h.serverPort = m_pt.dst_port;
	h.upRate = m_client.getRate();
	h.dnRate = m_server.getRate();
	h.protocol = m_pt.proto_id;
	h.completedTCP = (m_client.tcpOpen && m_client.tcpClose && m_server.tcpOpen && m_server.tcpClose) ||
		(!m_client.tcpOpen && !m_client.tcpClose && !m_server.tcpOpen && !m_server.tcpClose);

	return h;
}

void Stream::Header::toFile(ofstream *f) const
{
	f->write((const char *)this, sizeof(*this));
}

int Stream::Header::fromFile(ifstream *f)
{
	const size_t readSize = sizeof(*this);

	f->read((char *)this, readSize);
	return 	f->gcount() == readSize? 0 : -1;
}

size_t Stream::Header::getStreamLen() const
{
	return 	actionCount * sizeof(ActionEntry)
		+ clientHdrLen + clientContentLen
		+ serverHdrLen + serverContentLen;
}

void Stream::actionsToFile(ofstream *f) const
{
	ActionEntry actionEntry;
	uint32_t runningTotalLen[2] = {0};

	for (size_t i = 0; i < m_actions.size(); ++i) {
		actionEntry.peer = m_actions[i].isClient()? 0 : 1;
		actionEntry.beg = runningTotalLen[actionEntry.peer];
		actionEntry.len = m_actions[i].totLen();

		runningTotalLen[actionEntry.peer] += actionEntry.len;
		f->write((const char *)&actionEntry, sizeof(actionEntry));
	}
}

void Stream::clientHdrToFile(ofstream *f) const
{
	f->write((const char *)m_client.hdr, m_client.hdrLen);
}

void Stream::serverHdrToFile(ofstream *f) const
{
	f->write((const char *)m_server.hdr, m_server.hdrLen);
}

void Stream::contentsToFile(ofstream *f, bool isClient) const
{
	for (size_t i = 0; i < m_actions.size(); ++i)
		if (m_actions[i].isClient() == isClient)
			m_actions[i].toFile(f);
}

void Stream::toFile(ofstream *f)
{
	getHeader().toFile(f);
	actionsToFile(f);
	clientHdrToFile(f);
	serverHdrToFile(f);
	contentsToFile(f, true);
	contentsToFile(f, false);
}

void Stream::toPcap(const string& outFile)
{
	PcapWriter pw;

	pw.open(outFile);
	for (size_t i = 0; i < m_pkts.size(); ++i)
		pw.write(m_pkts[i]);
	pw.close();
}
