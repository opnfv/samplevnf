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

#include <fstream>
#include <arpa/inet.h>

#include "halfstream.hpp"

HalfStream::Action::Part HalfStream::addPkt(const PcapPkt &pkt)
{
	const uint32_t pktId = pkts.size();
	const uint8_t *l5;
	uint32_t l5Len;
	uint16_t tmpHdrLen;

	const struct PcapPkt::tcp_hdr *tcp;

	struct pkt_tuple pt = pkt.parsePkt((const uint8_t **)&tcp, &tmpHdrLen, &l5, &l5Len);

	if (pt.proto_id == IPPROTO_TCP) {
		if (tcp->tcp_flags & 0x02)
			tcpOpen = true;
		if (tcp->tcp_flags & 0x01)
			tcpClose = true;
	}

	if (pkts.empty()) {
		first = pkt.ts();
		hdrLen = tmpHdrLen;
		memcpy(hdr, pkt.payload(), hdrLen);
	}
	last = pkt.ts();
	totLen += pkt.len();
	contentLen += l5Len;

	pkts.push_back(pkt);

	return Action::Part(pktId, l5 - pkt.payload(), l5Len);
}

double HalfStream::getRate() const
{
	if (pkts.empty())
		return 0;
	if (first == last)
		return 1250000000;

	return totLen / (last - first);
}

HalfStream::Action::Action(HalfStream* stream, const Part &p, bool isClient)
	: halfStream(stream), m_isClient(isClient)
{
	addPart(p);
}

void HalfStream::Action::addPart(const Part &p)
{
	parts.push_back(p);
}

uint32_t HalfStream::Action::totLen() const
{
	uint32_t ret = 0;

	for (list<Part>::const_iterator i = parts.begin(); i != parts.end(); ++i) {
		ret += (*i).len;
	}

	return ret;
}

void HalfStream::Action::toFile(ofstream *f) const
{
	for (list<Part>::const_iterator i = parts.begin(); i != parts.end(); ++i) {
		const PcapPkt &pkt = halfStream->pkts[i->pktId];
		const uint8_t *payload = &pkt.payload()[i->offset];
		const uint16_t len = i->len;

		f->write((const char *)payload, len);
	}
}

HalfStream::HalfStream()
	: first(0, 0), last(0, 0), totLen(0), hdrLen(0), contentLen(0), tcpOpen(false), tcpClose(false)
{

}
