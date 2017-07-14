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
#include <list>
#include <vector>

#include "timestamp.hpp"
#include "pcappkt.hpp"

struct HalfStream {
	struct Action {
	public:
		struct Part {
			Part(uint32_t pktId, uint32_t offset, uint32_t len)
				: pktId(pktId), offset(offset), len(len) {}
			uint32_t pktId;
			uint32_t offset;
			uint32_t len;
		};

		Action(HalfStream* stream, const Part &p, bool isClient);
		void addPart(const Part& p);
		bool isClient() const {return m_isClient;}
		/* An action can consist of multiple
		   packets. The data is not stored in the
		   action. Instead, a packet id together with
		   an offset into the packet and a length is
		   kept to save space */
		void toFile(ofstream* f) const;
		uint32_t totLen() const;
	private:
		HalfStream *halfStream;
		bool       m_isClient;
		list<Part> parts;
	};

	HalfStream();
	Timestamp first;
	Timestamp last;
	uint64_t totLen;
	uint64_t hdrLen;
	uint8_t hdr[64];
	vector<PcapPkt> pkts;
	uint64_t contentLen;
	bool tcpOpen;
	bool tcpClose;
	Action::Part addPkt(const PcapPkt &pkt);
	double getRate() const;
};
