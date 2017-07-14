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

#ifndef _PCAPPKT_H_
#define _PCAPPKT_H_

#include <inttypes.h>
#include <pcap.h>
#include <string>
#include <cstring>

using namespace std;

struct pkt_tuple {
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t proto_id;
	uint16_t src_port;
	uint16_t dst_port;
	bool operator!=(const pkt_tuple& other) const
	{
		return src_addr != other.src_addr ||
			dst_addr != other.dst_addr ||
			proto_id != other.proto_id ||
			src_port != other.src_port ||
			dst_port != other.dst_port;
	}
	bool operator==(const pkt_tuple& other) const
	{
		return src_addr == other.src_addr &&
			dst_addr == other.dst_addr &&
			proto_id == other.proto_id &&
			src_port == other.src_port &&
			dst_port == other.dst_port;
	}
	friend ostream& operator<<(ostream& stream, const pkt_tuple &other);
	struct pkt_tuple flip() const
	{
		struct pkt_tuple ret;

		ret = *this;
		ret.src_addr = dst_addr;
		ret.src_port = dst_port;
		ret.dst_addr = src_addr;
		ret.dst_port = src_port;
		return ret;
	}

} __attribute__((packed));

class Allocator;

class PcapPkt {
	friend class PcapReader;
public:
	struct tcp_hdr {
		uint16_t src_port;  /**< TCP source port. */
		uint16_t dst_port;  /**< TCP destination port. */
		uint32_t sent_seq;  /**< TX data sequence number. */
		uint32_t recv_ack;  /**< RX data acknowledgement sequence number. */
		uint8_t  data_off;  /**< Data offset. */
		uint8_t  tcp_flags; /**< TCP flags */
		uint16_t rx_win;    /**< RX flow control window. */
		uint16_t cksum;     /**< TCP checksum. */
		uint16_t tcp_urp;   /**< TCP urgent pointer, if any. */
	} __attribute__((__packed__));

	static Allocator *allocator;
	enum L4Proto {PROTO_TCP, PROTO_UDP};
	PcapPkt();
	void* operator new(size_t size);
	static void operator delete(void *pointer);
	PcapPkt(const PcapPkt& other);
	PcapPkt(uint8_t *mem);
	void toMem(uint8_t *mem) const;
	void fromMem(uint8_t *mem);
	void toFile(ofstream *file) const;
	size_t memSize() const;
	const struct timeval &ts() const {return header.ts;}
	const uint16_t len() const {return header.len;}
	pkt_tuple parsePkt(const uint8_t **l4_hdr = NULL, uint16_t *hdr_len = NULL, const uint8_t **l5 = NULL, uint32_t *l5_len = NULL) const;
	const struct pcap_pkthdr &hdr() const {return header;}
	const uint8_t *payload() const {return buf;}
	enum L4Proto getProto() const;
	~PcapPkt();
private:
	struct pcap_pkthdr header;
	uint8_t *buf;
};

#endif /* _PCAPPKT_H_ */
