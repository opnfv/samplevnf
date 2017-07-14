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

#include <pcap.h>
#include <inttypes.h>
#include <cstring>
#include <arpa/inet.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include "allocator.hpp"
#include "pcappkt.hpp"

Allocator *PcapPkt::allocator = NULL;

void* PcapPkt::operator new(size_t size)
{
	if (allocator)
		return allocator->alloc(size);
	else
		return ::operator new(size);
}

void PcapPkt::operator delete(void *pointer)
{
	if (!allocator)
		:: operator delete(pointer);
}

PcapPkt::PcapPkt(uint8_t *mem)
{
	header = *(struct pcap_pkthdr *)mem;
	mem += sizeof(header);
	buf = new uint8_t[header.len];
	memcpy(buf, mem, header.len);
}

PcapPkt::PcapPkt()
{
	buf = new uint8_t[1514];
	memset(&header, 0, sizeof(header));
}

PcapPkt::PcapPkt(const PcapPkt& other)
{
	if (!allocator) {
		buf = new uint8_t[other.len()];
	}
	else {
		buf = (uint8_t *)allocator->alloc(other.len());
	}

	memcpy(buf, other.buf, other.len());
	header = other.header;
}

PcapPkt::~PcapPkt()
{
	if (!allocator)
		delete[] buf;
}

#define ETYPE_IPv4	0x0008	/* IPv4 in little endian */
#define ETYPE_IPv6	0xDD86	/* IPv6 in little endian */
#define ETYPE_ARP	0x0608	/* ARP in little endian */
#define ETYPE_VLAN	0x0081	/* 802-1aq - VLAN */
#define ETYPE_MPLSU	0x4788	/* MPLS unicast */
#define ETYPE_MPLSM	0x4888	/* MPLS multicast */
#define ETYPE_8021ad	0xA888	/* Q-in-Q */
#define ETYPE_LLDP	0xCC88	/* Link Layer Discovery Protocol (LLDP) */
#define ETYPE_EoGRE	0x5865	/* EoGRE in little endian */

struct ipv4_hdr {
	uint8_t  version_ihl;		/**< version and header length */
	uint8_t  type_of_service;	/**< type of service */
	uint16_t total_length;		/**< length of packet */
	uint16_t packet_id;		/**< packet ID */
	uint16_t fragment_offset;	/**< fragmentation offset */
	uint8_t  time_to_live;		/**< time to live */
	uint8_t  next_proto_id;		/**< protocol ID */
	uint16_t hdr_checksum;		/**< header checksum */
	uint32_t src_addr;		/**< source address */
	uint32_t dst_addr;		/**< destination address */
} __attribute__((__packed__));

struct ether_addr {
	uint8_t addr_bytes[6]; /**< Address bytes in transmission order */
} __attribute__((__packed__));

struct ether_hdr {
	struct ether_addr d_addr; /**< Destination address. */
	struct ether_addr s_addr; /**< Source address. */
	uint16_t ether_type;      /**< Frame type. */
} __attribute__((__packed__));

struct vlan_hdr {
	uint16_t vlan_tci; /**< Priority (3) + CFI (1) + Identifier Code (12) */
	uint16_t eth_proto;/**< Ethernet type of encapsulated frame. */
} __attribute__((__packed__));

struct udp_hdr {
	uint16_t src_port;    /**< UDP source port. */
	uint16_t dst_port;    /**< UDP destination port. */
	uint16_t dgram_len;   /**< UDP datagram length */
	uint16_t dgram_cksum; /**< UDP datagram checksum */
} __attribute__((__packed__));

struct pkt_tuple PcapPkt::parsePkt(const uint8_t **l4_hdr, uint16_t *hdr_len, const uint8_t **l5, uint32_t *l5_len) const
{
	struct pkt_tuple pt = {0};

	const struct ether_hdr *peth = (struct ether_hdr *)buf;
	int l2_types_count = 0;
	const struct ipv4_hdr* pip = 0;

	switch (peth->ether_type) {
	case ETYPE_IPv4:
			pip = (const struct ipv4_hdr *)(peth + 1);
		break;
	case ETYPE_VLAN: {
		const struct vlan_hdr *vlan = (const struct vlan_hdr *)(peth + 1);
		if (vlan->eth_proto == ETYPE_IPv4) {
			pip = (const struct ipv4_hdr *)(peth + 1);
		}
		else if (vlan->eth_proto == ETYPE_VLAN) {
			const struct vlan_hdr *vlan = (const struct vlan_hdr *)(peth + 1);
			if (vlan->eth_proto == ETYPE_IPv4) {
				pip = (const struct ipv4_hdr *)(peth + 1);
			}
			else if (vlan->eth_proto == ETYPE_IPv6) {
				throw 0;
			}
			else {
				/* TODO: handle BAD PACKET */
				throw 0;
			}
		}
	}
		break;
	case ETYPE_8021ad: {
		const struct vlan_hdr *vlan = (const struct vlan_hdr *)(peth + 1);
		if (vlan->eth_proto == ETYPE_VLAN) {
			const struct vlan_hdr *vlan = (const struct vlan_hdr *)(peth + 1);
			if (vlan->eth_proto == ETYPE_IPv4) {
				pip = (const struct ipv4_hdr *)(peth + 1);
			}
			else {
				throw 0;
			}
		}
		else {
			throw 0;
		}
	}
		break;
	case ETYPE_MPLSU:
		break;
	default:
		break;
	}

	/* L3 */
	if ((pip->version_ihl >> 4) == 4) {

		if ((pip->version_ihl & 0x0f) != 0x05) {
			/* TODO: optional fields */
			throw 0;
		}

		pt.proto_id = pip->next_proto_id;
		pt.src_addr = pip->src_addr;
		pt.dst_addr = pip->dst_addr;
	}
	else {
		/* TODO: IPv6 and bad packets */
		throw 0;
	}

	/* L4 parser */
	if (pt.proto_id == IPPROTO_UDP) {
		const struct udp_hdr *udp = (const struct udp_hdr*)(pip + 1);
		if (l4_hdr)
			*l4_hdr = (const uint8_t*)udp;
		if (hdr_len)
			*hdr_len = (const uint8_t*)udp - buf;
		pt.src_port = udp->src_port;
		pt.dst_port = udp->dst_port;
		if (l5)
			*l5 = ((const uint8_t*)udp) + sizeof(struct udp_hdr);
		if (l5_len)
			*l5_len = ntohs(udp->dgram_len) - sizeof(struct udp_hdr);
	}
	else if (pt.proto_id == IPPROTO_TCP) {
		const struct tcp_hdr *tcp = (const struct tcp_hdr *)(pip + 1);
		if (l4_hdr)
			*l4_hdr = (const uint8_t*)tcp;
		if (hdr_len)
			*hdr_len = (const uint8_t*)tcp - buf;
		pt.src_port = tcp->src_port;
		pt.dst_port = tcp->dst_port;

		if (l5)
			*l5 = ((const uint8_t*)tcp) + ((tcp->data_off >> 4)*4);
		if (l5_len)
			*l5_len = ntohs(pip->total_length) - sizeof(struct ipv4_hdr) - ((tcp->data_off >> 4)*4);
	}
	else {
		fprintf(stderr, "unsupported protocol %d\n", pt.proto_id);
		throw 0;
	}

	return pt;
}

void PcapPkt::toMem(uint8_t *mem) const
{
	memcpy(mem, &header, sizeof(header));
	mem += sizeof(header);
	memcpy(mem, buf, header.len);
}

void PcapPkt::fromMem(uint8_t *mem)
{
	memcpy(&header, mem, sizeof(header));
	mem += sizeof(header);
	memcpy(buf, mem, header.len);
}

void PcapPkt::toFile(ofstream *file) const
{
	file->write(reinterpret_cast<const char *>(&header), sizeof(header));
	file->write(reinterpret_cast<const char *>(buf), header.len);
}
size_t PcapPkt::memSize() const
{
	return sizeof(header) + header.len;
}

PcapPkt::L4Proto PcapPkt::getProto() const
{
	struct pkt_tuple pt = parsePkt();
	return pt.proto_id == IPPROTO_TCP? PROTO_TCP : PROTO_UDP;
}

ostream& operator<<(ostream& stream, const pkt_tuple &other)
{
       	stream << other.src_addr << ","
	       << other.dst_addr << ","
	       << (int)other.proto_id << ","
	       << other.src_port << ","
	       << other.dst_port;
	return stream;
}
