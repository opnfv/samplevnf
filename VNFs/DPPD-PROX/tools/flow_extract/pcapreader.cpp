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
#include <cstring>
#include <linux/in.h>

#include "pcapreader.hpp"

int PcapReader::open(const string& file_path)
{
	char err_str[PCAP_ERRBUF_SIZE];

	if (m_handle) {
		m_error = "Pcap file already open";
		return -1;
	}

	m_handle = pcap_open_offline_with_tstamp_precision(file_path.c_str(),
							   PCAP_TSTAMP_PRECISION_NANO,
							   err_str);

	if (!m_handle) {
		m_error = "Failed to open pcap file";
		return -1;
	}

	m_file_beg = ftell(pcap_file(m_handle));
	fseek(pcap_file(m_handle), 0, SEEK_END);
	m_file_end = ftell(pcap_file(m_handle));
	fseek(pcap_file(m_handle), m_file_beg, SEEK_SET);

	return 0;
}

int PcapReader::readOnce(PcapPkt *pkt, uint64_t pos)
{
	return -1;
}

int PcapReader::read(PcapPkt *pkt)
{
	if (!m_handle) {
		m_error = "No pcap file opened";
	}

	const uint8_t *buf = pcap_next(m_handle, &pkt->header);

	if (buf) {
		memcpy(pkt->buf, buf, pkt->header.len);
		pktReadCount++;
	}

	return !!buf;
}

void PcapReader::close()
{
	if (m_handle)
		pcap_close(m_handle);

	m_handle = NULL;
}
