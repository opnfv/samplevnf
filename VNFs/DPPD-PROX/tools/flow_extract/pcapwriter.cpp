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

#include "pcapwriter.hpp"

int PcapWriter::open(const string& file_path)
{
	m_handle = pcap_open_dead_with_tstamp_precision(DLT_EN10MB, 65536, PCAP_TSTAMP_PRECISION_NANO);
	if (m_handle == NULL)
		return -1;

	m_pcap_dumper = pcap_dump_open(m_handle, file_path.c_str());
	if (m_pcap_dumper == NULL) {
		pcap_close(m_handle);
		return -1;
	}

	return 0;
}

int PcapWriter::write(const PcapPkt& pkt)
{
	pcap_dump((unsigned char *)m_pcap_dumper, &pkt.hdr(), pkt.payload());
	return 0;
}

void PcapWriter::close()
{
	if (m_pcap_dumper)
		pcap_dump_close(m_pcap_dumper);
	if (m_handle)
		pcap_close(m_handle);
}
