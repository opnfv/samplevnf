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

#ifndef _PCAPREADER_H_
#define _PCAPREADER_H_

#include <inttypes.h>
#include <string>

#include <pcap.h>

#include "pcappkt.hpp"

using namespace std;

class PcapReader {
public:
        PcapReader() : m_handle(NULL), pktReadCount(0) {}
	int open(const string& file_path);
	size_t pos() {return ftell(pcap_file(m_handle)) - m_file_beg;}
	size_t end() {return m_file_end;}
	int read(PcapPkt *pkt);
	int readOnce(PcapPkt *pkt, uint64_t pos);
	size_t getPktReadCount() const {return pktReadCount;}
	void close();
	const string &getError() const {return m_error;}
private:
	pcap_t *m_handle;
	size_t m_file_beg;
	size_t m_file_end;
	size_t pktReadCount;
	string m_error;
};

#endif /* _PCAPREADER_H_ */
