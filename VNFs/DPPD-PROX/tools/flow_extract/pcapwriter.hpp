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

#ifndef _PCAPWRITER_H_
#define _PCAPWRITER_H_

#include "pcappkt.hpp"

class PcapWriter {
public:
	PcapWriter() {}
	int open(const string& file_path);
	int write(const PcapPkt& pkt);
	void close();
private:
	pcap_t *m_handle;
	pcap_dumper_t *m_pcap_dumper;
};

#endif /* _PCAPWRITER_H_ */
