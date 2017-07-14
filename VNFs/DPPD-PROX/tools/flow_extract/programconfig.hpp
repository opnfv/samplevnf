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

#ifndef _PROGRAMCONFIG_H_
#define _PROGRAMCONFIG_H_

#include <string>
#include <inttypes.h>

using namespace std;

class ProgramConfig {
public:
	ProgramConfig();
	string getUsage() const;
	int parseOptions(int argc, char *argv[]);
	const string& getError() const {return m_error;}

	string path_file_in_pcap;
	string path_dir_out;
	string path_file_dest_lua;
	uint32_t max_pkts;
	uint32_t max_streams;
	uint32_t sampleCount;
	uint32_t flowTableSize;
	bool run_first_step;
	bool write_pcaps;
private:
	int checkConfig();
	string m_error;
	string m_programName;
};

#endif /* _PROGRAMCONFIG_H_ */
