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

#include <sstream>
#include <getopt.h>
#include <iostream>
#include <cstdlib>
#include "programconfig.hpp"

ProgramConfig::ProgramConfig()
	: path_file_in_pcap(""), path_dir_out("output"),
	  path_file_dest_lua("lua"), max_pkts(UINT32_MAX),
	  max_streams(UINT32_MAX), sampleCount(20000), flowTableSize(8*1024*1024),
	  run_first_step(true), write_pcaps(false)
{
}

string ProgramConfig::getUsage() const
{
	stringstream ret;

	ret << "Usage example: "<< m_programName << " -i in.pcap\n\n"
	    << "Flow Extract 2.0 analyzes and extracts a traffic profile\n"
	    << "configuration from a pcap file. The output is a lua\n"
	    << "configuration file and a binary file containing all the\n"
	    << "headers and payloads for each stream.\n\n"

	    << "The program supports analyzing large pcap file (> 300 GB).\n"
	    << "For this, it uses a multi-pass approach. The output of \n"
	    << "intermediary steps is stored in the working directory. The\n"
	    << "algorithm can be described by the following steps:\n\n"
	    << "   1. The pcap file in read chunks of 16 GB. The packets in\n"
	    << "      each chunk are associated with streams. The streams are\n"
	    << "      ordered through a global ID. Each stream is stored as a"
	    << "      sequence of packets that belong to that stream. The\n"
	    << "      resulting file at 'DIR/tmp' where DIR is specified\n"
	    << "      through -o options as shown below.\n"
	    << "      Each chunk in tmp is merged and the result is written\n"
	    << "      to file1. Reading the stream with a given ID from all chunks\n"
	    << "      gets all the packets for the stream from the whole pcap in\n"
	    << "      memory. This first step forms is implemented by an\n"
	    << "      external sorting algorithm.\n"
	    << "   2. File2 is read and the source IP for each stream is used to\n"
	    << "      associate each stream with a bundle. SAMPLE_COUNT samples\n"
	    << "      are taken from the set of bundles. The set of streams that\n"
	    << "      are still referenced by the sampled bundles extracted from\n"
	    << "      file2 and written to the final binary file. This binary file\n"
	    << "      is referenced from the lua configuration. The lua config file\n"
	    << "      is written out as part of this step.\n"
	    << "Arguments:\n"
	    << "-i FILE         Input pcap to process\n"
	    << "-o DIR          output directory and working directory\n"
	    << "-s SAMPLE_COUNT Number of samples to take (default is 20K)\n"
	    << "-k              Skip the first step as described above. Useful to\n"
	    << "                adjust the number of samples without having to\n"
	    << "                repeat the whole process\n";


	return ret.str();
}

int ProgramConfig::checkConfig()
{
	if (path_file_in_pcap.empty()) {
		m_error = "Missing input pcap file\n";
		return -1;
	}
	return 0;
}

int ProgramConfig::parseOptions(int argc, char *argv[])
{
	char c;

	m_programName = argv[0];
	while ((c = getopt(argc, argv, "hki:o:s:p")) != -1) {
		switch (c) {
		case 'h':
			return -1;
			break;
		case 'k':
			run_first_step = false;
			break;
		case 'i':
			path_file_in_pcap = optarg;
			break;
		case 'o':
			path_dir_out = optarg;
			break;
		case 's':
			sampleCount = atoi(optarg);
			break;
		case 'p':
			write_pcaps = true;
			break;
		case '?':
			cerr << getUsage() << endl;
			return 0;
		default:
			m_error = "Invalid parameter\n";
			return -1;
		}
	}

	return checkConfig();
}
