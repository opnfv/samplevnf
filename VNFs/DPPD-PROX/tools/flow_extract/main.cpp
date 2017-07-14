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
#include <cstdlib>

#include "streamextract.hpp"

using namespace std;

int main(int argc, char *argv[])
{
	ProgramConfig programConfig;

	if (programConfig.parseOptions(argc, argv)) {
		cerr << programConfig.getError() << endl;
		cerr << programConfig.getUsage() << endl;
		return EXIT_FAILURE;
	}

	StreamExtract se(programConfig);

	return se.run();
}
