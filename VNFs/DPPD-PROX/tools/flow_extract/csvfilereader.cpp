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

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <stdint.h>

#include "csvfilereader.hpp"

int CsvFileReader::open(const string& str)
{
	char *resolved_path = new char[1024];

	memset(resolved_path, 0, 1024);
	realpath(str.c_str(), resolved_path);
	file.open(resolved_path);

	delete []resolved_path;
	return file.is_open();
}

vector<string> CsvFileReader::read()
{
	vector<string> ret;
	size_t prev = 0, cur = 0;
	string line;

	if (file.eof())
		return vector<string>();

   	std::getline(file, line);
	if (line.empty())
		return vector<string>();

	while (true) {
		cur = line.find_first_of(',', prev);

		if (cur != SIZE_MAX) {
			ret.push_back(line.substr(prev, cur - prev));
			prev = cur + 1;
		}
		else {
			ret.push_back(line.substr(prev, line.size() - prev));
			break;
		}
	}
	return ret;
}

void CsvFileReader::close()
{
	file.close();
}
