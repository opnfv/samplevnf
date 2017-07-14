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
#include <iomanip>
#include <sys/stat.h>
#include <sstream>
#include <fstream>

#include "path.hpp"

bool Path::isDir() const
{
	struct stat s = { 0 };

	if (stat(path.c_str(), &s)) {
		return false;
	}

	return s.st_mode & S_IFDIR;
}

bool Path::isFile() const
{
	struct stat s = { 0 };

	if (stat(path.c_str(), &s)) {
		return false;
	}

	return s.st_mode & S_IFREG;
}

Path Path::add(const string& str) const
{
	stringstream ss;

	ss << path << str;

        return Path(ss.str());
}

Path Path::add(int number) const
{
	stringstream ss;

	ss << path << number;

	return Path(ss.str());
}

Path &Path::concat(const string &add)
{
	stringstream ss;

	ss << path << add;
	path = ss.str();

        return *this;
}

int Path::mkdir() const
{
	if (!isDir())
		return ::mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	return 0;
}

std::ostream& operator<<(std::ofstream &stream, const Path &p)
{
	stream << p.path.c_str();

	return stream;
}

string Path::getFileName() const
{
	for (size_t i = path.size() - 1; i >= 0; --i) {
		if (path[i] == '/') {
			return path.substr(i + 1);
		}
	}
	return path;
}
