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

#ifndef _PATH_H_
#define _PATH_H_

#include <string>

using namespace std;

class Path {
public:
	Path();
	Path(const Path& other) : path(other.path) {}
	Path(const string& str) : path(str) {}
	Path add(const string& str) const;
	Path add(int number) const;
	Path &concat(const string &str);
	const string& str() const {return path;}
	bool isDir() const;
	bool isFile() const;
	string getFileName() const;
	int mkdir() const;
	friend std::ostream& operator<<(std::ofstream &stream, const Path &path);
private:
	string path;
};

#endif /* _PATH_H_ */
