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

#ifndef _TIMESTAMP_H_
#define _TIMESTAMP_H_

#include <iostream>

#include <sys/time.h>
#include <inttypes.h>

using namespace std;

class Timestamp {
public:
	Timestamp(const uint64_t sec, const uint64_t nsec) : m_sec(sec), m_nsec(nsec) {}
	Timestamp() {}
	Timestamp(const struct timeval& tv) : m_sec(tv.tv_sec), m_nsec(tv.tv_usec) {}
	Timestamp operator-(const Timestamp& other) const;
	bool operator==(const Timestamp &other) const;
	friend double operator/(double d, const Timestamp &denominator);
	bool operator>(const Timestamp& other);
	bool operator<(const Timestamp& other);
	uint64_t sec() const {return m_sec;}
	uint64_t nsec() const {return m_nsec;}
	friend ostream& operator<<(ostream& stream, const Timestamp& ts);
private:
	uint64_t m_sec;
	uint64_t m_nsec;
};

#endif /* _TIMESTAMP_H_ */
