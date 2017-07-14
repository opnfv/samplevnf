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

#include <cstdio>
#include <iostream>
#include <iomanip>

#include "timestamp.hpp"

Timestamp Timestamp::operator-(const Timestamp& other) const
{
	uint64_t sec;
	uint64_t nsec;

	if (other.m_nsec <= m_nsec) {
		nsec = m_nsec - other.m_nsec;
		sec = m_sec - other.m_sec;
	} else {
		nsec = (1000000000 + m_nsec) - other.m_nsec;
		sec = m_sec - 1 - other.m_sec;
	}

	return Timestamp(sec, nsec);
}

bool Timestamp::operator>(const Timestamp& other)
{
	return m_sec > other.m_sec ||
		(m_sec == other.m_sec && m_nsec > other.m_nsec);
}

bool Timestamp::operator<(const Timestamp& other)
{
	return m_sec < other.m_sec ||
		(m_sec == other.m_sec && m_nsec < other.m_nsec);
}

ostream& operator<<(ostream& stream, const Timestamp& ts)
{
	stream << ts.m_sec << "." << setw(9) << setfill('0') << ts.m_nsec;
	return stream;
}

double operator/(double d, const Timestamp &denominator)
{
	return d * 1000000000 / (denominator.m_sec * 1000000000 + denominator.m_nsec);
}

bool Timestamp::operator==(const Timestamp &other) const
{
	return m_sec == other.m_sec && m_nsec == other.m_nsec;
}
