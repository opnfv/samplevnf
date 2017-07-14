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

#include "netsocket.hpp"

NetSocket::NetSocket(uint32_t host, uint16_t port)
	: host(host), port(port)
{

}

bool NetSocket::operator>(const NetSocket& other) const
{
	return host > other.host || (host == other.host && port > other.port);
}

bool NetSocket::operator<(const NetSocket& other) const
{
	return host < other.host || (host == other.host && port < other.port);
}
