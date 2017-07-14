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

#include <iomanip>
#include <arpa/inet.h>
#include <sstream>

#include "stream.hpp"
#include "stream2.hpp"

int Stream2::fromFile(ifstream *f)
{
	m_actions.clear();
	if (streamHdr.fromFile(f))
		return -1;
	if (actionsFromFile(f, streamHdr.actionCount))
		return -1;
	if (setReferences(f))
		return -1;

	return 0;
}

int Stream2::actionsFromFile(ifstream *f, size_t actionCount)
{
	m_actions.resize(actionCount);
	for (size_t i = 0; i < actionCount; ++i)
		f->read((char *)&m_actions[i], sizeof(Stream::ActionEntry));

	return 0;
}

int Stream2::setReferences(ifstream *f)
{
	size_t toRead = streamHdr.clientHdrLen +
		streamHdr.serverHdrLen +
		streamHdr.clientContentLen +
		streamHdr.serverContentLen;

	delete [] clientServerHdrContent;
	clientServerHdrContent = new uint8_t[toRead];
	f->read((char *)clientServerHdrContent, toRead);
	return 0;
}

void Stream2::calcOffsets(ofstream *out)
{
	size_t curPos = out->tellp();

	clientHdrBeg = curPos;
	serverHdrBeg = clientHdrBeg + streamHdr.clientHdrLen;
	clientContentBeg = serverHdrBeg + streamHdr.serverHdrLen;
	serverContentBeg = clientContentBeg + streamHdr.clientContentLen;
}

void Stream2::toFile(ofstream *out) const
{
	size_t len = streamHdr.clientHdrLen +
		streamHdr.serverHdrLen +
		streamHdr.clientContentLen +
		streamHdr.serverContentLen;

	out->write((const char *)clientServerHdrContent, len);
}

static string ipToString(const uint32_t ip)
{
	uint32_t ip_ne = htonl(ip);
	stringstream ss;

	ss << ((ip_ne >> 24) & 0xff) << "."
	   << ((ip_ne >> 16) & 0xff) << "."
	   << ((ip_ne >> 8) & 0xff) << "."
	   << (ip_ne & 0xff);

	return ss.str();
}

static string spaces(uint32_t count)
{
	stringstream ss;

	while (count--)
		ss << " ";
	return ss.str();
}

NetSocket Stream2::getServerNetSocket() const
{
	return NetSocket(streamHdr.serverIP, ntohs(streamHdr.serverPort));
}

NetSocket Stream2::getClientNetSocket() const
{
	return NetSocket(streamHdr.clientIP, ntohs(streamHdr.clientPort));
}
void Stream2::setServerNetSocket(const NetSocket& netSocket)
{
	streamHdr.serverPort = htons(netSocket.port);
	streamHdr.serverIP = netSocket.host;
}

void Stream2::setClientNetSocket(const NetSocket& netSocket)
{
	streamHdr.clientPort = htons(netSocket.port);
	streamHdr.clientIP = netSocket.host;
}
void Stream2::toLua(ofstream *f, const string& binFileName, const string& streamTableName) const

{
	(*f) << std::fixed;

	(*f) << streamTableName << "[" << streamHdr.streamId << "] = {" << endl
	     << spaces(3) << "client_data = {" << endl
	     << spaces(6) << "header = bin_read(" << binFileName << "," << clientHdrBeg << "," << streamHdr.clientHdrLen << "), " << endl
	     << spaces(6) << "content = bin_read(" << binFileName << "," << clientContentBeg << "," << streamHdr.clientContentLen << "), " << endl
	     << spaces(3) << "}," << endl
	     << spaces(3) << "server_data = {" << endl
	     << spaces(6) << "header = bin_read(" << binFileName << "," << serverHdrBeg << "," << streamHdr.serverHdrLen << "), " << endl
	     << spaces(6) << "content = bin_read(" << binFileName << "," << serverContentBeg << "," << streamHdr.serverContentLen << "), " << endl
	     << spaces(3) << "}," << endl
	     << spaces(3) << "actions = {" << endl;

	for (size_t i = 0; i < m_actions.size(); ++i) {
		const char *peer_str = m_actions[i].peer == 0? "client" : "server";

		(*f) << spaces(6) <<  peer_str << "_content(" << m_actions[i].beg << "," << m_actions[i].len << ")," << endl;
	}

	(*f) << spaces(3) << "}," << endl
	     << spaces(3) << "clients = {ip = ip(\"" << ipToString(streamHdr.clientIP) << "\"), port = " << ntohs(streamHdr.clientPort) << "}," << endl
	     << spaces(3) << "servers = {ip = ip(\"" << ipToString(streamHdr.serverIP) << "\"), port = " << ntohs(streamHdr.serverPort) << "}," << endl
	     << spaces(3) << "l4_proto = \"" << (streamHdr.protocol == 0x06? "tcp" : "udp") << "\"," << endl
	     << spaces(3) << "up_bps = " << setprecision(4) << streamHdr.upRate << "," << endl
	     << spaces(3) << "dn_bps = " << setprecision(4) << streamHdr.dnRate << "," << endl;

	(*f) << "}" << endl;
}
