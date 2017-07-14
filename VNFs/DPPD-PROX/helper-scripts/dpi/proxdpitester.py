#!/bin/env python

##
## Copyright (c) 2010-2017 Intel Corporation
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##

from prox import *
from remotesystem import *
from time import *
from decimal import *
from timeseriespoint import *

class TestParameters:
    def __init__(self, max_setup_rate, total_connections, ss):
        self.max_setup_rate = max_setup_rate;
        self.total_connections = total_connections;
        self.ss = ss;

    def toString(self):
        ret = ""
        ret += "\tMaximum setup rate          = %d\n" % self.max_setup_rate
        ret += "\tTotal number of connections = %d\n" % self.total_connections
        ret += "\tSpeed scaling               = %s\n" % str(self.ss)
        return ret;

    def getPerSystem(self, count):
        msr = self.max_setup_rate / count
        cnn = self.total_connections / count
        return TestParameters(msr, cnn, self.ss);

    def getConnections(self):
        return self.total_connections;

class ProxDpiTester(Prox):
    TENGIGABITBYTESPERSECOND = 1250000000

    def __init__(self, ts, testParam, ID):
        super(ProxDpiTester, self).__init__(ts)

	self._sc = None
	self._lastTot = None
	self._prevTot = None;
	self._prevBytesClient = None
	self._lastBytesClient = None
	self._prevBytesTxMeassurement = None
	self._lastBytesTxMeassurement = None

	self._setDefaultArguments();
	self._setMsr(testParam.max_setup_rate)
	self._setConnections(testParam.total_connections);
	self._setSpeedScaling(testParam.ss);
	self._setID(ID);

    def _setDefaultArguments(self):
        self.addArgument("-e")
        self.addArgument("-t")
        self.addArgument("-k")
        self.addArgument("-d")
        self.addArgument("-r 0.01");

    def _setMsr(self, msr):
        self.addArgument("-q max_setup_rate=" + str(msr))

    def _setConnections(self, connections):
        self.addArgument("-q connections=" + str(connections))

    def _setID(self, ID):
        self.addArgument("-q test_system_id=" + str(ID))

    def _setSpeedScaling(self, ss):
        self.addArgument("-q ss=" + str(ss))

    def _querySetup2(self):
        self._query_client_ports();
        self._query_server_ports();
        self._query_cores();

    def _query_client_ports(self):
        self._client_ports = []
        for i in range(0, len(self._ports), 2):
            self._client_ports.append(self._ports[i]);

    def _query_server_ports(self):
        self._server_ports = []
        for i in range(1, len(self._ports), 2):
            self._server_ports.append(self._ports[i]);

    def _query_cores(self):
        self._query_ld();
        self._query_servers();
        self._query_clients();

    def _query_ld(self):
        self._ld = self._get_core_list("$all_ld");

    def _query_servers(self):
        self._servers = self._get_core_list("$all_servers")

    def _query_clients(self):
        self._clients = self._get_core_list("$all_clients")

    def _get_core_list(self, var):
        ret = []
        result = self._send("echo " + var)._recv();
        for e in result.split(","):
            ret += [e];
        return ret;

    def start_all_ld(self):
        self._send("start $all_ld");

    def start_all_workers(self):
        self._send("start $all_workers");

    def stop_all_ld(self):
        self._send("stop $all_ld");

    def stop_all_workers(self):
        self._send("stop $all_workers");

    def update_stats(self):
        if (self._sc is None):
            self._sc = StatsCmd(self)
            self._sc.add(self._buildTotalConnectionsCmd())
            self._sc.add(self._buildReTXCmd())
            self._sc.add(self._buildIerrorsCmd())
            self._sc.add(self._buildBytesPerPortCmd(self._client_ports, "rx"));

        self._sc.sendRecv()

        self._updateTotalConnections(self._sc.getResult(0))
        self._updateReTX(self._sc.getResult(1))
        self._updateIerrors(self._sc.getResult(2))
        self._update_rates_client_ports(self._sc.getResult(3));

    def _buildTotalConnectionsCmd(self):
        cmd = "l4gen(%s).tsc" % str(self._clients[0])

        for core in self._clients:
            if (len(cmd) > 0):
                cmd += ","
            cmd += "l4gen(%s).created,l4gen(%s).finished" % (str(core), str(core))
        return cmd;

    def _updateTotalConnections(self, rep):
        instant = Decimal(int(rep[0]) - self._beg)/self._hz
        rep = rep[1:]
        tot = 0;
        for i in range(0,len(rep), 2):
            tot += int(rep[i]) - int(rep[i + 1]);

        prev = self._lastTot;
        last = TimeSeriesPoint(tot, instant);

        if (prev == None):
            prev = last;

        self._prevTot = prev
        self._lastTot = last;

    def _buildReTXCmd(self):
        cmd = ""
        for core in self._clients + self._servers:
            if (len(cmd) > 0):
                cmd += ","
            cmd += "l4gen(%s).retx" % str(core)
        return cmd;

    def _updateReTX(self, rep):
        retx = 0;
        for i in rep:
            retx += int(i);
        self._retx = retx;

    def _updateIerrors(self, rep):
        self._ierrors = self._parseIerrorsReply(rep)

    def get_total_connections(self):
        return self._lastTot.getValue()

    def getCurrentSetupRate(self):
        return int(self._lastTot.getRateOfChange(self._prevTot));

    def get_total_retx(self):
        return self._retx

    def get_rates_client_ports(self):
        return self._calcLinkUtilization(self._prevBytesClient, self._lastBytesClient);

    def getIerrorsCached(self):
        return self._ierrors;

    def _update_rates_client_ports(self, rep):
        prevBytes = self._lastBytesClient
        lastBytes = self._parseTimeSeries(rep);

        if (prevBytes == None):
            prevBytes = lastBytes;

        self._prevBytesClient = prevBytes;
        self._lastBytesClient = lastBytes;

    def _getBytesPerPort(self, ports, rxOrTx):
        sc = StatsCmd(self);
        sc.add(self._buildBytesPerPortCmd(ports, rxOrTx))
        sc.sendRecv();

        rep = sc.getResult(0);

        return self._parseTimeSeries(rep);

    def _buildBytesPerPortCmd(self, ports, rxOrTx):
        cmd = ""
        for port in ports:
            if (len(cmd) > 0):
                cmd += ","
            cmd += "port(%s).%s.bytes,port(%s).tsc" % (str(port), rxOrTx, str(port));
        return cmd

    def tx_rate_meassurement(self):
        prev = self._lastBytesTxMeassurement
        last = self._getBytesPerPort(self._server_ports, "tx");

        if (prev == None):
            prev = last;

        self._prevBytesTxMeassurement = prev
        self._lastBytesTxMeassurement = last

        return self._calcLinkUtilization(prev, last);

    def _parseTimeSeries(self, rep):
        ret = []
        for i in range(0, len(rep), 2):
            val = int(rep[0])
            instant = Decimal(int(rep[1]) - self._beg)/self._hz
            ret.append(TimeSeriesPoint(val, instant));
        return ret;

    def _calcLinkUtilization(self, prev, last):
        ret = []
        for i in range(0, len(prev)):
            bytesPerSecond = last[i].getRateOfChange(prev[i]);
            linkFraction = Decimal(bytesPerSecond)/self.TENGIGABITBYTESPERSECOND
            ret.append(round(linkFraction,2));
        return ret;
