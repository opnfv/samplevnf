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

from proxdpitester import *

class testerSet:
    def __init__(self, test_systems, maxRate, testParam):
        self._test_systems = [];
        self._reason = ""
        self._maxRate = maxRate

        testParamPerSystem = testParam.getPerSystem(len(test_systems));

        for i in range(len(test_systems)):
            ts = test_systems[i];
            to_add = ProxDpiTester(ts, testParamPerSystem, i);
            self.add_test_system(to_add);

    def getCount(self):
        return len(self._test_systems);

    def add_test_system(self, test_system):
        self._test_systems.append(test_system);

    def startFork(self):
        print "Starting test systems:"
        for ts in self._test_systems:
            print "\t" + str(ts.getIP())
            ts.startFork();

    def startJoin(self):
        for ts in self._test_systems:
            elapsed = ts.startJoin();
            if (elapsed == None):
                print "Failed to start on " + str(ts.getIP())
            else:
                print "Started on " + str(ts.getIP())
        sleep(1);

    def startForkJoin(self):
        self.startFork();
        self.startJoin();

    def update_stats(self):
        for ts in self._test_systems:
            ts.update_stats();

    def wait_links_up(self):
        for ts in self._test_systems:
            ts.waitAllLinksUp();
        sleep(1);

    def start_cores(self):
        for ts in self._test_systems:
            ts.start_all_ld();
            ts.waitCmdFinished();
        for ts in self._test_systems:
            ts.start_all_workers();
        for ts in self._test_systems:
            ts.waitCmdFinished();

    def stop_cores(self):
        for ts in self._test_systems:
            ts.stop_all_workers();
            ts.stop_all_ld();

        for ts in self._test_systems:
            ts.waitCmdFinished();

    def getTsc(self):
        ret = []
        for ts in self._test_systems:
            ret += [ts.getTsc()]
        return ret;

    def get_setup_rate(self):
        total = 0;
        for ts in self._test_systems:
            total += ts.getCurrentSetupRate();
        return total

    def get_total_connections(self):
        total = 0;
        for ts in self._test_systems:
            ts_tot_conn = ts.get_total_connections();
            total += ts_tot_conn

        return total;

    def get_total_retx(self):
        total = 0;
        for ts in self._test_systems:
            total += ts.get_total_retx();
        return total;

    def getIerrors(self):
        total = 0;
        for ts in self._test_systems:
            total += ts.getIerrorsCached();
        return total;

    def get_rates(self):
        rates = [];
        for ts in self._test_systems:
            rates += ts.get_rates_client_ports();
        return rates;

    def tx_rate_meassurement(self):
        rates = []
        for ts in self._test_systems:
            rates += ts.tx_rate_meassurement();
        return rates;

    def scpStatsDump(self, dst):
        ret = []
        for i in range(len(self._test_systems)):
            dstFileName = dst + str(i);
            ret.append(dstFileName);
            self._test_systems[i].scpStatsDump(dstFileName)
        return ret;

    def conditionsGood(self):
        tot_retx = self.get_total_retx();
        rates = self.get_rates();
        ierrors = self.getIerrors();

        if (tot_retx > 100):
            self._reason = "Too many reTX (" + str(tot_retx) + ")"
            return False;
        if (ierrors > 0):
            self._reason = "Too many ierrors (" + str(ierrors) + ")"
            return False;
        for i in range(0, len(rates)):
            if (rates[i] > self._maxRate):
                self._setReason(i, rates)
                return False;
        return True;

    def _setReason(self, port, rates):
        portStr = str(port);
        rateStr = str(rates[port])
        maxRateStr = str(self._maxRate);
        allRatesStr = str(rates);

        fmt = "Rate on port %s = %s > %s, rate on all = %s"
        self._reason = fmt % (portStr, rateStr, maxRateStr, allRatesStr)

    def getReason(self):
        return self._reason;

    def quitProx(self):
        for ts in self._test_systems:
            ts.quitProx();

    def killProx(self):
        for ts in self._test_systems:
            ts.stop_all_workers();
        for ts in self._test_systems:
            ts.stop_all_ld();
        for ts in self._test_systems:
            ts.killProx();
