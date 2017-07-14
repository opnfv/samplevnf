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

from sutstatsconsfile import *
from tsstatsconsfile import *
from csvwriter import *

class TestResult:
    class Times:
        def __init__(self):
            self.serie = []
        def addTime(self, val):
            self.serie.append(val)
        def getTime(self, i):
            return self.serie[i]

    def __init__(self, testSystemCount):
        self.rates = None;
        self.tsStatsDump = [];
        self.tsTimes = [];
        for i in range(testSystemCount):
            self.tsStatsDump.append("");
            self.tsTimes.append(TestResult.Times());

        self.sutStatsDump = None;
        self.sutTime = TestResult.Times();

    def getTSCount(self):
        return len(self.tsTimes)

    def setTSStatsDump(self, filePaths):
        self.tsStatsDump = filePaths;

    def setSUTStatsDump(self, filePath):
        self.sutStatsDump = filePath;

    def getTSStatsDump(self):
        return self.tsStatsDump;

    def getSUTStatsDump(self):
        return self.sutStatsDump;

    def addTimeTS(self, times):
        for i in range(len(times)):
            self.tsTimes[i].addTime(times[i])

    def addTimeSUT(self, time):
        self.sutTime.addTime(time);


class ResultProcessor:
    def __init__(self, testResult):
        self._testResults = testResult;

    def process(self):
        self._readStatsConsLogs();
        self._mergeTsStats();
        self._calcSetupRate();

    def percentHandled(self):
        converged_tsc = self._testResults.sutTime.getTime(1) - self._testResults.sutTime.getTime(0)
        end_tsc = self._testResults.sutTime.getTime(2) - self._testResults.sutTime.getTime(0)

        converged = converged_tsc/Decimal(self._sutHz)
        end = end_tsc/Decimal(self._sutHz);

        rx_converged = -1
        tx_converged = -1
        rx_end = -1
        tx_end = -1

        for entry in self._sutStats:
            timeStamp = entry[3]
            if (rx_converged == -1):
                if (timeStamp > converged):
                    rx_converged = entry[0]
                    tx_converged = entry[1] - entry[2]
                else:
                    continue;
            else:
                if (timeStamp > end):
                    rx_end = entry[0]
                    tx_end = entry[1] - entry[2]
                    break;
        return (tx_end - tx_converged)/Decimal(rx_end - rx_converged)

    def toFile(self, fileName):
        outFile = CsvWriter();

        outFile.open(fileName)

        for entry in self._sutStats:
            timeStamp = round(entry[3], 3);
            rx = entry[0]
            tx = entry[1]
            drop = entry[2]

            outFile.write([timeStamp, rx, tx, drop, "", ""])

        for entry in self._tsStats:
            timeStamp = round(entry[-1], 3);
            connections = entry[0]
            setupRate = entry[3]
            outFile.write([timeStamp,"","","", connections, setupRate]);
        outFile.close();

    def _readStatsConsLogs(self):
        print "Reading SUT stats"
        self._sutStats = self._readSutStats();
        print "Reading TS stats"
        self._tsAllStats = self._readAllTSStats();

    def _mergeTsStats(self):
        # The first test system is the reference system. The totals
        # will be accumulated by repeatedly taking the closest
        # available data from other systems
        ret = []
        for entry in self._tsAllStats[0]:
            ret.append(entry)

        interSampleTime = ret[1][-1] - ret[0][-1];

        mergedSampleCount = 0;
        if (len(self._tsAllStats) == 1):
            mergedSampleCount = len(ret)

        for i in range(0, len(self._tsAllStats) - 1):
            prev = 0;
            for entry in ret:
                timeStamp = entry[-1]
                found = False;

                for idx in range(prev, len(self._tsAllStats[i])):
                    diff = abs(self._tsAllStats[i][idx][-1] - timeStamp)
                    if (diff < interSampleTime):
                        found = True;
                        prev = idx;
                        break;

                if (found):
                    entry[0] += self._tsAllStats[i][prev][0]
                    entry[1] += self._tsAllStats[i][prev][1]
                    mergedSampleCount += 1;
                else:
                    break;

        self._tsStats = ret[0: mergedSampleCount];

    def _calcSetupRate(self):
        for i in range(0, len(self._tsStats)):
            prevCreated = 0
            prevTime = 0
            if (i > 0):
                prevCreated = self._tsStats[i - 1][1];
                prevTime = self._tsStats[i - 1][-1];
            curCreated = self._tsStats[i][1];
            curTime = self._tsStats[i][-1];

            setupRate = (curCreated - prevCreated)/(curTime - prevTime)

            self._tsStats[i].append(setupRate);


    def _readSutStats(self):
        ret = []
        fileName = self._testResults.getSUTStatsDump();
        beg = self._testResults.sutTime.getTime(0);
        f = SutStatsConsFile(fileName, beg);
        entry = f.readNext();
        self._sutHz = f.getHz();
        while (entry is not None):
            ret.append(entry);
            entry = f.readNext();
        f.close();
        return ret;

    def _readAllTSStats(self):
        stats = []
        for i in range(self._testResults.getTSCount()):
            fileName = self._testResults.getTSStatsDump()[i]
            beg = self._testResults.tsTimes[i].getTime(0)
            tsStat = self._readTSStats(fileName, beg)
            stats.append(tsStat);
        return stats;

    def _readTSStats(self, fileName, beg):
        ret = []
        f = TSStatsConsFile(fileName, beg)

        entry = f.readNext()
        while (entry is not None):
            ret.append(entry);
            entry = f.readNext();
        f.close()
        return ret;
