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

from statsconsfile import *
from decimal import *

class SutStatsConsFile:
    def __init__(self, fileName, offset):
        self.offset = offset;
        self.statsConsFile = StatsConsFile(fileName)

    def readNext(self):
        entry = self._readNextEntry();

        if (entry is None):
            return None;

        while (entry is not None and entry[-1] <= 0):
            entry = self._readNextEntry();
        return entry;

    def getHz(self):
        return self.statsConsFile.getHz();

    def _readNextEntry(self):
        entry = self.statsConsFile.readNext();
        if (entry is None):
            return None;

        rx = 0;
        tx = 0;
        drop = 0;
        last_tsc = 0;

        for i in range(0, len(entry), 2):
            rx += entry[i][2]
            tx += entry[i][3]
            drop += entry[i][4]
            last_tsc = entry[i][5]

        last_tsc -= self.offset;
        last_tsc = Decimal(last_tsc) / self.statsConsFile.getHz();
        return [rx, tx, drop, last_tsc];

    def close(self):
        self.statsConsFile.close();
