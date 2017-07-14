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

import os
import struct

class StatsConsFile:
    def __init__(self, file_name, tsc = None):
        self._file = open(file_name, "rb");
        try:
            data = self._file.read(4*8);
            dataUnpacked = struct.unpack("<qqqq", data);

            self._hz = dataUnpacked[0]
            if (tsc is None):
                self._tsc = dataUnpacked[1]
            else:
                self._tsc = tsc;

            self._entryCount = dataUnpacked[2]
            fieldCount = dataUnpacked[3]

            data = self._file.read(fieldCount);
            fmt = "b" * fieldCount;

            dataUnpacked = struct.unpack("<" + fmt, data);
            self._entryFmt = "<";
            self._entrySize = 0;

            for e in dataUnpacked:
                if (e == 4):
                    self._entryFmt += "i"
                elif (e == 8):
                    self._entryFmt += "q"
                else:
                    raise Exception("Unknown field format: " + str(e))
                self._entrySize += e
        except:
            print "except"
            self._file.close();

    def setBeg(self, tsc):
        self._tsc = tsc

    def getBeg(self):
        return self._tsc;

    def getHz(self):
        return self._hz

    def readNext(self):
        ret = []
        for i in range(self._entryCount):
            entry = self._readNextEntry()
            if (entry == None):
                return None;
            ret.append(entry);
        return ret;

    def _readNextEntry(self):
        try:
            entry = self._file.read(self._entrySize);
            entryUnpacked = struct.unpack(self._entryFmt, entry);
            return list(entryUnpacked)
        except:
            return None;

    def close(self):
        self._file.close();
