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

from decimal import *

class CsvReaderError:
    def __init__(self, msg):
        self._msg = msg;

    def __str__(self):
        return self._msg;

class CsvReader:
    def __init__(self, fieldTypes = None):
        self._file_name = None;
        self._fieldTypes = fieldTypes;

    def open(self, file_name):
        self._file = open(file_name, 'r');
        self._file_name = file_name;

    def read(self):
        line = "#"
        while (len(line) != 0 and line[0] == "#"):
            line = self._file.readline();

        if (len(line) != 0):
            return self._lineToEntry(line)
        else:
            return None;

    def _lineToEntry(self, line):
        split = line.strip().split(',');
        if (self._fieldTypes is None):
            return split;
        have = len(split)
        expected = len(self._fieldTypes)
        if (have != expected):
            raise CsvReaderError("Invalid number of fields %d != %d" % (have, expected))

        entry = {};
        for i in range(len(self._fieldTypes)):
            curFieldType = self._fieldTypes[i][1]
            curFieldName = self._fieldTypes[i][0];
            if (curFieldType == "int"):
                entry[curFieldName] = int(split[i])
            elif (curFieldType == "Decimal"):
                entry[curFieldName] = Decimal(split[i])
            else:
                raise CsvReaderError("Invalid field type %s" % curFieldType);
        return entry;

    def readAll(self):
        ret = []
        line = self.read();
        while (line != None):
            ret.append(line);
            line = self.read();
        return ret;

    def close(self):
        self._file.close();
        self._file = None;
