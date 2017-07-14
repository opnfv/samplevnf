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

import sys
from config import *
from csvreader import *
from sets import Set
from csvwriter import *

class ResultEntry:
    def __init__(self):
        self.boundary = None;
        self.cores = {}

    def setBoundary(self, val):
        self.boundary = val;

    def addCoreResult(self, core, val):
        self.cores[core] = val

    def getCoreResult(self, core):
        if (core in self.cores):
            return self.cores[core];
        return None;

    def getBoundary(self):
        return self.boundary;

    def getCores(self):
        return self.cores

    def getMsr(self):
        return self.msr;

class DictEntry:
    def __init__(self, key):
        self.dictionary = {}
        self.entries = []
        self.key = key;

config = Config();
config.parse(sys.argv[0], sys.argv[1:])

err = config.getErrorMakeTable();

if (err is not None):
    print err
    exit(-1);

if (config._debug):
    print "Performance data: " + config.getInputFileName2()
    print "Boundaries: " + config.getInputFileName()

allData = {}

infileFields = []
infileFields += [("msr", "int")]
infileFields += [("conn", "int")]
infileFields += [("ss", "Decimal")]
infileFields += [("bw", "Decimal")]

boundariesFile = CsvReader(infileFields)
boundariesFile.open(config.getInputFileName());
boundaries = boundariesFile.readAll();

cores = Set()

orderedResults = []
finalResults = {}

for a in boundaries:
    key = a["conn"]
    if (key not in finalResults):
        newDict = DictEntry(key)
        finalResults[key] = newDict
        orderedResults.append(newDict)

for a in boundaries:
    table = finalResults[a["conn"]]
    key = a["msr"]
    value = ResultEntry()
    value.msr = a["msr"]
    value.conn = a["conn"]
    value.boundary = a["bw"]
    table.dictionary[key] = value
    table.entries.append(value)

infileFields2 = []
infileFields2 += [("cores", "int")]
infileFields2 += [("msr", "int")]
infileFields2 += [("conn", "int")]
infileFields2 += [("ss", "Decimal")]
infileFields2 += [("down", "Decimal")]

resultsFile = CsvReader(infileFields2)
resultsFile.open(config.getInputFileName2())

for a in resultsFile.readAll():
    table = finalResults[a["conn"]]
    key = a["msr"]
    table.dictionary[key].addCoreResult(a["cores"], a["down"])
    cores.add(a["cores"]);


outputFile = CsvWriter()

outputFile.open(config._output_file_name)

title = ["setup rate", "maximum"]
for e in sorted(cores):
    title += [str(e)]

for a in orderedResults:
    outputFile.write(["connections = " + str(a.key)])
    outputFile.write(title)

    for e in a.entries:
        line = [str(e.getMsr())]
        line += [str(e.getBoundary())]
        for c in sorted(cores):
            if (e.getCoreResult(c) is not None):
                line += [str(e.getCoreResult(c))]
            else:
                line += [""]
        outputFile.write(line)
