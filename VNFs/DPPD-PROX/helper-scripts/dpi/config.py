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

import getopt
import sys
from systemconfig import *

class Config:
    _debug = False;
    _test_systems = [];
    _output_file_name = None;
    _input_file_name = None
    _input_file_name2 = None
    _max_port_rate = 0.85
    _sut = None
    _accuracy = 2;
    _threshold = 0.95
    _once = None
    _skipTime = 10
    _testLength = 120
    _dpiCoreList = range(1, 5)
    _checkConditions = False;
    _interCheckDuration = float(1)

    def getInputFileName(self):
        return self._input_file_name

    def getInputFileName2(self):
        return self._input_file_name2

    def toString(self):
        ret = ""
        ret += "Test systems: \n"
        for ts in self._test_systems:
            ret += ts.toString();

        if (self._sut is not None):
            ret += "SUT: \n"
            ret += self._sut.toString();

        ret += "Output file name: " + str(self._output_file_name) + "\n"
        ret += "Max port rate: " + str(self._max_port_rate) + "\n"
        ret += "Accuracy: " + str(self._accuracy) + " digits after point"
        return ret

    def getErrorTestOne(self):
        if (len(self._test_systems) == 0):
            return "Missing test systems";
        if (self._output_file_name is None):
            return "No output file or input file defined";
        return None

    def getErrorTestTwo(self):
        if (self._input_file_name is None):
            return "Input file is missing"
        if (self._input_file_name == self._output_file_name):
            return "Input file and output file are the same"
        return self.getErrorTestOne();

    def getErrorMakeTable(self):
        if (self._input_file_name is None):
            return "Missing input file"
        if (self._input_file_name2 is None):
            return "Missing file with performance resuilts"
        if (self._output_file_name is None):
            return "No output file or input file defined";
        if (self._input_file_name2 == self._input_file_name):
            return "Input file used multiple times"
        if (self._input_file_name == self._output_file_name):
            return "output file is the same as the input file"
        if (self._input_file_name2 == self._output_file_name):
            return "output file is the same as the input file 2"

        return None

    def usageAndExit(self, argv0):
        print "Usage: " + str(argv0)
        print "-t    Add a test system, syntax: " + SystemConfig.expectedSyntax()
        print "-s    Add SUT, syntax: " + SystemConfig.expectedSyntax()
        print "-o    Ouput file name"
        print "-a    Accuracy, number of digits after point"
        print "-i    Input file"
        print "-j    File with performance results"
        print "-m    Maximum per port rate, by default 0.85 (85%)"
        print "-d    Enable debugging"
        print "-w    Fraction of connections to reach, by default is 0.95 (95%)"
        print "-h    Show help"
        print "-q    Run a single test iteration, syntax of argument "
        print "-b    Skip time, by default 10 sec"
        print "-l    Test length, by default 120 sec"
        print "-n    Maximum number of DPI cores to test"
        print "-k    Period between checking conditions, 1 second by default"
        print "-c    Check conditions during 10 second period after convergence"
        print "      is msr,conn,ss (i.e. -q 4000,100000,38.91)"
        exit(-1);

    def parse(self, programName, args):
        try:
            opts, args = getopt.getopt(args, "t:s:o:a:i:q:m:dhw:j:b:l:n:k:c")
        except getopt.GetoptError as err:
            print str(err)
            return;
        for option, arg in opts:
            if(option == "-t"):
                for ts in arg.split(","):
                    syntaxErr = SystemConfig.checkSyntax(ts)
                    if (syntaxErr != ""):
                        print syntaxErr
                        exit(-1);
                    self._test_systems.append(SystemConfig(ts));
            elif(option == "-s"):
                syntaxErr = SystemConfig.checkSyntax(ts)
                if (syntaxErr != ""):
                    print syntaxErr
                    exit(-1);
                self._sut = SystemConfig(arg);
            elif(option == "-w"):
                self._threshold = float(arg)
            elif(option == "-o"):
                self._output_file_name = arg;
            elif(option == '-a'):
                self._accuracy = int(arg);
            elif(option == "-i"):
                self._input_file_name = arg;
            elif(option == "-j"):
                self._input_file_name2 = arg;
            elif(option == "-q"):
                self._once = arg.split(",")
            elif(option == "-c"):
                self._checkConditions = True;
            elif(option == "-m"):
                self._max_port_rate = float(arg);
            elif(option == "-k"):
                self._interCheckDuration = float(arg);
            elif(option == "-d"):
                self._debug = True
            elif(option == '-h'):
                self.usageAndExit(programName)
            elif(option == '-b'):
                self._skipTime = int(arg)
            elif(option == '-l'):
                self._testLength = int(arg)
            elif(option == '-n'):
                self._dpiCoreList = self.strToList(arg)
            else:
                self.usageAndExit(programName);

    def strToList(self, arg):
        elements = [];
        tokens = arg.split(",");

        for a in tokens:
            if (a.count('-') == 0):
                elements.append(int(a))
            elif (a.count('-') == 1):
                beg = int(a.split('-')[0]);
                end = int(a.split('-')[1]);
                if (beg > end):
                    raise Exception("Invalid list input format")
                elements += range(beg, end + 1);
            else:
                raise Exception("Invalid list input format")
        return elements;
