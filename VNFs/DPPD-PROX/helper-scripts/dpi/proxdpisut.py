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

class ProxDpiSut(Prox):
    def __init__(self, ts, coreCount):
        super(ProxDpiSut, self).__init__(ts)

        self._setDefaultArguments();
        self._setDpiCoreCount(coreCount);

    def _setDefaultArguments(self):
        self.addArgument("-e");
        self.addArgument("-t");
        self.addArgument("-k");
        self.addArgument("-d");
        self.addArgument("-r 0.01");

    def _setDpiCoreCount(self, count):
        self.addArgument("-q dpi_core_count=" + str(count))

    def _querySetup2(self):
        self._query_cores();

    def _query_cores(self):
        print "querying cores"
        self._wk = self._get_core_list("$wk");

    def _get_core_list(self, var):
        ret = []
        result = self._send("echo " + var)._recv();
        for e in result.split(","):
            ret += [e];
        return ret;

    def getTsc(self):
        cmd = "stats task.core(%s).task(0).tsc" % self._wk[-1]
        res = int(self._send(cmd)._recv());
        if (res == 0):
            return self._getTsc();
        else:
            return res;
