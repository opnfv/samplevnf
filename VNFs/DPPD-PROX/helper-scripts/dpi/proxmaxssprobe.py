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
from prox import *

class ProxMaxSSProbe(Prox):
    def __init__(self, ts):
        super(ProxMaxSSProbe, self).__init__(ts)

    def getMaxSS(self):
        self.addArgument("-q max_ss_and_quit=true");
        self.addArgument("-q test_system_id=0");
        self.startFork();
        ret = self.startJoinNoConnect();
        last_occur = ret["out"].rfind("\n") + 1;
        last_line = ret["out"][last_occur:];

        return Decimal(last_line.split("=")[1])
