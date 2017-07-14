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

class TimeSeriesPoint:
    def __init__(self, value, instant):
        self._value = value;
        self._instant = instant;

    def getValue(self):
        return self._value;

    def getInstant(self):
        return self._instant;

    def getRateOfChange(self, other):
        diff = self.getValue() - other.getValue();
        t_diff = self.getInstant() - other.getInstant();

        if (diff == 0 or abs(t_diff) <= 0.00001):
            return Decimal(0)
        else:
            return Decimal(diff)/t_diff
