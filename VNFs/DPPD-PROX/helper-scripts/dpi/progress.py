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
from time import time

class Progress:
    def __init__(self, limit, fieldNames = [], overallETA = True):
        self._fieldNames = fieldNames;
        self._limit = limit;
        self._progress = 0;
        self._prevProgress = 0;
        self._prevTime = 0;
        self._progressSetCount = 0;
        self._time = 0;
        self._overallETA = overallETA;

    def setProgress(self, progress, fieldValues = []):
        self._fieldValues = fieldValues;
        if (self._overallETA == True):
            self._progress = progress
            self._time = time();
            if (self._progressSetCount == 0):
                self._prevProgress = self._progress;
                self._prevTime = self._time;
        else:
            self._prevProgress = self._progress;
            self._prevTime = self._time;
            self._progress = progress;
            self._time = time();
        self._progressSetCount += 1

    def incrProgress(self):
        self.setProgress(self._progress + 1);

    def toString(self):
        ret = ""
        ret += str(self._getETA()) + " seconds left"
        for f,v in zip(self._fieldNames, self._fieldValues):
            ret += ", %s=%s" % (str(f),str(v))
        return ret;

    def _getETA(self):
        if (self._progressSetCount < 2):
            return "N/A"
        diff = self._progress - self._prevProgress;
        t_diff = Decimal(self._time - self._prevTime);
        if (t_diff < 0.001 or diff <= 0):
            return "N/A"
        rate = Decimal(diff)/t_diff
        remaining = Decimal(self._limit - self._progress);
        return round(remaining/rate, 2);
