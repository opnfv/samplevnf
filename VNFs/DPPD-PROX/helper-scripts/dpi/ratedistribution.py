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
from decimal import *

def usage(progName):
    print "usage: " + progName + " config [up|down]"
    print " The script reads a lua configuration "
    print " and outputs a histogram wit 21 buckets."
    print " The first 20 buckets contain 70th percentile."
    print " The last bucket contains the remaining items."
    exit(-1);

if (len(sys.argv) != 3):
    usage(sys.argv[0])

if (sys.argv[2] == "down"):
    match = "dn_bps"
elif (sys.argv[2] == "up"):
    match = "up_bps"
else:
    usage(sys.argv[0])

values = []
for line in open(sys.argv[1]).readlines():
    line = line.strip();

    if line.find(match) != -1:
        v = line.split(" = ")[1].strip(",")
        values.append(Decimal(v));

values = sorted(values)

treshold = values[int(len(values)*0.7)]

buckets = [0]*21;

for v in values:
    if (v > treshold):
        buckets[20] += 1
    else:
        buckets[int(v * 20 / treshold)] += 1

stepSize = treshold / 20;

print "# bucket range, count"
for i in range(len(buckets) - 1):
    beg = str(int(i * stepSize))
    end = str(int((i + 1) * stepSize - 1))
    print beg + "-" + end + "," + str(buckets[i])

i = len(buckets) - 1
print beg + "+," + str(buckets[i])
