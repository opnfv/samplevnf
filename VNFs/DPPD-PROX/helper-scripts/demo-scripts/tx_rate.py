#!/bin/env python2.7

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
from decimal import *
from time import *

class data_point:
    value = 0;
    tsc = 0;
    def __init__(self, value, tsc):
        self.value = value;
        self.tsc = tsc;

def measure_tx(prox_instance, port_id):
    port_tx_pkt = "port(" + str(port_id) + ").tx.packets"
    port_tsc = "port(" + str(port_id) + ").tsc";
    cmd = "stats " + port_tx_pkt + "," + port_tsc;
    reply = prox_instance.send(cmd).recv().split(",");

    return data_point(int(reply[0]), int(reply[1]));

def get_rate(first, second, hz):
    tsc_diff = second.tsc - first.tsc;
    value_diff = second.value - first.value;

    return int(Decimal(value_diff * hz) / tsc_diff)

# make sure that prox has been started with the -t parameter
prox_instance = prox("127.0.0.1")
print "Connected to prox"

hz = int(prox_instance.send("stats hz").recv());

print "System is running at " + str(hz) + " Hz"

print "Showing TX pps on port 0"

update_interval = 0.1

print "Requesting new data every " + str(update_interval) + "s"

measure = measure_tx(prox_instance, 0);
while (True):
    sleep(update_interval)
    measure2 = measure_tx(prox_instance, 0);

    # since PROX takes measurements at a configured rate (through
    # update interval command or throw -r command line parameter), it
    # might be possible that two consecutive measurements report the
    # same. To get updates at a frequency higher than 1 Hz,
    # reconfigure prox as mentioned above.

    if (measure.tsc == measure2.tsc):
        continue;

    print get_rate(measure, measure2, hz);

    measure = measure2;
