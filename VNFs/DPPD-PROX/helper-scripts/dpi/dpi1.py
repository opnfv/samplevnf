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

from testerset import *
from time import sleep
from time import time
from decimal import *
import copy
from os import system
import socket
from itertools import chain
from math import *
from csvwriter import *
from config import *
from progress import *
from proxmaxssprobe import *

def runTest(minSetupRate, testParam):
    print "Running test with following parameters:"
    print testParam.toString();

    testers = testerSet(config._test_systems, config._max_port_rate, testParam);

    thresh = testParam.getConnections();
    p = Progress(thresh, ["connections", "setup rate", "reTX"], False);
    loop_count = 0;
    converged = False;

    testers.startForkJoin();
    testers.wait_links_up();
    testers.start_cores();

    print "Running until convergence (%s connections)" % str(thresh)
    while (not converged):
        sleep(config._interCheckDuration)
        testers.update_stats();
        tot = testers.get_total_connections();
        tot_retx = testers.get_total_retx();
        rates = testers.get_rates();
        curSetupRate = testers.get_setup_rate();
        ierrors = testers.getIerrors();

        converged = tot >= thresh;
        if (not converged):
            if (loop_count > 0 and curSetupRate < minSetupRate):
                reason = str(curSetupRate) + " < " + str(minSetupRate);
                print "Current setup rate is lower than min setup rate: " +  reason
                testers.killProx();
                return False, [];
            if (not testers.conditionsGood()):
                print "conditions are bad: " + testers.getReason();
                testers.killProx();
                return False, [];

        if (config._debug):
            p.setProgress(tot, [tot, curSetupRate, tot_retx]);
            print p.toString();
        loop_count += 1;
    print "converged"

    skipTime = config._skipTime
    print "Connection threshold reached, waiting for " + str(skipTime) + "s, conditions checked = " + str(config._checkConditions)
    while (skipTime > 0):
        skipTime -= config._interCheckDuration
        sleep(config._interCheckDuration)
        testers.update_stats();
        if (config._checkConditions and not testers.conditionsGood()):
            print "conditions are bad: " + testers.getReason();
            testers.killProx();
            return False, [];

    testers.tx_rate_meassurement();

    testLength = config._testLength
    print "Waiting final " + str(testLength) + "s"
    while (testLength > 0):
        testLength -= config._interCheckDuration
        sleep(config._interCheckDuration)
        testers.update_stats();
        if (not testers.conditionsGood()):
            print "conditions are bad: " + testers.getReason();
            testers.killProx();
            return False, [];

    rates = testers.tx_rate_meassurement();

    testers.killProx();
    return True, rates;

def find_ss(tot_conn, maxSetupRate, ss_max):
    iterationCount = 0;
    valid_ss = []
    speed_ss = [];

    # The setup rate must be in [0.2% of total connections, maxSetupRate]
    # Also, it must not be hihger than 50% of the total connections
    min_setup_rate = tot_conn / 500;

    if (min_setup_rate > maxSetupRate):
        print "min setup rate > max setup rate: " + str(min_setup_rate) + " > " + str(maxSetupRate);
        return valid_ss, speed_ss;
    if (maxSetupRate > tot_conn / 2):
        print "maximum setup rate (" + str(maxSetupRate) + ") is more than 50% of " + str(tot_conn)
        return valid_ss, speed_ss;

    accuracy = 10**config._accuracy
    ss_lo = 1
    ss_hi = int(round(ss_max * accuracy,0))

    iterationOverride = [ss_hi, ss_lo];
    # Binary search for highest speed scaling
    while (ss_lo <= ss_hi):
        if (iterationCount < len(iterationOverride)):
            ss = iterationOverride[iterationCount]
        else:
            ss = (ss_lo + ss_hi)/2;

        testParam = TestParameters(maxSetupRate, tot_conn, float(ss)/accuracy);

        success, rates = runTest(min_setup_rate, testParam);
        print "success = " + str(success) + ", rates = " + str(rates)
        if (success == True):
            valid_ss.append(float(ss)/accuracy);
            speed_ss.append(sum(rates)/len(rates))
            ss_lo = ss + 1
        else:
            ss_hi = ss - 1;
        iterationCount += 1
    return valid_ss, speed_ss;

def get_highest_ss_and_speed(valid_ss, speed_ss):
    highest_ss = None;
    highest_speed = None;

    for i in range(len(valid_ss)):
        if(highest_ss == None or highest_ss < valid_ss[i]):
            highest_ss = valid_ss[i];
            highest_speed = speed_ss[i];
    return highest_ss, highest_speed;

def get_max_ss():
    ts = config._test_systems[0];
    test_system = ProxMaxSSProbe(ts);
    max_ss = test_system.getMaxSS();

    return floor((max_ss * (10**config._accuracy)))/(10**config._accuracy)

config = Config();
config.parse(sys.argv[0], sys.argv[1:])

err = config.getErrorTestOne();
if (err is not None):
    print "Invalid configuration: " + err;
    exit(-1);
else:
    print config.toString()

if (config._once is not None):
    maxSetupRate = int(config._once[0])
    minSetupRate = maxSetupRate/500
    connections = int(config._once[1])
    speedScaling = float(config._once[2])

    testParam = TestParameters(maxSetupRate, connections, speedScaling)
    success, rates = runTest(minSetupRate, testParam)
    print "success = " + str(success) + ", port rates = " + str(rates)
    exit(0);

msr_list = []
msr_list += range(4000, 20000, 2000)
msr_list += range(20000, 100000, 20000)
msr_list += range(100000, 300000, 50000)
msr_list += range(300000, 800001, 100000);

conn_list = [1*10**5, 2*10**5, 4*10**5, 8*10**5, 1*10**6, 2*10**6]

summary_file = CsvWriter()
summary_file.open(config._output_file_name)

tot_it = 0;
for tot_conn in conn_list:
    for msr in msr_list:
        if (msr >= tot_conn/2):
            break;
        tot_it += 1

cnt = -1;
print "Search will include " + str(tot_it) + " parameter combinations"
print "Will search for highest link utilization"

# If the lowest msr was a for n connections, then the lowest msr
# for n + 1 connections can't be lower than a.
low_sr = msr_list[0];

max_ss = get_max_ss()

high_ss = Decimal(max_ss)

globalProgress = Progress(tot_it)
globalProgress.setProgress(0);
for tot_conn in conn_list:
    had_success = False;
    all_ss = []
    for msr in msr_list:
        globalProgress.incrProgress();

        if (msr < low_sr):
            print "skipping " + str(msr) + " since it is lower than " + str(low_sr)
            continue;

        print globalProgress.toString();

        valid_ss, speed_ss = find_ss(tot_conn, msr, high_ss)
        print "valid ss = " + str(valid_ss)
        print "valid speeds = " + str(speed_ss)

        if (len(valid_ss) > 0):
            highest_ss, highest_speed = get_highest_ss_and_speed(valid_ss, speed_ss);
            summary_file.write([msr, tot_conn, highest_ss, highest_speed]);

            if (not had_success):
                low_sr = msr;

            had_success = True;
        all_ss = all_ss + valid_ss;

    if (len(all_ss) > 0):
        high_ss = max(all_ss);
