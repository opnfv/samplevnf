#!/usr/bin/python

##
## Copyright (c) 2020 Intel Corporation
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
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
import time
import requests
from rapid_log import RapidLog
from rapid_test import RapidTest

class CoreStatsTest(RapidTest):
    """
    Class to manage the corestatstesting
    """
    def __init__(self, test_param,  runtime, testname, environment_file,
            machines):
        super().__init__(test_param, runtime, testname, environment_file)
        self.machines = machines 

    def run(self):
        result_details = {'Details': 'Nothing'}
        RapidLog.info("+------------------------------------------------------------------------------------------------------------------+")
        RapidLog.info("| Measuring core statistics on 1 or more PROX instances                                                            |")
        RapidLog.info("+-----------+-----------+------------+------------+------------+------------+------------+------------+------------+")
        RapidLog.info("| PROX ID   |    Time   |    RX      |     TX     | non DP RX  | non DP TX  |   TX - RX  | nonDP TX-RX|  DROP TOT  |")
        RapidLog.info("+-----------+-----------+------------+------------+------------+------------+------------+------------+------------+")
        duration = self.test['runtime']
        tot_drop = []
        old_rx = []; old_non_dp_rx = []; old_tx = []; old_non_dp_tx = []; old_drop = []; old_tx_fail = []; old_tsc = []
        new_rx = []; new_non_dp_rx = []; new_tx = []; new_non_dp_tx = []; new_drop = []; new_tx_fail = []; new_tsc = []
        machines_to_go = len (self.machines)
        for machine in self.machines:
            machine.reset_stats()
            tot_drop.append(0)
            old_rx.append(0); old_non_dp_rx.append(0); old_tx.append(0); old_non_dp_tx.append(0); old_drop.append(0); old_tx_fail.append(0); old_tsc.append(0)
            old_rx[-1], old_non_dp_rx[-1], old_tx[-1], old_non_dp_tx[-1], old_drop[-1], old_tx_fail[-1], old_tsc[-1], tsc_hz = machine.core_stats()
            new_rx.append(0); new_non_dp_rx.append(0); new_tx.append(0); new_non_dp_tx.append(0); new_drop.append(0); new_tx_fail.append(0); new_tsc.append(0)
        while (duration > 0):
            time.sleep(0.5)
            # Get statistics after some execution time
            for i, machine in enumerate(self.machines, start=0):
                new_rx[i], new_non_dp_rx[i], new_tx[i], new_non_dp_tx[i], new_drop[i], new_tx_fail[i], new_tsc[i], tsc_hz = machine.core_stats()
                drop = new_drop[i]-old_drop[i]
                rx = new_rx[i] - old_rx[i]
                tx = new_tx[i] - old_tx[i]
                non_dp_rx = new_non_dp_rx[i] - old_non_dp_rx[i]
                non_dp_tx = new_non_dp_tx[i] - old_non_dp_tx[i]
                tsc = new_tsc[i] - old_tsc[i]
                if tsc == 0 :
                    continue
                machines_to_go -= 1
                old_drop[i] = new_drop[i]
                old_rx[i] = new_rx[i]
                old_tx[i] = new_tx[i]
                old_non_dp_rx[i] = new_non_dp_rx[i]
                old_non_dp_tx[i] = new_non_dp_tx[i]
                old_tsc[i] = new_tsc[i]
                tot_drop[i] = tot_drop[i] + tx - rx
                RapidLog.info('|{:>10.0f}'.format(i)+ ' |{:>10.0f}'.format(duration)+' | ' + '{:>10.0f}'.format(rx) + ' | ' +'{:>10.0f}'.format(tx) + ' | '+'{:>10.0f}'.format(non_dp_rx)+' | '+'{:>10.0f}'.format(non_dp_tx)+' | ' + '{:>10.0f}'.format(tx-rx) + ' | '+ '{:>10.0f}'.format(non_dp_tx-non_dp_rx) + ' | '+'{:>10.0f}'.format(tot_drop[i]) +' |')
                result_details = {'test': self.test['test'],
                        'environment_file': self.test['environment_file'],
                        'PROXID': i,
                        'StepSize': duration,
                        'Received': rx,
                        'Sent': tx,
                        'NonDPReceived': non_dp_rx,
                        'NonDPSent': non_dp_tx,
                        'Dropped': tot_drop[i]}
                result_details = self.post_data('rapid_corestatstest', result_details)
                if machines_to_go == 0:
                    duration = duration - 1
                    machines_to_go = len (self.machines)
        RapidLog.info("+-----------+-----------+------------+------------+------------+------------+------------+------------+------------+")
        return (True, result_details)
                
