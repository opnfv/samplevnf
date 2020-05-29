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
from rapid_log import RapidLog
from rapid_test import RapidTest

class PortStatsTest(RapidTest):
    """
    Class to manage the portstatstesting
    """
    def __init__(self, runtime, pushgateway, environment_file, machines):
        self.runtime = runtime
        self.pushgateway = pushgateway
        self.environment_file = environment_file
        self.machines = machines 

    def run(self):
    #    fieldnames = ['PROXID','Time','Received','Sent','NoMbufs','iErrMiss']
    #    writer = csv.DictWriter(data_csv_file, fieldnames=fieldnames)
    #    writer.writeheader()
        RapidLog.info("+---------------------------------------------------------------------------+")
        RapidLog.info("| Measuring port statistics on 1 or more PROX instances                     |")
        RapidLog.info("+-----------+-----------+------------+------------+------------+------------+")
        RapidLog.info("| PROX ID   |    Time   |    RX      |     TX     | no MBUFS   | ierr&imiss |")
        RapidLog.info("+-----------+-----------+------------+------------+------------+------------+")
        duration = float(runtime)
        old_rx = []; old_tx = []; old_no_mbufs = []; old_errors = []; old_tsc = []
        new_rx = []; new_tx = []; new_no_mbufs = []; new_errors = []; new_tsc = []
        machines_to_go = len (self.machines)
        for machine in self.machines:
            machine.reset_stats()
            old_rx.append(0); old_tx.append(0); old_no_mbufs.append(0); old_errors.append(0); old_tsc.append(0)
            old_rx[-1], old_tx[-1], old_no_mbufs[-1], old_errors[-1], old_tsc[-1] = machine.multi_port_stats()
            new_rx.append(0); new_tx.append(0); new_no_mbufs.append(0); new_errors.append(0); new_tsc.append(0)
        while (duration > 0):
            time.sleep(0.5)
            # Get statistics after some execution time
            for i, machine in enumerate(self.machines, start=0):
                new_rx[i], new_tx[i], new_no_mbufs[i], new_errors[i], new_tsc[i] = machine.multi_port_stats()
                rx = new_rx[i] - old_rx[i]
                tx = new_tx[i] - old_tx[i]
                no_mbufs = new_no_mbufs[i] - old_no_mbufs[i]
                errors = new_errors[i] - old_errors[i]
                tsc = new_tsc[i] - old_tsc[i]
                if tsc == 0 :
                    continue
                machines_to_go -= 1
                old_rx[i] = new_rx[i]
                old_tx[i] = new_tx[i]
                old_no_mbufs[i] = new_no_mbufs[i]
                old_errors[i] = new_errors[i]
                old_tsc[i] = new_tsc[i]
                RapidLog.info('|{:>10.0f}'.format(i)+ ' |{:>10.0f}'.format(duration)+' | ' + '{:>10.0f}'.format(rx) + ' | ' +'{:>10.0f}'.format(tx) + ' | '+'{:>10.0f}'.format(no_mbufs)+' | '+'{:>10.0f}'.format(errors)+' |')
    #            writer.writerow({'PROXID':i,'Time':duration,'Received':rx,'Sent':tx,'NoMbufs':no_mbufs,'iErrMiss':errors})
                if self.pushgateway:
                    URL     = self.pushgateway + '/metrics/job/' + TestName + '/instance/' + self.environment_file + str(i)
                    DATA = 'PROXID {}\nTime {}\n Received {}\nSent {}\nNoMbufs {}\niErrMiss {}\n'.format(i,duration,rx,tx,no_mbufs,errors)
                    HEADERS = {'X-Requested-With': 'Python requests', 'Content-type': 'text/xml'}
                    response = requests.post(url=URL, data=DATA,headers=HEADERS)
                    if (response.status_code != 202) and (response.status_code != 200):
                        RapidLog.info('Cannot send metrics to {}'.format(URL))
                        RapidLog.info(DATA)
                if machines_to_go == 0:
                    duration = duration - 1
                    machines_to_go = len (self.machines)
        RapidLog.info("+-----------+-----------+------------+------------+------------+------------+")
        return (True)
