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

from past.utils import old_div
import sys
import time
import requests
from rapid_log import RapidLog
from rapid_test import RapidTest

class IrqTest(RapidTest):
    """
    Class to manage the irq testing
    """
    def __init__(self, test_param, runtime, testname, environment_file,
            machines):
        super().__init__(test_param, runtime, testname, environment_file)
        self.machines = machines

    def run(self):
        RapidLog.info("+----------------------------------------------------------------------------------------------------------------------------")
        RapidLog.info("| Measuring time probably spent dealing with an interrupt. Interrupting DPDK cores for more than 50us might be problematic   ")
        RapidLog.info("| and result in packet loss. The first row shows the interrupted time buckets: first number is the bucket between 0us and    ")
        RapidLog.info("| that number expressed in us and so on. The numbers in the other rows show how many times per second, the program was       ")
        RapidLog.info("| interrupted for a time as specified by its bucket. '0' is printed when there are no interrupts in this bucket throughout   ")
        RapidLog.info("| the duration of the test. 0.00 means there were interrupts in this bucket but very few. Due to rounding this shows as 0.00 ") 
        RapidLog.info("+----------------------------------------------------------------------------------------------------------------------------")
        sys.stdout.flush()
        for machine in self.machines:
            buckets=machine.socket.show_irq_buckets(1)
            print('Measurement ongoing ... ',end='\r')
            machine.start() # PROX cores will be started within 0 to 1 seconds
            # That is why we sleep a bit over 1 second to make sure all cores
            # are started
            time.sleep(1.2)
            old_irq = [[0 for x in range(len(buckets))] for y in range(len(machine.get_cores()))] 
            irq     = [[0 for x in range(len(buckets))] for y in range(len(machine.get_cores()))]
            column_names = []
            for bucket in buckets:
                column_names.append('<{}'.format(bucket))
            column_names[-1] = '>{}'.format(buckets[-2])
            for j,bucket in enumerate(buckets):
                for i,irqcore in enumerate(machine.get_cores()):
                    old_irq[i][j] = machine.socket.irq_stats(irqcore,j)
            # Measurements in the loop above, are updated by PROX every second
            # This means that taking the same measurement 0.5 second later
            # might results in the same data or data from the next 1s window
            time.sleep(float(self.test['runtime']))
            row_names = []
            for i,irqcore in enumerate(machine.get_cores()):
                row_names.append(irqcore)
                for j,bucket in enumerate(buckets):
                    diff =  machine.socket.irq_stats(irqcore,j) - old_irq[i][j]
                    if diff == 0:
                        irq[i][j] = '0'
                    else:
                        irq[i][j] = str(round(old_div(diff,float(self.test['runtime'])), 2))
            # Measurements in the loop above, are updated by PROX every second
            # This means that taking the same measurement 0.5 second later
            # might results in the same data or data from the next 1s window
            # Conclusion: we don't know the exact window size.
            # Real measurement windows might be wrong by 1 second
            # This could be fixed in this script by checking this data every
            # 0.5 seconds Not implemented since we can also run this test for
            # a longer time and decrease the error. The absolute number of
            # interrupts is not so important.
            machine.stop()
            RapidLog.info('Results for PROX instance %s'%machine.name)
            RapidLog.info('{:>12}'.format('bucket us') + ''.join(['{:>12}'.format(item) for item in column_names]))
            for j, row in enumerate(irq):
                RapidLog.info('Core {:>7}'.format(row_names[j]) + ''.join(['{:>12}'.format(item) for item in row]))
            variables = {}
            variables['test'] = self.test['test']
            variables['environment_file'] = self.test['environment_file']
            variables['Machine'] = machine.name
            for i,irqcore in enumerate(machine.get_cores()):
                variables['Core'] = '{}'.format(row_names[i])
                for j,bucket in enumerate(buckets):
                    variables['B{}'.format(column_names[j].replace(">","M").replace("<","").replace(" ",""))] = irq[i][j]
                self.post_data('rapid_irqtest', variables)
        return (True, None)
