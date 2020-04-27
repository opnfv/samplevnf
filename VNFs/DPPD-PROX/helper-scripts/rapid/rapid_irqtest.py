#!/usr/bin/python

##
## Copyright (c) 2010-2020 Intel Corporation
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
from rapid_log import RapidLog
from rapid_test import RapidTest

class IrqTest(RapidTest):
    """
    Class to manage the irq testing
    """
    def __init__(self, runtime, machines):
        self.runtime = runtime
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
            machine.stop()
            old_irq = [[0 for x in range(len(buckets)+1)] for y in range(len(machine.get_cores())+1)] 
            irq = [[0 for x in range(len(buckets)+1)] for y in range(len(machine.get_cores())+1)]
            irq[0][0] = 'bucket us' 
            for j,bucket in enumerate(buckets,start=1):
                irq[0][j] = '<'+ bucket
            irq[0][-1] = '>'+ buckets [-2]
            machine.start()
            time.sleep(2)
            for j,bucket in enumerate(buckets,start=1):
                for i,irqcore in enumerate(machine.get_cores(),start=1):
                    old_irq[i][j] = machine.socket.irq_stats(irqcore,j-1)
            time.sleep(float(self.runtime))
            machine.stop()
            for i,irqcore in enumerate(machine.get_cores(),start=1):
                irq[i][0]='core %s '%irqcore
                for j,bucket in enumerate(buckets,start=1):
                    diff =  machine.socket.irq_stats(irqcore,j-1) - old_irq[i][j]
                    if diff == 0:
                        irq[i][j] = '0'
                    else:
                        irq[i][j] = str(round(old_div(diff,float(self.runtime)), 2))
            RapidLog.info('Results for PROX instance %s'%machine.name)
            for row in irq:
                RapidLog.info(''.join(['{:>12}'.format(item) for item in row]))
        return (True)
