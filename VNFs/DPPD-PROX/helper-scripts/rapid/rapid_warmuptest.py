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

import sys
import time
from rapid_log import RapidLog
from rapid_test import RapidTest

class WarmupTest(RapidTest):
    """
    Class to manage the warmup testing
    """
    def __init__(self, test_param, gen_machine):
        self.test = test_param
        self.gen_machine = gen_machine

    def run(self):
    # Running at low speed to make sure the ARP messages can get through.
    # If not doing this, the ARP message could be dropped by a switch in overload and then the test will not give proper results
    # Note hoever that if we would run the test steps during a very long time, the ARP would expire in the switch.
    # PROX will send a new ARP request every seconds so chances are very low that they will all fail to get through
        imix = self.test['imix']
        FLOWSIZE = int(self.test['flowsize'])
        WARMUPSPEED = int(self.test['warmupspeed'])
        WARMUPTIME = int(self.test['warmuptime'])
        self.gen_machine.set_generator_speed(WARMUPSPEED)
        self.gen_machine.set_udp_packet_size(imix)
    #    gen_machine['socket'].set_value(gencores,0,56,1,1)
        self.gen_machine.set_flows(FLOWSIZE)
        self.gen_machine.start()
        time.sleep(WARMUPTIME)
        self.gen_machine.stop()
    #    gen_machine['socket'].set_value(gencores,0,56,50,1)
        time.sleep(WARMUPTIME)
        return (True)
