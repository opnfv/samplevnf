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
from rapid_log import bcolors
from rapid_test import RapidTest
from statistics import mean

class ImpairTest(RapidTest):
    """
    Class to manage the impair testing
    """
    def __init__(self, test_param, lat_percentile, runtime, testname,
            environment_file, gen_machine, sut_machine, background_machines):
        super().__init__(test_param, runtime, testname, environment_file)
        self.gen_machine = gen_machine
        self.sut_machine = sut_machine
        self.background_machines = background_machines
        self.test['lat_percentile'] = lat_percentile

    def run(self):
        result_details = {'Details': 'Nothing'}
        imix = self.test['imix']
        size = mean (imix)
        flow_number = self.test['flowsize']
        attempts = self.test['steps']
        self.gen_machine.set_udp_packet_size(imix)
        flow_number = self.gen_machine.set_flows(flow_number)
        self.gen_machine.start_latency_cores()
        RapidLog.info('+' + '-' * 188 + '+')
        RapidLog.info(("| Generator is sending UDP ({:>5} flow) packets ({:>5}"
            " bytes) to SUT via GW dropping and delaying packets. SUT sends "
            "packets back.{:>60}").format(flow_number,round(size),'|'))
        RapidLog.info('+' + '-' * 8 + '+' + '-' * 18 + '+' + '-' * 13 +
            '+' + '-' * 13 + '+' + '-' * 13 + '+' + '-' * 24 + '+' +
            '-' * 10 + '+' + '-' * 10 + '+' + '-' * 10 + '+' + '-' * 11
            + '+' + '-' * 11 + '+' + '-' * 11 + '+'  + '-' * 11 +  '+'
            + '-' * 7 + '+' + '-' * 4 + '+')
        RapidLog.info(('| Test   | Speed requested  | Gen by core | Sent by NIC'
            ' | Fwrd by SUT | Rec. by core           | Avg. Lat.|{:.0f} Pcentil'
            '| Max. Lat.|   Sent    |  Received |    Lost   | Total Lost|'
            'L.Ratio|Time|').format(self.test['lat_percentile']*100))
        RapidLog.info('+' + '-' * 8 + '+' + '-' * 18 + '+' + '-' * 13 +
            '+' + '-' * 13 + '+' + '-' * 13 + '+' + '-' * 24 + '+' +
            '-' * 10 + '+' + '-' * 10 + '+' + '-' * 10 + '+' + '-' * 11
            + '+' + '-' * 11 + '+' + '-' * 11 + '+'  + '-' * 11 +  '+'
            + '-' * 7 + '+' + '-' * 4 + '+')
        speed = self.test['startspeed']
        self.gen_machine.set_generator_speed(speed)
        while attempts:
            attempts -= 1
            print('Measurement ongoing at speed: ' + str(round(speed,2)) + '%      ',end='\r')
            sys.stdout.flush()
            time.sleep(1)
            # Get statistics now that the generation is stable and NO ARP messages any more
            iteration_data = self.run_iteration(float(self.test['runtime']),flow_number,size,speed)
            iteration_data['speed'] = speed
            # Drop rate is expressed in percentage. lat_used is a ratio (0 to 1). The sum of these 2 should be 100%.
            # If the sum is lower than 95, it means that more than 5% of the latency measurements where dropped for accuracy reasons.
            if (iteration_data['drop_rate'] +
                    iteration_data['lat_used'] * 100) < 95:
                lat_warning = ('{} Latency accuracy issue?: {:>3.0f}%'
                    '{}').format(bcolors.WARNING,
                            iteration_data['lat_used']*100, bcolors.ENDC)
            else:
                lat_warning = ''
            iteration_prefix = {'speed' : '',
                    'lat_avg' : '',
                    'lat_perc' : '',
                    'lat_max' : '',
                    'abs_drop_rate' : '',
                    'drop_rate' : ''}
            RapidLog.info(self.report_result(attempts, size, iteration_data,
                iteration_prefix))
            iteration_data['test'] = self.test['testname']
            iteration_data['environment_file'] = self.test['environment_file']
            iteration_data['Flows'] = flow_number
            iteration_data['Size'] = size
            iteration_data['RequestedSpeed'] = RapidTest.get_pps(
                    iteration_data['speed'] ,size)
            result_details = self.post_data(iteration_data)
            RapidLog.debug(result_details)
        RapidLog.info('+' + '-' * 8 + '+' + '-' * 18 + '+' + '-' * 13 +
            '+' + '-' * 13 + '+' + '-' * 13 + '+' + '-' * 24 + '+' +
            '-' * 10 + '+' + '-' * 10 + '+' + '-' * 10 + '+' + '-' * 11
            + '+' + '-' * 11 + '+' + '-' * 11 + '+'  + '-' * 11 +  '+'
            + '-' * 7 + '+' + '-' * 4 + '+')
        self.gen_machine.stop_latency_cores()
        return (True, result_details)
