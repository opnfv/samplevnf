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
import copy
from math import ceil
from statistics import mean
from past.utils import old_div
from rapid_log import RapidLog
from rapid_log import bcolors
from rapid_test import RapidTest
inf = float("inf")

class FlowSizeTest(RapidTest):
    """
    Class to manage the flowsizetesting
    """
    def __init__(self, test_param, lat_percentile, runtime, testname,
            environment_file, gen_machine, sut_machine, background_machines):
        super().__init__(test_param, runtime, testname, environment_file)
        self.gen_machine = gen_machine
        self.sut_machine = sut_machine
        self.background_machines = background_machines
        self.test['lat_percentile'] = lat_percentile
        if self.test['test'] == 'TST009test':
            # This test implements some of the testing as defined in
            # https://docbox.etsi.org/ISG/NFV/open/Publications_pdf/Specs-Reports/NFV-TST%20009v3.2.1%20-%20GS%20-%20NFVI_Benchmarks.pdf
            self.test['TST009_n'] = int(ceil(old_div(
                self.test['maxframespersecondallingress'],
                self.test['stepsize'])))
            self.test['TST009'] = True
            self.test['TST009_L'] = 0
            self.test['TST009_R'] = self.test['TST009_n'] - 1
            self.test['TST009_S']= []
            for m in range(0, self.test['TST009_n']):
                self.test['TST009_S'].append((m+1) * self.test['stepsize'])
        elif self.test['test'] == 'fixed_rate':
            for key in['drop_rate_threshold','lat_avg_threshold',
                    'lat_perc_threshold','lat_max_threshold','mis_ordered_threshold']:
                self.test[key] = inf

    def new_speed(self, speed,size,success):
        if self.test['test'] == 'fixed_rate':
            return (self.test['startspeed'])
        elif self.test['test'] == 'increment_till_fail':
            return (speed + self.test['step'])
        elif 'TST009' in self.test.keys():
            if success:
                self.test['TST009_L'] = self.test['TST009_m'] + 1
            else:
                self.test['TST009_R'] = max(self.test['TST009_m'] - 1,
                        self.test['TST009_L'])
            self.test['TST009_m'] = int (old_div((self.test['TST009_L'] +
                self.test['TST009_R']),2))
            return (self.get_percentageof10Gbps(self.test['TST009_S'][self.test['TST009_m']],size))
        else:
            if success:
                self.test['minspeed'] = speed
            else:
                self.test['maxspeed'] = speed
            return (old_div((self.test['minspeed'] + self.test['maxspeed']),2.0))

    def get_start_speed_and_init(self, size):
        if self.test['test'] == 'fixed_rate':
            return (self.test['startspeed'])
        elif self.test['test'] == 'increment_till_fail':
            return (self.test['startspeed'])
        elif 'TST009' in self.test.keys():
            self.test['TST009_L'] = 0
            self.test['TST009_R'] = self.test['TST009_n'] - 1
            self.test['TST009_m'] = int(old_div((self.test['TST009_L'] +
                self.test['TST009_R']), 2))
            return (self.get_percentageof10Gbps(self.test['TST009_S'][self.test['TST009_m']],size))
        else:
            self.test['minspeed'] = 0
            self.test['maxspeed'] = self.test['startspeed'] 
            return (self.test['startspeed'])

    def resolution_achieved(self):
        if self.test['test'] == 'fixed_rate':
            return (True)
        elif 'TST009' in self.test.keys():
            return (self.test['TST009_L'] == self.test['TST009_R'])
        else:
            return ((self.test['maxspeed'] - self.test['minspeed']) <= self.test['accuracy'])

    def warm_up(self):
        # Running at low speed to make sure the ARP messages can get through.
        # If not doing this, the ARP message could be dropped by a switch in overload and then the test will not give proper results
        # Note however that if we would run the test steps during a very long time, the ARP would expire in the switch.
        # PROX will send a new ARP request every seconds so chances are very low that they will all fail to get through
        imix = self.test['warmupimix']
        FLOWSIZE = self.test['warmupflowsize']
        WARMUPSPEED = self.test['warmupspeed']
        WARMUPTIME = self.test['warmuptime']

        if WARMUPTIME == 0:
            RapidLog.info(("Not Warming up"))
            return

        RapidLog.info(("Warming up during {} seconds..., packet size = {},"
            " flows = {}, speed = {}").format(WARMUPTIME, imix, FLOWSIZE,
                WARMUPSPEED))
        self.gen_machine.set_generator_speed(WARMUPSPEED)
        self.set_background_speed(self.background_machines, WARMUPSPEED)
        self.gen_machine.set_udp_packet_size(imix)
        self.set_background_size(self.background_machines, imix)
        if FLOWSIZE:
            _ = self.gen_machine.set_flows(FLOWSIZE)
            self.set_background_flows(self.background_machines, FLOWSIZE)
        self.gen_machine.start()
        self.start_background_traffic(self.background_machines)
        time.sleep(WARMUPTIME)
        self.stop_background_traffic(self.background_machines)
        self.gen_machine.stop()

    def run(self):
        result_details = {'Details': 'Nothing'}
        TestResult = 0
        end_data = {}
        iteration_prefix = {}
        self.warm_up()
        for imix in self.test['imixs']:
            size = mean(imix)
            self.gen_machine.set_udp_packet_size(imix)
            if self.background_machines:
                backgroundinfo = ('{}Running {} x background traffic not '
                    'represented in the table{}').format(bcolors.FLASH,
                            len(self.background_machines),bcolors.ENDC)
            else:
                backgroundinfo = '{}{}'.format(bcolors.FLASH,bcolors.ENDC)
            self.set_background_size(self.background_machines, imix)
            RapidLog.info('+' + '-' * 200 + '+')
            RapidLog.info(("| UDP, {:>5} bytes, different number of flows by "
                "randomizing SRC & DST UDP port. {:128.128}|").
                format(round(size), backgroundinfo))
            RapidLog.info('+' + '-' * 8 + '+' + '-' * 18 + '+' + '-' * 13 +
                    '+' + '-' * 13 + '+' + '-' * 13 + '+' + '-' * 24 + '+' +
                    '-' * 10 + '+' + '-' * 10 + '+' + '-' * 10 + '+' + '-' * 11
                    + '+' + '-' * 11 + '+' + '-' * 11 + '+'  + '-' * 11 +  '+'
                    + '-' * 7 + '+' + '-' * 11 + '+' + '-' * 4 + '+')
            RapidLog.info(('| Flows  | Speed requested  | Gen by core | Sent by'
                ' NIC | Fwrd by SUT | Rec. by core           | Avg. Lat.|{:.0f}'
                ' Pcentil| Max. Lat.|   Sent    |  Received |    Lost   | Total'
                ' Lost|L.Ratio|Mis-ordered|Time').format(self.test['lat_percentile']*100))
            RapidLog.info('+' + '-' * 8 + '+' + '-' * 18 + '+' + '-' * 13 +
                    '+' + '-' * 13 + '+' + '-' * 13 + '+' + '-' * 24 + '+' +
                    '-' * 10 + '+' + '-' * 10 + '+' + '-' * 10 + '+' + '-' * 11
                    + '+' + '-' * 11 + '+' + '-' * 11 + '+'  + '-' * 11 +  '+'
                    + '-' * 7 + '+' + '-' * 11 + '+' + '-' * 4 + '+')
            for flow_number in self.test['flows']:
                attempts = 0
                self.gen_machine.reset_stats()
                if self.sut_machine:
                    self.sut_machine.reset_stats()
                if flow_number != 0:
                    flow_number = self.gen_machine.set_flows(flow_number)
                    self.set_background_flows(self.background_machines, flow_number)
                end_data['speed'] = None
                speed = self.get_start_speed_and_init(size)
                while True:
                    attempts += 1
                    endwarning = False
                    print('{} flows: Measurement ongoing at speed: {}%'.format(
                        str(flow_number), str(round(speed, 2))), end='     \r')
                    sys.stdout.flush()
                    iteration_data = self.run_iteration(
                            float(self.test['runtime']),flow_number,size,speed)
                    if iteration_data['r'] > 1:
                        retry_warning = '{} {:1} retries needed{}'.format(
                                bcolors.WARNING, iteration_data['r'],
                                bcolors.ENDC)
                    else:
                        retry_warning = ''
                    # Drop rate is expressed in percentage. lat_used is a ratio
                    # (0 to 1). The sum of these 2 should be 100%.
                    # If the sum is lower than 95, it means that more than 5%
                    # of the latency measurements where dropped for accuracy
                    # reasons.
                    if (iteration_data['drop_rate'] +
                            iteration_data['lat_used'] * 100) < 95:
                        lat_warning = ('{} Latency accuracy issue?: {:>3.0f}%'
                            '{}').format(bcolors.WARNING,
                                    iteration_data['lat_used'] * 100,
                                    bcolors.ENDC)
                    else:
                        lat_warning = ''
                    iteration_prefix = {'speed' : bcolors.ENDC,
                            'lat_avg' : bcolors.ENDC,
                            'lat_perc' : bcolors.ENDC,
                            'lat_max' : bcolors.ENDC,
                            'abs_drop_rate' : bcolors.ENDC,
                            'mis_ordered' : bcolors.ENDC,
                            'drop_rate' : bcolors.ENDC}
                    if self.test['test'] == 'fixed_rate':
                        end_data = copy.deepcopy(iteration_data)
                        end_prefix = copy.deepcopy(iteration_prefix)
                        if lat_warning or retry_warning:
                            endwarning = '|        | {:177.177} |'.format(
                                    retry_warning + lat_warning)
                        success = True
                        # TestResult = TestResult + iteration_data['pps_rx']
                        # fixed rate testing result is strange: we just report
                        # the pps received
                    # The following if statement is testing if we pass the
                    # success criteria of a certain drop rate, average latency
                    # and maximum latency below the threshold.
                    # The drop rate success can be achieved in 2 ways: either
                    # the drop rate is below a treshold, either we want that no
                    # packet has been lost during the test.
                    # This can be specified by putting 0 in the .test file
                    elif ((iteration_data['drop_rate'] < self.test['drop_rate_threshold']) or (iteration_data['abs_dropped']==self.test['drop_rate_threshold']==0)) and (iteration_data['lat_avg']< self.test['lat_avg_threshold']) and (iteration_data['lat_perc']< self.test['lat_perc_threshold']) and (iteration_data['lat_max'] < self.test['lat_max_threshold'] and iteration_data['mis_ordered'] <= self.test['mis_ordered_threshold']):
                        if (old_div((self.get_pps(speed,size) - iteration_data['pps_tx']),self.get_pps(speed,size)))>0.01:
                            iteration_prefix['speed'] = bcolors.WARNING
                            if iteration_data['abs_tx_fail'] > 0:
                                gen_warning = bcolors.WARNING + ' Network limit?: requesting {:<.3f} Mpps and getting {:<.3f} Mpps - {} failed to be transmitted'.format(self.get_pps(speed,size), iteration_data['pps_tx'], iteration_data['abs_tx_fail']) + bcolors.ENDC
                            else:
                                gen_warning = bcolors.WARNING + ' Generator limit?: requesting {:<.3f} Mpps and getting {:<.3f} Mpps'.format(self.get_pps(speed,size), iteration_data['pps_tx']) + bcolors.ENDC
                        else:
                            iteration_prefix['speed'] = bcolors.ENDC
                            gen_warning = ''
                        end_data = copy.deepcopy(iteration_data)
                        end_prefix = copy.deepcopy(iteration_prefix)
                        if lat_warning or gen_warning or retry_warning:
                            endwarning = '|        | {:186.186} |'.format(retry_warning + lat_warning + gen_warning)
                        success = True
                        success_message=' SUCCESS'
                        RapidLog.debug(self.report_result(-attempts, size,
                            iteration_data, iteration_prefix) + success_message +
                            retry_warning + lat_warning + gen_warning)
                    else:
                        success_message=' FAILED'
                        if ((iteration_data['abs_dropped']>0) and (self.test['drop_rate_threshold'] ==0)):
                            iteration_prefix['abs_drop_rate'] = bcolors.FAIL
                        if (iteration_data['drop_rate'] <= self.test['drop_rate_threshold']):
                            iteration_prefix['drop_rate'] = bcolors.ENDC
                        else:
                            iteration_prefix['drop_rate'] = bcolors.FAIL
                        if (iteration_data['lat_avg']< self.test['lat_avg_threshold']):
                            iteration_prefix['lat_avg'] = bcolors.ENDC
                        else:
                            iteration_prefix['lat_avg'] = bcolors.FAIL
                        if (iteration_data['lat_perc']< self.test['lat_perc_threshold']):
                            iteration_prefix['lat_perc'] = bcolors.ENDC
                        else:
                            iteration_prefix['lat_perc'] = bcolors.FAIL
                        if (iteration_data['lat_max']< self.test['lat_max_threshold']):
                            iteration_prefix['lat_max'] = bcolors.ENDC
                        else:
                            iteration_prefix['lat_max'] = bcolors.FAIL
                        if ((old_div((self.get_pps(speed,size) - iteration_data['pps_tx']),self.get_pps(speed,size)))<0.001):
                            iteration_prefix['speed'] = bcolors.ENDC
                        else:
                            iteration_prefix['speed'] = bcolors.FAIL
                        if (iteration_data['mis_ordered']< self.test['mis_ordered_threshold']):
                            iteration_prefix['mis_ordered'] = bcolors.ENDC
                        else:
                            iteration_prefix['mis_ordered'] = bcolors.FAIL

                        success = False 
                        RapidLog.debug(self.report_result(-attempts, size,
                            iteration_data, iteration_prefix) +
                            success_message + retry_warning + lat_warning)
                    speed = self.new_speed(speed, size, success)
                    if self.test['test'] == 'increment_till_fail':
                        if not success:
                            break
                    elif self.resolution_achieved():
                        break
                if end_data['speed'] is None:
                    end_data = iteration_data
                    end_prefix = iteration_prefix
                    RapidLog.info('|{:>7} | {:<177} |'.format("FAILED","Speed 0 or close to 0, data for last failed step below:"))
                RapidLog.info(self.report_result(flow_number, size,
                    end_data, end_prefix))
                if end_data['avg_bg_rate']:
                    tot_avg_rx_rate = end_data['pps_rx'] + (end_data['avg_bg_rate'] * len(self.background_machines))
                    endtotaltrafficrate = '|        | Total amount of traffic received by all generators during this test: {:>4.3f} Gb/s {:7.3f} Mpps {} |'.format(RapidTest.get_speed(tot_avg_rx_rate,size) , tot_avg_rx_rate, ' '*84)
                    RapidLog.info (endtotaltrafficrate)
                if endwarning:
                    RapidLog.info (endwarning)
                if self.test['test'] != 'fixed_rate':
                    TestResult = TestResult + end_data['pps_rx']
                    end_data['test'] = self.test['testname']
                    end_data['environment_file'] = self.test['environment_file']
                    end_data['Flows'] = flow_number
                    end_data['Size'] = size
                    end_data['RequestedSpeed'] = RapidTest.get_pps(end_data['speed'] ,size)
                    result_details = self.post_data(end_data)
                    RapidLog.debug(result_details)
                RapidLog.info('+' + '-' * 8 + '+' + '-' * 18 + '+' + '-' * 13 +
                    '+' + '-' * 13 + '+' + '-' * 13 + '+' + '-' * 24 + '+' +
                    '-' * 10 + '+' + '-' * 10 + '+' + '-' * 10 + '+' + '-' * 11
                    + '+' + '-' * 11 + '+' + '-' * 11 + '+'  + '-' * 11 +  '+'
                    + '+' + '-' * 11 + '+'
                    + '-' * 7 + '+' + '-' * 4 + '+')
        return (TestResult, result_details)
