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

import yaml
import requests
import time
import os
import copy
from past.utils import old_div
from rapid_log import RapidLog
from rapid_log import bcolors
inf = float("inf")
from datetime import datetime as dt

_CURR_DIR = os.path.dirname(os.path.realpath(__file__))

class RapidTest(object):
    """
    Class to manage the testing
    """
    def __init__(self, test_param, runtime, testname, environment_file ):
        self.test = test_param
        self.test['runtime'] = runtime
        self.test['testname'] = testname
        self.test['environment_file'] = environment_file
        if 'maxr' not in self.test.keys():
            self.test['maxr'] = 1
        if 'maxz' not in self.test.keys():
            self.test['maxz'] = inf
        with open(os.path.join(_CURR_DIR,'format.yaml')) as f:
            self.data_format = yaml.load(f, Loader=yaml.FullLoader)

    @staticmethod
    def get_percentageof10Gbps(pps_speed,size):
        # speed is given in pps, returning % of 10Gb/s
        # 12 bytes is the inter packet gap 
        # pre-amble is 7 bytes
        # SFD (start of frame delimiter) is 1 byte
        # Total of 20 bytes overhead per packet
        return (pps_speed / 1000000.0 * 0.08 * (size+20))

    @staticmethod
    def get_pps(speed,size):
        # speed is given in % of 10Gb/s, returning Mpps
        # 12 bytes is the inter packet gap 
        # pre-amble is 7 bytes
        # SFD (start of frame delimiter) is 1 byte
        # Total of 20 bytes overhead per packet
        return (speed * 100.0 / (8*(size+20)))

    @staticmethod
    def get_speed(packet_speed,size):
        # return speed in Gb/s
        # 12 bytes is the inter packet gap 
        # pre-amble is 7 bytes
        # SFD (start of frame delimiter) is 1 byte
        # Total of 20 bytes overhead per packet
        return (packet_speed / 1000.0 * (8*(size+20)))

    @staticmethod
    def set_background_flows(background_machines, number_of_flows):
        for machine in background_machines:
            _ = machine.set_flows(number_of_flows)

    @staticmethod
    def set_background_speed(background_machines, speed):
        for machine in background_machines:
            machine.set_generator_speed(speed)

    @staticmethod
    def set_background_size(background_machines, imix):
        # imixs is a list of packet sizes
        for machine in background_machines:
            machine.set_udp_packet_size(imix)

    @staticmethod
    def start_background_traffic(background_machines):
        for machine in background_machines:
            machine.start()

    @staticmethod
    def stop_background_traffic(background_machines):
        for machine in background_machines:
            machine.stop()

    @staticmethod
    def parse_data_format_dict(data_format, variables):
        for k, v in data_format.items():
            if type(v) is dict:
                RapidTest.parse_data_format_dict(v, variables)
            else:
                if v in variables.keys():
                    data_format[k] = variables[v]

    def post_data(self, variables):
        test_type = type(self).__name__
        var = copy.deepcopy(self.data_format)
        self.parse_data_format_dict(var, variables)
        if var.keys() >= {'URL', test_type, 'Format'}:
            URL=''
            for value in var['URL'].values():
                URL = URL + value
            HEADERS = {'X-Requested-With': 'Python requests', 'Content-type': 'application/rapid'}
            if var['Format'] == 'PushGateway':
                data = "\n".join("{} {}".format(k, v) for k, v in var[test_type].items()) + "\n"
                response = requests.post(url=URL, data=data,headers=HEADERS)
            elif var['Format'] == 'Xtesting':
                data = var[test_type]
                response = requests.post(url=URL, json=data)
            if (response.status_code >= 300):
                RapidLog.info('Cannot send metrics to {}'.format(URL))
                RapidLog.info(data)
        return (var[test_type])

    @staticmethod
    def report_result(flow_number, size, data, prefix):
        if flow_number < 0:
            flow_number_str = '| ({:>4}) |'.format(abs(flow_number))
        else:
            flow_number_str = '|{:>7} |'.format(flow_number)
        if data['pps_req_tx'] is None:
            pps_req_tx_str = '{0: >14}'.format('   NA     |')
        else:
            pps_req_tx_str = '{:>7.3f} Mpps |'.format(data['pps_req_tx'])
        if data['pps_tx'] is None:
            pps_tx_str = '{0: >14}'.format('   NA     |')
        else:
            pps_tx_str = '{:>7.3f} Mpps |'.format(data['pps_tx']) 
        if data['pps_sut_tx'] is None:
            pps_sut_tx_str = '{0: >14}'.format('   NA     |')
        else:
            pps_sut_tx_str = '{:>7.3f} Mpps |'.format(data['pps_sut_tx'])
        if data['pps_rx'] is None:
            pps_rx_str = '{0: >25}'.format('NA        |')
        else:
            pps_rx_str = bcolors.OKBLUE + '{:>4.1f} Gb/s |{:7.3f} Mpps {}|'.format(
                    RapidTest.get_speed(data['pps_rx'],size),data['pps_rx'],bcolors.ENDC)
        if data['abs_dropped'] is None:
            tot_drop_str = ' |       NA  | '
        else:
            tot_drop_str = ' | {:>9.0f} | '.format(data['abs_dropped'])
        if data['lat_perc'] is None:
            lat_perc_str = '|{:^10.10}|'.format('NA')
        elif data['lat_perc_max'] == True:
            lat_perc_str = '|>{}{:>5.0f} us{} |'.format(prefix['lat_perc'],
                    float(data['lat_perc']), bcolors.ENDC) 
        else:
            lat_perc_str = '| {}{:>5.0f} us{} |'.format(prefix['lat_perc'],
                    float(data['lat_perc']), bcolors.ENDC) 
        if data['actual_duration'] is None:
            elapsed_time_str = ' NA |'
        else:
            elapsed_time_str = '{:>3.0f} |'.format(data['actual_duration'])
        if data['mis_ordered'] is None:
            mis_ordered_str = '    NA   '
        else:
            mis_ordered_str = '{:>9.0f} '.format(data['mis_ordered'])
        return(flow_number_str + '{:>5.1f}'.format(data['speed']) + '% ' + prefix['speed']
                + '{:>6.3f}'.format(RapidTest.get_pps(data['speed'],size)) + ' Mpps|' +
                pps_req_tx_str + pps_tx_str + bcolors.ENDC + pps_sut_tx_str +
                pps_rx_str + prefix['lat_avg'] + ' {:>6.0f}'.format(data['lat_avg']) +
                ' us' + lat_perc_str +prefix['lat_max']+'{:>6.0f}'.format(data['lat_max'])
                + ' us | ' + '{:>9.0f}'.format(data['abs_tx']) + ' | {:>9.0f}'.format(data['abs_rx']) +
                ' | '+ prefix['abs_drop_rate']+ '{:>9.0f}'.format(data['abs_tx']-data['abs_rx']) +
                tot_drop_str + prefix['drop_rate'] +
                '{:>5.2f}'.format(100*old_div(float(data['abs_tx']-data['abs_rx']),data['abs_tx'])) + ' |' + 
                prefix['mis_ordered'] + mis_ordered_str + bcolors.ENDC +
                ' |' + elapsed_time_str)

    def run_iteration(self, requested_duration, flow_number, size, speed):
        BUCKET_SIZE_EXP = self.gen_machine.bucket_size_exp
        sleep_time = self.test['sleep_time']
        LAT_PERCENTILE = self.test['lat_percentile']
        iteration_data= {}
        time_loop_data= {}
        iteration_data['r'] = 0;

        while (iteration_data['r'] < self.test['maxr']):
            self.gen_machine.start_latency_cores()
            time.sleep(sleep_time)
            # Sleep_time is needed to be able to do accurate measurements to check for packet loss. We need to make this time large enough so that we do not take the first measurement while some packets from the previous tests migth still be in flight
            t1_rx, t1_non_dp_rx, t1_tx, t1_non_dp_tx, t1_drop, t1_tx_fail, t1_tsc, abs_tsc_hz = self.gen_machine.core_stats()
            t1_dp_rx = t1_rx - t1_non_dp_rx
            t1_dp_tx = t1_tx - t1_non_dp_tx
            self.gen_machine.set_generator_speed(0)
            self.gen_machine.start_gen_cores()
            self.set_background_speed(self.background_machines, 0)
            self.start_background_traffic(self.background_machines)
            if 'ramp_step' in self.test.keys():
                ramp_speed = self.test['ramp_step']
            else:
                ramp_speed = speed
            while ramp_speed < speed:
                self.gen_machine.set_generator_speed(ramp_speed)
                self.set_background_speed(self.background_machines, ramp_speed)
                time.sleep(2)
                ramp_speed = ramp_speed + self.test['ramp_step']
            self.gen_machine.set_generator_speed(speed)
            self.set_background_speed(self.background_machines, speed)
            iteration_data['speed'] = speed
            time_loop_data['speed'] = speed
            time.sleep(2) ## Needs to be 2 seconds since this 1 sec is the time that PROX uses to refresh the stats. Note that this can be changed in PROX!! Don't do it.
            start_bg_gen_stats = []
            for bg_gen_machine in self.background_machines:
                bg_rx, bg_non_dp_rx, bg_tx, bg_non_dp_tx, _, _, bg_tsc, _ = bg_gen_machine.core_stats()
                bg_gen_stat = {
                        "bg_dp_rx" : bg_rx - bg_non_dp_rx,
                        "bg_dp_tx" : bg_tx - bg_non_dp_tx,
                        "bg_tsc"   : bg_tsc
                        }
                start_bg_gen_stats.append(dict(bg_gen_stat))
            if self.sut_machine!= None:
                t2_sut_rx, t2_sut_non_dp_rx, t2_sut_tx, t2_sut_non_dp_tx, t2_sut_drop, t2_sut_tx_fail, t2_sut_tsc, sut_tsc_hz = self.sut_machine.core_stats()
            t2_rx, t2_non_dp_rx, t2_tx, t2_non_dp_tx, t2_drop, t2_tx_fail, t2_tsc, tsc_hz = self.gen_machine.core_stats()
            tx = t2_tx - t1_tx
            iteration_data['abs_tx'] =  tx - (t2_non_dp_tx - t1_non_dp_tx )
            iteration_data['abs_rx'] =  t2_rx - t1_rx - (t2_non_dp_rx - t1_non_dp_rx) 
            iteration_data['abs_dropped'] = iteration_data['abs_tx'] - iteration_data['abs_rx']
            if tx == 0:
                RapidLog.critical("TX = 0. Test interrupted since no packet has been sent.")
            if iteration_data['abs_tx'] == 0:
                RapidLog.critical("Only non-dataplane packets (e.g. ARP) sent. Test interrupted since no packet has been sent.")
            # Ask PROX to calibrate the bucket size once we have a PROX function to do this.
            # Measure latency statistics per second
            iteration_data.update(self.gen_machine.lat_stats())
            t2_lat_tsc = iteration_data['lat_tsc']
            sample_count = 0
            for sample_percentile, bucket in enumerate(iteration_data['buckets'],start=1):
                sample_count += bucket
                if sample_count > sum(iteration_data['buckets']) * LAT_PERCENTILE:
                    break
            iteration_data['lat_perc_max'] = (sample_percentile == len(iteration_data['buckets']))
            iteration_data['bucket_size'] = float(2 ** BUCKET_SIZE_EXP) / (old_div(float(iteration_data['lat_hz']),float(10**6)))
            time_loop_data['bucket_size'] = iteration_data['bucket_size']
            iteration_data['lat_perc'] = sample_percentile * iteration_data['bucket_size'] 
            if self.test['test'] == 'fixed_rate':
                iteration_data['pps_req_tx'] = None
                iteration_data['pps_tx'] = None
                iteration_data['pps_sut_tx'] = None
                iteration_data['pps_rx'] = None
                iteration_data['lat_perc'] = None
                iteration_data['actual_duration'] = None
                iteration_prefix = {'speed' : '',
                        'lat_avg' : '',
                        'lat_perc' : '',
                        'lat_max' : '',
                        'abs_drop_rate' : '',
                        'mis_ordered' : '',
                        'drop_rate' : ''}
                RapidLog.info(self.report_result(flow_number, size,
                    iteration_data, iteration_prefix ))
            tot_rx = tot_non_dp_rx = tot_tx = tot_non_dp_tx = tot_drop = 0
            iteration_data['lat_avg'] = iteration_data['lat_used'] = 0
            tot_lat_measurement_duration = float(0)
            iteration_data['actual_duration'] = float(0)
            tot_sut_core_measurement_duration = float(0)
            tot_sut_rx = tot_sut_non_dp_rx = tot_sut_tx = tot_sut_non_dp_tx = tot_sut_drop = tot_sut_tx_fail = tot_sut_tsc = 0
            lat_avail = core_avail = sut_avail = False
            while (iteration_data['actual_duration'] - float(requested_duration) <= 0.1) or (tot_lat_measurement_duration - float(requested_duration) <= 0.1):
                time.sleep(0.5)
                time_loop_data.update(self.gen_machine.lat_stats())
                # Get statistics after some execution time
                if time_loop_data['lat_tsc'] != t2_lat_tsc:
                    single_lat_measurement_duration = (time_loop_data['lat_tsc'] - t2_lat_tsc) * 1.0 / time_loop_data['lat_hz']  # time difference between the 2 measurements, expressed in seconds.
                    # A second has passed in between to lat_stats requests. Hence we need to process the results
                    tot_lat_measurement_duration = tot_lat_measurement_duration + single_lat_measurement_duration
                    if iteration_data['lat_min'] > time_loop_data['lat_min']:
                        iteration_data['lat_min'] = time_loop_data['lat_min']
                    if iteration_data['lat_max'] < time_loop_data['lat_max']:
                        iteration_data['lat_max'] = time_loop_data['lat_max']
                    iteration_data['lat_avg'] = iteration_data['lat_avg'] + time_loop_data['lat_avg'] * single_lat_measurement_duration # Sometimes, There is more than 1 second between 2 lat_stats. Hence we will take the latest measurement
                    iteration_data['lat_used'] = iteration_data['lat_used'] + time_loop_data['lat_used'] * single_lat_measurement_duration # and give it more weigth.
                    sample_count = 0
                    for sample_percentile, bucket in enumerate(time_loop_data['buckets'],start=1):
                        sample_count += bucket
                        if sample_count > sum(time_loop_data['buckets']) * LAT_PERCENTILE:
                            break
                    time_loop_data['lat_perc_max'] = (sample_percentile == len(time_loop_data['buckets']))
                    time_loop_data['lat_perc'] = sample_percentile *  iteration_data['bucket_size']
                    iteration_data['buckets'] = [iteration_data['buckets'][i] + time_loop_data['buckets'][i] for i in range(len(iteration_data['buckets']))]
                    t2_lat_tsc = time_loop_data['lat_tsc'] 
                    lat_avail = True
                t3_rx, t3_non_dp_rx, t3_tx, t3_non_dp_tx, t3_drop, t3_tx_fail, t3_tsc, tsc_hz = self.gen_machine.core_stats()
                if t3_tsc != t2_tsc:
                    time_loop_data['actual_duration'] = (t3_tsc - t2_tsc) * 1.0 / tsc_hz  # time difference between the 2 measurements, expressed in seconds.
                    iteration_data['actual_duration'] = iteration_data['actual_duration'] + time_loop_data['actual_duration']
                    delta_rx = t3_rx - t2_rx
                    tot_rx += delta_rx
                    delta_non_dp_rx = t3_non_dp_rx - t2_non_dp_rx
                    tot_non_dp_rx += delta_non_dp_rx
                    delta_tx = t3_tx - t2_tx
                    tot_tx += delta_tx
                    delta_non_dp_tx = t3_non_dp_tx - t2_non_dp_tx
                    tot_non_dp_tx += delta_non_dp_tx
                    delta_dp_tx = delta_tx -delta_non_dp_tx
                    delta_dp_rx = delta_rx -delta_non_dp_rx
                    time_loop_data['abs_dropped'] = delta_dp_tx - delta_dp_rx
                    iteration_data['abs_dropped'] += time_loop_data['abs_dropped']
                    delta_drop = t3_drop - t2_drop
                    tot_drop += delta_drop
                    t2_rx, t2_non_dp_rx, t2_tx, t2_non_dp_tx, t2_drop, t2_tx_fail, t2_tsc = t3_rx, t3_non_dp_rx, t3_tx, t3_non_dp_tx, t3_drop, t3_tx_fail, t3_tsc
                    core_avail = True
                if self.sut_machine!=None:
                    t3_sut_rx, t3_sut_non_dp_rx, t3_sut_tx, t3_sut_non_dp_tx, t3_sut_drop, t3_sut_tx_fail, t3_sut_tsc, sut_tsc_hz = self.sut_machine.core_stats()
                    if t3_sut_tsc != t2_sut_tsc:
                        single_sut_core_measurement_duration = (t3_sut_tsc - t2_sut_tsc) * 1.0 / sut_tsc_hz  # time difference between the 2 measurements, expressed in seconds.
                        tot_sut_core_measurement_duration = tot_sut_core_measurement_duration + single_sut_core_measurement_duration
                        tot_sut_rx += t3_sut_rx - t2_sut_rx
                        tot_sut_non_dp_rx += t3_sut_non_dp_rx - t2_sut_non_dp_rx
                        delta_sut_tx = t3_sut_tx - t2_sut_tx
                        tot_sut_tx += delta_sut_tx
                        delta_sut_non_dp_tx = t3_sut_non_dp_tx - t2_sut_non_dp_tx
                        tot_sut_non_dp_tx += delta_sut_non_dp_tx 
                        t2_sut_rx, t2_sut_non_dp_rx, t2_sut_tx, t2_sut_non_dp_tx, t2_sut_drop, t2_sut_tx_fail, t2_sut_tsc = t3_sut_rx, t3_sut_non_dp_rx, t3_sut_tx, t3_sut_non_dp_tx, t3_sut_drop, t3_sut_tx_fail, t3_sut_tsc
                        sut_avail = True
                if self.test['test'] == 'fixed_rate':
                    if lat_avail == core_avail == True:
                        lat_avail = core_avail = False
                        time_loop_data['pps_req_tx'] = (delta_tx + delta_drop - delta_rx)/time_loop_data['actual_duration']/1000000
                        time_loop_data['pps_tx'] = delta_tx/time_loop_data['actual_duration']/1000000
                        if self.sut_machine != None and sut_avail:
                            time_loop_data['pps_sut_tx'] = delta_sut_tx/single_sut_core_measurement_duration/1000000
                            sut_avail = False
                        else:
                            time_loop_data['pps_sut_tx'] = None
                        time_loop_data['pps_rx'] = delta_rx/time_loop_data['actual_duration']/1000000
                        time_loop_data['abs_tx'] = delta_dp_tx
                        time_loop_data['abs_rx'] = delta_dp_rx
                        time_loop_prefix = {'speed' : '',
                                'lat_avg' : '',
                                'lat_perc' : '',
                                'lat_max' : '',
                                'abs_drop_rate' : '',
                                'mis_ordered' : '',
                                'drop_rate' : ''}
                        RapidLog.info(self.report_result(flow_number, size, time_loop_data,
                            time_loop_prefix))
                        time_loop_data['test'] = self.test['testname']
                        time_loop_data['environment_file'] = self.test['environment_file']
                        time_loop_data['Flows'] = flow_number
                        time_loop_data['Size'] = size
                        time_loop_data['RequestedSpeed'] = RapidTest.get_pps(speed, size)
                        _ = self.post_data(time_loop_data)
            end_bg_gen_stats = []
            for bg_gen_machine in self.background_machines:
                bg_rx, bg_non_dp_rx, bg_tx, bg_non_dp_tx, _, _, bg_tsc, bg_hz = bg_gen_machine.core_stats()
                bg_gen_stat = {"bg_dp_rx" : bg_rx - bg_non_dp_rx,
                        "bg_dp_tx" : bg_tx - bg_non_dp_tx,
                        "bg_tsc"   : bg_tsc,
                        "bg_hz"    : bg_hz
                        }
                end_bg_gen_stats.append(dict(bg_gen_stat))
            self.stop_background_traffic(self.background_machines)
            i = 0
            bg_rates =[]
            while i < len(end_bg_gen_stats):
                bg_rates.append(0.000001*(end_bg_gen_stats[i]['bg_dp_rx'] -
                    start_bg_gen_stats[i]['bg_dp_rx']) / ((end_bg_gen_stats[i]['bg_tsc'] -
                    start_bg_gen_stats[i]['bg_tsc']) * 1.0 / end_bg_gen_stats[i]['bg_hz']))
                i += 1
            if len(bg_rates):
                iteration_data['avg_bg_rate'] = sum(bg_rates) / len(bg_rates)
                RapidLog.debug('Average Background traffic rate: {:>7.3f} Mpps'.format(iteration_data['avg_bg_rate']))
            else:
                iteration_data['avg_bg_rate'] = None
            #Stop generating
            self.gen_machine.stop_gen_cores()
            time.sleep(3.5)
            self.gen_machine.stop_latency_cores()
            iteration_data['r'] += 1
            iteration_data['lat_avg'] = old_div(iteration_data['lat_avg'], float(tot_lat_measurement_duration))
            iteration_data['lat_used'] = old_div(iteration_data['lat_used'], float(tot_lat_measurement_duration))
            t4_tsc = t2_tsc
            while t4_tsc == t2_tsc:
                t4_rx, t4_non_dp_rx, t4_tx, t4_non_dp_tx, t4_drop, t4_tx_fail, t4_tsc, abs_tsc_hz = self.gen_machine.core_stats()
            if self.test['test'] == 'fixed_rate':
                iteration_data['lat_tsc'] = t2_lat_tsc
                while iteration_data['lat_tsc'] == t2_lat_tsc:
                    iteration_data.update(self.gen_machine.lat_stats())
                sample_count = 0
                for percentile, bucket in enumerate(iteration_data['buckets'],start=1):
                    sample_count += bucket
                    if sample_count > sum(iteration_data['buckets']) * LAT_PERCENTILE:
                        break
                iteration_data['lat_perc_max'] = (percentile == len(iteration_data['buckets']))
                iteration_data['lat_perc'] = percentile *  iteration_data['bucket_size']
                delta_rx = t4_rx - t2_rx
                delta_non_dp_rx = t4_non_dp_rx - t2_non_dp_rx
                delta_tx = t4_tx - t2_tx
                delta_non_dp_tx = t4_non_dp_tx - t2_non_dp_tx
                delta_dp_tx = delta_tx -delta_non_dp_tx
                delta_dp_rx = delta_rx -delta_non_dp_rx
                iteration_data['abs_tx'] = delta_dp_tx
                iteration_data['abs_rx'] = delta_dp_rx
                iteration_data['abs_dropped'] += delta_dp_tx - delta_dp_rx
                iteration_data['pps_req_tx'] = None
                iteration_data['pps_tx'] = None
                iteration_data['pps_sut_tx'] = None
                iteration_data['drop_rate'] = 100.0*(iteration_data['abs_tx']-iteration_data['abs_rx'])/iteration_data['abs_tx']
                iteration_data['actual_duration'] = None
                break ## Not really needed since the while loop will stop when evaluating the value of r
            else:
                sample_count = 0
                for percentile, bucket in enumerate(iteration_data['buckets'],start=1):
                    sample_count += bucket
                    if sample_count > sum(iteration_data['buckets']) * LAT_PERCENTILE:
                        break
                iteration_data['lat_perc_max'] = (percentile == len(iteration_data['buckets']))
                iteration_data['lat_perc'] = percentile *  iteration_data['bucket_size']
                iteration_data['pps_req_tx'] = (tot_tx + tot_drop - tot_rx)/iteration_data['actual_duration']/1000000.0 # tot_drop is all packets dropped by all tasks. This includes packets dropped at the generator task + packets dropped by the nop task. In steady state, this equals to the number of packets received by this VM
                iteration_data['pps_tx'] = tot_tx/iteration_data['actual_duration']/1000000.0 # tot_tx is all generated packets actually accepted by the interface
                iteration_data['pps_rx'] = tot_rx/iteration_data['actual_duration']/1000000.0 # tot_rx is all packets received by the nop task = all packets received in the gen VM
                if self.sut_machine != None and sut_avail:
                    iteration_data['pps_sut_tx'] = tot_sut_tx / tot_sut_core_measurement_duration / 1000000.0
                else:
                    iteration_data['pps_sut_tx'] = None
                iteration_data['abs_tx'] = (t4_tx - t1_tx) - (t4_non_dp_tx - t1_non_dp_tx)
                iteration_data['abs_rx'] = (t4_rx - t1_rx) - (t4_non_dp_rx - t1_non_dp_rx)
                iteration_data['abs_dropped'] = iteration_data['abs_tx'] - iteration_data['abs_rx']
                iteration_data['drop_rate'] = 100.0*iteration_data['abs_dropped']/iteration_data['abs_tx']
                if ((iteration_data['drop_rate'] < self.test['drop_rate_threshold']) or (iteration_data['abs_dropped'] == self.test['drop_rate_threshold'] ==0) or (iteration_data['abs_dropped'] > self.test['maxz'])):
                    break
            self.gen_machine.stop_latency_cores()
        iteration_data['abs_tx_fail'] = t4_tx_fail - t1_tx_fail
        return (iteration_data)
