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

class ImpairTest(RapidTest):
    """
    Class to manage the impair testing
    """
    def __init__(self, test_param, lat_percentile, runtime, pushgateway,
            environment_file, gen_machine):
        self.test = test_param
        self.gen_machine = gen_machine
        self.sut_machine = sut_machine
        self.test['lat_percentile'] = lat_percentile
        self.test['runtime'] = runtime
        self.test['pushgateway'] = pushgateway
        self.test['environment_file'] = environment_file

    def run(self):
    #    fieldnames = ['Flows','PacketSize','RequestedPPS','GeneratedPPS','SentPPS','ForwardedPPS','ReceivedPPS','AvgLatencyUSEC','MaxLatencyUSEC','Dropped','DropRate']
    #    writer = csv.DictWriter(data_csv_file, fieldnames=fieldnames)
    #    writer.writeheader()
        imix = self.test['imix']
        size = mean (imix)
        flow_number = self.test['flowsize']
        RapidLog.info("+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+")
        RapidLog.info("| Generator is sending UDP ("+'{:>5}'.format(flow_number)+" flow) packets ("+ '{:>5}'.format(size) +" bytes) to SUT via GW dropping and delaying packets. SUT sends packets back. Use ctrl-c to stop the test    |")
        RapidLog.info("+--------+--------------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+------------+")
        RapidLog.info("| Test   |  Speed requested   | Sent to NIC    |  Sent by Gen   | Forward by SUT |  Rec. by Gen   |  Avg. Latency  |  Max. Latency  |  Packets Lost  | Loss Ratio |")
        RapidLog.info("+--------+--------------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+------------+")
        attempts = 0
        self.gen_machine.set_udp_packet_size(imix)
        self.gen_machine.set_flows(flow_number)
        self.gen_machine.start_latency_cores()
        speed = self.test['startspeed']
        self.gen_machine.set_generator_speed(speed)
        while True:
            attempts += 1
            print('Measurement ongoing at speed: ' + str(round(speed,2)) + '%      ',end='\r')
            sys.stdout.flush()
            time.sleep(1)
            # Get statistics now that the generation is stable and NO ARP messages any more
            pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx,lat_avg, lat_perc, lat_perc_max, lat_max, abs_dropped, abs_tx_fail, abs_tx, lat_min, lat_used, r, actual_duration = run_iteration(float(self.test['runtime']),flow_number,size,speed)
            drop_rate = 100.0*abs_dropped/abs_tx
            if lat_used < 0.95:
                lat_warning = bcolors.FAIL + ' Potential latency accuracy problem: {:>3.0f}%'.format(lat_used*100) +  bcolors.ENDC
            else:
                lat_warning = ''
            RapidLog.info('|{:>7}'.format(str(attempts))+" | " + '{:>5.1f}'.format(speed) + '% ' +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps | '+ '{:>9.3f}'.format(pps_req_tx)+' Mpps | '+ '{:>9.3f}'.format(pps_tx) +' Mpps | ' + '{:>9}'.format(pps_sut_tx_str) +' Mpps | '+ '{:>9.3f}'.format(pps_rx)+' Mpps | '+ '{:>9.0f}'.format(lat_avg)+' us   | '+ '{:>9.0f}'.format(lat_max)+' us   | '+ '{:>14d}'.format(abs_dropped)+ ' |''{:>9.2f}'.format(drop_rate)+ '%  |'+lat_warning)
    #        writer.writerow({'Flows':flow_number,'PacketSize':(size+4),'RequestedPPS':get_pps(speed,size),'GeneratedPPS':pps_req_tx,'SentPPS':pps_tx,'ForwardedPPS':pps_sut_tx_str,'ReceivedPPS':pps_rx,'AvgLatencyUSEC':lat_avg,'MaxLatencyUSEC':lat_max,'Dropped':abs_dropped,'DropRate':drop_rate})
            if self.test['pushgateway']:
                URL     = self.test['pushgateway'] + '/metrics/job/' + TestName + '/instance/' + self.test['environment_file'] 
                DATA = 'Flows {}\nPacketSize {}\nRequestedPPS {}\nGeneratedPPS {}\nSentPPS {}\nForwardedPPS {}\nReceivedPPS {}\nAvgLatencyUSEC {}\nMaxLatencyUSEC {}\nDropped {}\nDropRate {}\n'.format(flow_number,size+4,get_pps(speed,size),pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx,lat_avg,lat_max,abs_dropped,drop_rate)
                HEADERS = {'X-Requested-With': 'Python requests', 'Content-type': 'text/xml'}
                response = requests.post(url=URL, data=DATA,headers=HEADERS)
                if (response.status_code != 202) and (response.status_code != 200):
                    RapidLog.info('Cannot send metrics to {}'.format(URL))
                    RapidLog.info(DATA)
        self.gen_machine.stop_latency_cores()
        return (True)
