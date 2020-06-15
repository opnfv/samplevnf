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
from statistics import mean

class ImpairTest(RapidTest):
    """
    Class to manage the impair testing
    """
    def __init__(self, test_param, lat_percentile, runtime, pushgateway,
            environment_file, gen_machine, sut_machine):
        super().__init__(test_param, runtime, pushgateway, environment_file)
        self.gen_machine = gen_machine
        self.sut_machine = sut_machine
        self.test['lat_percentile'] = lat_percentile

    def run(self):
    #    fieldnames = ['Flows','PacketSize','RequestedPPS','GeneratedPPS','SentPPS','ForwardedPPS','ReceivedPPS','AvgLatencyUSEC','MaxLatencyUSEC','Dropped','DropRate']
    #    writer = csv.DictWriter(data_csv_file, fieldnames=fieldnames)
    #    writer.writeheader()
        imix = self.test['imix']
        size = mean (imix)
        flow_number = self.test['flowsize']
        attempts = 0
        self.gen_machine.set_udp_packet_size(imix)
        flow_number = self.gen_machine.set_flows(flow_number)
        self.gen_machine.start_latency_cores()
        RapidLog.info("+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+")
        RapidLog.info("| Generator is sending UDP ({:>5} flow) packets ({:>5} bytes) to SUT via GW dropping and delaying packets. SUT sends packets back. Use ctrl-c to stop the test                               |".format(flow_number,size))
        RapidLog.info("+--------+------------------+-------------+-------------+-------------+------------------------+----------+----------+----------+-----------+-----------+-----------+-----------+-------+----+")
        RapidLog.info('| Test   | Speed requested  | Gen by core | Sent by NIC | Fwrd by SUT | Rec. by core           | Avg. Lat.|{:.0f} Pcentil| Max. Lat.|   Sent    |  Received |    Lost   | Total Lost|L.Ratio|Time|'.format(self.test['lat_percentile']*100))
        RapidLog.info("+--------+------------------+-------------+-------------+-------------+------------------------+----------+----------+----------+-----------+-----------+-----------+-----------+-------+----+")

        speed = self.test['startspeed']
        self.gen_machine.set_generator_speed(speed)
        while True:
            attempts += 1
            print('Measurement ongoing at speed: ' + str(round(speed,2)) + '%      ',end='\r')
            sys.stdout.flush()
            time.sleep(1)
            # Get statistics now that the generation is stable and NO ARP messages any more
            pps_req_tx,pps_tx,pps_sut_tx,pps_rx,lat_avg, lat_perc, lat_perc_max, lat_max, abs_tx, abs_rx, abs_dropped, abs_tx_fail, drop_rate, lat_min, lat_used, r, actual_duration = self.run_iteration(float(self.test['runtime']),flow_number,size,speed)
            # Drop rate is expressed in percentage. lat_used is a ratio (0 to 1). The sum of these 2 should be 100%.
            # If the sum is lower than 95, it means that more than 5% of the latency measurements where dropped for accuracy reasons.
            if (drop_rate + lat_used * 100) < 95:
                lat_warning = bcolors.WARNING + ' Latency accuracy issue?: {:>3.0f}%'.format(lat_used*100) +  bcolors.ENDC
            else:
                lat_warning = ''
            RapidLog.info(self.report_result(attempts,size,speed,pps_req_tx,pps_tx,pps_sut_tx,pps_rx,lat_avg,lat_perc,lat_perc_max,lat_max,abs_tx,abs_rx,abs_dropped,actual_duration))
#        writer.writerow({'Flows':flow_number,'PacketSize':(size+4),'RequestedPPS':self.get_pps(speed,size),'GeneratedPPS':pps_req_tx,'SentPPS':pps_tx,'ForwardedPPS':pps_sut_tx_str,'ReceivedPPS':pps_rx,'AvgLatencyUSEC':lat_avg,'MaxLatencyUSEC':lat_max,'Dropped':abs_dropped,'DropRate':drop_rate})
            if self.test['pushgateway']:
                URL     = self.test['pushgateway'] + self.test['test'] + '/instance/' + self.test['environment_file'] 
                DATA = 'Flows {}\nPacketSize {}\nRequestedPPS {}\nGeneratedPPS {}\nSentPPS {}\nForwardedPPS {}\nReceivedPPS {}\nAvgLatencyUSEC {}\nMaxLatencyUSEC {}\nDropped {}\nDropRate {}\n'.format(flow_number,size+4,self.get_pps(speed,size),pps_req_tx,pps_tx,pps_sut_tx,pps_rx,lat_avg,lat_max,abs_dropped,drop_rate)
                HEADERS = {'X-Requested-With': 'Python requests', 'Content-type': 'text/xml'}
                response = requests.post(url=URL, data=DATA,headers=HEADERS)
                if (response.status_code != 202) and (response.status_code != 200):
                    RapidLog.info('Cannot send metrics to {}'.format(URL))
                    RapidLog.info(DATA)
        self.gen_machine.stop_latency_cores()
        return (True)
