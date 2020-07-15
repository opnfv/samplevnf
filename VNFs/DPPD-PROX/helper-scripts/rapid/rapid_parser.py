#!/usr/bin/python

##
## Copyright (c) 2020 Intel Corporation
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##

from rapid_log import RapidLog 
from past.utils import old_div
try:
    import configparser
except ImportError:
    # Python 2.x fallback
    import ConfigParser as configparser
import ast

class RapidConfigParser(object):
    """
    Class to deal with rapid configuration files
    """
    @staticmethod
    def parse_config(test_params):
        testconfig = configparser.RawConfigParser()
        testconfig.read(test_params['test_file'])
        test_params['required_number_of_test_machines'] = int(testconfig.get('TestParameters', 'total_number_of_test_machines'))
        test_params['number_of_tests'] = int(testconfig.get('TestParameters', 'number_of_tests'))
        test_params['TestName'] = testconfig.get('TestParameters', 'name')
        if testconfig.has_option('TestParameters', 'lat_percentile'):
            test_params['lat_percentile'] = old_div(float(testconfig.get('TestParameters', 'lat_percentile')),100.0)
        else:
            test_params['lat_percentile'] = 0.99
        RapidLog.info('Latency percentile at {:.0f}%'.format(test_params['lat_percentile']*100))
        config = configparser.RawConfigParser()
        config.read(test_params['environment_file'])
        test_params['vim_type'] = config.get('Varia', 'vim')
        test_params['key'] = config.get('ssh', 'key')
        test_params['user'] = config.get('ssh', 'user')
        test_params['total_number_of_machines'] = int(config.get('rapid', 'total_number_of_machines'))
        tests = []
        test = {}
        for test_index in range(1, test_params['number_of_tests']+1):
            test.clear()
            section = 'test%d'%test_index
            options = testconfig.options(section)
            for option in options:
                if option in ['imix','imixs','flows']:
                    test[option] = ast.literal_eval(testconfig.get(section, option))
#                    test[option] = [int(i) for i in test[option]]
                elif option in ['maxframespersecondallingress','stepsize','flowsize']:
                    test[option] = int(testconfig.get(section, option))
                elif option in ['startspeed','drop_rate_threshold','lat_avg_threshold','lat_perc_threshold','lat_max_threshold','accuracy','maxr','maxz','pass_threshold']:
                    test[option] = float(testconfig.get(section, option))
                else:
                    test[option] = testconfig.get(section, option)
            tests.append(dict(test))
        for test in tests:
            if test['test'] in ['flowsizetest','TST009test']:
                if 'drop_rate_threshold' not in test.keys():
                    test['drop_rate_threshold'] = 0
        test_params['tests'] = tests
        if test_params['required_number_of_test_machines'] > test_params['total_number_of_machines']:
            RapidLog.exception("Not enough VMs for this test: %d needed and only %d available" % (required_number_of_test_machines,total_number_of_machines))
            raise Exception("Not enough VMs for this test: %d needed and only %d available" % (required_number_of_test_machines,total_number_of_machines))
        machine_map = configparser.RawConfigParser()
        machine_map.read(test_params['machine_map_file'])
        machines = []
        machine = {}
        for test_machine in range(1, test_params['required_number_of_test_machines']+1):
            machine.clear()
            if not(testconfig.has_option('TestM%d'%test_machine, 'prox_socket') and not testconfig.getboolean('TestM%d'%test_machine, 'prox_socket')):
                section = 'TestM%d'%test_machine
                options = testconfig.options(section)
                for option in options:
                    if option in ['prox_socket','prox_launch_exit','monitor']:
                        machine[option] = testconfig.getboolean(section, option)
                    elif option in ['cores', 'gencores','latcores']:
                        machine[option] = ast.literal_eval(testconfig.get(section, option))
                    elif option in ['bucket_size_exp']:
                        machine[option] = int(testconfig.get(section, option))
                    else:
                        machine[option] = testconfig.get(section, option)
                    for key in ['prox_socket','prox_launch_exit']:
                       if key not in machine.keys():
                           machine[key] = True
                if 'monitor' not in machine.keys():
                    machine['monitor'] = True
                index = int(machine_map.get('TestM%d'%test_machine, 'machine_index'))
                section = 'M%d'%index
                options = config.options(section)
                for option in options:
                    machine[option] = config.get(section, option)
                machines.append(dict(machine))
        for machine in machines:
            dp_ports = []
            if 'dest_vm' in machine.keys():
                index = 1
                while True: 
                    dp_ip_key = 'dp_ip{}'.format(index)
                    dp_mac_key = 'dp_mac{}'.format(index)
                    if dp_ip_key in machines[int(machine['dest_vm'])-1].keys() and \
                            dp_mac_key in machines[int(machine['dest_vm'])-1].keys():
                        dp_port = {'ip': machines[int(machine['dest_vm'])-1][dp_ip_key],
                                'mac' : machines[int(machine['dest_vm'])-1][dp_mac_key]}
                        dp_ports.append(dict(dp_port))
                        index += 1
                    else:
                        break
                    machine['dest_ports'] = list(dp_ports)
            gw_ips = []
            if 'gw_vm' in machine.keys():
                index = 1
                while True:
                    gw_ip_key = 'dp_ip{}'.format(index)
                    if gw_ip_key in machines[int(machine['gw_vm'])-1].keys():
                        gw_ip = machines[int(machine['gw_vm'])-1][gw_ip_key]
                        gw_ips.append(gw_ip)
                        index += 1
                    else:
                        break
                    machine['gw_ips'] = list(gw_ips)
        test_params['machines'] = machines
        return (test_params)
