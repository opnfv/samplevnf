#!/usr/bin/python3

##
## Copyright (c) 2010-2020 Intel Corporation
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
from __future__ import print_function
from __future__ import print_function
from __future__ import division

from future import standard_library
standard_library.install_aliases()
from builtins import object
import os
import sys
import concurrent.futures
from concurrent.futures import ALL_COMPLETED
from rapid_cli import RapidCli
from rapid_log import RapidLog
from rapid_parser import RapidConfigParser
from rapid_defaults import RapidDefaults
from rapid_machine import RapidMachine
from rapid_generator_machine import RapidGeneratorMachine
from rapid_flowsizetest import FlowSizeTest
from rapid_corestatstest import CoreStatsTest
from rapid_portstatstest import PortStatsTest
from rapid_impairtest import ImpairTest
from rapid_irqtest import IrqTest
from rapid_warmuptest import WarmupTest

class RapidTestManager(object):
    """
    RapidTestManager Class
    """
    def __init__(self):
        """
        Init Function
        """
        self.machines = []

    def __del__(self):
        for machine in self.machines:
            machine.close_prox()

    @staticmethod
    def get_defaults():
        return (RapidDefaults.test_params)

    def run_tests(self, test_params):
        test_params = RapidConfigParser.parse_config(test_params)
        monitor_gen = monitor_sut = False
        background_machines = []
        sut_machine = gen_machine = None
        configonly = test_params['configonly']
        machine_names = []
        machine_counter = {}
        for machine_params in test_params['machines']:
            if machine_params['name'] not in machine_names:
                machine_names.append(machine_params['name'])
                machine_counter[machine_params['name']] = 1
            else:
                machine_counter[machine_params['name']] += 1
                machine_params['name'] = '{}_{}'.format(machine_params['name'],
                        machine_counter[machine_params['name']])
            if 'gencores' in machine_params.keys():
                machine = RapidGeneratorMachine(test_params['key'],
                        test_params['user'], test_params['password'],
                        test_params['vim_type'], test_params['rundir'],
                        test_params['resultsdir'], machine_params, configonly,
                        test_params['ipv6'])
                if machine_params['monitor']:
                    if monitor_gen:
                        RapidLog.exception("Can only monitor 1 generator")
                        raise Exception("Can only monitor 1 generator")
                    else:
                        monitor_gen = True
                        gen_machine = machine
                else:
                    background_machines.append(machine)
            else:
                machine = RapidMachine(test_params['key'], test_params['user'],
                        test_params['password'], test_params['vim_type'],
                        test_params['rundir'], test_params['resultsdir'],
                        machine_params, configonly)
                if machine_params['monitor']:
                    if monitor_sut:
                        RapidLog.exception("Can only monitor 1 sut")
                        raise Exception("Can only monitor 1 sut")
                    else:
                        monitor_sut = True
                        if machine_params['prox_socket']:
                            sut_machine = machine
            self.machines.append(machine)
        RapidLog.debug(test_params)
        try:
            prox_executor = concurrent.futures.ThreadPoolExecutor(max_workers=len(self.machines))
            self.future_to_prox = {prox_executor.submit(machine.start_prox): machine for machine in self.machines}
            if configonly:
                concurrent.futures.wait(self.future_to_prox,return_when=ALL_COMPLETED)
                sys.exit()
            socket_executor = concurrent.futures.ThreadPoolExecutor(max_workers=len(self.machines))
            future_to_connect_prox = {socket_executor.submit(machine.connect_prox): machine for machine in self.machines}
            concurrent.futures.wait(future_to_connect_prox,return_when=ALL_COMPLETED)
            result = 0
            for test_param in test_params['tests']:
                RapidLog.info(test_param['test'])
                if test_param['test'] in ['flowsizetest', 'TST009test',
                        'fixed_rate', 'increment_till_fail']:
                    test = FlowSizeTest(test_param,
                            test_params['lat_percentile'],
                            test_params['runtime'],
                            test_params['TestName'],
                            test_params['environment_file'],
                            gen_machine,
                            sut_machine, background_machines,
                            test_params['sleep_time'])
                elif test_param['test'] in ['corestatstest']:
                    test = CoreStatsTest(test_param,
                            test_params['runtime'],
                            test_params['TestName'],
                            test_params['environment_file'],
                            self.machines)
                elif test_param['test'] in ['portstatstest']:
                    test = PortStatsTest(test_param,
                            test_params['runtime'],
                            test_params['TestName'],
                            test_params['environment_file'],
                            self.machines)
                elif test_param['test'] in ['impairtest']:
                    test = ImpairTest(test_param,
                            test_params['lat_percentile'],
                            test_params['runtime'],
                            test_params['TestName'],
                            test_params['environment_file'],
                            gen_machine,
                            sut_machine, background_machines)
                elif test_param['test'] in ['irqtest']:
                    test = IrqTest(test_param,
                            test_params['runtime'],
                            test_params['TestName'],
                            test_params['environment_file'],
                            self.machines)
                elif test_param['test'] in ['warmuptest']:
                    test = WarmupTest(test_param,
                            gen_machine)
                else:
                    RapidLog.debug('Test name ({}) is not valid:'.format(
                        test_param['test']))
                single_test_result, result_details = test.run()
                result = result + single_test_result
            for machine in self.machines:
                machine.close_prox()
            concurrent.futures.wait(self.future_to_prox,
                    return_when=ALL_COMPLETED)
        except (ConnectionError, KeyboardInterrupt) as e:
            result = result_details = None
            socket_executor.shutdown(wait=False)
            socket_executor._threads.clear()
            prox_executor.shutdown(wait=False)
            prox_executor._threads.clear()
            concurrent.futures.thread._threads_queues.clear()
            RapidLog.error("Test interrupted: {} {}".format(
                type(e).__name__,e))
        return (result, result_details)

def main():
    """Main function.
    """
    test_params = RapidTestManager.get_defaults()
    # When no cli is used, the process_cli can be replaced by code modifying
    # test_params
    test_params = RapidCli.process_cli(test_params)
    _, test_file_name = os.path.split(test_params['test_file'])
    _, environment_file_name = os.path.split(test_params['environment_file'])
    if 'resultsdir' in test_params:
        res_dir = test_params['resultsdir']
        log_file = '{}/RUN{}.{}.log'.format(res_dir,environment_file_name,
                test_file_name)
    else:
        log_file = 'RUN{}.{}.log'.format(environment_file_name, test_file_name)
    RapidLog.log_init(log_file, test_params['loglevel'],
            test_params['screenloglevel'] , test_params['version']  )
    test_manager = RapidTestManager()
    test_result, _ = test_manager.run_tests(test_params)
    RapidLog.log_close()

if __name__ == "__main__":
    main()
