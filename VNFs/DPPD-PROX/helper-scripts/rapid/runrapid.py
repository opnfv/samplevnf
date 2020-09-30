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
    def __del__(self):
        for machine in self.machines:
            machine.close_prox()

    @staticmethod
    def get_defaults():
        return (RapidDefaults.test_params)

    def run_tests(self, test_params):
        test_params = RapidConfigParser.parse_config(test_params)
        RapidLog.debug(test_params)
        monitor_gen = monitor_sut = False
        background_machines = []
        sut_machine = gen_machine = None
        self.machines = []
        configonly = test_params['configonly']
        for machine_params in test_params['machines']:
            if 'gencores' in machine_params.keys():
                machine = RapidGeneratorMachine(test_params['key'],
                        test_params['user'], test_params['vim_type'],
                        test_params['rundir'], machine_params,
                        configonly, test_params['ipv6'])
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
                        test_params['vim_type'], test_params['rundir'],
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
        prox_executor = concurrent.futures.ThreadPoolExecutor(max_workers=len(self.machines))
        self.future_to_prox = {prox_executor.submit(machine.start_prox): machine for machine in self.machines}
        if configonly:
            concurrent.futures.wait(self.future_to_prox,return_when=ALL_COMPLETED)
            sys.exit()
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.machines)) as executor:
            future_to_connect_prox = {executor.submit(machine.connect_prox): machine for machine in self.machines}
            concurrent.futures.wait(future_to_connect_prox,return_when=ALL_COMPLETED)
        result = True
        for test_param in test_params['tests']:
            RapidLog.info(test_param['test'])
            if test_param['test'] in ['flowsizetest', 'TST009test',
                    'fixed_rate', 'increment_till_fail']:
                test = FlowSizeTest(test_param, test_params['lat_percentile'],
                        test_params['runtime'], 
                        test_params['TestName'], 
                        test_params['environment_file'], gen_machine,
                        sut_machine, background_machines)
            elif test_param['test'] in ['corestats']:
                test = CoreStatsTest(test_param, test_params['runtime'],
                        test_params['TestName'], 
                        test_params['environment_file'], self.machines)
            elif test_param['test'] in ['portstats']:
                test = PortStatsTest(test_param, test_params['runtime'],
                        test_params['TestName'], 
                        test_params['environment_file'], self.machines)
            elif test_param['test'] in ['impairtest']:
                test = ImpairTest(test_param, test_params['lat_percentile'],
                        test_params['runtime'],
                        test_params['TestName'], 
                        test_params['environment_file'], gen_machine,
                        sut_machine)
            elif test_param['test'] in ['irqtest']:
                test = IrqTest(test_param, test_params['runtime'],
                        test_params['TestName'], 
                        test_params['environment_file'], self.machines)
            elif test_param['test'] in ['warmuptest']:
                test = WarmupTest(test_param, gen_machine)
            else:
                RapidLog.debug('Test name ({}) is not valid:'.format(
                    test_param['test']))
            single_test_result = test.run()
            if not single_test_result:
                result = False
        return (result)

def main():
    """Main function.
    """
    test_params = RapidTestManager.get_defaults()
    # When no cli is used, the process_cli can be replaced by code modifying
    # test_params
    test_params = RapidCli.process_cli(test_params)
    log_file = 'RUN{}.{}.log'.format(test_params['environment_file'],
            test_params['test_file'])
    RapidLog.log_init(log_file, test_params['loglevel'],
            test_params['screenloglevel'] , test_params['version']  )
    test_manager = RapidTestManager()
    test_result = test_manager.run_tests(test_params)
    RapidLog.info('Test result is : {}'.format(test_result))

if __name__ == "__main__":
    main()
