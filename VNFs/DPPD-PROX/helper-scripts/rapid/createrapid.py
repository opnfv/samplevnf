#!/usr/bin/python

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
from rapid_log import RapidLog
from stackdeployment import StackDeployment
try:
    import configparser
except ImportError:
    # Python 2.x fallback
    import ConfigParser as configparser

class RapidStackManager(object):
    @staticmethod
    def parse_config(rapid_stack_params):
        config = configparser.RawConfigParser()
        config.read('config_file')
        section = 'OpenStack'
        options = config.options(section)
        for option in options:
            rapid_stack_params[option] = config.get(section, option)
        return (rapid_stack_params)

    @staticmethod
    def deploy_stack(rapid_stack_params):
        cloud_name = rapid_stack_params['cloud_name']
        stack_name = rapid_stack_params['stack_name']
        heat_template = rapid_stack_params['heat_template']
        heat_param = rapid_stack_params['heat_param']
        keypair_name = rapid_stack_params['keypair_name']
        user = rapid_stack_params['user']
        dataplane_subnet_mask = rapid_stack_params['dataplane_subnet_mask']
        deployment = StackDeployment(cloud_name)
        deployment.deploy(stack_name, keypair_name, heat_template, heat_param)
        deployment.generate_env_file(user, dataplane_subnet_mask)

def main():
    rapid_stack_params = {}
    RapidStackManager.parse_config(rapid_stack_params)
    log_file = 'CREATE{}.log'.format(rapid_stack_params['stack_name'])
    RapidLog.log_init(log_file, 'DEBUG', 'INFO', '2020.09.23')
    #cloud_name = 'openstackL6'
    #stack_name = 'rapid'
    #heat_template = 'openstack-rapid.yaml'
    #heat_param = 'params_rapid.yaml'
    #keypair_name = 'prox_key'
    #user = 'centos'
    RapidStackManager.deploy_stack(rapid_stack_params)

if __name__ == "__main__":
    main()
