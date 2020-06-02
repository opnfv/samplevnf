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

class RapidDefaults(object):
    """
    Class to define the test defaults
    """
    test_params = {
        'version' : '2020.04.15', # Please do NOT change, used for debugging
        'environment_file' : 'rapid.env', #Default string for environment
        'test_file' : 'basicrapid.test', #Default string for test
        'machine_map_file' : 'machine.map', #Default string for machine map file
        'loglevel' : 'DEBUG', # sets log level for writing to file
        'screenloglevel' : 'INFO', # sets log level for writing to screen
        'runtime' : 10, # time in seconds for 1 test run
        'configonly' : False, # If True, the system will upload all the necessary config fiels to the VMs, but not start PROX and the actual testing
        'rundir' : '/opt/rapid', # Directory where to find the tools in the machines running PROX
        'lat_percentile' : 0.99
        }
