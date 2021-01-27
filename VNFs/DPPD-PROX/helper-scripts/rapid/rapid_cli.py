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

import getopt
import sys

class RapidCli(object):
    """
    Class to deal with runrapid cli
    """
    @staticmethod
    def usage(test_params):
        print("usage: runrapid    [--version] [-v]")
        print("                   [--env ENVIRONMENT_NAME]")
        print("                   [--test TEST_NAME]")
        print("                   [--map MACHINE_MAP_FILE]")
        print("                   [--runtime TIME_FOR_TEST]")
        print("                   [--configonly False|True]")
        print("                   [--log DEBUG|INFO|WARNING|ERROR|CRITICAL]")
        print("                   [-h] [--help]")
        print("")
        print("Command-line interface to runrapid")
        print("")
        print("optional arguments:")
        print("  -v,  --version         Show program's version number and exit")
        print("  --env ENVIRONMENT_NAME Parameters will be read from ENVIRONMENT_NAME. Default is %s."%test_params['environment_file'])
        print("  --test TEST_NAME       Test cases will be read from TEST_NAME. Default is %s."%test_params['test_file'])
        print("  --map MACHINE_MAP_FILE Machine mapping will be read from MACHINE_MAP_FILE. Default is %s."%test_params['machine_map_file'])
        print("  --map INDEX_LIST       This parameter can also be a list of indices, e.g. [2,3]")
        print("  --runtime              Specify time in seconds for 1 test run")
        print("  --configonly           If this option is specified, only upload all config files to the VMs, do not run the tests")
        print("  --log                  Specify logging level for log file output, default is DEBUG")
        print("  --screenlog            Specify logging level for screen output, default is INFO")
        print("  -h, --help             Show help message and exit.")
        print("")

    @staticmethod
    def process_cli(test_params):
        try:
            opts, args = getopt.getopt(sys.argv[1:], "vh", ["version","help", "env=", "test=", "map=", "runtime=","configonly","log=","screenlog="])
        except getopt.GetoptError as err:
            print("===========================================")
            print(str(err))
            print("===========================================")
            RapidCli.usage(test_params)
            sys.exit(2)
        if args:
            RapidCli.usage(test_params)
            sys.exit(2)
        for opt, arg in opts:
            if opt in ["-h", "--help"]:
                RapidCli.usage(test_params)
                sys.exit()
            if opt in ["-v", "--version"]:
                print("Rapid Automated Performance Indication for Dataplane "+test_params['version'])
                sys.exit()
            if opt in ["--env"]:
                test_params['environment_file'] = arg
            if opt in ["--test"]:
                test_params['test_file'] = arg
            if opt in ["--map"]:
                test_params['machine_map_file'] = arg
            if opt in ["--runtime"]:
                test_params['runtime'] = int(arg)
            if opt in ["--configonly"]:
                test_params['configonly'] = True
                print('No actual runs, only uploading configuration files')
            if opt in ["--log"]:
                test_params['loglevel'] = arg
                print ("Log level: "+ test_params['loglevel'])
            if opt in ["--screenlog"]:
                test_params['screenloglevel'] = arg
                print ("Screen Log level: "+ test_params['screenloglevel'])
        print ("Using '"+test_params['environment_file']+"' as name for the environment")
        print ("Using '"+test_params['test_file']+"' for test case definition")
        print ("Using '"+test_params['machine_map_file']+"' for machine mapping")
        print ("Runtime: "+ str(test_params['runtime']))
        return(test_params)
