#!/usr/bin/python3

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
 
# pylint: disable=missing-docstring

import json
import os
import sys
import time

from xtesting.core import testcase
from runrapid import RapidTestManager
from rapid_cli import RapidCli
from rapid_log import RapidLog

class RapidXt(testcase.TestCase):

    def run(self, **kwargs):
        try:
            test_params = RapidTestManager.get_defaults()
            for key in kwargs:
                test_params[key] = kwargs[key]
            os.makedirs(self.res_dir, exist_ok=True)
            test_params['resultsdir'] = self.res_dir
            _, test_file_name = os.path.split(test_params['test_file'])
            _, environment_file_name = os.path.split(
                    test_params['environment_file'])
            log_file = '{}/RUN{}.{}.log'.format(self.res_dir,
                    environment_file_name, test_file_name)
            RapidLog.log_init(log_file, test_params['loglevel'],
                test_params['screenloglevel'] , test_params['version']  )
            test_manager = RapidTestManager()
            self.start_time = time.time()
            self.result, self.details = test_manager.run_tests(test_params)
            self.stop_time = time.time()
            RapidLog.log_close()

        except Exception:  # pylint: disable=broad-except
            print("Unexpected error:", sys.exc_info()[0])
            self.result = 0
            self.stop_time = time.time()
