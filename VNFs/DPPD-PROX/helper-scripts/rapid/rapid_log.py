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

import logging
from logging.handlers import RotatingFileHandler
from logging import handlers
import os
import sys
import time

class bcolors(object):
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    FLASH = '\033[5m'

class RapidLog(object):
    """
    Class to deal with rapid logging
    """
    log = None

    @staticmethod
    def log_init(log_file, loglevel, screenloglevel, version):
        # create formatters
        screen_formatter = logging.Formatter("%(message)s")
        file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

        # get a top-level logger,
        # set its log level,
        # BUT PREVENT IT from propagating messages to the root logger
        #
        log = logging.getLogger()
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % loglevel)
        log.setLevel(numeric_level)
        log.propagate = 0

        # create a console handler
        # and set its log level to the command-line option 
        # 
        console_handler = logging.StreamHandler(sys.stdout)
        #console_handler.setLevel(logging.INFO)
        numeric_screenlevel = getattr(logging, screenloglevel.upper(), None)
        if not isinstance(numeric_screenlevel, int):
            raise ValueError('Invalid screenlog level: %s' % screenloglevel)
        console_handler.setLevel(numeric_screenlevel)
        console_handler.setFormatter(screen_formatter)

        # create a file handler
        # and set its log level
        #
        file_handler = logging.handlers.RotatingFileHandler(log_file, backupCount=10)
        #file_handler = log.handlers.TimedRotatingFileHandler(log_file, 'D', 1, 5)
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(file_formatter)

        # add handlers to the logger
        #
        log.addHandler(file_handler)
        log.addHandler(console_handler)

        # Check if log exists and should therefore be rolled
        needRoll = os.path.isfile(log_file)


        # This is a stale log, so roll it
        if needRoll:    
            # Add timestamp
            log.debug('\n---------\nLog closed on %s.\n---------\n' % time.asctime())

            # Roll over on application start
            log.handlers[0].doRollover()

        # Add timestamp
        log.debug('\n---------\nLog started on %s.\n---------\n' % time.asctime())

        log.debug("runrapid.py version: " + version)
        RapidLog.log = log

    @staticmethod
    def exception(exception_info):
        RapidLog.log.exception(exception_info)
        raise Exception(exception_info)

    def critical(critical_info):
        RapidLog.log.critical(critical_info)
        raise Exception(critical_info)

    @staticmethod
    def error(error_info):
        RapidLog.log.error(error_info)

    @staticmethod
    def debug(debug_info):
        RapidLog.log.debug(debug_info)

    @staticmethod
    def info(info):
        RapidLog.log.info(info)
