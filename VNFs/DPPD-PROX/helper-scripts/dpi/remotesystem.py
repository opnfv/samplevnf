#!/bin/env python

##
## Copyright (c) 2010-2017 Intel Corporation
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

import os
import time
import socket

def ssh(user, ip, cmd):
    # print cmd;
    ssh_options = ""
    ssh_options += "-o StrictHostKeyChecking=no "
    ssh_options += "-o UserKnownHostsFile=/dev/null "
    ssh_options += "-o LogLevel=quiet "
    running = os.popen("ssh " + ssh_options + " " + user + "@" + ip + " \"" + cmd + "\"");
    ret = {};
    ret['out'] = running.read().strip();
    ret['ret'] = running.close();
    if (ret['ret'] == None):
        ret['ret'] = 0;

    return ret;

def ssh_check_quit(obj, user, ip, cmd):
    ret = ssh(user, ip, cmd);
    if (ret['ret'] != 0):
        obj._err = True;
        obj._err_str = ret['out'];
        exit(-1);

class remoteSystem:
    def __init__(self, user, ip):
        self._ip          = ip;
        self._user        = user;

    def run(self, cmd):
        return ssh(self._user, self._ip, cmd);

    def scp(self, src, dst):
        running = os.popen("scp " + self._user + "@" + self._ip + ":" + src + " " + dst);
        return running.close();

    def getIP(self):
        return self._ip
