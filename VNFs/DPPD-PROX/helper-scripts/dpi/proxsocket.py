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

import socket

class ProxSocket:
    def __init__(self, ip):
        self._ip = ip;
        self._dat = ""

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self._ip, 8474))
        except:
            raise Exception("Failed to connect to prox on " + self._ip)
        self._sock = sock;

    def send(self, msg):
        self._sock.sendall(msg + "\n");
        return self

    def recv(self):
        ret_str = "";
        done = 0;
        while done == 0:
            if (len(self._dat) == 0):
                self._dat = self._sock.recv(256);
                if (self._dat == ''):
                    return '';

            while(len(self._dat)):
                if (self._dat[0] == '\n'):
                    done = 1
                    self._dat = self._dat[1:]
                    break;
                else:
                    ret_str += self._dat[0];
                    self._dat = self._dat[1:]
        return ret_str;
