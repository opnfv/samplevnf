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

class SystemConfig:
    _user = None
    _ip = None
    _proxDir = None
    _cfgFile = None
    def __init__(self, user, ip, proxDir, configDir):
        self._user = user;
        self._ip = ip;
        self._proxDir = proxDir;
        self._cfgFile = configDir;
    def __init__(self, text):
        self._user = text.split("@")[0];
        text = text.split("@")[1];
        self._ip = text.split(":")[0];
        self._proxDir = text.split(":")[1];
        self._cfgFile = text.split(":")[2];

    def getUser(self):
        return self._user;

    def getIP(self):
        return self._ip;

    def getProxDir(self):
        return self._proxDir;

    def getCfgFile(self):
        return self._cfgFile;

    @staticmethod
    def checkSyntax(text):
        split = text.split("@");
        if (len(split) != 2):
            return SystemConfig.getSyntaxError(text);
        after = split[1].split(":");
        if (len(after) != 3):
            return SystemConfig.getSyntaxError(text);
        return ""
    def toString(self):
        ret = "";
        ret += "  " + self._user + "@" + self._ip + "\n"
        ret += "    " + "prox dir: " + self._proxDir + "\n"
        ret += "    " + "cfg dir: " + self._cfgFile + "\n"
        return ret;

    @staticmethod
    def getSyntaxError(text):
        ret = "Invaild system syntax"
        ret += ", got: " + str(text)
        ret += ", expected: " + str(SystemConfig.expectedSyntax())
        return ret;

    @staticmethod
    def expectedSyntax():
        return "user@ip:proxDir:cfgFile"
