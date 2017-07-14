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

import threading
from time import *
from proxsocket import *
from remotesystem import *

class ProxStarter:
    def __init__(self, remoteSystem, cmd):
	self._remoteSystem = remoteSystem
	self._cmd = cmd
	self._thread = None
	self._prox = None;
	self._result = None;
	self._startDuration = None

    def startThreaded(self):
	self._start_thread = threading.Thread(target = self._run, args = (self, 1))
        self._start_thread.start();

    def joinThreaded(self):
	self._start_thread.join();
	return self._result;

    def getResult(self):
	return self._result;

    def getStartDuration(self):
	return self._startDuration;
    def getProx(self):
        return self._prox;

    def _run(self, a, b):
	before = time.time()
	self._remoteSystem.run("sudo killall -w -q -9 prox")

	self._result = self._remoteSystem.run(self._cmd);

	sleep(1)
	after = time.time()
	self._startDuration = after - before;

class StatsCmd(object):
    def __init__(self, prox):
        self._cmd = ""
        self._parts = []
        self._beforeParts = []
        self._prox = prox;

    def sendRecv(self):
        cmd = self.getCmd()
        reply = self._prox._send(cmd)._recv()
        self.setReply(reply)

    def add(self, stats):
        if (len(self._cmd) != 0):
            self._cmd += ","
        self._cmd += stats

        if (len(self._parts) == 0):
            self._beforeParts += [0]
        else:
            before = self._parts[-1] + self._beforeParts[-1];
            self._beforeParts += [before]

        self._parts += [stats.count(",") + 1];

    def getCmd(self):
        return "stats " + self._cmd;

    def setReply(self, reply):
        self._reply = reply.split(",");

    def getResult(self, idx):
        start = self._beforeParts[idx];
        end = start + self._parts[idx];
        return self._reply[start:end]

class Prox(object):
    def __init__(self, systemConfig):
        self._systemConfig = systemConfig;
        self._proxStarter = None

        user = self._systemConfig._user
        ip = self._systemConfig._ip
        self._remoteSystem = remoteSystem(user, ip);

        self.resetArguments()

    def resetArguments(self):
        self._args = []

    def addArgument(self, arg):
        self._args.append(arg);

    def startFork(self):
        cmd = self.getCmd();
        self._proxStarter = ProxStarter(self._remoteSystem, cmd)
        self._proxStarter.startThreaded();

    def startJoin(self):
        ret = self.startJoinNoConnect();
        self._connectSocket();
        self._querySetup();
        return self._proxStarter.getStartDuration();

    def startJoinNoConnect(self):
        return self._proxStarter.joinThreaded();

    def getCmd(self):
        proxDir = self._systemConfig.getProxDir();
        cfgFile = self._systemConfig.getCfgFile();

        cmd = "cd " + proxDir + "; "
        cmd += "sudo ./build/prox "
        cmd += "-f " + cfgFile

        for arg in self._args:
            cmd += " " + arg
        return cmd

    def getLog(self):
        proxDir = self._systemConfig.getProxDir()
        cmd = "cat " + proxDir + "/prox.log";
	return self._remoteSystem.run(cmd)["out"];

    def getIP(self):
        return self._systemConfig._ip;

    def getHz(self):
        return self._hz;

    def getBeg(self):
        return self._beg;

    def getPorts(self):
        return self._ports;

    def getIerrors(self):
        sc = StatsCmd(self)
        sc.add(self._buildIerrorsCmd());
        sc.sendRecv()
        return self._parseIerrorsReply(sc.getResult(0));

    def _parseIerrorsReply(self, rep):
        tot_ierrors = 0;
        for e in rep:
            tot_ierrors += int(e);
        return tot_ierrors;

    def _buildIerrorsCmd(self):
        cmd = ""
        for port in self._ports:
            if (len(cmd)):
                cmd += ","
            cmd += "port(%s).ierrors" % str(port)
        return cmd;

    def waitCmdFinished(self):
        self._send("stats hz")._recv();

    def waitAllLinksUp(self):
        link_down = True;
        while (link_down):
            link_down = False;
            for port in self._ports:
                cmd = "port link state %s" % str(port)
                link_state = self._send(cmd)._recv();
                if (link_state == "down"):
                    link_down = True;
                    print "Link down on port " + str(port) + ", waiting one second"
                    break;
            sleep(1);

    def startAllCores(self):
        self._send("start all");

    def stopAllCores(self):
        self._send("stop all");

    def forceQuit(self):
        self._send("quit_force")._recv();

    def killProx(self):
        self._remoteSystem.run("sudo killall -w -q -9 prox")

    def getTsc(self):
        return self._getTsc();

    def _getTsc(self):
        return int(self._send("stats global.tsc")._recv());

    def scpStatsDump(self, dst):
        proxDir = self._systemConfig.getProxDir()

        src = proxDir + "/stats_dump";
        print "Copying " + src + " to " + dst
        self._remoteSystem.scp(src, dst);

    def _querySetup(self):
        print "Query setup on " + str(self.getIP())
        self._queryHz()
        self._queryBeg()
        self._queryPorts()
        self._querySetup2()

    def _querySetup2(self):
        print "running query 2"
        pass

    def quitProx(self):
        self._send("quit")._recv();

    def _queryHz(self):
        self._hz = int(self._send("stats hz")._recv());

    def _queryBeg(self):
        self._beg = self._getTsc();

    def _queryPorts(self):
        self._ports = []
        port_info_all = self._send("port info all")._recv();
        port_info_list = port_info_all.split(',');

        for port_info in port_info_list:
            if (len(port_info) > 0):
                self._ports.append(int(port_info.split(":")[0]));

    def _connectSocket(self):
        self._proxSocket = ProxSocket(self.getIP())

    def _send(self, msg):
        self._proxSocket.send(msg);
        return self

    def _recv(self):
        return self._proxSocket.recv();
