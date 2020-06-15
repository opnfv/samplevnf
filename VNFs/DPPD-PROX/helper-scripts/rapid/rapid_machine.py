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

from rapid_log import RapidLog 
from prox_ctrl import prox_ctrl
import re

class RapidMachine(object):
    """
    Class to deal with rapid configuration files
    """
    def __init__(self, key, user, vim, rundir, machine_params):
        self.name = machine_params['name']
        self.ip = machine_params['admin_ip']
        self.key = key
        self.user = user
        self.rundir = rundir
        self.dp_ports = []
        self.dpdk_port_index = []
        index = 1
        while True:
            ip_key = 'dp_ip{}'.format(index)
            mac_key = 'dp_mac{}'.format(index)
            if ip_key in machine_params.keys() and mac_key in machine_params.keys():
                dp_port = {'ip': machine_params[ip_key], 'mac' : machine_params[mac_key]}
                self.dp_ports.append(dict(dp_port))
                self.dpdk_port_index.append(index - 1)
                index += 1
            else:
                break
        self.rundir = rundir
        self.machine_params = machine_params
        self._client = prox_ctrl(self.ip, self.key, self.user)
        self._client.connect()
        if vim in ['OpenStack']:
            self.devbind()
        self.generate_lua(vim)
        self._client.scp_put(self.machine_params['config_file'], '{}/{}'.format(self.rundir, machine_params['config_file']))

    def get_cores(self):
        return (self.machine_params['cores'])

    def devbind(self):
        # Script to bind the right network interface to the poll mode driver
        for index, dp_port in enumerate(self.dp_ports, start = 1):
            DevBindFileName = self.rundir + '/devbind-{}-port{}.sh'.format(self.ip, index)
            self._client.scp_put('./devbind.sh', DevBindFileName)
            cmd =  'sed -i \'s/MACADDRESS/' + dp_port['mac'] + '/\' ' + DevBindFileName 
            result = self._client.run_cmd(cmd)
            RapidLog.debug('devbind.sh MAC updated for port {} on {} {}'.format(index, self.name, result))
            result = self._client.run_cmd(DevBindFileName)
            RapidLog.debug('devbind.sh running for port {} on {} {}'.format(index, self.name, result))

    def generate_lua(self, vim, appendix = ''):
        PROXConfigfile =  open (self.machine_params['config_file'], 'r')
        PROXConfig = PROXConfigfile.read()
        PROXConfigfile.close()
        self.all_tasks_for_this_cfg = set(re.findall("task\s*=\s*(\d+)",PROXConfig))
        self.LuaFileName = 'parameters-{}.lua'.format(self.ip)
        with open(self.LuaFileName, "w") as LuaFile:
            LuaFile.write('require "helper"\n')
            LuaFile.write('name="%s"\n'% self.name)
            for index, dp_port in enumerate(self.dp_ports, start = 1):
                LuaFile.write('local_ip{}="{}"\n'.format(index, dp_port['ip']))
                LuaFile.write('local_hex_ip{}=convertIPToHex(local_ip{})\n'.format(index, index))
            if vim in ['kubernetes']:
                LuaFile.write("eal=\"--socket-mem=512,0 --file-prefix %s --pci-whitelist %s\"\n" % (self.name, self.machine_params['dp_pci_dev']))
            else:
                LuaFile.write("eal=\"\"\n")
            if 'cores' in self.machine_params.keys():
                LuaFile.write('cores="%s"\n'% ','.join(map(str, self.machine_params['cores'])))
            if 'ports' in self.machine_params.keys():
                LuaFile.write('ports="%s"\n'% ','.join(map(str, self.machine_params['ports'])))
            if 'dest_ports' in self.machine_params.keys():
                for index, dest_port in enumerate(self.machine_params['dest_ports'], start = 1):
                    LuaFile.write('dest_ip{}="{}"\n'.format(index, dest_port['ip']))
                    LuaFile.write('dest_hex_ip{}=convertIPToHex(dest_ip{})\n'.format(index, index))
                    LuaFile.write('dest_hex_mac{}="{}"\n'.format(index , dest_port['mac'].replace(':',' ')))
            LuaFile.write(appendix)
        self._client.scp_put(self.LuaFileName, self.rundir + '/parameters.lua')
        self._client.scp_put('helper.lua', self.rundir + '/helper.lua')

    def start_prox(self, autostart=''):
        if self.machine_params['prox_launch_exit']:
            cmd = 'sudo {}/prox {} -t -o cli -f {}/{}'.format(self.rundir, autostart, self.rundir, self.machine_params['config_file'])
            result = self._client.fork_cmd(cmd, 'PROX Testing on {}'.format(self.name))
            RapidLog.debug("Starting PROX on {}: {}, {}".format(self.name, cmd, result))
        self.socket = self._client.connect_socket()

    def start(self):
        self.socket.start(self.get_cores())

    def stop(self):
        self.socket.stop(self.get_cores())

    def reset_stats(self):
        self.socket.reset_stats()

    def core_stats(self):
        return (self.socket.core_stats(self.get_cores(), self.all_tasks_for_this_cfg))

    def multi_port_stats(self):
        return (self.socket.multi_port_stats(self.dpdk_port_index))
