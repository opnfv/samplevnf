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
import os
import re

class RapidMachine(object):
    """
    Class to deal with a PROX instance (VM, bare metal, container)
    """
    def __init__(self, key, user, vim, rundir, resultsdir, machine_params,
            configonly):
        self.name = machine_params['name']
        self.ip = machine_params['admin_ip']
        self.key = key
        self.user = user
        self.rundir = rundir
        self.resultsdir = resultsdir
        self.dp_ports = []
        self.dpdk_port_index = []
        self.configonly = configonly
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
        self.machine_params = machine_params
        self.vim = vim
        self.cpu_mapping = None
        PROXConfigfile =  open (self.machine_params['config_file'], 'r')
        PROXConfig = PROXConfigfile.read()
        PROXConfigfile.close()
        self.all_tasks_for_this_cfg = set(re.findall("task\s*=\s*(\d+)",PROXConfig))

    def __del__(self):
        if ((not self.configonly) and self.machine_params['prox_socket']):
            self._client.scp_get('/prox.log', '{}/{}.prox.log'.format(
                self.resultsdir, self.name))

    def get_cores(self):
        return (self.machine_params['cores'])

    def expand_cpuset(self, cpuset):
        """Expand cpuset provided as comma-separated list of CPU numbers and
        CPU ranges of numbers. For more information please see
        https://man7.org/linux/man-pages/man7/cpuset.7.html
        """
        cpuset_expanded = []
        for cpu in cpuset.split(','):
            if '-' in cpu:
                cpu_range = cpu.split('-')
                cpuset_expanded += range(int(cpu_range[0]), int(cpu_range[1]) + 1)
            else:
                cpuset_expanded.append(int(cpu))
        return cpuset_expanded

    def read_cpuset(self):
        """Read list of cpus on which we allowed to execute
        """
        cmd = 'cat /sys/fs/cgroup/cpuset/cpuset.cpus'
        cpuset_cpus = self._client.run_cmd(cmd).decode().rstrip()
        RapidLog.debug('{} ({}): Allocated cpuset: {}'.format(self.name, self.ip, cpuset_cpus))
        self.cpu_mapping = self.expand_cpuset(cpuset_cpus)
        RapidLog.debug('{} ({}): Expanded cpuset: {}'.format(self.name, self.ip, self.cpu_mapping))

        # Log CPU core mapping for user information
        cpu_mapping_str = ''
        for i in range(len(self.cpu_mapping)):
            cpu_mapping_str = cpu_mapping_str + '[' + str(i) + '->' + str(self.cpu_mapping[i]) + '], '
        cpu_mapping_str = cpu_mapping_str[:-2]
        RapidLog.debug('{} ({}): CPU mapping: {}'.format(self.name, self.ip, cpu_mapping_str))

    def remap_cpus(self, cpus):
        """Convert relative cpu ids provided as function parameter to match
        cpu ids from allocated list
        """
        cpus_remapped = []
        for cpu in cpus:
            cpus_remapped.append(self.cpu_mapping[cpu])
        return cpus_remapped

    def remap_all_cpus(self):
        """Convert relative cpu ids for different parameters (mcore, cores)
        """
        if self.cpu_mapping is None:
            RapidLog.debug('{} ({}): cpu mapping is not defined! Please check the configuration!'.format(self.name, self.ip))
            return

        if 'mcore' in self.machine_params.keys():
            cpus_remapped = self.remap_cpus(self.machine_params['mcore'])
            RapidLog.debug('{} ({}): mcore {} remapped to {}'.format(self.name, self.ip, self.machine_params['mcore'], cpus_remapped))
            self.machine_params['mcore'] = cpus_remapped

        if 'cores' in self.machine_params.keys():
            cpus_remapped = self.remap_cpus(self.machine_params['cores'])
            RapidLog.debug('{} ({}): cores {} remapped to {}'.format(self.name, self.ip, self.machine_params['cores'], cpus_remapped))
            self.machine_params['cores'] = cpus_remapped

    def devbind(self):
        # Script to bind the right network interface to the poll mode driver
        for index, dp_port in enumerate(self.dp_ports, start = 1):
            DevBindFileName = self.rundir + '/devbind-{}-port{}.sh'.format(self.ip, index)
            self._client.scp_put('./devbind.sh', DevBindFileName)
            cmd =  'sed -i \'s/MACADDRESS/' + dp_port['mac'] + '/\' ' + DevBindFileName 
            result = self._client.run_cmd(cmd)
            RapidLog.debug('devbind.sh MAC updated for port {} on {} {}'.format(index, self.name, result))
            if ((not self.configonly) and self.machine_params['prox_launch_exit']):
                result = self._client.run_cmd(DevBindFileName)
                RapidLog.debug('devbind.sh running for port {} on {} {}'.format(index, self.name, result))

    def generate_lua(self, appendix = ''):
        self.LuaFileName = 'parameters-{}.lua'.format(self.ip)
        with open(self.LuaFileName, "w") as LuaFile:
            LuaFile.write('require "helper"\n')
            LuaFile.write('name="%s"\n'% self.name)
            for index, dp_port in enumerate(self.dp_ports, start = 1):
                LuaFile.write('local_ip{}="{}"\n'.format(index, dp_port['ip']))
                LuaFile.write('local_hex_ip{}=convertIPToHex(local_ip{})\n'.format(index, index))
            if self.vim in ['kubernetes']:
                LuaFile.write("eal=\"--socket-mem=512,0 --file-prefix %s --pci-whitelist %s\"\n" % (self.name, self.machine_params['dp_pci_dev']))
            else:
                LuaFile.write("eal=\"\"\n")
            if 'mcore' in self.machine_params.keys():
                LuaFile.write('mcore="%s"\n'% ','.join(map(str, self.machine_params['mcore'])))
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
        if self.machine_params['prox_socket']:
            self._client = prox_ctrl(self.ip, self.key, self.user)
            self._client.connect()
            if self.vim in ['OpenStack']:
                self.devbind()
            if self.vim in ['kubernetes']:
                self.read_cpuset()
                self.remap_all_cpus()
            _, prox_config_file_name = os.path.split(self.machine_params['config_file'])
            self.generate_lua()
            self._client.scp_put(self.machine_params['config_file'], '{}/{}'.format(self.rundir, prox_config_file_name))
            if ((not self.configonly) and self.machine_params['prox_launch_exit']):
                cmd = 'sudo {}/prox {} -t -o cli -f {}/{}'.format(self.rundir, autostart, self.rundir, prox_config_file_name)
                RapidLog.debug("Starting PROX on {}: {}".format(self.name, cmd))
                result = self._client.run_cmd(cmd, 'PROX Testing on {}'.format(self.name))
                RapidLog.debug("Finished PROX on {}: {}".format(self.name, cmd))

    def close_prox(self):
        if (not self.configonly) and self.machine_params['prox_socket'] and self.machine_params['prox_launch_exit']:
            self.socket.quit_prox()

    def connect_prox(self):
        if self.machine_params['prox_socket']:
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
