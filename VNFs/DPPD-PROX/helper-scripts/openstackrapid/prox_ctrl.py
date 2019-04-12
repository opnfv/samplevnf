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

from __future__ import print_function

import os
import subprocess
import socket

class prox_ctrl(object):
    def __init__(self, ip, key=None, user=None):
        self._ip   = ip
        self._key  = key
        self._user = user
        self._children = []
        self._proxsock = []

    def ip(self):
        return self._ip

    def connect(self):
        """Simply try to run 'true' over ssh on remote system.
        On failure, raise RuntimeWarning exception when possibly worth
        retrying, and raise RuntimeError exception otherwise.
        """
        return self.run_cmd('true', True)

    def close(self):
        """Must be called before program termination."""
#        for prox in self._proxsock:
#            prox.quit()
        children = len(self._children)
        if children == 0:
            return
        if children > 1:
            print('Waiting for %d child processes to complete ...' % children)
        for child in self._children:
            ret = os.waitpid(child[0], os.WNOHANG)
            if ret[0] == 0:
                print("Waiting for child process '%s' to complete ..." % child[1])
                ret = os.waitpid(child[0], 0)
            rc = ret[1]
            if os.WIFEXITED(rc):
                if os.WEXITSTATUS(rc) == 0:
                    print("Child process '%s' completed successfully" % child[1])
                else:
                    print("Child process '%s' returned exit status %d" % (
                            child[1], os.WEXITSTATUS(rc)))
            elif os.WIFSIGNALED(rc):
                print("Child process '%s' exited on signal %d" % (
                        child[1], os.WTERMSIG(rc)))
            else:
                print("Wait status for child process '%s' is 0x%04x" % (
                        child[1], rc))

    def run_cmd(self, command, _connect=False):
        """Execute command over ssh on remote system.
        Wait for remote command completion.
        Return command output (combined stdout and stderr).
        _connect argument is reserved for connect() method.
        """
        cmd = self._build_ssh(command)
        try:
            return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as ex:
            if _connect and ex.returncode == 255:
                raise RuntimeWarning(ex.output.strip())
            raise RuntimeError('ssh returned exit status %d:\n%s'
                    % (ex.returncode, ex.output.strip()))

    def fork_cmd(self, command, name=None):
        """Execute command over ssh on remote system, in a child process.
        Do not wait for remote command completion.
        Return child process id.
        """
        if name is None:
            name = command
        cmd = self._build_ssh(command)
        pid = os.fork()
        if (pid != 0):
            # In the parent process
            self._children.append((pid, name))
            return pid
        # In the child process: use os._exit to terminate
        try:
            # Actually ignore output on success, but capture stderr on failure
            subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as ex:
            raise RuntimeError("Child process '%s' failed:\n"
                    'ssh returned exit status %d:\n%s'
                    % (name, ex.returncode, ex.output.strip()))
        os._exit(0)

    def prox_sock(self, port=8474):
        """Connect to the PROX instance on remote system.
        Return a prox_sock object on success, None on failure.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self._ip, port))
            prox = prox_sock(sock)
            self._proxsock.append(prox)
            return prox
        except:
            return None

    def scp_put(self, src, dst):
        """Copy src file from local system to dst on remote system."""
        cmd = [ 'scp',
                '-B',
                '-oStrictHostKeyChecking=no',
                '-oUserKnownHostsFile=/dev/null',
                '-oLogLevel=ERROR' ]
        if self._key is not None:
            cmd.extend(['-i', self._key])
        cmd.append(src)
        remote = ''
        if self._user is not None:
            remote += self._user + '@'
        remote += self._ip + ':' + dst
        cmd.append(remote)
        try:
            # Actually ignore output on success, but capture stderr on failure
            subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as ex:
            raise RuntimeError('scp returned exit status %d:\n%s'
                    % (ex.returncode, ex.output.strip()))

    def _build_ssh(self, command):
        cmd = [ 'ssh',
                '-oBatchMode=yes',
                '-oStrictHostKeyChecking=no',
                '-oUserKnownHostsFile=/dev/null',
                '-oLogLevel=ERROR' ]
        if self._key is not None:
            cmd.extend(['-i', self._key])
        remote = ''
        if self._user is not None:
            remote += self._user + '@'
        remote += self._ip
        cmd.append(remote)
        cmd.append(command)
        return cmd

class prox_sock(object):
    def __init__(self, sock):
        self._sock = sock
        self._rcvd = b''

    def quit(self):
        if self._sock is not None:
            self._send('quit')
            self._sock.close()
            self._sock = None

    def start(self, cores):
        self._send('start %s' % ','.join(map(str, cores)))

    def stop(self, cores):
        self._send('stop %s' % ','.join(map(str, cores)))

    def speed(self, speed, cores, tasks=None):
        if tasks is None:
            tasks = [ 0 ] * len(cores)
        elif len(tasks) != len(cores):
            raise ValueError('cores and tasks must have the same len')
        for (core, task) in zip(cores, tasks):
            self._send('speed %s %s %s' % (core, task, speed))

    def reset_stats(self):
        self._send('reset stats')

    def lat_stats(self, cores, task=0):
        min_lat = 999999999
	max_lat = avg_lat = 0
        self._send('lat stats %s %s' % (','.join(map(str, cores)), task))
        for core in cores:
            stats = self._recv().split(',')
            min_lat = min(int(stats[0]),min_lat)
            max_lat = max(int(stats[1]),max_lat)
            avg_lat += int(stats[2])
        avg_lat = avg_lat/len(cores)
        self._send('stats latency(0).used')
        used = float(self._recv())
        self._send('stats latency(0).total')
        total = float(self._recv())
        return min_lat, max_lat, avg_lat, (used/total)

    def irq_stats(self, core, bucket, task=0):
        self._send('stats task.core(%s).task(%s).irq(%s)' % (core, task, bucket))
        stats = self._recv().split(',')
        return int(stats[0])

    def show_irq_buckets(self, core, task=0):
        rx = tx = drop = tsc = hz = 0
        self._send('show irq buckets %s %s' % (core,task))
        buckets = self._recv().split(';')
	buckets = buckets[:-1]
        return buckets

    def core_stats(self, cores, task=0):
        rx = tx = drop = tsc = hz = rx_non_dp = tx_non_dp = 0
        self._send('dp core stats %s %s' % (','.join(map(str, cores)), task))
        for core in cores:
            stats = self._recv().split(',')
            rx += int(stats[0])
            tx += int(stats[1])
            rx_non_dp += int(stats[2])
            tx_non_dp += int(stats[3])
            drop += int(stats[4])
            tsc = int(stats[5])
            hz = int(stats[6])
        return rx-rx_non_dp, tx-tx_non_dp, drop, tsc, hz

    def set_random(self, cores, task, offset, mask, length):
        self._send('set random %s %s %s %s %s' % (','.join(map(str, cores)), task, offset, mask, length))

    def set_size(self, cores, task, pkt_size):
        self._send('pkt_size %s %s %s' % (','.join(map(str, cores)), task, pkt_size))

    def set_value(self, cores, task, offset, value, length):
        self._send('set value %s %s %s %s %s' % (','.join(map(str, cores)), task, offset, value, length))

    def _send(self, cmd):
        """Append LF and send command to the PROX instance."""
        if self._sock is None:
            raise RuntimeError("PROX socket closed, cannot send '%s'" % cmd)
        self._sock.sendall(cmd.encode() + b'\n')

    def _recv(self):
        """Receive response from PROX instance, and return it with LF removed."""
        if self._sock is None:
            raise RuntimeError("PROX socket closed, cannot receive anymore")
        pos = self._rcvd.find(b'\n')
        while pos == -1:
            self._rcvd += self._sock.recv(256)
            pos = self._rcvd.find(b'\n')
        rsp = self._rcvd[:pos]
        self._rcvd = self._rcvd[pos+1:]
        return rsp.decode()

