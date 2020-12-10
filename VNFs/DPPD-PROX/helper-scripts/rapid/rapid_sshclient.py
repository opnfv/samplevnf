##
## Copyright (c) 2019 Intel Corporation
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

import paramiko
import logging

class SSHClient:
    """Wrapper class for paramiko module to connect via SSH
    """
    _log = None

    _ip = None
    _user = None
    _rsa_private_key = None
    _timeout = None
    _ssh = None
    _connected = False

    _output = None
    _error = None

    def __init__(self, ip=None, user=None, rsa_private_key=None, timeout=15, logger_name=None):
        self._ip = ip
        self._user = user
        self._rsa_private_key = rsa_private_key
        self._timeout = timeout

        if (logger_name is not None):
            self._log = logging.getLogger(logger_name)

        self._connected = False

    def set_credentials(self, ip, user, rsa_private_key):
        self._ip = ip
        self._user = user
        self._rsa_private_key = rsa_private_key

    def connect(self):
        if self._connected:
            if (self._log is not None):
                self._log.debug("Already connected!")
            return

        if ((self._ip is None) or (self._user is None) or
            (self._rsa_private_key is None)):
            if (self._log is not None):
                self._log.error("Wrong parameter! IP %s, user %s, RSA private key %s"
                                % (self._ip, self._user, self._rsa_private_key))
            self._connected = False
            return

        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key = paramiko.RSAKey.from_private_key_file(self._rsa_private_key)

        try:
            self._ssh.connect(hostname = self._ip, username = self._user, pkey = private_key)
        except Exception as e:
            if (self._log is not None):
                self._log.error("Failed to connect to the host! IP %s, user %s, RSA private key %s\n%s"
                                % (self._ip, self._user, self._rsa_private_key, e))
            self._connected = False
            self._ssh.close()
            return

        self._connected = True

    def disconnect(self):
        if self._connected:
            self._connected = False
            self._ssh.close()

    def run_cmd(self, cmd):
        self.connect()

        if self._connected is not True:
            return -1

        try:
            ret = 0
            _stdin, stdout, stderr = self._ssh.exec_command(cmd, timeout = self._timeout)
            self._output = stdout.read()
            self._error = stderr.read()
        except Exception as e:
            if (self._log is not None):
                self._log.error("Failed to execute command! IP %s, cmd %s\n%s"
                                % (self._ip, cmd, e))
            ret = -1

        self.disconnect()

        return ret

    def get_output(self):
        return self._output

    def get_error(self):
        return self._error
