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

from os import path
import time, yaml
import logging
from kubernetes import client, config

from rapid_sshclient import SSHClient

class Pod:
    """Class which represents test pods.
    For example with traffic gen, forward/swap applications, etc
    """
    k8s_CoreV1Api = None

    _log = None

    _name = "pod"
    _namespace = "default"
    _nodeSelector_hostname = None
    _last_status = None
    _id = None
    _admin_ip = None
    _dp_ip = None
    _dp_subnet = None

    _ssh_client = None

    _sriov_vf = None
    _sriov_vf_mac = None

    def __init__(self, name, namespace = "default", logger_name = "k8srapid"):
        self._log = logging.getLogger(logger_name)

        self._name = name
        self._namespace = namespace
        self._ssh_client = SSHClient(logger_name = logger_name)

    def __del__(self):
        """Destroy POD. Do a cleanup.
        """
        if self._ssh_client is not None:
            self._ssh_client.disconnect()

    def create_from_yaml(self, file_name):
        """Load POD description from yaml file.
        """
        with open(path.join(path.dirname(__file__), file_name)) as yaml_file:
            self.body = yaml.safe_load(yaml_file)

            self.body["metadata"]["name"] = self._name

            if (self._nodeSelector_hostname is not None):
                if ("nodeSelector" not in self.body["spec"]):
                    self.body["spec"]["nodeSelector"] = {}
                self.body["spec"]["nodeSelector"]["kubernetes.io/hostname"] = self._nodeSelector_hostname
            self._log.debug("Creating POD, body:\n%s" % self.body)

            try:
                self.k8s_CoreV1Api.create_namespaced_pod(body = self.body,
                                                namespace = self._namespace)
            except client.rest.ApiException as e:
                self._log.error("Couldn't create POD %s!\n%s\n" % (self._name, e))

    def terminate(self):
        """Terminate POD. Close SSH connection.
        """
        if self._ssh_client is not None:
            self._ssh_client.disconnect()

        try:
            self.k8s_CoreV1Api.delete_namespaced_pod(name = self._name,
                                                     namespace = self._namespace)
        except client.rest.ApiException as e:
            if e.reason != "Not Found":
                self._log.error("Couldn't delete POD %s!\n%s\n" % (self._name, e.reason))

    def update_admin_ip(self):
        """Check for admin IP address assigned by k8s.
        """
        try:
            pod = self.k8s_CoreV1Api.read_namespaced_pod_status(name = self._name, namespace = self._namespace)
            self._admin_ip = pod.status.pod_ip
        except client.rest.ApiException as e:
            self._log.error("Couldn't update POD %s admin IP!\n%s\n" % (self._name, e))

    def wait_for_start(self):
        """Wait for POD to start.
        """
        self._log.info("Waiting for POD %s to start..." % self._name)
        while True:
            self.get_status()
            if (self._last_status == "Running" or self._last_status == "Failed"
                or self._last_status == "Unknown"):
                break
            else:
                time.sleep(3)

        self.update_admin_ip()

        return self._last_status

    def ssh_run_cmd(self, cmd):
        """Execute command for POD via SSH connection.
        SSH credentials should be configured before use of this function.
        """
        self._ssh_client.run_cmd(cmd)

    def get_name(self):
        return self._name

    def get_admin_ip(self):
        return self._admin_ip

    def get_dp_ip(self):
        return self._dp_ip

    def get_dp_subnet(self):
        return self._dp_subnet

    def get_dp_mac(self):
        return self._sriov_vf_mac

    def get_dp_pci_dev(self):
        return self._sriov_vf

    def get_id(self):
        return self._id

    def get_status(self):
        """Get current status fro the pod.
        """
        try:
            pod = self.k8s_CoreV1Api.read_namespaced_pod_status(name = self._name,
                                                                namespace = self._namespace)
        except client.rest.ApiException as e:
            self._log.error("Couldn't read POD %s status!\n%s\n" % (self._name, e))

        self._last_status = pod.status.phase
        return self._last_status

    def get_sriov_dev_mac(self):
        """Get assigned by k8s SRIOV network device plugin SRIOV VF devices.
        Return 0 in case of sucessfull configuration.
        Otherwise return -1.
        """
        self._log.info("Checking assigned SRIOV VF for POD %s" % self._name)
        ret = self._ssh_client.run_cmd("cat /opt/rapid/k8s_sriov_device_plugin_envs")
        if ret != 0:
            self._log.error("Failed to check assigned SRIOV VF!"
                            "Error %s" % self._ssh_client.get_error())
            return -1

        cmd_output = self._ssh_client.get_output().decode("utf-8").rstrip()
        self._log.debug("Environment variable %s" % cmd_output)

        # Parse environment variable
        cmd_output = cmd_output.split("=")[1]
        self._sriov_vf = cmd_output.split(",")[0]
        self._log.debug("Using first SRIOV VF %s" % self._sriov_vf)

        self._log.info("Getting MAC address for assigned SRIOV VF %s" % self._sriov_vf)
        self._ssh_client.run_cmd("sudo /opt/rapid/port_info_app -n 4 -w %s" % self._sriov_vf)
        if ret != 0:
            self._log.error("Failed to get MAC address!"
                            "Error %s" % self._ssh_client.get_error())
            return -1

        # Parse MAC address
        cmd_output = self._ssh_client.get_output().decode("utf-8").rstrip()
        self._log.debug(cmd_output)
        cmd_output = cmd_output.splitlines()
        for line in cmd_output:
            if line.startswith("Port 0 MAC: "):
                self._sriov_vf_mac = line[12:]

        self._log.debug("MAC %s" % self._sriov_vf_mac)

    def set_dp_ip(self, dp_ip):
        self._dp_ip = dp_ip

    def set_dp_subnet(self, dp_subnet):
        self._dp_subnet = dp_subnet

    def set_id(self, pod_id):
        self._id = pod_id

    def set_nodeselector(self, hostname):
        """Set hostname on which POD will be executed.
        """
        self._nodeSelector_hostname = hostname

    def set_ssh_credentials(self, user, rsa_private_key):
        """Set SSH credentials for the SSH connection to the POD.
        """
        self.update_admin_ip()
        self._ssh_client.set_credentials(ip = self._admin_ip,
                                         user = user,
                                         rsa_private_key = rsa_private_key)
