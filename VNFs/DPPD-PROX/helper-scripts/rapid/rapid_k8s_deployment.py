##
## Copyright (c) 2019-2020 Intel Corporation
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

import sys
from kubernetes import client, config
try:
    import configparser
except ImportError:
    # Python 2.x fallback
    import ConfigParser as configparser
import logging
from logging import handlers

from rapid_k8s_pod import Pod

class K8sDeployment:
    """Deployment class to create containers for test execution in Kubernetes
    environment. 
    """
    LOG_FILE_NAME = "createrapidk8s.log"
    SSH_PRIVATE_KEY = "./rapid_rsa_key"
    SSH_USER = "centos"

    POD_YAML_TEMPLATE_FILE_NAME = "pod-rapid.yaml"

    _log = None
    _create_config = None
    _runtime_config = None
    _total_number_of_pods = 0
    _pods = []

    def __init__(self):
        # Configure logger
        self._log = logging.getLogger("k8srapid")
        self._log.setLevel(logging.DEBUG)

        console_formatter = logging.Formatter("%(message)s")
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(console_formatter)

        file_formatter = logging.Formatter("%(asctime)s - "
                                           "%(levelname)s - "
                                           "%(message)s")
        file_handler = logging.handlers.RotatingFileHandler(self.LOG_FILE_NAME,
                                                            backupCount=10)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(file_formatter)

        self._log.addHandler(file_handler)
        self._log.addHandler(console_handler)

        # Initialize k8s plugin
        config.load_kube_config()
        Pod.k8s_CoreV1Api = client.CoreV1Api()

    def load_create_config(self, config_file_name):
        """Read and parse configuration file for the test environment.
        """
        self._log.info("Loading configuration file %s", config_file_name)
        self._create_config = configparser.RawConfigParser()
        try:
            self._create_config.read(config_file_name)
        except Exception as e:
            self._log.error("Failed to read config file!\n%s\n" % e)
            return -1

        # Now parse config file content
        # Parse [DEFAULT] section
        if self._create_config.has_option("DEFAULT", "total_number_of_pods"):
            self._total_number_of_pods = self._create_config.getint(
                "DEFAULT", "total_number_of_pods")
        else:
            self._log.error("No option total_number_of_pods in DEFAULT section")
            return -1

        self._log.debug("Total number of pods %d" % self._total_number_of_pods)

        # Parse [PODx] sections
        for i in range(1, int(self._total_number_of_pods) + 1):
            # Search for POD name
            if self._create_config.has_option("POD%d" % i,
                                              "name"):
                pod_name = self._create_config.get(
                    "POD%d" % i, "name")
            else:
                pod_name = "pod-rapid-%d" % i

            # Search for POD hostname
            if self._create_config.has_option("POD%d" % i,
                                              "nodeSelector_hostname"):
                pod_nodeselector_hostname = self._create_config.get(
                    "POD%d" % i, "nodeSelector_hostname")
            else:
                pod_nodeselector_hostname = None

            # Search for POD dataplane static IP
            if self._create_config.has_option("POD%d" % i,
                                              "dp_ip"):
                pod_dp_ip = self._create_config.get(
                    "POD%d" % i, "dp_ip")
            else:
                pod_dp_ip = None

            # Search for POD dataplane subnet
            if self._create_config.has_option("POD%d" % i,
                                              "dp_subnet"):
                pod_dp_subnet = self._create_config.get(
                    "POD%d" % i, "dp_subnet")
            else:
                pod_dp_subnet = "24"

            pod = Pod(pod_name)
            pod.set_nodeselector(pod_nodeselector_hostname)
            pod.set_dp_ip(pod_dp_ip)
            pod.set_dp_subnet(pod_dp_subnet)
            pod.set_id(i)

            # Add POD to the list of PODs which need to be created
            self._pods.append(pod)

        return 0

    def create_pods(self):
        """ Create test PODs and wait for them to start.
        Collect information for tests to run.
        """
        self._log.info("Creating PODs...")

        # Create PODs using template from yaml file
        for pod in self._pods:
            self._log.info("Creating POD %s...", pod.get_name())
            pod.create_from_yaml(K8sDeployment.POD_YAML_TEMPLATE_FILE_NAME)

        # Wait for PODs to start
        for pod in self._pods:
            pod.wait_for_start()

        # Collect information from started PODs for test execution
        for pod in self._pods:
            pod.set_ssh_credentials(K8sDeployment.SSH_USER, K8sDeployment.SSH_PRIVATE_KEY)
            pod.get_sriov_dev_mac()

    def save_runtime_config(self, config_file_name):
        self._log.info("Saving config %s for runrapid script...",
                       config_file_name)
        self._runtime_config = configparser.RawConfigParser()

        # Section [DEFAULT]
#        self._runtime_config.set("DEFAULT",
#                                 "total_number_of_test_machines",
#                                 self._total_number_of_pods)

        # Section [ssh]
        self._runtime_config.add_section("ssh")
        self._runtime_config.set("ssh",
                                 "key",
                                 K8sDeployment.SSH_PRIVATE_KEY)
        self._runtime_config.set("ssh",
                                 "user",
                                 K8sDeployment.SSH_USER)

        # Section [rapid]
        self._runtime_config.add_section("rapid")
        self._runtime_config.set("rapid",
                                 "total_number_of_machines",
                                 self._total_number_of_pods)

        # Export information about each pod
        # Sections [Mx]
        for pod in self._pods:
            self._runtime_config.add_section("M%d" % pod.get_id())
            self._runtime_config.set("M%d" % pod.get_id(),
                                     "admin_ip", pod.get_admin_ip())
            self._runtime_config.set("M%d" % pod.get_id(),
                                     "dp_mac1", pod.get_dp_mac())
            self._runtime_config.set("M%d" % pod.get_id(),
                                     "dp_pci_dev", pod.get_dp_pci_dev())
            self._runtime_config.set("M%d" % pod.get_id(),
                                     "dp_ip1", pod.get_dp_ip() + "/" +
                                     pod.get_dp_subnet())

        # Section [Varia]
        self._runtime_config.add_section("Varia")
        self._runtime_config.set("Varia",
                                 "vim",
                                 "kubernetes")

        # Write runtime config file
        with open(config_file_name, "w") as file:
            self._runtime_config.write(file)

    def delete_pods(self):
        for pod in self._pods:
            pod.terminate()
