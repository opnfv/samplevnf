#!/usr/bin/env python2.7

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

from k8sdeployment import K8sDeployment

# Config file name for deployment creation
CREATE_CONFIG_FILE_NAME = "rapid.pods"

# Config file name for runrapid script
RUN_CONFIG_FILE_NAME = "rapid.env"

# Create a new deployment
deployment = K8sDeployment()

# Load config file with test environment description
deployment.load_create_config(CREATE_CONFIG_FILE_NAME)

# Create PODs for test
deployment.create_pods()

# Save config file for runrapid script
deployment.save_runtime_config(RUN_CONFIG_FILE_NAME)
