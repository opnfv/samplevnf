#!/usr/bin/env python3

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

import argparse
from rapid_k8s_deployment import K8sDeployment

# Config file name for deployment creation
CREATE_CONFIG_FILE_NAME = "rapid.pods"

# Config file name for runrapid script
RUN_CONFIG_FILE_NAME = "rapid.env"

def main():
    # Parse command line arguments
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-c", "--clean", action = "store_true",
                           help = "Terminate pod-rapid-* PODs. "
                           "Clean up cluster before or after the testing.")
    args = argparser.parse_args()

    # Create a new deployment
    deployment = K8sDeployment()

    # Load config file with test environment description
    deployment.load_create_config(CREATE_CONFIG_FILE_NAME)

    if args.clean:
        deployment.delete_pods()
        return

    # Create PODs for test
    deployment.create_pods()

    # Save config file for runrapid script
    deployment.save_runtime_config(RUN_CONFIG_FILE_NAME)

if __name__ == "__main__":
    main()
