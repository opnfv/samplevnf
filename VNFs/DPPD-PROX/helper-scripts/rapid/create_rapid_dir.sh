#!/usr/bin/env bash
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

# Directory for package build
BUILD_DIR="/opt/rapid"

# If already running from root, no need for sudo
SUDO=""
[ $(id -u) -ne 0 ] && SUDO="sudo"


[ ! -d ${BUILD_DIR} ] && ${SUDO} mkdir -p ${BUILD_DIR}
${SUDO} chmod 0777 ${BUILD_DIR}

