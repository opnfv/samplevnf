#!/bin/bash

##
## Copyright (c) 2010-2018 Intel Corporation
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
sudo yum install deltarpm -y
sudo yum update -y
sudo yum-config-manager --add-repo http://www.nasm.us/nasm.repo
sudo yum install git wget gcc unzip libpcap-devel ncurses-devel libedit-devel lua-devel kernel-devel iperf3 pciutils numactl-devel vim tuna openssl-devel nasm -y
# Enabling root ssh access
sudo sed -i '/disable_root: 1/c\disable_root: 0' /etc/cloud/cloud.cfg
# Reboot, before continuing with deploycentos2.sh
sudo reboot
