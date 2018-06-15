#!/bin/bash

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

link="$(ip -o link | grep MACADDRESS |cut -d":" -f 2)"
if [ -n "$link" ];
then
	echo Need to bind
	/root/dpdk/usertools/dpdk-devbind.py --force --bind igb_uio $(/root/dpdk/usertools/dpdk-devbind.py --status |grep  $link | cut -d" " -f 1)
else
       echo Assuming port is already bound to DPDK
fi
exit 0
