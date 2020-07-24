#!/usr/bin/env bash
##
## Copyright (c) 2010-2019 Intel Corporation
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

function save_k8s_envs()
{
	printenv | grep "PCIDEVICE_INTEL_COM" > /opt/rapid/k8s_sriov_device_plugin_envs
}

function create_tun()
{
	mkdir -p /dev/net
	mknod /dev/net/tun c 10 200
	chmod 600 /dev/net/tun
}

save_k8s_envs
create_tun

# Ready for testing
touch /opt/rapid/system_ready_for_rapid

# Start SSH server in background
/usr/sbin/sshd

exec sleep infinity
