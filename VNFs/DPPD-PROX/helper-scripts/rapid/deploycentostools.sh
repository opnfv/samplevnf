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

BUILD_DIR="/opt/rapid"
WORK_DIR="/home/centos" # Directory where the packer tool has copied some files (e.g. check_prox_system_setup.sh)
			# Runtime scripts are assuming ${WORK_DIR} as the directory for PROX. Check the rundir variable in runrapid.py. Should be the same!
			# This variable is defined in 4 different places and should have the same value: centos.json, deploycentos.sh, check_prox_system_setup.sh and runrapid.py
DPDK_VERSION="19.05"
PROX_COMMIT="f456ab65"
MULTI_BUFFER_LIB_VER="0.52"
export RTE_SDK="${BUILD_DIR}/dpdk-${DPDK_VERSION}"
export RTE_TARGET="x86_64-native-linuxapp-gcc"

function os_pkgs_install()
{
	sudo yum install -y deltarpm yum-utils
	# NASM repository for AESNI MB library
	sudo yum-config-manager --add-repo http://www.nasm.us/nasm.repo

	sudo yum update -y
	sudo yum install -y git wget gcc unzip libpcap-devel ncurses-devel \
			 libedit-devel lua-devel kernel-devel iperf3 pciutils \
			 numactl-devel vim tuna openssl-devel nasm wireshark
}

function os_cfg()
{
	# huge pages to be used by DPDK
	sudo sh -c '(echo "vm.nr_hugepages = 1024") > /etc/sysctl.conf'

	# Enabling tuned with the realtime-virtual-guest profile
	pushd ${BUILD_DIR} > /dev/null 2>&1
	wget http://linuxsoft.cern.ch/cern/centos/7/rt/x86_64/Packages/tuned-profiles-realtime-2.8.0-5.el7_4.2.noarch.rpm
	wget http://linuxsoft.cern.ch/cern/centos/7/rt/x86_64/Packages/tuned-profiles-nfv-guest-2.8.0-5.el7_4.2.noarch.rpm
	# Install with --nodeps. The latest CentOS cloud images come with a tuned version higher than 2.8. These 2 packages however
	# do not depend on v2.8 and also work with tuned 2.9. Need to be careful in the future
	sudo rpm -ivh ${BUILD_DIR}/tuned-profiles-realtime-2.8.0-5.el7_4.2.noarch.rpm --nodeps
	sudo rpm -ivh ${BUILD_DIR}/tuned-profiles-nfv-guest-2.8.0-5.el7_4.2.noarch.rpm --nodeps
	# Although we do no know how many cores the VM will have when begin deployed for real testing, we already put a number for the
	# isolated CPUs so we can start the realtime-virtual-guest profile. If we don't, that command will fail.
	# When the VM will be instantiated, the check_kernel_params service will check for the real number of cores available to this VM 
	# and update the realtime-virtual-guest-variables.conf accordingly.
	echo "isolated_cores=1" | sudo tee -a /etc/tuned/realtime-virtual-guest-variables.conf
	sudo tuned-adm profile realtime-virtual-guest

	# Install the check_tuned_params service to make sure that the grub cmd line has the right cpus in isolcpu. The actual number of cpu's
	# assigned to this VM depends on the flavor used. We don't know at this time what that will be.
	sudo chmod +x ${WORK_DIR}/check_prox_system_setup.sh
	sudo cp -r ${WORK_DIR}/check_prox_system_setup.sh /usr/local/libexec/
	sudo cp -r ${WORK_DIR}/check-prox-system-setup.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable check-prox-system-setup.service

	popd > /dev/null 2>&1
}

function mblib_install()
{
	export AESNI_MULTI_BUFFER_LIB_PATH="${BUILD_DIR}/intel-ipsec-mb-${MULTI_BUFFER_LIB_VER}"

	# Downloading the Multi-buffer library. Note that the version to download is linked to the DPDK version being used
	pushd ${BUILD_DIR} > /dev/null 2>&1
	wget https://github.com/01org/intel-ipsec-mb/archive/v${MULTI_BUFFER_LIB_VER}.zip
	unzip v${MULTI_BUFFER_LIB_VER}.zip
	pushd ${AESNI_MULTI_BUFFER_LIB_PATH}
	make -j`getconf _NPROCESSORS_ONLN`
	sudo make install
	popd > /dev/null 2>&1
	popd > /dev/null 2>&1
}

function dpdk_install()
{
	# Build DPDK for the latest kernel installed
	LATEST_KERNEL_INSTALLED=`ls -v1 /lib/modules/ | tail -1`
	export RTE_KERNELDIR="/lib/modules/${LATEST_KERNEL_INSTALLED}/build"

	# Get and compile DPDK
	pushd ${BUILD_DIR} > /dev/null 2>&1
	wget http://fast.dpdk.org/rel/dpdk-${DPDK_VERSION}.tar.xz
	tar -xf ./dpdk-${DPDK_VERSION}.tar.xz
	popd > /dev/null 2>&1

	sudo ln -s ${RTE_SDK} ${WORK_DIR}/dpdk

	pushd ${RTE_SDK} > /dev/null 2>&1
	make config T=${RTE_TARGET}
	# The next sed lines make sure that we can compile DPDK 17.11 with a relatively new OS. Using a newer DPDK (18.5) should also resolve this issue
	#sudo sed -i '/CONFIG_RTE_LIBRTE_KNI=y/c\CONFIG_RTE_LIBRTE_KNI=n' ${RTE_SDK}/build/.config
	#sudo sed -i '/CONFIG_RTE_LIBRTE_PMD_KNI=y/c\CONFIG_RTE_LIBRTE_PMD_KNI=n' ${RTE_SDK}/build/.config
	#sudo sed -i '/CONFIG_RTE_KNI_KMOD=y/c\CONFIG_RTE_KNI_KMOD=n' ${RTE_SDK}/build/.config
	#sudo sed -i '/CONFIG_RTE_KNI_PREEMPT_DEFAULT=y/c\CONFIG_RTE_KNI_PREEMPT_DEFAULT=n' ${RTE_SDK}/build/.config
	# Compile with MB library
	sed -i '/CONFIG_RTE_LIBRTE_PMD_AESNI_MB=n/c\CONFIG_RTE_LIBRTE_PMD_AESNI_MB=y' ${RTE_SDK}/build/.config
	make -j`getconf _NPROCESSORS_ONLN`
	ln -s ${RTE_SDK}/build ${RTE_SDK}/${RTE_TARGET}
	popd > /dev/null 2>&1
}

function prox_compile()
{
	# Compile PROX
	pushd ${BUILD_DIR}/samplevnf/VNFs/DPPD-PROX
	make -j`getconf _NPROCESSORS_ONLN`
	popd > /dev/null 2>&1
}

function prox_install()
{
	# Clone and compile PROX
	pushd ${BUILD_DIR} > /dev/null 2>&1
	git clone https://git.opnfv.org/samplevnf
	pushd ${BUILD_DIR}/samplevnf/VNFs/DPPD-PROX
	git checkout ${PROX_COMMIT}
	popd > /dev/null 2>&1
	prox_compile
	sudo ln -s ${BUILD_DIR}/samplevnf/VNFs/DPPD-PROX ${WORK_DIR}/prox
	popd > /dev/null 2>&1
}

if [ "$1" == "compile" ]; then
	prox_compile
else
	[ ! -d ${BUILD_DIR} ] && sudo mkdir -p ${BUILD_DIR}
	sudo chmod 0777 ${BUILD_DIR}

	os_pkgs_install
	os_cfg
	mblib_install
	dpdk_install
	prox_install
fi
