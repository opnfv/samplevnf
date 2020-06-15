#!/usr/bin/env bash
##
## Copyright (c) 2010-2020 Intel Corporation
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
DPDK_VERSION="20.05"
PROX_COMMIT="7c3217fc16"
PROX_CHECKOUT="git checkout ${PROX_COMMIT}"
## Next line is overruling the PROX_COMMIT and will replace the version with a very specific patch. Should be commented out
## 	if you want to use a committed version of PROX with the COMMIT ID specified above
##Following line has the commit for testing IMIX, IPV6, ... It is the merge of all PROX commits on May 27th 2020
#PROX_CHECKOUT="git fetch \"https://gerrit.opnfv.org/gerrit/samplevnf\" refs/changes/23/70223/1 && git checkout FETCH_HEAD"
MULTI_BUFFER_LIB_VER="0.52"
export RTE_SDK="${BUILD_DIR}/dpdk-${DPDK_VERSION}"
export RTE_TARGET="x86_64-native-linuxapp-gcc"

# By default, do not update OS
OS_UPDATE="n"
# By default, asumming that we are in the VM
K8S_ENV="n"

# If already running from root, no need for sudo
SUDO=""
[ $(id -u) -ne 0 ] && SUDO="sudo"

function os_pkgs_install()
{
	${SUDO} yum install -y deltarpm yum-utils

	# NASM repository for AESNI MB library
	${SUDO} yum-config-manager --add-repo http://www.nasm.us/nasm.repo

	[ "${OS_UPDATE}" == "y" ] && ${SUDO} yum update -y
	${SUDO} yum install -y git wget gcc unzip libpcap-devel ncurses-devel \
			 libedit-devel lua-devel kernel-devel iperf3 pciutils \
			 numactl-devel vim tuna openssl-devel nasm wireshark \
			 make driverctl
}

function k8s_os_pkgs_runtime_install()
{
	[ "${OS_UPDATE}" == "y" ] && ${SUDO} yum update -y

	# Install required dynamically linked libraries + required packages
	${SUDO} yum install -y numactl-libs libpcap openssh openssh-server \
		  openssh-clients sudo
}

function os_cfg()
{
	# huge pages to be used by DPDK
	${SUDO} sh -c '(echo "vm.nr_hugepages = 1024") > /etc/sysctl.conf'

	# Enabling tuned with the realtime-virtual-guest profile
	pushd ${BUILD_DIR} > /dev/null 2>&1
	wget http://linuxsoft.cern.ch/cern/centos/7/rt/x86_64/Packages/tuned-profiles-realtime-2.8.0-5.el7_4.2.noarch.rpm
	wget http://linuxsoft.cern.ch/cern/centos/7/rt/x86_64/Packages/tuned-profiles-nfv-guest-2.8.0-5.el7_4.2.noarch.rpm
	# Install with --nodeps. The latest CentOS cloud images come with a tuned version higher than 2.8. These 2 packages however
	# do not depend on v2.8 and also work with tuned 2.9. Need to be careful in the future
	${SUDO} rpm -ivh ${BUILD_DIR}/tuned-profiles-realtime-2.8.0-5.el7_4.2.noarch.rpm --nodeps
	${SUDO} rpm -ivh ${BUILD_DIR}/tuned-profiles-nfv-guest-2.8.0-5.el7_4.2.noarch.rpm --nodeps
	# Although we do no know how many cores the VM will have when begin deployed for real testing, we already put a number for the
	# isolated CPUs so we can start the realtime-virtual-guest profile. If we don't, that command will fail.
	# When the VM will be instantiated, the check_kernel_params service will check for the real number of cores available to this VM 
	# and update the realtime-virtual-guest-variables.conf accordingly.
	echo "isolated_cores=1" | ${SUDO} tee -a /etc/tuned/realtime-virtual-guest-variables.conf
	${SUDO} tuned-adm profile realtime-virtual-guest

	# Install the check_tuned_params service to make sure that the grub cmd line has the right cpus in isolcpu. The actual number of cpu's
	# assigned to this VM depends on the flavor used. We don't know at this time what that will be.
	${SUDO} chmod +x ${BUILD_DIR}/check_prox_system_setup.sh
	${SUDO} mv ${BUILD_DIR}/check_prox_system_setup.sh /usr/local/libexec/
	${SUDO} mv ${BUILD_DIR}/check-prox-system-setup.service /etc/systemd/system/
	${SUDO} systemctl daemon-reload
	${SUDO} systemctl enable check-prox-system-setup.service
    # Following lines are added to fix the following issue: When the VM gets
    # instantiated, the rapid scripts will try to ssh into the VM to start
    # the testing. Once the script connects with ssh, it starts downloading
    # config files and then start prox, etc... The problem is that when the VM
    # boots, check_prox_system_setup.sh will check for some things and
    # potentially reboot, resulting in losing the ssh connection again.
    # To fix this issue, the following lines are disabling ssh access for the 
    # centos user. The script will not be able to connect to the VM till ssh
    # access is restored after a reboot. Restoring ssh is now done by
    # check-prox-system-setup.service
	printf "\nMatch User centos\n" | ${SUDO} tee -a /etc/ssh/sshd_config
	printf "%sPubkeyAuthentication no\n" "    " | ${SUDO} tee -a /etc/ssh/sshd_config
	printf "%sPasswordAuthentication no\n" "    " | ${SUDO} tee -a /etc/ssh/sshd_config
	popd > /dev/null 2>&1
}

function k8s_os_cfg()
{
	[ ! -f /etc/ssh/ssh_host_rsa_key ] && ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''
	[ ! -f /etc/ssh/ssh_host_ecdsa_key ] && ssh-keygen -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key -N ''
	[ ! -f /etc/ssh/ssh_host_ed25519_key ] && ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''

	[ ! -d /var/run/sshd ] && mkdir -p /var/run/sshd

	USER_NAME="centos"
	USER_PWD="centos"

	useradd -m -d /home/${USER_NAME} -s /bin/bash -U ${USER_NAME}
	echo "${USER_NAME}:${USER_PWD}" | chpasswd
	usermod -aG wheel ${USER_NAME}

	echo "%wheel ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/wheelnopass
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
	${SUDO} make install
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

	${SUDO} ln -s ${RTE_SDK} ${BUILD_DIR}/dpdk

	pushd ${RTE_SDK} > /dev/null 2>&1
	make config T=${RTE_TARGET}
	# Starting from DPDK 20.05, the IGB_UIO driver is not compiled by default.
    # Uncomment the sed command to enable the driver compilation
    #${SUDO} sed -i 's/CONFIG_RTE_EAL_IGB_UIO=n/c\/CONFIG_RTE_EAL_IGB_UIO=y' ${RTE_SDK}/build/.config

	# For Kubernetes environment we use host vfio module
	if [ "${K8S_ENV}" == "y" ]; then
		sed -i 's/CONFIG_RTE_EAL_IGB_UIO=y/CONFIG_RTE_EAL_IGB_UIO=n/g' ${RTE_SDK}/build/.config
		sed -i 's/CONFIG_RTE_LIBRTE_KNI=y/CONFIG_RTE_LIBRTE_KNI=n/g' ${RTE_SDK}/build/.config
		sed -i 's/CONFIG_RTE_KNI_KMOD=y/CONFIG_RTE_KNI_KMOD=n/g' ${RTE_SDK}/build/.config
    fi

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
	${SUDO} cp ${BUILD_DIR}/samplevnf/VNFs/DPPD-PROX/build/app/prox ${BUILD_DIR}/prox
	popd > /dev/null 2>&1
}

function prox_install()
{
	# Clone and compile PROX
	pushd ${BUILD_DIR} > /dev/null 2>&1
	git clone https://git.opnfv.org/samplevnf
	pushd ${BUILD_DIR}/samplevnf/VNFs/DPPD-PROX > /dev/null 2>&1
	bash -c "${PROX_CHECKOUT}"
	popd > /dev/null 2>&1
	prox_compile
	popd > /dev/null 2>&1
}

function port_info_build()
{
	[ ! -d ${BUILD_DIR}/port_info ] && echo "Skipping port_info compilation..." && return

	pushd ${BUILD_DIR}/port_info > /dev/null 2>&1
	make
	${SUDO} cp ${BUILD_DIR}/port_info/build/app/port_info_app ${BUILD_DIR}/port_info_app
	popd > /dev/null 2>&1
}

function create_minimal_install()
{
	ldd ${BUILD_DIR}/prox | awk '{ if ($(NF-1) != "=>") print $(NF-1) }' >> ${BUILD_DIR}/list_of_install_components

	echo "${BUILD_DIR}/prox" >> ${BUILD_DIR}/list_of_install_components
	echo "${BUILD_DIR}/port_info_app" >> ${BUILD_DIR}/list_of_install_components

	tar -czvhf ${BUILD_DIR}/install_components.tgz -T ${BUILD_DIR}/list_of_install_components
}

function cleanup()
{
	${SUDO} yum autoremove -y
	${SUDO} yum clean all
	${SUDO} rm -rf /var/cache/yum
}

function k8s_runtime_image()
{
	k8s_os_pkgs_runtime_install
	k8s_os_cfg
	cleanup

	pushd / > /dev/null 2>&1
	tar -xvf ${BUILD_DIR}/install_components.tgz --skip-old-files
	popd > /dev/null 2>&1

	ldconfig

	#rm -rf ${BUILD_DIR}/install_components.tgz
}

function print_usage()
{
	echo "Usage: ${0} [OPTIONS] [COMMAND]"
	echo "Options:"
	echo "   -u, --update     Full OS update"
	echo "   -k, --kubernetes Build for Kubernetes environment"
	echo "Commands:"
	echo "   deploy           Run through all deployment steps"
	echo "   compile          PROX compile only"
	echo "   runtime_image    Apply runtime configuration only"
}

COMMAND=""
# Parse options and comman
for opt in "$@"; do
	case ${opt} in
		-u|--update)
		echo 'Full OS update will be done!'
		OS_UPDATE="y"
		;;
		-k|--kubernetes)
		echo "Kubernetes environment is set!"
		K8S_ENV="y"
		;;
		compile)
		COMMAND="compile"
		;;
		runtime_image)
		COMMAND="runtime_image"
		;;
		deploy)
		COMMAND="deploy"
		;;
		*)
		echo "Unknown option/command ${opt}"
		print_usage
		exit 1
		;;
	esac
done

if [ "${COMMAND}" == "compile" ]; then
	echo "PROX compile only..."
	prox_compile
elif [ "${COMMAND}" == "runtime_image" ]; then
	echo "Runtime image intallation and configuration..."
	k8s_runtime_image
elif [ "${COMMAND}" == "deploy" ]; then
	[ ! -d ${BUILD_DIR} ] && ${SUDO} mkdir -p ${BUILD_DIR}
	${SUDO} chmod 0777 ${BUILD_DIR}

	os_pkgs_install

	if [ "${K8S_ENV}" == "y" ]; then
		k8s_os_cfg
	else
		os_cfg
	fi

	mblib_install
	dpdk_install
	prox_install

	if [ "${K8S_ENV}" == "y" ]; then
		port_info_build
		create_minimal_install
	fi

	cleanup
else
	print_usage
fi
