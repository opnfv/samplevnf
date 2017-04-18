#! /bin/bash
#
# Copyright (c) 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

cd $(dirname ${BASH_SOURCE[0]})/..
export VNF_CORE=$PWD
echo "------------------------------------------------------------------------------"
echo " VNF_CORE exported as $VNF_CORE"
echo "------------------------------------------------------------------------------"

HUGEPGSZ=`cat /proc/meminfo  | grep Hugepagesize | cut -d : -f 2 | tr -d ' '`
MODPROBE="/sbin/modprobe"
INSMOD="/sbin/insmod"
DPDK_DOWNLOAD="http://dpdk.org/browse/dpdk/snapshot/dpdk-16.04.zip"
DPDK_DIR=$VNF_CORE/dpdk

#
# Sets QUIT variable so script will finish.
#
quit()
{
	QUIT=$1
}

# Shortcut for quit.
q()
{
	quit
}

setup_http_proxy()
{
	while true; do
		echo
		read -p "Enter Proxy : " proxy
		export http_proxy=$proxy
		export https_proxy=$proxy
		echo "Acquire::http::proxy \"$http_proxy\";" | sudo tee -a /etc/apt/apt.conf > /dev/null
		echo "Acquire::https::proxy \"$http_proxy\";" | sudo tee -a /etc/apt/apt.conf > /dev/null

		wget -T 20 -t 3 --spider http://www.google.com > /dev/null 2>&1
		if [ "$?" != 0 ]; then
			echo -e "No Internet connection. Proxy incorrect? Try again"
			echo -e "eg: http://<proxy>:<port>"
			exit 1
		fi
	return
	done
	echo "Network connectivity successful."
}

step_1()
{
        TITLE="Environment setup."
        CONFIG_NUM=1
        TEXT[1]="Check OS and network connection"
        FUNC[1]="setup_env"
}
setup_env()
{
	# a. Check for OS dependencies
	source /etc/os-release
	if [[ $VERSION_ID != "16.04" ]] ; then
		echo "WARNING: It is recommended to use Ubuntu 16.04..Your version is "$VERSION_ID
	else
		echo "Ubuntu 16.04 OS requirement met..."
	fi
	echo
	echo "Checking network connectivity..."
	# b. Check for internet connections
	wget -T 20 -t 3 --spider http://www.google.com > /dev/null 2>&1
	if [ "$?" != 0 ]; then
		while true; do
			read -p "No Internet connection. Are you behind a proxy (y/n)? " yn
			case $yn in
				[Yy]* ) $SETUP_PROXY ; return;;
				[Nn]* ) echo "Please check your internet connection..." ; exit;;
				* ) "Please answer yes or no.";;
			esac
		done
	fi
	echo "Network connectivity successful."
}

step_2()
{
        TITLE="Download and Install"
        CONFIG_NUM=1
        TEXT[1]="Agree to download"
        FUNC[1]="get_agreement_download"
	TEXT[2]="Download packages"
	FUNC[2]="install_libs"
	TEXT[3]="Download DPDK zip"
	FUNC[3]="download_dpdk_zip"
	TEXT[4]="Build and Install DPDK"
	FUNC[4]="install_dpdk"
	TEXT[5]="Setup hugepages"
	FUNC[5]="setup_hugepages"
}
get_agreement_download()
{
	echo
	echo "List of packages needed for VNFs build and installation:"
	echo "-------------------------------------------------------"
	echo "1. DPDK version 16.04"
	echo "2. build-essential"
	echo "3. linux-headers-generic"
	echo "4. git"
	echo "5. unzip"
	echo "6. libpcap-dev"
	echo "7. make"
	echo "8. and other library dependencies"
	while true; do
		read -p "We need download above mentioned package. Press (y/n) to continue? " yn
		case $yn in
			[Yy]* )
				touch .agree
				return;;
			[Nn]* ) exit;;
			* ) "Please answer yes or no.";;
		esac
	done
}

install_libs()
{
	echo "Install libs needed to build and run VNFs..."
	file_name=".agree"
	if [ ! -e "$file_name" ]; then
		echo "Please choose option '2.Agree to download' first"
		return
	fi
	file_name=".download"
	if [ -e "$file_name" ]; then
		clear
		return
	fi
	sudo apt-get update
	sudo apt-get -y install build-essential linux-headers-$(uname -r) git unzip libpcap0.8-dev gcc \
		make libc6 libc6-dev g++-multilib libzmq3-dev libcurl4-openssl-dev
	touch .download
}

download_dpdk_zip()
{
	echo "Download DPDK zip"
	file_name=".agree"
	if [ ! -e "$file_name" ]; then
		echo "Please choose option '2.Agree to download' first"
		return
	fi
	rm -rf $DPDK_DIR
	if [ ! -e ${DPDK_DOWNLOAD##*/} ] ; then
		wget ${DPDK_DOWNLOAD}
	fi
	unzip -o ${DPDK_DOWNLOAD##*/}
	mv $VNF_CORE/dpdk-16.04 $VNF_CORE/dpdk
}

install_dpdk()
{
	echo "Build DPDK"

	if [ ! -d "$DPDK_DIR" ]; then
     echo "Please choose option '4 Download DPDK zip'"
     return
	fi

	export RTE_TARGET=x86_64-native-linuxapp-gcc

	pushd $DPDK_DIR
	echo "Apply dpdk custom patches..."
	patch -p0 < $VNF_CORE/patches/dpdk_custom_patch/rte_pipeline.patch
	patch -p1 < $VNF_CORE/patches/dpdk_custom_patch/i40e-fix-link-management.patch
	patch -p1 < $VNF_CORE/patches/dpdk_custom_patch/i40e-fix-Rx-hang-when-disable-LLDP.patch
	patch -p1 < $VNF_CORE/patches/dpdk_custom_patch/i40e-fix-link-status-change-interrupt.patch
	patch -p1 < $VNF_CORE/patches/dpdk_custom_patch/i40e-fix-VF-bonded-device-link-down.patch

	make -j install T=$RTE_TARGET
	if [ $? -ne 0 ] ; then
		echo "Failed to build dpdk, please check the errors."
		return
	fi
	sudo modinfo igb_uio
	if [ $? -ne 0 ] ; then
		sudo $MODPROBE -v uio
		sudo $INSMOD $RTE_TARGET/kmod/igb_uio.ko
		sudo cp -f $RTE_TARGET/kmod/igb_uio.ko /lib/modules/$(uname -r)
		echo "uio" | sudo tee -a /etc/modules
		echo "igb_uio" | sudo tee -a /etc/modules
		sudo depmod
	fi
	popd
}

setup_hugepages()
{
	#----
	Pages=16
	if [[ "$HUGEPGSZ" = "2048kB" ]] ; then
		Pages=8192
	fi
	if [ ! "`grep nr_hugepages /etc/sysctl.conf`" ] ; then
		echo "vm.nr_hugepages=$Pages" | sudo tee /etc/sysctl.conf
	fi
	sudo sysctl -p

	sudo service procps start

	grep -s '/dev/hugepages' /proc/mounts
	if [ $? -ne 0 ] ; then
		echo "Creating /mnt/huge and mounting as hugetlbfs"
		sudo mkdir -p /mnt/huge
		sudo mount -t hugetlbfs nodev /mnt/huge
		echo "nodev /mnt/huge hugetlbfs defaults 0 0" | sudo tee -a /etc/fstab > /dev/null
        fi
}

step_3()
{
        TITLE="Build VNFs"
        CONFIG_NUM=1
				TEXT[1]="Build all VNFs (vACL, vCGNAPT, vFW)"
        FUNC[1]="build_vnfs"
}

build_vnfs()
{
	export RTE_SDK=$DPDK_DIR
	export RTE_TARGET=x86_64-native-linuxapp-gcc
	pushd $VNF_CORE
	make clean
	make || { echo -e "\nVNF: Make failed\n"; }
	popd
}

SETUP_PROXY="setup_http_proxy"
STEPS[1]="step_1"
STEPS[2]="step_2"
STEPS[3]="step_3"

QUIT=0

clear

echo -n "Checking for user permission.. "
sudo -n true
if [ $? -ne 0 ]; then
   echo "Password-less sudo user must run this script" 1>&2
   exit 1
fi
echo "Done"
clear

while [ "$QUIT" == "0" ]; do
        OPTION_NUM=1
        for s in $(seq ${#STEPS[@]}) ; do
                ${STEPS[s]}

                echo "----------------------------------------------------------"
                echo " Step $s: ${TITLE}"
                echo "----------------------------------------------------------"

                for i in $(seq ${#TEXT[@]}) ; do
                        echo "[$OPTION_NUM] ${TEXT[i]}"
                        OPTIONS[$OPTION_NUM]=${FUNC[i]}
                        let "OPTION_NUM+=1"
                done

                # Clear TEXT and FUNC arrays before next step
                unset TEXT
                unset FUNC

                echo ""
        done

        echo "[$OPTION_NUM] Exit Script"
        OPTIONS[$OPTION_NUM]="quit"
        echo ""
        echo -n "Option: "
        read our_entry
        echo ""
        ${OPTIONS[our_entry]} ${our_entry}

        if [ "$QUIT" == "0" ] ; then
                echo
                echo -n "Press enter to continue ..."; read
                clear
                continue
                exit
        fi
        echo "Installation successfully complete."
done
