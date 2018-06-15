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
sudo sh -c '(echo "export RTE_TARGET=\"build\"";echo "export RTE_SDK=\"/root/dpdk\"";echo "export AESNI_MULTI_BUFFER_LIB_PATH=\"/home/centos/intel-ipsec-mb-0.48\"";) >> /root/.bashrc'
sudo yum install deltarpm -y
sudo yum update -y
sudo yum-config-manager --add-repo http://www.nasm.us/nasm.repo
sudo yum install git wget gcc unzip libpcap-devel ncurses-devel libedit-devel lua-devel kernel-devel iperf3 pciutils numactl-devel vim tuna openssl-devel nasm -y
# Enabling root ssh access
sudo sed -i '/disable_root: 1/c\disable_root: 0' /etc/cloud/cloud.cfg
# The following line is commented since this was a workaround for a problem with the content of /etc/resolv.conf.
# That file could contain DNS information coming from the dataplane which might be wrong. A solution is to confire the correct DNS for the dataplne
# in OpenStack.  DNS might be slowing down ssh access. We don't need that for our dataplane benchmarking purposes
# sudo sed -i '/#UseDNS yes/c\UseDNS no' /etc/ssh/sshd_config

# Mounting huge pages to be used by DPDK
sudo mkdir -p /mnt/huge
sudo umount `awk '/hugetlbfs/ { print $2 }' /proc/mounts` >/dev/null 2>&1
sudo mount -t hugetlbfs nodev /mnt/huge/
sudo sh -c '(echo "vm.nr_hugepages = 1024") > /etc/sysctl.conf'

# Downloading the Multi-buffer library
wget https://github.com/01org/intel-ipsec-mb/archive/v0.48.zip
unzip v0.48.zip
export  AESNI_MULTI_BUFFER_LIB_PATH=/home/centos/intel-ipsec-mb-0.48
cd $AESNI_MULTI_BUFFER_LIB_PATH
make -j8
# Clone and compile DPDK
cd /home/centos/
git clone http://dpdk.org/git/dpdk
cd dpdk
git checkout v17.11
export RTE_TARGET=build
export RTE_SDK=/home/centos/dpdk
make config T=x86_64-native-linuxapp-gcc
# The next sed lines make sure that we can compile DPDK 17.11 with a relatively new OS. Using a newer DPDK (18.5) should also resolve this issue
sudo sed -i '/CONFIG_RTE_LIBRTE_KNI=y/c\CONFIG_RTE_LIBRTE_KNI=n' /home/centos/dpdk/build/.config
sudo sed -i '/CONFIG_RTE_LIBRTE_PMD_KNI=y/c\CONFIG_RTE_LIBRTE_PMD_KNI=n' /home/centos/dpdk/build/.config
sudo sed -i '/CONFIG_RTE_KNI_KMOD=y/c\CONFIG_RTE_KNI_KMOD=n' /home/centos/dpdk/build/.config
sudo sed -i '/CONFIG_RTE_KNI_PREEMPT_DEFAULT=y/c\CONFIG_RTE_KNI_PREEMPT_DEFAULT=n' /home/centos/dpdk/build/.config
# Compile with MB library
sudo sed -i '/CONFIG_RTE_LIBRTE_PMD_AESNI_MB=n/c\CONFIG_RTE_LIBRTE_PMD_AESNI_MB=y' /home/centos/dpdk/build/.config
make -j8 
cd /home/centos
# Copy everything to root since the scripts are assuming /root as the directory for PROX
sudo cp -r dpdk /root/

# Clone and compile PROX
git clone https://git.opnfv.org/samplevnf
cp -r /home/centos/samplevnf/VNFs/DPPD-PROX /home/centos/prox
cd /home/centos/prox
make -j8
cd /home/centos
# Copy everything to root since the scripts are assuming /root as the directory for PROX
sudo cp -r /home/centos/prox /root/

# Enabling tuned with the realtime-virtual-guest profile
wget http://linuxsoft.cern.ch/cern/centos/7/rt/x86_64/Packages/tuned-profiles-realtime-2.8.0-5.el7_4.2.noarch.rpm
wget http://linuxsoft.cern.ch/cern/centos/7/rt/x86_64/Packages/tuned-profiles-nfv-guest-2.8.0-5.el7_4.2.noarch.rpm
# Install with --nodeps. The latest CentOS cloud images come with a tuned version higher than 2.8. These 2 packages however
# do not depend on v2.8 and also work with tuned 2.9. Need to be careful in the future
sudo rpm -ivh /home/centos/tuned-profiles-realtime-2.8.0-5.el7_4.2.noarch.rpm --nodeps
sudo rpm -ivh /home/centos/tuned-profiles-nfv-guest-2.8.0-5.el7_4.2.noarch.rpm --nodeps
# Although we do no know how many cores the VM will have when begin deployed for real testing, we already put a number for the
# isolated CPUs so we can start the realtime-virtual-guest profile. If we don't, that command will fail.
# When the VM will be instantiated, the check_kernel_params service will check for the real number of cores available to this VM 
# and update the realtime-virtual-guest-variables.conf accordingly.
echo "isolated_cores=1" | sudo tee -a /etc/tuned/realtime-virtual-guest-variables.conf
sudo tuned-adm profile realtime-virtual-guest

# Install the check_tuned_params service to make sure that the grub cmd line has the right cpus in isolcpu. The actual number of cpu's
# assigned to this VM depends on the flavor used. We don't know at this time what that will be.
sudo cp -r /home/centos/check_prox_system_setup.sh /usr/local/libexec/
sudo cp -r /home/centos/check-prox-system-setup.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable check-prox-system-setup.service
