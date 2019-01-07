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
# The following line is commented since this was a workaround for a problem with the content of /etc/resolv.conf.
# That file could contain DNS information coming from the dataplane which might be wrong. A solution is to confire the correct DNS for the dataplne
# in OpenStack.  DNS might be slowing down ssh access. We don't need that for our dataplane benchmarking purposes
# sudo sed -i '/#UseDNS yes/c\UseDNS no' /etc/ssh/sshd_config
sudo sh -c '(echo "export RTE_TARGET=\"build\"";echo "export RTE_SDK=\"/root/dpdk\"";echo "export AESNI_MULTI_BUFFER_LIB_PATH=\"/home/centos/intel-ipsec-mb-0.50\"";) >> /root/.bashrc'
export RTE_TARGET=build
export RTE_SDK=/home/centos/dpdk
export AESNI_MULTI_BUFFER_LIB_PATH=/home/centos/intel-ipsec-mb-0.50
# Mounting huge pages to be used by DPDK
sudo mkdir -p /mnt/huge
sudo umount `awk '/hugetlbfs/ { print $2 }' /proc/mounts` >/dev/null 2>&1
sudo mount -t hugetlbfs nodev /mnt/huge/
sudo sh -c '(echo "vm.nr_hugepages = 1024") > /etc/sysctl.conf'

# Downloading the Multi-buffer library. Note that the version to download is linked to the DPDK version being used
cd /home/centos
wget https://github.com/01org/intel-ipsec-mb/archive/v0.50.zip
unzip v0.50.zip
cd $AESNI_MULTI_BUFFER_LIB_PATH
make
sudo make install
# Clone and compile DPDK
cd /home/centos/
git clone http://dpdk.org/git/dpdk
# Runtime scripts are assuming /root as the directory for PROX
sudo ln -s /home/centos/dpdk /root/dpdk
cd $RTE_SDK
git checkout v18.08
make config T=x86_64-native-linuxapp-gcc
# The next sed lines make sure that we can compile DPDK 17.11 with a relatively new OS. Using a newer DPDK (18.5) should also resolve this issue
#sudo sed -i '/CONFIG_RTE_LIBRTE_KNI=y/c\CONFIG_RTE_LIBRTE_KNI=n' /home/centos/dpdk/build/.config
#sudo sed -i '/CONFIG_RTE_LIBRTE_PMD_KNI=y/c\CONFIG_RTE_LIBRTE_PMD_KNI=n' /home/centos/dpdk/build/.config
#sudo sed -i '/CONFIG_RTE_KNI_KMOD=y/c\CONFIG_RTE_KNI_KMOD=n' /home/centos/dpdk/build/.config
#sudo sed -i '/CONFIG_RTE_KNI_PREEMPT_DEFAULT=y/c\CONFIG_RTE_KNI_PREEMPT_DEFAULT=n' /home/centos/dpdk/build/.config
# Compile with MB library
sed -i '/CONFIG_RTE_LIBRTE_PMD_AESNI_MB=n/c\CONFIG_RTE_LIBRTE_PMD_AESNI_MB=y' /home/centos/dpdk/build/.config
make 

# Clone and compile PROX
cd /home/centos
git clone https://git.opnfv.org/samplevnf
cd /home/centos/samplevnf/VNFs/DPPD-PROX
git checkout ffc6be26
make
sudo ln -s /home/centos/samplevnf/VNFs/DPPD-PROX /root/prox

# Enabling tuned with the realtime-virtual-guest profile
cd /home/centos/
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
