.. This work is licensed under a Creative Commons Attribution 4.0 International
.. License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) OPNFV, National Center of Scientific Research "Demokritos" and others.

============================
CGNAPT - Installation Guide
============================


vCGNAPT Compilation
===================

After downloading (or doing a git clone) in a directory (samplevnf)

###### Dependencies
* DPDK 16.04: Downloaded and installed via vnf_build.sh or manually from [here](http://fast.dpdk.org/rel/dpdk-16.04.tar.xz)
Both the options are available as part of vnf_build.sh below.
* libpcap-dev
* libzmq
* libcurl

###### Environment variables

Apply all the additional patches in 'patches/dpdk_custom_patch/' and build dpdk

::
  export RTE_SDK=<dpdk 16.04 directory>
  export RTE_TARGET=x86_64-native-linuxapp-gcc

This is done by vnf_build.sh script.

Auto Build:
==========
$ ./tools/vnf_build.sh in samplevnf root folder

Follow the steps in the screen from option [1] --> [8] and select option [7]
to build the vnfs.
It will automatically download DPDK 16.04 and any required patches and will setup
everything and build vCGNAPT VNFs.

Following are the options for setup:

::

  ----------------------------------------------------------
   Step 1: Environment setup.
  ----------------------------------------------------------
  [1] Check OS and network connection

  ----------------------------------------------------------
   Step 2: Download and Install
  ----------------------------------------------------------
  [2] Agree to download
  [3] Download packages
  [4] Download DPDK zip (optional, use it when option 4 fails)
  [5] Install DPDK
  [6] Setup hugepages

  ----------------------------------------------------------
   Step 3: Build VNF
  ----------------------------------------------------------
  [7] Build VNF

  [8] Exit Script

An vCGNAPT executable will be created at the following location
samplevnf/VNFs/vCGNAPT/build/vCGNAPT


Manual Build:
============
1. Download DPDK 16.04 from dpdk.org
   - http://dpdk.org/browse/dpdk/snapshot/dpdk-16.04.zip
2. unzip  dpdk-16.04 and apply dpdk patch
   - cd dpdk-16.04
	 - patch -p0 < VNF_CORE/patches/dpdk_custom_patch/rte_pipeline.patch
 	 - patch -p1 < VNF_CORE/patches/dpdk_custom_patch/i40e-fix-link-management.patch
	 - patch -p1 < VNF_CORE/patches/dpdk_custom_patch/i40e-fix-Rx-hang-when-disable-LLDP.patch
 	 - patch -p1 < VNF_CORE/patches/dpdk_custom_patch/i40e-fix-link-status-change-interrupt.patch
 	 - patch -p1 < VNF_CORE/patches/dpdk_custom_patch/i40e-fix-VF-bonded-device-link-down.patch
   - build dpdk
	- make config T=x86_64-native-linuxapp-gcc O=x86_64-native-linuxapp-gcc
	- cd x86_64-native-linuxapp-gcc
	- make
   - Setup huge pages
	- For 1G/2M hugepage sizes, for example 1G pages, the size must be specified
          explicitly and can also be optionally set as the default hugepage size for
          the system. For example, to reserve 8G of hugepage memory in the form of
          eight 1G pages, the following options should be passed to the kernel:
		* default_hugepagesz=1G hugepagesz=1G hugepages=8  hugepagesz=2M hugepages=2048
	- Add this to Go to /etc/default/grub configuration file.
	  - Append "default_hugepagesz=1G hugepagesz=1G hugepages=8 hugepagesz=2M hugepages=2048"
	    to the GRUB_CMDLINE_LINUX entry.
3. Setup Environment Variable
   - export RTE_SDK=<samplevnf>/dpdk-16.04
   - export RTE_TARGET=x86_64-native-linuxapp-gcc
   - export VNF_CORE=<samplevnf>
     or using ./toot/setenv.sh
4. Build vCGNAPT VNFs
   - cd <samplevnf>/VNFs/vCGNAPT
   - make clean
   - make
5. An vCGNAPT executable will be created at the following location
   - <samplevnf>/VNFs/vCGNAPT/build/vCGNAPT

Run
====

Setup Port to run VNF:
----------------------
::
  1. cd <samplevnf>/dpdk-16.04
  3. ./tool/dpdk_nic_bind.py --status <--- List the network device
  2. ./tool/dpdk_nic_bind.py -b igb_uio <PCI Port 0> <PCI Port 1>
  .. _More details: http://dpdk.org/doc/guides-16.04/linux_gsg/build_dpdk.html#binding-and-unbinding-network-ports-to-from-the-kernel-modules

  Make the necessary changes to the config files to run the vCGNAPT VNF
  eg: ports_mac_list = 00:00:00:30:21:F0 00:00:00:30:21:F1 

Dynamic CGNAPT
--------------
Update the configuration according to system configuration.

::
  ./vCGNAPT -p <port mask> -f <config> -s <script> - SW_LoadB
  ./vCGNAPT -p <port mask> -f <config> -s <script> -hwlb <num_WT> - HW_LoadB

Static CGNAPT
-------------
Update the script file and add Static NAT Entry

::
  e.g, 
  ;p <pipeline id> entry addm <prv_ipv4/6> prvport> <pub_ip> <pub_port> <phy_port> <ttl> <no_of_entries> <end_prv_port> <end_pub_port>
  ;p 3 entry addm 152.16.100.20 1234 152.16.40.10 1 0 500 65535 1234 65535

Run IPv4
----------
::
  Software LoadB
  --------------
  cd <samplevnf>/VNFs/vCGNAPT/build
  ./vCGNAPT -p 0x3 -f ./config/arp_txrx-2P-1T.cfg  -s ./config/arp_txrx_ScriptFile_2P.cfg


  Hardware LoadB
  --------------
  cd <samplevnf>/VNFs/vCGNAPT/build
  ./vCGNAPT -p 0x3 -f ./config/arp_hwlb-2P-1T.cfg  -s ./config/arp_hwlb_scriptfile_2P.cfg --hwlb 1

Run IPv6
---------
::
  Software LoadB
  --------------
  cd <samplevnf>/VNFs/vCGNAPT/build
  ./vCGNAPT -p 0x3 -f ./config/arp_txrx-2P-1T-ipv6.cfg  -s ./config/arp_txrx_ScriptFile_2P.cfg


  Hardware LoadB
  --------------
  cd <samplevnf>/VNFs/vCGNAPT/build
  ./vCGNAPT -p 0x3 -f ./config/arp_hwlb-2P-1T-ipv6.cfg  -s ./config/arp_hwlb_scriptfile_2P.cfg --hwlb 1

vCGNAPT execution on BM & SRIOV:
--------------------------------
::
  To run the VNF, execute the following:
  samplevnf/VNFs/vCGNAPT# ./build/vCGNAPT -p 0x3 -f ./config/arp_txrx-2P-1T.cfg -s ./config/arp_txrx_ScriptFile_2P.cfg
  Command Line Params:
  -p PORTMASK: Hexadecimal bitmask of ports to configure
  -f CONFIG FILE: vCGNAPT configuration file
  -s SCRIPT FILE: vCGNAPT script file

vCGNAPT execution on OVS:
-------------------------
::
  To run the VNF, execute the following:
  samplevnf/VNFs/vCGNAPT# ./build/vCGNAPT -p 0x3 ./config/arp_txrx-2P-1T.cfg -s ./config/arp_txrx_ScriptFile_2P.cfg --disable-hw-csum
  Command Line Params:
  -p PORTMASK: Hexadecimal bitmask of ports to configure
  -f CONFIG FILE: vCGNAPT configuration file
  -s SCRIPT FILE: vCGNAPT script file
  --disable-hw-csum :Disable TCP/UDP hw checksum
