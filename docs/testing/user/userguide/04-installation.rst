.. This work is licensed under a Creative Commons Attribution 4.0 International
.. License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) OPNFV, Intel Corporation and others.

SampleVNF Installation
======================


Abstract
--------

This project provides a placeholder for various sample VNF
(Virtual Network Function (:term `VNF`)) development which includes example
reference architecture and optimization methods related to VNF/Network service
for high performance VNFs.
The sample VNFs are Open Source approximations* of Telco grade VNF’s using
optimized VNF + NFVi Infrastructure libraries, with Performance Characterization
of Sample† Traffic Flows.

::
  • * Not a commercial product. Encourage the community to contribute and close the feature gaps.
  • † No Vendor/Proprietary Workloads 

SampleVNF supports installation directly in Ubuntu. The installation procedure
are detailed in the sections below.

The steps needed to run SampleVNF are:
1. Install and Build SampleVNF.
2. deploy the VNF on the target and modify the config based on the
   Network under test
3. Run the traffic generator to generate the traffic.

Prerequisites
-------------

Supported Test setup:
--------------------
The device under test (DUT) consists of a system following;
  * A single or dual processor and PCH chip, except for System on Chip (SoC) cases
  * DRAM memory size and frequency (normally single DIMM per channel)
  * Specific Intel Network Interface Cards (NICs)
  * BIOS settings noting those that updated from the basic settings
  * DPDK build configuration settings, and commands used for tests
Connected to the DUT is an IXIA* or Software Traffic generator like pktgen or TRex,
simulation platform to generate packet traffic to the DUT ports and
determine the throughput/latency at the tester side.

Below are the supported/tested (:term `VNF`) deployment type.
.. image:: images/deploy_type.png
   :width: 800px
   :alt: SampleVNF supported topology

Hardware & Software Ingredients
-------------------------------
.. code-block:: console
   +-----------+------------------+
   | Item      | Description      |
   +-----------+------------------+
   | Memory    | Min 20GB         |
   +-----------+------------------+
   | NICs      | 2 x 10G          |
   +-----------+------------------+
   | OS        | Ubuntu 16.04 LTS |
   +-----------+------------------+
   | kernel    |  4.4.0-34-generic|
   +-----------+------------------+
   |DPD        | 17.02            |
   +-----------+------------------+

   Boot and BIOS settings
   +------------------+---------------------------------------------------+
   | Boot settings    | default_hugepagesz=1G hugepagesz=1G hugepages=16  |
   |                  | hugepagesz=2M hugepages=2048 isolcpus=1-11,22-33  |
   |                  | nohz_full=1-11,22-33 rcu_nocbs=1-11,22-33         |
   |                  | Note: nohz_full and rcu_nocbs is to disable Linux*|
   |                  | kernel interrupts, and it’s import                |
   +------------------+---------------------------------------------------+
   |BIOS              | CPU Power and Performance Policy <Performance>    |
   |                  | CPU C-state Disabled                              |
   |                  | CPU P-state Disabled                              |
   |                  | Enhanced Intel® Speedstep® Tech Disabled          |
   |                  | Hyper-Threading Technology (If supported) Enable  |
   |                  | Virtualization Techology Enable                   |
   |                  | Coherency Enable                                  |
   |                  | Turbo Boost Disabled                              |
   +------------------+---------------------------------------------------+

Network Topology for testing VNFs
---------------------------------
The ethernet cables should be connected between traffic generator and the VNF server (BM,
SRIOV or OVS) setup based on the test profile.

The connectivity could be
1. Single port pair : One pair ports used for traffic 
   ::
     e.g. Single port pair link0 and link1 of VNF are used
     TG:port 0 ------ VNF:Port 0
     TG:port 1 ------ VNF:Port 1

2. Multi port pair :  More than one pair of traffic
   ::
     e.g. Two port pair link 0, link1, link2 and link3 of VNF are used
     TG:port 0 ------ VNF:Port 0
     TG:port 1 ------ VNF:Port 1
     TG:port 2 ------ VNF:Port 2 
     TG:port 3 ------ VNF:Port 3

 * Bare-Metal
   Refer: http://fast.dpdk.org/doc/pdf-guides/ to setup the DUT for VNF to run 

 * Standalone Virtualization - PHY-VM-PHY
   * SRIOV
     Refer below link to setup sriov
     https://software.intel.com/en-us/articles/using-sr-iov-to-share-an-ethernet-port-among-multiple-vms

   * OVS/OVS/DPDK
     Refer below link to setup ovs/ovs-dpdk
     http://docs.openvswitch.org/en/latest/intro/install/general/
     http://docs.openvswitch.org/en/latest/intro/install/dpdk/

 * Openstack
     Use OPNFV installer to deploy the openstack.
    

Build VNFs on the DUT:
----------------------
 * Clone sampleVNF project repository  - git clone https://git.opnfv.org/samplevnf
 Auto Build
 ----------
   * Interactive options: 
         ::
           ./tools/vnf_build.sh -i
           Follow the steps in the screen from option [1] –> [9] and
           select option [8] to build the vnfs.
           It will automatically download selected DPDK version and any
           required patches and will setup everything and build VNFs.

           Following are the options for setup:
           ----------------------------------------------------------
            Step 1: Environment setup.
            ----------------------------------------------------------
            [1] Check OS and network connection
            [2] Select DPDK RTE version

          ----------------------------------------------------------
           Step 2: Download and Install
           ----------------------------------------------------------
           [3] Agree to download
           [4] Download packages
           [5] Download DPDK zip
           [6] Build and Install DPDK
           [7] Setup hugepages

           ----------------------------------------------------------
            Step 3: Build VNFs
            ----------------------------------------------------------
            [8] Build all VNFs (vACL, vCGNAPT, vFW, UDP_Replay, DPPD-PROX)

            [9] Exit Script
    * non-Interactive options:
          ::
            ./tools/vnf_build.sh -s -d=<dpdk version eg 17.02>
Manual Build
------------
   ::
      1.Download DPDK supported version from dpdk.org
        http://dpdk.org/browse/dpdk/snapshot/dpdk-$DPDK_RTE_VER.zip
        unzip dpdk-$DPDK_RTE_VER.zip and apply dpdk patches only in case of 16.04 (Not required for other DPDK versions)
        cd dpdk
        make config T=x86_64-native-linuxapp-gcc O=x86_64-native-linuxapp-gcc
        cd x86_64-native-linuxapp-gcc
        make -j
      2.Setup huge pages
        For 1G/2M hugepage sizes, for example 1G pages, the size must be specified
        explicitly and can also be optionally set as the default hugepage size
        for the system. For example, to reserve 8G of hugepage memory in the form
        of eight 1G pages, the following options should be passed to the
        kernel: * default_hugepagesz=1G hugepagesz=1G hugepages=8 hugepagesz=2M hugepages=2048
      3.Add this to Go to /etc/default/grub configuration file.
        Append “default_hugepagesz=1G hugepagesz=1G hugepages=8 hugepagesz=2M hugepages=2048”to the GRUB_CMDLINE_LINUX entry.
      4.Setup Environment Variable
        export RTE_SDK=<samplevnf>/dpdk
        export RTE_TARGET=x86_64-native-linuxapp-gcc
        export VNF_CORE=<samplevnf>
        or using ./tools/setenv.sh
      5.Build vACL VNFs
        cd <samplevnf>/VNFs/vACL
        make clean
        make
        The vACL executable will be created at the following location
        <samplevnf>/VNFs/vACL/build/vACL

Standalone virtualization/Openstack:
 ::
  * Build image from yardstick
    git clone https://git.opnfv.org/yardstick
  * cd yardstick and run
    ./tools/yardstick-img-modify tools/ubuntu-server-cloudimg-samplevnf-modify.sh

Modify Scripts as per Traffic Generator Settings
---------------------------------------------------------

e.g: vFW
Modify the configuration according to system test configuration.

traffic_type selction in config file:
The traffic_type parmeter should be set to 4 (IPv4) or 6 (IPv6)
traffic type.

There are many other vFW parameters which can be changed
in the config file for simulating different traffic conditions like
timeouts.

Modify the scripts according to system test configuration.

The routeadd and arpadd settings should be updated as per the
traffic generator settings.

; routeadd <port #> <ipv4 nhip address in decimal> <Mask>
routeadd 0 202.16.100.20 0xff000000
routeadd 1 172.16.40.20 0xff000000

;routeadd <port #> <ipv6 nhip address in hex> <Depth>
;routeadd 0 fec0::6a05:caff:fe30:21b0 64
;routeadd 1 2012::6a05:caff:fe30:2081 64

; IPv4 static ARP
;p 1 arpadd 1 172.16.40.20 00:00:00:00:00:04
;p 1 arpadd 0 202.16.100.20 00:00:00:00:00:01

; IPv6 static ARP
;p 1 arpadd 0 fec0::6a05:caff:fe30:21b0 00:00:00:00:00:01
;p 1 arpadd 1 2012::6a05:caff:fe30:2081 00:00:00:00:00:04

The vFW supports  enabling/disabling of multiple features
like firewall, conntrack, synproxy and debug.
Thease features can be enabled/disabled through scripts or
CLI commands.


ACL rules can be modified based on the test scenarios.
The default rules are provided for reference.


Commands to run vFW
----------------------------
::
  SW_LoadB
  ./vFW -p <port mask> -f <config> -s <script>
 
  HW_LoadB
  ./vFW -p <port mask> -f <config> -s <script> -hwlb <num_WT>
