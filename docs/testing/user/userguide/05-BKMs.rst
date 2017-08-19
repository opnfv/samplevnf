.. This work is licensed under a Creative Commons Attribution 4.0 International
.. License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) OPNFV, Intel Corporation and others.

SampleVNF BKMs - Example how to run VNF vFW
============================================


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

 * Stadalone Virtualization - PHY-VM-PHY
   * SRIOV
     Refer below link to setup sriov
     https://software.intel.com/en-us/articles/using-sr-iov-to-share-an-ethernet-port-among-multiple-vms

   * OVS/OVS/DPDK
     Refer below link to setup ovs/ovs-dpdk
     http://docs.openvswitch.org/en/latest/intro/install/general/
     http://docs.openvswitch.org/en/latest/intro/install/dpdk/

 * Openstack
     use OPNFV installer to deploy the openstack.
    
Traffic generator and VNF Setup details
----------------------------------------

step 0:  Preparing hardware connection.
         Connect Traffic generator and VNF system back to back as shown in previous section e.g. Bare-Metal Configuration
         TRex port 0 ↔ (VNF Port 0) ↔ (VNF Port 1) ↔ TRex port 1

step 1: Setting up Traffic generator (TRex) (Refer: https://trex-tgn.cisco.com/trex/doc/trex_stateless_bench.html)
        TRex Software preparations
        --------------------------
        a. Install the OS (Bare metal Linux, not VM!)
        b. Obtain the latest TRex package: wget https://trex-tgn.cisco.com/trex/release/latest
        c. Untar the package: tar -xzf latest
        d. Change dir to unzipped TRex
        e. Create config file using command: sudo python dpdk_setup_ports.py -i
           In case of Ubuntu 16 need python3
           See paragraph config creation for detailed step-by-step
step 2: Setting up VNF

        Deployment type - Bare-Metal:
        ----------------------------
        a. Clone sampleVNF project repository  - git clone https://git.opnfv.org/samplevnf
        Auto Build
          * Interactive options: 
                ./tools/vnf_build.sh -i
                Follow the steps in the screen from option [1] –> [9] and select option [8] to build the vnfs. It will automatically download selected DPDK version and any required patches and will setup everything and build VNFs.
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
                ./tools/vnf_build.sh -s -d=<dpdk version eg 17.02>
        Manual Build
           1. Download DPDK supported version from dpdk.org
              http://dpdk.org/browse/dpdk/snapshot/dpdk-$DPDK_RTE_VER.zip
              unzip dpdk-$DPDK_RTE_VER.zip and apply dpdk patches only in case of 16.04 (Not required for other DPDK versions)
              cd dpdk
              make config T=x86_64-native-linuxapp-gcc O=x86_64-native-linuxapp-gcc
              cd x86_64-native-linuxapp-gcc
              make
           2. Setup huge pages
              For 1G/2M hugepage sizes, for example 1G pages, the size must be
              specified explicitly and can also be optionally set as the
              default hugepage size for the system. For example, to reserve 8G
              of hugepage memory in the form of eight 1G pages, the following
              options should be passed to the kernel: * default_hugepagesz=1G
              hugepagesz=1G hugepages=8 hugepagesz=2M hugepages=2048
           3. Add this to Go to /etc/default/grub configuration file.
              Append “default_hugepagesz=1G hugepagesz=1G hugepages=8 hugepagesz=2M hugepages=2048”
              to the GRUB_CMDLINE_LINUX entry.
           4. Setup Environment Variable
              export RTE_SDK=<samplevnf>/dpdk
              export RTE_TARGET=x86_64-native-linuxapp-gcc
              export VNF_CORE=<samplevnf>
              or using ./tools/setenv.sh
           5. Build vFW VNFs
              cd <samplevnf>/VNFs/vFW
              make clean
              make
              The vFW executable will be created at the following location
              <samplevnf>/VNFs/vFW/build/vFW

step 3: Running VNF
  a. Setup Port to run VNF
        For DPDK versions 17.xx
        1. cd <samplevnf>/dpdk
        2. ./usertools/dpdk-devbind.py --status <--- List the network device
        3. ./usertools/dpdk-devbind.py -b igb_uio <PCI Port 0> <PCI Port 1>
        .. _More details: http://dpdk.org/doc/guides-17.05/linux_gsg/build_dpdk.html#binding-and-unbinding-network-ports-to-from-the-kernel-modules 
  b. Prepare script to enalble VNF to route the packets
        ::
          cd <samplevnf>/VNFs/vFW/config
          Open -> VFW_SWLB_SinglePortPair_script.tc. Replace the bold items based on your setting.

           link 0 config <VNF port 0 IP eg 202.16.100.10> 8
           link 0 up
           link 1 down
           link 1 config <VNF port 0 IP eg 172.16.40.10> 8
           link 1 up
           ; routeadd <port #> <ipv4 nhip address in decimal> <Mask>
           routeadd 0 <traffic generator port 0 IP eg 202.16.100.20> 0xff000000
           routeadd 1 <traffic generator port 1 IP eg 172.16.40.20> 0xff000000

           ; IPv4 static ARP; disable if dynamic arp is enabled.
           p 1 arpadd 0 <traffic generator port 0 IP eg 202.16.100.20> <traffic generator port 0 MAC>
           p 1 arpadd 1  <traffic generator port 1 IP eg 172.16.40.20> <traffic generator port 1 MAC>
           p action add 0 accept
           p action add 0 fwd 0
           p action add 0 count
           p action add 1 accept
           p action add 1 fwd 1
           p action add 1 count
           p action add 2 drop
           p action add 2 count
           p action add 0 conntrack
           p action add 1 conntrack
           p action add 2 conntrack
           p action add 3 conntrack
           ; IPv4 rules
           p vfw add 1 <traffic generator port 0 IP eg 202.16.100.20> 8 <traffic generator port 1 IP eg 172.16.40.20> 8 0 65535 67 69 0 0 2
           p vfw add 2 <traffic generator port 0 IP eg 202.16.100.20> 8 <traffic generator port 1 IP eg 172.16.40.20> 8 0 65535 0 65535 0 0 1
           p vfw add 2 <traffic generator port 1 IP eg 172.16.40.20> 8 <traffic generator port 0 IP eg 202.16.100.20> 8 0 65535 0 65535 0 0 0
           p vfw applyruleset
   c. Run below cmd to launch the VNF. Please make sure both hugepages and ports to be used are bind to dpdk.
      ::
        cd <samplevnf>/VNFs/vFW/
        ./build/vFW -p 0x3 -f ./config/VFW_SWLB_SinglePortPair_4Thread.cfg  -s ./config/VFW_SWLB_SinglePortPair_script.tc

step 4: Run Test using traffic geneator

On traffic generator system:
        cd <trex eg v2.28/stl>
        Update the bench.py to generate the traffic. 

        class STLBench(object):
        ip_range = {}
        ip_range['src'] = {'start': '<traffic generator port 0 IP eg 202.16.100.20>', 'end': '<traffic generator port 0 IP eg 202.16.100.20>'}
        ip_range['dst'] = {'start': '<traffic generator port 1 IP eg 172.16.40.20>', 'end': '<traffic generator port 1 IP eg 172.16.40.20>'}
        cd <trex eg v2.28>
        Run the TRex server: sudo ./t-rex-64 -i -c 7
        In another shell run TRex console: trex-console
        The console can be run from another computer with -s argument, --help for more info.
        Other options for TRex client are automation or GUI
        In the console, run "tui" command, and then send the traffic with commands like:
        start -f stl/bench.py -m 50% --port 0 3 -t size=590,vm=var1
        For more details refer: https://trex-tgn.cisco.com/trex/doc/trex_stateless_bench.html 

Deployment type Standalone Virtualization/Openstack:
Step 0: Setup the NFVi Infrastrucutre. (Refer installation section)
Step 1: Build SampleVNF enabled VM
  * Build image from yardstick
    git clone https://git.opnfv.org/yardstick
  * cd yardstick and run
    ./tools/yardstick-img-modify tools/ubuntu-server-cloudimg-samplevnf-modify.sh
Step 3: Follow steps 0 to 4 in above section to run the VNF.
