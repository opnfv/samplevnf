.. This work is licensed under a Creative Commons Attribution 4.0 International
.. License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) OPNFV, Intel Corporation and others.

SampleVNF - How to run
======================

Prerequisites
-------------

Supported Test setup
^^^^^^^^^^^^^^^^^^^^
The device under test (DUT) consists of a system following;
  * A single or dual processor and PCH chip, except for System on Chip (SoC) cases
  * DRAM memory size and frequency (normally single DIMM per channel)
  * Specific Intel Network Interface Cards (NICs)
  * BIOS settings noting those that updated from the basic settings
  * DPDK build configuration settings, and commands used for tests
Connected to the DUT is an IXIA* or Software Traffic generator like pktgen or TRex,
simulation platform to generate packet traffic to the DUT ports and
determine the throughput/latency at the tester side.

Below are the supported/tested (:term:`VNF`) deployment type.

.. image:: images/deploy_type.png
   :width: 800px
   :alt: SampleVNF supported topology

Hardware & Software Ingredients
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

SUT requirements:


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
   | DPDK      | 17.02            |
   +-----------+------------------+

Boot and BIOS settings:


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

1) Single port pair : One pair ports used for traffic
   ::
     e.g. Single port pair link0 and link1 of VNF are used
     TG:port 0 <------> VNF:Port 0
     TG:port 1 <------> VNF:Port 1

2) Multi port pair :  More than one pair of traffic
   ::
     e.g. Two port pair link 0, link1, link2 and link3 of VNF are used
     TG:port 0 <------> VNF:Port 0
     TG:port 1 <------> VNF:Port 1
     TG:port 2 <------> VNF:Port 2
     TG:port 3 <------> VNF:Port 3

     For correalted traffic, use below configuration
     TG_1:port 0 <------> VNF:Port 0
                        VNF:Port 1 <------> TG_2:port 0 (UDP Replay)
     (TG_2(UDP_Replay) reflects all the traffic on the given port)
 * Bare-Metal
   Refer: http://fast.dpdk.org/doc/pdf-guides/ to setup the DUT for VNF to run

 * Standalone Virtualization - PHY-VM-PHY
   * SRIOV
     Refer below link to setup sriov
     https://software.intel.com/en-us/articles/using-sr-iov-to-share-an-ethernet-port-among-multiple-vms

   * OVS_DPDK
     Refer below link to setup ovs-dpdk
     http://docs.openvswitch.org/en/latest/intro/install/general/
     http://docs.openvswitch.org/en/latest/intro/install/dpdk/

 * Openstack
     Use any OPNFV installer to deploy the openstack.

Setup Traffic generator
-----------------------

Step 0: Preparing hardware connection

    Connect Traffic generator and VNF system back to back as shown in previous section
    TRex port 0 ↔ (VNF Port 0) ↔ (VNF Port 1) ↔ TRex port 1

Step 1: Setting up Traffic generator (TRex)

    TRex Software preparations
    ^^^^^^^^^^^^^^^^^^^^^^^^^^
    * Install the OS (Bare metal Linux, not VM!)
    * Obtain the latest TRex package: wget https://trex-tgn.cisco.com/trex/release/latest
    * Untar the package: tar -xzf latest
    * Change dir to unzipped TRex
    * Create config file using command: sudo python dpdk_setup_ports.py -i
       In case of Ubuntu 16 need python3
       See paragraph config creation for detailed step-by-step
    (Refer: https://trex-tgn.cisco.com/trex/doc/trex_stateless_bench.html)


Build SampleVNFs
-----------------

Step 2: Procedure to build SampleVNFs

   a) Clone sampleVNF project repository  - git clone https://git.opnfv.org/samplevnf
   b) Build VNFs
      Auto Build
      ^^^^^^^^^^

      * Interactive options:

   ::

              ./tools/vnf_build.sh -i
              Follow the steps in the screen from option [1] –> [9] and select option [8] to build the vnfs.
              It will automatically download selected DPDK version and any required patches and will setup everything and build VNFs.
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
              [8] Download civetweb

              ----------------------------------------------------------
              Step 3: Build VNFs
              ----------------------------------------------------------
              [9] Build all VNFs (vACL, vCGNAPT, vFW, UDP_Replay, DPPD-PROX)

              [10] Exit Script


       * non-Interactive options:

   ::

              ./tools/vnf_build.sh -s -d=<dpdk version eg 17.02>

      Manual Build
      ^^^^^^^^^^^^

::

           1) Download DPDK supported version from dpdk.org
              http://dpdk.org/browse/dpdk/snapshot/dpdk-$DPDK_RTE_VER.zip
              unzip dpdk-$DPDK_RTE_VER.zip and apply dpdk patches only in case of 16.04 (Not required for other DPDK versions)
              cd dpdk
              make config T=x86_64-native-linuxapp-gcc O=x86_64-native-linuxapp-gcc
              cd x86_64-native-linuxapp-gcc
              make

           2) Download civetweb 1.9 version from the following link
              https://sourceforge.net/projects/civetweb/files/1.9/CivetWeb_V1.9.zip
              unzip CivetWeb_V1.9.zip
              mv civetweb-master civetweb
              cd civetweb
              make lib

           3) Setup huge pages
              For 1G/2M hugepage sizes, for example 1G pages, the size must be
              specified explicitly and can also be optionally set as the
              default hugepage size for the system. For example, to reserve 8G
              of hugepage memory in the form of eight 1G pages, the following
              options should be passed to the kernel: * default_hugepagesz=1G
              hugepagesz=1G hugepages=8 hugepagesz=2M hugepages=2048
           4) Add this to Go to /etc/default/grub configuration file.
              Append “default_hugepagesz=1G hugepagesz=1G hugepages=8 hugepagesz=2M hugepages=2048”
              to the GRUB_CMDLINE_LINUX entry.
           5) Setup Environment Variable
              export RTE_SDK=<samplevnf>/dpdk
              export RTE_TARGET=x86_64-native-linuxapp-gcc
              export VNF_CORE=<samplevnf>
              or using ./tools/setenv.sh
           6) Build VNFs
              cd <samplevnf>
              make
              or to build individual VNFs
                cd <samplevnf>/VNFs/
                make clean
                make
                The vFW executable will be created at the following location
                <samplevnf>/VNFs/vFW/build/vFW


Virtual Firewall - How to run
-----------------------------

Step 3: Bind the datapath ports to DPDK

    a) Bind ports to DPDK

::

        For DPDK versions 17.xx
        1) cd <samplevnf>/dpdk
        2) ./usertools/dpdk-devbind.py --status <--- List the network device
        3) ./usertools/dpdk-devbind.py -b igb_uio <PCI Port 0> <PCI Port 1>
        .. _More details: http://dpdk.org/doc/guides-17.05/linux_gsg/build_dpdk.html#binding-and-unbinding-network-ports-to-from-the-kernel-modules

    b) Prepare script to enalble VNF to route the packets

::

          cd <samplevnf>/VNFs/vFW/config
          Open -> VFW_SWLB_SinglePortPair_script.tc. Replace the bold items based on your setting.

           link 0 config <VNF port 0 IP eg 202.16.100.10> 8
           link 0 up
           link 1 down
           link 1 config <VNF port 0 IP eg 172.16.40.10> 8
           link 1 up

           ; routeadd <net/host> <port #> <ipv4 nhip address in decimal> <Mask>
           routeadd net 0 <traffic generator port 0 IP eg 202.16.100.20> 0xff000000
           routeadd net 1 <traffic generator port 1 IP eg 172.16.40.20> 0xff000000

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

     c) Run below cmd to launch the VNF. Please make sure both hugepages and ports to be used are bind to dpdk.

::

          cd <samplevnf>/VNFs/vFW/
          ./build/vFW -p 0x3 -f ./config/VFW_SWLB_SinglePortPair_4Thread.cfg  -s ./config/VFW_SWLB_SinglePortPair_script.tc

step 4: Run Test using traffic geneator

  ::

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

Virtual Access Control list - How to run
----------------------------------------

Step 3: Bind the datapath ports to DPDK

    a) Bind ports to DPDK

  ::

        For DPDK versions 17.xx
        1) cd <samplevnf>/dpdk
        2) ./usertools/dpdk-devbind.py --status <--- List the network device
        3) ./usertools/dpdk-devbind.py -b igb_uio <PCI Port 0> <PCI Port 1>
        .. _More details: http://dpdk.org/doc/guides-17.05/linux_gsg/build_dpdk.html#binding-and-unbinding-network-ports-to-from-the-kernel-modules

    b) Prepare script to enalble VNF to route the packets

  ::

          cd <samplevnf>/VNFs/vACL/config
          Open -> IPv4_swlb_acl.tc. Replace the bold items based on your setting.

           link 0 config <VNF port 0 IP eg 202.16.100.10> 8
           link 0 up
           link 1 down
           link 1 config <VNF port 0 IP eg 172.16.40.10> 8
           link 1 up

           ; routeadd <port #> <ipv4 nhip address in decimal> <Mask>
           routeadd net 0 <traffic generator port 0 IP eg 202.16.100.20> 0xff000000
           routeadd net 1 <traffic generator port 1 IP eg 172.16.40.20> 0xff000000

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
           p acl add 1 <traffic generator port 0 IP eg 202.16.100.20> 8 <traffic generator port 1 IP eg 172.16.40.20> 8 0 65535 67 69 0 0 2
           p acl add 2 <traffic generator port 0 IP eg 202.16.100.20> 8 <traffic generator port 1 IP eg 172.16.40.20> 8 0 65535 0 65535 0 0 1
           p acl add 2 <traffic generator port 1 IP eg 172.16.40.20> 8 <traffic generator port 0 IP eg 202.16.100.20> 8 0 65535 0 65535 0 0 0
           p acl applyruleset

     c) Run below cmd to launch the VNF. Please make sure both hugepages and ports to be used are bind to dpdk.

  ::

        cd <samplevnf>/VNFs/vFW/
        ./build/vFW -p 0x3 -f ./config/IPv4_swlb_acl_1LB_1t.cfg  -s ./config/IPv4_swlb_acl.tc.

step 4: Run Test using traffic geneator

  ::

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


vCGNAPT - How to run
--------------------

Step 3: Bind the datapath ports to DPDK

    a) Bind ports to DPDK

  ::

        For DPDK versions 17.xx
        1) cd <samplevnf>/dpdk
        2) ./usertools/dpdk-devbind.py --status <--- List the network device
        3) ./usertools/dpdk-devbind.py -b igb_uio <PCI Port 0> <PCI Port 1>
        .. _More details: http://dpdk.org/doc/guides-17.05/linux_gsg/build_dpdk.html#binding-and-unbinding-network-ports-to-from-the-kernel-modules

    b) Prepare script to enalble VNF to route the packets

  ::

          cd <samplevnf>/VNFs/vCGNAPT/config
          Open -> sample_swlb_2port_2WT.tc Replace the bold items based on your setting.

           link 0 config <VNF port 0 IP eg 202.16.100.10> 8
           link 0 up
           link 1 down
           link 1 config <VNF port 0 IP eg 172.16.40.10> 8
           link 1 up

           ; uncomment to enable static NAPT
           ;p <cgnapt pipeline id> entry addm <prv_ipv4/6> prvport> <pub_ip> <pub_port> <phy_port> <ttl> <no_of_entries> <end_prv_port> <end_pub_port>
           ;p 5 entry addm 202.16.100.20 1234 152.16.40.10 1 0 500 65535 1234 65535

           ; routeadd <net/host> <port #> <ipv4 nhip address in decimal> <Mask>
           routeadd net 0 <traffic generator port 0 IP eg 202.16.100.20> 0xff000000
           routeadd net 1 <traffic generator port 1 IP eg 172.16.40.20> 0xff000000

           ; IPv4 static ARP; disable if dynamic arp is enabled.
           p 1 arpadd 0 <traffic generator port 0 IP eg 202.16.100.20> <traffic generator port 0 MAC>
           p 1 arpadd 1  <traffic generator port 1 IP eg 172.16.40.20> <traffic generator port 1 MAC>
       For dynamic cgnapt. Please use UDP_Replay as one of the traffic generator
          (TG1) (port 0) --> (port 0) VNF (CGNAPT) (Port 1) --> (port0)(UDPReplay)

     c) Run below cmd to launch the VNF. Please make sure both hugepages and ports to be used are bind to dpdk.

  ::

        cd <samplevnf>/VNFs/vCGNAPT/
        ./build/vCGNAPT -p 0x3 -f ./config/sample_swlb_2port_2WT.cfg  -s ./config/sample_swlb_2port_2WT.tc


step 4: Run Test using traffic geneator

  ::
        On traffic generator system:
        cd <trex eg v2.28/stl>
        Update the bench.py to generate the traffic.

        class STLBench(object):
        ip_range = {}
        ip_range['src'] = {'start': '<traffic generator port 0 IP eg 202.16.100.20>', 'end': '<traffic generator port 0 IP eg 202.16.100.20>'}
        ip_range['dst'] = {'start': '<traffic generator port 1 IP eg 172.16.40.20>', 'end': '<public ip e.g 152.16.40.10>'}
        cd <trex eg v2.28>
        Run the TRex server: sudo ./t-rex-64 -i -c 7
        In another shell run TRex console: trex-console
        The console can be run from another computer with -s argument, --help for more info.
        Other options for TRex client are automation or GUI
        In the console, run "tui" command, and then send the traffic with commands like:
        start -f stl/bench.py -m 50% --port 0 3 -t size=590,vm=var1
        For more details refer: https://trex-tgn.cisco.com/trex/doc/trex_stateless_bench.html

UDP_Replay - How to run
----------------------------------------

Step 3: Bind the datapath ports to DPDK

    a) Bind ports to DPDK

  ::

        For DPDK versions 17.xx
        1) cd <samplevnf>/dpdk
        2) ./usertools/dpdk-devbind.py --status <--- List the network device
        3) ./usertools/dpdk-devbind.py -b igb_uio <PCI Port 0> <PCI Port 1>
        .. _More details: http://dpdk.org/doc/guides-17.05/linux_gsg/build_dpdk.html#binding-and-unbinding-network-ports-to-from-the-kernel-modules

    b) Run below cmd to launch the VNF. Please make sure both hugepages and ports to be used are bind to dpdk.

  ::

          cd <samplevnf>/VNFs/UDP_Replay/
          cmd: ./build/UDP_Replay -c 0x7 -n 4 -w <pci> -w <pci> -- --no-hw-csum -p <portmask> --config='(port, queue, cpucore)'
          e.g ./build/UDP_Replay -c 0x7 -n 4 -w 0000:07:00.0 -w 0000:07:00.1 -- --no-hw-csum -p 0x3 --config='(0, 0, 1)(1, 0, 2)'

step 4: Run Test using traffic geneator

  ::

    On traffic generator system:
    cd <trex eg v2.28/stl>
    Update the bench.py to generate the traffic.

    class STLBench(object):
    ip_range = {}
    ip_range['src'] = {'start': '<traffic generator port 0 IP eg 202.16.100.20>', 'end': '<traffic generator port 0 IP eg 202.16.100.20>'}
    ip_range['dst'] = {'start': '<traffic generator port 1 IP eg 172.16.40.20>', 'end': '<public ip e.g 152.16.40.10>'}
    cd <trex eg v2.28>
    Run the TRex server: sudo ./t-rex-64 -i -c 7
    In another shell run TRex console: trex-console
    The console can be run from another computer with -s argument, --help for more info.
    Other options for TRex client are automation or GUI
    In the console, run "tui" command, and then send the traffic with commands like:
    start -f stl/bench.py -m 50% --port 0 3 -t size=590,vm=var1
    For more details refer: https://trex-tgn.cisco.com/trex/doc/trex_stateless_bench.html

PROX - How to run
------------------

Description
^^^^^^^^^^^

This is PROX, the Packet pROcessing eXecution engine, part of Intel(R)
Data Plane Performance Demonstrators, and formerly known as DPPD-BNG.
PROX is a DPDK-based application implementing Telco use-cases such as
a simplified BRAS/BNG, light-weight AFTR... It also allows configuring
finer grained network functions like QoS, Routing, load-balancing...

Compiling and running this application
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This application supports DPDK 16.04, 16.11, 17.02 and 17.05.
The following commands assume that the following variables have been set:

export RTE_SDK=/path/to/dpdk
export RTE_TARGET=x86_64-native-linuxapp-gcc

Example: DPDK 17.05 installation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* git clone http://dpdk.org/git/dpdk
* cd dpdk
* git checkout v17.05
* make install T=$RTE_TARGET

PROX compilation
^^^^^^^^^^^^^^^^

The Makefile with this application expects RTE_SDK to point to the
root directory of DPDK (e.g. export RTE_SDK=/root/dpdk). If RTE_TARGET
has not been set, x86_64-native-linuxapp-gcc will be assumed.

Running PROX
^^^^^^^^^^^^

After DPDK has been set up, run make from the directory where you have
extracted this application. A build directory will be created
containing the PROX executable. The usage of the application is shown
below. Note that this application assumes that all required ports have
been bound to the DPDK provided igb_uio driver. Refer to the "Getting
Started Guide - DPDK" document for more details.

::

  Usage: ./build/prox [-f CONFIG_FILE] [-l LOG_FILE] [-p] [-o DISPLAY] [-v] [-a|-e] [-m|-s|-i] [-n] [-w DEF] [-q] [-k] [-d] [-z] [-r VAL] [-u] [-t]
        -f CONFIG_FILE : configuration file to load, ./prox.cfg by default
        -l LOG_FILE : log file name, ./prox.log by default
        -p : include PID in log file name if default log file is used
        -o DISPLAY: Set display to use, can be 'curses' (default), 'cli' or 'none'
        -v verbosity : initial logging verbosity
        -a : autostart all cores (by default)
        -e : don't autostart
        -n : Create NULL devices instead of using PCI devices, useful together with -i
        -m : list supported task modes and exit
        -s : check configuration file syntax and exit
        -i : check initialization sequence and exit
        -u : Listen on UDS /tmp/prox.sock
        -t : Listen on TCP port 8474
        -q : Pass argument to Lua interpreter, useful to define variables
        -w : define variable using syntax varname=value
             takes precedence over variables defined in CONFIG_FILE
        -k : Log statistics to file "stats_dump" in current directory
        -d : Run as daemon, the parent process will block until PROX is not initialized
        -z : Ignore CPU topology, implies -i
        -r : Change initial screen refresh rate. If set to a lower than 0.001 seconds,
                  screen refreshing will be disabled

While applications using DPDK typically rely on the core mask and the
number of channels to be specified on the command line, this
application is configured using a .cfg file. The core mask and number
of channels is derived from this config. For example, to run the
application from the source directory execute:

  user@target:~$ ./build/prox -f ./config/nop.cfg

Provided example configurations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
PROX can be configured either as the SUT (System Under Test) or as the
Traffic Generator. Some example configuration files are provided, both
in the config directory to run PROX as a SUT, and in the gen directory
to run it as a Traffic Generator.
A quick description of these example configurations is provided below.
Additional details are provided in the example configuration files.

Basic configurations, mostly used as sanity check:
- config/nop.cfg
- config/nop-rings.cfg
- gen/nop-gen.cfg

Simplified BNG (Border Network Gateway) configurations, using different
number of ports, with and without QoS, running on the host or in a VM:
- config/bng-4ports.cfg
- config/bng-8ports.cfg
- config/bng-qos-4ports.cfg
- config/bng-qos-8ports.cfg
- config/bng-1q-4ports.cfg
- config/bng-ovs-usv-4ports.cfg
- config/bng-no-cpu-topology-4ports.cfg
- gen/bng-4ports-gen.cfg
- gen/bng-8ports-gen.cfg
- gen/bng-ovs-usv-4ports-gen.cfg

Light-weight AFTR configurations:
- config/lw_aftr.cfg
- gen/lw_aftr-gen.cfg

