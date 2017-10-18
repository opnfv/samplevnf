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
   | kernel    | 4.4.0-34-generic |
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
   | BIOS             | CPU Power and Performance Policy <Performance>    |
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

     For correalted traffic, use below configuration
     TG_1:port 0 <------> VNF:Port 0
                          VNF:Port 1 <------> TG_2:port 0 (UDP Replay)
     (TG_2(UDP_Replay) reflects all the traffic on the given port)

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
     TG_1:port 1 <------> VNF:Port 2
                          VNF:Port 3 <------> TG_2:port 1 (UDP Replay)
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

    ::

        TRex port 0 ↔ (VNF Port 0) ↔ (VNF Port 1) ↔ TRex port 1

Step 1: Setting up Traffic generator (TRex)

    TRex Software preparations
    **************************
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
   Follow the steps in the screen from option [1] –> [10] and select option [9] to build the vnfs.
   It will automatically download selected DPDK version and any required patches and will setup everything and build VNFs.

   Options [8], If RestAPI feature is needed install 'civetweb'

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
   [8] Download and Build civetweb

   ----------------------------------------------------------
   Step 3: Build VNFs
   ----------------------------------------------------------
   [9] Build all VNFs (vACL, vCGNAPT, vFW, UDP_Replay, DPPD-PROX)

   [10] Exit Script


* Non-Interactive options:

::

   ./tools/vnf_build.sh -s -d=<dpdk version eg 17.02>
   if system is behind the proxy
   ./tools/vnf_build.sh -s -d=<dpdk version eg 17.02> -p=<proxy>

Manual Build
^^^^^^^^^^^^

::

   1) Download DPDK supported version from dpdk.org
      * http://dpdk.org/browse/dpdk/snapshot/dpdk-$DPDK_RTE_VER.zip
      * unzip dpdk-$DPDK_RTE_VER.zip and apply dpdk patches only in case of 16.04 (Not required for other DPDK versions)
      * cd dpdk
      * make config T=x86_64-native-linuxapp-gcc O=x86_64-native-linuxapp-gcc
      * cd x86_64-native-linuxapp-gcc
      * make

   2) Download civetweb 1.9 version from the following link
      * https://sourceforge.net/projects/civetweb/files/1.9/CivetWeb_V1.9.zip
      * unzip CivetWeb_V1.9.zip
      * mv civetweb-master civetweb
      * cd civetweb
      * make lib

   3) Add this to Go to /etc/default/grub configuration file to setup higepages.
      * Append “default_hugepagesz=1G hugepagesz=1G hugepages=8 hugepagesz=2M hugepages=2048” to the GRUB_CMDLINE_LINUX entry.
      * execute update-grub
      * Reboot after grub setup

   4) Setup Environment Variable
      * export RTE_SDK=<samplevnf>/dpdk
      * export RTE_TARGET=x86_64-native-linuxapp-gcc
      * export VNF_CORE=<samplevnf> or using ./tools/setenv.sh

   5) Build VNFs
      * cd <samplevnf>
      * make
      * or To build individual VNFs
        * cd <samplevnf>/VNFs/
        * make clean
        * make
        * The vFW executable will be created at the following location
        * <samplevnf>/VNFs/vFW/build/vFW


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

 d) Run UDP_replay to reflect the traffic on public side.

  ::

    cmd: ./build/UDP_Replay -c 0x7 -n 4 -w <pci> -w <pci> -- --no-hw-csum -p <portmask> --config='(port, queue, cpucore)'
    e.g ./build/UDP_Replay -c 0x7 -n 4 -w 0000:07:00.0 -w 0000:07:00.1 -- --no-hw-csum -p 0x3 --config='(0, 0, 1)(1, 0, 2)'

step 4: Run Test using traffic geneator

 On traffic generator system:
 ::

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

PROX COMMANDS AND SCREENS
-------------------------

  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  |   *RUNTIME COMMAND*                          |           *DESCRIPTION*                                                   |      *EXAMPLE*             |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | quit                                         | Stop all cores and quit                                                   |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | help <substr>                                | Show list of commands that have <substr> as a substring.                  |                            |
  |                                              | If no substring is provided, all commands are shown.                      |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | verbose <level>                              | Set the verbosity level of some printed messages.                         |                            |
  |                                              | Possible values are: 0 (default value, error messages only),              |  verbose 1                 |
  |                                              | 1 (+ warnings), 2 (+ info) and 3 (+ debugging)                            |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | thread info <core_id> <task_id>              | Show task specific information                                            |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | update interval <value>                      | Update statistics refresh rate, in msec (must be >=10).                   |                            |
  |                                              | Default is 1 second                                                       |  update interval 500       |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | rx tx info                                   | Print connections between tasks on all cores                              |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | start <core list>|all <task_id>              | Start cores specified in <core list> or all cores.                        |  start all                 |
  |                                              | If <task_id> is not specified, all tasks for the specified cores          |  start 1                   |
  |                                              | will be started.                                                          |  start 1s0-4s0             |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | stop <core list>|all <task_id>               | Stop cores specified in <core list> or all cores.                         |                            |
  |                                              | If <task_id> is not specified, all tasks for the specified                |  stop 1                    |
  |                                              | cores will be stopped.                                                    |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | dump <coreid> <taskid> <nbpkts>              | Create a hex dump of <nb_packets> from <task_id> on <core_id>             |  dump 2 1 5                |
  |                                              | showing how packets have changed between RX and TX.                       |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | dump_rx <coreid> <taskid> <nbpkts>           | Create a hex dump of <nb_packets> from <task_id> on <coreid> at RX        | dump_rx 2 1 5              |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | dump_tx <coreid> <taskid> <nbpkts>           | Create a hex dump of <nb_packets> from <task_id> on <coreid> at TX        | dump_tx 2 1 5              |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | rx distr start                               | Start gathering statistical distribution of received packets              |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | rx distr stop                                | Stop gathering statistical distribution of received packets               |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | rx distr reset                               | Reset gathered statistical distribution of received packets               |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | rx distr show                                | Display gathered statistical distribution of received packets             |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | rate <port id> <queue id> <rate>             | Set transmit rate in Mb/s. This does not include preamble, SFD and IFG    | rate 0 0 1000              |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | count <core id> <task id> <count>            | Generate <count> packets, then pause generating                           | count  1 0 5               |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | pkt_size <coreid> <taskid> <pktsize>         | Set the packet size to <pkt_size>                                         | pkt_size 1 3 255           |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | speed <core_id> <task_id> <speed percentage> | Change the speed to <speed percentage> of a                               |                            |
  |                                              | 10 Gbps line at which packets are being generated                         | speed 1 0 50               |
  |                                              | on core <core_id> in task <task_id>                                       |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | speed_byte <core_id> <task_id> <speed>       | Change speed to <speed>. The speed is specified in units of bytes per sec |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | set value <core_id> <task_id> <offset>       | Set <value_len> bytes to <value> at offset <offset> in packets            |                            |
  | <value> <value_len>                          | generated on <core_id> <task_id>                                          | set value 4 1 14 10 1      |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | reset values all                             | Undo all `set value` commands on all cores/tasks                          |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | reset values <core id> <task id>             | Undo all `set value` commands on specified core/task                      |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | arp add <core id> <task id> <port id>        |                                                                           |                            |
  | <gre id> <svlan> <cvlan> <ip addr>           |                                                                           |                            |
  | <mac addr> <user>                            | Add a single ARP entry into a CPE table on <core id>/<task id>            |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | rule add <core id> <task id> svlan_id&mask   |                                                                           |                            |
  | cvlan_id&mask ip_proto&mask                  |                                                                           |                            |
  | source_ip/prefix destination_ip/prefix       |                                                                           |                            |
  | range dport_range action                     | Add a rule to the ACL table on <core id>/<task id>                        |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | route add <core id> <task id>                |                                                                           |                            |
  | <ip/prefix> <next hop id>                    | Add a route to the routing table on core <core id> <task id>              | route add 10.0.16.0/24 9   |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | reset stats                                  | Reset all statistics                                                      |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | tot stats                                    | Print total RX and TX packets                                             |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | tot ierrors per sec                          | Print total number of ierrors per second                                  |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | pps stats                                    | Print RX and TX packet rate in unit of packet per second                  |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | lat stats <core id> <task id>                | Print min,max,avg latency as measured during last sampling interval       | lat stats 1 0              |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | lat packets <core id> <task id>              | Print the latency for each of the last set of packets                     |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | core stats <core id> <task id>               | Print rx/tx/drop for task <task id> running on core <core id>             |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | port_stats <port id>                         | Print rate for no_mbufs, ierrors, rx_bytes, tx_bytes, rx_pkts,            |                            |
  |                                              | tx_pkts and totals for RX, TX, no_mbufs ierrors for port <port id>        |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | ring info all                                | Get information about ring, such as ring size and                         |                            |
  |                                              | number of elements in the ring                                            |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | ring info <core id> <task id>                |  Get information about ring on core <core id>                             |                            |
  |                                              |  in task <task id>, such as ring size and number of elements in the ring  | ring info 1 0              |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | port info <port id> [brief]                  | Get port related information, such as MAC address, socket,                |                            |
  |                                              | number of descriptors..., . Adding `brief` after command                  |                            |
  |                                              | prints short version of output.                                           | port info 1                |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | port up <port id>                            | Set the port up (all ports are up at startup)                             | port up 1                  |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | port down <port id>                          | Set the port down                                                         | port down 1                |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | port xstats <port id>                        | Get extra statistics for the port                                         | port xstats 1              |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | version                                      | Show version                                                              |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
  | port_stats <port id>                         |  Print rate for no_mbufs, ierrors, rx_bytes, tx_bytes, rx_pkts,           |                            |
  |                                              | tx_pkts and totals for RX, TX, no_mbufs ierrors for port <port id>        |                            |
  +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+

While PROX is running, F1 to F6 change the view on the system. Pressing F1 switches to the main screen showing per core statistics. When PROX is started,
this is the screen shown by default. Pressing F2 switches to show port-based information. Pressing F3 shows information (i.e. occupancy, memory usage, ...)
about memory pools. If there are tasks with mode=lat, F4 displays latency measurements made during the last second by each of those tasks.
F5 displays DPDK ring information. F6 is for L4 generation. If no command has been entered, numbers 1 to 6 can also be used to change the view on the system.
This is provided to allow changing screens in environments that do not pass function keys to PROX.

Page Up and Page Down can be used to view per core statistics that would otherwise not fit on the screen. Escape quits PROX.
The history of previously entered commands can be navigated using the Up and Down arrows. Statistics can be reset with F12.

COMMAND LINE OPTIONS
--------------------
Run PROX with the "--help" argument to display the usage text and the list of supported options as shown below.
PROX supports many compilation flags to enable or disable features. For these flags, refer to the Makefile.
Refer to the README file for more information on how to run PROX for specific use cases.

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

CONFIGURATION FILE FORMAT
-------------------------
The configuration file is divided into multiple sections, each of which is used to define some parameters and options.
Sections are created using the [section name] syntax. The list of sections, where # represents an integer, is as follows:

::

    [eal options]
    [port #]
    [variables]
    [defaults]
    [global]
    [core #]

In each section, entries are created using the key=value syntax.
Comments are created using the ; symbol: all characters from the ;
symbol to the end of line are ignored. A # symbol at the beginning of the section name comments
the whole section out: all entries in the section are treated as comments and are ignored. For example:

::

    [#core 1]
    ; this is a comment
    parameter name=parameter value ; this entry is ignored because the section is commented out

* [EAL OPTIONS]: The following parameters are supported:

::

    -m  ; Specifies the amount of memory used. If not provided, all hugepages will be used.
    -n  ; Specifies the number of memory channels. Use -n4 for latest Intel Xeon based platforms
    -r  ; Specifies the number of memory ranks.
    eal ; Specifies DPDK EAL extra options. Those options will be passed blindly to DPDK.

* [PORT #]: DPDK ports are usually referenced by their port_id, i.e. an integer starting from 0.
  Using port_id in the configuration file is tedious, since the same port_id can appear at
  different places (rx port, tx port, routing tables), and those ports might change (e.g. if cables are swapped).
  In order to make the configuration file easier to read and modify, DPDK ports are given a name with the name= option.
  The name serves as the reference, and in addition, it will show up in the display at runtime.

::

    PARAMETER    EXAMPLE         DESCRIPTION
    ----------------------------------------------------------------------------
    name         inet0           Use inet0 to later refer to this port
    mac          hardware        value can be: hardware, random or a literal MAC address
    rx desc      256             number of descriptors to allocate for reception
    tx desc      256             number of descriptors to allocate for transmission
    promiscuous  yes             enable promiscuous mode
    strip crc    yes             enable CRC stripping
    rss          yes             enable RSS
    lsc          no              While lsc is disabled for drivers known to not provide support,
                                     this option explicitely overrides these settings.
    rx_ring      dpdk_ring_name  use DPDK ring as an interface (receive side)
    tx_ring      dpdk_ring_name  use DPDK ring as an interface (transmit side)

* [VARIABLES]: Variables can be defined in the configuration file using the $varname=value syntax.
  Variables defined on the command line (-w varname=value) take precedence and do not create
  conflicts with variables defined in the configuration file. Variables are used in the
  configuration file using the $varname syntax: each instance of $varname is replaced by its
  associated value. This is typically useful if the same parameter must be used at several places.
  For instance, you might want to have multiple load balancers, all transmitting to the same set
  of worker cores. The list of worker cores could then be defined once in a variable:

::

    [variables]
    $wk=1s0-5s0

Then, a load balancer definition would use the variable:

::

    [core 6s0]
    name=LB
    task=0
    mode=lbnetwork
    tx cores=$wk task=0
    ...

And the section defining the worker cores would be:

::

    [core $wk]
    name=worker
    task=0
    mode=qinqencapv4
    ...

* [DEFAULTS]: The default value of some options can be overridden using the [defaults] section:

::

  PARAMETER     EXAMPLE   DESCRIPTION
  -----------------------------------
  mempool       size      16K number of mbufs per task, relevant when task receives from a port.
                          this is the n argument provided to rte_mempool_create()
  qinq tag      0xa888    Set qinq tag for all tasks. The result of adding this option is the
                          same as adding qinq tag= to each task
  memcache size 128       number of mbufs cached per core, default is 256 this is the cache_size
                          argument provided to rte_mempool_create()

* [GLOBAL]: The following parameters are supported:

::

  PARAMETER          EXAMPLE            DESCRIPTION
  -------------------------------------------------
  name               BNG                Name of the configuration, which will be shown in the title box at runtime.
  start time         10                 Time in seconds after which average statistics will be started.
                                        Default value is 0.
  duration time      30                 Runtime duration in seconds, counted after start time.
                                        This is typically useful to automate testing using
                                        different parameters: PROX automatically exits when the
                                        runtime duration has elapsed. Initialization and start time
                                        are not included in this runtime duration.
                                        For example, if start time is set to 10 and duration time is set to 30,
                                        the total execution time (after initialization) will be 40 seconds.
                                        Default value is 0, which means infinity and prevents PROX from automatically exiting.
  shuffle            yes                When this parameter is set to yes, the order of mbufs
                                        within mempools is randomized to simulate a system that has
                                        been warmed up. Default value is no.
  gre cfg            /path/to/file.csv  Path to CSV file that provides QinQ-to-GRE mapping.
                                        Default value is gre_table.csv in same directory as
                                        configuration file. Fields are GRE key and QinQ value (computed as SVLAN * 4096 + CVLAN).
  pre cmd            ls                 Arbitrary system commands to run while reading cfg. This option can occur multiple times.
  user cfg           /path/to/file.csv  Path to CSV file that provides QinQ-to-User mapping.
                                        Default value is user_table.csv in same directory as configuration file.
                                        Fields are SVLAN, CVLAN and User-Id.
  next hop cfg       /path/to/file.csv  Path to CSV file that provides Next-Hop details.
                                        Default value is next_hop.csv in same directory as configuration file.
                                        Fields are Next-Hop index (as returned by LPM lookup),
                                        Out-Port index, Next-Hop IP (unused), Next-Hop MAC and MPLS label.
  ipv4 cfg           /path/to/file.csv  Path to CSV file that provides IPv4 LPM routing table.
                                        Default value is ipv4.csv in same directory as configuration file.
                                        Fields are IPv4 subnet (in CIDR notation) and Next-Hop index.
  dscp cfg           /path/to/file.csv  Path to CSV file that provides mapping for QoS classification,
                                        from DSCP to Traffic Class and Queue.
                                        Default value is dscp.csv in same directory as configuration file.
                                        Fields are DSCP (0-63), Traffic Class (0-3) and Queue (0-3).
  ipv6 tunnel cfg    /path/to/file.csv  Path to CSV file that provides lwAFTR binding table.
                                        Default value is ipv6_tun_bind.csv in same directory as configuration file.
                                        Fields are lwB4 IPv6 address, next hop MAC address towards lwB4,
                                        IPv4 Public address and IPv4 Public Port Set.
  acl cfg            /path/to/file.csv  Path to CSV file that provides ACL rules.
                                        Default value is rules.csv in same directory as configuration file.
                                        Fields are SVLAN value & mask, CVLAN value & mask, IP protocol value & mask,
                                        source IPv4 subnet (in CIDR notation), destination IPv4 subnet (in CIDR notation),
                                        source port range, destination port range, and action (drop, allow, rate limit).
  unique mempool     yes
  per socket

* [CORE #]: Cores can be configured by means of a set of [core #] sections, where # represents either:

  an absolute core number: e.g. on a 10-core, dual socket system with hyper-threading, cores are numbered from 0 to 39;
  a core number, the letter 's', and a socket number: this allows selecting per-socket cores, independently from their interleaved numbering;
  a core number and the letter 'h': this allows selecting the hyper-thread sibling of the specified core;
  a dash-separated range of core numbers; a comma-separated list of core numbers; any combination of the above;
  or a variable whose value complies with the above syntax.
  The socket and hyper-thread syntax makes it easier to use the same configuration file on several platforms,
  even if their core numbering differs (e.g. interleaving rule or number of cores per socket).

  Each core can be assigned with a set of tasks, each running one of the implemented packet processing modes.

The following parameters are supported:

.. image:: images/prox_core.png
   :width: 800px
   :alt: SampleVNF supported topology

Compiling and running this application
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

PREREQUISITES
^^^^^^^^^^^^^
DPDK must be installed prior to running make in the PROX directory.
The README file shipped with PROX describes what versions of DPDK are supported,
and if any patches are needed for the chosen DPDK version.

The following packages need to be installed. (Example for destributions that are using rpm)

::

  sudo yum install net-tools wget gcc unzip libpcap-devel ncurses-devel libedit-devel pciutils lua-devel kernel-devel
  Jump Start

The following instructions are here to help customers to start using PROX.
It's by no means a complete guide, for detailed instructions on how to install and use
DPDK please refer to its documentation.
Your mileage may vary depending on a particular Linux distribution and hardware in use.

Edit grub default configuration:

::

  vi /etc/default/grub

Add the following to the kernel boot parameters

::

  default_hugepagesz=1G hugepagesz=1G hugepages=8

Rebuild grub config and reboot the system:

::

  grub2-mkconfig -o /boot/grub2/grub.cfg
  reboot

Verify that hugepages are available

::

    cat /proc/meminfo
    ...
    HugePages_Total:  8
    HugePages_Free:   8
    Hugepagesize:     1048576 kB
    ...

Re-mount huge pages

::

  mkdir -p /mnt/huge
  umount `awk '/hugetlbfs/ { print $2 }' /proc/mounts` >/dev/null 2>&1
  mount -t hugetlbfs nodev /mnt/huge/

This application supports DPDK 16.04, 16.11, 17.02 and 17.05.
The following commands assume that the following variables have been set:

export RTE_SDK=/path/to/dpdk
export RTE_TARGET=x86_64-native-linuxapp-gcc

PROX Compiation installation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* git clone https://git.opnfv.org/samplevnf
* cd samplevnf
* export RTE_SDK=`pwd`/dpdk
* export RTE_TARGET=x86_64-native-linuxapp-gcc
* git clone http://dpdk.org/git/dpdk
* cd dpdk
* git checkout v17.05
* make install T=$RTE_TARGET
* cd <samplevnf>/VNFs/DPPD-PROX
* make

or Auto build

::

  * git clone https://git.opnfv.org/samplevnf
  * cd samplevnf
  * ./tools/vnf_build.sh -s -d='17.05' [-p=<proxy> if behind the proxy]

Load uio module

::

  lsmod | grep -w "^uio" >/dev/null 2>&1 || sudo modprobe uio
  sleep 1

Load igb_uio module

::

  lsmod | grep -w "^igb_uio" >/dev/null 2>&1 || sudo insmod $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko

Discover network devices available on the system:

::

  lspci | grep Ethernet

Prior launching PROX, ports that are to be used by it must be bound to the igb_uio driver.

The following command will bind all Intel® Ethernet Converged Network Adapter X710 ports to igb_uio:

::

  lspci | grep X710 | cut -d' ' -f 1 | sudo xargs -I {} python2.7 $RTE_UNBIND --bind=igb_uio {}

The following command will bind all Intel® 82599 10 Gigabit Ethernet Controller ports to igb_uio:

::

  lspci | grep 82599 | cut -d' ' -f 1 | sudo xargs -I {}  python2.7 $RTE_UNBIND --bind=igb_uio {}

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

::

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

::

  * config/nop.cfg
  * config/nop-rings.cfg
  * gen/nop-gen.cfg

Simplified BNG (Border Network Gateway) configurations, using different
number of ports, with and without QoS, running on the host or in a VM:

::

  * config/bng-4ports.cfg
  * config/bng-8ports.cfg
  * config/bng-qos-4ports.cfg
  * config/bng-qos-8ports.cfg
  * config/bng-1q-4ports.cfg
  * config/bng-ovs-usv-4ports.cfg
  * config/bng-no-cpu-topology-4ports.cfg
  * gen/bng-4ports-gen.cfg
  * gen/bng-8ports-gen.cfg
  * gen/bng-ovs-usv-4ports-gen.cfg

Light-weight AFTR configurations:

::

  * config/lw_aftr.cfg
  * gen/lw_aftr-gen.cfg
