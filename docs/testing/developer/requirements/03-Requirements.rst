.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) OPNFV, Intel Corporation and others.

.. OPNFV SAMPLEVNF Documentation design file.

============
Requirements
============

**Required Test setup:**

.. _SampleVNF: https://wiki.opnfv.org/samplevnf
.. _Technical_Briefs: https://wiki.opnfv.org/display/SAM/Technical+Briefs+of+VNFs

Supported Test setup:
--------------------

The device under test (DUT) consists of a system following

  * A single or dual processor and PCH chip, except for System on Chip (SoC) cases
  * DRAM memory size and frequency (normally single DIMM per channel)
  * Specific Intel Network Interface Cards (NICs)
  * BIOS settings noting those that updated from the basic settings
  * DPDK build configuration settings, and commands used for tests

Connected to the DUT is an IXIA* or Software Traffic generator like pktgen or TRex,
simulation platform to generate packet traffic to the DUT ports and
determine the throughput/latency at the tester side.


Hardware & Software Ingredients
-------------------------------

::

   +---------------+------------------+
   | Item          | Description      |
   +---------------+------------------+
   | Memory        | Min 20GB         |
   +---------------+------------------+
   | NICs          | 2 x 10G          |
   +---------------+------------------+
   | HostOS/Guest  | Ubuntu 16.04 LTS |
   +---------------+------------------+
   | kernel        | >4.4.0-34-generic|
   +---------------+------------------+
   |DPDK           | >17.02           |
   +---------------+------------------+

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

- Single port pair : One pair ports used for traffic

 ::

     e.g. Single port pair link0 and link1 of VNF are used
     TG:port 0 <------> VNF:Port 0
     TG:port 1 <------> VNF:Port 1


-  Multi port pair :  More than one pair of traffic

 ::

     e.g. Two port pair link 0, link1, link2 and link3 of VNF are used
     TG:port 0 <------> VNF:Port 0
     TG:port 1 <------> VNF:Port 1
     TG:port 2 <------> VNF:Port 2
     TG:port 3 <------> VNF:Port 3

For openstack/Standalone virtualization, installation please refer the openstack guide and ovs-dpdk/sriov github.
(TBA - Add link to guide)
