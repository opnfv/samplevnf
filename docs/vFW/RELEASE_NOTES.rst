.. This work is licensed under a Creative Commons Attribution 4.0 International
.. License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) OPNFV, National Center of Scientific Research "Demokritos" and others.

=========================================================
Virtual Firewall - vFW
=========================================================

1.	Introduction
================

This is a beta release for Sample Virtual Firewall VNF.
This vFW can application can be run independently (refer INSTALL.rst).

2.	User Guide
===============
Refer to README.rst for further details on vFW, HLD, features supported, test
plan. For build configurations and execution requisites please refer to
INSTALL.rst.

3. Feature for this release
===========================
This release supports following features as part of vFW:
  - Basic packet filtering (malformed packets, IP fragments)
  - Connection tracking for TCP and UDP
  - Access Control List for rule based policy enforcement
  - SYN-flood protection via Synproxy* for TCP
  - UDP, TCP and ICMP protocol pass-through
  - CLI based enable/disable connection tracking, synproxy, basic packet
    filtering
  - L2L3 stack support for ARP/ICMP handling
  - ARP (request, response, gratuitous)
  - ICMP (terminal echo, echo response, passthrough)
  - ICMPv6 and ND (Neighbor Discovery)
  - Hardware and Software Load Balancing
  - Multithread support
  - Multiple physical port support

4. System requirements - OS and kernel version
==============================================
This is supported on Ubuntu 14.04 and Ubuntu 16.04 and kernel version less than 4.5

   VNFs on BareMetal support:
                OS: Ubuntu 14.04 or 16.04 LTS
                kernel: < 4.5
                http://releases.ubuntu.com/16.04/
                Download/Install the image: ubuntu-16.04.1-server-amd64.iso

   VNFs on Standalone Hypervisor
                HOST OS: Ubuntu 14.04 or 16.04 LTS
                http://releases.ubuntu.com/16.04/
                Download/Install the image: ubuntu-16.04.1-server-amd64.iso
             -   OVS (DPDK) - 2.5
             -   kernel: < 4.5
             -   Hypervisor - KVM
             -   VM OS - Ubuntu 16.04/Ubuntu 14.04

5. Known Bugs and limitations
=============================
 - Hadware Load Balancer feature is supported on fortville nic FW version 4.53 and below.
 - Hardware Checksum offload is not supported for IPv6 traffic.
 - vFW on sriov is tested upto 4 threads
 - Http Multiple clients/server with HWLB is not working

6. Future Work
==============
Following would be possible enhancement functionalities
 - Automatic enable/disable of synproxy
 - Support TCP timestamps with synproxy
 - FTP ALG integration
 - Performance optimization on different platforms

7. References
=============
Following links provides additional information for differenet version of DPDKs
        .. _QUICKSTART:
                        http://dpdk.org/doc/guides-16.04/linux_gsg/quick_start.html
                        http://dpdk.org/doc/guides-16.11/linux_gsg/quick_start.html
                        http://dpdk.org/doc/guides-17.02/linux_gsg/quick_start.html
                        http://dpdk.org/doc/guides-17.05/linux_gsg/quick_start.html

        .. _DPDKGUIDE:
                        http://dpdk.org/doc/guides-16.04/prog_guide/index.html
                        http://dpdk.org/doc/guides-16.11/prog_guide/index.html
                        http://dpdk.org/doc/guides-17.02/prog_guide/index.html
                        http://dpdk.org/doc/guides-17.05/prog_guide/index.html
