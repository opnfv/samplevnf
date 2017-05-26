.. This work is licensed under a Creative Commons Attribution 4.0 International
.. License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) OPNFV, National Center of Scientific Research "Demokritos" and others.

=========================================================
UDP_Replay
=========================================================

1. Introduction
================

This is a beta release for Sample UDP_Replay application.
This UDP_Replay can application can be run independently (refer INSTALL.rst).

2. User Guide
===============
Refer to README.rst for further details on UDP_Replay, HLD, features supported, test
plan. For build configurations and execution requisites please refer to
INSTALL.rst.

3. Feature for this release
===========================
This release supports following features as part of UDP_Replay:
  - L2l3 stack
  - Interface Manager
  - ARP solicitation & response. implements ARP states
  - Implements ICMPv4 support handling echo request/response messages
  - ICMPv6 support handling echo request/response messages
  - ND handling neighbour solicitation & neighbour advertisement messages

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

6. Future Work
==============
Following would be possible enhancement functionalities
 - Automatic enable/disable of synproxy
 - Support TCP timestamps with synproxy
 - FTP ALG integration
 - Performance optimization on different platforms

7. References
=============
Following links provides additional information
	.. _QUICKSTART: http://dpdk.org/doc/guides-16.04/linux_gsg/quick_start.html
	.. _DPDKGUIDE: http://dpdk.org/doc/guides-16.04/prog_guide/index.html
