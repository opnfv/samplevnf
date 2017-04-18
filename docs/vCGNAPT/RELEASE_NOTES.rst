.. This work is licensed under a Creative Commons Attribution 4.0 International
.. License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) OPNFV, National Center of Scientific Research "Demokritos" and others.

=========================================================
Carrier Grade Network Address Port Translation - vCGNAPT
=========================================================

1.	Introduction
================
This is the beta release for vCGNAPT VNF.
vCGNAPT application can be run independently (refer INSTALL.rst).

2.	User Guide
===============
Refer to README.rst for further details on vCGNAPT, HLD, features supported, test
plan. For build configurations and execution requisites please refer to
INSTALL.rst.

3. Feature for this release
===========================
This release supports following features as part of vCGNAPT:
-	vCGNAPT can run as a standalone application on bare-metal linux server or on a
	virtual machine using SRIOV and OVS dpdk.
- Static NAT
- Dynamic NAT
- Static NAPT
- Dynamic NAPT
- ARP (request, response, gratuitous)
- ICMP (terminal echo, echo response, passthrough)
- ICMPv6 and ND (Neighbor Discovery)
- UDP, TCP and ICMP protocol passthrough
- Multithread support
- Multiple physical port support
- Limiting max ports per client
- Limiting max clients per public IP address
- Live Session tracking to NAT flow
- PCP support
- NAT64
- ALG SIP
- ALG FTP

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
-	Hadware Loab Balancer feature is supported on fortville nic FW version 4.53 and below. 
- L4 UDP Replay is used to capture throughput for dynamic cgnapt
- Hardware Checksum offload is not supported for IPv6 traffic.
- CGNAPT on sriov is tested till 4 threads

6. Future Work
==============
- SCTP passthrough support
- Multi-homing support
- Performance optimization on different platforms

7. References
=============
Following links provides additional information
	.. _QUICKSTART: http://dpdk.org/doc/guides-16.04/linux_gsg/quick_start.html
	.. _DPDKGUIDE: http://dpdk.org/doc/guides-16.04/prog_guide/index.html
