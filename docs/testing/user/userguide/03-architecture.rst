.. This work is licensed under a Creative Commons Attribution 4.0 International
.. License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) OPNFV, Intel Corporation and others.

============
Architecture
============

Abstract
========
This chapter describes the samplevnf software architecture.
we will introduce it VNFs. More technical details will be introduced in this chapter.

Overview
========

Architecture overview
---------------------
This project provides a placeholder for various sample VNF (Virtual Network Function)
development which includes example reference architecture and optimization methods
related to VNF/Network service for high performance VNFs.

The sample VNFs are Open Source approximations* of Telco grade VNF’s using
optimized VNF + NFVi Infrastructure libraries, with Performance Characterization
of Sample† Traffic Flows.

::

 * Not a commercial product. Encourage the community to contribute and close the feature gaps.
 † No Vendor/Proprietary Workloads

It helps to facilitate deterministic & repeatable bench-marking on Industry
standard high volume Servers. It augments well with a Test infrastructure to
help facilitate consistent/repeatable methodologies for characterizing &
validating the sample VNFs through OPEN SOURCE VNF approximations and test tools.
The VNFs belongs to this project are never meant for field deployment.
All the VNF source code part of this project requires Apache License Version 2.0.

Supported deployment:
----------------------
* Bare-Metal - All VNFs can run on a Bare-Metal DUT
* Standalone Virtualization(SV): All VNFs can run on SV like VPP as switch, ovs,
  ovs-dpdk, srioc
* Openstack: Latest Openstack supported

VNF supported
-------------
 - Carrier Grade Network Address Translation (CG-NAT) VNF
   ::
      The Carrier Grade Network Address and port Translation (vCG-NAPT) is a
      VNF approximation extending the life of the service providers IPv4 network
      infrastructure and mitigate IPv4 address exhaustion by using address and
      port translation in large scale. It processes the traffic in both the directions.
      It also supports the connectivity between the IPv6 access network to
      IPv4 data network using the IPv6 to IPv4 address translation and vice versa.
 - Firewall (vFW) VNF
   ::
      The Virtual Firewall (vFW) is a VNF approximation serving as a state full
      L3/L4 packet filter with connection tracking enabled for TCP, UDP and ICMP.
      The VNF could be a part of Network Services (industry use-cases) deployed
      to secure the enterprise network from un-trusted network.
 - Access Control List (vACL) VNF
   ::
      The vACL vNF is implemented as a DPDK application using VNF Infrastructure
      Library (VIL). The VIL implements common VNF internal, optimized for
      Intel Architecture functions like load balancing between cores, IPv4/IPv6
      stack features, and interface to NFV infrastructure like OVS or SRIOV.
 - UDP_Replay
   ::
      The UDP Replay is implemented as a DPDK application using VNF Infrastructure
      Library (VIL). Performs as a refelector of all the traffic on given port.
 - Prox - Packet pROcessing eXecution engine.
   ::
      Packet pROcessing eXecution Engine (PROX) which is a DPDK application.
      PROX can do operations on packets in a highly configurable manner.
      The PROX application is also displaying performance statistics that can
      be used for performance investigations.
      Intel® DPPD - PROX is an application built on top of DPDK which allows
      creating software architectures, such as the one depicted below, through
      small and readable configuration files.
      This VNF can act as L2FWD, L3FWD, BNG etc.

Feature supported by the VNFs
-----------------------------

The following features were verified by SampleVNF test cases:

   - vFW - Virtual Firewall

     * Basic Packet filter dropping malformed, invalid packets based on L3/L4 packet headers
     * Policy based filtering
     * Dynamic Packet filtering through Connection Tracker for TCP and UDP
     * SYN-flood protection via synproxy for TCP
     * UDP, TCP and ICMP protocol pass-through
     * CLI based enable/disable connection tracking, synproxy, basic packet filtering
     * Multithread support
     * Multiple physical port support
     * Providing statistics on traffic traversing the VNF

   - vCG-NAPT - Carrier Grade Network Address and port Translation

     * Static and dynamic Network address translation.
     * Static and dynamic Network address and port translation
     * ARP (request, response, gratuitous)
     * ICMP (terminal echo, echo response, pass-through)
     * UDP, TCP and ICMP protocol pass-through
     * Multithread support and Multiple physical port support
     * Limiting max ports per client
     * Limiting max clients per public IP address
     * Live Session tracking to NAT flow
     * NAT64 – connectivity between IPv6 access network to IPv4 data network.

   - vACL - Access Control List

     * CLI based Run-time rule configuration (Add, Delete, List, Display, Clear, Modify)
     * IPv4 and IPv6 5 tuple packet Selector support
     * Counting packets and bytes per rule
     * Multithread support
     * Multiple physical port support
     * Forwarding packets to specific ports on base of rules
     * Rules definition on base TCP/UDP connection tracking

   - Prox - Packet pROcessing eXecution engine.

     * Classify
     * Drop
     * Basic Forwarding (no touch)
     * L2 Forwarding (change MAC)
     * GRE encap/decap
     * Load balance based on packet fields
     * Symmetric load balancing
     * QinQ encap/decap IPv4/IPv6
     * ARP
     * QoS
     * Routing
     * Unmpls
     * Policing
     * Basic ACL
     * Basic CGNAT

Test Framework
--------------

.. _Yardstick_NSB: http://artifacts.opnfv.org/yardstick/docs/testing_user_userguide/index.html#document-13-nsb-overview

SampleVNF Test Infrastructure (NSB (Yardstick_NSB_)) in yardstick helps to facilitate
consistent/repeatable methodologies for characterizing & validating the
sample VNFs (:term:`VNF`) through OPEN SOURCE VNF approximations.


Network Service Benchmarking in yardstick framework follows ETSI GS NFV-TST001_
to verify/characterize both :term:`NFVI` & :term:`VNF`

For more inforamtion refer, Yardstick_NSB_

SampleVNF Directory structure
=============================

**samplevnf/** - SampleVNF main directory.

*common/* - Common re-useable code like arp, nd, packet fwd etc

*docs/* - All documentation is stored here, such as configuration guides,
          user guides and SampleVNF descriptions.

*tools/* - Currently contains tools to build image for VMs which are deployed
           by Heat. Currently contains helper scripts like install, setup env

*VNFs/* - all VNF source code directory.

*VNF_Catalogue/* - Collection of all  Open Source VNFs

*heat_template/* - Sample HEAT templates for VNFs
