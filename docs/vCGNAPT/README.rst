.. this work is licensed under a creative commons attribution 4.0 international
.. license.
.. http://creativecommons.org/licenses/by/4.0
.. (c) opnfv, national center of scientific research "demokritos" and others.

========================================================
Carrier Grade Network Address Port Translation - vCGNAPT
========================================================

1 Introduction
==============
This application implements vCGNAPT. The idea of vCGNAPT is to extend the life of
the service providers IPv4 network infrastructure and mitigate IPv4 address
exhaustion by using address and port translation in large scale. It processes the
traffic in both the directions.

It also supports the connectivity between the IPv6 access network to IPv4 data network
using the IPv6 to IPv4 address translation and vice versa.

About DPDK
----------
The DPDK IP Pipeline Framework provides set of libraries to build a pipeline
application. In this document, CG-NAT application will be explained with its
own building blocks.

This document assumes the reader possess the knowledge of DPDK concepts and IP
Pipeline Framework. For more details, read DPDK Getting Started Guide, DPDK
Programmers Guide, DPDK Sample Applications Guide.

2.  Scope
==========
This application provides a standalone DPDK based high performance vCGNAPT
Virtual Network  Function implementation.

3. Features
===========
The vCGNAPT VNF currently supports the following functionality:
  • Static NAT
  • Dynamic NAT
  • Static NAPT
  • Dynamic NAPT
  • ARP (request, response, gratuitous)
  • ICMP (terminal echo, echo response, passthrough)
  • ICMPv6 and ND (Neighbor Discovery)
  • UDP, TCP and ICMP protocol passthrough
  • Multithread support
  • Multiple physical port support
  • Limiting max ports per client
  • Limiting max clients per public IP address
  • Live Session tracking to NAT flow
  • NAT64
  • PCP Support
  • ALG SIP
  • ALG FTP

4. High Level Design
====================
The Upstream path defines the traffic from Private to Public and the downstream
path defines the traffic from Public to Private. The vCGNAPT has same set of
components to process Upstream and Downstream traffic.

In vCGNAPT application, each component is constructed as IP Pipeline framework.
It includes Master pipeline component, load balancer pipeline component and vCGNAPT
pipeline component.

A Pipeline framework is collection of input ports, table(s), output ports and
actions (functions). In vCGNAPT pipeline, main sub components are the Inport function
handler, Table and Table function handler. vCGNAPT rules will be configured in the
table which translates egress and ingress traffic according to physical port
information from which side packet is arrived. The actions can be forwarding to the
output port (either egress or ingress) or to drop the packet.

vCGNAPT Graphical Overview
==========================
The idea of vCGNAPT is to extend the life of the service providers IPv4 network infrastructure
and mitigate IPv4 address exhaustion by using address and port translation in large scale.
It processes the traffic in both the directions.

.. code-block:: console
  +------------------+
  |                 +-----+
  | Private consumer | CPE  |---------------+
  |   IPv4 traffic  +-----+                 |
  +------------------+                      |
                 +------------------+       v        +----------------+
                 |                  | +------------+ |                |
                 |   Private IPv4   | |  vCGNAPT   | |    Public      |
                 |  access network  | |   NAT44    | |  IPv4 traffic  |
                 |                  | +------------+ |                |
                 +------------------+       |        +----------------+
  +------------------+                      |
  |                 +-----+                 |
  | Private consumer| CPE |-----------------+
  |  IPv4 traffic   +-----+
  +------------------+
      Figure 1: vCGNAPT deployment in Service provider network


Components of vCGNAPT
=====================
In vCGNAPT, each component is constructed as a packet framework. It includes Master pipeline
component, driver, load balancer pipeline component and vCGNAPT worker pipeline component. A
pipeline framework is a collection of input ports, table(s), output ports and actions
(functions).

Receive and transmit driver
----------------------------
Packets will be received in bulk and provided to load balancer thread. The transmit takes
packets from worker thread in a dedicated ring and sent to the hardware queue.

ARPICMP pipeline
------------------------
ARPICMP pipeline is responsible for handling all l2l3 arp related packets.

----------------
This component does not process any packets and should configure with Core 0,
to save cores for other components which processes traffic. The component
is responsible for:
 1. Initializing each component of the Pipeline application in different threads
 2. Providing CLI shell for the user
 3. Propagating the commands from user to the corresponding components.
 4. ARP and ICMP are handled here.

Load Balancer pipeline
------------------------
Load balancer is part of the Multi-Threaded CGMAPT release which distributes
the flows to Multiple ACL worker threads.

Distributes traffic based on the 2 or 5 tuple (source address, source port,
destination  address, destination port and protocol) applying an XOR logic
distributing the  load to active worker threads, thereby maintaining an
affinity of flows to  worker threads.

Tuple can be modified/configured using configuration file

4. vCGNAPT - Static
====================
The vCGNAPT component performs translation of private IP & port to public IP &
port at egress side and public IP & port to private IP & port at Ingress side
based on the NAT rules added to the pipeline Hash table. The NAT rules are
added to the Hash table via user commands. The packets that have a matching
egress key or ingress key in the NAT table will be processed to change IP &
port and will be forwarded to the output port. The packets that do not have a
match will be taken a default action. The default action may result in drop of
the packets.

5. vCGNAPT- Dynamic
===================
The vCGNAPT component performs translation of private IP & port to public IP & port
at egress side and public IP & port to private IP & port at Ingress side based on the
NAT rules added to the pipeline Hash table. Dynamic nature of vCGNAPT refers to the
addition of NAT entries in the Hash table dynamically when new packet arrives. The NAT
rules will be added to the Hash table automatically when there is no matching entry in
the table and the packet is circulated through software queue. The packets that have a
matching egress key or ingress key in the NAT table will be processed to change IP &
port and will be forwarded to the output port defined in the entry.

Dynamic vCGNAPT acts as static one too, we can do NAT entries statically. Static NAT
entries port range must not conflict to dynamic NAT port range.

vCGNAPT Static Topology:
------------------------
::
  IXIA(Port 0)-->(Port 0)VNF(Port 1)-->(Port 1) IXIA
  operation:
    Egress --> The packets sent out from ixia(port 0) will be CGNAPTed to ixia(port 1).
    Igress --> The packets sent out from ixia(port 1) will be CGNAPTed to ixia(port 0).

vCGNAPT Dynamic Topology (L4REPLAY):
------------------------------------
::
  IXIA(Port 0)-->(Port 0)VNF(Port 1)-->(Port 0)L4REPLAY
  operation:
    Egress --> The packets sent out from ixia will be CGNAPTed to L3FWD/L4REPLAY.
    Ingress --> The L4REPLAY upon reception of packets (Private to Public Network),
                will immediately replay back the traffic to IXIA interface. (Pub -->Priv).

How to run L4Replay:
--------------------
::
  1. After the installation of samplevnf:
     go to <samplevnf/VNFs/L4Replay>
  2. ./buid/L4replay -c  core_mask -n no_of_channels(let it be as 2) -- -p PORT_MASK --config="(port,queue,lcore)"
     eg: ./L4replay -c 0xf -n 4 -- -p 0x3 --config="(0,0,1)"

6. Installation, Compile and Execution
-----------------------------------------------------------------
Plase refer to <samplevnf>/docs/vCGNAPT/INSTALL.rst for installation, configuration, compilation
and execution.
