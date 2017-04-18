.. This work is licensed under a creative commons attribution 4.0 international
.. license.
.. http://creativecommons.org/licenses/by/4.0
.. (c) opnfv, national center of scientific research "demokritos" and others.

========================================================
Virtual ACL - vACL
========================================================

1. Introduction
==============
This application implements Access Control List (ACL). ACL is typically 
used for rule based policy enforcement. It restricts access to a destination
IP address/port based on various header fields, such as source IP address/port, 
destination IP address/port and protocol. It is built on top of DPDK and
uses the packet framework infrastructure.


About DPDK
----------
The DPDK IP Pipeline Framework provides a set of libraries to build a pipeline
application. In this document, vACL will be explained in detail with its own
building blocks.

This document assumes the reader possesses the knowledge of DPDK concepts and
packet framework. For more details, read DPDK Getting Started Guide, DPDK
Programmers Guide, DPDK Sample Applications Guide.

2.  Scope
==========
This application provides a standalone DPDK based high performance vACL Virtual
Network Function implementation.

3. Features
===========
The vACL VNF currently supports the following functionality:
  • CLI based Run-time rule configuration.(Add, Delete, List,  Display,  Clear, Modify)
  • Ipv4 and ipv6 standard 5 tuple packet Selector support.
  • Multithread support
  • Multiple physical port support
  • Hardware and Software Load Balancing
  • L2L3 stack support for ARP/ICMP handling
  • ARP (request, response, gratuitous)
  • ICMP (terminal echo, echo response, passthrough)
  • ICMPv6 and ND (Neighbor Discovery)
 
4. High Level Design
====================
The ACL Filter performs bulk filtering of incoming packets based on rules in current ruleset,
discarding any packets not permitted by the rules. The mechanisms needed for building the
rule database and performing lookups are provided by the DPDK API.
http://dpdk.org/doc/api/rte__acl_8h.html

The Input FIFO contains all the incoming packets for ACL filtering. Packets will be dequeued
from the FIFO in bulk for processing by the ACL. Packets will be enqueued to the output FIFO.
The Input and Output FIFOs will be implemented using DPDK Ring Buffers.

The DPDK ACL example: http://dpdk.org/doc/guides/sample_app_ug/l3_forward_access_ctrl.html
#figure-ipv4-acl-rule contains a suitable syntax and parser for ACL rules.

===================
5. Components of vACL
===================
In vACL, each component is constructed using packet framework pipelines. 
It includes Rx and Tx Driver, Master pipeline, load balancer pipeline and
vACL worker pipeline components. A Pipeline framework is a collection of input
ports, table(s),output ports and actions (functions).

Receive and Transmit Driver
******************************
Packets will be received in bulk and provided to LoadBalancer(LB) thread.
Transimit takes packets from worker threads in a dedicated ring and sent to
hardware queue.

Master Pipeline
******************************
The Master component is part of all the IP Pipeline applications. This component
does not process any packets and should configure with Core 0, to allow
other cores for processing of the traffic. This component is responsible for
 1. Initializing each component of the Pipeline application in different threads
 2. Providing CLI shell for the user control/debug
 3. Propagating the commands from user to the corresponding components

ARPICMP Pipeline
******************************
This pipeline processes the APRICMP packets.

TXRX Pipelines
******************************
The TXTX and RXRX pipelines are pass through pipelines to forward both ingress
and egress traffic to Loadbalancer. This is required when the Software
Loadbalancer is used.

Load Balancer Pipeline
******************************
The vACL support both hardware and software balancing for load blalcning of 
traffic across multiple VNF threads. The Hardware load balncing require support
from hardware like Flow Director for steering of packets to application through
hardware queues. 

The Software Load balancer is also supported if hardware loadbalancing can't be
used for any reason. The TXRX along with LOADB pipeline provides support for
software load balancing by distributing the flows to Multiple vACL worker
threads.
Loadbalancer (HW or SW) distributes traffic based on the 5 tuple (src addr, src 
port, dest addr, dest port and protocol) applying an XOR logic distributing to
active worker threads, thereby maintaining an affinity of flows to worker
threads.

vACL Pipeline
******************************
The vACL performs the rule-based packet filtering.

vACL Topology:
------------------------
::
  IXIA(Port 0)-->(Port 0)VNF(Port 1)-->(Port 1) IXIA
  operation:
    Egress --> The packets sent out from ixia(port 0) will be sent through ACL to ixia(port 1).
    Igress --> The packets sent out from ixia(port 1) will be sent through ACL to ixia(port 0).

vACL Topology (L4REPLAY):
------------------------------------
::
  IXIA(Port 0)-->(Port 0)VNF(Port 1)-->(Port 0)L4REPLAY
  operation:
    Egress --> The packets sent out from ixia will pass through vACL to L3FWD/L4REPLAY.
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
Plase refer to <samplevnf>/docs/vACL/INSTALL.rst for installation, configuration, compilation
and execution.
