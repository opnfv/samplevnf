.. This work is licensed under a creative commons attribution 4.0 international
.. license.
.. http://creativecommons.org/licenses/by/4.0
.. (c) opnfv, national center of scientific research "demokritos" and others.

========================================================
Virtual Firewall - vFW
========================================================

1. Introduction
==============
The virtual firewall (vFW) is an application implements Firewall. vFW is used
as a barrier between secure internal and an un-secure external network. The
firewall performs Dynamic Packet Filtering. This involves keeping track of the
state of Layer 4 (Transport)traffic,by examining both incoming and outgoing
packets over time. Packets which don't fall within expected parameters given
the state of the connection are discarded. The Dynamic Packet Filtering will
be performed by Connection Tracking component, similar to that supported in
linux. The firewall also supports Access Controlled List(ACL) for rule based
policy enforcement. Firewall is built on top of DPDK and uses the packet library.

About DPDK
----------
The DPDK IP Pipeline Framework provides a set of libraries to build a pipeline
application. In this document, vFW will be explained in detail with its own
building blocks.

This document assumes the reader possesses the knowledge of DPDK concepts and
packet framework. For more details, read DPDK Getting Started Guide, DPDK
Programmers Guide, DPDK Sample Applications Guide.

2.  Scope
==========
This application provides a standalone DPDK based high performance vFW Virtual
Network Function implementation.

3. Features
===========
The vFW VNF currently supports the following functionality:
  • Basic packet filtering (malformed packets, IP fragments)
  • Connection tracking for TCP and UDP
  • Access Control List for rule based policy enforcement
  • SYN-flood protection via Synproxy* for TCP
  • UDP, TCP and ICMP protocol pass-through
  • CLI based enable/disable connection tracking, synproxy, basic packet
    filtering
  • Multithread support
  • Multiple physical port support
  • Hardware and Software Load Balancing
  • L2L3 stack support for ARP/ICMP handling
  • ARP (request, response, gratuitous)
  • ICMP (terminal echo, echo response, passthrough)
  • ICMPv6 and ND (Neighbor Discovery)

4. High Level Design
====================
The Firewall performs basic filtering for malformed packets and dynamic packet
filtering incoming packets using the connection tracker library.
The connection data will be stored using a DPDK hash table. There will be one
entry in the hash table for each connection. The hash key will be based on source
address/port,destination address/port, and protocol of a packet. The hash key
will be processed to allow a single entry to be used, regardless of which
direction the packet is flowing (thus changing the source and destination).
The ACL is implemented as libray stattically linked to vFW, which is used for
used for rule based packet filtering.

TCP connections and UDP pseudo connections will be tracked separately even if
theaddresses and ports are identical. Including the protocol in the hash key
will ensure this.

The Input FIFO contains all the incoming packets for vFW filtering.  The vFW
Filter has no dependency on which component has written to the Input FIFO.
Packets will be dequeued from the FIFO in bulk for processing by the vFW.
Packets will be enqueued to the output FIFO.
The software or hardware loadbalancing can be used for traffic distribution
across multiple worker threads. The hardware loadbalancing require ethernet
flow director support from hardware (eg. Fortville x710 NIC card).
The Input and Output FIFOs will be implemented using DPDK Ring Buffers.

===================
5. Components of vFW
===================
In vFW, each component is constructed using packet framework pipelines.
It includes Rx and Tx Driver, Master pipeline, load balancer pipeline and
vfw worker pipeline components. A Pipeline framework is a collection of input
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
The vFW support both hardware and software balancing for load balancing of
traffic across multiple VNF threads. The Hardware load balancing require support
from hardware like Flow Director for steering of packets to application through
hardware queues.

The Software Load balancer is also supported if hardware load balancing can't be
used for any reason. The TXRX along with LOADB pipeline provides support for
software load balancing by distributing the flows to Multiple vFW worker
threads.
Loadbalancer (HW or SW) distributes traffic based on the 5 tuple (src addr, src
port, dest addr, dest port and protocol) applying an XOR logic distributing to
active worker threads, thereby maintaining an affinity of flows to worker
threads.

vFW Pipeline
******************************
The vFW performs the basic packet filtering and will drop the invalid and
malformed packets.The Dynamic packet filtering done using the connection tracker
library. The packets are processed in bulk and Hash table is used to maintain
the connection details.
Every TCP/UDP packets are passed through connection tracker library for valid
connection. The ACL library integrated to firewall provide rule based filtering.

vFW Topology:
------------------------
::
  IXIA(Port 0)-->(Port 0)VNF(Port 1)-->(Port 1) IXIA
  operation:
    Egress --> The packets sent out from ixia(port 0) will be Firewalled to ixia(port 1).
    Igress --> The packets sent out from ixia(port 1) will be Firewalled to ixia(port 0).

vFW Topology (L4REPLAY):
------------------------------------
::
  IXIA(Port 0)-->(Port 0)VNF(Port 1)-->(Port 0)L4REPLAY
  operation:
    Egress --> The packets sent out from ixia will pass through vFW to L3FWD/L4REPLAY.
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
Plase refer to <samplevnf>/docs/vFW/INSTALL.rst for installation, configuration,
compilation and execution.
