.. this work is licensed under a creative commons attribution 4.0 international
.. license.
.. http://creativecommons.org/licenses/by/4.0
.. (c) opnfv, national center of scientific research "demokritos" and others.

========================================================
UDP_Replay
========================================================

1 Introduction
==============
This application implements UDP_Replay. The UDP Replay application is a simple example of 
packet processing using the DPDK. The application performs UDP replay. This application
is based on l3fwd application from dpdk. Packets are replayed back over the same port as
received. This application is used in VNF approximation.

2 Compiling the Application
===========================

To compile the application:

Go to the sample application directory: 
cd samplevnf/VNF's/UDP_Replay

export RTE_SDK=/path/to/rte_sdk
cd ${RTE_SDK}/examples/l3fwd
Set the target (a default target is used if not specified). For example:

export RTE_TARGET=x86_64-native-linuxapp-gcc
See the DPDK Getting Started Guide for possible RTE_TARGET values.

Build the application:
make

3 Running the Application
===========================

The application has a number of command line options:

./build/UDP_Replay [EAL options] -- -p PORTMASK
                                 --config(port,queue,lcore)[,(port,queue,lcore)]

-p PORTMASK: Hexadecimal bitmask of ports to configure
--config (port,queue,lcore)[,(port,queue,lcore)]: Determines which queues from 
which ports are mapped to which cores.

For e.g

For single port
./build/UDP_Replay -c 0xf -n 4 -- -p 0x1 --config="(0,0,1)"

For dual port
./build/UDP_Replay -c 0xf -n 4 -- -p 0x3 --config="(0,0,1),(1,0,2)"

In this command:

The -l option enables cores 1, 2
The -p option enables ports 0 and 1
The –config option enables one queue on each port and maps each (port,queue) 
pair to a specific core. The following table shows the mapping in 
this example:

Port	Queue	lcore	        Description
 0		  0		  1	    Map queue 0 from port 0 to lcore 1.
 1		  0	  	  2	    Map queue 0 from port 1 to lcore 2.

For ARP/ICMP support
use the sample config provided under samplevnf/VNFs/UDP_Replay/sample.cfg

For e.g
./build/UDP_Replay -c 0xf -n 4 -- -s sample_ipv4.cfg -p 0x1 --config="(0,0,1),(1,0,2)"
