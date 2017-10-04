.. This work is licensed under a creative commons attribution 4.0 international
.. license.
.. http://creativecommons.org/licenses/by/4.0
.. (c) opnfv, national center of scientific research "demokritos" and others.

=====================
CLI Command Reference
=====================

Introduction
============
This chapter provides a commonly used sampleVNFs CLI commmands description.
The more detailed information and details will be available from the CLI
prompt of the VNF.

Generic commands
================

routeadd
--------
The routeadd command provides a mechanism to add the routing entries for the
VNF.

The destination device me be directly(host) attached or attached to net. The
parameter net or host should be used accordngly along with other information.

IPv4 interaface:

::

 Syntax:

 routeadd <net/host> <port #> <ipv4 nhip address in decimal> <Mask/NotApplicable>

 Example:

 routeadd net 0 202.16.100.20 0xffff0000
 routeadd net 1 172.16.40.20 0xffff0000
 routeadd host 0 202.16.100.20
 routeadd host 1 172.16.40.20


IPv6 interaface:

::

 Syntax:

 routeadd <net/host> <port #> <ipv6 nhip address in hex> <Depth/NotApplicable>

 Example:

 routeadd net 0 fec0::6a05:caff:fe30:21b0 64
 routeadd net 1 2012::6a05:caff:fe30:2081 64
 routeadd host 0 fec0::6a05:caff:fe30:21b0
 routeadd host 1 2012::6a05:caff:fe30:2081


The route can also be added to the VNF as a config parameters. This method is
deprecated and not recommended to use but is supported for backward
compatiblity.

IPv4 interaface:

::

 Syntax:

 ARP route table entries (ip, mask, if_port, nh) hex values with no 0x

 Example:

 arp_route_tbl = (c0106414,FFFF0000,0,c0106414)
 arp_route_tbl = (ac102814,FFFF0000,1,ac102814)


IPv6 interaface:

::

 Syntax:

 ARP route table entries (ip, mask, if_port, nh) hex values with no 0x

 Example:

 nd_route_tbl = (0064:ff9b:0:0:0:0:9810:6414,120,0,0064:ff9b:0:0:0:0:9810:6414)
 nd_route_tbl = (0064:ff9b:0:0:0:0:9810:2814,120,1,0064:ff9b:0:0:0:0:9810:2814)


arpadd
------
The arpadd command is provided to add the static arp entries to the VNF.

IPv4 interface:

::

 Syntax:

 p <arpicmp_pipe_id> arpadd <interface_id> <ip_address in deciaml> <mac addr in hex>

 Example:

 p 1 arpadd 0 202.16.100.20 00:ca:10:64:14:00
 p 1 arpadd 1 172.16.40.20 00:ac:10:28:14:00


IPv6 interface:

::

 Syntax:

 p <arpicmp_pipe_id> arpadd <interface_id> <ip_address in deciaml> <mac addr in hex>

 Example:

 p 1 arpadd 0 0064:ff9b:0:0:0:0:9810:6414 00:00:00:00:00:01
 p 1 arpadd 1 0064:ff9b:0:0:0:0:9810:2814 00:00:00:00:00:02


vFW Specific commands
=====================
The following list of commands are specific to VFW pipeline.

action add
==========
Refer to "action add" CLI command line help to get more details.
Many options are available for this command for accept, fwd, count, conntrack
etc.

applyruleset
============
This command must be executed to apply the ACL rules configured.

::

 Syntax/Example:

 p vfw applyruleset


add
===
This command is used to add teh ACL rules to vFW

Adding ACL rules for IPv4:

::

 Syntax:

 p vfw add <priority> <src_ip> <mask> <dst_ip> <mask> <src_port_start> <src_port_end> <dst_port_start> <dst_port_end> <protocol_mask> <action_id>
 ;Log info: Prio = 1 (SA = 202.0.0.0/8, DA = 192.0.0.0/8, SP = 0-65535, DP = 0-65535, Proto = 0 / 0x0) => Action ID = 1

 Example:

 p vfw add 2 202.16.100.20 8 172.16.40.20 8 0 65535 0 65535 0 0 1
 p vfw add 2 172.16.40.20 8 202.16.100.20 8 0 65535 0 65535 0 0 0


Adding ACL rules for IPv6:

::

 Syntax:

 p vfw add <priority> <src_ip> <mask> <dst_ip> <mask> <src_port_start> <src_port_end> <dst_port_start> <dst_port_end> <protocol_mask> <action_id>

 Example:

 p vfw add 2 fec0::6a05:caff:fe30:21b0 64 2012::6a05:caff:fe30:2081 64 0 65535 0 65535 0 0 1
 p vfw add 2 2012::6a05:caff:fe30:2081 64 fec0::6a05:caff:fe30:21b0 64 0 65535 0 65535 0 0 0


vACL Specific commands
======================
ACL Commands are similar to vFW CLI commands.

Refer to CLI command line for more info.


