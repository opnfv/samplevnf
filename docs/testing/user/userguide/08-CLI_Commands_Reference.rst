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


lbentry
-------
Loadbalancer CLI commands for debug

::

 LB Commands
 -------------------------------------------------------------
 Commands                       Description
 -------------------------------------------------------------
 p <pipe_id> lbentry dbg 0 0   To show received packets count
 p <pipe_id> lbentry dbg 1 0   To reset received packets count
 p <pipe_id> lbentry dbg 2 0   To set debug level
 p <pipe_id> lbentry dbg 3 0   To display debug level
 p <pipe_id> lbentry dbg 4 0   To display port statistics


arpls
-----

The arpls command is used to list the arp and route entries.

::

 Syntax:

 P <pipe_id> arpls <0: IPv4, 1: IPv6>

 Example:

 p 1 arpls 0
 p 1 arpls 1


vFW Specific commands
=====================
The following list of commands are specific to VFW pipeline.

action add
----------
Refer to "action add" CLI command line help to get more details.
Many options are available for this command for accept, fwd, count, conntrack
etc.

applyruleset
------------
This command must be executed to apply the ACL rules configured.

::

 Syntax/Example:

 p vfw applyruleset


add
---
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


stats
-----
Display vFW stats.

::

 Syntax/Example:

 p vfw stats

clearstats
-----------
Clear vFW stats

::

 Syntax/Example:

 p vfw clearstats

counterdump
-----------
Enable or disable the counterdump using the following commands

::

 Syntax/Example:

 p vfw counterdump start
 p vfw counterdump stop

debug
-----
Enable or Disable the dynamic debug logs

::

 Syntax/Example:

 Disable dbg logs
 p vfw dbg 0

 Enable dbg logs
 p vfw dbg 1

firewall
--------
Enable or disable the firewall basic filtering using following commands.

::

 Syntax/Example:

 To disable
 p <pipe_id> vfw firewall 0

 To enable
 p <pipe_id> vfw firewall 1

synproxy
--------
Enable or disable the synproxy using following commands.

::

 Syntax/Example:

 To disable
 p <pipe_id> vfw synproxy 0

 To enable
 p <pipe_id> vfw synproxy 1

conntrack
---------
Enable or disable the connection tracking per VFW pipeline

::

 Syntax/Example:

 To enable connection tracking
 p action add <pipe_id> conntrack

 To disable connection tracking
 p action del <pipe_id> conntrack


loadrules
---------

A new file containing ACL rules and actions. The existing ACL rules and actions are
cleared.

::

 Syntax:
 p vfw loadrules <rule file>

 Example:
 p vfw loadrules ./config/acl_script_rules.tc

list
----
List the ACL rules in vFW

::

 Syntax/Example:

 List Active ACL rules
 p vfw ls 0

 List Standby ACL rules
 p vfw ls 1


vACL Specific commands
======================
Following are the typical commands used in vACL. Refer to CLI command line
prompt for more details.


action add
----------
Using pipeline CLI, an action can be added using the following command:

::

 Syntax:
 p action add <action-id> <action> <optional option>

 Example:

 Accept:
 p action add 1 accept

 Drop:
 p action add 2 drop

 Count:
 p action add 1 count

 fwd:
 p action add 1 fwd 1
 Where a port # must be specified

 NAT:
 p action add 3 nat 2
 Where a port # must be specified

 List Action:
 p action ls <pipleine-id>
 e.g. p action ls 2

add rules
---------
Using pipeline CLI, an ACL rule can be added using the following command:

::

 Syntax:
 p acl add <priority> <src-ip> <mask> <dst-ip> <mask> <src-port-from> <src-port-to> <dst-port-from> <dst-port-to> <protocol> <protocol-mask> <action-id>

 Example:
 p acl add 1 0.0.0.0 0 0.0.0.0 0 0 65535 0 65535 0 0 1

 UDP only with source and destination IP addresses:
 p acl add 1 172.16.100.00 24 172.16.40.00 24 0 65535 0 65535 17 255 1
 p acl add 1 172.16.40.00 24 172.16.100.00 24 0 65535 0 65535 17 255 1

 UDP Only:
 p acl add 1 0.0.0.0 0 0.0.0.0 0 0 65535 0 65535 17 255 1

 Allow all packets:
 -----------------
 p acl add 1 0.0.0.0 0 0.0.0.0 0 0 65535 0 65535 0 0 1


list ACL rules
--------------
Using pipeline CLI, the list of current ACL rules can be viewed using:

::

 Syntax:
 p acl ls <pipe_id>

 Example:
 p acl ls 2


del an ACL rule
---------------
Using pipeline CLI, an ACL rule can be deleted using the following command:

::

 Syntax:
 p acl del <src-ip> <mask> <dst-ip> <mask> <src-port-from> <src-port-to> <dst-port-from> <dst-port-to> <protocol> <protocol-mask>

 Example:
 p acl del 0.0.0.0 0 0.0.0.0 0 0 65535 0 65535 0 0


stats
-----
Display ACL stats.

::

 Syntax/Example:

 p acl stats

clearstats
-----------
Clear ACL stats

::

 Syntax/Example:

 p acl clearstats


loadrules
---------

A new file containing ACL rules and actions. The existing ACL rules and actions are
cleared.

::

 Syntax:
 p acl loadrules <rule file>

 Example:
 p acl loadrules ./config/acl_script_rules.tc


debug
-----
Debug logs can be turn on or turn off using the following commands

::

 Syntax/Example:

 Turn on Debug:
 p 2 acl dbg 1

 Turn off Debug:
 p 2 acl dbg 0


vCGNAT Specific commands
========================

The following are the details of the CLI commands supported by vCGNAT.
Refer to vCGNAPT application CLI command prompt help more details.

::

 To add bulk vCGNAPT entries
 p <pipe_id> entry addm <prv_ip/prv_ipv6> <prv_port> <pub_ip> <pub_port> <phy_port> <ttl> <no_of_entries> <end_prv_port> <end_pub_port>

 To add single vCGNAPT entry
 p <pipe_id> entry add <prv_ip/prv_ipv6> <prv_port> <pub_ip> <pub_port> <phy_port> <ttl>

 To delete single vCGNAPT entry
 p <pipe_id> entry del <prv_ip/prv_ipv6> <prv_port> <phy_port>

 Displays all vCGNAPT static entries
 p <pipe_id> entry ls

 To display debug level , bulk entries added count
 p <pipe_id> entry dbg 3 0 0

 To show counters info
 p <pipe_id> entry dbg 3 3 0

 To show physical port statistics
 p <pipe_id> entry dbg 6 0 0

 To show SWQ number stats
 p <pipe_id> entry dbg 6 1 <SWQ number>

 For code instrumentation
 p <pipe_id> entry dbg 7 0 0

 Displays CGNAPT version
 p <pipe_id> entry ver 1 0

 To enable ipv6 traffic.
 p <pipe_id> entry dbg 11 1 0

 To disable ipv6 traffic.
 p <pipe_id> entry dbg 11 0 0

 To add Network Specific Preifx and depth in prefix table
 p <pipe_id> nsp add <nsp_prefix/depth>

 To delete Network Specific Preifx and depth in prefix table
 p <pipe_id> nsp del <nsp_prefix/depth>

 To show nsp prefix/depth configured/added in prefix table.
 p <pipe_id> entry dbg 13 0 0

 To show number of clients per public IP address
 p <pipe_id> entry dbg 14 0 0

 To show list of public IP addresses
 p <pipe_id> entry dbg 15 0 0

 To show number of clients per public IP address
 p <pipe_id> numipcli

 Enable dual stack.
 p <pipe_id> entry dbg 11 1 0

