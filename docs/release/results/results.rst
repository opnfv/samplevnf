.. This work is licensed under a Creative Commons Attribution 4.0 International
.. License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) OPNFV, Intel Corporation and other.

Results listed by scenario
==========================

The following sections describe the yardstick results as evaluated for the
Euphrates release. Each section describes the determined state of the specific
test case in Euphrates release.

Feature Test Results
====================

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
