.. This work is licensed under a Creative Commons Attribution 4.0 International
.. License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) OPNFV, Intel Corporation and others.

SampleVNF - Config files
========================

The configuration files are created based on the DUT test scenarios.
The example reference files are provided as part of the VNFs in the
config folder.

Following parameters will define the config files.

1. Load balancing type: Hardware or Software
2. Traffic type: IPv4 or IPv6
3. Number of Port Pairs: Single or Multi

Following are the example configuration files for sampleVNFs.

vCGNAPT Config files
--------------------
The reference configuration files explained here are for Software and Hardware
loadbalancing with IPv4 traffic type and single port pair.
For other configurations liek IPv6 and Multi-port, refer to example config
files provided as part of the source code in config(VNFs/vCGNAPT/config) folder
of the VNFs.

1. SWLB, IPv4, Single Port Pair, 1WT:

  ::

    [EAL]
    w = 05:00.0
    w = 05:00.1

    [PIPELINE0]
    type = MASTER
    core = 0

    [PIPELINE1]
    type = ARPICMP
    core = 1
    pktq_in = SWQ0
    pktq_out = SWQ7

    pktq_in_prv = RXQ0.0
    prv_to_pub_map = (0, 1)

    [PIPELINE2]
    type = TIMER
    core = 2
    n_flows = 1048576

    [PIPELINE3]
    type = TXRX
    core = 3
    pipeline_txrx_type = RXRX
    dest_if_offset = 176
    pktq_in = RXQ0.0 RXQ1.0
    pktq_out = SWQ1 SWQ2 SWQ0

    [PIPELINE4]
    type = LOADB
    core = 4
    pktq_in = SWQ1 SWQ2
    pktq_out = SWQ3 SWQ4
    outport_offset = 136; 8
    n_vnf_threads = 1
    prv_que_handler = (0,)

    [PIPELINE5]
    type = CGNAPT
    core = 5
    pktq_in = SWQ3 SWQ4
    pktq_out = SWQ5 SWQ6
    phyport_offset = 204
    n_flows = 1048576
    key_offset = 192;64
    key_size = 8
    hash_offset = 200;72
    timer_period = 100
    max_clients_per_ip = 65535
    max_port_per_client = 10
    public_ip_port_range = 98103214:(1, 65535)
    vnf_set = (3,4,5)
    pkt_type = ipv4
    cgnapt_meta_offset = 128
    prv_que_handler = (0,)

    [PIPELINE6]
    type = TXRX
    core = 6
    pipeline_txrx_type = TXTX
    dest_if_offset = 176
    pktq_in = SWQ5 SWQ6
    pktq_out = TXQ0.0 TXQ1.0

2. HWLB, IPv4, Single Port Pair, 1 WT:

This configuration doesn't require LOADB and TXRX pipelines

::

  [EAL]
  w = 05:00.0
  w = 05:00.1

  [PIPELINE0]
  type = MASTER
  core = 0

  [PIPELINE1]
  type = ARPICMP
  core = 1
  pktq_in = SWQ0
  pktq_out = TXQ0.0 TXQ1.0


  pktq_in_prv = RXQ0.0
  prv_to_pub_map = (0, 1)

  [PIPELINE2]
  type = TIMER
  core = 2
  n_flows = 1048576

  [PIPELINE3]
  type = CGNAPT
  core = 3
  pktq_in = RXQ0.0 RXQ1.0
  pktq_out = TXQ0.1 TXQ1.1 SWQ0
  phyport_offset = 204
  n_flows = 1048576
  key_offset = 192;64
  key_size = 8
  hash_offset = 200;72
  timer_period = 100
  max_clients_per_ip = 65535
  max_port_per_client = 10
  public_ip_port_range = 98103214:(1, 65535)
  vnf_set = (3,4,5)
  pkt_type = ipv4
  cgnapt_meta_offset = 128
  prv_que_handler = (0,)

vFW Config files
----------------

The reference configuration files explained here are for Software and Hardware
loadbalancing with IPv4 traffic type and single port pair.
For other configurations liek IPv6 and Multi-port, refer to example config
files provided as part of the source code in config(VNFs/vFW/config) folder
of the VNFs.

1. SWLB, IPv4, Single Port Pair, 4WT:

  ::

    [PIPELINE0]
    type = MASTER
    core = 0

    [PIPELINE1]
    type =  ARPICMP
    core = 0

    pktq_in  = SWQ2
    pktq_out = TXQ0.0 TXQ1.0

    ; IPv4 ARP route table entries (dst_ip, mask, if_port, nh) hex values with no 0x
    ; arp_route_tbl = (ac102814,ff000000,1,ac102814) (ca106414,ff000000,0,ca106414)

    ; IPv6 ARP route table entries (dst_ip, mask, if_port, nh) hex values with no 0x
    ;nd_route_tbl =  (fec0::6a05:caff:fe30:21b0,64,0,fec0::6a05:caff:fe30:21b0)
    ;nd_route_tbl =  (2012::6a05:caff:fe30:2081,64,1,2012::6a05:caff:fe30:2081)

    ; egress (private interface) info
    pktq_in_prv =  RXQ0.0

    ;for pub port <-> prv port mapping (prv, pub)
    prv_to_pub_map = (0,1)
    prv_que_handler = (0)

    [PIPELINE2]
    type = TXRX
    core = 1
    pktq_in  = RXQ0.0 RXQ1.0
    pktq_out = SWQ0 SWQ1 SWQ2
    pipeline_txrx_type = RXRX

    [PIPELINE3]
    type = LOADB
    core = 2
    pktq_in  = SWQ0 SWQ1
    pktq_out = SWQ3 SWQ4 SWQ5 SWQ6 SWQ7 SWQ8 SWQ9 SWQ10
    outport_offset = 136
    n_vnf_threads = 4 ; Number of worker threads
    prv_que_handler = (0)
    n_lb_tuples = 5 ; tuple(src_ip,dst_ip, src_port, dst_port, protocol)
    ;loadb_debug = 0

    [PIPELINE4]
    type = VFW
    core = 3
    pktq_in  = SWQ3 SWQ4
    pktq_out = SWQ11 SWQ12;TXQ0.0 TXQ1.0

    n_rules = 4096 ; Max number of ACL rules
    ;n_flows gets round up to power of 2
    n_flows = 1048576 ; Max number of connections/flows per vFW WT
    traffic_type = 4 ; IPv4 Traffic
    ;traffic_type = 6 ; IPv6 Traffic
    ; tcp_time_wait controls timeout for closed connection, normally 120
    tcp_time_wait = 10	; TCP Connection WAIT timeout
    tcp_be_liberal = 0
    ;udp_unreplied and udp_replied controls udp "connection" timeouts, normally 30/180
    udp_unreplied = 180 ; UDP timeouts for unreplied traffic
    udp_replied = 180 ; UDP timeout for replied traffic

    [PIPELINE5]
    type = VFW
    core = 4
    pktq_in  = SWQ5 SWQ6
    pktq_out = SWQ13 SWQ14;TXQ0.0 TXQ1.0

    n_rules = 4096
    ;n_flows gets round up to power of 2
    n_flows = 1048576
    traffic_type = 4 ; IPv4 Traffic
    ;traffic_type = 6 ; IPv6 Traffic
    ; tcp_time_wait controls timeout for closed connection, normally 120
    tcp_time_wait = 10
    tcp_be_liberal = 0
    ;udp_unreplied and udp_replied controls udp "connection" timeouts, normally 30/180
    udp_unreplied = 180
    udp_replied = 180

    [PIPELINE6]
    type = VFW
    core = 5
    pktq_in  = SWQ7 SWQ8
    pktq_out = SWQ15 SWQ16

    n_rules = 4096
    ;n_flows gets round up to power of 2
    n_flows = 1048576
    traffic_type = 4 ; IPv4 Traffic
    ;traffic_type = 6 ; IPv6 Traffic
    ; tcp_time_wait controls timeout for closed connection, normally 120
    tcp_time_wait = 10
    tcp_be_liberal = 0
    ;udp_unreplied and udp_replied controls udp "connection" timeouts, normally 30/180
    udp_unreplied = 180
    udp_replied = 180

    [PIPELINE7]
    type = VFW
    core = 6
    pktq_in  = SWQ9 SWQ10
    pktq_out = SWQ17 SWQ18

    n_rules = 4096
    ;n_flows gets round up to power of 2
    n_flows = 1048576
    traffic_type = 4 ; IPv4 Traffic
    ;traffic_type = 6 ; IPv6 Traffic
    ; tcp_time_wait controls timeout for closed connection, normally 120
    tcp_time_wait = 10
    tcp_be_liberal = 0
    udp_unreplied = 180
    udp_replied = 180

    [PIPELINE8]
    type = TXRX
    core = 1h
    pktq_in  = SWQ11 SWQ12 SWQ13 SWQ14 SWQ15 SWQ16 SWQ17 SWQ18
    pktq_out = TXQ0.1 TXQ1.1 TXQ0.2 TXQ1.2 TXQ0.3 TXQ1.3 TXQ0.4 TXQ1.4
    pipeline_txrx_type = TXTX


2. HWLB, IPv4, Single Port Pair, 4 WT:

This configuration doesn't require LOADB and TXRX pipelines

  ::

    [PIPELINE0]
    type = MASTER
    core = 0

    [PIPELINE1]
    type =  ARPICMP
    core = 0
    pktq_in  = SWQ0 SWQ1 SWQ2 SWQ3
    pktq_out = TXQ0.0 TXQ1.0

    ; egress (private interface) info
    pktq_in_prv =  RXQ0.0

    ;for pub port <-> prv port mapping (prv, pub)
    prv_to_pub_map = (0,1)
    prv_que_handler = (0)

    [PIPELINE2]
    type = VFW
    core = 1
    pktq_in  = RXQ0.0 RXQ1.0
    pktq_out = TXQ0.1 TXQ1.1 SWQ0

    n_rules = 4096
    ;n_flows gets round up to power of 2
    n_flows = 1048576

    traffic_type = 4 ; IPv4 Traffic
    ;traffic_type = 6 ; IPv6 Traffic
    ; tcp_time_wait controls timeout for closed connection, normally 120
    tcp_time_wait = 10
    tcp_be_liberal = 0
    ;udp_unreplied and udp_replied controls udp "connection" timeouts, normally 30/180
    udp_unreplied = 180
    udp_replied = 180

    [PIPELINE3]
    type = VFW
    core = 2
    pktq_in  = RXQ0.1 RXQ1.1
    pktq_out = TXQ0.2 TXQ1.2 SWQ1

    n_rules = 4096
    ;n_flows gets round up to power of 2
    n_flows = 1048576

    traffic_type = 4 ; IPv4 Traffic
    ;traffic_type = 6 ; IPv6 Traffic
    ; tcp_time_wait controls timeout for closed connection, normally 120
    tcp_time_wait = 10
    tcp_be_liberal = 0
    ;udp_unreplied and udp_replied controls udp "connection" timeouts, normally 30/180
    udp_unreplied = 180
    udp_replied = 180

    [PIPELINE4]
    type = VFW
    core = 3
    pktq_in  = RXQ0.2 RXQ1.2
    pktq_out = TXQ0.3 TXQ1.3 SWQ2

    n_rules = 4096
    ;n_flows gets round up to power of 2
    n_flows = 1048576

    traffic_type = 4 ; IPv4 Traffic
    ;traffic_type = 6 ; IPv6 Traffic
    ; tcp_time_wait controls timeout for closed connection, normally 120
    tcp_time_wait = 10
    tcp_be_liberal = 0
    ;udp_unreplied and udp_replied controls udp "connection" timeouts, normally 30/180
    udp_unreplied = 180
    udp_replied = 180

    [PIPELINE5]
    type = VFW
    core = 4
    pktq_in  = RXQ0.3 RXQ1.3
    pktq_out = TXQ0.4 TXQ1.4 SWQ3

    n_rules = 4096
    ;n_flows gets round up to power of 2
    n_flows = 1048576

    traffic_type = 4 ; IPv4 Traffic
    ;traffic_type = 6 ; IPv6 Traffic
    ; tcp_time_wait controls timeout for closed connection, normally 120
    tcp_time_wait = 10
    tcp_be_liberal = 0
    ;udp_unreplied and udp_replied controls udp "connection" timeouts, normally 30/180
    udp_unreplied = 180
    udp_replied = 180


vACL Config files
----------------

The reference configuration files explained here are for Software and Hardware
loadbalancing with IPv4 traffic type and single port pair.
For other configurations liek IPv6 and Multi-port, refer to example config
files provided as part of the source code in config(VNFs/vACL/config) folder
of the VNFs.

1. SWLB, IPv4, Single Port Pair, 1 WT:

 ::

    [EAL]
    # add pci whitelist eg below
    w = 05:00.0  ; Network Ports binded to dpdk
    w = 05:00.1  ; Network Ports binded to dpdk

    [PIPELINE0]
    type = MASTER
    core = 0

    [PIPELINE1]
    type = ARPICMP
    core = 0
    pktq_in  = SWQ2
    pktq_out = SWQ7
    pktq_in_prv =  RXQ0.0
    prv_to_pub_map = (0,1)
    prv_que_handler = (0)

    [PIPELINE2]
    type = TXRX
    core = 1
    pktq_in  = RXQ0.0 RXQ1.0
    pktq_out = SWQ0 SWQ1 SWQ2
    pipeline_txrx_type = RXRX
    dest_if_offset = 176

    [PIPELINE3]
    type = LOADB
    core = 2
    pktq_in  = SWQ0 SWQ1
    pktq_out = SWQ3 SWQ4
    outport_offset = 136
    phyport_offset = 204
    n_vnf_threads = 1
    prv_que_handler = (0)

    [PIPELINE4]
    type = ACL
    core = 3
    pktq_in  = SWQ3 SWQ4
    pktq_out = SWQ5 SWQ6
    n_flows = 1000000
    pkt_type = ipv4
    traffic_type = 4

    [PIPELINE5]
    type = TXRX
    core = 1h
    pktq_in  = SWQ5 SWQ6 SWQ7
    pktq_out = TXQ0.0 TXQ1.0
    pipeline_txrx_type = TXTX


2. SWLB, IPv4, Single Port Pair, 1 WT:

 ::

    [EAL]
    # add pci whitelist eg below
    w = 05:00.0
    w = 05:00.1

    [PIPELINE0]
    type = MASTER
    core = 0

    [PIPELINE1]
    type = ARPICMP
    core = 0
    pktq_in  = SWQ0
    pktq_out = TXQ0.0 TXQ1.0
    pktq_in_prv =  RXQ0.0
    prv_to_pub_map = (0,1)
    prv_que_handler = (0)

    [PIPELINE2]
    type = ACL
    core = 1
    pktq_in  = RXQ0.0 RXQ1.0
    pktq_out = TXQ0.1 TXQ1.1 SWQ0
    n_flows = 1000000
    pkt_type = ipv4
    traffic_type = 4
