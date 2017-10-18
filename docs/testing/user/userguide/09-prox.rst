.. This work is licensed under a Creative Commons Attribution 4.0 International
.. License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) OPNFV, Intel Corporation and others.

PROX - Packet pROcessing eXecution engine.
==========================================

Change since previous release, support has been added for the following:

8 workloads for automated dataplane benchmarking using DATS
Support DPDK 17.05
L4 stateful traffic generation and flow extraction tool
lua configuration files for easy table population
New modes: impair, lb5tuple, mirror,  nat, decapnsh, encapnsh and genl4
helper script for automated VM core pinning for Qemu
New screens for viewing information regarding DPDK rings (screen 5) and L4 generation (screen 6)
Improved command editing using libedit
Improved ncurses display
Rename of dppd-bng zip file to dppd-prox
Latency histogram collection

PROX COMMANDS AND SCREENS
-------------------------
::
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |   **RUNTIME COMMAND**                        |           **DESCRIPTION**                                                 |      **EXAMPLE**           |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |quit                                          | Stop all cores and quit                                                   |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |help <substr>                                 | Show list of commands that have <substr> as a substring.                  |                            |
        |                                              | If no substring is provided, all commands are shown.                      |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |verbose <level>                               | Set the verbosity level of some printed messages.                         |                            |
        |                                              | Possible values are: 0 (default value, error messages only),              |  verbose 1                 |
        |                                              | 1 (+ warnings), 2 (+ info) and 3 (+ debugging)                            |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |thread info <core_id> <task_id>               | Show task specific information                                            |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |update interval <value>                       | Update statistics refresh rate, in msec (must be >=10).                   |                            |
        |                                              | Default is 1 second                                                       |  update interval 500       |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |rx tx info                                    | Print connections between tasks on all cores                              |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |start <core list>|all <task_id>               | Start cores specified in <core list> or all cores.                        |  start all                 |
        |                                              | If <task_id> is not specified, all tasks for the specified cores          |  start 1                   |
        |                                              | will be started.                                                          |  start 1s0-4s0             |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |stop <core list>|all <task_id>                | Stop cores specified in <core list> or all cores.                         |                            |
        |                                              | If <task_id> is not specified, all tasks for the specified                |  stop 1                    |
        |                                              | cores will be stopped.                                                    |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |dump <coreid> <taskid> <nbpkts>               | Create a hex dump of <nb_packets> from <task_id> on <core_id>             |  dump 2 1 5                |
        |                                              | showing how packets have changed between RX and TX.                       |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |dump_rx <coreid> <taskid> <nbpkts>            | Create a hex dump of <nb_packets> from <task_id> on <coreid> at RX        | dump_rx 2 1 5              |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |dump_tx <coreid> <taskid> <nbpkts>            | Create a hex dump of <nb_packets> from <task_id> on <coreid> at TX        | dump_tx 2 1 5              |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |rx distr start                                | Start gathering statistical distribution of received packets              |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |rx distr stop                                 | Stop gathering statistical distribution of received packets               |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |rx distr reset                                | Reset gathered statistical distribution of received packets               |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |rx distr show                                 | Display gathered statistical distribution of received packets             |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |rate <port id> <queue id> <rate>              | Set transmit rate in Mb/s. This does not include preamble, SFD and IFG    | rate 0 0 1000              |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |count <core id> <task id> <count>             | Generate <count> packets, then pause generating                           | count  1 0 5               |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |pkt_size <coreid> <taskid> <pktsize>          | Set the packet size to <pkt_size>                                         | pkt_size 1 3 255           |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |speed <core_id> <task_id> <speed percentage>  | Change the speed to <speed percentage> of a                               |
        |                                              | 10 Gbps line at which packets are being generated                         | speed 1 0 50               |
        |                                              | on core <core_id> in task <task_id>                                       |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |speed_byte <core_id> <task_id> <speed>        | Change speed to <speed>. The speed is specified in units of bytes per sec |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |set value <core_id> <task_id> <offset>        | Set <value_len> bytes to <value> at offset <offset> in packets            |                            |
        | <value> <value_len>                          | generated on <core_id> <task_id>                                          | set value 4 1 14 10 1      |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        | reset values all                             | Undo all `set value` commands on all cores/tasks                          |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |reset values <core id> <task id>  | Undo all `set value` commands on specified core/task                                  |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |arp add <core id> <task id> <port id>         |                                                                           |                            |
        | <gre id> <svlan> <cvlan> <ip addr>           |                                                                           |                            |
        | <mac addr> <user>                            | Add a single ARP entry into a CPE table on <core id>/<task id>            |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |rule add <core id> <task id> svlan_id&mask    |                                                                           |                            |
        | cvlan_id&mask ip_proto&mask                  |                                                                           |                            |
        | source_ip/prefix destination_ip/prefix       |                                                                           |                            |
        | range dport_range action                     | Add a rule to the ACL table on <core id>/<task id>                        |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |route add <core id> <task id>                 |                                                                           |                            |
        | <ip/prefix> <next hop id>                    | Add a route to the routing table on core <core id> <task id>              | route add 10.0.16.0/24 9   |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |reset stats                                   | Reset all statistics                                                      |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |tot stats                                     | Print total RX and TX packets                                             |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |tot ierrors per sec                           | Print total number of ierrors per second                                  |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |pps stats                                     | Print RX and TX packet rate in unit of packet per second                  |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |lat stats <core id> <task id>                 | Print min,max,avg latency as measured during last sampling interval       | lat stats 1 0              |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |lat packets <core id> <task id>               | Print the latency for each of the last set of packets                     |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |core stats <core id> <task id>                | Print rx/tx/drop for task <task id> running on core <core id>             |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |port_stats <port id>                          | Print rate for no_mbufs, ierrors, rx_bytes, tx_bytes, rx_pkts,            |                            |
        |                                              | tx_pkts and totals for RX, TX, no_mbufs ierrors for port <port id>        |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |ring info all                                 | Get information about ring, such as ring size and                         |                            |
        |                                              | number of elements in the ring                                            |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |ring info <core id> <task id>                 |  Get information about ring on core <core id>                             |                            |
        |                                              |  in task <task id>, such as ring size and number of elements in the ring  | ring info 1 0              |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |port info <port id> [brief]                   | Get port related information, such as MAC address, socket,                |                            |
        |                                              | number of descriptors..., . Adding `brief` after command                  |                            |
        |                                              | prints short version of output.                                           | port info 1                |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |port up <port id>                             | Set the port up (all ports are up at startup)                             | port up 1                  |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |port down <port id>                           | Set the port down                                                         | port down 1                |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |port xstats <port id>                         | Get extra statistics for the port                                         | port xstats 1              |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |version                                       | Show version                                                              |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+
        |port_stats <port id>                          |  Print rate for no_mbufs, ierrors, rx_bytes, tx_bytes, rx_pkts,           |                            |
        |                                              | tx_pkts and totals for RX, TX, no_mbufs ierrors for port <port id>        |                            |
        +----------------------------------------------+---------------------------------------------------------------------------+----------------------------+

While PROX is running, F1 to F6 change the view on the system. Pressing F1 switches to the main screen showing per core statistics. When PROX is started,
this is the screen shown by default. Pressing F2 switches to show port-based information. Pressing F3 shows information (i.e. occupancy, memory usage, ...)
about memory pools. If there are tasks with mode=lat, F4 displays latency measurements made during the last second by each of those tasks.
F5 displays DPDK ring information. F6 is for L4 generation. If no command has been entered, numbers 1 to 6 can also be used to change the view on the system.
This is provided to allow changing screens in environments that do not pass function keys to PROX.

Page Up and Page Down can be used to view per core statistics that would otherwise not fit on the screen. Escape quits PROX.
The history of previously entered commands can be navigated using the Up and Down arrows. Statistics can be reset with F12.

COMMAND LINE OPTIONS
--------------------
Run PROX with the "--help" argument to display the usage text and the list of supported options as shown below.
PROX supports many compilation flags to enable or disable features. For these flags, refer to the Makefile.
Refer to the README file for more information on how to run PROX for specific use cases.

::

  Usage: ./build/prox [-f CONFIG_FILE] [-l LOG_FILE] [-p] [-o DISPLAY] [-v] [-a|-e] [-m|-s|-i] [-n] [-w DEF] [-q] [-k] [-d] [-z] [-r VAL] [-u] [-t]
        -f CONFIG_FILE : configuration file to load, ./prox.cfg by default
        -l LOG_FILE : log file name, ./prox.log by default
        -p : include PID in log file name if default log file is used
        -o DISPLAY: Set display to use, can be 'curses' (default), 'cli' or 'none'
        -v verbosity : initial logging verbosity
        -a : autostart all cores (by default)
        -e : don't autostart
        -n : Create NULL devices instead of using PCI devices, useful together with -i
        -m : list supported task modes and exit
        -s : check configuration file syntax and exit
        -i : check initialization sequence and exit
        -u : Listen on UDS /tmp/prox.sock
        -t : Listen on TCP port 8474
        -q : Pass argument to Lua interpreter, useful to define variables
        -w : define variable using syntax varname=value
             takes precedence over variables defined in CONFIG_FILE
        -k : Log statistics to file "stats_dump" in current directory
        -d : Run as daemon, the parent process will block until PROX is not initialized
        -z : Ignore CPU topology, implies -i
        -r : Change initial screen refresh rate. If set to a lower than 0.001 seconds,
                  screen refreshing will be disabled

CONFIGURATION FILE FORMAT
-------------------------
The configuration file is divided into multiple sections, each of which is used to define some parameters and options.
Sections are created using the [section name] syntax. The list of sections, where # represents an integer, is as follows:

::
    [eal options]
    [port #]
    [variables]
    [defaults]
    [global]
    [core #]

In each section, entries are created using the key=value syntax.
Comments are created using the ; symbol: all characters from the ;
symbol to the end of line are ignored. A # symbol at the beginning of the section name comments
the whole section out: all entries in the section are treated as comments and are ignored. For example:

::
  [#core 1]
  ; this is a comment
  parameter name=parameter value ; this entry is ignored because the section is commented out

[EAL OPTIONS]
The following parameters are supported:

::
  -m  ; Specifies the amount of memory used. If not provided, all hugepages will be used.
  -n  ; Specifies the number of memory channels. Use -n4 for latest Intel Xeon based platforms
  -r  ; Specifies the number of memory ranks.
  eal ; Specifies DPDK EAL extra options. Those options will be passed blindly to DPDK.

[PORT #]
DPDK ports are usually referenced by their port_id, i.e. an integer starting from 0.
Using port_id in the configuration file is tedious, since the same port_id can appear at
different places (rx port, tx port, routing tables),
and those ports might change (e.g. if cables are swapped).
In order to make the configuration file easier to read and modify,
DPDK ports are given a name with the name= option.
The name serves as the reference, and in addition, it will show up in the display at runtime.

::
        PARAMETER    EXAMPLE         DESCRIPTION
        ----------------------------------------------------------------------------
        name         inet0           Use inet0 to later refer to this port
        mac          hardware        value can be: hardware, random or a literal MAC address
        rx desc      256             number of descriptors to allocate for reception
        tx desc      256             number of descriptors to allocate for transmission
        promiscuous  yes             enable promiscuous mode
        strip crc    yes             enable CRC stripping
        rss          yes             enable RSS
        lsc          no              While lsc is disabled for drivers known to not provide support,
                                     this option explicitely overrides these settings.
        rx_ring      dpdk_ring_name  use DPDK ring as an interface (receive side)
        tx_ring      dpdk_ring_name  use DPDK ring as an interface (transmit side)

[VARIABLES]
Variables can be defined in the configuration file using the $varname=value syntax.
Variables defined on the command line (-w varname=value) take precedence and do not
create conflicts with variables defined in the configuration file. Variables are
used in the configuration file using the $varname syntax: each instance of $varname
is replaced by its associated value. This is typically useful if the same parameter
must be used at several places. For instance, you might want to have multiple load
balancers, all transmitting to the same set of worker cores.
The list of worker cores could then be defined once in a variable:

::
  [variables]
  $wk=1s0-5s0

Then, a load balancer definition would use the variable:

::
  [core 6s0]
  name=LB
  task=0
  mode=lbnetwork
  tx cores=$wk task=0
  ...

And the section defining the worker cores would be:

::
  [core $wk]
  name=worker
  task=0
  mode=qinqencapv4
  ...

[DEFAULTS]
The default value of some options can be overridden using the [defaults] section:

::
  PARAMETER     EXAMPLE   DESCRIPTION
  -----------------------------------
  mempool       size      16K number of mbufs per task, relevant when task receives from a port.
                          this is the n argument provided to rte_mempool_create()
  qinq tag      0xa888    Set qinq tag for all tasks. The result of adding this option is the
                          same as adding qinq tag= to each task
  memcache size 128       number of mbufs cached per core, default is 256 this is the cache_size
                          argument provided to rte_mempool_create()

[GLOBAL]
The following parameters are supported:

::
  PARAMETER          EXAMPLE            DESCRIPTION
  -------------------------------------------------
  name               BNG                Name of the configuration, which will be shown in the title box at runtime.
  start time         10                 Time in seconds after which average statistics will be started.
                                        Default value is 0.
  duration time      30                 Runtime duration in seconds, counted after start time.
                                        This is typically useful to automate testing using
                                        different parameters: PROX automatically exits when the
                                        runtime duration has elapsed. Initialization and start time
                                        are not included in this runtime duration.
                                        For example, if start time is set to 10 and duration time is set to 30,
                                        the total execution time (after initialization) will be 40 seconds.
                                        Default value is 0, which means infinity and prevents PROX from automatically exiting.
  shuffle            yes                When this parameter is set to yes, the order of mbufs
                                        within mempools is randomized to simulate a system that has
                                        been warmed up. Default value is no.
  gre cfg            /path/to/file.csv  Path to CSV file that provides QinQ-to-GRE mapping.
                                        Default value is gre_table.csv in same directory as
                                        configuration file. Fields are GRE key and QinQ value (computed as SVLAN * 4096 + CVLAN).
  pre cmd            ls                 Arbitrary system commands to run while reading cfg. This option can occur multiple times.
  user cfg           /path/to/file.csv  Path to CSV file that provides QinQ-to-User mapping.
                                        Default value is user_table.csv in same directory as configuration file.
                                        Fields are SVLAN, CVLAN and User-Id.
  next hop cfg       /path/to/file.csv  Path to CSV file that provides Next-Hop details.
                                        Default value is next_hop.csv in same directory as configuration file.
                                        Fields are Next-Hop index (as returned by LPM lookup),
                                        Out-Port index, Next-Hop IP (unused), Next-Hop MAC and MPLS label.
  ipv4 cfg           /path/to/file.csv  Path to CSV file that provides IPv4 LPM routing table.
                                        Default value is ipv4.csv in same directory as configuration file.
                                        Fields are IPv4 subnet (in CIDR notation) and Next-Hop index.
  dscp cfg           /path/to/file.csv  Path to CSV file that provides mapping for QoS classification,
                                        from DSCP to Traffic Class and Queue.
                                        Default value is dscp.csv in same directory as configuration file.
                                        Fields are DSCP (0-63), Traffic Class (0-3) and Queue (0-3).
  ipv6 tunnel cfg    /path/to/file.csv  Path to CSV file that provides lwAFTR binding table.
                                        Default value is ipv6_tun_bind.csv in same directory as configuration file.
                                        Fields are lwB4 IPv6 address, next hop MAC address towards lwB4,
                                        IPv4 Public address and IPv4 Public Port Set.
  acl cfg            /path/to/file.csv  Path to CSV file that provides ACL rules.
                                        Default value is rules.csv in same directory as configuration file.
                                        Fields are SVLAN value & mask, CVLAN value & mask, IP protocol value & mask,
                                        source IPv4 subnet (in CIDR notation), destination IPv4 subnet (in CIDR notation),
                                        source port range, destination port range, and action (drop, allow, rate limit).
  unique mempool     yes
  per socket

[CORE #]
Cores can be configured by means of a set of [core #] sections, where # represents either:

an absolute core number: e.g. on a 10-core, dual socket system with hyper-threading, cores are numbered from 0 to 39;
a core number, the letter 's', and a socket number: this allows selecting per-socket cores, independently from their interleaved numbering;
a core number and the letter 'h': this allows selecting the hyper-thread sibling of the specified core;
a dash-separated range of core numbers;
a comma-separated list of core numbers;
any combination of the above;
or a variable whose value complies with the above syntax.
The socket and hyper-thread syntax makes it easier to use the same configuration file on several platforms,
even if their core numbering differs (e.g. interleaving rule or number of cores per socket).

Each core can be assigned with a set of tasks, each running one of the implemented packet processing modes.

The following parameters are supported:
.. image:: images/prox_core.png
   :width: 1024px
   :alt: SampleVNF supported topology

INSTALLATION
------------

PREREQUISITES
^^^^^^^^^^^^^
DPDK must be installed prior to running make in the PROX directory.
The README file shipped with PROX describes what versions of DPDK are supported,
and if any patches are needed for the chosen DPDK version.

The following packages need to be installed. (Example for destributions that are using rpm)

::
  sudo yum install net-tools wget gcc unzip libpcap-devel ncurses-devel libedit-devel pciutils lua-devel kernel-devel
  Jump Start

The following instructions are here to help customers to start using PROX.
It's by no means a complete guide, for detailed instructions on how to install and use
DPDK please refer to its documentation.
Your mileage may vary depending on a particular Linux distribution and hardware in use.

Edit grub default configuration:

::
  vi /etc/default/grub

Add the following to the kernel boot parameters

::
  default_hugepagesz=1G hugepagesz=1G hugepages=8

Rebuild grub config and reboot the system:

::
  grub2-mkconfig -o /boot/grub2/grub.cfg
  reboot

Verify that hugepages are available

::
    cat /proc/meminfo
    ...
    HugePages_Total:  8
    HugePages_Free:   8
    Hugepagesize:     1048576 kB
    ...

Re-mount huge pages

::
  mkdir -p /mnt/huge
  umount `awk '/hugetlbfs/ { print $2 }' /proc/mounts` >/dev/null 2>&1
  mount -t hugetlbfs nodev /mnt/huge/

Add the following to the end of ~/.bashrc file

::
  export RTE_SDK=/root/dpdk
  export RTE_TARGET=x86_64-native-linuxapp-gcc
  export RTE_UNBIND=$RTE_SDK/tools/dpdk_nic_bind.py

Re-login or source that file

::
  . ~/.bashrc

Build DPDK

::
  git clone http://dpdk.org/git/dpdk
  cd dpdk
  git checkout v1.8.0
  make install T=$RTE_TARGET

Load uio module

::
  lsmod | grep -w "^uio" >/dev/null 2>&1 || sudo modprobe uio
  sleep 1

Load igb_uio module

::
  lsmod | grep -w "^igb_uio" >/dev/null 2>&1 || sudo insmod $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko

Discover network devices available on the system:

::
  lspci | grep Ethernet

Prior launching PROX, ports that are to be used by it must be bound to the igb_uio driver.

The following command will bind all Intel® Ethernet Converged Network Adapter X710 ports to igb_uio:

::
  lspci | grep X710 | cut -d' ' -f 1 | sudo xargs -I {} python2.7 $RTE_UNBIND --bind=igb_uio {}

The following command will bind all Intel® 82599 10 Gigabit Ethernet Controller ports to igb_uio:

::
  lspci | grep 82599 | cut -d' ' -f 1 | sudo xargs -I {}  python2.7 $RTE_UNBIND --bind=igb_uio {}

COMPILING AND RUNNING PROX
--------------------------

Download and extract the PROX archive

::
  wget https://01.org/sites/default/files/downloads/intel-data-plane-performance-demonstrators/dppd-prox-v021.zip
  unzip dppd-prox-v021.zip
  cd dppd-prox-v021

Build the PROX

::
  make

The set of sample configuration files can be found in:

::
  ./config/*

PROX generation sample configs are in:

::
  ./gen/*

To launch PROX one may use the following command as an example, assuming the current directory is where you've just built PROX:

::
  ./build/prox -f ./config/handle_none.cfg
