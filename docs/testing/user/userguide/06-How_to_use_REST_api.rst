.. This work is licensed under a creative commons attribution 4.0 international
.. license.
.. http://creativecommons.org/licenses/by/4.0
.. (c) opnfv, national center of scientific research "demokritos" and others.

========================================================
REST API
========================================================

Introduction
---------------
As the internet industry progresses creating REST API becomes more concrete
with emerging best Practices. RESTful web services don’t follow a prescribed
standard except fpr the protocol that is used which is HTTP, its important
to build RESTful API in accordance with industry best practices to ease
development & increase client adoption.

In REST Architecture everything is a resource. RESTful web services are light
weight, highly scalable and maintainable and are very commonly used to
create APIs for web-based applications.

Here are important points to be considered:

 * GET operations are read only and are safe.
 * PUT and DELETE operations are idempotent means their result will
   always same no matter how many times these operations are invoked.
 * PUT and POST operation are nearly same with the difference lying
   only in the result where PUT operation is idempotent and POST
    operation can cause different result.


REST API in SampleVNF
---------------------

In SampleVNF project VNF’s are run under different contexts like BareMetal,
SRIOV, OVS & Openstack etc. It becomes difficult to interact with the
VNF’s using the command line interface provided by the VNF’s currently.

Hence there is a need to provide a web interface to the VNF’s running in
different environments through the REST api’s. REST can be used to modify
or view resources on the server without performing any server-side
operations.

REST api on VNF’s will help adapting with the new automation techniques
being adapted in yardstick.

Web server integration with VNF’s
----------------------------------

In order to implement REST api’s in VNF one of the first task is to
identify a simple web server that needs to be integrated with VNF’s.
For this purpose “civetweb” is identified as the web server That will
be integrated with the VNF application.

CivetWeb is an easy to use, powerful, C/C++ embeddable web server with
optional CGI, SSL and Lua support. CivetWeb can be used by developers
as a library, to add web server functionality to an existing application.

Civetweb is a project forked out of Mongoose. CivetWeb uses an [MITlicense].
It can also be used by end users as a stand-alone web server. It is available
as single executable, no installation is required.

In our project we will be integrating civetweb into each of our VNF’s.
Civetweb exposes a few functions which are used to resgister custom handlers
for different URI’s that are implemented.
Typical usage is shown below

URI definition for different VNF’s
==================================


+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| *URI*                           |  *Method* |    *Arguments*           |   *description*                                    |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf*                          |   GET     | None                     |  Displays top level methods available              |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config*                   |   GET     | None                     |  Displays the current config set                   |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config*                   |   POST    |                          |                                                    |
|                                 |           | pci_white_list           |                                                    |
|                                 |           |   num_worker(o)          |                                                    |
|                                 |           |   vnf_type(o)            |                                                    |
|                                 |           |   pkt_type (o)           |                                                    |
|                                 |           |   num_lb(o)              |                                                    |
|                                 |           |   sw_lb(o)               |                                                    |
|                                 |           |   sock_in(o)             |                                                    |
|                                 |           |   hyperthread(o)         |                                                    |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config/arp*               |   GET     |  None                    | Displays ARP/ND info                               |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config/arp*               |   POST    |  action: <add/del/req>   |                                                    |
|                                 |           |    ipv4/ipv6: <address>  |                                                    |
|                                 |           |    portid: <>            |                                                    |
|                                 |           |    macaddr: <> for add   |                                                    |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config/link*              |   GET     |  None                    |                                                    |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config/link*              |   POST    |  link_id:<>              |                                                    |
|                                 |           |  state: <1/0>            |                                                    |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config/link/<link id>*    |   GET     |  None                    |                                                    |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config/link/<link id>*    |   POST    |  ipv4/ipv6: <address>    |                                                    |
|                                 |           |  depth: <>               |                                                    |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config/route*             |   GET     |  None                    | Displays gateway route entries                     |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config/route*             |   POST    |  portid: <>              | Adds route entries for default gateway             |
|                                 |           |  nhipv4/nhipv6: <addr>   |                                                    |
|                                 |           |  depth: <>               |                                                    |
|                                 |           |  type:"net/host"         |                                                    |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config/rules(vFW/vACL)*   |   GET     |  None                    | Displays the methods /load/clear                   |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config/rules/load*        |   GET     |  None                    | Displays if file was loaded                        |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config/rules/load*        |   PUT     |  <script file            |                                                    |
|                                 |           |  with cmds>              | Executes each command from script file             |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config/rules/clear*       |   GET     |  None                    |                                                    |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config/nat(vCGNAPT only)* |   GET     |  None                    | Displays the methods /load/clear                   |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config/nat/load*          |   GET     |  None                    | Displays if file was loaded                        |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config/rules/load*        |   PUT     |  <script file with cmds> |                                                    |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/config/nat/clear*         |   GET     |  None                    |                                                    |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/log*                      |   GET     |  None                    | This needs to be implemented for each VNF          |
|                                 |           |                          |          just keeping this as placeholder.         |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/dbg*                      |   GET     |  None                    | Will display methods supported like /pipelines/cmd |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/dbg/pipelines*            |   GET     |  None                    | Displays pipeline information(names)               |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/dbg/pipelines/<pipe id>*  |   GET     |  None                    | Displays debug level for particular pipeline       |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/dbg/cmd*                  |   GET     |  None                    | Last executed command parameters                   |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+
| */vnf/dbg/cmd*                  |   POST    |  cmd:                    |                                                    |
|                                 |           |    dbg:                  |                                                    |
|                                 |           |    d1:                   |                                                    |
|                                 |           |    d2:                   |                                                    |
+---------------------------------+-----------+--------------------------+----------------------------------------------------+

   PUT/POST - Command success/failure

API Usage
---------

Run time Usage
^^^^^^^^^^^^^^

An application(say vFW) with REST API support is run as follows
with just PORT MASK as input. The following environment variables
need to be set before launching the application(To be run from
samplevnf directory).

   ::

     ./build/vFW (Without the -f & -s option)

1. When VNF(vCGNAPT/vACL/vFW) is launched it waits for user to provide the /vnf/config REST method.
   ::

    e.g curl -X POST -H "Content-Type:application/json" -d '{"pci_white_list": "0000:08:00.0 0000:08:00.1"}' http://<IP>/vnf/config

    Note: the config is mostly implemented based on existing VNF's. if new parameters
          are required in the config we need to add that as part of the vnf_template.

    Once the config is provided the application gets launched.

    Note for CGNAPT we can add public_ip_port_range as follows, the following e.g gives
    a multiport configuration with 4 ports, 2 load balancers, worker threads 10, multiple
    public_ip_port_range being added, please note the "/" being used to seperate multiple
    inputs for public_ip_port_range.

    e.g curl -X POST -H "Content-Type:application/json" -d '{"pci_white_list": "0000:05:00.0 0000:05:00.2 0000:07:00.0 0000:07:00.2",
        "num_lb":"2", "num_worker":"10","public_ip_port_range_0": "04040000:(1, 65535)/04040001:(1, 65535)",
        "public_ip_port_range_1": "05050000:(1, 65535)/05050001:(1, 65535)" }' http://10.223.197.179/vnf/config

2. Check the Link IP's using the REST API (vCGNAPT/vACL/vFW)
   ::
     e.g curl <IP>/vnf/config/link

     This would indicate the number of links enabled. You should enable all the links
     by using following curl command for links 0 & 1

     e.g curl -X POST -H "Content-Type:application/json" -d '{"linkid": "0", "state": "1"}'
     http://<IP>/vnf/config/link
     curl -X POST -H "Content-Type:application/json" -d '{"linkid": "1", "state": "1"}'
     http://<IP>/vnf/config/link

3. Now that links are enabled we can configure IP's using link method as follows (vCGNAPT/vACL/vFW)
   ::
     e.g  curl -X POST -H "Content-Type:application/json" -d '{"ipv4":"<IP to be configured>","depth":"24"}'
     http://<IP>/vnf/config/link/0
     curl -X POST -H "Content-Type:application/json" -d '{"ipv4":"IP to be configured","depth":"24"}'
     http://<IP>/vnf/config/link/1

     Once the IP's are set in place time to add NHIP for ARP Table. This is done using for all the ports required.
     /vnf/config/route

     curl -X POST -H "Content-Type:application/json" -d '{"portid":"0", "nhipv4":"IPV4 address",
     "depth":"8", "type":"net"}' http://<IP>/vnf/config/route

4. Adding arp entries we can use this method (vCGNAPT/vACL/vFW)
   ::
     /vnf/config/arp

     e.g
     curl -X POST -H "Content-Type:application/json" -d '{"action":"add", "ipv4":"202.16.100.20",
                 "portid":"0", "macaddr":"00:00:00:00:00:01"}'
                 http://10.223.166.213/vnf/config/arp

     curl -X POST -H "Content-Type:application/json" -d '{"action":"add", "ipv4":"172.16.40.20",
                 "portid":"1", "macaddr":"00:00:00:00:00:02"}'
                 http://10.223.166.213/vnf/config/arp

5. Adding route entries we can use this method (vCGNAPT/vACL/vFW)
   ::
     /vnf/config/route

     e.g curl -X POST -H "Content-Type:application/json" -d '{"type":"net", "depth":"8", "nhipv4":"202.16.100.20",
                  "portid":"0"}' http://10.223.166.240/vnf/config/route
     curl -X POST -H "Content-Type:application/json" -d '{"type":"net", "depth":8", "nhipv4":"172.16.100.20",
                 "portid":"1"}' http://10.223.166.240/vnf/config/route

5. In order to load the rules a script file needs to be posting a script.(vACL/vFW)
   ::
     /vnf/config/rules/load

     Typical example for loading a script file is shown below
     curl -X PUT -F 'image=@<path to file>' http://<IP>/vnf/config/rules/load

     typically arpadd/routeadd commands can be provided as part of this to
     add static arp entries & adding route entries providing the NHIP's.

6. The following REST api's for runtime configuring through a script (vCGNAPT Only)
   ::
     /vnf/config/rules/clear
     /vnf/config/nat
     /vnf/config/nat/load

7. For debug purpose following REST API's could be used as described above.(vCGNAPT/vACL/vFW)
   ::
     /vnf/dbg
     e.g curl http://10.223.166.240/vnf/config/dbg

     /vnf/dbg/pipelines
     e.g curl http://10.223.166.240/vnf/config/dbg/pipelines

     /vnf/dbg/pipelines/<pipe id>
     e.g curl http://10.223.166.240/vnf/config/dbg/pipelines/<id>

     /vnf/dbg/cmd

8. For stats we can use the following method (vCGNAPT/vACL/vFW)
   ::
     /vnf/stats
     e.g curl <IP>/vnf/stats

9. For quittiong the application (vCGNAPT/vACL/vFW)
   ::
     /vnf/quit
     e.g curl <IP>/vnf/quit
