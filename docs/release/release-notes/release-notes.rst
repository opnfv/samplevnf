.. This work is licensed under a Creative Commons Attribution 4.0 International
.. License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) OPNFV, Intel Corporation and others.

=======
License
=======

OPNFV release note for SampleVNF Docs
are licensed under a Creative Commons Attribution 4.0 International License.
You should have received a copy of the license along with this.
If not, see <http://creativecommons.org/licenses/by/4.0/>.
:

The *SampleVNFs*, the *SampleVNF test cases* are opensource software,
licensed under the terms of the Apache License, Version 2.0.

==========================================
OPNFV Farser Release Note for SampleVNF
==========================================

.. toctree::
   :maxdepth: 2

.. _SampleVNF: https://wiki.opnfv.org/SAM

.. _Yardstick: https://wiki.opnfv.org/yardstick

.. _NFV-TST001: http://www.etsi.org/deliver/etsi_gs/NFV-TST/001_099/001/01.01.01_60/gs_NFV-TST001v010101p.pdf


Abstract
========

This document describes the release note of SampleVNF project.


Version History
===============

+----------------+--------------------+---------------------------------+
| *Date*         | *Version*          | *Comment*                       |
|                |                    |                                 |
+----------------+--------------------+---------------------------------+
| "May 25 2018"  |  6.1.0             | SampleVNF for Farser release    |
|                |                    |                                 |
+----------------+--------------------+---------------------------------+


Important Notes
===============

The software delivered in the OPNFV SampleVNF_ Project, comprising the
*SampleVNF VNFs* and performance test case are part of  OPNFV Yardstick_
Project is a realization of the methodology in ETSI-ISG NFV-TST001_.


OPNFV Farser Release
======================

This Farser release provides *SampleVNF* as a approx VNF repository for
VNF/NFVI testing, characterization and OPNFV feature testing, automated on
OPNFV platform, including:

* Documentation generated with Sphinx

  * User Guide

  * Developer Guide

  * Release notes (this document)

  * Results

* Automated SampleVNF test suit in OPNFV Yardstick_ Project

* SampleVNF source code

For Farser release, the *SampleVNF* supported:

+----------------+---------------------------------------------------------+-------------------+
| *VNF*          |                 *Name*                                  |    *version*      |
+----------------+---------------------------------------------------------+-------------------+
| *CGNAPT*       | Carrier Grade Network Address and port Translation .5.0 |     v0.1.0        |
+----------------+---------------------------------------------------------+-------------------+
| *Prox*         | Packet pROcessing eXecution engine                      |     v0.40.0       |
|                |  acts as traffic generator, L3FWD, L2FWD, BNG etc       |                   |
+----------------+---------------------------------------------------------+-------------------+
| *vACL*         | Access Control List                                     |     v0.1.0        |
+----------------+---------------------------------------------------------+-------------------+
| *vFW*          | Firewall                                                |     v0.1.0        |
+----------------+---------------------------------------------------------+-------------------+
| *UDP_replay*   | UDP_Replay                                              |     v0.1.0        |
+----------------+---------------------------------------------------------+-------------------+

.. note:: Highlevel Desgin and features supported by each of the VNFs is described in Developer
          and user guide.

For Farser release, the *SampleVNF* is used for the following
testing:

* OPNFV platform testing - generic test cases to measure the categories:

  * NFVI Characterization:

    * Network

  * VNF Characterization:

    * Network - rfc2544, rfc3511, latency, http_test etc


The *SampleVNF* is developed in the OPNFV community, by the SampleVNF_ team.
The *Network Service Benchmarking* SampleVNF Characterization Testing tool is a part of the
Yardstick Project.

.. note:: The test case description template used for the SampleVNF in yardstick
  test cases is based on the document ETSI-ISG NFV-TST001_; the results report template
  used for the SampleVNF test results is based on the IEEE Std 829-2008.


Release Data
============

+--------------------------------------+--------------------------------------+
| **Project**                          | SampleVNF                            |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Repo/tag**                         | opnfv-6.1.0                          |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **SampleVNF Docker image tag**       | Farser 6.1                           |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release designation**              | Farser 6.1                           |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release date**                     | "May 25 2018"                        |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Purpose of the delivery**          | Fraser alignment to Released         |
|                                      | bug-fixes for the following:         |
|                                      | - Memory leak                        |
|                                      | - minimum latency                    |
|                                      | - Increase default mbuf size and     |
|                                      |   code simplification/cleanup        |
|                                      | - Crash in rx/tx distribution        |
|                                      |                                      |
+--------------------------------------+--------------------------------------+


Deliverables
============

Documents
---------

 - User Guide: http://artifacts.opnfv.org/samplevnf/docs/testing_user_userguide/index.html

 - Developer Guide: http://artifacts.opnfv.org/samplevnf/docs/testing_developer/index.html


Software Deliverables
---------------------

 - The SampleVNF Docker image: To be added


**SampleVNF tested on Contexts**

+---------------------+-------------------------------------------------------+
| **Context**         | **Description**                                       |
|                     |                                                       |
+---------------------+-------------------------------------------------------+
| *Heat*              | Models orchestration using OpenStack Heat             |
|                     |                                                       |
+---------------------+-------------------------------------------------------+
| *Node*              | Models Baremetal, Controller, Compute                 |
|                     |                                                       |
+---------------------+-------------------------------------------------------+
| *Standalone*        | Models VM running on Non-Managed NFVi                 |
|                     |                                                       |
+---------------------+-------------------------------------------------------+

Document Version Changes
------------------------

This is the first version of the SampleVNF  in OPNFV.
It includes the following documentation updates:

- SampleVNF User Guide:

- SampleVNF Developer Guide

- SampleVNF Release Notes for SampleVNF: this document


Feature additions
-----------------

- SampleVNF RESTful API support
- Security gateway testing
- Support reading inline jumbo frame and dump them
- Add support for generation of jumbo frames
- Support for dpdk-stable-17.11.1 crypto
- Add support for multiple variables in core definition
- Support async operation in handle_esp
- Add support for reception of jumbo frames
- Support additional MAC format in config file
- Add support for multiple GEN tasks running on the same core
- Add support for crypto on multiple cores
- Zero packet loss testing has been added.
- Integrate irq mode into PROX (support display and command line)
- Support async operation in handle_esp
- Add config option to use port mac as src mac in l2fwd and swap
- Add support for DPDK 17.11
- Add support for multiple tasks generating to same ip in l3 mode.
- Add l3 support for tasks without physical tx ports

Bug fixes:
- link speed when link is down at startup.
- minimum latency
- potential crash if link speed is null
- the calculation of dropped packets and other changes
- latency accuracy and dumping latencies to file
- issues with the pkt_size command
- potential crash in rx and tx distribution
- extrapolation used in latency measurements
- dumping receive packets
- using signature in latency measurements
- stacking of rx receive functions
- potential crash when issuing "tx distr stop" command.
- extrapolation used in latency measurements
- memory leak introduced by 4a65cd84


Known Issues/Faults
-------------------
- Huge page freeing needs to be handled properly while running the application else it might
  cause system crash. Known issue from DPDK.
- UDP Replay is used to capture throughput for dynamic cgnapt
- Hardware Checksum offload is not supported for IPv6 traffic
- SampleVNF on sriov is tested till 4 threads
- Rest API is supported only for vACL, vFW, vCGNAPT
- Rest API uses port 80, make sure other webservices are stopped before using SampleVNF RestAPI.

Corrected Faults
----------------

Farser 6.1:

+----------------------------+-------------------------------------------------------------------+
| **JIRA REFERENCE**         | **DESCRIPTION**                                                   |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-98               |  SampleVNF RESTful API support                                    |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-99               |  Security gateway testing                                         |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-100              |  Add support for generation of jumbo frames                       |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-101              |  Support for dpdk-stable-17.11.1 crypto                           |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-102              |  Support async operation in handle_espo                           |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-103              |  Add support for reception of jumbo frames                        |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-104              |  Support additional MAC format in config file                     |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-105              |  support for multiple GEN tasks running on the same core          |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-106              |  Add support for crypto on multiple cores                         |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-107              |  Zero packet loss testing                                         |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-108              |  Integrate irq mode into PROX (support display and command line)  |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-109              |  Add config option to use port mac as src mac in l2fwd and swap   |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-110              |  Add support for DPDK 17.11                                       |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-111              |  Add support for multiple tasks generating to same ip in l3 mode  |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-112              |  Add l3 support for tasks without physical tx ports               |
+----------------------------+-------------------------------------------------------------------+

Bug Fix Jira:

+----------------------------+-------------------------------------------------------------------+
| **JIRA REFERENCE**         | **DESCRIPTION**                                                   |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-113              |  link speed when link is down at startup.                         |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-114              |  minimum latency                                                  |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-115              |  potential crash if link speed is null                            |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-116              |  the calculation of dropped packets and other changes             |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-117              |  latency accuracy and dumping latencies to file                   |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-118              |  issues with the pkt_size command                                 |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-119              |  extrapolation used in latency measurements                       |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-120              |  dumping receive packets                                          |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-121              |  using signature in latency measurements                          |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-122              |  stacking of rx receive functions                                 |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-123              |  potential crash when issuing "tx distr stop" command.            |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-124              |  extrapolation used in latency measurements                       |
+----------------------------+-------------------------------------------------------------------+
| SAMPLEVNF-125              |  memory leak introduced by 4a65cd84                               |
+----------------------------+-------------------------------------------------------------------+

Farser known restrictions/issues
====================================
+-----------+-----------+----------------------------------------------+
| Installer | Scenario  |  Issue                                       |
+===========+===========+==============================================+
|           |           |                                              |
+-----------+-----------+----------------------------------------------+


Open JIRA tickets
=================

+----------------------------+------------------------------------------------+
| **JIRA REFERENCE**         | **DESCRIPTION**                                |
|                            |                                                |
+----------------------------+------------------------------------------------+
|                            |                                                |
|                            |                                                |
+----------------------------+------------------------------------------------+


Useful links
============

 - wiki project page: https://wiki.opnfv.org/display/SAM

 - wiki SampleVNF Farser release planing page: https://wiki.opnfv.org/display/SAM/F+Release+Plan+for+SampleVNF

 - SampleVNF repo: https://git.opnfv.org/cgit/samplevnf

 - SampleVNF IRC chanel: #opnfv-samplevnf
