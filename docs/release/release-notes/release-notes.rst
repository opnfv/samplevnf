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
OPNFV Euphrates Release Note for SampleVNF
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
| "Oct 20 2017"  |  5.1               | SampleVNF for Euphrates release |
|                |                    |                                 |
+----------------+--------------------+---------------------------------+


Important Notes
===============

The software delivered in the OPNFV SampleVNF_ Project, comprising the
*SampleVNF VNFs* and performance test case are part of  OPNFV Yardstick_
Project is a realization of the methodology in ETSI-ISG NFV-TST001_.


OPNFV Euphrates Release
======================

This Euphrates release provides *SampleVNF* as a approx VNF repository for
VNF/NFVI testing, characterization and OPNFV feature testing, automated on
OPNFV platform, including:

* Documentation generated with Sphinx

  * User Guide

  * Developer Guide

  * Release notes (this document)

  * Results

* Automated SampleVNF test suit in OPNFV Yardstick_ Project

* SampleVNF source code

For Euphrates release, the *SampleVNF* supported:

+----------------+---------------------------------------------------------+-------------------+
| *VNF*          |                 *Name*                                  |    *version*      |
+----------------+---------------------------------------------------------+-------------------+
| *CGNAPT*       | Carrier Grade Network Address and port Translation .5.0 |     v0.1.0        |
+----------------+---------------------------------------------------------+-------------------+
| *Prox*         | Packet pROcessing eXecution engine                      |     v0.39.0       |
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

For Euphrates release, the *SampleVNF* is used for the following
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
| **Repo/tag**                         | samplevnf/Euphrates.5.1              |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **SampleVNF Docker image tag**       | Euphrates.5.1                        |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release designation**              | Euphrates                            |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release date**                     | "October 20 2017"                    |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Purpose of the delivery**          | OPNFV Euphrates release 5.1          |
|                                      |                                      |
+--------------------------------------+--------------------------------------+


Deliverables
============

Documents
---------

 - User Guide: http://artifacts.opnfv.org/samplevnf/euphrates/5.0.0/docs/testing_user_userguide/index.html

 - Developer Guide: http://artifacts.opnfv.org/samplevnf/euphrates/5.0.0/docs/testing_developer/index.html


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

- Introduce Network service benchmarking


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

Euphrates.5.1:

+----------------------------+------------------------------------------------+
| **JIRA REFERENCE**         | **DESCRIPTION**                                |
|                            |                                                |
+----------------------------+------------------------------------------------+
|                            |                                                |
|                            |                                                |
+----------------------------+------------------------------------------------+


Euphrates known restrictions/issues
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

 - wiki SampleVNF Euphrates release planing page: https://wiki.opnfv.org/display/SAM/SampleVNF+Euphrates+Release+Planning

 - SampleVNF repo: https://git.opnfv.org/cgit/samplevnf

 - SampleVNF IRC chanel: #opnfv-samplevnf
