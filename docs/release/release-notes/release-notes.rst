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

===========================================
OPNFV Euphrates Release Note for SampleVNF
===========================================

.. toctree::
   :maxdepth: 2

.. _SampleVNF: https://wiki.opnfv.org/samplevnf

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
+----------------+--------------------+---------------------------------+
|                |  1.0               | SampleVNF for Euphrates release    |
|                |                    |                                 |
+----------------+--------------------+---------------------------------+


Important Notes
===============

The software delivered in the OPNFV SampleVNF_ Project, comprising the
*SampleVNF VNFs*, the *SampleVNF test cases* and performace test case
are part of  OPNFV Yardstick_ Project is a realization of the methodology in
ETSI-ISG NFV-TST001_.


OPNFV Euphrates Release
======================

This Euphrates release provides *SampleVNF* as a aprox VNF repository for
VNF/NFVI testing, characterization and OPNFV feature testing, automated on
OPNFV platform, including:

* Documentation generated with Sphinx

  * User Guide

  * Developer Guide

  * Release notes (this document)

  * Results

* Automated SampleVNF test suit in OPNFV Yardstick_ Project

* SampleVNF source code

For Euphrates release, the *SampleVNF * is used for the following
testing:

* OPNFV platform testing - generic test cases to measure the categories:

  * NFVi Characterization:

    * Network

  * VNF Characterization:

    * Network - rfc2544, rfc3511, latency, http_test etc


The *SampleVNF* is developed in the OPNFV community, by the
SampleVNF_ team. The *Network Service Benchmarking* Testing tool is a part of
the Yardstick Project.

.. note:: The test case description template used for the SampleVNF in yardstick
  test cases is based on the document ETSI-ISG NFV-TST001_; the results report template
  used for the SampleVNF test results is based on the IEEE Std 829-2008.


Release Data
============

+--------------------------------------+--------------------------------------+
| **Project**                          | SampleVNF                            |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Repo/tag**                         |                                      |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **SampleVNF Docker image tag**       |                                      |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release designation**              | Euphrates                            |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Release date**                     |                                      |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
| **Purpose of the delivery**          |                                      |
|                                      |                                      |
+--------------------------------------+--------------------------------------+


Deliverables
============

Documents
---------

 - User Guide:  To be added

 - Developer Guide: To be added


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
  add "network service benchmarking(NSB)" chapter;
  add "SampleVNF - NSB Testing -Installation" chapter; add "SampleVNF API" chapter;
  add "SampleVNF user interface" chapter; Update SampleVNF installation chapter;

- SampleVNF Developer Guide

- SampleVNF Release Notes for SampleVNF: this document


Feature additions
-----------------

- SampleVNF RESTful API support

- Introduce Network service benchmarking


Known Issues/Faults
------------



Corrected Faults
----------------

Euphrates.1.0:

+----------------------------+------------------------------------------------+
| **JIRA REFERENCE**         | **DESCRIPTION**                                |
|                            |                                                |
+----------------------------+------------------------------------------------+
| JIRA: samplevnf-           |                                                |
|                            |                                                |
+----------------------------+------------------------------------------------+


Euphrates  known restrictions/issues
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
