.. This work is licensed under a Creative Commons Attribution 4.0 International
.. License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) OPNFV, Intel Corporation and others.

===========
Methodology
===========

Abstract
========

This chapter describes the methodology/overview of SampleVNF project from
the perspective of a :term:`VNF` and :term:`NFVI` Characterization

Overview
========
This project provides a placeholder for various sample VNF (Virtual Network Function (:term:`VNF`))
development which includes example reference architecture and optimization methods
related to VNF/Network service for high performance VNFs.

The sample VNFs are Open Source approximations* of Telco grade :term:`VNF`
using optimized VNF + NFVi Infrastructure libraries, with Performance Characterization of Sample† Traffic Flows.
• * Not a commercial product. Encourage the community to contribute and close the feature gaps.
• † No Vendor/Proprietary Workloads

ETSI-NFV
========

.. _NFV-TST001: http://www.etsi.org/deliver/etsi_gs/NFV-TST/001_099/001/01.01.01_60/gs_NFV-TST001v010101p.pdf
.. _SampleVNFtst: https://wiki.opnfv.org/display/SAM/Technical+Briefs+of+VNFs
.. _Yardstick_NSB: http://artifacts.opnfv.org/yardstick/docs/testing_user_userguide/index.html#document-13-nsb-overview

SampleVNF Test Infrastructure (NSB (Yardstick_NSB_))in yardstick helps to facilitate
consistent/repeatable methodologies for characterizing & validating the
sample VNFs (:term:`VNF`) through OPEN SOURCE VNF approximations.

Network Service Benchmarking in yardstick framework follows ETSI GS NFV-TST001_
to verify/characterize both :term:`NFVI` & :term:`VNF`

The document ETSI GS NFV-TST001_, "Pre-deployment Testing; Report on Validation
of NFV Environments and Services", recommends methods for pre-deployment
testing of the functional components of an NFV environment.

The SampleVNF project implements the methodology described in chapter 13 of Yardstick_NSB_,
"Pre-deployment validation of NFV infrastructure".

The methodology consists in decomposing the typical :term:`VNF` work-load
performance metrics into a number of characteristics/performance vectors, which
each can be represented by distinct test-cases.

.. seealso:: SampleVNFtst_ for material on alignment ETSI TST001 and SampleVNF.

Metrics
=======

The metrics, as defined by ETSI GS NFV-TST001, are shown in
:ref:`Table1 <table2_1>`.

.. _table2_1:

**Table 1 - Performance/Speed Metrics**

+---------+-------------------------------------------------------------------+
| Category| Performance/Speed                                                 |
|         |                                                                   |
+---------+-------------------------------------------------------------------+
| Network | * Throughput per NFVI node (frames/byte per second)               |
|         | * Throughput provided to a VM (frames/byte per second)            |
|         | * Latency per traffic flow                                        |
|         | * Latency between VMs                                             |
|         | * Latency between NFVI nodes                                      |
|         | * Packet delay variation (jitter) between VMs                     |
|         | * Packet delay variation (jitter) between NFVI nodes              |
|         | * RFC 3511 benchmark                                              |
|         |                                                                   |
+---------+-------------------------------------------------------------------+

.. note:: The description in this OPNFV document is intended as a reference for
  users to understand the scope of the SampleVNF Project and the
  deliverables of the SampleVNF framework. For complete description of
  the methodology, please refer to the ETSI document.

.. rubric:: Footnotes
.. [1] To be included in future deliveries.

