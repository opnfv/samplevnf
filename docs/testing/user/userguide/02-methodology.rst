.. This work is licensed under a Creative Commons Attribution 4.0 International
.. License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) OPNFV, Intel Corporation and others.

===========
Methodology
===========
.. _NFV-TST009: https://docbox.etsi.org/ISG/NFV/open/Publications_pdf/Specs-Reports/NFV-TST%20009v3.2.1%20-%20GS%20-%20NFVI_Benchmarks.pdf

Abstract
========

This chapter describes the methodology/overview of SampleVNF project from
the perspective of :term:`NFVI` Characterization

Overview
========
This project covers the dataplane benchmarking for Network Function Virtualization
Infrastructure (:term:`NFVI`)) using the PROX tool, according to ETSI GS NFV-TST009_.

The test execution and reporting is driven by the Xtesting framework and is fully automated.

When executing the tests, traffic will be send between 2 or more PROX VMs and all metrics
will be collected in the Xtesting database.
The placement of the test VMs (in which the PROX tool is running), can be controlled by
Heat stacks, but can also be done through other means. This will be explained in the chapter
covering the PROX instance deployment, and needs to be done prior to the test execution.

The PROX tool is a DPDK based application optimized for high throughput packet handling.
As such, we will not measure limitations imposed by the tool, but the capacity of the 
NFVI. In the rare case that the PROX tool would impose a limit, a warning will be logged.

ETSI-NFV
========
The document ETSI GS NFV-TST009_, "Specification of Networking Benchmarks and
Measurement Methods for NFVI", specifies vendor-agnostic definitions of performance
metrics and the associated methods of measurement for Benchmarking networks supported
in the NFVI. Throughput, latency, packet loss and delay variation will be measured.
The delay variation is not represented by the Frame Delay Variation (FDV) as defined in
the specification, but by the average latency, the 99 percentile latency, the maximum
latency and the complete latency distribution histogram.

Metrics
=======

The metrics, as reported by the tool, and aligned with the definitions in ETSI GS NFV-TST009_,
are shown in :ref:`Table1 <table2_1>`.

.. _table2_1:

**Table 1 - Network Metrics**

+-----------------+---------------------------------------------------------------+
| Measurement     | Description                                                   |
|                 |                                                               |
+-----------------+---------------------------------------------------------------+
| Throughput      | Maximum number of traffic that can be sent between 2 VM       |
|                 | instances, within the allowed packet loss requirements.       |
|                 | Results are expressed in Mpps and in Gb/s                     |
+-----------------+---------------------------------------------------------------+
| Latency         | 99 percentile Round trip latency expressed in micro-seconds   |
|                 | Note that you can also specify the n-th percentile            |
+-----------------+---------------------------------------------------------------+
| Delay Variation | Average latency, maximum latency and the latency histogram    |
+-----------------+---------------------------------------------------------------+
| Loss            | Packets per seconds that were lost on their round trip between|
|                 | VMs. Total packet loss numbers are also reported              |
+-----------------+---------------------------------------------------------------+

.. note:: The description in this OPNFV document is intended as a reference for
  users to understand the scope of the SampleVNF Project and the
  deliverables of the SampleVNF framework. For complete description of
  the methodology, please refer to the ETSI document.
