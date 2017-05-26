..  BSD LICENSE
    Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

    * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in
    the documentation and/or other materials provided with the
    distribution.
    * Neither the name of Intel Corporation nor the names of its
    contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

.. _Enabling_Additional_Functionality:

Enabling Additional Functionality
=================================

.. _High_Precision_Event_Timer:

High Precision Event Timer HPET) Functionality
----------------------------------------------

BIOS Support
~~~~~~~~~~~~

The High Precision Timer (HPET) must be enabled in the platform BIOS if the HPET is to be used.
Otherwise, the Time Stamp Counter (TSC) is used by default.
The BIOS is typically accessed by pressing F2 while the platform is starting up.
The user can then navigate to the HPET option. On the Crystal Forest platform BIOS, the path is:
**Advanced -> PCH-IO Configuration -> High Precision Timer ->** (Change from Disabled to Enabled if necessary).

On a system that has already booted, the following command can be issued to check if HPET is enabled::

   grep hpet /proc/timer_list

If no entries are returned, HPET must be enabled in the BIOS (as per the instructions above) and the system rebooted.

Linux Kernel Support
~~~~~~~~~~~~~~~~~~~~

The DPDK makes use of the platform HPET timer by mapping the timer counter into the process address space, and as such,
requires that the ``HPET_MMAP`` kernel configuration option be enabled.

.. warning::

    On Fedora, and other common distributions such as Ubuntu, the ``HPET_MMAP`` kernel option is not enabled by default.
    To recompile the Linux kernel with this option enabled, please consult the distributions documentation for the relevant instructions.

Enabling HPET in the DPDK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default, HPET support is disabled in the DPDK build configuration files.
To use HPET, the ``CONFIG_RTE_LIBEAL_USE_HPET`` setting should be changed to ``y``, which will enable the HPET settings at compile time.

For an application to use the ``rte_get_hpet_cycles()`` and ``rte_get_hpet_hz()`` API calls,
and optionally to make the HPET the default time source for the rte_timer library,
the new ``rte_eal_hpet_init()`` API call should be called at application initialization.
This API call will ensure that the HPET is accessible, returning an error to the application if it is not,
for example, if ``HPET_MMAP`` is not enabled in the kernel.
The application can then determine what action to take, if any, if the HPET is not available at run-time.

.. note::

    For applications that require timing APIs, but not the HPET timer specifically,
    it is recommended that the ``rte_get_timer_cycles()`` and ``rte_get_timer_hz()`` API calls be used instead of the HPET-specific APIs.
    These generic APIs can work with either TSC or HPET time sources, depending on what is requested by an application call to ``rte_eal_hpet_init()``,
    if any, and on what is available on the system at runtime.

Running DPDK Applications Without Root Privileges
--------------------------------------------------------

Although applications using the DPDK use network ports and other hardware resources directly,
with a number of small permission adjustments it is possible to run these applications as a user other than "root".
To do so, the ownership, or permissions, on the following Linux file system objects should be adjusted to ensure that
the Linux user account being used to run the DPDK application has access to them:

*   All directories which serve as hugepage mount points, for example,   ``/mnt/huge``

*   The userspace-io device files in  ``/dev``, for example,  ``/dev/uio0``, ``/dev/uio1``, and so on

*   The userspace-io sysfs config and resource files, for example for ``uio0``::

       /sys/class/uio/uio0/device/config
       /sys/class/uio/uio0/device/resource*

*   If the HPET is to be used,  ``/dev/hpet``

.. note::

    On some Linux installations, ``/dev/hugepages``  is also a hugepage mount point created by default.

Power Management and Power Saving Functionality
-----------------------------------------------

Enhanced Intel SpeedStep® Technology must be enabled in the platform BIOS if the power management feature of DPDK is to be used.
Otherwise, the sys file folder ``/sys/devices/system/cpu/cpu0/cpufreq`` will not exist, and the CPU frequency- based power management cannot be used.
Consult the relevant BIOS documentation to determine how these settings can be accessed.

For example, on some Intel reference platform BIOS variants, the path to Enhanced Intel SpeedStep® Technology is::

   Advanced
     -> Processor Configuration
     -> Enhanced Intel SpeedStep® Tech

In addition, C3 and C6 should be enabled as well for power management. The path of C3 and C6 on the same platform BIOS is::

   Advanced
     -> Processor Configuration
     -> Processor C3 Advanced
     -> Processor Configuration
     -> Processor C6

Using Linux Core Isolation to Reduce Context Switches
-----------------------------------------------------

While the threads used by an DPDK application are pinned to logical cores on the system,
it is possible for the Linux scheduler to run other tasks on those cores also.
To help prevent additional workloads from running on those cores,
it is possible to use the ``isolcpus`` Linux kernel parameter to isolate them from the general Linux scheduler.

For example, if DPDK applications are to run on logical cores 2, 4 and 6,
the following should be added to the kernel parameter list:

.. code-block:: console

    isolcpus=2,4,6

Loading the DPDK KNI Kernel Module
----------------------------------

To run the DPDK Kernel NIC Interface (KNI) sample application, an extra kernel module (the kni module) must be loaded into the running kernel.
The module is found in the kmod sub-directory of the DPDK target directory.
Similar to the loading of the ``igb_uio`` module, this module should be loaded using the insmod command as shown below
(assuming that the current directory is the DPDK target directory):

.. code-block:: console

   insmod kmod/rte_kni.ko

.. note::

   See the "Kernel NIC Interface Sample Application" chapter in the *DPDK Sample Applications User Guide* for more details.

Using Linux IOMMU Pass-Through to Run DPDK with Intel® VT-d
-----------------------------------------------------------

To enable Intel® VT-d in a Linux kernel, a number of kernel configuration options must be set. These include:

*   ``IOMMU_SUPPORT``

*   ``IOMMU_API``

*   ``INTEL_IOMMU``

In addition, to run the DPDK with Intel® VT-d, the ``iommu=pt`` kernel parameter must be used when using ``igb_uio`` driver.
This results in pass-through of the DMAR (DMA Remapping) lookup in the host.
Also, if ``INTEL_IOMMU_DEFAULT_ON`` is not set in the kernel, the ``intel_iommu=on`` kernel parameter must be used too.
This ensures that the Intel IOMMU is being initialized as expected.

Please note that while using ``iommu=pt`` is compulsory for ``igb_uio driver``, the ``vfio-pci`` driver can actually work with both ``iommu=pt`` and ``iommu=on``.

High Performance of Small Packets on 40G NIC
--------------------------------------------

As there might be firmware fixes for performance enhancement in latest version
of firmware image, the firmware update might be needed for getting high performance.
Check with the local Intel's Network Division application engineers for firmware updates.
The base driver to support firmware version of FVL3E will be integrated in the next
DPDK release, so currently the validated firmware version is 4.2.6.

Enabling Extended Tag
~~~~~~~~~~~~~~~~~~~~~

PCI configuration of ``extended_tag`` has big impact on small packet size
performance of 40G ports. Enabling ``extended_tag`` can help 40G port to
achieve the best performance, especially for small packet size.

* Disabling/enabling ``extended_tag`` can be done in some BIOS implementations.

* If BIOS does not enable it, and does not support changing it, tools
  (e.g. ``setpci`` on Linux) can be used to enable or disable ``extended_tag``.

* From release 16.04, ``extended_tag`` is enabled by default during port
  initialization, users don't need to care about that anymore.

Use 16 Bytes RX Descriptor Size
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As i40e PMD supports both 16 and 32 bytes RX descriptor sizes, and 16 bytes size can provide helps to high performance of small packets.
Configuration of ``CONFIG_RTE_LIBRTE_I40E_16BYTE_RX_DESC`` in config files can be changed to use 16 bytes size RX descriptors.

High Performance and per Packet Latency Tradeoff
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Due to the hardware design, the interrupt signal inside NIC is needed for per
packet descriptor write-back. The minimum interval of interrupts could be set
at compile time by ``CONFIG_RTE_LIBRTE_I40E_ITR_INTERVAL`` in configuration files.
Though there is a default configuration, the interval could be tuned by the
users with that configuration item depends on what the user cares about more,
performance or per packet latency.
