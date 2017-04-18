SAMPLEVNF Installation Guide
============================

1. Installation and Compilation
-------------------------------

###### Dependencies
* DPDK 16.04: Downloaded and installed via install.sh or manually from [here](http://fast.dpdk.org/rel/dpdk-16.04.tar.xz)
Both the options are avialble as part of install.sh below.
* libpcap-dev
* libzmq
* libcurl

###### Environment variables

Apply all the additional patches in 'patches/dpdk_custom_patch/' and build dpdk

::
  export RTE_SDK=<dpdk 16.04 directory>
  export RTE_TARGET=x86_64-native-linuxapp-gcc

This is done by install.sh script.

###### Initial Compilation

#### 1.1 Using install.sh:

Run "./install.sh" in samplevnf root folder.

Following are the options for setup:

::

  ----------------------------------------------------------
   Step 1: Environment setup.
  ----------------------------------------------------------
  [1] Check OS and network connection

  ----------------------------------------------------------
   Step 2: Download and Install
  ----------------------------------------------------------
  [2] Agree to download
  [3] Download packages
  [4] Download DPDK zip (optional, use it when option 4 fails)
  [5] Install DPDK
  [6] Setup hugepages

  ----------------------------------------------------------
   Step 3: Build VNF
  ----------------------------------------------------------
  [7] Build VNF

  [8] Exit Script


[1] This will check the OS version and network connectivity and report
    any anomaly. If the system is behind a proxy, it will ask for a proxy
    and update the required environment variables.
[2] Select yes in this option to be able to download the required packages.
[3] Actual download of the dependent packages like libpcap, build essentials
    etc.
[4] Dpdk  downloaded as a zip file using this option.
[5] Build and set environment variables to use DPDK.
[6] Setup hugepages for the system
[7] Build controlplane and dataplane applications. This sets the RTE_SDK
    environment variable and builds the applications.

#### 1.2 Manual build:

Control Pland and Data Plane applications can be built using install.sh using
"Step 3 Build VNF" or can be done manually as follows:

1. Setup RTE_SDK and RTE_TARGET variables using ./setenv.sh.
   Point RTE_SDK to the path where dpdk is downloaded.
2. Use "make" in samplevnf root directory to build all the VNFs
   OR
   Use respective "make" in individual VNF folder to build them individually.
