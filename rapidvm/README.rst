RAPID VM IMAGE
++++++++++++++

This repo will build a centos 7 image with dpdk and prox installed.
Optimizations for dpdk will also be done.

BUILD INSTRUCTIONS
==================

Build the image
---------------
- cd dib
- update the version number for the image (if needed) by modifying __version__ in build-image.sh
- setup your http_proxy if needed
- bash build-image.sh

IMAGE INSTANCE AND CONFIG
=========================

VM Requirements
---------------
The instance must be launched with:
- 1 network interface for the management network
- at least 1 interface for the dataplane networks
- at least 4 vCPUs
- 4 GB RAM
- cpu pinning set to exclusive

Auto-configuration
------------------
The rapid scripts will configure the prox instances and drive the testing.


Hardcoded Username and Password
--------------------------------
In case of problems, you can ssh into the VM:
- Username: rapid
- Password: rapid
