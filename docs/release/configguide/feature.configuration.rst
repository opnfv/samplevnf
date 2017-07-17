.. This work is licensed under a Creative Commons Attribution 4.0 International License.
.. http://creativecommons.org/licenses/by/4.0
.. (c) Ferenc Cserepkei, Brady Allen Johnson, Manuel Buil and others

Abstract
========
This document provides information on how to install the OpenDayLigh SFC
features in OPNFV with the use of os_odl-l2_sfc-(no)ha scenario.

SFC feature desciription
========================
For details of the scenarios and their provided capabilities refer to
the scenario description documents:

- http://artifacts.opnfv.org/sfc/colorado/docs/scenarios_os-odl_l2-sfc-ha/index.html

- http://artifacts.opnfv.org/sfc/colorado/docs/scenarios_os-odl_l2-sfc-noha/index.html


The SFC feature enables creation of Service Fuction Chains - an ordered list
of chained network funcions (e.g. firewalls, NAT, QoS)

The SFC feature in OPNFV is implemented by 3 major components:

- OpenDayLight SDN controller

- Tacker: Generic VNF Manager (VNFM) and a NFV Orchestrator (NFVO)

- OpenvSwitch: The Service Function Forwarder(s)

Hardware requirements
=====================

The SFC scenarios can be deployed on a bare-metal OPNFV cluster or on a
virtual environment on a single host.

Bare metal deployment on (OPNFV) Pharos lab
-------------------------------------------
Hardware requirements for bare-metal deployments of the OPNFV infrastructure
are given by the Pharos project. The Pharos project provides an OPNFV
hardware specification for configuring your hardware:
http://artifacts.opnfv.org/pharos/docs/pharos-spec.html


Virtual deployment
------------------
To perform a virtual deployment of an OPNFV SFC scenario on a single host,
that host has to meet the following hardware requirements:

- SandyBridge compatible CPU with virtualization support

- capable to host 5 virtual cores (5 physical ones at least)

- 8-12 GBytes RAM for virtual hosts (controller, compute), 48GByte at least

- 128 GiBiBytes room on disk for each virtual host (controller, compute) +
  64GiBiBytes for fuel master, 576 GiBiBytes at least

- Ubuntu Trusty Tahr - 14.04(.5) server operating system with at least ssh
  service selected at installation.

- Internet Connection (preferably http proxyless)


Pre-configuration activites - Preparing the host to install Fuel by script
==========================================================================
.. Not all of these options are relevant for all scenario's.  I advise following the
.. instructions applicable to the deploy tool used in the scenario.

Before starting the installation of the SFC scenarios some preparation of the
machine that will host the Colorado Fuel cluster must be done.

Installation of required packages
---------------------------------
To be able to run the installation of the basic OPNFV fuel installation the
Jumphost (or the host which serves the VMs for the virtual deployment) needs to
install the following packages:
::

 sudo apt-get install -y git make curl libvirt-bin libpq-dev qemu-kvm \
                         qemu-system tightvncserver virt-manager sshpass \
                         fuseiso genisoimage blackbox xterm python-pip \
                         python-git python-dev python-oslo.config \
                         python-pip python-dev libffi-dev libxml2-dev \
                         libxslt1-dev libffi-dev libxml2-dev libxslt1-dev \
                         expect curl python-netaddr p7zip-full

 sudo pip install GitPython pyyaml netaddr paramiko lxml scp \
                  scp pycrypto ecdsa debtcollector netifaces enum

During libvirt install the user is added to the libvirtd group, so you have to
logout then login back again


Download the installer source code and artifact
-----------------------------------------------
To be able to install the scenario os_odl-l2_sfc-(no)ha one can follow the way
CI is deploying the scenario.
First of all the opnfv-fuel repository needs to be cloned:
::

 git clone -b 'stable/colorado' ssh://<user>@gerrit.opnfv.org:29418/fuel

This command copies the whole colorado branch of repository fuel.

Now download the appropriate OPNFV Fuel ISO into an appropriate folder:
::

 wget http://artifacts.opnfv.org/fuel/colorado/opnfv-colorado.1.0.iso

The exact name of the ISO image may change.
Check https://www.opnfv.org/opnfv-colorado-fuel-users to get the latest ISO.

Simplified scenario deployment procedure using Fuel
===================================================

This section describes the installation of the os-odl-l2_sfc or
os-odl-l2_sfc-noha OPNFV reference platform stack across a server cluster
or a single host as a virtual deployment.

Scenario Preparation
--------------------
dea.yaml and dha.yaml need to be copied and changed according to the
lab-name/host where you deploy.
Copy the full lab config from:
::

 cp -r <path-to-opnfv-fuel-repo>/deploy/config/labs/devel-pipeline/elx \
    <path-to-opnfv-fuel-repo>/deploy/config/labs/devel-pipeline/<your-lab-name>

Add at the bottom of dha.yaml
::

 disks:
   fuel: 64G
   controller: 128G
   compute: 128G

 define_vms:
   controller:
     vcpu:
       value: 2
     memory:
       attribute_equlas:
         unit: KiB
       value: 12521472
     currentMemory:
       attribute_equlas:
         unit: KiB
       value: 12521472
   compute:
     vcpu:
       value: 2
     memory:
       attribute_equlas:
         unit: KiB
       value: 8388608
     currentMemory:
       attribute_equlas:
         unit: KiB
       value: 8388608
   fuel:
     vcpu:
       value: 2
     memory:
       attribute_equlas:
         unit: KiB
       value: 2097152
     currentMemory:
       attribute_equlas:
         unit: KiB
       value: 2097152

Check if the default settings in dea.yaml are in line with your intentions
and make changes as required.

Installation procedures
-----------------------

We state here several alternatives.
First, we describe methods that are based on the use of the deploy.sh script,
what is used by the OPNFV CI system and can be found in the Fuel repository.

In addition, the SFC feature can also be configured manually in the Fuel GUI
what we will show in the last subsection.

Before starting any of the following procedures, go to
::

 cd <opnfv-fuel-repo>/ci

Full automatic virtual deployment, High Availablity mode
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This example will deploy the high-availability flavor of SFC scenario
os_odl-l2_sfc-ha in a fully automatic way, i.e. all installation steps
(Fuel server installation, configuration, node discovery and platform
deployment) will take place without any further prompt for user input.
::

 sudo bash ./deploy.sh -b file://<path-to-opnfv-fuel-repo>/config/ -l devel-pipeline -p <your-lab-name>
 -s os_odl-l2_sfc-ha -i file://<path-to-fuel-iso>

Full automatic virtual deployment, non HIGH Availablity mode
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following command will deploy the SFC scenario with non-high-availability
flavor (note the  different scenario name for the -s switch). Otherwise it
does the same as described above.
::

 sudo bash ./deploy.sh -b file://<path-to-opnfv-fuel-repo>/config/ -l devel-pipeline -p <your-lab-name>
 -s os_odl-l2_sfc-noha -i file://<path-to-fuel-iso>

Automatic Fuel installation and manual scenario deployment
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A useful alternative to the full automatic procedure is to only deploy the Fuel host and to run host selection, role assignment and SFC scenario configuration manually.
::

 sudo bash ./deploy.sh -b file://<path-to-opnfv-fuel-repo>/config/ -l devel-pipeline -p <your-lab-name> -s os_odl-l2_sfc-ha -i file://<path-to-fuel-iso> -e

With -e option the installer will skip environment deployment, so an user
can do some modification before the scenario is really deployed. Another
useful option is the -f option which deploys the scenario using an existing
Fuel host.

The result of this installation is a well configured Fuel sever. The use of
the deploy button on Fuel dashboard can initiate the deployment. A user may
perform manual post-configuration as well.

Feature configuration on existing Fuel
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If a Fuel server is already provisioned but the fuel plugins for Opendaylight,
Openvswitch are not provided install them by:
::

 cd /opt/opnfv/
 fuel plugins --install fuel-plugin-ovs-*.noarch.rpm
 fuel plugins --install opendaylight-*.noarch.rpm

If plugins are installed and you want to update them use --force flag.

Note that One may inject other - Colorado compatible - plugins to the Fuel
Master host using the command scp:

scp <plugin>.rpm root@10.20.0.2:<plugin>.rpm

Now the feature can be configured. Create a new environment with
Networking Setup:"OpenDayLight with tunneling segmentation". Then go to
settings/other and check "OpenDaylight plugin, SFC enabled",
"Install Openvswitch with NSH/DPDK, with NSH enabled". During node provision
remember assign the OpenDayLight role to the (primary)controller

Now the deploy button on fuel dashboard can be used to deploy the environment.
