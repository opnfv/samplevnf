#!/usr/bin/python

##
## Copyright (c) 2010-2019 Intel Corporation
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##

from __future__ import print_function

import os
import stat
import sys
import time
import subprocess
import getopt
import re
import logging
from logging.handlers import RotatingFileHandler
from logging import handlers
from prox_ctrl import prox_ctrl
import ConfigParser

version="19.6.30"
stack = "rapid" #Default string for stack. This is not an OpenStack Heat stack, just a group of VMs
vms = "rapidVMs.vms" #Default string for vms file
key = "prox" # default name for key
image = "rapidVM" # default name for the image
image_file = "rapidVM.qcow2"
dataplane_network = "dataplane-network" # default name for the dataplane network
subnet = "dpdk-subnet" #subnet for dataplane
subnet_cidr="10.10.10.0/24" # cidr for dataplane
internal_network="admin_internal_net"
floating_network="admin_floating_net"
loglevel="DEBUG" # sets log level for writing to file

def usage():
	print("usage: createrapid [--version] [-v]")
	print("                   [--stack STACK_NAME]")
	print("                   [--vms VMS_FILE]")
	print("                   [--key KEY_NAME]")
	print("                   [--image IMAGE_NAME]")
	print("                   [--image_file IMAGE_FILE]")
	print("                   [--dataplane_network DP_NETWORK]")
	print("                   [--subnet DP_SUBNET]")
	print("                   [--subnet_cidr SUBNET_CIDR]")
	print("                   [--internal_network ADMIN_NETWORK]")
	print("                   [--floating_network FLOATING_NETWORK]")
	print("                   [--log DEBUG|INFO|WARNING|ERROR|CRITICAL]")
	print("                   [-h] [--help]")
	print("")
	print("Command-line interface to createrapid")
	print("")
	print("optional arguments:")
	print("  -v,  --version           	Show program's version number and exit")
	print("  --stack STACK_NAME       	Specify a name for the stack. Default is %s."%stack)
	print("  --vms VMS_FILE         	Specify the vms file to be used. Default is %s."%vms)
	print("  --key KEY_NAME           	Specify the key to be used. Default is %s."%key)
	print("  --image IMAGE_NAME       	Specify the image to be used. Default is %s."%image)
	print("  --image_file IMAGE_FILE  	Specify the image qcow2 file to be used. Default is %s."%image_file)
	print("  --dataplane_network NETWORK 	Specify the network name to be used for the dataplane. Default is %s."%dataplane_network)
	print("  --subnet DP_SUBNET	 	Specify the subnet name to be used for the dataplane. Default is %s."%subnet)
	print("  --subnet_cidr SUBNET_CIDR  	Specify the subnet CIDR to be used for the dataplane. Default is %s."%subnet_cidr)
	print("  --internal_network NETWORK 	Specify the network name to be used for the control plane. Default is %s."%internal_network)
	print("  --floating_network NETWORK 	Specify the external floating ip network name. Default is %s. NO if no floating ip used."%floating_network)
	print("  --log				Specify logging level for log file output, screen output level is hard coded")
	print("  -h, --help               	Show help message and exit.")
	print("")

try:
	opts, args = getopt.getopt(sys.argv[1:], "vh", ["version","help", "vms=","stack=","key=","image=","image_file=","dataplane_network=","subnet=","subnet_cidr=","internal_network=","floating_network=","log="])
except getopt.GetoptError as err:
	print("===========================================")
	print(str(err))
	print("===========================================")
	usage()
	sys.exit(2)
if args:
	usage()
	sys.exit(2)
for opt, arg in opts:
	if opt in ["-h", "--help"]:
		usage()
		sys.exit()
	if opt in ["-v", "--version"]:
		print("Rapid Automated Performance Indication for Dataplane "+version)
		sys.exit()
	if opt in ["--stack"]:
		stack = arg
		print ("Using '"+stack+"' as name for the stack")
	elif opt in ["--vms"]:
		vms = arg
		print ("Using Virtual Machines Description: "+vms)
	elif opt in ["--key"]:
		key = arg
		print ("Using key: "+key)
	elif opt in ["--image"]:
		image = arg
		print ("Using image: "+image)
	elif opt in ["--image_file"]:
		image_file = arg
		print ("Using qcow2 file: "+image_file)
	elif opt in ["--dataplane_network"]:
		dataplane_network = arg
		print ("Using dataplane network: "+ dataplane_network)
	elif opt in ["--subnet"]:
		subnet = arg
		print ("Using dataplane subnet: "+ subnet)
	elif opt in ["--subnet_cidr"]:
		subnet_cidr = arg
		print ("Using dataplane subnet: "+ subnet_cidr)
	elif opt in ["--internal_network"]:
		internal_network = arg
		print ("Using control plane network: "+ internal_network)
	elif opt in ["--floating_network"]:
		floating_network = arg
		print ("Using floating ip network: "+ floating_network)
	elif opt in ["--log"]:
		loglevel = arg
		print ("Log level: "+ loglevel)


# create formatters
screen_formatter = logging.Formatter("%(message)s")
file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

# get a top-level logger,
# set its log level,
# BUT PREVENT IT from propagating messages to the root logger
#
log = logging.getLogger()
numeric_level = getattr(logging, loglevel.upper(), None)
if not isinstance(numeric_level, int):
	raise ValueError('Invalid log level: %s' % loglevel)
log.setLevel(numeric_level)
log.propagate = 0

# create a console handler
# and set its log level to the command-line option 
# 
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(screen_formatter)

# create a file handler
# and set its log level to DEBUG
#
log_file = 'CREATE' +stack +'.log'
file_handler = logging.handlers.RotatingFileHandler(log_file, backupCount=10)
#file_handler = log.handlers.TimedRotatingFileHandler(log_file, 'D', 1, 5)
file_handler.setLevel(numeric_level)
file_handler.setFormatter(file_formatter)

# add handlers to the logger
#
log.addHandler(file_handler)
log.addHandler(console_handler)

# Check if log exists and should therefore be rolled
needRoll = os.path.isfile(log_file)


# This is a stale log, so roll it
if needRoll:    
	# Add timestamp
	log.debug('\n---------\nLog closed on %s.\n---------\n' % time.asctime())
	# Roll over on application start
	log.handlers[0].doRollover()

# Add timestamp
log.debug('\n---------\nLog started on %s.\n---------\n' % time.asctime())

log.debug("createrapid.py version: "+version)
# Checking if the control network already exists, if not, stop the script
log.debug("Checking control plane network: " + internal_network)
cmd = 'openstack network list -f value -c Name'
log.debug (cmd)
Networks = subprocess.check_output(cmd , shell=True).decode().strip()
if internal_network in Networks:
	log.info("Control plane network (" + internal_network+")  already active")
else:
	log.exception("Control plane network " + internal_network + " not existing")
	raise Exception("Control plane network " + internal_network + " not existing")

# Checking if the floating ip network should be used. If yes, check if it exists and stop the script if it doesn't
if floating_network !='NO':
	log.debug("Checking floating ip network: " + floating_network)
	if floating_network in Networks:
		log.info("Floating ip network (" + floating_network + ")  already active")
	else:
		log.exception("Floating ip network " + floating_network + " not existing")
		raise Exception("Floating ip network " + floating_network + " not existing")

# Checking if the dataplane network already exists, if not create it
log.debug("Checking dataplane network: " + dataplane_network)
if dataplane_network in Networks:
	# If the dataplane already exists, we are assuming that this network is already created before with the proper configuration, hence we do not check if the subnet is created etc...
	log.info("Dataplane network (" + dataplane_network + ") already active")
else:
	log.info('Creating dataplane network ...')
	cmd = 'openstack network create '+dataplane_network+' -f value -c status'
	log.debug(cmd)
	NetworkExist = subprocess.check_output(cmd , shell=True).decode().strip()
	if 'ACTIVE' in NetworkExist:
		log.info("Dataplane network created")
		# Checking if the dataplane subnet already exists, if not create it
		log.debug("Checking subnet: "+subnet)
		cmd = 'openstack subnet list -f value -c Name'
		log.debug (cmd)
		Subnets = subprocess.check_output(cmd , shell=True).decode().strip()
		if subnet in  Subnets:
			log.info("Subnet (" +subnet+ ") already exists")
		else:
			log.info('Creating subnet ...')
			cmd = 'openstack subnet create --network ' + dataplane_network + ' --subnet-range ' + subnet_cidr +' --gateway none ' + subnet+' -f value -c name'
			log.debug(cmd)
			Subnets = subprocess.check_output(cmd , shell=True).decode().strip()
			if subnet in Subnets:
				log.info("Subnet created")
			else :
				log.exception("Failed to create subnet: " + subnet)
				raise Exception("Failed to create subnet: " + subnet)
	else :
		log.exception("Failed to create dataplane network: " + dataplane_network)
		raise Exception("Failed to create dataplane network: " + dataplane_network)

# Checking if the image already exists, if not create it
log.debug("Checking image: " + image)
cmd = 'openstack image list -f value -c Name'
log.debug(cmd)
Images = subprocess.check_output(cmd , shell=True).decode().strip()
if image in Images:
	log.info("Image (" + image + ") already available")
else:
	log.info('Creating image ...')
	cmd = 'openstack image create  -f value -c status --disk-format qcow2 --container-format bare --public --file ./'+image_file+ ' ' +image
	log.debug(cmd)
	ImageExist = subprocess.check_output(cmd , shell=True).decode().strip()
	if 'active' in ImageExist:
		log.info('Image created and active')
#		cmd = 'openstack image set --property hw_vif_multiqueue_enabled="true" ' +image
#		subprocess.check_call(cmd , shell=True)
	else :
		log.exception("Failed to create image")
		raise Exception("Failed to create image")

# Checking if the key already exists, if not create it
log.debug("Checking key: "+key)
cmd = 'openstack keypair list -f value -c Name'
log.debug (cmd)
KeyExist = subprocess.check_output(cmd , shell=True).decode().strip()
if key in KeyExist:
	log.info("Key ("+key+") already installed")
else:
	log.info('Creating key ...')
	cmd = 'openstack keypair create '+ key + '>' +key+'.pem'
	log.debug(cmd)
	subprocess.check_call(cmd , shell=True)
	cmd = 'chmod 600 ' +key+'.pem'
	subprocess.check_call(cmd , shell=True)
	cmd = 'openstack keypair list -f value -c Name'
	log.debug(cmd)
	KeyExist = subprocess.check_output(cmd , shell=True).decode().strip()
	if key in KeyExist:
		log.info("Key created")
	else :
		log.exception("Failed to create key: " + key)
		raise Exception("Failed to create key: " + key)

ServerToBeCreated=[]
ServerName=[]
config = ConfigParser.RawConfigParser()
vmconfig = ConfigParser.RawConfigParser()
vmname = os.path.dirname(os.path.realpath(__file__))+'/' + vms
#vmconfig.read_file(open(vmname))
vmconfig.readfp(open(vmname))
total_number_of_VMs = vmconfig.get('DEFAULT', 'total_number_of_vms')
cmd = 'openstack server list -f value -c Name'
log.debug (cmd)
Servers = subprocess.check_output(cmd , shell=True).decode().strip()
cmd = 'openstack flavor list -f value -c Name'
log.debug (cmd)
Flavors = subprocess.check_output(cmd , shell=True).decode().strip()
for vm in range(1, int(total_number_of_VMs)+1):
	flavor_info = vmconfig.get('VM%d'%vm, 'flavor_info')
	flavor_meta_data = vmconfig.get('VM%d'%vm, 'flavor_meta_data')
	boot_info = vmconfig.get('VM%d'%vm, 'boot_info')
	SRIOV_port = vmconfig.get('VM%d'%vm, 'SRIOV_port')
	SRIOV_mgmt_port = vmconfig.get('VM%d'%vm, 'SRIOV_mgmt_port')
	ServerName.append('%s-VM%d'%(stack,vm))
	flavor_name = '%s-VM%d-flavor'%(stack,vm)
	log.debug("Checking server: " + ServerName[-1])
	if ServerName[-1] in Servers:
		log.info("Server (" + ServerName[-1] + ") already active")
		ServerToBeCreated.append("no")
	else:
		ServerToBeCreated.append("yes")
		# Checking if the flavor already exists, if not create it
		log.debug("Checking flavor: " + flavor_name)
		if flavor_name in Flavors:
			log.info("Flavor (" + flavor_name+") already installed")
		else:
			log.info('Creating flavor ...')
			cmd = 'openstack flavor create %s %s -f value -c name'%(flavor_name,flavor_info)
			log.debug(cmd)
			NewFlavor = subprocess.check_output(cmd , shell=True).decode().strip()
			if flavor_name in NewFlavor:
				cmd = 'openstack flavor set %s %s'%(flavor_name, flavor_meta_data)
				log.debug(cmd)
				subprocess.check_call(cmd , shell=True)
				log.info("Flavor created")
			else :
				log.exception("Failed to create flavor: " + flavor_name)
				raise Exception("Failed to create flavor: " + flavor_name)
		if SRIOV_mgmt_port == 'NO':
			nic_info = '--nic net-id=%s'%(internal_network)
		else:
			nic_info = '--nic port-id=%s'%(SRIOV_mgmt_port)
		if SRIOV_port == 'NO':
			nic_info = nic_info + ' --nic net-id=%s'%(dataplane_network)
		else:
			for port in SRIOV_port.split(','):
				nic_info = nic_info + ' --nic port-id=%s'%(port)
		if vm==int(total_number_of_VMs):
			# For the last server, we want to wait for the server creation to complete, so the next operations will succeeed (e.g. IP allocation)
			# Note that this waiting is not bullet proof. Imagine, we loop through all the VMs, and the last VM was already running, while the previous
			# VMs still needed to be created. Or the previous server creations take much longer than the last one.
			# In that case, we might be too fast when we query for the IP & MAC addresses.
			wait = '--wait'
		else:
			wait = ''
		log.info("Creating server...")
		cmd = 'openstack server create --flavor %s --key-name %s --image %s %s %s %s %s'%(flavor_name,key,image,nic_info,boot_info,wait,ServerName[-1])
		log.debug(cmd)
		output = subprocess.check_output(cmd , shell=True).decode().strip()
if floating_network != 'NO':
	for vm in range(0, int(total_number_of_VMs)):
		if ServerToBeCreated[vm] =="yes":
			log.info('Creating & Associating floating IP for ('+ServerName[vm]+')...')
			cmd = 'openstack server show %s -c addresses -f value |grep -Eo "%s=[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | cut -d"=" -f2'%(ServerName[vm],internal_network)
			log.debug(cmd)
			vmportIP = subprocess.check_output(cmd , shell=True).decode().strip()
			cmd = 'openstack port list -c ID -c "Fixed IP Addresses" | grep %s  | cut -d" " -f 2 ' %(vmportIP)
			log.debug(cmd)
			vmportID = subprocess.check_output(cmd , shell=True).decode().strip()
			cmd = 'openstack floating ip create --port %s %s'%(vmportID,floating_network)
			log.debug(cmd)
			output = subprocess.check_output(cmd , shell=True).decode().strip()

config.add_section('rapid')
config.set('rapid', 'loglevel', loglevel)
config.set('rapid', 'version', version)
config.set('rapid', 'total_number_of_machines', total_number_of_VMs)
for vm in range(1, int(total_number_of_VMs)+1):
	cmd = 'openstack server show %s'%(ServerName[vm-1])
	log.debug(cmd)
	output = subprocess.check_output(cmd , shell=True).decode().strip()
	searchString = '.*%s=([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)' %(dataplane_network)
	matchObj = re.search(searchString, output, re.DOTALL)
	vmDPIP = matchObj.group(1)
	searchString = '.*%s=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+),*\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)*' %(internal_network)
	matchObj = re.search(searchString, output, re.DOTALL)
	vmAdminIP = matchObj.group(2)
	if vmAdminIP == None:
		vmAdminIP = matchObj.group(1)
	cmd = 'openstack port list |egrep  "\\b%s\\b" | tr -s " " | cut -d"|" -f 4'%(vmDPIP)
	log.debug(cmd)
	vmDPmac = subprocess.check_output(cmd , shell=True).decode().strip()
	config.add_section('M%d'%vm)
	config.set('M%d'%vm, 'name', ServerName[vm-1])
	config.set('M%d'%vm, 'admin_ip', vmAdminIP)
	config.set('M%d'%vm, 'dp_ip', vmDPIP)
	config.set('M%d'%vm, 'dp_mac', vmDPmac)
	log.info('%s: (admin IP: %s), (dataplane IP: %s), (dataplane MAC: %s)' % (ServerName[vm-1],vmAdminIP,vmDPIP,vmDPmac))

config.add_section('ssh')
config.set('ssh', 'key', key)
config.add_section('Varia')
config.set('Varia', 'VIM', 'OpenStack')
config.set('Varia', 'stack', stack)
config.set('Varia', 'VMs', vms)
config.set('Varia', 'image', image)
config.set('Varia', 'image_file', image_file)
config.set('Varia', 'dataplane_network', dataplane_network)
config.set('Varia', 'subnet', subnet)
config.set('Varia', 'subnet_cidr', subnet_cidr)
config.set('Varia', 'internal_network', internal_network)
config.set('Varia', 'floating_network', floating_network)
# Writing the environment file
with open(stack+'.env', 'wb') as envfile:
	config.write(envfile)
