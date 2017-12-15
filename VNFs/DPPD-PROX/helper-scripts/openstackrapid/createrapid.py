#!/usr/bin/python

##
## Copyright (c) 2010-2017 Intel Corporation
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

version="17.12.15"
stack = "rapid" #Default string for stack
yaml = "rapid.yaml" #Default string for yaml file
key = "prox" # This is also the default in the yaml file....
flavor = "prox_flavor" # This is also the default in the yaml file....
image = "rapidVM" # This is also the default in the yaml file....
image_file = "rapidVM.qcow2"
dataplane_network = "dataplane-network" # This is also the default in the yaml file....
subnet = "dpdk-subnet" #Hardcoded at this moment
subnet_cidr="10.10.10.0/24" # cidr for dataplane
internal_network="admin_internal_net"
floating_network="admin_floating_net"
loglevel="DEBUG" # sets log level for writing to file
runtime=10 # time in seconds for 1 test run

def usage():
	print("usage: createrapid [--version] [-v]")
	print("                   [--stack STACK_NAME]")
	print("                   [--yaml YAML_FILE]")
	print("                   [--key KEY_NAME]")
	print("                   [--flavor FLAVOR_NAME]")
	print("                   [--image IMAGE_NAME]")
	print("                   [--image_file IMAGE_FILE]")
	print("                   [--dataplane_network DP_NETWORK]")
	print("                   [--subnet DP_SUBNET]")
	print("                   [--subnet_cidr SUBNET_CIDR]")
	print("                   [--internal_network ADMIN_NETWORK]")
	print("                   [--floating_network ADMIN_NETWORK]")
	print("                   [--log DEBUG|INFO|WARNING|ERROR|CRITICAL")
	print("                   [-h] [--help]")
	print("")
	print("Command-line interface to createrapid")
	print("")
	print("optional arguments:")
	print("  -v,  --version           	Show program's version number and exit")
	print("  --stack STACK_NAME       	Specify a name for the heat stack. Default is %s."%stack)
	print("  --yaml YAML_FILE         	Specify the yaml file to be used. Default is %s."%yaml)
	print("  --key KEY_NAME           	Specify the key to be used. Default is %s."%key)
	print("  --flavor FLAVOR_NAME     	Specify the flavor to be used. Default is %s."%flavor)
	print("  --image IMAGE_NAME       	Specify the image to be used. Default is %s."%image)
	print("  --image_file IMAGE_FILE  	Specify the image qcow2 file to be used. Default is %s."%image_file)
	print("  --dataplane_network NETWORK 	Specify the network name to be used for the dataplane. Default is %s."%dataplane_network)
	print("  --subnet DP_SUBNET	 	Specify the subnet name to be used for the dataplane. Default is %s."%subnet)
	print("  --subnet_cidr SUBNET_CIDR  	Specify the subnet CIDR to be used for the dataplane. Default is %s."%subnet_cidr)
	print("  --internal_network NETWORK 	Specify the network name to be used for the control plane. Default is %s."%internal_network)
	print("  --floating_network NETWORK 	Specify the external floating ip network name. Default is %s."%floating_network)
	print("  --log				Specify logging level for log file output, screen output level is hard coded")
	print("  -h, --help               	Show help message and exit.")
	print("")
	print("To delete the rapid stack, type the following command")
	print("   openstack stack delete --yes --wait %s"%stack)
	print("Note that %s is the default stack name. Replace with STACK_NAME if needed"%stack)

try:
	opts, args = getopt.getopt(sys.argv[1:], "vh", ["version","help", "yaml=","stack=","key=","flavor=","image=","image_file=","dataplane_network=","subnet=","subnet_cidr=","internal_network=","floating_network=","log="])
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
	if opt in ("-h", "--help"):
		usage()
		sys.exit()
	if opt in ("-v", "--version"):
		print("Rapid Automated Performance Indication for Dataplane "+version)
		sys.exit()
	if opt in ("--stack"):
		stack = arg
		print ("Using '"+stack+"' as name for the stack")
	elif opt in ("--yaml"):
		yaml = arg
		print ("Using stack: "+yaml)
	elif opt in ("--key"):
		key = arg
		print ("Using key: "+key)
	elif opt in ("--flavor"):
		flavor = arg
		print ("Using flavor: "+flavor)
	elif opt in ("--image"):
		image = arg
		print ("Using image: "+image)
	elif opt in ("--image_file"):
		image_file = arg
		print ("Using qcow2 file: "+image_file)
	elif opt in ("--dataplane_network"):
		dataplane_network = arg
		print ("Using dataplane network: "+ dataplane_network)
	elif opt in ("--subnet"):
		subnet = arg
		print ("Using dataplane subnet: "+ subnet)
	elif opt in ("--subnet_cidr"):
		subnet_cidr = arg
		print ("Using dataplane subnet: "+ subnet_cidr)
	elif opt in ("--internal_network"):
		internal_network = arg
		print ("Using controle plane network: "+ internal_network)
	elif opt in ("--floating_network"):
		floating_network = arg
		print ("Using floating ip network: "+ floating_network)
	elif opt in ("--log"):
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
log.debug("Checking control plane network: "+internal_network)
cmd = 'openstack network show '+internal_network
log.debug (cmd)
cmd = cmd + ' |grep "status " | tr -s " " | cut -d" " -f 4'
NetworkExist = subprocess.check_output(cmd , shell=True).strip()
if NetworkExist == 'ACTIVE':
	log.info("Control plane network ("+internal_network+")  already active")
else:
	log.exception("Control plane network " + internal_network + " not existing")
	raise Exception("Control plane network " + internal_network + " not existing")

# Checking if the floating ip network already exists, if not, stop the script
log.debug("Checking floating ip network: "+floating_network)
cmd = 'openstack network show '+floating_network
log.debug (cmd)
cmd = cmd + ' |grep "status " | tr -s " " | cut -d" " -f 4'
NetworkExist = subprocess.check_output(cmd , shell=True).strip()
if NetworkExist == 'ACTIVE':
	log.info("Floating ip network ("+floating_network+")  already active")
else:
	log.exception("Floating ip network " + floating_network + " not existing")
	raise Exception("Floating ip network " + floating_network + " not existing")

# Checking if the image already exists, if not create it
log.debug("Checking image: "+image)
cmd = 'openstack image show '+image
log.debug(cmd)
cmd = cmd +' |grep "status " | tr -s " " | cut -d" " -f 4'
ImageExist = subprocess.check_output(cmd , shell=True).strip()
if ImageExist == 'active':
	log.info("Image ("+image+") already available")
else:
	log.info('Creating image ...')
	cmd = 'openstack image create --disk-format qcow2 --container-format bare --public --file ./'+image_file+ ' ' +image
	log.debug(cmd)
	cmd = cmd + ' |grep "status " | tr -s " " | cut -d" " -f 4'
	ImageExist = subprocess.check_output(cmd , shell=True).strip()
	if ImageExist == 'active':
		log.info('Image created and active')
		cmd = 'openstack image set --property hw_vif_multiqueue_enabled="true" ' +image
#		subprocess.check_call(cmd , shell=True)
	else :
		log.exception("Failed to create image")
		raise Exception("Failed to create image")

# Checking if the key already exists, if not create it
log.debug("Checking key: "+key)
cmd = 'openstack keypair show '+key
log.debug (cmd)
cmd = cmd + ' |grep "name " | tr -s " " | cut -d" " -f 4'
KeyExist = subprocess.check_output(cmd , shell=True).strip()
if KeyExist == key:
	log.info("Key ("+key+") already installed")
else:
	log.info('Creating key ...')
	cmd = 'openstack keypair create '+ key + '>' +key+'.pem'
	log.debug(cmd)
	subprocess.check_call(cmd , shell=True)
	cmd = 'chmod 600 ' +key+'.pem'
	subprocess.check_call(cmd , shell=True)
	cmd = 'openstack keypair show '+key
	log.debug(cmd)
	cmd = cmd + ' |grep "name " | tr -s " " | cut -d" " -f 4'
	KeyExist = subprocess.check_output(cmd , shell=True).strip()
	if KeyExist == key:
		log.info("Key created")
	else :
		log.exception("Failed to create key: " + key)
		raise Exception("Failed to create key: " + key)

# Checking if the flavor already exists, if not create it
log.debug("Checking flavor: "+flavor)
cmd = 'openstack flavor show '+flavor
log.debug (cmd)
cmd = cmd + ' |grep "name " | tr -s " " | cut -d" " -f 4'
FlavorExist = subprocess.check_output(cmd , shell=True).strip()
if FlavorExist == flavor:
	log.info("Flavor ("+flavor+") already installed")
else:
	log.info('Creating flavor ...')
	cmd = 'openstack flavor create '+flavor+' --ram 8192 --disk 20 --vcpus 4'
	log.debug(cmd)
	cmd = cmd + ' |grep "name " | tr -s " " | cut -d" " -f 4'
	FlavorExist = subprocess.check_output(cmd , shell=True).strip()
	if FlavorExist == flavor:
		cmd = 'openstack flavor set '+ flavor +' --property hw:mem_page_size="large" --property hw:cpu_policy="dedicated" --property hw:cpu_threads_policy="isolate"'
		log.debug(cmd)
		subprocess.check_call(cmd , shell=True)
		log.info("Flavor created")
	else :
		log.exception("Failed to create flavor: " + flavor)
		raise Exception("Failed to create flavor: " + flavor)

# Checking if the dataplane network already exists, if not create it
log.debug("Checking dataplane network: "+dataplane_network)
cmd = 'openstack network show '+dataplane_network
log.debug (cmd)
cmd = cmd + ' |grep "status " | tr -s " " | cut -d" " -f 4'
NetworkExist = subprocess.check_output(cmd , shell=True).strip()
if NetworkExist == 'ACTIVE':
	log.info("Dataplane network ("+dataplane_network+") already active")
else:
	log.info('Creating dataplane network ...')
	cmd = 'openstack network create '+dataplane_network
	log.debug(cmd)
	cmd = cmd + ' |grep "status " | tr -s " " | cut -d" " -f 4'
	NetworkExist = subprocess.check_output(cmd , shell=True).strip()
	if NetworkExist == 'ACTIVE':
		log.info("Dataplane network created")
	else :
		log.exception("Failed to create dataplane network: " + dataplane_network)
		raise Exception("Failed to create dataplane network: " + dataplane_network)

# Checking if the dataplane subnet already exists, if not create it
log.debug("Checking subnet: "+subnet)
cmd = 'openstack subnet show '+ subnet
log.debug (cmd)
cmd = cmd +' |grep "name " | tr -s " " | cut -d"|" -f 3'
SubnetExist = subprocess.check_output(cmd , shell=True).strip()
if SubnetExist == subnet:
	log.info("Subnet (" +subnet+ ") already exists")
else:
	log.info('Creating subnet ...')
	cmd = 'openstack subnet create --network ' + dataplane_network + ' --subnet-range ' + subnet_cidr +' --gateway none ' + subnet
	log.debug(cmd)
	cmd = cmd + ' |grep "name " | tr -s " " | cut -d"|" -f 3'
	SubnetExist = subprocess.check_output(cmd , shell=True).strip()
	if SubnetExist == subnet:
		log.info("Subnet created")
	else :
		log.exception("Failed to create subnet: " + subnet)
		raise Exception("Failed to create subnet: " + subnet)

# Checking if the stack already exists, if not create it
log.debug("Checking Stack: "+stack)
cmd = 'openstack stack show '+stack
log.debug (cmd)
cmd = cmd+' |grep "stack_status " | tr -s " " | cut -d"|" -f 3'
StackRunning = subprocess.check_output(cmd , shell=True).strip()
if StackRunning == '':
	log.info('Creating Stack ...')
	cmd = 'openstack stack create -t '+ yaml +  ' --parameter flavor="'+flavor  +'" --parameter key="'+ key + '" --parameter image="'+image  + '" --parameter dataplane_network="'+dataplane_network+ '" --parameter internal_network="'+internal_network+'" --parameter floating_network="'+floating_network+'" --wait '+stack 
	log.debug(cmd)
	cmd = cmd + ' |grep "stack_status " | tr -s " " | cut -d"|" -f 3'
	StackRunning = subprocess.check_output(cmd , shell=True).strip()
if StackRunning != 'CREATE_COMPLETE':
	log.exception("Failed to create stack")
	raise Exception("Failed to create stack")

# Obtaining IP & MAC addresses for the VMs created in the stack
log.info("Stack ("+stack+") running")
cmd='openstack stack show -f yaml -c outputs ' + stack
log.debug(cmd)
output = subprocess.check_output(cmd , shell=True).strip()
matchObj = re.search('.*total_number_of_VMs.*?([0-9])', output, re.DOTALL)
total_number_of_VMs = matchObj.group(1)
vmDPIP =[]
vmAdminIP =[]
vmDPmac =[]
config = ConfigParser.RawConfigParser()
for vm in range(1, int(total_number_of_VMs)+1):
	searchString = '.*vm%d_dataplane_ip.*?([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)' % vm
	matchObj = re.search(searchString, output, re.DOTALL)
	vmDPIP.append(matchObj.group(1))
	searchString = '.*vm%d_public_ip.*?([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)' % vm
	matchObj = re.search(searchString, output, re.DOTALL)
	vmAdminIP.append(matchObj.group(1))
	searchString = '.*vm%d_dataplane_mac.*?([a-fA-F0-9:]{17})' % vm
	matchObj = re.search(searchString, output, re.DOTALL)
	vmDPmac.append(matchObj.group(1))
	log.info('VM%d: (admin IP: %s), (dataplane IP: %s), (dataplane MAC: %s)' % (vm,vmAdminIP[-1],vmDPIP[-1],vmDPmac[-1]))
	config.add_section('VM%d'%vm)
	config.set('VM%d'%vm, 'admin_ip', vmAdminIP[-1])
	config.set('VM%d'%vm, 'dp_ip', vmDPIP[-1])
	config.set('VM%d'%vm, 'dp_mac', vmDPmac[-1])
config.add_section('OpenStack')
config.set('OpenStack', 'stack', stack)
config.set('OpenStack', 'yaml', yaml)
config.set('OpenStack', 'key', key)
config.set('OpenStack', 'flavor', flavor)
config.set('OpenStack', 'image', image)
config.set('OpenStack', 'image_file', image_file)
config.set('OpenStack', 'dataplane_network', dataplane_network)
config.set('OpenStack', 'subnet', subnet)
config.set('OpenStack', 'subnet_cidr', subnet_cidr)
config.set('OpenStack', 'internal_network', internal_network)
config.set('OpenStack', 'floating_network', floating_network)
config.add_section('rapid')
config.set('rapid', 'loglevel', loglevel)
config.set('rapid', 'version', version)
config.set('rapid', 'total_number_of_VMs', total_number_of_VMs)
config.set('DEFAULT', 'admin_ip', 'none')
# Writing the environment file
with open(stack+'.env', 'wb') as envfile:
    config.write(envfile)

