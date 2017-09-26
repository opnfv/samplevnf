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

version="17.09.03"
stack = "rapidTestEnv" #Default string for stack
yaml = "rapid.yaml" #Default string for yaml file
key = "prox" # This is also the default in the yaml file....
flavor = "prox_flavor" # This is also the default in the yaml file....
image = "rapidVM" # This is also the default in the yaml file....
image_file = "rapidVM.qcow2"
dataplane_network = "dataplane-network" # This is also the default in the yaml file....
subnet = "dpdk-subnet" #Hardcoded at this moment
subnet_cidr="10.10.10.0/24" # cidr for dataplane
admin_network="admin_internal_net"
loglevel="DEBUG" # sets log level for writing to file
runtime=10 # time in seconds for 1 test run

def usage():
	print("usage: rapid       [--version] [-v]")
	print("                   [--stack STACK_NAME]")
	print("                   [--yaml YAML_FILE]")
	print("                   [--key KEY_NAME]")
	print("                   [--flavor FLAVOR_NAME]")
	print("                   [--image IMAGE_NAME]")
	print("                   [--image_file IMAGE_FILE]")
	print("                   [--dataplane_network DP_NETWORK]")
	print("                   [--admin_network ADMIN_NETWORK]")
	print("                   [--log DEBUG|INFO|WARNING|ERROR|CRITICAL")
	print("                   [-h] [--help]")
	print("")
	print("Command-line interface to RAPID")
	print("")
	print("optional arguments:")
	print("  -v,  --version           	Show program's version number and exit")
	print("  --stack STACK_NAME       	Specify a name for the heat stack. Default is rapidTestEnv.")
	print("  --yaml YAML_FILE         	Specify the yaml file to be used. Default is rapid.yaml.")
	print("  --key KEY_NAME           	Specify the key to be used. Default is prox.")
	print("  --flavor FLAVOR_NAME     	Specify the flavor to be used. Default is prox_flavor.")
	print("  --image IMAGE_NAME       	Specify the image to be used. Default is rapidVM.")
	print("  --image_file IMAGE_FILE  	Specify the image qcow2 file to be used. Default is rapidVM.qcow2.")
	print("  --dataplane_network NETWORK 	Specify the network name to be used for the dataplane. Default is dataplane-network.")
	print("  --admin_network NETWORK 	Specify the network name to be used for the control plane. Default is admin-network.")
	print("  --log				Specify logging level for log file output, screen output level is hard coded")
	print("  -h, --help               	Show help message and exit.")
	print("")
	print("To delete the rapid stack, type the following command")
	print("   openstack stack delete --yes --wait rapidTestEnv")
	print("Note that rapidTestEnv is the default stack name. Replace with STACK_NAME if needed")

try:
	opts, args = getopt.getopt(sys.argv[1:], "vh", ["version","help", "yaml=","stack=","key=","flavor=","image=","dataplane_network=","admin_network=","log="])
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
	elif opt in ("--admin_network"):
		admin_network = arg
		print ("Using controle plane network: "+ admin_network)
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
log.debug("Checking control plane network: "+admin_network)
cmd = 'openstack network show '+admin_network
log.debug (cmd)
cmd = cmd + ' |grep "status " | tr -s " " | cut -d" " -f 4'
NetworkExist = subprocess.check_output(cmd , shell=True).strip()
if NetworkExist == 'ACTIVE':
	log.info("Control plane network ("+admin_network+")  already active")
else:
	log.exception("Control plane network " + admin_network + " not existing")
	raise Exception("Control plane network " + admin_network + " not existing")

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
	cmd = 'openstack stack create -t '+ yaml +  ' --parameter flavor="'+flavor  +'" --parameter key="'+ key + '" --parameter image="'+image  + '" --parameter dataplane_network="'+dataplane_network+ '" --parameter admin_network="'+admin_network+'" --wait '+stack
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
matchObj = re.search('.*gen_dataplane_ip.*?([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)', output, re.DOTALL)
genDPIP = matchObj.group(1)
matchObj = re.search('.*gen_public_ip.*?([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)', output, re.DOTALL)
genAdminIP = matchObj.group(1)
matchObj = re.search('.*gen_dataplane_mac.*?([a-fA-F0-9:]{17})', output, re.DOTALL)
genDPmac = matchObj.group(1)
matchObj = re.search('.*sut_dataplane_ip.*?([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)', output, re.DOTALL)
sutDPIP = matchObj.group(1)
matchObj = re.search('.*sut_public_ip.*?([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)', output, re.DOTALL)
sutAdminIP = matchObj.group(1)
matchObj = re.search('.*sut_dataplane_mac.*?([a-fA-F0-9:]{17})', output, re.DOTALL)
sutDPmac = matchObj.group(1)
log.info('Generator: (admin IP: '+ genAdminIP + '), (dataplane IP: ' + genDPIP+'), (dataplane MAC: ' +genDPmac+')')
log.info('SUT:       (admin IP: '+ sutAdminIP + '), (dataplane IP: ' + sutDPIP+'), (dataplane MAC: ' +sutDPmac+')')
config = ConfigParser.RawConfigParser()
config.add_section('Generator')
config.set('Generator', 'admin_ip', genAdminIP)
config.set('Generator', 'dp_ip', genDPIP)
config.set('Generator', 'dp_mac', genDPmac)
config.add_section('SUT')
config.set('SUT', 'admin_ip', sutAdminIP)
config.set('SUT', 'dp_ip', sutDPIP)
config.set('SUT', 'dp_mac', sutDPmac)
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
config.set('OpenStack', 'admin_network', admin_network)
config.add_section('rapid')
config.set('rapid', 'loglevel', loglevel)
config.set('rapid', 'version', version)
config.set('DEFAULT', 'admin_ip', 'none')
# Writing our configuration file
with open(stack+'.cfg', 'wb') as configfile:
    config.write(configfile)

