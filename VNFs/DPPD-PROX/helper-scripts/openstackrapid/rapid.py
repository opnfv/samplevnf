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

import sys
import time
import subprocess
import getopt
from prox_ctrl import prox_ctrl

version="17.04.19"
stack = "rapidTestEnv" #Default string for stack
yaml = "rapid.yaml" #Default string for yaml file
key = "prox" # This is also the default in the yaml file....
flavor = "prox_flavor" # This is also the default in the yaml file....
image = "rapidVM" # This is also the default in the yaml file....
image_file = "rapidVM.qcow2"
network = "dpdk-network" # This is also the default in the yaml file....
subnet = "dpdk-subnet" #Hardcoded at this moment

def usage():
	print("usage: rapid       [--version] [-v]")
	print("                   [--stack STACK_NAME]")
	print("                   [--yaml YAML_FILE]")
	print("                   [--key KEY_NAME]")
	print("                   [--flavor FLAVOR_NAME]")
	print("                   [--image IMAGE_NAME]")
	print("                   [--image_file IMAGE_FILE]")
	print("                   [--network NETWORK]")
	print("                   [-h] [--help]")
	print("")
	print("Command-line interface to RAPID")
	print("")
	print("optional arguments:")
	print("  -v,  --version           Show program's version number and exit")
	print("  --stack STACK_NAME       Specify a name for the heat stack. Default is rapidTestEnv.")
	print("  --yaml YAML_FILE         Specify the yaml file to be used. Default is rapid.yaml.")
	print("  --key KEY_NAME           Specify the key to be used. Default is prox.")
	print("  --flavor FLAVOR_NAME     Specify the flavor to be used. Default is prox_flavor.")
	print("  --image IMAGE_NAME       Specify the image to be used. Default is rapidVM.")
	print("  --image_file IMAGE_FILE  Specify the image qcow2 file to be used. Default is rapidVM.qcow2.")
	print("  --network NETWORK        Specify the network name to be used for the dataplane. Default is dpdk-network.")
	print("  -h, --help               Show help message and exit.")
	print("")
	print("To delete the rapid stack, type the following command")
	print("   openstack stack delete --yes --wait DPTestEnv")
	print("Note that rapidTestEnv is the default stack name. Replace with STACK_NAME if needed")

try:
	opts, args = getopt.getopt(sys.argv[1:], "vh", ["version","help", "yaml=","stack=","key=","flavor=","image=","network="])
except getopt.GetoptError as err:
	print("===========================================")
	print str(err)
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
	elif opt in ("--network"):
		network = arg
		print ("Using network: "+ network)

print("Checking image: "+image)
cmd = 'openstack image show '+image+' |grep "status " | tr -s " " | cut -d" " -f 4'
ImageExist = subprocess.check_output(cmd , shell=True).strip()
if ImageExist == 'active':
	print("Image already available")
else:
	print('Creating image ...')
	cmd = 'openstack image create --disk-format qcow2 --container-format bare --public --file ./'+image_file+ ' ' +image+' |grep "status " | tr -s " " | cut -d" " -f 4'
	ImageExist = subprocess.check_output(cmd , shell=True).strip()
	if ImageExist == 'active':
		print('Image created and active')
		cmd = 'openstack image set --property hw_vif_multiqueue_enabled="true" ' +image
		subprocess.check_call(cmd , shell=True)
	else :
		raise Exception("Failed to create image")

print("Checking key: "+key)
cmd = 'openstack keypair show '+key+' |grep "name " | tr -s " " | cut -d" " -f 4'
KeyExist = subprocess.check_output(cmd , shell=True).strip()
if KeyExist == key:
	print("Key already installed")
else:
	print('Creating key ...')
	cmd = 'openstack keypair create '+ key + '>' +key+'.pem'
	subprocess.check_call(cmd , shell=True)
	cmd = 'chmod 600 ' +key+'.pem'
	subprocess.check_call(cmd , shell=True)
	cmd = 'openstack keypair show '+key+' |grep "name " | tr -s " " | cut -d" " -f 4'
	KeyExist = subprocess.check_output(cmd , shell=True).strip()
	if KeyExist == key:
		print("Key created")
	else :
		raise Exception("Failed to create key: " + key)

print("Checking flavor: "+flavor)
cmd = 'openstack flavor show '+flavor+' |grep "name " | tr -s " " | cut -d" " -f 4'
FlavorExist = subprocess.check_output(cmd , shell=True).strip()
if FlavorExist == flavor:
	print("Flavor already installed")
else:
	print('Creating flavor ...')
	cmd = 'openstack flavor create '+flavor+' --ram 8192 --disk 80 --vcpus 4 |grep "name " | tr -s " " | cut -d" " -f 4'
	FlavorExist = subprocess.check_output(cmd , shell=True).strip()
	if FlavorExist == flavor:
		cmd = 'openstack flavor set '+ flavor +' --property hw:mem_page_size="large" --property hw:cpu_policy="dedicated" --property hw:cpu_threads_policy="isolate"'
		subprocess.check_call(cmd , shell=True)
		print("Flavor created")
	else :
		raise Exception("Failed to create flavor: " + flavor)

print("Checking network: "+network)
cmd = 'openstack network show '+network+' |grep "status " | tr -s " " | cut -d" " -f 4'
NetworkExist = subprocess.check_output(cmd , shell=True).strip()
if NetworkExist == 'ACTIVE':
	print("Network already active")
else:
	print('Creating network ...')
	cmd = 'openstack network create '+network+' |grep "status " | tr -s " " | cut -d" " -f 4'
	NetworkExist = subprocess.check_output(cmd , shell=True).strip()
	if NetworkExist == 'ACTIVE':
		print("Network created")
	else :
		raise Exception("Failed to create network: " + network)

print("Checking subnet: "+subnet)
cmd = 'neutron subnet-show '+ subnet+' |grep "name " | tr -s " " | cut -d" " -f 4'
SubnetExist = subprocess.check_output(cmd , shell=True).strip()
if SubnetExist == subnet:
	print("Subnet already exists")
else:
	print('Creating subnet ...')
	cmd = 'neutron subnet-create --name '+ subnet+ ' ' +network+' 10.10.10.0/24 |grep "name " | tr -s " " | cut -d" " -f 4'
	SubnetExist = subprocess.check_output(cmd , shell=True).strip()
	if SubnetExist == subnet:
		print("Subnet created")
	else :
		raise Exception("Failed to create subnet: " + subnet)

print("Checking Stack: "+stack)
cmd = 'openstack stack show '+stack+' |grep "stack_status " | tr -s " " | cut -d" " -f 4'
StackRunning = subprocess.check_output(cmd , shell=True).strip()
if StackRunning == '':
	print('Creating Stack ...')
	cmd = 'openstack stack create -t '+ yaml +  ' --parameter flavor="'+flavor  +'" --parameter key="'+ key + '" --parameter image="'+image  + '" --parameter dpdk_network="'+network+'" --wait '+stack +' |grep "stack_status " | tr -s " " | cut -d" " -f 4'
	StackRunning = subprocess.check_output(cmd , shell=True).strip()
if StackRunning != 'CREATE_COMPLETE':
	raise Exception("Failed to create stack")

print('Stack running')
genName=stack+'-gen'
sutName=stack+'-sut'
cmd = 'nova list | grep  '+ genName +' | tr -s " " | cut -d " " -f 4'
genVMName = subprocess.check_output(cmd , shell=True).strip()
print('Generator: '+ genVMName)
cmd = 'nova list | grep  '+ sutName +' | tr -s " " | cut -d " " -f 4'
sutVMName = subprocess.check_output(cmd , shell=True).strip()
print('SUT:       '+ sutVMName)
cmd='nova show ' + genVMName + ' | grep "dpdk-network" | tr -s " " | cut -d" " -f 5'
genDPIP = subprocess.check_output(cmd , shell=True).strip()
cmd='nova show ' + genVMName + ' | grep "admin_internal_net" | tr -s " " | cut -d" " -f 6'
genAdminIP = subprocess.check_output(cmd , shell=True).strip()
cmd='nova show ' + sutVMName + ' | grep "dpdk-network" | tr -s " " | cut -d" " -f 5'
sutDPIP = subprocess.check_output(cmd , shell=True).strip()
cmd='nova show ' + sutVMName + ' | grep "admin_internal_net" | tr -s " " | cut -d" " -f 6'
sutAdminIP = subprocess.check_output(cmd , shell=True).strip()

#========================================================================
def connect_socket(client):
	attempts = 1
	print("Trying to connect to PROX (just launched) on %s, attempt: %d"
			% (client.ip(), attempts))
	sock = None
	while True:
		sock = client.prox_sock()
		if sock is not None:
			break
		attempts += 1
		if attempts > 20:
			raise Exception("Failed to connect to PROX on %s after %d attempts"
					% (client.ip(), attempts))
		time.sleep(10)
		print("Trying to connect to PROX (just launched) on %s, attempt: %d"
				% (client.ip(), attempts))
	print("Connected to PROX on %s" % client.ip())
	return sock

def connect_client(client):
	attempts = 1
	print ("Trying to connect to VM which was just launched on %s, attempt: %d"
			% (client.ip(), attempts))
	while True:
		try:
			client.connect()
			break
		except RuntimeWarning, ex:
			attempts += 1
			if attempts > 20:
				raise Exception("Failed to connect to VM after %d attempts:\n%s"
						% (attempts, ex))
			time.sleep(15)
			print ("Trying to connect to VM which was just launched on %s, attempt: %d"
					% (client.ip(), attempts))
	print("Connected to VM on %s" % client.ip())


def run_testA():
	global genclient
	global sutclient
	ip = genDPIP.split('.')
	hexgenDPIP=hex(int(ip[0]))[2:].zfill(2) + ' ' + hex(int(ip[1]))[2:].zfill(2) + ' ' + hex(int(ip[2]))[2:].zfill(2) + ' ' + hex(int(ip[3]))[2:].zfill(2)
	ip = sutDPIP.split('.')
	hexsutDPIP=hex(int(ip[0]))[2:].zfill(2) + ' ' + hex(int(ip[1]))[2:].zfill(2) + ' ' + hex(int(ip[2]))[2:].zfill(2) + ' ' + hex(int(ip[3]))[2:].zfill(2)
	with open("parameters.lua", "w") as f:
		f.write('gen_hex_ip="'+hexgenDPIP+'"\n')
		f.write('sut_hex_ip="'+hexsutDPIP+'"\n')
		f.write('gen_ip="'+genDPIP+'"\n')
		f.write('sut_ip="'+sutDPIP+'"\n')
		f.close
	genclient.scp_put('./gen.cfg', '/root/gen.cfg')
	sutclient.scp_put('./sut.cfg', '/root/sut.cfg')
	genclient.scp_put('./parameters.lua', '/root/parameters.lua')
	sutclient.scp_put('./parameters.lua', '/root/parameters.lua')
	print("Config files copied")
	cmd = '/root/prox/build/prox -e -t -o cli -f /root/gen.cfg'
	genclient.fork_cmd(cmd, 'PROX GEN')
	cmd = '/root/prox/build/prox -t -o cli -f /root/sut.cfg'
	sutclient.fork_cmd(cmd, 'PROX SUT')
	gensock = connect_socket(genclient)
	sutsock = connect_socket(sutclient)
	new_speed = 100
	attempts = 0
	cores = [1,2]
	gencores = [1]
	gensock.reset_stats()
	sutsock.reset_stats()
	gensock.start([2])
	print("+---------------------------------------------------------------------------------------------------------+")
	print("| Generator is sending UDP (1 flow) packets (64 bytes) to SUT. SUT sends packets back                     |")
	print("+------+-----------------+----------------+----------------+----------------+----------------+------------+")
	print("| Test | Speed requested | Req to Generate|  Sent by Gen   | Forward by SUT |  Rec. by Gen   | Result     |")
	print("+------+-----------------+----------------+----------------+----------------+----------------+------------+")
	while (new_speed > 0.1):
		attempts += 1
		# Start generating packets at requested speed (in % of a 10Gb/s link)
		gensock.speed(new_speed, gencores)
		gensock.start(gencores)
		time.sleep(1)
		# Get statistics now that the generation is stable and NO ARP messages any more
		old_sut_rx, old_sut_tx, old_sut_drop, old_sut_tsc, sut_tsc_hz = sutsock.core_stats([1])
		old_rx, old_tx, old_drop, old_tsc, tsc_hz = gensock.core_stats(cores)
		time.sleep(10)
		# Get statistics after some execution time
		new_rx, new_tx, new_drop, new_tsc, tsc_hz = gensock.core_stats(cores)
		new_sut_rx, new_sut_tx, new_sut_drop, new_sut_tsc, sut_tsc_hz = sutsock.core_stats([1])
		time.sleep(1)
		# Stop generating
		gensock.stop(gencores)
		drop = new_drop-old_drop # drop is all packets dropped by all tasks. This includes packets dropped at the generator task + packets dropped by the nop task. In steady state, this equals to the number of packets received by this VM
		rx = new_rx - old_rx     # rx is all packets received by the nop task = all packets received in the gen VM
		tx = new_tx - old_tx  	 # tx is all generated packets actually accepted by the interface
		tsc = new_tsc - old_tsc  # time difference between the 2 measurements, expressed in cycles.
		sut_rx = new_sut_rx - old_sut_rx
		sut_tx = new_sut_tx - old_sut_tx
		sut_tsc = new_sut_tsc - old_sut_tsc
		if (tx == 0):
			raise Exception("TX = 0")
		drop_rate = round(((drop-rx) * 100.0)/(tx+drop-rx),1)
		pps_req_tx = round((tx+drop-rx)*tsc_hz*1.0/(tsc*1000000),5)
		pps_tx = round(tx*tsc_hz*1.0/(tsc*1000000),5)
		pps_rx = round(rx*tsc_hz*1.0/(tsc*1000000),5)
		pps_sut_tx = round(sut_tx*sut_tsc_hz*1.0/(sut_tsc*1000000),5)
		if ((drop_rate) < 1):
			# This will stop the test when number of dropped packets is below a certain percentage
			print("+------+-----------------+----------------+----------------+----------------+----------------+------------+")
			print('|{:>5}'.format(str(attempts))+" | "+ '{:>14}'.format(str(new_speed)) + '% | '+ '{:>9}'.format(str(pps_req_tx))+' Mpps | '+ '{:>9}'.format(str(pps_tx)) +' Mpps | ' + '{:>9}'.format(str(pps_sut_tx)) +' Mpps | '+ '{:>9}'.format(str(pps_rx))+" Mpps | SUCCESS    |")
			print("+------+-----------------+----------------+----------------+----------------+----------------+------------+")
			break
		else:
			print('|{:>5}'.format(str(attempts))+" | "+ '{:>14}'.format(str(new_speed)) + '% | '+ '{:>9}'.format(str(pps_req_tx))+' Mpps | '+ '{:>9}'.format(str(pps_tx)) +' Mpps | ' + '{:>9}'.format(str(pps_sut_tx)) +' Mpps | '+ '{:>9}'.format(str(pps_rx))+" Mpps | FAILED     |")
		# Following calculates the ratio for the new speed to be applied
		# On the Y axis, we will find the ratio, a number between 0 and 1
		# On the x axis, we find the % of dropped packets, a number between 0 and 100
		# 2 lines are drawn and we take the minumun of these lines to calculate the ratio
		# One line goes through (0,y0) and (p,q)
		# The second line goes through (p,q) and (100,y100)
		y0=0.99
		y100=0.1
		p=15
		q=.9
		ratio = min((q-y0)/p*drop_rate+y0,(q-y100)/(p-100)*drop_rate+q-p*(q-y100)/(p-100))
		new_speed = (int(new_speed*ratio*100)+0.5)/100
	gensock.quit()
	sutsock.quit()
	time.sleep(2)
	print("")

def run_testB():
	global genclient
	global sutclient
	ip = genDPIP.split('.')
	hexgenDPIP=hex(int(ip[0]))[2:].zfill(2) + ' ' + hex(int(ip[1]))[2:].zfill(2) + ' ' + hex(int(ip[2]))[2:].zfill(2) + ' ' + hex(int(ip[3]))[2:].zfill(2)
	ip = sutDPIP.split('.')
	hexsutDPIP=hex(int(ip[0]))[2:].zfill(2) + ' ' + hex(int(ip[1]))[2:].zfill(2) + ' ' + hex(int(ip[2]))[2:].zfill(2) + ' ' + hex(int(ip[3]))[2:].zfill(2)
	with open("parameters.lua", "w") as f:
		f.write('gen_hex_ip="'+hexgenDPIP+'"\n')
		f.write('sut_hex_ip="'+hexsutDPIP+'"\n')
		f.write('gen_ip="'+genDPIP+'"\n')
		f.write('sut_ip="'+sutDPIP+'"\n')
		f.close
	genclient.scp_put('./gen.cfg', '/root/gen.cfg')
	sutclient.scp_put('./sut.cfg', '/root/sut.cfg')
	genclient.scp_put('./parameters.lua', '/root/parameters.lua')
	sutclient.scp_put('./parameters.lua', '/root/parameters.lua')
	print("Config files copied")
	cmd = '/root/prox/build/prox -e -t -o cli -f /root/gen.cfg'
	genclient.fork_cmd(cmd, 'PROX GEN')
	cmd = '/root/prox/build/prox -t -o cli -f /root/sut.cfg'
	sutclient.fork_cmd(cmd, 'PROX SUT')
	gensock = connect_socket(genclient)
	sutsock = connect_socket(sutclient)
	print("+----------------------------------------------------------------------------------------------+")
	print("| UDP, 64 bytes, different number of flows by randomizing SRC & DST UDP port                   |")
	print("+--------+-----------------+----------------+----------------+----------------+----------------+")
	print("| Flows  | Speed requested | Req to Generate|  Sent by Gen   | Forward by SUT |  Rec. by Gen   |")
	print("+--------+-----------------+----------------+----------------+----------------+----------------+")
	cores = [1,2]
	gencores = [1]
	gensock.start([2])
	new_speed = 100
	# To generate a desired number of flows, PROX will randomize the bits in source and destination ports, as specified by the bit masks in the flows variable. 
	flows={128:['0000000000000XXX','000000000000XXXX'],1024:['00000000000XXXXX','00000000000XXXXX'],8192:['0000000000XXXXXX','000000000XXXXXXX'],65535:['00000000XXXXXXXX','00000000XXXXXXXX'],524280:['0000000XXXXXXXXX','000000XXXXXXXXXX']}
	for flow_number in sorted(flows.iterkeys()):
		#new_speed = 100 Commented out: Not starting from 100% since we are trying more flows, so speed will not be higher than the speed achieved in previous loop
		attempts = 0
		gensock.reset_stats()
		sutsock.reset_stats()
		source_port,destination_port = flows[flow_number]
		gensock.set_random(gencores,0,34,source_port,2)
		gensock.set_random(gencores,0,36,destination_port,2)
		while (new_speed > 0.1):
			attempts += 1
			# Start generating packets at requested speed (in % of a 10Gb/s link)
			gensock.speed(new_speed, gencores)
			gensock.start(gencores)
			time.sleep(1)
			# Get statistics now that the generation is stable and NO ARP messages any more
			old_sut_rx, old_sut_tx, old_sut_drop, old_sut_tsc, sut_tsc_hz = sutsock.core_stats([1])
			old_rx, old_tx, old_drop, old_tsc, tsc_hz = gensock.core_stats(cores)
			time.sleep(10)
			# Get statistics after some execution time
			new_rx, new_tx, new_drop, new_tsc, tsc_hz = gensock.core_stats(cores)
			new_sut_rx, new_sut_tx, new_sut_drop, new_sut_tsc, sut_tsc_hz = sutsock.core_stats([1])
			time.sleep(1)
			# Stop generating
			gensock.stop(gencores)
			drop = new_drop-old_drop # drop is all packets dropped by all tasks. This includes packets dropped at the generator task + packets dropped by the nop task. In steady state, this equals to the number of packets received by this VM
			rx = new_rx - old_rx     # rx is all packets received by the nop task = all packets received in the gen VM
			tx = new_tx - old_tx  	 # tx is all generated packets actually accepted by the interface
			tsc = new_tsc - old_tsc  # time difference between the 2 measurements, expressed in cycles.
			sut_rx = new_sut_rx - old_sut_rx
			sut_tx = new_sut_tx - old_sut_tx
			sut_tsc = new_sut_tsc - old_sut_tsc
			if (tx == 0):
				raise Exception("TX = 0")
			drop_rate = round(((drop-rx) * 100.0)/(tx+drop-rx),1)
			pps_req_tx = round((tx+drop-rx)*tsc_hz*1.0/(tsc*1000000),5)
			pps_tx = round(tx*tsc_hz*1.0/(tsc*1000000),5)
			pps_rx = round(rx*tsc_hz*1.0/(tsc*1000000),5)
			pps_sut_tx = round(sut_tx*sut_tsc_hz*1.0/(sut_tsc*1000000),5)
			if ((drop_rate) < 1):
				# This will stop the test when number of dropped packets is below a certain percentage
				print('|{:>7}'.format(str(flow_number))+" | "+ '{:>14}'.format(str(new_speed)) + '% | '+ '{:>9}'.format(str(pps_req_tx))+' Mpps | '+ '{:>9}'.format(str(pps_tx)) +' Mpps | ' + '{:>9}'.format(str(pps_sut_tx)) +' Mpps | '+ '{:>9}'.format(str(pps_rx))+" Mpps |")
				print("+--------+-----------------+----------------+----------------+----------------+----------------+")
				break
			# Following calculates the ratio for the new speed to be applied
			# On the Y axis, we will find the ratio, a number between 0 and 1
			# On the x axis, we find the % of dropped packets, a number between 0 and 100
			# 2 lines are drawn and we take the minumun of these lines to calculate the ratio
			# One line goes through (0,y0) and (p,q)
			# The second line goes through (p,q) and (100,y100)
			y0=0.99
			y100=0.1
			p=15
			q=.9
			ratio = min((q-y0)/p*drop_rate+y0,(q-y100)/(p-100)*drop_rate+q-p*(q-y100)/(p-100))
			new_speed = (int(new_speed*ratio*100)+0.5)/100
	gensock.quit()
	sutsock.quit()
	time.sleep(2)
	print("")

#========================================================================
genclient = prox_ctrl(genAdminIP, key+'.pem')
connect_client(genclient)
sutclient = prox_ctrl(sutAdminIP, key+'.pem')
connect_client(sutclient)
#####################################################################################
run_testA()
run_testB()
#####################################################################################
genclient.close()
sutclient.close()

