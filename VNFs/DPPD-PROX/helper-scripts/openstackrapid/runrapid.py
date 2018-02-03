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
import ast

version="18.2.3"
env = "rapid" #Default string for environment
test = "basicrapid" #Default string for test
loglevel="DEBUG" # sets log level for writing to file
runtime=10 # time in seconds for 1 test run

def usage():
	print("usage: runrapid    [--version] [-v]")
	print("                   [--env ENVIRONMENT_NAME]")
	print("                   [--test TEST_NAME]")
	print("                   [--runtime TIME_FOR_TEST]")
	print("                   [--log DEBUG|INFO|WARNING|ERROR|CRITICAL]")
	print("                   [-h] [--help]")
	print("")
	print("Command-line interface to runrapid")
	print("")
	print("optional arguments:")
	print("  -v,  --version           	Show program's version number and exit")
	print("  --env ENVIRONMENT_NAME       	Parameters will be read from ENVIRONMENT_NAME.env Default is %s."%env)
	print("  --test TEST_NAME       	Test cases will be read from TEST_NAME.test Default is %s."%test)
	print("  --runtime			Specify time in seconds for 1 test run")
	print("  --log				Specify logging level for log file output, screen output level is hard coded")
	print("  -h, --help               	Show help message and exit.")
	print("")

try:
	opts, args = getopt.getopt(sys.argv[1:], "vh", ["version","help", "env=", "test=","runtime=","log="])
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
	if opt in ("--env"):
		env = arg
		print ("Using '"+env+"' as name for the environment")
	if opt in ("--test"):
		test = arg
		print ("Using '"+test+".test' for test case definition")
	if opt in ("--runtime"):
		runtime = arg
		print ("Runtime: "+ runtime)
	if opt in ("--log"):
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
log_file = 'RUN' +env+'.'+test+'.log'
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

log.debug("runrapid.py version: "+version)
#========================================================================
def connect_socket(client):
	attempts = 1
	log.debug("Trying to connect to PROX (just launched) on %s, attempt: %d" % (client.ip(), attempts))
	sock = None
	while True:
		sock = client.prox_sock()
		if sock is not None:
			break
		attempts += 1
		if attempts > 20:
			log.exception("Failed to connect to PROX on %s after %d attempts" % (client.ip(), attempts))
			raise Exception("Failed to connect to PROX on %s after %d attempts" % (client.ip(), attempts))
		time.sleep(2)
		log.debug("Trying to connect to PROX (just launched) on %s, attempt: %d" % (client.ip(), attempts))
	log.info("Connected to PROX on %s" % client.ip())
	return sock

def connect_client(client):
	attempts = 1
	log.debug("Trying to connect to VM which was just launched on %s, attempt: %d" % (client.ip(), attempts))
	while True:
		try:
			client.connect()
			break
		except RuntimeWarning, ex:
			attempts += 1
			if attempts > 20:
				log.exception("Failed to connect to VM after %d attempts:\n%s" % (attempts, ex))
				raise Exception("Failed to connect to VM after %d attempts:\n%s" % (attempts, ex))
			time.sleep(2)
			log.debug("Trying to connect to VM which was just launched on %s, attempt: %d" % (client.ip(), attempts))
	log.info("Connected to VM on %s" % client.ip())

def run_iteration(gensock,sutsock):
	gensock.start(gencores)
	time.sleep(3)
	if sutsock!='none':
		old_sut_rx, old_sut_tx, old_sut_drop, old_sut_tsc, sut_tsc_hz = sutsock.core_stats(sutstatcores)
	old_rx, old_tx, old_drop, old_tsc, tsc_hz = gensock.core_stats(genstatcores)
	time.sleep(float(runtime))
	lat_min, lat_max, lat_avg = gensock.lat_stats(latcores)
	# Get statistics after some execution time
	new_rx, new_tx, new_drop, new_tsc, tsc_hz = gensock.core_stats(genstatcores)
	if sutsock!='none':
		new_sut_rx, new_sut_tx, new_sut_drop, new_sut_tsc, sut_tsc_hz = sutsock.core_stats(sutstatcores)
	time.sleep(1)
	#Stop generating
	gensock.stop(gencores)
	drop = new_drop-old_drop # drop is all packets dropped by all tasks. This includes packets dropped at the generator task + packets dropped by the nop task. In steady state, this equals to the number of packets received by this VM
	rx = new_rx - old_rx     # rx is all packets received by the nop task = all packets received in the gen VM
	tx = new_tx - old_tx     # tx is all generated packets actually accepted by the interface
	tsc = new_tsc - old_tsc  # time difference between the 2 measurements, expressed in cycles.
	pps_req_tx = round((tx+drop-rx)*tsc_hz*1.0/(tsc*1000000),3)
	pps_tx = round(tx*tsc_hz*1.0/(tsc*1000000),3)
	pps_rx = round(rx*tsc_hz*1.0/(tsc*1000000),3)
	if sutsock!='none':
		sut_rx = new_sut_rx - old_sut_rx
		sut_tx = new_sut_tx - old_sut_tx
		sut_tsc = new_sut_tsc - old_sut_tsc
		pps_sut_tx = round(sut_tx*sut_tsc_hz*1.0/(sut_tsc*1000000),3)
		pps_sut_tx_str = '{:>9.2f}'.format(pps_sut_tx)
	else:
		pps_sut_tx = 0
		pps_sut_tx_str = 'NO MEAS.'
	if (tx == 0):
        	log.critical("TX = 0. Test interrupted since no packet has been sent.")
		raise Exception("TX = 0")
	return(pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx,lat_avg)

def new_speed(speed,minspeed,maxspeed,drop_rate):
	# Following calculates the ratio for the new speed to be applied
	# On the Y axis, we will find the ratio, a number between 0 and 1
	# On the x axis, we find the % of dropped packets, a number between 0 and 100
	# 2 lines are drawn and we take the minumun of these lines to calculate the ratio
	# One line goes through (0,y0) and (p,q)
	# The second line goes through (p,q) and (100,y100)
#	y0=0.99
#	y100=0.1
#	p=1
#	q=.99
#	ratio = min((q-y0)/p*drop_rate+y0,(q-y100)/(p-100)*drop_rate+q-p*(q-y100)/(p-100))
#	return (int(speed*ratio*100)+0.5)/100.0
	if drop_rate < DROP_RATE_TRESHOLD:
		minspeed = speed
	else:
		maxspeed = speed
	newspeed = (maxspeed+minspeed)/2.0
	return (newspeed,minspeed,maxspeed)

def get_pps(speed,size):
	return (speed * 100.0 / (8*(size+24)))

def get_drop_rate(speed,pps_rx,size):
	# pps_rx are all the packets that are received by the generator. That is substracted
	# from the pps that we wanted to send. This is calculated by taking the variable speed
	# which is the requested percentage of a 10Gb/s link. So we take  10000bps (10Gbps, note
	# that the speed variable is already expressed in % so we only take 100 and not 10000)
	# divided by the number of bits in 1 packet. That is 8 bits in a byte times the size of
	# a frame (=our size + 24 bytes overhead).
	tried_to_send = get_pps(speed,size)
	return (100.0*(tried_to_send - pps_rx)/tried_to_send)

def run_speedtest(gensock,sutsock):
        log.info("+----------------------------------------------------------------------------------------------------------------------------+")
        log.info("| Generator is sending UDP (1 flow) packets (64 bytes) to SUT. SUT sends packets back                                        |")
        log.info("+--------+-----------------+----------------+----------------+----------------+----------------+----------------+------------+")
        log.info("| Test   | Speed requested | Sent to NIC    |  Sent by Gen   | Forward by SUT |  Rec. by Gen   |  Avg. Latency  | Result     |")
        log.info("+--------+-----------------+----------------+----------------+----------------+----------------+----------------+------------+")
	speed = 100
	maxspeed = speed
	minspeed = 0
	size=60
	attempts = 0
	endpps_sut_tx_str = 'NO_RESULTS'
	gensock.set_size(gencores,0,size) # This is setting the frame size
	gensock.set_value(gencores,0,16,(size-18),2) # 18 is the difference between the frame size and IP size = size of (MAC addresses, ethertype and FCS)
	gensock.set_value(gencores,0,38,(size-38),2) # 38 is the difference between the frame size and UDP size = 18 + size of IP header (=20)
	# This will only work when using sending UDP packets. For different protocls and ehternet types, we would need a differnt calculation
        while (maxspeed-minspeed > 1):
                attempts += 1
                print('Measurement ongoing at speed: ' + str(round(speed,2)) + '%      ',end='\r')
                sys.stdout.flush()
                # Start generating packets at requested speed (in % of a 10Gb/s link)
                gensock.speed(speed, gencores)
                time.sleep(1)
                # Get statistics now that the generation is stable and NO ARP messages any more
		pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx,lat_avg = run_iteration(gensock,sutsock)
		drop_rate = get_drop_rate(speed,pps_rx,size)
	        if (drop_rate < DROP_RATE_TRESHOLD):
	                log.info('|{:>7}'.format(str(attempts))+" | "+ '{:>10.2f}'.format(get_pps(speed,size)) + ' Mpps | '+ '{:>9.2f}'.format(pps_req_tx)+' Mpps | '+ '{:>9.2f}'.format(pps_tx) +' Mpps | ' + '{:>9}'.format(pps_sut_tx_str) +' Mpps | '+ '{:>9.2f}'.format(pps_rx)+' Mpps | '+ '{:>9.0f}'.format(lat_avg)+" us   | SUCCESS    |")
			endspeed = speed
			endpps_req_tx = pps_req_tx
			endpps_tx = pps_tx
			endpps_sut_tx_str = pps_sut_tx_str
			endpps_rx = pps_rx
			endlat_avg = lat_avg 
	        else:
	                log.info('|{:>7}'.format(str(attempts))+" | "+ '{:>10.2f}'.format(get_pps(speed,size)) + ' Mpps | '+ '{:>9.2f}'.format(pps_req_tx)+' Mpps | '+ '{:>9.2f}'.format(pps_tx) +' Mpps | ' + '{:>9}'.format(pps_sut_tx_str) +' Mpps | '+ '{:>9.2f}'.format(pps_rx)+' Mpps | '+ '{:>9.0f}'.format(lat_avg)+" us   | FAILED     |")
		speed,minspeed,maxspeed = new_speed(speed,minspeed,maxspeed,drop_rate)
	if endpps_sut_tx_str <>  'NO_RESULTS':
	        log.info("+--------+-----------------+----------------+----------------+----------------+----------------+----------------+------------+")
		log.info('|{:>7}'.format("END")+" | "+ '{:>10.2f}'.format(get_pps(endspeed,size)) + ' Mpps | '+ '{:>9.2f}'.format(endpps_req_tx)+' Mpps | '+ '{:>9.2f}'.format(endpps_tx) +' Mpps | ' + '{:>9}'.format(endpps_sut_tx_str) +' Mpps | '+ '{:>9.2f}'.format(endpps_rx)+' Mpps | '+ '{:>9.0f}'.format(endlat_avg)+" us   | SUCCESS    |")
	        log.info("+--------+-----------------+----------------+----------------+----------------+----------------+----------------+------------+")
	else:
		log.debug('| Speed 0 or close to 0')

def run_flowtest(gensock,sutsock):
	log.info("+---------------------------------------------------------------------------------------------------------------+")
	log.info("| UDP, 64 bytes, different number of flows by randomizing SRC & DST UDP port                                    |")
	log.info("+--------+-----------------+----------------+----------------+----------------+----------------+----------------+")
	log.info("| Flows  | Speed requested | Sent to NIC    |  Sent by Gen   | Forward by SUT |  Rec. by Gen   |  Avg. Latency  |")
	log.info("+--------+-----------------+----------------+----------------+----------------+----------------+----------------+")
	speed = 100
	size=60
	# To generate a desired number of flows, PROX will randomize the bits in source and destination ports, as specified by the bit masks in the flows variable. 
	flows={128:['1000000000000XXX','100000000000XXXX'],1024:['10000000000XXXXX','10000000000XXXXX'],8192:['1000000000XXXXXX','100000000XXXXXXX'],65535:['10000000XXXXXXXX','10000000XXXXXXXX'],524280:['1000000XXXXXXXXX','100000XXXXXXXXXX']}
#	flows={524280:['1000000XXXXXXXXX','100000XXXXXXXXXX']}
	gensock.set_size(gencores,0,size) # This is setting the frame size
	gensock.set_value(gencores,0,16,(size-18),2) # 18 is the difference between the frame size and IP size = size of (MAC addresses, ethertype and FCS)
	gensock.set_value(gencores,0,38,(size-38),2) # 38 is the difference between the frame size and UDP size = 18 + size of IP header (=20)
	# This will only work when using sending UDP packets. For different protocls and ehternet types, we would need a differnt calculation
	for flow_number in sorted(flows.iterkeys()):
		#speed = 100 Commented out: Not starting from 100% since we are trying more flows, so speed will not be higher than the speed achieved in previous loop
		gensock.reset_stats()
		if sutsock!='none':
			sutsock.reset_stats()
		source_port,destination_port = flows[flow_number]
		gensock.set_random(gencores,0,34,source_port,2)
		gensock.set_random(gencores,0,36,destination_port,2)
		endpps_sut_tx_str = 'NO_RESULTS'
		maxspeed = speed
		minspeed = 0
		while (maxspeed-minspeed > 1):
			print(str(flow_number)+' flows: Measurement ongoing at speed: ' + str(round(speed,2)) + '%      ',end='\r')
			sys.stdout.flush()
			# Start generating packets at requested speed (in % of a 10Gb/s link)
			gensock.speed(speed, gencores)
			time.sleep(1)
			# Get statistics now that the generation is stable and NO ARP messages any more
			pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx,lat_avg = run_iteration(gensock,sutsock)
			drop_rate = get_drop_rate(speed,pps_rx,size)
			if (drop_rate < DROP_RATE_TRESHOLD):
				endspeed = speed
				endpps_req_tx = pps_req_tx
				endpps_tx = pps_tx
				endpps_sut_tx_str = pps_sut_tx_str
				endpps_rx = pps_rx
				endlat_avg = lat_avg 
			speed,minspeed,maxspeed = new_speed(speed,minspeed,maxspeed,drop_rate)
		if endpps_sut_tx_str <>  'NO_RESULTS':
			log.info('|{:>7}'.format(str(flow_number))+" | "+ '{:>10.2f}'.format(get_pps(endspeed,size)) + ' Mpps | '+ '{:>9.2f}'.format(endpps_req_tx)+' Mpps | '+ '{:>9.2f}'.format(endpps_tx) +' Mpps | ' + '{:>9}'.format(endpps_sut_tx_str) +' Mpps | '+ '{:>9.2f}'.format(endpps_rx)+' Mpps | '+ '{:>9.0f}'.format(endlat_avg)+' us   |{:>7.1f}%'.format(speed))
			log.info("+--------+-----------------+----------------+----------------+----------------+----------------+----------------+")
		else:
			log.debug('|{:>7}'.format(str(flow_number))+" | Speed 0 or close to 0")

def run_sizetest(gensock,sutsock):
	log.info("+---------------------------------------------------------------------------------------------------------------+")
	log.info("| UDP, 1 flow, different packet sizes                                                                           |")
	log.info("+--------+-----------------+----------------+----------------+----------------+----------------+----------------+")
	log.info("| Pktsize| Speed requested | Sent to NIC    |  Sent by Gen   | Forward by SUT |  Rec. by Gen   |  Avg. Latency  |")
	log.info("+--------+-----------------+----------------+----------------+----------------+----------------+----------------+")
	speed = 100
	# PROX will use different packet sizes as defined in sizes[]
#	sizes=[1496,1020,508,252,124,60]
	sizes=[1020,508,252,124,60]
	for size in sizes:
		#speed = 100 Commented out: Not starting from 100% since we are trying smaller packets, so speed will not be higher than the speed achieved in previous loop
		gensock.reset_stats()
		if sutsock!='none':
			sutsock.reset_stats()
		gensock.set_size(gencores,0,size) # This is setting the frame size
		gensock.set_value(gencores,0,16,(size-18),2) # 18 is the difference between the frame size and IP size = size of (MAC addresses, ethertype and FCS)
		gensock.set_value(gencores,0,38,(size-38),2) # 38 is the difference between the frame size and UDP size = 18 + size of IP header (=20)
		# This will only work when using sending UDP packets. For different protocls and ehternet types, we would need a differnt calculation
		endpps_sut_tx_str = 'NO_RESULTS'
		maxspeed = speed
		minspeed = 0
		while (maxspeed-minspeed > 1):
			print(str(size)+' bytes: Measurement ongoing at speed: ' + str(round(speed,2)) + '%      ',end='\r')
			sys.stdout.flush()
			# Start generating packets at requested speed (in % of a 10Gb/s link)
			gensock.speed(speed, gencores)
			# Get statistics now that the generation is stable and NO ARP messages any more
			pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx,lat_avg = run_iteration(gensock,sutsock)
			drop_rate = get_drop_rate(speed,pps_rx,size)
			if (drop_rate < DROP_RATE_TRESHOLD):
				endspeed = speed
				endpps_req_tx = pps_req_tx
				endpps_tx = pps_tx
				endpps_sut_tx_str = pps_sut_tx_str
				endpps_rx = pps_rx
				endlat_avg = lat_avg 
			speed,minspeed,maxspeed = new_speed(speed,minspeed,maxspeed,drop_rate)
		if endpps_sut_tx_str <>  'NO_RESULTS':
			log.info('|{:>7d}'.format(size+4)+" | "+ '{:>10.2f}'.format(get_pps(endspeed,size)) + ' Mpps | '+ '{:>9.2f}'.format(endpps_req_tx)+' Mpps | '+ '{:>9.2f}'.format(endpps_tx) +' Mpps | ' + '{:>9}'.format(endpps_sut_tx_str) +' Mpps | '+ '{:>9.2f}'.format(endpps_rx)+' Mpps | '+ '{:>9.0f}'.format(endlat_avg)+' us   | {:>7.1f}%'.format(speed))
			log.info("+--------+-----------------+----------------+----------------+----------------+----------------+----------------+")
		else:
			log.debug('|{:>7}'.format(str(size))+" | Speed 0 or close to 0")

def run_irqtest(sock):
        log.info("+----------------------------------------------------------------------------------------------------------------------------")
        log.info("| Measuring time probably spent dealing with an interrupt. Interrupting DPDK cores for more than 50us might be problematic   ")
        log.info("| and result in packet loss. The first row shows the interrupted time buckets: first number is the bucket between 0us and    ")
	log.info("| that number expressed in us and so on. The numbers in the other rows show how many times per second, the program was       ")
        log.info("| interrupted for a time as specified by its bucket.                                                                                           ")
        log.info("+----------------------------------------------------------------------------------------------------------------------------")
        sys.stdout.flush()
	buckets=sock.show_irq_buckets(1)
        print('Measurement ongoing ... ',end='\r')
	sock.stop(irqcores)
	old_irq = [[0 for x in range(len(buckets)+1)] for y in range(len(irqcores)+1)] 
	new_irq = [[0 for x in range(len(buckets)+1)] for y in range(len(irqcores)+1)] 
	irq = [[0 for x in range(len(buckets)+1)] for y in range(len(irqcores)+1)]
	irq[0][0] = 'bucket us' 
	for j,bucket in enumerate(buckets,start=1):
		irq[0][j] = '<'+ bucket
	irq[0][-1] = '>'+ buckets [-2]
	for j,bucket in enumerate(buckets,start=1):
		for i,irqcore in enumerate(irqcores,start=1):
			old_irq[i][j] = sock.irq_stats(irqcore,j-1)
	sock.start(irqcores)
	time.sleep(float(runtime))
	sock.stop(irqcores)
	for i,irqcore in enumerate(irqcores,start=1):
		irq[i][0]='core %s'%irqcore
		for j,bucket in enumerate(buckets,start=1):
			new_irq[i][j] = sock.irq_stats(irqcore,j-1)
			irq[i][j] = (new_irq[i][j] - old_irq[i][j])/float(runtime)
	log.info('\n'.join([''.join(['{:>10}'.format(item) for item in row]) for row in irq]))


def init_test():
# Running at low speed to make sure the ARP messages can get through.
# If not doing this, the ARP message could be dropped by a switch in overload and then the test will not give proper results
# Note hoever that if we would run the test steps during a very long time, the ARP would expire in the switch.
# PROX will send a new ARP request every seconds so chances are very low that they will all fail to get through
	sock[0].speed(0.01, gencores)
	sock[0].start(genstatcores)
	time.sleep(2)
	sock[0].stop(gencores)

global sutstatcores
global genstatcores
global latcores
global gencores
global irqcores
global DROP_RATE_TRESHOLD
DROP_RATE_TRESHOLD = 1
vmDPIP =[]
vmAdminIP =[]
vmDPmac =[]
hexDPIP =[]
config_file =[]
script_control =[]

testconfig = ConfigParser.RawConfigParser()
testconfig.read(test+'.test')
required_number_of_VMs = testconfig.get('DEFAULT', 'total_number_of_vms')
config = ConfigParser.RawConfigParser()
config.read(env+'.env')
key = config.get('OpenStack', 'key')
total_number_of_VMs = config.get('rapid', 'total_number_of_VMs')
if int(required_number_of_VMs) > int(total_number_of_VMs):
	log.exception("Not enough VMs for this test: %s needed and only %s available" % (required_number_of_VMs,total_number_of_VMs))
	raise Exception("Not enough VMs for this test: %s needed and only %s available" % (required_number_of_VMs,total_number_of_VMs))
for vm in range(1, int(total_number_of_VMs)+1):
	vmAdminIP.append(config.get('VM%d'%vm, 'admin_ip'))
	vmDPmac.append(config.get('VM%d'%vm, 'dp_mac'))
	vmDPIP.append(config.get('VM%d'%vm, 'dp_ip'))
	ip = vmDPIP[-1].split('.')
	hexDPIP.append(hex(int(ip[0]))[2:].zfill(2) + ' ' + hex(int(ip[1]))[2:].zfill(2) + ' ' + hex(int(ip[2]))[2:].zfill(2) + ' ' + hex(int(ip[3]))[2:].zfill(2))
for vm in range(1, int(required_number_of_VMs)+1):
	config_file.append(testconfig.get('VM%d'%vm, 'config_file'))
	script_control.append(testconfig.get('VM%d'%vm, 'script_control'))
        group1cores=testconfig.get('VM%d'%vm, 'group1cores')
	if group1cores <> 'not_used':
		group1cores=ast.literal_eval(group1cores)
        group2cores=testconfig.get('VM%d'%vm, 'group2cores')
	if group2cores <> 'not_used':
		group2cores=ast.literal_eval(group2cores)
        group3cores=testconfig.get('VM%d'%vm, 'group3cores')
	if group3cores <> 'not_used':
		group3cores=ast.literal_eval(group3cores)
	with open("parameters%d.lua"%vm, "w") as f:
		f.write('name="%s"\n'% testconfig.get('VM%d'%vm, 'name'))
		f.write('local_ip="%s"\n'% vmDPIP[vm-1])
		f.write('local_hex_ip="%s"\n'% hexDPIP[vm-1])
		gwVM = testconfig.get('VM%d'%vm, 'gw_vm')
		if gwVM <> 'not_used':
			gwVMindex = int(gwVM)-1
			f.write('gw_ip="%s"\n'% vmDPIP[gwVMindex])
			f.write('gw_hex_ip="%s"\n'% hexDPIP[gwVMindex])
		destVM = testconfig.get('VM%d'%vm, 'dest_vm')
		if destVM <> 'not_used':
			destVMindex = int(destVM)-1
			f.write('dest_ip="%s"\n'% vmDPIP[destVMindex])
			f.write('dest_hex_ip="%s"\n'% hexDPIP[destVMindex])
                if group1cores <> 'not_used':
                        f.write('group1="%s"\n'% ','.join(map(str, group1cores)))
                if group2cores <> 'not_used':
                        f.write('group2="%s"\n'% ','.join(map(str, group2cores)))
                if group3cores <> 'not_used':
                        f.write('group3="%s"\n'% ','.join(map(str, group3cores)))
	if config_file[-1] == 'gen.cfg':
		gencores = group1cores
		latcores = group2cores
		genstatcores = group3cores
	elif config_file[-1] == 'gen_gw.cfg':
		gencores = group1cores
		latcores = group2cores
		genstatcores = group3cores
	elif config_file[-1] == 'swap.cfg':
		sutstatcores = group1cores
	elif config_file[-1] == 'secgw2.cfg':
		sutstatcores = group1cores
	elif config_file[-1] == 'irq.cfg':
		irqcores = group1cores
	f.close
#####################################################################################
client =[]
sock =[]

for vm in range(0, int(required_number_of_VMs)):
	client.append(prox_ctrl(vmAdminIP[vm], key+'.pem','root'))
	connect_client(client[-1])
# Creating script to bind the right network interface to the poll mode driver
	devbindfile = "devbindvm%d.sh"%(vm+1)
	with open("devbind.sh") as f:
		newText=f.read().replace('MACADDRESS', vmDPmac[vm])
		with open(devbindfile, "w") as f:
			f.write(newText)
	st = os.stat(devbindfile)
	os.chmod(devbindfile, st.st_mode | stat.S_IEXEC)
	client[-1].scp_put('./%s'%devbindfile, '/root/devbind.sh')
	cmd = '/root/devbind.sh'
	client[-1].run_cmd(cmd)
	log.info("devbind.sh running on VM%d"%(vm+1))
	client[-1].scp_put('./%s'%config_file[vm], '/root/%s'%config_file[vm])
	client[-1].scp_put('./parameters%d.lua'%(vm+1), '/root/parameters.lua')
	log.info("Starting PROX on VM%d"%(vm+1))
	if script_control[vm] == 'true':
		cmd = '/root/prox/build/prox -e -t -o cli -f /root/%s'%config_file[vm]
	else:
		cmd = '/root/prox/build/prox -t -o cli -f /root/%s'%config_file[vm]
	client[-1].fork_cmd(cmd, 'PROX Testing on VM%d'%(vm+1))
	sock.append(connect_socket(client[-1]))

init_code = testconfig.get('DEFAULT', 'init_code')
if init_code <> 'not_used':
	eval(init_code)
####################################################
# Run test cases
# Best to run the flow test at the end since otherwise the tests coming after thatmight be influenced by the big number of entries in the switch flow tables
####################################################
number_of_tests = testconfig.get('DEFAULT', 'number_of_tests')
for vm in range(1, int(number_of_tests)+1):
	cmd=testconfig.get('test%d'%vm,'cmd')
	eval(cmd)
####################################################
for vm in range(0, int(required_number_of_VMs)):
	sock[vm].quit()
	client[vm].close()
