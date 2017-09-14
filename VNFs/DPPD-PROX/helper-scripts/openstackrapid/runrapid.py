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
loglevel="DEBUG" # sets log level for writing to file
runtime=10 # time in seconds for 1 test run

def usage():
	print("usage: rapid       [--version] [-v]")
	print("                   [--stack STACK_NAME]")
	print("                   [--runtime TIME_FOR_TEST]")
	print("                   [--log DEBUG|INFO|WARNING|ERROR|CRITICAL")
	print("                   [-h] [--help]")
	print("")
	print("Command-line interface to RAPID")
	print("")
	print("optional arguments:")
	print("  -v,  --version           	Show program's version number and exit")
	print("  --stack STACK_NAME       	Parameters will be read from STACK_NAME.cfg Default is rapidTestEnv.")
	print("  --runtime			Specify time in seconds for 1 test run")
	print("  --log				Specify logging level for log file output, screen output level is hard coded")
	print("  -h, --help               	Show help message and exit.")
	print("")
	print("To delete the rapid stack, type the following command")
	print("   openstack stack delete --yes --wait rapidTestEnv")
	print("Note that rapidTestEnv is the default stack name. Replace with STACK_NAME if needed")

try:
	opts, args = getopt.getopt(sys.argv[1:], "vh", ["version","help", "stack=","runtime=","log="])
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
	elif opt in ("--runtime"):
		runtime = arg
		print ("Runtime: "+ runtime)
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
log_file = 'RUN' +stack +'.log'
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
		time.sleep(8)
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
			time.sleep(8)
			log.debug("Trying to connect to VM which was just launched on %s, attempt: %d" % (client.ip(), attempts))
	log.info("Connected to VM on %s" % client.ip())

def run_iteration(gensock,sutsock,cores,gencores):
	if sutAdminIP!='none':
		old_sut_rx, old_sut_tx, old_sut_drop, old_sut_tsc, sut_tsc_hz = sutsock.core_stats([1])
	old_rx, old_tx, old_drop, old_tsc, tsc_hz = gensock.core_stats(cores)
	time.sleep(float(runtime))
	# Get statistics after some execution time
	new_rx, new_tx, new_drop, new_tsc, tsc_hz = gensock.core_stats(cores)
	if sutAdminIP!='none':
		new_sut_rx, new_sut_tx, new_sut_drop, new_sut_tsc, sut_tsc_hz = sutsock.core_stats([1])
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
	if sutAdminIP!='none':
		sut_rx = new_sut_rx - old_sut_rx
		sut_tx = new_sut_tx - old_sut_tx
		sut_tsc = new_sut_tsc - old_sut_tsc
		pps_sut_tx = round(sut_tx*sut_tsc_hz*1.0/(sut_tsc*1000000),3)
		pps_sut_tx_str = str(pps_sut_tx)
	else:
		pps_sut_tx = 0
		pps_sut_tx_str = 'NO MEAS.'
	if (tx == 0):
		raise Exception("TX = 0")
	drop_rate = round(((pps_req_tx-pps_rx) * 100.0)/pps_req_tx,1)
	return(drop_rate,pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx)

def new_speed(speed,drop_rate):
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
	return (int(speed*ratio*100)+0.5)/100

def run_speedtest():
        global genclient
        global sutclient
        log.info("Starting PROX")
        speed = 100
        attempts = 0
        cores = [1]
        gencores = [1]
        cmd = '/root/prox/build/prox -e -t -o cli -f /root/gen.cfg'
        genclient.fork_cmd(cmd, 'PROX GEN speed Test')
        gensock = connect_socket(genclient)
        gensock.reset_stats()
        if sutAdminIP!='none':
                cmd = '/root/prox/build/prox -t -o cli -f /root/sut.cfg'
                sutclient.fork_cmd(cmd, 'PROX SUT speed Test')
                sutsock = connect_socket(sutclient)
                sutsock.reset_stats()
	else:
		sutsock = 'none'
        log.info("+-----------------------------------------------------------------------------------------------------------+")
        log.info("| Generator is sending UDP (1 flow) packets (64 bytes) to SUT. SUT sends packets back                       |")
        log.info("+--------+-----------------+----------------+----------------+----------------+----------------+------------+")
        log.info("| Test   | Speed requested | Req to Generate|  Sent by Gen   | Forward by SUT |  Rec. by Gen   | Result     |")
        log.info("+--------+-----------------+----------------+----------------+----------------+----------------+------------+")
        while (speed > 0.1):
                attempts += 1
                print('Measurement ongoing at speed: ' + str(round(speed,2)) + '%      ',end='\r')
                sys.stdout.flush()
                # Start generating packets at requested speed (in % of a 10Gb/s link)
                gensock.speed(speed, gencores)
                gensock.start(gencores)
                time.sleep(1)
                # Get statistics now that the generation is stable and NO ARP messages any more
		drop_rate,pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx = run_iteration(gensock,sutsock,cores,gencores)
	        if ((drop_rate) < 1):
	                # This will stop the test when number of dropped packets is below a certain percentage
	                log.info("+--------+-----------------+----------------+----------------+----------------+----------------+------------+")
	                log.info('|{:>7}'.format(str(attempts))+" | "+ '{:>14}'.format(str(round(speed,2))) + '% | '+ '{:>9}'.format(str(pps_req_tx))+' Mpps | '+ '{:>9}'.format(str(pps_tx)) +' Mpps | ' + '{:>9}'.format(pps_sut_tx_str) +' Mpps | '+ '{:>9}'.format(str(pps_rx))+" Mpps | SUCCESS    |")
	                log.info("+--------+-----------------+----------------+----------------+----------------+----------------+------------+")
	                break
	        else:
	                log.info('|{:>7}'.format(str(attempts))+" | "+ '{:>14}'.format(str(round(speed,2))) + '% | '+ '{:>9}'.format(str(pps_req_tx))+' Mpps | '+ '{:>9}'.format(str(pps_tx)) +' Mpps | ' + '{:>9}'.format(pps_sut_tx_str) +' Mpps | '+ '{:>9}'.format(str(pps_rx))+" Mpps | FAILED     |")
		speed = new_speed(speed,drop_rate)
        gensock.quit()
        if sutAdminIP!='none':
                sutsock.quit()
        time.sleep(2)


#	print("")

def run_flowtest():
	global genclient
	global sutclient
	log.info("Starting PROX")
	speed = 100
	attempts = 0
	cores = [1]
	gencores = [1]
	cmd = '/root/prox/build/prox -e -t -o cli -f /root/gen.cfg'
	genclient.fork_cmd(cmd, 'PROX GEN flow Test')
	gensock = connect_socket(genclient)
	gensock.reset_stats()
	if sutAdminIP!='none':
		cmd = '/root/prox/build/prox -t -o cli -f /root/sut.cfg'
		sutclient.fork_cmd(cmd, 'PROX SUT flow Test')
		sutsock = connect_socket(sutclient)
		sutsock.reset_stats()
	else:
		sutsock = 'none'
	log.info("+----------------------------------------------------------------------------------------------+")
	log.info("| UDP, 64 bytes, different number of flows by randomizing SRC & DST UDP port                   |")
	log.info("+--------+-----------------+----------------+----------------+----------------+----------------+")
	log.info("| Flows  | Speed requested | Req to Generate|  Sent by Gen   | Forward by SUT |  Rec. by Gen   |")
	log.info("+--------+-----------------+----------------+----------------+----------------+----------------+")
	cores = [1]
	gencores = [1]
	speed = 100
	# To generate a desired number of flows, PROX will randomize the bits in source and destination ports, as specified by the bit masks in the flows variable. 
	flows={128:['1000000000000XXX','100000000000XXXX'],1024:['10000000000XXXXX','10000000000XXXXX'],8192:['1000000000XXXXXX','100000000XXXXXXX'],65535:['10000000XXXXXXXX','10000000XXXXXXXX'],524280:['1000000XXXXXXXXX','100000XXXXXXXXXX']}
	for flow_number in sorted(flows.iterkeys()):
		#speed = 100 Commented out: Not starting from 100% since we are trying more flows, so speed will not be higher than the speed achieved in previous loop
		attempts = 0
		gensock.reset_stats()
		if sutAdminIP!='none':
			sutsock.reset_stats()
		source_port,destination_port = flows[flow_number]
		gensock.set_random(gencores,0,34,source_port,2)
		gensock.set_random(gencores,0,36,destination_port,2)
		while (speed > 0.1):
			print(str(flow_number)+' flows: Measurement ongoing at speed: ' + str(round(speed,2)) + '%      ',end='\r')
			sys.stdout.flush()
			attempts += 1
			# Start generating packets at requested speed (in % of a 10Gb/s link)
			gensock.speed(speed, gencores)
			gensock.start(gencores)
			time.sleep(1)
			# Get statistics now that the generation is stable and NO ARP messages any more
			drop_rate,pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx = run_iteration(gensock,sutsock,cores,gencores)
			if ((drop_rate) < 1):
				# This will stop the test when number of dropped packets is below a certain percentage
				log.info('|{:>7}'.format(str(flow_number))+" | "+ '{:>14}'.format(str(round(speed,2))) + '% | '+ '{:>9}'.format(str(pps_req_tx))+' Mpps | '+ '{:>9}'.format(str(pps_tx)) +' Mpps | ' + '{:>9}'.format(pps_sut_tx_str) +' Mpps | '+ '{:>9}'.format(str(pps_rx))+" Mpps |")
				log.info("+--------+-----------------+----------------+----------------+----------------+----------------+")
				break
			speed = new_speed(speed,drop_rate)
	gensock.quit()
	if sutAdminIP!='none':
		sutsock.quit()
	time.sleep(2)
#	print("")

def run_sizetest():
	global genclient
	global sutclient
	log.info("Starting PROX")
	speed = 100
	attempts = 0
	cores = [1]
	gencores = [1]
	cmd = '/root/prox/build/prox -e -t -o cli -f /root/gen.cfg'
	genclient.fork_cmd(cmd, 'PROX GEN size Test')
	gensock = connect_socket(genclient)
	gensock.reset_stats()
	if sutAdminIP!='none':
		cmd = '/root/prox/build/prox -t -o cli -f /root/sut.cfg'
		sutclient.fork_cmd(cmd, 'PROX SUT size Test')
		sutsock = connect_socket(sutclient)
		sutsock.reset_stats()
	else:
		sutsock = 'none'
	log.info("+----------------------------------------------------------------------------------------------+")
	log.info("| UDP, 1 flow, different packet sizes                                                          |")
	log.info("+--------+-----------------+----------------+----------------+----------------+----------------+")
	log.info("| Pktsize| Speed requested | Req to Generate|  Sent by Gen   | Forward by SUT |  Rec. by Gen   |")
	log.info("+--------+-----------------+----------------+----------------+----------------+----------------+")
	cores = [1]
	gencores = [1]
	speed = 100
	# To generate a desired number of flows, PROX will randomize the bits in source and destination ports, as specified by the bit masks in the flows variable. 
	sizes=[1500,1024,512,256,128,64]
	for size in sizes:
		#speed = 100 Commented out: Not starting from 100% since we are trying smaller packets, so speed will not be higher than the speed achieved in previous loop
		attempts = 0
		gensock.reset_stats()
		if sutAdminIP!='none':
			sutsock.reset_stats()
		gensock.set_size(gencores,0,size) # This is setting the frame size
		gensock.set_value(gencores,0,16,(size-18),2) # 18 is the difference between the frame size and IP size = size of (MAC addresses, ethertype and FCS)
		gensock.set_value(gencores,0,38,(size-38),2) # 38 is the difference between the frame size and UDP size = 18 + size of IP header (=20)
		# This will only work when using sending UDP packets. For different protocls and ehternet types, we would need a differnt calculation
		while (speed > 0.1):
			print(str(size)+' bytes: Measurement ongoing at speed: ' + str(round(speed,2)) + '%      ',end='\r')
			sys.stdout.flush()
			attempts += 1
			# Start generating packets at requested speed (in % of a 10Gb/s link)
			gensock.speed(speed, gencores)
			gensock.start(gencores)
			time.sleep(1)
			# Get statistics now that the generation is stable and NO ARP messages any more
			drop_rate,pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx = run_iteration(gensock,sutsock,cores,gencores)
			if ((drop_rate) < 1):
				# This will stop the test when number of dropped packets is below a certain percentage
				log.info('|{:>7}'.format(str(size))+" | "+ '{:>14}'.format(str(round(speed,2))) + '% | '+ '{:>9}'.format(str(pps_req_tx))+' Mpps | '+ '{:>9}'.format(str(pps_tx)) +' Mpps | ' + '{:>9}'.format(pps_sut_tx_str) +' Mpps | '+ '{:>9}'.format(str(pps_rx))+" Mpps |")
				log.info("+--------+-----------------+----------------+----------------+----------------+----------------+")
				break
			speed = new_speed(speed,drop_rate)
	gensock.quit()
	if sutAdminIP!='none':
		sutsock.quit()
	time.sleep(2)
#========================================================================
config = ConfigParser.RawConfigParser()
config.read(stack+'.cfg')

genAdminIP = config.get('Generator', 'admin_ip')
genDPmac = config.get('Generator', 'dp_mac')
genDPIP = config.get('Generator', 'dp_ip')
sutAdminIP = config.get('SUT', 'admin_ip')
sutDPmac = config.get('SUT', 'dp_mac')
sutDPIP = config.get('SUT', 'dp_ip')
key = config.get('OpenStack', 'key')
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

#####################################################################################
genclient = prox_ctrl(genAdminIP, key+'.pem','root')
connect_client(genclient)
genclient.scp_put('./gen.cfg', '/root/gen.cfg')
genclient.scp_put('./parameters.lua', '/root/parameters.lua')
# Creating script to bind the right network interface to the poll mode driver
with open("devbind.sh") as f:
    newText=f.read().replace('MACADDRESS', genDPmac)
with open("gendevbind.sh", "w") as f:
    f.write(newText)
st = os.stat('gendevbind.sh')
os.chmod('gendevbind.sh', st.st_mode | stat.S_IEXEC)
genclient.scp_put('./gendevbind.sh', '/root/gendevbind.sh')
cmd = '/root/gendevbind.sh'
genclient.run_cmd(cmd)
log.info("Generator Config files copied & running devbind.sh")

#####################################################################################
if sutAdminIP!='none':
	sutclient = prox_ctrl(sutAdminIP, key+'.pem','root')
	connect_client(sutclient)
	sutclient.scp_put('./sut.cfg', '/root/sut.cfg')
	sutclient.scp_put('./parameters.lua', '/root/parameters.lua')
# Creating script to bind the right network interface to the poll mode driver
	with open("devbind.sh") as f:
	    newText=f.read().replace('MACADDRESS', sutDPmac)
	with open("sutdevbind.sh", "w") as f:
	    f.write(newText)
	st = os.stat('sutdevbind.sh')
	os.chmod('sutdevbind.sh', st.st_mode | stat.S_IEXEC)
	sutclient.scp_put('./sutdevbind.sh', '/root/sutdevbind.sh')
	cmd = '/root/sutdevbind.sh'
	sutclient.run_cmd(cmd)
	log.info("SUT Config files copied & running devbind.sh")
run_speedtest()
run_flowtest()
run_sizetest()
#####################################################################################
genclient.close()
if sutAdminIP!='none':
	sutclient.close()
