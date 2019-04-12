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
import atexit
import csv

version="19.4.15"
env = "rapid" #Default string for environment
test = "basicrapid" #Default string for test
machine_map_file = "MachineMap" #Default string for machine map file
loglevel="DEBUG" # sets log level for writing to file
runtime=10 # time in seconds for 1 test run
configonly = False # IF True, the system will upload all the necessary config fiels to the VMs, but not start PROX and the actual testing

def usage():
	print("usage: runrapid    [--version] [-v]")
	print("                   [--env ENVIRONMENT_NAME]")
	print("                   [--test TEST_NAME]")
	print("                   [--map MACHINE_MAP_FILE]")
	print("                   [--runtime TIME_FOR_TEST]")
	print("                   [--configonly False|True]")
	print("                   [--log DEBUG|INFO|WARNING|ERROR|CRITICAL]")
	print("                   [-h] [--help]")
	print("")
	print("Command-line interface to runrapid")
	print("")
	print("optional arguments:")
	print("  -v,  --version           	Show program's version number and exit")
	print("  --env ENVIRONMENT_NAME       	Parameters will be read from ENVIRONMENT_NAME.env Default is %s."%env)
	print("  --test TEST_NAME       	Test cases will be read from TEST_NAME.test Default is %s."%test)
	print("  --map MACHINE_MAP_FILE	Machine mapping will be read from MACHINE_MAP_FILE.cfg Default is %s."%machine_map_file)
	print("  --runtime			Specify time in seconds for 1 test run")
	print("  --configonly			If True, only upload all config files to the VMs, do not run the tests. Default is %s."%configonly)
	print("  --log				Specify logging level for log file output, screen output level is hard coded")
	print("  -h, --help               	Show help message and exit.")
	print("")

try:
	opts, args = getopt.getopt(sys.argv[1:], "vh", ["version","help", "env=", "test=", "map=", "runtime=","configonly=","log="])
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
	if opt in ("--map"):
		machine_map_file = arg
		print ("Using '"+machine_map_file+".cfg' for machine mapping")
	if opt in ("--runtime"):
		runtime = arg
		print ("Runtime: "+ runtime)
	if opt in ("--configonly"):
		configonly = arg
		print ("configonly: "+ configonly)
	if opt in ("--log"):
		loglevel = arg
		print ("Log level: "+ loglevel)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

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
log_file = 'RUN{}.{}.log'.format(env,test)
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
	log.debug("Connected to VM on %s" % client.ip())

def run_iteration(gensock,sutsock):
	sleep_time = 3
	# Sleep_time is needed to be able to do accurate measurements to check for packet loss. We need to make this time large enough so that we do not take the first measurement while some packets from the previous tests migth still be in flight
	time.sleep(sleep_time)
	abs_old_rx, abs_old_tx, abs_old_drop, abs_old_tsc, abs_tsc_hz = gensock.core_stats(genstatcores)
	gensock.start(gencores)
	time.sleep(sleep_time)
	if sutsock!='none':
		old_sut_rx, old_sut_tx, old_sut_drop, old_sut_tsc, sut_tsc_hz = sutsock.core_stats(sutstatcores)
	old_rx, old_tx, old_drop, old_tsc, tsc_hz = gensock.core_stats(genstatcores)
	# Measure latency statistics per second
        n_loops = 0
        lat_min = 0
        lat_max = 0
        lat_avg = 0
	used_avg = 0
        while n_loops < float(runtime):
                n_loops +=1
                time.sleep(1)
                lat_min_sample, lat_max_sample, lat_avg_sample, used_sample = gensock.lat_stats(latcores)
                if lat_min > lat_min_sample:
                        lat_min = lat_min_sample
                if lat_max < lat_max_sample:
                        lat_max = lat_max_sample
                lat_avg = lat_avg + lat_avg_sample
		used_avg = used_avg + used_sample
        lat_avg = lat_avg / n_loops
	used_avg = used_avg / n_loops
	# Get statistics after some execution time
	new_rx, new_tx, new_drop, new_tsc, tsc_hz = gensock.core_stats(genstatcores)
	if sutsock!='none':
		new_sut_rx, new_sut_tx, new_sut_drop, new_sut_tsc, sut_tsc_hz = sutsock.core_stats(sutstatcores)
	#Stop generating
	gensock.stop(gencores)
	time.sleep(sleep_time)
	abs_new_rx, abs_new_tx, abs_new_drop, abs_new_tsc, abs_tsc_hz = gensock.core_stats(genstatcores)
	drop = new_drop-old_drop # drop is all packets dropped by all tasks. This includes packets dropped at the generator task + packets dropped by the nop task. In steady state, this equals to the number of packets received by this VM
	rx = new_rx - old_rx     # rx is all packets received by the nop task = all packets received in the gen VM
	tx = new_tx - old_tx     # tx is all generated packets actually accepted by the interface
	abs_dropped = (abs_new_tx - abs_old_tx) - (abs_new_rx - abs_old_rx)
	tsc = new_tsc - old_tsc  # time difference between the 2 measurements, expressed in cycles.
	pps_req_tx = (tx+drop-rx)*tsc_hz*1.0/(tsc*1000000)
	pps_tx = tx*tsc_hz*1.0/(tsc*1000000)
	pps_rx = rx*tsc_hz*1.0/(tsc*1000000)
	if sutsock!='none':
		sut_rx = new_sut_rx - old_sut_rx
		sut_tx = new_sut_tx - old_sut_tx
		sut_tsc = new_sut_tsc - old_sut_tsc
		pps_sut_tx = sut_tx*sut_tsc_hz*1.0/(sut_tsc*1000000)
		pps_sut_tx_str = '{:>9.3f}'.format(pps_sut_tx)
	else:
		pps_sut_tx = 0
		pps_sut_tx_str = 'NO MEAS.'
	if (tx == 0):
        	log.critical("TX = 0. Test interrupted since no packet has been sent.")
		raise Exception("TX = 0")
	return(pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx,lat_avg,lat_max,abs_dropped,(abs_new_tx - abs_old_tx),lat_min,used_avg)

def new_speed(speed,minspeed,maxspeed,success):
	if success:
		minspeed = speed
	else:
		maxspeed = speed
	newspeed = (maxspeed+minspeed)/2.0
	return (newspeed,minspeed,maxspeed)

def get_pps(speed,size):
	return (speed * 100.0 / (8*(size+24)))

def run_speedtest(gensock,sutsock):
	maxspeed = speed = STARTSPEED
	minspeed = 0
	size=PACKETSIZE-4
	attempts = 0
        log.info("+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+")
        log.info("| Generator is sending UDP (1 flow) packets ("+ '{:>5}'.format(size+4) +" bytes) to SUT. SUT sends packets back                                                                                       |")
	log.info("+--------+--------------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+------------+------------+")
	log.info("| Test   |  Speed requested   | Sent to NIC    |  Sent by Gen   | Forward by SUT |  Rec. by Gen   |  Avg. Latency  |  Max. Latency  |  Packets Lost  | Loss Ratio | Result     |")
	log.info("+--------+--------------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+------------+------------+")
	endpps_sut_tx_str = 'NO_RESULTS'
	gensock.set_size(gencores,0,size) # This is setting the frame size
	gensock.set_value(gencores,0,16,(size-14),2) # 18 is the difference between the frame size and IP size = size of (MAC addresses, ethertype and FCS)
	gensock.set_value(gencores,0,38,(size-34),2) # 38 is the difference between the frame size and UDP size = 18 + size of IP header (=20)
	# This will only work when using sending UDP packets. For different protocols and ethernet types, we would need a different calculation
	gensock.start(latcores)
        while (maxspeed-minspeed > ACCURACY):
                attempts += 1
                print('Measurement ongoing at speed: ' + str(round(speed,2)) + '%      ',end='\r')
                sys.stdout.flush()
                # Start generating packets at requested speed (in % of a 10Gb/s link)
		gensock.speed(speed / len(gencores), gencores)
                time.sleep(1)
                # Get statistics now that the generation is stable and initial ARP messages are dealt with.
		pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx,lat_avg,lat_max, abs_dropped, abs_tx, lat_min, lat_used = run_iteration(gensock,sutsock)
		drop_rate = 100.0*abs_dropped/abs_tx
		if lat_used < 0.95:
			lat_warning = bcolors.FAIL + ' Potential latency accuracy problem: {:>3.0f}%'.format(lat_used*100) +  bcolors.ENDC
		else:
			lat_warning = ''
        	if ((get_pps(speed,size) - pps_tx)/get_pps(speed,size))<0.001 and ((drop_rate < DROP_RATE_TRESHOLD) or (abs_dropped==DROP_RATE_TRESHOLD ==0)) and (lat_avg< LAT_AVG_TRESHOLD) and (lat_max < LAT_MAX_TRESHOLD):
	                log.info('|{:>7}'.format(str(attempts))+" | " + '{:>5.1f}'.format(speed) + '% ' +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps | '+ '{:>9.3f}'.format(pps_req_tx)+' Mpps | '+ '{:>9.3f}'.format(pps_tx) +' Mpps | ' + '{:>9}'.format(pps_sut_tx_str) +' Mpps | '+ '{:>9.3f}'.format(pps_rx)+' Mpps | '+ '{:>9.0f}'.format(lat_avg)+' us   | '+  '{:>9.0f}'.format(lat_max)+' us   | '+ '{:>14d}'.format(abs_dropped)+ ' |''{:>9.2f}'.format(drop_rate)+ '%  | SUCCESS    |'+lat_warning)
			endspeed = speed
			endpps_req_tx = pps_req_tx
			endpps_tx = pps_tx
			endpps_sut_tx_str = pps_sut_tx_str
			endpps_rx = pps_rx
			endlat_avg = lat_avg
			endlat_max = lat_max
			endabs_dropped = abs_dropped
			enddrop_rate = drop_rate
			endwarning = lat_warning
			success = True 
	        else:
			abs_drop_rate_prefix = bcolors.ENDC
			if ((abs_dropped>0) and (DROP_RATE_TRESHOLD ==0)):
				abs_drop_rate_prefix = bcolors.FAIL
			if (drop_rate < DROP_RATE_TRESHOLD):
				drop_rate_prefix = bcolors.ENDC
			else:
				drop_rate_prefix = bcolors.FAIL
			if (lat_avg< LAT_AVG_TRESHOLD):
				lat_avg_prefix = bcolors.ENDC
			else:
				lat_avg_prefix = bcolors.FAIL
			if (lat_max< LAT_MAX_TRESHOLD):
				lat_max_prefix = bcolors.ENDC
			else:
				lat_max_prefix = bcolors.FAIL
			if (((get_pps(speed,size) - pps_tx)/get_pps(speed,size))<0.001):
				speed_prefix = bcolors.ENDC
			else:
				speed_prefix = bcolors.FAIL
	                log.info('|{:>7}'.format(str(attempts))+" | " + '{:>5.1f}'.format(speed) + '% '+speed_prefix +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps | '+ '{:>9.3f}'.format(pps_req_tx)+' Mpps | ' + '{:>9.3f}'.format(pps_tx) +' Mpps | '+ bcolors.ENDC  + '{:>9}'.format(pps_sut_tx_str) +' Mpps | '+ '{:>9.3f}'.format(pps_rx)+' Mpps | '+lat_avg_prefix+ '{:>9.0f}'.format(lat_avg)+' us   | '+lat_max_prefix+ '{:>9.0f}'.format(lat_max)+' us   | '+ abs_drop_rate_prefix + '{:>14d}'.format(abs_dropped)+drop_rate_prefix+ ' |''{:>9.2f}'.format(drop_rate)+bcolors.ENDC+ '%  | FAILED     |'+lat_warning)
			success = False 
		speed,minspeed,maxspeed = new_speed(speed,minspeed,maxspeed,success)
	if endpps_sut_tx_str <>  'NO_RESULTS':
		log.info("+--------+--------------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+------------+------------+")
                log.info('|{:>7}'.format('END')+" | " + '{:>5.1f}'.format(endspeed) + '% ' +'{:>6.3f}'.format(get_pps(endspeed,size)) + ' Mpps | '+ '{:>9.3f}'.format(endpps_req_tx)+' Mpps | '+ '{:>9.3f}'.format(endpps_tx) +' Mpps | ' + '{:>9}'.format(endpps_sut_tx_str) +' Mpps | '+ '{:>9.3f}'.format(endpps_rx)+' Mpps | '+ '{:>9.0f}'.format(endlat_avg)+' us   | '+ '{:>9.0f}'.format(endlat_max)+' us   | '+'{:>14d}'.format(endabs_dropped)+ ' |''{:>9.2f}'.format(enddrop_rate)+ '%  | SUCCESS    |'+endwarning)
		log.info("+--------+--------------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+------------+------------+")
		writer.writerow({'flow':'1','size':(size+4),'endspeed':endspeed,'endspeedpps':get_pps(endspeed,size),'endpps_req_tx':endpps_req_tx,'endpps_tx':endpps_tx,'endpps_sut_tx_str':endpps_sut_tx_str,'endpps_rx':endpps_rx,'endlat_avg':endlat_avg,'endlat_max':endlat_max,'endabs_dropped':endabs_dropped,'enddrop_rate':enddrop_rate})
	else:
		log.info('| Speed 0 or close to 0')
	gensock.stop(latcores)

def run_flowtest(gensock,sutsock):
	size=PACKETSIZE-4
	log.info("+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+")
	log.info("| UDP, "+ '{:>5}'.format(size+4) +" bytes, different number of flows by randomizing SRC & DST UDP port                                                                                   |")
	log.info("+--------+--------------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+------------+")
	log.info("| Flows  |  Speed requested   | Sent to NIC    |  Sent by Gen   | Forward by SUT |  Rec. by Gen   |  Avg. Latency  |  Max. Latency  |  Packets Lost  | Loss Ratio |")
	log.info("+--------+--------------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+------------+")
	# To generate a desired number of flows, PROX will randomize the bits in source and destination ports, as specified by the bit masks in the flows variable. 
	flows={\
	1:      ['1000000000000000','1000000000000000'],\
	2:      ['1000000000000000','100000000000000X'],\
	4:      ['100000000000000X','100000000000000X'],\
	8:      ['100000000000000X','10000000000000XX'],\
	16:     ['10000000000000XX','10000000000000XX'],\
	32:     ['10000000000000XX','1000000000000XXX'],\
	64:     ['1000000000000XXX','1000000000000XXX'],\
	128:    ['1000000000000XXX','100000000000XXXX'],\
	256:    ['100000000000XXXX','100000000000XXXX'],\
	512:    ['100000000000XXXX','10000000000XXXXX'],\
	1024:   ['10000000000XXXXX','10000000000XXXXX'],\
	2048:   ['10000000000XXXXX','1000000000XXXXXX'],\
	4096:   ['1000000000XXXXXX','1000000000XXXXXX'],\
	8192:   ['1000000000XXXXXX','100000000XXXXXXX'],\
	16384:  ['100000000XXXXXXX','100000000XXXXXXX'],\
	32768:  ['100000000XXXXXXX','10000000XXXXXXXX'],\
	65535:  ['10000000XXXXXXXX','10000000XXXXXXXX'],\
	131072: ['10000000XXXXXXXX','1000000XXXXXXXXX'],\
	262144: ['1000000XXXXXXXXX','1000000XXXXXXXXX'],\
	524280: ['1000000XXXXXXXXX','100000XXXXXXXXXX'],\
	1048576:['100000XXXXXXXXXX','100000XXXXXXXXXX'],}
	gensock.set_size(gencores,0,size) # This is setting the frame size
	gensock.set_value(gencores,0,16,(size-14),2) # 18 is the difference between the frame size and IP size = size of (MAC addresses, ethertype and FCS)
	gensock.set_value(gencores,0,38,(size-34),2) # 38 is the difference between the frame size and UDP size = 18 + size of IP header (=20)
	# This will only work when using sending UDP packets. For different protocls and ehternet types, we would need a differnt calculation
	gensock.start(latcores)
	for flow_number in flow_size_list:
		attempts = 0
		gensock.reset_stats()
		if sutsock!='none':
			sutsock.reset_stats()
		source_port,destination_port = flows[flow_number]
		gensock.set_random(gencores,0,34,source_port,2)
		gensock.set_random(gencores,0,36,destination_port,2)
		endpps_sut_tx_str = 'NO_RESULTS'
		maxspeed = speed = STARTSPEED
		minspeed = 0
		while (maxspeed-minspeed > ACCURACY):
                	attempts += 1
			print(str(flow_number)+' flows: Measurement ongoing at speed: ' + str(round(speed,2)) + '%      ',end='\r')
			sys.stdout.flush()
			# Start generating packets at requested speed (in % of a 10Gb/s link)
			gensock.speed(speed / len(gencores), gencores)
			time.sleep(1)
			# Get statistics now that the generation is stable and initial ARP messages are dealt with
			pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx,lat_avg,lat_max, abs_dropped, abs_tx, lat_min, lat_used = run_iteration(gensock,sutsock)
			drop_rate = 100.0*abs_dropped/abs_tx
			if lat_used < 0.95:
				lat_warning = bcolors.FAIL + ' Potential latency accuracy problem: {:>3.0f}%'.format(lat_used*100) +  bcolors.ENDC
			else:
				lat_warning = ''
	        	if ((get_pps(speed,size) - pps_tx)/get_pps(speed,size))<0.001 and ((drop_rate < DROP_RATE_TRESHOLD) or (abs_dropped==DROP_RATE_TRESHOLD ==0)) and (lat_avg< LAT_AVG_TRESHOLD) and (lat_max < LAT_MAX_TRESHOLD):
	                	log.debug('|{:>7}'.format(str(attempts))+" | " + '{:>5.1f}'.format(speed) + '% ' +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps | '+ '{:>9.3f}'.format(pps_req_tx)+' Mpps | '+ '{:>9.3f}'.format(pps_tx) +' Mpps | ' + '{:>9}'.format(pps_sut_tx_str) +' Mpps | '+ '{:>9.3f}'.format(pps_rx)+' Mpps | '+ '{:>9.0f}'.format(lat_avg)+' us   | '+  '{:>9.0f}'.format(lat_max)+' us   | '+ '{:>14d}'.format(abs_dropped)+ ' |''{:>9.2f}'.format(drop_rate)+ '%  | SUCCESS    |'+lat_warning)
				endspeed = speed
				endpps_req_tx = pps_req_tx
				endpps_tx = pps_tx
				endpps_sut_tx_str = pps_sut_tx_str
				endpps_rx = pps_rx
				endlat_avg = lat_avg 
				endlat_max = lat_max 
				endabs_dropped = abs_dropped
				enddrop_rate = drop_rate
				endwarning = lat_warning
				success = True
			else:
				abs_drop_rate_prefix = bcolors.ENDC
				if ((abs_dropped>0) and (DROP_RATE_TRESHOLD ==0)):
					abs_drop_rate_prefix = bcolors.FAIL
				if (drop_rate < DROP_RATE_TRESHOLD):
					drop_rate_prefix = bcolors.ENDC
				else:
					drop_rate_prefix = bcolors.FAIL
				if (lat_avg< LAT_AVG_TRESHOLD):
					lat_avg_prefix = bcolors.ENDC
				else:
					lat_avg_prefix = bcolors.FAIL
				if (lat_max< LAT_MAX_TRESHOLD):
					lat_max_prefix = bcolors.ENDC
				else:
					lat_max_prefix = bcolors.FAIL
				if (((get_pps(speed,size) - pps_tx)/get_pps(speed,size))<0.001):
					speed_prefix = bcolors.ENDC
				else:
					speed_prefix = bcolors.FAIL
				log.debug('|{:>7}'.format(str(attempts))+" | " + '{:>5.1f}'.format(speed) + '% '+speed_prefix +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps | '+ '{:>9.3f}'.format(pps_req_tx)+' Mpps | ' + '{:>9.3f}'.format(pps_tx) +' Mpps | '+ bcolors.ENDC  + '{:>9}'.format(pps_sut_tx_str) +' Mpps | '+ '{:>9.3f}'.format(pps_rx)+' Mpps | '+lat_avg_prefix+ '{:>9.0f}'.format(lat_avg)+' us   | '+lat_max_prefix+ '{:>9.0f}'.format(lat_max)+' us   | '+ abs_drop_rate_prefix + '{:>14d}'.format(abs_dropped)+drop_rate_prefix+ ' |''{:>9.2f}'.format(drop_rate)+bcolors.ENDC+ '%  | FAILED     |'+lat_warning)
				success = False 
			speed,minspeed,maxspeed = new_speed(speed,minspeed,maxspeed,success)
		if endpps_sut_tx_str <>  'NO_RESULTS':
                	log.info('|{:>7}'.format(str(flow_number))+" | " + '{:>5.1f}'.format(endspeed) + '% ' +'{:>6.3f}'.format(get_pps(endspeed,size)) + ' Mpps | '+ '{:>9.3f}'.format(endpps_req_tx)+' Mpps | '+ '{:>9.3f}'.format(endpps_tx) +' Mpps | ' + '{:>9}'.format(endpps_sut_tx_str) +' Mpps | '+ '{:>9.3f}'.format(endpps_rx)+' Mpps | '+ '{:>9.0f}'.format(endlat_avg)+' us   | '+ '{:>9.0f}'.format(endlat_max)+' us   | '+ '{:>14d}'.format(endabs_dropped)+ ' |'+'{:>9.2f}'.format(enddrop_rate)+ '%  |'+endwarning)
			log.info("+--------+--------------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+------------+")
			writer.writerow({'flow':flow_number,'size':(size+4),'endspeed':endspeed,'endspeedpps':get_pps(endspeed,size),'endpps_req_tx':endpps_req_tx,'endpps_tx':endpps_tx,'endpps_sut_tx_str':endpps_sut_tx_str,'endpps_rx':endpps_rx,'endlat_avg':endlat_avg,'endlat_max':endlat_max,'endabs_dropped':endabs_dropped,'enddrop_rate':enddrop_rate})
		else:
			log.info('|{:>7}'.format(str(flow_number))+" | Speed 0 or close to 0")
	gensock.stop(latcores)

def run_sizetest(gensock,sutsock):
	log.info("+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+")
	log.info("| UDP, 1 flow, different packet sizes                                                                                                                             |")
	log.info("+--------+--------------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+------------+")
	log.info("| Pktsize|  Speed requested   | Sent to NIC    |  Sent by Gen   | Forward by SUT |  Rec. by Gen   |  Avg. Latency  |  Max. Latency  |  Packets Lost  | Loss Ratio |")
	log.info("+--------+--------------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+------------+")
	gensock.start(latcores)
	for size in packet_size_list:
		size = size-4
		attempts = 0
		gensock.reset_stats()
		if sutsock!='none':
			sutsock.reset_stats()
		gensock.set_size(gencores,0,size) # This is setting the frame size
		gensock.set_value(gencores,0,16,(size-14),2) # 18 is the difference between the frame size and IP size = size of (MAC addresses, ethertype and FCS)
		gensock.set_value(gencores,0,38,(size-34),2) # 38 is the difference between the frame size and UDP size = 18 + size of IP header (=20)
		# This will only work when using sending UDP packets. For different protocls and ehternet types, we would need a differnt calculation
		endpps_sut_tx_str = 'NO_RESULTS'
		maxspeed = speed = STARTSPEED
		minspeed = 0
		while (maxspeed-minspeed > ACCURACY):
                	attempts += 1
			print(str(size+4)+' bytes: Measurement ongoing at speed: ' + str(round(speed,2)) + '%      ',end='\r')
			sys.stdout.flush()
			# Start generating packets at requested speed (in % of a 10Gb/s link)
			gensock.speed(speed / len(gencores), gencores)
			# Get statistics now that the generation is stable and initial ARP messages are dealt with
			pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx,lat_avg,lat_max, abs_dropped, abs_tx, lat_min, lat_used = run_iteration(gensock,sutsock)
			drop_rate = 100.0*abs_dropped/abs_tx
			if lat_used < 0.95:
				lat_warning = bcolors.FAIL + ' Potential latency accuracy problem: {:>3.0f}%'.format(lat_used*100) +  bcolors.ENDC
			else:
				lat_warning = ''
	        	if ((get_pps(speed,size) - pps_tx)/get_pps(speed,size))<0.001 and ((drop_rate < DROP_RATE_TRESHOLD) or (abs_dropped==DROP_RATE_TRESHOLD ==0)) and (lat_avg< LAT_AVG_TRESHOLD) and (lat_max < LAT_MAX_TRESHOLD):
	                	log.debug('|{:>7}'.format(str(attempts))+" | " + '{:>5.1f}'.format(speed) + '% ' +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps | '+ '{:>9.3f}'.format(pps_req_tx)+' Mpps | '+ '{:>9.3f}'.format(pps_tx) +' Mpps | ' + '{:>9}'.format(pps_sut_tx_str) +' Mpps | '+ '{:>9.3f}'.format(pps_rx)+' Mpps | '+ '{:>9.0f}'.format(lat_avg)+' us   | '+  '{:>9.0f}'.format(lat_max)+' us   | '+ '{:>14d}'.format(abs_dropped)+ ' |''{:>9.2f}'.format(drop_rate)+ '%  | SUCCESS    |'+lat_warning)
				endspeed = speed
				endpps_req_tx = pps_req_tx
				endpps_tx = pps_tx
				endpps_sut_tx_str = pps_sut_tx_str
				endpps_rx = pps_rx
				endlat_avg = lat_avg 
				endlat_max = lat_max 
				endabs_dropped = abs_dropped
				enddrop_rate = drop_rate
				endwarning = lat_warning
				success = True
			else:
				abs_drop_rate_prefix = bcolors.ENDC
				if ((abs_dropped>0) and (DROP_RATE_TRESHOLD ==0)):
					abs_drop_rate_prefix = bcolors.FAIL
				if (drop_rate < DROP_RATE_TRESHOLD):
					drop_rate_prefix = bcolors.ENDC
				else:
					drop_rate_prefix = bcolors.FAIL
				if (lat_avg< LAT_AVG_TRESHOLD):
					lat_avg_prefix = bcolors.ENDC
				else:
					lat_avg_prefix = bcolors.FAIL
				if (lat_max< LAT_MAX_TRESHOLD):
					lat_max_prefix = bcolors.ENDC
				else:
					lat_max_prefix = bcolors.FAIL
				if (((get_pps(speed,size) - pps_tx)/get_pps(speed,size))<0.001):
					speed_prefix = bcolors.ENDC
				else:
					speed_prefix = bcolors.FAIL
				log.debug('|{:>7}'.format(str(attempts))+" | " + '{:>5.1f}'.format(speed) + '% '+speed_prefix +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps | '+ '{:>9.3f}'.format(pps_req_tx)+' Mpps | ' + '{:>9.3f}'.format(pps_tx) +' Mpps | '+ bcolors.ENDC  + '{:>9}'.format(pps_sut_tx_str) +' Mpps | '+ '{:>9.3f}'.format(pps_rx)+' Mpps | '+lat_avg_prefix+ '{:>9.0f}'.format(lat_avg)+' us   | '+lat_max_prefix+ '{:>9.0f}'.format(lat_max)+' us   | '+ abs_drop_rate_prefix + '{:>14d}'.format(abs_dropped)+drop_rate_prefix+ ' |''{:>9.2f}'.format(drop_rate)+bcolors.ENDC+ '%  | FAILED     |'+ lat_warning)
				success = False 
			speed,minspeed,maxspeed = new_speed(speed,minspeed,maxspeed,success)
		if endpps_sut_tx_str <>  'NO_RESULTS':
                	log.info('|{:>7}'.format(size+4)+" | " + '{:>5.1f}'.format(endspeed) + '% ' +'{:>6.3f}'.format(get_pps(endspeed,size)) + ' Mpps | '+ '{:>9.3f}'.format(endpps_req_tx)+' Mpps | '+ '{:>9.3f}'.format(endpps_tx) +' Mpps | ' + '{:>9}'.format(endpps_sut_tx_str) +' Mpps | '+ '{:>9.3f}'.format(endpps_rx)+' Mpps | '+ '{:>9.0f}'.format(endlat_avg)+' us   | '+'{:>9.0f}'.format(endlat_max)+' us   | '+ '{:>14d}'.format(endabs_dropped)+ ' |'+'{:>9.2f}'.format(enddrop_rate)+ '%  |'+ endwarning)
        		log.info("+--------+--------------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+------------+")
			writer.writerow({'flow':'1','size':(size+4),'endspeed':endspeed,'endspeedpps':get_pps(endspeed,size),'endpps_req_tx':endpps_req_tx,'endpps_tx':endpps_tx,'endpps_sut_tx_str':endpps_sut_tx_str,'endpps_rx':endpps_rx,'endlat_avg':endlat_avg,'endlat_max':endlat_max,'endabs_dropped':endabs_dropped,'enddrop_rate':enddrop_rate})
		else:
			log.debug('|{:>7}'.format(str(size))+" | Speed 0 or close to 0")
	gensock.stop(latcores)

def run_max_frame_rate(gensock,sutsock):
        log.info("+-----------------------------------------------------------------------------------------------------------------------------------------------------------+")
        log.info("| UDP, 1 flow, different packet sizes                                                                                                                       |")
        log.info("+-----+------------------+-------------+-------------+-------------+-------------+-------------+-------------+-----------+-----------+---------+------------+")
        log.info("|Pktsz| Speed requested  | Sent to NIC | Sent by Gen | Fwrd by SUT | Rec. by Gen | Avg. Latency| Max. Latency|   Sent    |  Received |  Lost   | Total Lost |")
        log.info("+-----+------------------+-------------+-------------+-------------+-------------+-------------+-------------+-----------+-----------+---------+------------+")
        sleep_time = 3
	gensock.start(latcores)
	for size in packet_size_list:
                # Sleep_time is needed to be able to do accurate measurements to check for packet loss. We need to make this time large enough so that we do not take the first measurement while some packets from the previous tests migth still be in flight
                time.sleep(sleep_time)
		size = size-4
                gensock.reset_stats()
                if sutsock!='none':
                        sutsock.reset_stats()
                gensock.set_size(gencores,0,size) # This is setting the frame size
                gensock.set_value(gencores,0,16,(size-14),2) # 18 is the difference between the frame size and IP size = size of (MAC addresses, ethertype and FCS)
                gensock.set_value(gencores,0,38,(size-34),2) # 38 is the difference between the frame size and UDP size = 18 + size of IP header (=20)
                # This will only work when using sending UDP packets. For different protocls and ehternet types, we would need a differnt calculation
                pps_sut_tx_str = 'NO_RESULTS'
                speed = STARTSPEED
                # Start generating packets at requested speed (in % of a 10Gb/s link)
                gensock.speed(speed / len(gencores), gencores)
                duration = float(runtime)
                first = 1
                tot_drop = 0
                if sutsock!='none':
                        old_sut_rx, old_sut_tx, old_sut_drop, old_sut_tsc, sut_tsc_hz = sutsock.core_stats(sutstatcores)
                old_rx, old_tx, old_drop, old_tsc, tsc_hz = gensock.core_stats(genstatcores)
                gensock.start(gencores)
                while (duration > 0):
                        time.sleep(0.5)
                        lat_min, lat_max, lat_avg, lat_used = gensock.lat_stats(latcores)
			if lat_used < 0.95:
				lat_warning = bcolors.FAIL + ' Potential latency accuracy problem: {:>3.0f}%'.format(lat_used*100) +  bcolors.ENDC
			else:
				lat_warning = ''
                        # Get statistics after some execution time
                        new_rx, new_tx, new_drop, new_tsc, tsc_hz = gensock.core_stats(genstatcores)
                        if sutsock!='none':
                                new_sut_rx, new_sut_tx, new_sut_drop, new_sut_tsc, sut_tsc_hz = sutsock.core_stats(sutstatcores)
                        drop = new_drop-old_drop # drop is all packets dropped by all tasks. This includes packets dropped at the generator task + packets dropped by the nop task. In steady state, this equals to the number of packets received by this VM
                        rx = new_rx - old_rx     # rx is all packets received by the nop task = all packets received in the gen VM
                        tx = new_tx - old_tx     # tx is all generated packets actually accepted by the interface
                        tsc = new_tsc - old_tsc  # time difference between the 2 measurements, expressed in cycles.
			if tsc == 0 :
				continue
                        if sutsock!='none':
                                sut_rx = new_sut_rx - old_sut_rx
                                sut_tx = new_sut_tx - old_sut_tx
                                sut_tsc = new_sut_tsc - old_sut_tsc
				if sut_tsc == 0 :
					continue
                        duration = duration - 1
                        old_drop = new_drop
                        old_rx = new_rx
                        old_tx = new_tx
                        old_tsc = new_tsc
                        pps_req_tx = (tx+drop-rx)*tsc_hz*1.0/(tsc*1000000)
                        pps_tx = tx*tsc_hz*1.0/(tsc*1000000)
                        pps_rx = rx*tsc_hz*1.0/(tsc*1000000)
                        if sutsock!='none':
                                old_sut_tx = new_sut_tx
                                old_sut_rx = new_sut_rx
                                old_sut_tsc= new_sut_tsc
                                pps_sut_tx = sut_tx*sut_tsc_hz*1.0/(sut_tsc*1000000)
                                pps_sut_tx_str = '{:>7.3f}'.format(pps_sut_tx)
                        else:
                                pps_sut_tx = 0
                                pps_sut_tx_str = 'NO MEAS.'
                        if (tx == 0):
                                log.critical("TX = 0. Test interrupted since no packet has been sent.")
                                raise Exception("TX = 0")
                        tot_drop = tot_drop + tx - rx

                        if pps_sut_tx_str <>  'NO_RESULTS':
                                # First second mpps are not valid as there is no alignement between time the generator is started and per seconds stats
                                if (first):
                                        log.info('|{:>4}'.format(size+4)+" |" + '{:>5.1f}'.format(speed) + '% ' +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps|'+'             |' +'             |'  +'             |'+ '             |'+ '{:>8.0f}'.format(lat_avg)+' us  |'+'{:>8.0f}'.format(lat_max)+' us  | ' + '{:>9.0f}'.format(tx) + ' | '+ '{:>9.0f}'.format(rx) + ' | '+ '{:>7.0f}'.format(tx-rx) + ' | '+'{:>7.0f}'.format(tot_drop) +'    |'+lat_warning)
                                else:
                                        log.info('|{:>4}'.format(size+4)+" |" + '{:>5.1f}'.format(speed) + '% ' +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps|'+ '{:>7.3f}'.format(pps_req_tx)+' Mpps |'+ '{:>7.3f}'.format(pps_tx) +' Mpps |' + '{:>7}'.format(pps_sut_tx_str) +' Mpps |'+ '{:>7.3f}'.format(pps_rx)+' Mpps |'+ '{:>8.0f}'.format(lat_avg)+' us  |'+'{:>8.0f}'.format(lat_max)+' us  | ' + '{:>9.0f}'.format(tx) + ' | '+ '{:>9.0f}'.format(rx) + ' | '+ '{:>7.0f}'.format(tx-rx) + ' | '+ '{:>7.0f}'.format(tot_drop) +'    |'+lat_warning)
                        else:
                                log.debug('|{:>7}'.format(str(size))+" | Speed 0 or close to 0")
                        first = 0
                        if (duration <= 0):
                                #Stop generating
                                gensock.stop(gencores)
                                time.sleep(sleep_time)
                                lat_min, lat_max, lat_avg, lat_used = gensock.lat_stats(latcores)
				if lat_used < 0.95:
					lat_warning = bcolors.FAIL + ' Potential latency accuracy problem: {:>3.0f}%'.format(lat_used*100) +  bcolors.ENDC
				else:
					lat_warning = ''
                                # Get statistics after some execution time
                                new_rx, new_tx, new_drop, new_tsc, tsc_hz = gensock.core_stats(genstatcores)
                                if sutsock!='none':
                                        new_sut_rx, new_sut_tx, new_sut_drop, new_sut_tsc, sut_tsc_hz = sutsock.core_stats(sutstatcores)
                                drop = new_drop-old_drop # drop is all packets dropped by all tasks. This includes packets dropped at the generator task + packets dropped by the nop task. In steady state, this equals to the number of packets received by this VM
                                rx = new_rx - old_rx     # rx is all packets received by the nop task = all packets received in the gen VM
                                tx = new_tx - old_tx     # tx is all generated packets actually accepted by the interface
                                tsc = new_tsc - old_tsc  # time difference between the 2 measurements, expressed in cycles.
                                tot_drop = tot_drop + tx - rx
                                if sutsock!='none':
                                        sut_rx = new_sut_rx - old_sut_rx
                                        sut_tx = new_sut_tx - old_sut_tx
                                        sut_tsc = new_sut_tsc - old_sut_tsc
                                if pps_sut_tx_str <>  'NO_RESULTS':
                                        log.info('|{:>4}'.format(size+4)+" |" + '{:>5.1f}'.format(speed) + '% ' +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps|'+'             |' +'             |'  +'             |'+ '             |'+ '{:>8.0f}'.format(lat_avg)+' us  |'+'{:>8.0f}'.format(lat_max)+' us  | ' + '{:>9.0f}'.format(tx) + ' | '+ '{:>9.0f}'.format(rx) + ' | '+ '{:>7.0f}'.format(tx-rx) + ' | '+ '{:>7.0f}'.format(tot_drop) +'    |'+lat_warning)
                log.info("+-----+------------------+-------------+-------------+-------------+-------------+-------------+-------------+-----------+-----------+---------+------------+")
	gensock.stop(latcores)



def run_irqtest(sock):
        log.info("+----------------------------------------------------------------------------------------------------------------------------")
        log.info("| Measuring time probably spent dealing with an interrupt. Interrupting DPDK cores for more than 50us might be problematic   ")
        log.info("| and result in packet loss. The first row shows the interrupted time buckets: first number is the bucket between 0us and    ")
	log.info("| that number expressed in us and so on. The numbers in the other rows show how many times per second, the program was       ")
        log.info("| interrupted for a time as specified by its bucket. '0' is printed when there are no interrupts in this bucket throughout   ")
        log.info("| the duration of the test. This is to avoid rounding errors in the case of 0.0                                              ") 
        log.info("+----------------------------------------------------------------------------------------------------------------------------")
        sys.stdout.flush()
	buckets=sock.show_irq_buckets(1)
        print('Measurement ongoing ... ',end='\r')
	sock.stop(irqcores)
	old_irq = [[0 for x in range(len(buckets)+1)] for y in range(len(irqcores)+1)] 
	irq = [[0 for x in range(len(buckets)+1)] for y in range(len(irqcores)+1)]
	irq[0][0] = 'bucket us' 
	for j,bucket in enumerate(buckets,start=1):
		irq[0][j] = '<'+ bucket
	irq[0][-1] = '>'+ buckets [-2]
	sock.start(irqcores)
	time.sleep(2)
	for j,bucket in enumerate(buckets,start=1):
		for i,irqcore in enumerate(irqcores,start=1):
			old_irq[i][j] = sock.irq_stats(irqcore,j-1)
	time.sleep(float(runtime))
	sock.stop(irqcores)
	for i,irqcore in enumerate(irqcores,start=1):
		irq[i][0]='core %s '%irqcore
		for j,bucket in enumerate(buckets,start=1):
			diff =  sock.irq_stats(irqcore,j-1) - old_irq[i][j]
			if diff == 0:
				irq[i][j] = '0'
			else:
				irq[i][j] = str(round(diff/float(runtime), 2))
	for row in irq:
		log.info(''.join(['{:>12}'.format(item) for item in row]))
#	log.info('\n'.join([''.join(['{:>12}'.format(item) for item in row]) for row in irq]))

def run_impairtest(gensock,sutsock):
	size=PACKETSIZE-4
        log.info("+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+")
        log.info("| Generator is sending UDP (1 flow) packets ("+ '{:>5}'.format(size+4) +" bytes) to SUT via GW dropping and delaying packets. SUT sends packets back. Use ctrl-c to stop the test        |")
	log.info("+--------+--------------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+------------+")
	log.info("| Test   |  Speed requested   | Sent to NIC    |  Sent by Gen   | Forward by SUT |  Rec. by Gen   |  Avg. Latency  |  Max. Latency  |  Packets Lost  | Loss Ratio |")
	log.info("+--------+--------------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+------------+")
	attempts = 0
	gensock.set_size(gencores,0,size) # This is setting the frame size
	gensock.set_value(gencores,0,16,(size-14),2) # 18 is the difference between the frame size and IP size = size of (MAC addresses, ethertype and FCS)
	gensock.set_value(gencores,0,38,(size-34),2) # 38 is the difference between the frame size and UDP size = 18 + size of IP header (=20)
	# This will only work when using sending UDP packets. For different protocols and ethernet types, we would need a different calculation
	gensock.start(latcores)
	speed = STARTSPEED
	gensock.speed(speed / len(gencores), gencores)
        while True:
                attempts += 1
                print('Measurement ongoing at speed: ' + str(round(speed,2)) + '%      ',end='\r')
                sys.stdout.flush()
                time.sleep(1)
                # Get statistics now that the generation is stable and NO ARP messages any more
		pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx,lat_avg,lat_max, abs_dropped, abs_tx, lat_min, lat_used = run_iteration(gensock,sutsock)
		drop_rate = 100.0*abs_dropped/abs_tx
		if lat_used < 0.95:
			lat_warning = bcolors.FAIL + ' Potential latency accuracy problem: {:>3.0f}%'.format(lat_used*100) +  bcolors.ENDC
		else:
			lat_warning = ''
	        log.info('|{:>7}'.format(str(attempts))+" | " + '{:>5.1f}'.format(speed) + '% ' +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps | '+ '{:>9.3f}'.format(pps_req_tx)+' Mpps | '+ '{:>9.3f}'.format(pps_tx) +' Mpps | ' + '{:>9}'.format(pps_sut_tx_str) +' Mpps | '+ '{:>9.3f}'.format(pps_rx)+' Mpps | '+ '{:>9.0f}'.format(lat_avg)+' us   | '+ '{:>9.0f}'.format(lat_max)+' us   | '+ '{:>14d}'.format(abs_dropped)+ ' |''{:>9.2f}'.format(drop_rate)+ '%  |'+lat_warning)
		writer.writerow({'flow':'1','size':(size+4),'endspeed':speed,'endspeedpps':get_pps(speed,size),'endpps_req_tx':pps_req_tx,'endpps_tx':pps_tx,'endpps_sut_tx_str':pps_sut_tx_str,'endpps_rx':pps_rx,'endlat_avg':lat_avg,'endlat_max':lat_max,'endabs_dropped':abs_dropped,'enddrop_rate':drop_rate})
	gensock.stop(latcores)

def run_inittest(gensock):
# Running at low speed to make sure the ARP messages can get through.
# If not doing this, the ARP message could be dropped by a switch in overload and then the test will not give proper results
# Note hoever that if we would run the test steps during a very long time, the ARP would expire in the switch.
# PROX will send a new ARP request every seconds so chances are very low that they will all fail to get through
	gensock.speed(0.01 / len(gencores), gencores)
	gensock.start(genstatcores)
	time.sleep(2)
	gensock.stop(genstatcores)

global sutstatcores
global genstatcores
global latcores
global gencores
global irqcores
global PACKETSIZE
global packet_size_list
global flow_size_list
global required_number_of_test_machines
clients =[]
socks =[]
socks_control =[]
vmDPIP =[]
vmAdminIP =[]
vmDPmac =[]
hexDPIP =[]
config_file =[]
prox_socket =[]
prox_launch_exit =[]
auto_start =[]
mach_type =[]
sock_type =[]

data_file = 'RUN{}.{}.csv'.format(env,test)
data_csv_file = open(data_file,'w')
testconfig = ConfigParser.RawConfigParser()
testconfig.read(test+'.test')
required_number_of_test_machines = testconfig.get('DEFAULT', 'total_number_of_test_machines')
config = ConfigParser.RawConfigParser()
config.read(env+'.env')
machine_map = ConfigParser.RawConfigParser()
machine_map.read(machine_map_file +'.cfg')
key = config.get('OpenStack', 'key')
total_number_of_machines = config.get('rapid', 'total_number_of_machines')
if int(required_number_of_test_machines) > int(total_number_of_machines):
	log.exception("Not enough VMs for this test: %s needed and only %s available" % (required_number_of_test_machines,total_number_of_machines))
	raise Exception("Not enough VMs for this test: %s needed and only %s available" % (required_number_of_test_machines,total_number_of_machines))
for vm in range(1, int(total_number_of_machines)+1):
	vmAdminIP.append(config.get('M%d'%vm, 'admin_ip'))
	vmDPmac.append(config.get('M%d'%vm, 'dp_mac'))
	vmDPIP.append(config.get('M%d'%vm, 'dp_ip'))
	ip = vmDPIP[-1].split('.')
	hexDPIP.append(hex(int(ip[0]))[2:].zfill(2) + ' ' + hex(int(ip[1]))[2:].zfill(2) + ' ' + hex(int(ip[2]))[2:].zfill(2) + ' ' + hex(int(ip[3]))[2:].zfill(2))
machine_index = []
for vm in range(1, int(required_number_of_test_machines)+1):
	machine_index.append(int(machine_map.get('TestM%d'%vm, 'machine_index'))-1)
	prox_socket.append(testconfig.getboolean('TestM%d'%vm, 'prox_socket'))
for vm in range(1, int(required_number_of_test_machines)+1):
	if prox_socket[vm-1]:
		prox_launch_exit.append(testconfig.getboolean('TestM%d'%vm, 'prox_launch_exit'))
		config_file.append(testconfig.get('TestM%d'%vm, 'config_file'))
		with open('{}_{}_parameters{}.lua'.format(env,test,vm), "w") as f:
			f.write('name="%s"\n'% testconfig.get('TestM%d'%vm, 'name'))
			f.write('local_ip="%s"\n'% vmDPIP[machine_index[vm-1]])
			f.write('local_hex_ip="%s"\n'% hexDPIP[machine_index[vm-1]])
			if re.match('(l2){0,1}gen\.cfg',config_file[-1]):
				gencores = ast.literal_eval(testconfig.get('TestM%d'%vm, 'gencores'))
				latcores = ast.literal_eval(testconfig.get('TestM%d'%vm, 'latcores'))
				STARTSPEED = float(testconfig.get('TestM%d'%vm, 'startspeed'))
				genstatcores = gencores + latcores
				auto_start.append(False)
				mach_type.append('gen')
				f.write('gencores="%s"\n'% ','.join(map(str, gencores)))
				f.write('latcores="%s"\n'% ','.join(map(str, latcores)))
				destVMindex = int(testconfig.get('TestM%d'%vm, 'dest_vm'))-1
				f.write('dest_ip="%s"\n'% vmDPIP[machine_index[destVMindex]])
				f.write('dest_hex_ip="%s"\n'% hexDPIP[machine_index[destVMindex]])
				f.write('dest_hex_mac="%s"\n'% vmDPmac[machine_index[destVMindex]].replace(':',' '))
			elif re.match('(l2){0,1}gen_gw\.cfg',config_file[-1]):
				gencores = ast.literal_eval(testconfig.get('TestM%d'%vm, 'gencores'))
				latcores = ast.literal_eval(testconfig.get('TestM%d'%vm, 'latcores'))
				STARTSPEED = float(testconfig.get('TestM%d'%vm, 'startspeed'))
				genstatcores = gencores + latcores
				auto_start.append(False)
				mach_type.append('gen')
				f.write('gencores="%s"\n'% ','.join(map(str, gencores)))
				f.write('latcores="%s"\n'% ','.join(map(str, latcores)))
				gwVMindex = int(testconfig.get('TestM%d'%vm, 'gw_vm')) -1
				f.write('gw_ip="%s"\n'% vmDPIP[machine_index[gwVMindex]])
				f.write('gw_hex_ip="%s"\n'% hexDPIP[machine_index[gwVMindex]])
				destVMindex = int(testconfig.get('TestM%d'%vm, 'dest_vm'))-1
				f.write('dest_ip="%s"\n'% vmDPIP[machine_index[destVMindex]])
				f.write('dest_hex_ip="%s"\n'% hexDPIP[machine_index[destVMindex]])
				f.write('dest_hex_mac="%s"\n'% vmDPmac[machine_index[destVMindex]].replace(':',' '))
			elif  re.match('(l2){0,1}swap.*\.cfg',config_file[-1]):
				sutstatcores = ast.literal_eval(testconfig.get('TestM%d'%vm, 'swapcores'))
				auto_start.append(True)
				mach_type.append('sut')
				f.write('swapcores="%s"\n'% ','.join(map(str, sutstatcores)))
			elif config_file[-1] == 'secgw1.cfg':
				auto_start.append(True)
				mach_type.append('none')
				f.write('secgwcores="%s"\n'% ','.join(map(str, ast.literal_eval(testconfig.get('TestM%d'%vm, 'secgwcores')))))
				destVMindex = int(testconfig.get('TestM%d'%vm, 'dest_vm'))-1
				f.write('dest_ip="%s"\n'% vmDPIP[machine_index[destVMindex]])
				f.write('dest_hex_ip="%s"\n'% hexDPIP[machine_index[destVMindex]])
				f.write('dest_hex_mac="%s"\n'% vmDPmac[machine_index[destVMindex]].replace(':',' '))
			elif config_file[-1] == 'secgw2.cfg':
				sutstatcores = ast.literal_eval(testconfig.get('TestM%d'%vm, 'secgwcores'))
				auto_start.append(True)
				mach_type.append('sut')
				f.write('secgwcores="%s"\n'% ','.join(map(str, sutstatcores)))
			elif config_file[-1] == 'impair.cfg':
				auto_start.append(True)
				mach_type.append('none')
				f.write('impaircores="%s"\n'% ','.join(map(str, ast.literal_eval(testconfig.get('TestM%d'%vm, 'impaircores')))))
			elif config_file[-1] == 'irq.cfg':
				irqcores = ast.literal_eval(testconfig.get('TestM%d'%vm, 'irqcores'))
				auto_start.append(False)
				mach_type.append('irq')
				f.write('irqcores="%s"\n'% ','.join(map(str, irqcores)))
		f.close
#####################################################################################
def exit_handler():
	log.debug ('exit cleanup')
	for index, sock in enumerate(socks):
		if socks_control[index]:
	        	sock.quit()
	for client in clients:
	        client.close()
	data_csv_file.close
	sys.exit(0)

atexit.register(exit_handler)

for vm in range(0, int(required_number_of_test_machines)):
	if prox_socket[vm]:
		clients.append(prox_ctrl(vmAdminIP[machine_index[vm]], key+'.pem','root'))
		connect_client(clients[-1])
# Creating script to bind the right network interface to the poll mode driver
		devbindfile = '{}_{}_devbindvm{}.sh'.format(env,test, vm+1)
		with open("devbind.sh") as f:
			newText=f.read().replace('MACADDRESS', vmDPmac[machine_index[vm]])
			with open(devbindfile, "w") as f:
				f.write(newText)
		st = os.stat(devbindfile)
		os.chmod(devbindfile, st.st_mode | stat.S_IEXEC)
		clients[-1].scp_put('./%s'%devbindfile, '/root/devbind.sh')
		cmd = '/root/devbind.sh'
		clients[-1].run_cmd(cmd)
		log.debug("devbind.sh running on VM%d"%(vm+1))
		clients[-1].scp_put('./%s'%config_file[vm], '/root/%s'%config_file[vm])
		clients[-1].scp_put('./{}_{}_parameters{}.lua'.format(env,test, vm+1), '/root/parameters.lua')
		if not configonly:
			if prox_launch_exit[vm]:
				log.debug("Starting PROX on VM%d"%(vm+1))
				if auto_start[vm]:
					cmd = '/root/prox/build/prox -t -o cli -f /root/%s'%config_file[vm]
				else:
					cmd = '/root/prox/build/prox -e -t -o cli -f /root/%s'%config_file[vm]
				clients[-1].fork_cmd(cmd, 'PROX Testing on TestM%d'%(vm+1))
			socks_control.append(prox_launch_exit[vm])
			socks.append(connect_socket(clients[-1]))
			sock_type.append(mach_type[vm])
socks.append('none')
socks_control.append(False)

def get_BinarySearchParams() :
	global DROP_RATE_TRESHOLD
	global LAT_AVG_TRESHOLD
	global LAT_MAX_TRESHOLD
	global ACCURACY
	global STARTSPEED
	DROP_RATE_TRESHOLD = float(testconfig.get('BinarySearchParams', 'drop_rate_threshold'))
	LAT_AVG_TRESHOLD = float(testconfig.get('BinarySearchParams', 'lat_avg_threshold'))
	LAT_MAX_TRESHOLD = float(testconfig.get('BinarySearchParams', 'lat_max_threshold'))
	ACCURACY = float(testconfig.get('BinarySearchParams', 'accuracy'))
	
if configonly:
	sys.exit()
####################################################
# Run test cases
# Best to run the flow test at the end since otherwise the tests coming after might be influenced by the big number of entries in the switch flow tables
####################################################
gensock_index = sock_type.index('gen') if 'gen' in sock_type else -1
sutsock_index = sock_type.index('sut') if 'sut' in sock_type else -1
irqsock_index = sock_type.index('irq') if 'irq' in sock_type else -1
number_of_tests = testconfig.get('DEFAULT', 'number_of_tests')
with data_csv_file:
	fieldnames = ['flow','size','endspeed','endspeedpps','endpps_req_tx','endpps_tx','endpps_sut_tx_str','endpps_rx','endlat_avg','endlat_max','endabs_dropped','enddrop_rate']
	writer = csv.DictWriter(data_csv_file, fieldnames=fieldnames)
	writer.writeheader()
	for test_nr in range(1, int(number_of_tests)+1):
		test=testconfig.get('test%d'%test_nr,'test')
		log.info(test)
		if test == 'speedtest':
			get_BinarySearchParams()
			PACKETSIZE = int(testconfig.get('test%d'%test_nr, 'packetsize'))
			run_speedtest(socks[gensock_index],socks[sutsock_index])
		elif test == 'flowtest':
			get_BinarySearchParams()
			PACKETSIZE = int(testconfig.get('test%d'%test_nr, 'packetsize'))
			flow_size_list = ast.literal_eval(testconfig.get('test%d'%test_nr, 'flows'))
			run_flowtest(socks[gensock_index],socks[sutsock_index])
		elif test == 'sizetest':
			get_BinarySearchParams()
			packet_size_list = ast.literal_eval(testconfig.get('test%d'%test_nr, 'packetsizes'))
			run_sizetest(socks[gensock_index],socks[sutsock_index])
		elif test == 'max_frame_rate':
#			PACKETSIZE = int(testconfig.get('test%d'%test_nr, 'packetsize'))
			packet_size_list = ast.literal_eval(testconfig.get('test%d'%test_nr, 'packetsizes'))
			run_max_frame_rate(socks[gensock_index],socks[sutsock_index])
		elif test == 'impairtest':
			get_BinarySearchParams()
			PACKETSIZE = int(testconfig.get('test%d'%test_nr, 'packetsize'))
			run_impairtest(socks[gensock_index],socks[sutsock_index])
		elif test == 'irqtest':
			run_irqtest(socks[irqsock_index])
		elif test == 'inittest':
			run_inittest(socks[gensock_index])
####################################################
