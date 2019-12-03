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
import ast
import atexit
import csv
import requests

version="19.11.21"
env = "rapid.env" #Default string for environment
test_file = "basicrapid.test" #Default string for test
machine_map_file = "machine.map" #Default string for machine map file
loglevel="DEBUG" # sets log level for writing to file
screenloglevel="INFO" # sets log level for writing to screen
runtime=10 # time in seconds for 1 test run
configonly = False # IF True, the system will upload all the necessary config fiels to the VMs, but not start PROX and the actual testing
rundir = "/home/centos" # Directory where to find the tools in the machines running PROX

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
	print("  --env ENVIRONMENT_NAME       	Parameters will be read from ENVIRONMENT_NAME. Default is %s."%env)
	print("  --test TEST_NAME       	Test cases will be read from TEST_NAME. Default is %s."%test_file)
	print("  --map MACHINE_MAP_FILE	Machine mapping will be read from MACHINE_MAP_FILE. Default is %s."%machine_map_file)
	print("  --runtime			Specify time in seconds for 1 test run")
	print("  --configonly			If this option is specified, only upload all config files to the VMs, do not run the tests")
	print("  --log				Specify logging level for log file output, default is DEBUG")
	print("  --screenlog			Specify logging level for screen output, default is INFO")
	print("  -h, --help               	Show help message and exit.")
	print("")

try:
	opts, args = getopt.getopt(sys.argv[1:], "vh", ["version","help", "env=", "test=", "map=", "runtime=","configonly","log=","screenlog="])
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
	if opt in ["--env"]:
		env = arg
	if opt in ["--test"]:
		test_file = arg
	if opt in ["--map"]:
		machine_map_file = arg
	if opt in ["--runtime"]:
		runtime = arg
	if opt in ["--configonly"]:
		configonly = True
		print('No actual runs, only uploading configuration files')
	if opt in ["--log"]:
		loglevel = arg
		print ("Log level: "+ loglevel)
	if opt in ["--screenlog"]:
		screenloglevel = arg
		print ("Screen Log level: "+ screenloglevel)

print ("Using '"+env+"' as name for the environment")
print ("Using '"+test_file+"' for test case definition")
print ("Using '"+machine_map_file+"' for machine mapping")
print ("Runtime: "+ str(runtime))

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
#console_handler.setLevel(logging.INFO)
numeric_screenlevel = getattr(logging, screenloglevel.upper(), None)
if not isinstance(numeric_screenlevel, int):
	raise ValueError('Invalid screenlog level: %s' % screenloglevel)
console_handler.setLevel(numeric_screenlevel)
console_handler.setFormatter(screen_formatter)

# create a file handler
# and set its log level
#
log_file = 'RUN{}.{}.log'.format(env,test_file)
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
	sleep_time = 2
	# Sleep_time is needed to be able to do accurate measurements to check for packet loss. We need to make this time large enough so that we do not take the first measurement while some packets from the previous tests migth still be in flight
	time.sleep(sleep_time)
	abs_old_rx, abs_old_non_dp_rx, abs_old_tx, abs_old_non_dp_tx, abs_old_drop, abs_old_tx_fail, abs_old_tsc, abs_tsc_hz = gensock.core_stats(genstatcores,gentasks)
	abs_old_rx = abs_old_rx - abs_old_non_dp_rx
	abs_old_tx = abs_old_tx - abs_old_non_dp_tx
	gensock.start(gencores)
	time.sleep(sleep_time)
	if sutsock!='none':
		old_sut_rx, old_sut_non_dp_rx, old_sut_tx, old_sut_non_dp_tx, old_sut_drop, old_sut_tx_fail, old_sut_tsc, sut_tsc_hz = sutsock.core_stats(sutstatcores,tasks)
		old_sut_rx = old_sut_rx - old_sut_non_dp_rx
		old_sut_tx = old_sut_tx - old_sut_non_dp_tx
	old_rx, old_non_dp_rx, old_tx, old_non_dp_tx, old_drop, old_tx_fail, old_tsc, tsc_hz = gensock.core_stats(genstatcores,gentasks)
	old_rx = old_rx - old_non_dp_rx
	old_tx = old_tx - old_non_dp_tx
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
	new_rx, new_non_dp_rx, new_tx, new_non_dp_tx, new_drop, new_tx_fail, new_tsc, tsc_hz = gensock.core_stats(genstatcores,gentasks)
	new_rx = new_rx - new_non_dp_rx
	new_tx = new_tx - new_non_dp_tx
	if sutsock!='none':
		new_sut_rx, new_sut_non_dp_rx, new_sut_tx, new_sut_non_dp_tx, new_sut_drop, new_sut_tx_fail, new_sut_tsc, sut_tsc_hz = sutsock.core_stats(sutstatcores,tasks)
		new_sut_rx = new_sut_rx - new_sut_non_dp_rx
		new_sut_tx = new_sut_tx - new_sut_non_dp_tx
	#Stop generating
	gensock.stop(gencores)
	time.sleep(sleep_time)
	abs_new_rx, abs_new_non_dp_rx, abs_new_tx, abs_new_non_dp_tx, abs_new_drop, abs_new_tx_fail, abs_new_tsc, abs_tsc_hz = gensock.core_stats(genstatcores,gentasks)
	abs_new_rx = abs_new_rx - abs_new_non_dp_rx
	abs_new_tx = abs_new_tx - abs_new_non_dp_tx
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
	return(pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx,lat_avg,lat_max,abs_dropped,(abs_new_tx_fail - abs_old_tx_fail),(abs_new_tx - abs_old_tx),lat_min,used_avg)

def new_speed(speed,minspeed,maxspeed,success):
	if success:
		minspeed = speed
	else:
		maxspeed = speed
	newspeed = (maxspeed+minspeed)/2.0
	return (newspeed,minspeed,maxspeed)

def get_pps(speed,size):
	# speed is given in % of 10Gb/s, returning Mpps
	return (speed * 100.0 / (8*(size+24)))

def get_speed(packet_speed,size):
	# return speed in Gb/s
	return (packet_speed / 1000.0 * (8*(size+24)))


def run_flow_size_test(gensock,sutsock):
	fieldnames = ['Flows','PacketSize','Gbps','Mpps','AvgLatency','MaxLatency','PacketsDropped','PacketDropRate']
	writer = csv.DictWriter(data_csv_file, fieldnames=fieldnames)
	writer.writeheader()
	gensock.start(latcores)
	for size in packet_size_list:
		size = size-4
		gensock.set_size(gencores,0,size) # This is setting the frame size
		gensock.set_value(gencores,0,16,(size-14),2) # 18 is the difference between the frame size and IP size = size of (MAC addresses, ethertype and FCS)
		gensock.set_value(gencores,0,38,(size-34),2) # 38 is the difference between the frame size and UDP size = 18 + size of IP header (=20)
		# This will only work when using sending UDP packets. For different protocls and ehternet types, we would need a different calculation
		log.info("+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+")
		log.info("| UDP, "+ '{:>5}'.format(size+4) +" bytes, different number of flows by randomizing SRC & DST UDP port                                                                                           |")
		log.info("+--------+--------------------+----------------+----------------+----------------+------------------------+----------------+----------------+----------------+------------+")
		log.info("| Flows  |  Speed requested   | core generated | Sent by Gen NIC| Forward by SUT |      core received     |  Avg. Latency  |  Max. Latency  |  Packets Lost  | Loss Ratio |")
		log.info("+--------+--------------------+----------------+----------------+----------------+------------------------+----------------+----------------+----------------+------------+")
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
				endwarning =''
				print(str(flow_number)+' flows: Measurement ongoing at speed: ' + str(round(speed,2)) + '%      ',end='\r')
				sys.stdout.flush()
				# Start generating packets at requested speed (in % of a 10Gb/s link)
				gensock.speed(speed / len(gencores) / len (gentasks), gencores, gentasks)
				time.sleep(1)
				# Get statistics now that the generation is stable and initial ARP messages are dealt with
				pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx,lat_avg,lat_max, abs_dropped, abs_tx_fail, abs_tx, lat_min, lat_used = run_iteration(gensock,sutsock)
				drop_rate = 100.0*abs_dropped/abs_tx
				if lat_used < 0.95:
					lat_warning = bcolors.WARNING + ' Latency accuracy issue?: {:>3.0f}%'.format(lat_used*100) +  bcolors.ENDC
				else:
					lat_warning = ''
				# The following if statement is testing if we pass the success criteria of a certain drop rate, average latenecy and maximum latency below the threshold
				# The drop rate success can be achieved in 2 ways: either the drop rate is below a treshold, either we want that no packet has been lost during the test
				# This can be specified by putting 0 in the .test file
				if ((drop_rate < DROP_RATE_TRESHOLD) or (abs_dropped==DROP_RATE_TRESHOLD ==0)) and (lat_avg< LAT_AVG_TRESHOLD) and (lat_max < LAT_MAX_TRESHOLD):
					lat_avg_prefix = bcolors.ENDC
					lat_max_prefix = bcolors.ENDC
					abs_drop_rate_prefix = bcolors.ENDC
					drop_rate_prefix = bcolors.ENDC
					if ((get_pps(speed,size) - pps_tx)/get_pps(speed,size))>0.01:
						speed_prefix = bcolors.WARNING
						if abs_tx_fail > 0:
							gen_warning = bcolors.WARNING + ' Network limit?: requesting {:<.3f} Mpps and getting {:<.3f} Mpps - {} failed to be transmitted'.format(get_pps(speed,size), pps_tx, abs_tx_fail) + bcolors.ENDC
						else:
							gen_warning = bcolors.WARNING + ' Generator limit?: requesting {:<.3f} Mpps and getting {:<.3f} Mpps'.format(get_pps(speed,size), pps_tx) + bcolors.ENDC
					else:
						speed_prefix = bcolors.ENDC
						gen_warning = ''
					endspeed = speed
					endspeed_prefix = speed_prefix
					endpps_req_tx = pps_req_tx
					endpps_tx = pps_tx
					endpps_sut_tx_str = pps_sut_tx_str
					endpps_rx = pps_rx
					endlat_avg = lat_avg 
					endlat_max = lat_max 
					endabs_dropped = abs_dropped
					enddrop_rate = drop_rate
					if lat_warning or gen_warning:
						endwarning = '|        | {:167.167} |'.format(lat_warning + gen_warning)
					success = True
					success_message='%  | SUCCESS'
				else:
					success_message='%  | FAILED'
					gen_warning = ''
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
					success = False 
				log.debug('|step{:>3}'.format(str(attempts))+" | " + '{:>5.1f}'.format(speed) + '% '+speed_prefix +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps | '+ '{:>9.3f}'.format(pps_req_tx)+' Mpps | ' + '{:>9.3f}'.format(pps_tx) +' Mpps | '+ bcolors.ENDC  + '{:>9}'.format(pps_sut_tx_str) +' Mpps | '+bcolors.OKBLUE + '{:>4.1f}'.format(get_speed(pps_rx,size)) + 'Gb/s{:>9.3f}'.format(pps_rx)+' Mpps'+bcolors.ENDC+' | '+lat_avg_prefix+ '{:>9.0f}'.format(lat_avg)+' us   | '+lat_max_prefix+ '{:>9.0f}'.format(lat_max)+' us   | '+ abs_drop_rate_prefix + '{:>14d}'.format(abs_dropped)+drop_rate_prefix+ ' |''{:>9.2f}'.format(drop_rate)+bcolors.ENDC+ success_message +lat_warning + gen_warning)
				speed,minspeed,maxspeed = new_speed(speed,minspeed,maxspeed,success)
			if endpps_sut_tx_str !=  'NO_RESULTS':
				log.info('|{:>7}'.format(str(flow_number))+" | " + '{:>5.1f}'.format(endspeed) + '% ' + endspeed_prefix + '{:>6.3f}'.format(get_pps(endspeed,size)) + ' Mpps | '+ '{:>9.3f}'.format(endpps_req_tx)+ ' Mpps | '+ '{:>9.3f}'.format(endpps_tx) + ' Mpps | ' + bcolors.ENDC + '{:>9}'.format(endpps_sut_tx_str) +' Mpps | '+bcolors.OKBLUE + '{:>4.1f}'.format(get_speed(endpps_rx,size)) + 'Gb/s{:>9.3f}'.format(endpps_rx)+' Mpps'+bcolors.ENDC+' | '+ '{:>9.0f}'.format(endlat_avg)+' us   | '+ '{:>9.0f}'.format(endlat_max)+' us   | '+ '{:>14d}'.format(endabs_dropped)+ ' |'+'{:>9.2f}'.format(enddrop_rate)+ '%  |')
				if endwarning:
					log.info (endwarning)
				log.info("+--------+--------------------+----------------+----------------+----------------+------------------------+----------------+----------------+----------------+------------+")
				writer.writerow({'Flows':flow_number,'PacketSize':(size+4),'Gbps':get_speed(endpps_rx,size),'Mpps':endpps_rx,'AvgLatency':endlat_avg,'MaxLatency':endlat_max,'PacketsDropped':endabs_dropped,'PacketDropRate':enddrop_rate})
				if PushGateway:
					URL     = PushGateway + '/metrics/job/' + TestName + '/instance/' + env
					DATA = 'Flows {}\nPacketSize {}\nGbps {}\nMpps {}\nAvgLatency {}\nMaxLatency {}\nPacketsDropped {}\nPacketDropRate {}\n'.format(flow_number,size+4,get_speed(endpps_rx,size),endpps_rx,endlat_avg,endlat_max,endabs_dropped,enddrop_rate)
					HEADERS = {'X-Requested-With': 'Python requests', 'Content-type': 'text/xml'}
					response = requests.post(url=URL, data=DATA,headers=HEADERS)
			else:
				log.info('|{:>7}'.format(str(flow_number))+" | Speed 0 or close to 0")
	gensock.stop(latcores)


def run_fixed_rate(gensock,sutsock):
	fieldnames = ['Flows','PacketSize','RequestedPPS','GeneratedPPS','SentPPS','ForwardedPPS','ReceivedPPS','AvgLatencyUSEC','MaxLatencyUSEC','Sent','Received','Lost','LostTotal']
	writer = csv.DictWriter(data_csv_file, fieldnames=fieldnames)
	writer.writeheader()
	gensock.start(latcores)
	sleep_time=3
	for size in packet_size_list:
		size = size-4
		gensock.set_size(gencores,0,size) # This is setting the frame size
		gensock.set_value(gencores,0,16,(size-14),2) # 18 is the difference between the frame size and IP size = size of (MAC addresses, ethertype and FCS)
		gensock.set_value(gencores,0,38,(size-34),2) # 38 is the difference between the frame size and UDP size = 18 + size of IP header (=20)
		# This will only work when using sending UDP packets. For different protocols and ehternet types, we would need a different calculation
		log.info("+--------------------------------------------------------------------------------------------------------------------------------------------------------------+")
		log.info("| UDP, "+ '{:>5}'.format(size+4) +" bytes, different number of flows by randomizing SRC & DST UDP port                                                                                |")
		log.info("+--------+------------------+-------------+-------------+-------------+-------------+-------------+-------------+-----------+-----------+---------+------------+")
		log.info("| Flows  | Speed requested  | Gen by core | Sent by NIC | Fwrd by SUT | Rec. by core| Avg. Latency| Max. Latency|   Sent    |  Received |  Lost   | Total Lost |")
		log.info("+--------+------------------+-------------+-------------+-------------+-------------+-------------+-------------+-----------+-----------+---------+------------+")
		for flow_number in flow_size_list:
			time.sleep(sleep_time)
			gensock.reset_stats()
			if sutsock!='none':
				sutsock.reset_stats()
			source_port,destination_port = flows[flow_number]
			gensock.set_random(gencores,0,34,source_port,2)
			gensock.set_random(gencores,0,36,destination_port,2)
			endpps_sut_tx_str = 'NO_RESULTS'
			speed = STARTSPEED
			# Start generating packets at requested speed (in % of a 10Gb/s link)
			gensock.speed(speed / len(gencores) / len (gentasks), gencores, gentasks)
			duration = float(runtime)
			first = 1
			tot_drop = 0
			if sutsock!='none':
				old_sut_rx, old_sut_non_dp_rx, old_sut_tx, old_sut_non_dp_tx, old_sut_drop, old_sut_tx_fail, old_sut_tsc, sut_tsc_hz = sutsock.core_stats(sutstatcores,tasks)
				old_sut_rx = old_sut_rx - old_sut_non_dp_rx
				old_sut_tx = old_sut_tx - old_sut_non_dp_tx
			old_rx, old_non_dp_rx, old_tx, old_non_dp_tx, old_drop, old_tx_fail, old_tsc, tsc_hz = gensock.core_stats(genstatcores,gentasks)
			old_rx = old_rx - old_non_dp_rx
			old_tx = old_tx - old_non_dp_tx
			gensock.start(gencores)
			while (duration > 0):
				time.sleep(0.5)
				lat_min, lat_max, lat_avg, lat_used = gensock.lat_stats(latcores)
				if lat_used < 0.95:
					lat_warning = bcolors.FAIL + ' Potential latency accuracy problem: {:>3.0f}%'.format(lat_used*100) +  bcolors.ENDC
				else:
					lat_warning = ''
				# Get statistics after some execution time
				new_rx, new_non_dp_rx, new_tx, new_non_dp_tx, new_drop, new_tx_fail, new_tsc, tsc_hz = gensock.core_stats(genstatcores,gentasks)
				new_rx = new_rx - new_non_dp_rx
				new_tx = new_tx - new_non_dp_tx
				if sutsock!='none':
					new_sut_rx, new_sut_non_dp_rx, new_sut_tx, new_sut_non_dp_tx, new_sut_drop, new_sut_tx_fail, new_sut_tsc, sut_tsc_hz = sutsock.core_stats(sutstatcores,tasks)
					new_sut_rx = new_sut_rx - new_sut_non_dp_rx
					new_sut_tx = new_sut_tx - new_sut_non_dp_tx
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

				if pps_sut_tx_str !=  'NO_RESULTS':
					# First second mpps are not valid as there is no alignement between time the generator is started and per seconds stats
					if (first):
						log.info('|{:>7}'.format(flow_number)+" |" + '{:>5.1f}'.format(speed) + '% ' +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps|'+'             |' +'             |'  +'             |'+ '             |'+ '{:>8.0f}'.format(lat_avg)+' us  |'+'{:>8.0f}'.format(lat_max)+' us  | ' + '{:>9.0f}'.format(tx) + ' | '+ '{:>9.0f}'.format(rx) + ' | '+ '{:>7.0f}'.format(tx-rx) + ' | '+'{:>7.0f}'.format(tot_drop) +'    |'+lat_warning)
					else:
						log.info('|{:>7}'.format(flow_number)+" |" + '{:>5.1f}'.format(speed) + '% ' +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps|'+ '{:>7.3f}'.format(pps_req_tx)+' Mpps |'+ '{:>7.3f}'.format(pps_tx) +' Mpps |' + '{:>7}'.format(pps_sut_tx_str) +' Mpps |'+ '{:>7.3f}'.format(pps_rx)+' Mpps |'+ '{:>8.0f}'.format(lat_avg)+' us  |'+'{:>8.0f}'.format(lat_max)+' us  | ' + '{:>9.0f}'.format(tx) + ' | '+ '{:>9.0f}'.format(rx) + ' | '+ '{:>7.0f}'.format(tx-rx) + ' | '+ '{:>7.0f}'.format(tot_drop) +'    |'+lat_warning)
						writer.writerow({'Flows':flow_number,'PacketSize':(size+4),'RequestedPPS':get_pps(speed,size),'GeneratedPPS':pps_req_tx,'SentPPS':pps_tx,'ForwardedPPS':pps_sut_tx,'ReceivedPPS':pps_rx,'AvgLatencyUSEC':lat_avg,'MaxLatencyUSEC':lat_max,'Sent':tx,'Received':rx,'Lost':(tx-rx),'LostTotal':tot_drop})
						if PushGateway:
							URL     = PushGateway + '/metrics/job/' + TestName + '/instance/' + env
							DATA = 'Flows {}\nPacketSize {}\nRequestedPPS {}\nGeneratedPPS {}\nSentPPS {}\nForwardedPPS {}\nReceivedPPS {}\nAvgLatencyUSEC {}\nMaxLatencyUSEC {}\nSent {}\nReceived {}\nLost {}\nLostTotal {}\n'.format(flow_number,size+4,get_pps(speed,size),pps_req_tx,pps_tx,pps_sut_tx,pps_rx,lat_avg,lat_max,tx,rx,(tx-rx),tot_drop)
							HEADERS = {'X-Requested-With': 'Python requests', 'Content-type': 'text/xml'}
							response = requests.post(url=URL, data=DATA,headers=HEADERS)
				else:
					log.debug('|{:>7} | Speed 0 or close to 0'.format(str(size)))
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
					new_rx, new_non_dp_rx, new_tx, new_non_dp_tx, new_drop, new_tx_fail, new_tsc, tsc_hz = gensock.core_stats(genstatcores,gentasks)
					new_rx = new_rx - new_non_dp_rx
					new_tx = new_tx - new_non_dp_tx
					if sutsock!='none':
						new_sut_rx, new_sut_non_dp_rx, new_sut_tx, new_sut_non_dp_tx, new_sut_drop, new_sut_tx_fail, new_sut_tsc, sut_tsc_hz = sutsock.core_stats(sutstatcores,tasks)
						new_sut_rx = new_sut_rx - new_sut_non_dp_rx
						new_sut_tx = new_sut_tx - new_sut_non_dp_tx
					drop = new_drop-old_drop # drop is all packets dropped by all tasks. This includes packets dropped at the generator task + packets dropped by the nop task. In steady state, this equals to the number of packets received by this VM
					rx = new_rx - old_rx     # rx is all packets received by the nop task = all packets received in the gen VM
					tx = new_tx - old_tx     # tx is all generated packets actually accepted by the interface
					tsc = new_tsc - old_tsc  # time difference between the 2 measurements, expressed in cycles.
					tot_drop = tot_drop + tx - rx
					if sutsock!='none':
						sut_rx = new_sut_rx - old_sut_rx
						sut_tx = new_sut_tx - old_sut_tx
						sut_tsc = new_sut_tsc - old_sut_tsc
					if pps_sut_tx_str !=  'NO_RESULTS':
						log.info('|{:>7}'.format(flow_number)+" |" + '{:>5.1f}'.format(speed) + '% ' +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps|'+'             |' +'             |'  +'             |'+ '             |'+ '{:>8.0f}'.format(lat_avg)+' us  |'+'{:>8.0f}'.format(lat_max)+' us  | ' + '{:>9.0f}'.format(tx) + ' | '+ '{:>9.0f}'.format(rx) + ' | '+ '{:>7.0f}'.format(tx-rx) + ' | '+ '{:>7.0f}'.format(tot_drop) +'    |'+lat_warning)
			log.info("+--------+------------------+-------------+-------------+-------------+-------------+-------------+-------------+-----------+-----------+---------+------------+")
	gensock.stop(latcores)

def run_core_stats(socks):
	fieldnames = ['PROXID','Time','Received','Sent','NonDPReceived','NonDPSent','Delta','NonDPDelta','Dropped']
	writer = csv.DictWriter(data_csv_file, fieldnames=fieldnames)
	writer.writeheader()
	log.info("+------------------------------------------------------------------------------------------------------------------+")
	log.info("| Measuring core statistics on 1 or more PROX instances                                                            |")
	log.info("+-----------+-----------+------------+------------+------------+------------+------------+------------+------------+")
	log.info("| PROX ID   |    Time   |    RX      |     TX     | non DP RX  | non DP TX  |   TX - RX  | nonDP TX-RX|  DROP TOT  |")
	log.info("+-----------+-----------+------------+------------+------------+------------+------------+------------+------------+")
	for sock in socks:
		sock.reset_stats()
	duration = float(runtime)
	tot_drop = []
	old_rx = []; old_non_dp_rx = []; old_tx = []; old_non_dp_tx = []; old_drop = []; old_tx_fail = []; old_tsc = []
	new_rx = []; new_non_dp_rx = []; new_tx = []; new_non_dp_tx = []; new_drop = []; new_tx_fail = []; new_tsc = []
	sockets_to_go = len (socks)
	for i,sock in enumerate(socks,start=0):
		tot_drop.append(0)
		old_rx.append(0); old_non_dp_rx.append(0); old_tx.append(0); old_non_dp_tx.append(0); old_drop.append(0); old_tx_fail.append(0); old_tsc.append(0)
		old_rx[-1], old_non_dp_rx[-1], old_tx[-1], old_non_dp_tx[-1], old_drop[-1], old_tx_fail[-1], old_tsc[-1], tsc_hz = sock.core_stats(cores[i],tasks)
		new_rx.append(0); new_non_dp_rx.append(0); new_tx.append(0); new_non_dp_tx.append(0); new_drop.append(0); new_tx_fail.append(0); new_tsc.append(0)
	while (duration > 0):
		time.sleep(0.5)
		# Get statistics after some execution time
		for i,sock in enumerate(socks,start=0):
			new_rx[i], new_non_dp_rx[i], new_tx[i], new_non_dp_tx[i], new_drop[i], new_tx_fail[i], new_tsc[i], tsc_hz = sock.core_stats(cores[i],tasks)
			drop = new_drop[i]-old_drop[i]
			rx = new_rx[i] - old_rx[i]
			tx = new_tx[i] - old_tx[i]
			non_dp_rx = new_non_dp_rx[i] - old_non_dp_rx[i]
			non_dp_tx = new_non_dp_tx[i] - old_non_dp_tx[i]
			tsc = new_tsc[i] - old_tsc[i]
			if tsc == 0 :
				continue
			sockets_to_go -= 1
			old_drop[i] = new_drop[i]
			old_rx[i] = new_rx[i]
			old_tx[i] = new_tx[i]
			old_non_dp_rx[i] = new_non_dp_rx[i]
			old_non_dp_tx[i] = new_non_dp_tx[i]
			old_tsc[i] = new_tsc[i]
			tot_drop[i] = tot_drop[i] + tx - rx
			log.info('|{:>10.0f}'.format(i)+ ' |{:>10.0f}'.format(duration)+' | ' + '{:>10.0f}'.format(rx) + ' | ' +'{:>10.0f}'.format(tx) + ' | '+'{:>10.0f}'.format(non_dp_rx)+' | '+'{:>10.0f}'.format(non_dp_tx)+' | ' + '{:>10.0f}'.format(tx-rx) + ' | '+ '{:>10.0f}'.format(non_dp_tx-non_dp_rx) + ' | '+'{:>10.0f}'.format(tot_drop[i]) +' |')
			writer.writerow({'PROXID':i,'Time':duration,'Received':rx,'Sent':tx,'NonDPReceived':non_dp_rx,'NonDPSent':non_dp_tx,'Delta':tx-rx,'NonDPDelta':non_dp_tx-non_dp_rx,'Dropped':tot_drop[i]})
			if PushGateway:
				URL     = PushGateway + '/metrics/job/' + TestName + '/instance/' + env + str(i)
				DATA = 'PROXID {}\nTime {}\n Received {}\nSent {}\nNonDPReceived {}\nNonDPSent {}\nDelta {}\nNonDPDelta {}\nDropped {}\n'.format(i,duration,rx,tx,non_dp_rx,non_dp_tx,tx-rx,non_dp_tx-non_dp_rx,tot_drop[i])
				HEADERS = {'X-Requested-With': 'Python requests', 'Content-type': 'text/xml'}
				response = requests.post(url=URL, data=DATA,headers=HEADERS)
			if sockets_to_go == 0:
				duration = duration - 1
				sockets_to_go = len (socks)
	log.info("+-----------+-----------+------------+------------+------------+------------+------------+------------+------------+")

def run_port_stats(socks):
	fieldnames = ['PROXID','Time','Received','Sent','NoMbufs','iErrMiss']
	writer = csv.DictWriter(data_csv_file, fieldnames=fieldnames)
	writer.writeheader()
	log.info("+---------------------------------------------------------------------------+")
	log.info("| Measuring port statistics on 1 or more PROX instances                     |")
	log.info("+-----------+-----------+------------+------------+------------+------------+")
	log.info("| PROX ID   |    Time   |    RX      |     TX     | no MBUFS   | ierr&imiss |")
	log.info("+-----------+-----------+------------+------------+------------+------------+")
	for sock in socks:
		sock.reset_stats()
	duration = float(runtime)
	old_rx = []; old_tx = []; old_no_mbufs = []; old_errors = []; old_tsc = []
	new_rx = []; new_tx = []; new_no_mbufs = []; new_errors = []; new_tsc = []
	sockets_to_go = len (socks)
	for i,sock in enumerate(socks,start=0):
		old_rx.append(0); old_tx.append(0); old_no_mbufs.append(0); old_errors.append(0); old_tsc.append(0)
		old_rx[-1], old_tx[-1], old_no_mbufs[-1], old_errors[-1], old_tsc[-1] = sock.multi_port_stats(ports[i])
		new_rx.append(0); new_tx.append(0); new_no_mbufs.append(0); new_errors.append(0); new_tsc.append(0)
	while (duration > 0):
		time.sleep(0.5)
		# Get statistics after some execution time
		for i,sock in enumerate(socks,start=0):
			new_rx[i], new_tx[i], new_no_mbufs[i], new_errors[i], new_tsc[i] = sock.multi_port_stats(ports[i])
			rx = new_rx[i] - old_rx[i]
			tx = new_tx[i] - old_tx[i]
			no_mbufs = new_no_mbufs[i] - old_no_mbufs[i]
			errors = new_errors[i] - old_errors[i]
			tsc = new_tsc[i] - old_tsc[i]
			if tsc == 0 :
				continue
			sockets_to_go -= 1
			old_rx[i] = new_rx[i]
			old_tx[i] = new_tx[i]
			old_no_mbufs[i] = new_no_mbufs[i]
			old_errors[i] = new_errors[i]
			old_tsc[i] = new_tsc[i]
			log.info('|{:>10.0f}'.format(i)+ ' |{:>10.0f}'.format(duration)+' | ' + '{:>10.0f}'.format(rx) + ' | ' +'{:>10.0f}'.format(tx) + ' | '+'{:>10.0f}'.format(no_mbufs)+' | '+'{:>10.0f}'.format(errors)+' |')
			writer.writerow({'PROXID':i,'Time':duration,'Received':rx,'Sent':tx,'NoMbufs':no_mbufs,'iErrMiss':errors})
			if PushGateway:
				URL     = PushGateway + '/metrics/job/' + TestName + '/instance/' + env + str(i)
				DATA = 'PROXID {}\nTime {}\n Received {}\nSent {}\nNoMbufs {}\niErrMiss {}\n'.format(i,duration,rx,tx,no_mbufs,errors)
				HEADERS = {'X-Requested-With': 'Python requests', 'Content-type': 'text/xml'}
				response = requests.post(url=URL, data=DATA,headers=HEADERS)
			if sockets_to_go == 0:
				duration = duration - 1
				sockets_to_go = len (socks)
	log.info("+-----------+-----------+------------+------------+------------+------------+")

def run_irqtest(socks):
	log.info("+----------------------------------------------------------------------------------------------------------------------------")
	log.info("| Measuring time probably spent dealing with an interrupt. Interrupting DPDK cores for more than 50us might be problematic   ")
	log.info("| and result in packet loss. The first row shows the interrupted time buckets: first number is the bucket between 0us and    ")
	log.info("| that number expressed in us and so on. The numbers in the other rows show how many times per second, the program was       ")
	log.info("| interrupted for a time as specified by its bucket. '0' is printed when there are no interrupts in this bucket throughout   ")
	log.info("| the duration of the test. 0.00 means there were interrupts in this bucket but very few. Due to rounding this shows as 0.00 ") 
	log.info("+----------------------------------------------------------------------------------------------------------------------------")
	sys.stdout.flush()
	for sock_index,sock in enumerate(socks,start=0):
		buckets=socks[sock_index].show_irq_buckets(1)
		print('Measurement ongoing ... ',end='\r')
		socks[sock_index].stop(cores[sock_index])
		old_irq = [[0 for x in range(len(buckets)+1)] for y in range(len(cores[sock_index])+1)] 
		irq = [[0 for x in range(len(buckets)+1)] for y in range(len(cores[sock_index])+1)]
		irq[0][0] = 'bucket us' 
		for j,bucket in enumerate(buckets,start=1):
			irq[0][j] = '<'+ bucket
		irq[0][-1] = '>'+ buckets [-2]
		socks[sock_index].start(cores[sock_index])
		time.sleep(2)
		for j,bucket in enumerate(buckets,start=1):
			for i,irqcore in enumerate(cores[sock_index],start=1):
				old_irq[i][j] = socks[sock_index].irq_stats(irqcore,j-1)
		time.sleep(float(runtime))
		socks[sock_index].stop(cores[sock_index])
		for i,irqcore in enumerate(cores[sock_index],start=1):
			irq[i][0]='core %s '%irqcore
			for j,bucket in enumerate(buckets,start=1):
				diff =  socks[sock_index].irq_stats(irqcore,j-1) - old_irq[i][j]
				if diff == 0:
					irq[i][j] = '0'
				else:
					irq[i][j] = str(round(diff/float(runtime), 2))
		log.info('Results for PROX instance %s'%sock_index)
		for row in irq:
			log.info(''.join(['{:>12}'.format(item) for item in row]))

def run_impairtest(gensock,sutsock):
	fieldnames = ['Flows','PacketSize','RequestedPPS','GeneratedPPS','SentPPS','ForwardedPPS','ReceivedPPS','AvgLatencyUSEC','MaxLatencyUSEC','Dropped','DropRate']
	writer = csv.DictWriter(data_csv_file, fieldnames=fieldnames)
	writer.writeheader()
	size=PACKETSIZE-4
	log.info("+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+")
	log.info("| Generator is sending UDP ("+'{:>5}'.format(FLOWSIZE)+" flow) packets ("+ '{:>5}'.format(size+4) +" bytes) to SUT via GW dropping and delaying packets. SUT sends packets back. Use ctrl-c to stop the test    |")
	log.info("+--------+--------------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+------------+")
	log.info("| Test   |  Speed requested   | Sent to NIC    |  Sent by Gen   | Forward by SUT |  Rec. by Gen   |  Avg. Latency  |  Max. Latency  |  Packets Lost  | Loss Ratio |")
	log.info("+--------+--------------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+------------+")
	attempts = 0
	gensock.set_size(gencores,0,size) # This is setting the frame size
	gensock.set_value(gencores,0,16,(size-14),2) # 18 is the difference between the frame size and IP size = size of (MAC addresses, ethertype and FCS)
	gensock.set_value(gencores,0,38,(size-34),2) # 38 is the difference between the frame size and UDP size = 18 + size of IP header (=20)
	# This will only work when using sending UDP packets. For different protocols and ethernet types, we would need a different calculation
	source_port,destination_port = flows[FLOWSIZE]
	gensock.set_random(gencores,0,34,source_port,2)
	gensock.set_random(gencores,0,36,destination_port,2)
	gensock.start(latcores)
	speed = STARTSPEED
	gensock.speed(speed / len(gencores) / len(gentasks), gencores, gentasks)
	while True:
		attempts += 1
		print('Measurement ongoing at speed: ' + str(round(speed,2)) + '%      ',end='\r')
		sys.stdout.flush()
		time.sleep(1)
		# Get statistics now that the generation is stable and NO ARP messages any more
		pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx,lat_avg,lat_max, abs_dropped, abs_tx_fail, abs_tx, lat_min, lat_used = run_iteration(gensock,sutsock)
		drop_rate = 100.0*abs_dropped/abs_tx
		if lat_used < 0.95:
			lat_warning = bcolors.FAIL + ' Potential latency accuracy problem: {:>3.0f}%'.format(lat_used*100) +  bcolors.ENDC
		else:
			lat_warning = ''
		log.info('|{:>7}'.format(str(attempts))+" | " + '{:>5.1f}'.format(speed) + '% ' +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps | '+ '{:>9.3f}'.format(pps_req_tx)+' Mpps | '+ '{:>9.3f}'.format(pps_tx) +' Mpps | ' + '{:>9}'.format(pps_sut_tx_str) +' Mpps | '+ '{:>9.3f}'.format(pps_rx)+' Mpps | '+ '{:>9.0f}'.format(lat_avg)+' us   | '+ '{:>9.0f}'.format(lat_max)+' us   | '+ '{:>14d}'.format(abs_dropped)+ ' |''{:>9.2f}'.format(drop_rate)+ '%  |'+lat_warning)
		writer.writerow({'Flows':FLOWSIZE,'PacketSize':(size+4),'RequestedPPS':get_pps(speed,size),'GeneratedPPS':pps_req_tx,'SentPPS':pps_tx,'ForwardedPPS':pps_sut_tx_str,'ReceivedPPS':pps_rx,'AvgLatencyUSEC':lat_avg,'MaxLatencyUSEC':lat_max,'Dropped':abs_dropped,'DropRate':drop_rate})
		if PushGateway:
			URL     = PushGateway + '/metrics/job/' + TestName + '/instance/' + env
			DATA = 'Flows {}\nPacketSize {}\nRequestedPPS {}\nGeneratedPPS {}\nSentPPS {}\nForwardedPPS {}\nReceivedPPS {}\nAvgLatencyUSEC {}\nMaxLatencyUSEC {}\nDropped {}\nDropRate {}\n'.format(FLOWSIZE,size+4,get_pps(speed,size),pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx,lat_avg,lat_max,abs_dropped,drop_rate)
			HEADERS = {'X-Requested-With': 'Python requests', 'Content-type': 'text/xml'}
			response = requests.post(url=URL, data=DATA,headers=HEADERS)

def run_warmuptest(gensock):
# Running at low speed to make sure the ARP messages can get through.
# If not doing this, the ARP message could be dropped by a switch in overload and then the test will not give proper results
# Note hoever that if we would run the test steps during a very long time, the ARP would expire in the switch.
# PROX will send a new ARP request every seconds so chances are very low that they will all fail to get through
	gensock.speed(WARMUPSPEED / len(gencores) /len (gentasks), gencores, gentasks)
	size=PACKETSIZE-4
	gensock.set_size(gencores,0,size) # This is setting the frame size
	gensock.set_value(gencores,0,16,(size-14),2) # 18 is the difference between the frame size and IP size = size of (MAC addresses, ethertype and FCS)
	gensock.set_value(gencores,0,38,(size-34),2) # 38 is the difference between the frame size and UDP size = 18 + size of IP header (=20)
	gensock.set_value(gencores,0,56,1,1)
	# This will only work when using sending UDP packets. For different protocols and ethernet types, we would need a different calculation
	source_port,destination_port = flows[FLOWSIZE]
	gensock.set_random(gencores,0,34,source_port,2)
	gensock.set_random(gencores,0,36,destination_port,2)
	gensock.start(genstatcores)
	time.sleep(WARMUPTIME)
	gensock.stop(genstatcores)
	gensock.set_value(gencores,0,56,50,1)

global sutstatcores
global genstatcores
global latcores
global gencores
global irqcores
global PACKETSIZE
global packet_size_list
global FLOWSIZE
global flow_size_list
global WARMUPTIME
global WARMUPSPEED
global required_number_of_test_machines
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
65536:  ['10000000XXXXXXXX','10000000XXXXXXXX'],\
131072: ['10000000XXXXXXXX','1000000XXXXXXXXX'],\
262144: ['1000000XXXXXXXXX','1000000XXXXXXXXX'],\
524288: ['1000000XXXXXXXXX','100000XXXXXXXXXX'],\
1048576:['100000XXXXXXXXXX','100000XXXXXXXXXX'],}
clients =[]
socks =[]
socks_control =[]
vmDPIP =[]
vmAdminIP =[]
vmDPmac =[]
hexDPIP =[]
vmDPPCIDEV =[]
config_file =[]
prox_socket =[]
prox_launch_exit =[]
auto_start =[]
mach_type =[]
sock_type =[]
cores = []
ports = []
tasks = {}

data_file = 'RUN{}.{}.csv'.format(env,test_file)
data_csv_file = open(data_file,'w')
testconfig = ConfigParser.RawConfigParser()
testconfig.read(test_file)
required_number_of_test_machines = testconfig.get('DEFAULT', 'total_number_of_test_machines')
TestName = testconfig.get('DEFAULT', 'name')
if testconfig.has_option('DEFAULT', 'PushGateway'):
	PushGateway = testconfig.get('DEFAULT', 'PushGateway')
	log.info('Measurements will be pushed to %s'%PushGateway)
else:
	PushGateway = None
config = ConfigParser.RawConfigParser()
config.read(env)
machine_map = ConfigParser.RawConfigParser()
machine_map.read(machine_map_file)
vim_type = config.get('Varia', 'vim')
key = config.get('ssh', 'key')
user = config.get('ssh', 'user')
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
	if (vim_type == "kubernetes"):
		vmDPPCIDEV.append(config.get('M%d'%vm, 'dp_pci_dev'))
machine_index = []
for vm in range(1, int(required_number_of_test_machines)+1):
	machine_index.append(int(machine_map.get('TestM%d'%vm, 'machine_index'))-1)
	prox_socket.append(testconfig.getboolean('TestM%d'%vm, 'prox_socket'))
for vm in range(1, int(required_number_of_test_machines)+1):
	if prox_socket[vm-1]:
		prox_launch_exit.append(testconfig.getboolean('TestM%d'%vm, 'prox_launch_exit'))
		config_file.append(testconfig.get('TestM%d'%vm, 'config_file'))
		# Looking for all task definitions in the PROX cfg files. Constructing a list of all tasks used
		textfile =  open (config_file[-1], 'r')
		filetext = textfile.read()
		textfile.close()
		tasks_for_this_cfg = set(re.findall("task\s*=\s*(\d+)",filetext))
		with open('{}_{}_parameters{}.lua'.format(env,test_file,vm), "w") as f:
			f.write('name="%s"\n'% testconfig.get('TestM%d'%vm, 'name'))
			f.write('local_ip="%s"\n'% vmDPIP[machine_index[vm-1]])
			f.write('local_hex_ip="%s"\n'% hexDPIP[machine_index[vm-1]])
			if (vim_type == "kubernetes"):
				f.write("eal=\"--socket-mem=512,0 --file-prefix %s-%s-%s --pci-whitelist %s\"\n" % (env, test_file, vm, vmDPPCIDEV[machine_index[vm-1]]))
			else:
				f.write("eal=\"\"\n")
			if testconfig.has_option('TestM%d'%vm, 'cores'):
				cores.append(ast.literal_eval(testconfig.get('TestM%d'%vm, 'cores')))
				f.write('cores="%s"\n'% ','.join(map(str, cores[-1])))
			else:
				cores.append(None)
			if testconfig.has_option('TestM%d'%vm, 'ports'):
				ports.append(ast.literal_eval(testconfig.get('TestM%d'%vm, 'ports')))
				f.write('ports="%s"\n'% ','.join(map(str, ports[-1])))
			else:
				ports.append(None)
			if re.match('(l2){0,1}gen(_bare){0,1}.*\.cfg',config_file[-1]):
				gencores = ast.literal_eval(testconfig.get('TestM%d'%vm, 'gencores'))
				latcores = ast.literal_eval(testconfig.get('TestM%d'%vm, 'latcores'))
				genstatcores = gencores + latcores
				gentasks = tasks_for_this_cfg
				auto_start.append(False)
				mach_type.append('gen')
				f.write('gencores="%s"\n'% ','.join(map(str, gencores)))
				f.write('latcores="%s"\n'% ','.join(map(str, latcores)))
				destVMindex = int(testconfig.get('TestM%d'%vm, 'dest_vm'))-1
				f.write('dest_ip="%s"\n'% vmDPIP[machine_index[destVMindex]])
				f.write('dest_hex_ip="%s"\n'% hexDPIP[machine_index[destVMindex]])
				f.write('dest_hex_mac="%s"\n'% vmDPmac[machine_index[destVMindex]].replace(':',' '))
			elif re.match('(l2){0,1}gen_gw.*\.cfg',config_file[-1]):
				gencores = ast.literal_eval(testconfig.get('TestM%d'%vm, 'gencores'))
				latcores = ast.literal_eval(testconfig.get('TestM%d'%vm, 'latcores'))
				genstatcores = gencores + latcores
				gentasks = tasks_for_this_cfg
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
			elif re.match('(l2){0,1}swap.*\.cfg',config_file[-1]):
				sutstatcores = cores[-1]
				auto_start.append(True)
				mach_type.append('sut')
			elif re.match('secgw1.*\.cfg',config_file[-1]):
				auto_start.append(True)
				mach_type.append('none')
				destVMindex = int(testconfig.get('TestM%d'%vm, 'dest_vm'))-1
				f.write('dest_ip="%s"\n'% vmDPIP[machine_index[destVMindex]])
				f.write('dest_hex_ip="%s"\n'% hexDPIP[machine_index[destVMindex]])
				f.write('dest_hex_mac="%s"\n'% vmDPmac[machine_index[destVMindex]].replace(':',' '))
			elif re.match('secgw2.*\.cfg',config_file[-1]):
				sutstatcores = cores[-1]
				auto_start.append(True)
				mach_type.append('sut')
			else:
				auto_start.append(True)
				mach_type.append('none')
		f.close
		tasks = tasks_for_this_cfg.union(tasks)
log.debug("Tasks detected in all PROX config files %r"%tasks)
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
		clients.append(prox_ctrl(vmAdminIP[machine_index[vm]], key,user))
		connect_client(clients[-1])
		if (vim_type == "OpenStack"):
# Creating script to bind the right network interface to the poll mode driver
			devbindfile = '{}_{}_devbindvm{}.sh'.format(env,test_file, vm+1)
			with open(devbindfile, "w") as f:
				newText= 'link="$(ip -o link | grep '+vmDPmac[machine_index[vm]]+' |cut -d":" -f 2)"\n'
				f.write(newText)
				newText= 'if [ -n "$link" ];\n'
				f.write(newText)
				newText= 'then\n'
				f.write(newText)
				newText= '        echo Need to bind\n'
				f.write(newText)
				newText= '        sudo ' + rundir + '/dpdk/usertools/dpdk-devbind.py --force --bind igb_uio $('+rundir+'/dpdk/usertools/dpdk-devbind.py --status |grep  $link | cut -d" " -f 1)\n'
				f.write(newText)
				newText= 'else\n'
				f.write(newText)
				newText= '       echo Assuming port is already bound to DPDK\n'
				f.write(newText)
				newText= 'fi\n'
				f.write(newText)
				newText= 'exit 0\n'
				f.write(newText)
			st = os.stat(devbindfile)
			os.chmod(devbindfile, st.st_mode | stat.S_IEXEC)
			clients[-1].scp_put('./%s'%devbindfile, rundir+'/devbind.sh')
			cmd = 'sudo ' + rundir+ '/devbind.sh'
			clients[-1].run_cmd(cmd)
			log.debug("devbind.sh running on VM%d"%(vm+1))

		clients[-1].scp_put('./%s'%config_file[vm], rundir+'/%s'%config_file[vm])
		clients[-1].scp_put('./{}_{}_parameters{}.lua'.format(env,test_file, vm+1), rundir + '/parameters.lua')
		if not configonly:
			if prox_launch_exit[vm]:
				log.debug("Starting PROX on VM%d"%(vm+1))
				if auto_start[vm]:
					cmd = 'sudo ' + rundir + '/prox -t -o cli -f ' + rundir + '/%s'%config_file[vm]
				else:
					cmd = 'sudo ' + rundir + '/prox -e -t -o cli -f ' + rundir + '/%s'%config_file[vm]
				clients[-1].fork_cmd(cmd, 'PROX Testing on TestM%d'%(vm+1))
			socks_control.append(prox_launch_exit[vm])
			socks.append(connect_socket(clients[-1]))
			sock_type.append(mach_type[vm])

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
	STARTSPEED = float(testconfig.get('BinarySearchParams', 'startspeed'))
	
if configonly:
	sys.exit()
####################################################
# Run test cases
# Best to run the flow test at the end since otherwise the tests coming after might be influenced by the big number of entries in the switch flow tables
####################################################
gensock_index = sock_type.index('gen') if 'gen' in sock_type else -1
sutsock_index = sock_type.index('sut') if 'sut' in sock_type else -1
number_of_tests = testconfig.get('DEFAULT', 'number_of_tests')
for test_nr in range(1, int(number_of_tests)+1):
	test=testconfig.get('test%d'%test_nr,'test')
	log.info(test)
	if test == 'flowsizetest':
		get_BinarySearchParams()
		packet_size_list = ast.literal_eval(testconfig.get('test%d'%test_nr, 'packetsizes'))
		flow_size_list = ast.literal_eval(testconfig.get('test%d'%test_nr, 'flows'))
		run_flow_size_test(socks[gensock_index],socks[sutsock_index])
	elif test == 'fixed_rate':
		packet_size_list = ast.literal_eval(testconfig.get('test%d'%test_nr, 'packetsizes'))
		flow_size_list = ast.literal_eval(testconfig.get('test%d'%test_nr, 'flows'))
		STARTSPEED = float(testconfig.get('test%d'%test_nr, 'speed'))
		run_fixed_rate(socks[gensock_index],socks[sutsock_index])
	elif test == 'corestats':
		run_core_stats(socks)
	elif test == 'portstats':
		run_port_stats(socks)
	elif test == 'impairtest':
		get_BinarySearchParams()
		PACKETSIZE = int(testconfig.get('test%d'%test_nr, 'packetsize'))
		FLOWSIZE = int(testconfig.get('test%d'%test_nr, 'flowsize'))
		run_impairtest(socks[gensock_index],socks[sutsock_index])
	elif test == 'irqtest':
		run_irqtest(socks)
	elif test == 'warmuptest':
		PACKETSIZE = int(testconfig.get('test%d'%test_nr, 'packetsize'))
		FLOWSIZE = int(testconfig.get('test%d'%test_nr, 'flowsize'))
		WARMUPSPEED = int(testconfig.get('test%d'%test_nr, 'warmupspeed'))
		WARMUPTIME = int(testconfig.get('test%d'%test_nr, 'warmuptime'))
		run_warmuptest(socks[gensock_index])
####################################################
