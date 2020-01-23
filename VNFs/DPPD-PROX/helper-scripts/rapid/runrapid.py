#!/usr/bin/python

##
## Copyright (c) 2010-2020 Intel Corporation
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
from numpy import inf
from math import ceil

version="20.01.10"
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

def report_result(flow_number,size,speed,pps_req_tx,pps_tx,pps_sut_tx,pps_rx,lat_avg,lat_perc,lat_perc_max,lat_max,tx,rx,tot_drop,elapsed_time,speed_prefix='',lat_avg_prefix='',lat_perc_prefix='',lat_max_prefix='',abs_drop_rate_prefix='',drop_rate_prefix=''):
	if flow_number < 0:
		flow_number_str = '| ({:>4}) |'.format(abs(flow_number))
	else:
		flow_number_str = '|{:>7} |'.format(flow_number)
	if pps_req_tx == None:
		pps_req_tx_str = '{0: >14}'.format('   NA     |')
	else:
		pps_req_tx_str = '{:>7.3f} Mpps |'.format(pps_req_tx)
	if pps_tx == None:
		pps_tx_str = '{0: >14}'.format('   NA     |')
	else:
		pps_tx_str = '{:>7.3f} Mpps |'.format(pps_tx) 
	if pps_sut_tx == None:
		pps_sut_tx_str = '{0: >14}'.format('   NA     |')
	else:
		pps_sut_tx_str = '{:>7.3f} Mpps |'.format(pps_sut_tx)
	if pps_rx == None:
		pps_rx_str = '{0: >24|}'.format('NA        ')
	else:
		pps_rx_str = bcolors.OKBLUE + '{:>4.1f} Gb/s |{:7.3f} Mpps {}|'.format(get_speed(pps_rx,size),pps_rx,bcolors.ENDC)
	if tot_drop == None:
		tot_drop_str = ' |       NA  | '
	else:
		tot_drop_str = ' | {:>9.0f} | '.format(tot_drop)
	if lat_perc == None:
		lat_perc_str = ' |{:^10.10}|'.format('NA')
	elif lat_perc_max == True:
		lat_perc_str = ' |>{}{:>5.0f} us{} |'.format(lat_perc_prefix,float(lat_perc), bcolors.ENDC) 
	else:
		lat_perc_str = ' | {}{:>5.0f} us{} |'.format(lat_perc_prefix,float(lat_perc), bcolors.ENDC) 
	if elapsed_time == None:
		elapsed_time_str = ' NA |'
	else:
		elapsed_time_str = '{:>3.0f} |'.format(elapsed_time)
	return(flow_number_str + '{:>5.1f}'.format(speed) + '% '+speed_prefix +'{:>6.3f}'.format(get_pps(speed,size)) + ' Mpps|'+ pps_req_tx_str + pps_tx_str + bcolors.ENDC + pps_sut_tx_str + pps_rx_str +lat_avg_prefix+ ' {:>5.0f}'.format(lat_avg)+' us'+lat_perc_str+lat_max_prefix+'{:>6.0f}'.format(lat_max)+' us | ' + '{:>9.0f}'.format(tx) + ' | {:>9.0f}'.format(rx) + ' | '+ abs_drop_rate_prefix+ '{:>9.0f}'.format(tx-rx) + tot_drop_str +drop_rate_prefix+ '{:>5.2f}'.format(float(tx-rx)/tx)  +bcolors.ENDC+' |' + elapsed_time_str)
		
def run_iteration(gensock, sutsock, requested_duration,flow_number,size,speed):
	r = 0;
	sleep_time = 2
	while (r < TST009_MAXr):
		time.sleep(sleep_time)
		# Sleep_time is needed to be able to do accurate measurements to check for packet loss. We need to make this time large enough so that we do not take the first measurement while some packets from the previous tests migth still be in flight
		t1_rx, t1_non_dp_rx, t1_tx, t1_non_dp_tx, t1_drop, t1_tx_fail, t1_tsc, abs_tsc_hz = gensock.core_stats(genstatcores,gentasks)
		t1_dp_rx = t1_rx - t1_non_dp_rx
		t1_dp_tx = t1_tx - t1_non_dp_tx
		gensock.start(gencores)
		time.sleep(2) ## Needs to be 2 seconds since this the time that PROX uses to refresh the stats. Note that this can be changed in PROX!! Don't do it.
		if sutsock!='none':
			t2_sut_rx, t2_sut_non_dp_rx, t2_sut_tx, t2_sut_non_dp_tx, t2_sut_drop, t2_sut_tx_fail, t2_sut_tsc, sut_tsc_hz = sutsock.core_stats(sutstatcores,tasks)
			##t2_sut_rx = t2_sut_rx - t2_sut_non_dp_rx
			##t2_sut_tx = t2_sut_tx - t2_sut_non_dp_tx
		t2_rx, t2_non_dp_rx, t2_tx, t2_non_dp_tx, t2_drop, t2_tx_fail, t2_tsc, tsc_hz = gensock.core_stats(genstatcores,gentasks)
		tx = t2_tx - t1_tx
		dp_tx =  tx - (t2_non_dp_tx - t1_non_dp_tx )
		dp_rx =  t2_rx - t1_rx - (t2_non_dp_rx - t1_non_dp_rx) 
		tot_dp_drop = dp_tx - dp_rx
		if tx == 0:
			log.critical("TX = 0. Test interrupted since no packet has been sent.")
			raise Exception("TX = 0")
		if dp_tx == 0:
			log.critical("Only non-dataplane packets (e.g. ARP) sent. Test interrupted since no packet has been sent.")
			raise Exception("Only non-dataplane packets (e.g. ARP) sent")
		# Ask PROX to calibrate the bucket size once we have a PROX function to do this.
		# Measure latency statistics per second
		lat_min, lat_max, lat_avg, used_avg, t2_lat_tsc, lat_hz, buckets = gensock.lat_stats(latcores)
		lat_samples = sum(buckets)
		sample_count = 0
		for sample_percentile, bucket in enumerate(buckets,start=1):
			sample_count += bucket
			if sample_count > (lat_samples * LAT_PERCENTILE):
				break
		if sample_percentile == len(buckets):
			percentile_max = True
		else:
			percentile_max = False
		sample_percentile = sample_percentile *  float(2 ** BUCKET_SIZE_EXP) / (float(lat_hz)/float(10**6))
		if test == 'fixed_rate':
			log.info(report_result(flow_number,size,speed,None,None,None,None,lat_avg,sample_percentile,percentile_max,lat_max, dp_tx, dp_rx , None, None))
		tot_rx = tot_non_dp_rx = tot_tx = tot_non_dp_tx = tot_drop = 0
		lat_avg = used_avg = 0
		buckets_total = [0] * 128
		tot_lat_samples = 0
		tot_lat_measurement_duration = float(0)
		tot_core_measurement_duration = float(0)
		tot_sut_core_measurement_duration = float(0)
		tot_sut_rx = tot_sut_non_dp_rx = tot_sut_tx = tot_sut_non_dp_tx = tot_sut_drop = tot_sut_tx_fail = tot_sut_tsc = 0
		lat_avail = core_avail = sut_avail = False
		##while (tot_core_measurement_duration - float(requested_duration) <= 0.1) or (tot_sut_core_measurement_duration - float(requested_duration) <= 0.1) or (tot_lat_measurement_duration - float(requested_duration) <= 0.1):
		while (tot_core_measurement_duration - float(requested_duration) <= 0.1) or (tot_lat_measurement_duration - float(requested_duration) <= 0.1):
			time.sleep(0.5)
			lat_min_sample, lat_max_sample, lat_avg_sample, used_sample, t3_lat_tsc, lat_hz, buckets = gensock.lat_stats(latcores)
			single_lat_measurement_duration = (t3_lat_tsc - t2_lat_tsc) * 1.0 / lat_hz  # time difference between the 2 measurements, expressed in seconds.
			# Get statistics after some execution time
			if single_lat_measurement_duration != 0:
				# A second has passed in between to lat_stats requests. Hence we need to process the results
				tot_lat_measurement_duration = tot_lat_measurement_duration + single_lat_measurement_duration
				if lat_min > lat_min_sample:
					lat_min = lat_min_sample
				if lat_max < lat_max_sample:
					lat_max = lat_max_sample
				lat_avg = lat_avg + lat_avg_sample * single_lat_measurement_duration # Sometimes, There is more than 1 second between 2 lat_stats. Hence we will take the latest measurement
				used_avg = used_avg + used_sample * single_lat_measurement_duration  # and give it more weigth.
				lat_samples = sum(buckets)
				tot_lat_samples += lat_samples
				sample_count = 0
				for sample_percentile, bucket in enumerate(buckets,start=1):
					sample_count += bucket
					if sample_count > lat_samples * LAT_PERCENTILE:
						break
				if sample_percentile == len(buckets):
					percentile_max = True
				else:
					percentile_max = False
				sample_percentile = sample_percentile *  float(2 ** BUCKET_SIZE_EXP) / (float(lat_hz)/float(10**6))
				buckets_total = [buckets_total[i] + buckets[i] for i in range(len(buckets_total))] 
				t2_lat_tsc = t3_lat_tsc
				lat_avail = True
			t3_rx, t3_non_dp_rx, t3_tx, t3_non_dp_tx, t3_drop, t3_tx_fail, t3_tsc, tsc_hz = gensock.core_stats(genstatcores,gentasks)
			single_core_measurement_duration = (t3_tsc - t2_tsc) * 1.0 / tsc_hz  # time difference between the 2 measurements, expressed in seconds.
			if single_core_measurement_duration!= 0:
				stored_single_core_measurement_duration = single_core_measurement_duration
				tot_core_measurement_duration = tot_core_measurement_duration + single_core_measurement_duration
				delta_rx = t3_rx - t2_rx
				tot_rx += delta_rx
				delta_non_dp_rx = t3_non_dp_rx - t2_non_dp_rx
				tot_non_dp_rx += delta_non_dp_rx
				delta_tx = t3_tx - t2_tx
				tot_tx += delta_tx
				delta_non_dp_tx = t3_non_dp_tx - t2_non_dp_tx
				tot_non_dp_tx += delta_non_dp_tx
				delta_dp_tx = delta_tx -delta_non_dp_tx
				delta_dp_rx = delta_rx -delta_non_dp_rx
				delta_dp_drop = delta_dp_tx - delta_dp_rx
				tot_dp_drop += delta_dp_drop
				delta_drop = t3_drop - t2_drop
				tot_drop += delta_drop
				t2_rx, t2_non_dp_rx, t2_tx, t2_non_dp_tx, t2_drop, t2_tx_fail, t2_tsc = t3_rx, t3_non_dp_rx, t3_tx, t3_non_dp_tx, t3_drop, t3_tx_fail, t3_tsc
				core_avail = True
			if sutsock!='none':
				t3_sut_rx, t3_sut_non_dp_rx, t3_sut_tx, t3_sut_non_dp_tx, t3_sut_drop, t3_sut_tx_fail, t3_sut_tsc, sut_tsc_hz = sutsock.core_stats(sutstatcores,tasks)
				single_sut_core_measurement_duration = (t3_sut_tsc - t2_sut_tsc) * 1.0 / tsc_hz  # time difference between the 2 measurements, expressed in seconds.
				if single_sut_core_measurement_duration!= 0:
					stored_single_sut_core_measurement_duration = single_sut_core_measurement_duration
					tot_sut_core_measurement_duration = tot_sut_core_measurement_duration + single_sut_core_measurement_duration
					tot_sut_rx += t3_sut_rx - t2_sut_rx
					tot_sut_non_dp_rx += t3_sut_non_dp_rx - t2_sut_non_dp_rx
					delta_sut_tx = t3_sut_tx - t2_sut_tx
					tot_sut_tx += delta_sut_tx
					delta_sut_non_dp_tx = t3_sut_non_dp_tx - t2_sut_non_dp_tx
					tot_sut_non_dp_tx += delta_sut_non_dp_tx 
					t2_sut_rx, t2_sut_non_dp_rx, t2_sut_tx, t2_sut_non_dp_tx, t2_sut_drop, t2_sut_tx_fail, t2_sut_tsc = t3_sut_rx, t3_sut_non_dp_rx, t3_sut_tx, t3_sut_non_dp_tx, t3_sut_drop, t3_sut_tx_fail, t3_sut_tsc
					sut_avail = True
			if test == 'fixed_rate':
				if lat_avail == core_avail == True:
					lat_avail = core_avail = False
					pps_req_tx = (delta_tx + delta_drop - delta_rx)/stored_single_core_measurement_duration/1000000
					pps_tx = delta_tx/stored_single_core_measurement_duration/1000000
					if sutsock!='none' and sut_avail:
						pps_sut_tx = delta_sut_tx/stored_single_sut_core_measurement_duration/1000000
						sut_avail = False
					else:
						pps_sut_tx = None
					pps_rx = delta_rx/stored_single_core_measurement_duration/1000000
					log.info(report_result(flow_number,size,speed,pps_req_tx,pps_tx,pps_sut_tx,pps_rx,lat_avg_sample,sample_percentile,percentile_max,lat_max_sample,delta_dp_tx,delta_dp_rx,tot_dp_drop,stored_single_core_measurement_duration))
		#Stop generating
		gensock.stop(gencores)
		r += 1
		lat_avg = lat_avg / float(tot_lat_measurement_duration)
		used_avg = used_avg / float(tot_lat_measurement_duration)
		t4_tsc = t2_tsc
		while t4_tsc == t2_tsc:
			t4_rx, t4_non_dp_rx, t4_tx, t4_non_dp_tx, t4_drop, t4_tx_fail, t4_tsc, abs_tsc_hz = gensock.core_stats(genstatcores,gentasks)
		if test == 'fixed_rate':
			t4_lat_tsc = t2_lat_tsc
			while t4_lat_tsc == t2_lat_tsc:
				lat_min_sample, lat_max_sample, lat_avg_sample, used_sample, t4_lat_tsc, lat_hz, buckets = gensock.lat_stats(latcores)
			sample_count = 0
			lat_samples = sum(buckets)
			for percentile, bucket in enumerate(buckets,start=1):
				sample_count += bucket
				if sample_count > lat_samples * LAT_PERCENTILE:
					break
			if percentile == len(buckets):
				percentile_max = True
			else:
				percentile_max = False
			percentile = percentile *  float(2 ** BUCKET_SIZE_EXP) / (float(lat_hz)/float(10**6))
			lat_max = lat_max_sample
			lat_avg = lat_avg_sample
			delta_rx = t4_rx - t2_rx
			delta_non_dp_rx = t4_non_dp_rx - t2_non_dp_rx
			delta_tx = t4_tx - t2_tx
			delta_non_dp_tx = t4_non_dp_tx - t2_non_dp_tx
			delta_dp_tx = delta_tx -delta_non_dp_tx
			delta_dp_rx = delta_rx -delta_non_dp_rx
			dp_tx = delta_dp_tx
			dp_rx = delta_dp_rx
			tot_dp_drop += delta_dp_tx - delta_dp_rx
			pps_req_tx = None
			pps_tx = None
			pps_sut_tx = None
			pps_rx = None
			drop_rate = 100.0*(dp_tx-dp_rx)/dp_tx
			tot_core_measurement_duration = None
			break ## Not really needed since the while loop will stop when evaluating the value of r
		else:
			sample_count = 0
			for percentile, bucket in enumerate(buckets_total,start=1):
				sample_count += bucket
				if sample_count > tot_lat_samples * LAT_PERCENTILE:
					break
			if percentile == len(buckets):
				percentile_max = True
			else:
				percentile_max = False
			percentile = percentile *  float(2 ** BUCKET_SIZE_EXP) / (float(lat_hz)/float(10**6))
			pps_req_tx = (tot_tx + tot_drop - tot_rx)/tot_core_measurement_duration/1000000.0 # tot_drop is all packets dropped by all tasks. This includes packets dropped at the generator task + packets dropped by the nop task. In steady state, this equals to the number of packets received by this VM
			pps_tx = tot_tx/tot_core_measurement_duration/1000000.0 # tot_tx is all generated packets actually accepted by the interface
			pps_rx = tot_rx/tot_core_measurement_duration/1000000.0 # tot_rx is all packets received by the nop task = all packets received in the gen VM
			if sutsock!='none' and sut_avail:
				pps_sut_tx = tot_sut_tx / tot_sut_core_measurement_duration / 1000000.0
			else:
				pps_sut_tx = None
			dp_tx = (t4_tx - t1_tx) - (t4_non_dp_tx - t1_non_dp_tx)
			dp_rx = (t4_rx - t1_rx) - (t4_non_dp_rx - t1_non_dp_rx)
			tot_dp_drop = dp_tx - dp_rx
			drop_rate = 100.0*tot_dp_drop/dp_tx
			if ((drop_rate < DROP_RATE_TRESHOLD) or (tot_dp_drop == DROP_RATE_TRESHOLD ==0) or (tot_dp_drop > TST009_MAXz)):
				break
	return(pps_req_tx,pps_tx,pps_sut_tx,pps_rx,lat_avg,percentile,percentile_max,lat_max,dp_tx,dp_rx,tot_dp_drop,(t4_tx_fail - t1_tx_fail),drop_rate,lat_min,used_avg,r,tot_core_measurement_duration)

def new_speed(speed,size,success):
	if test == 'fixed_rate':
		return (STARTSPEED)
	elif TST009:
		global TST009_m
		global TST009_L
		global TST009_R
		if success:
			TST009_L = TST009_m + 1
		else:
			TST009_R = max(TST009_m - 1, TST009_L)
		TST009_m = int ((TST009_L + TST009_R)/2)
		return (get_percentageof10Gbs(TST009_S[TST009_m],size))
	else:
		global minspeed
		global maxspeed
		if success:
			minspeed = speed
		else:
			maxspeed = speed
		return ((minspeed + maxspeed)/2.0)

def get_start_speed_and_init(size):
	if test == 'fixed_rate':
		return (STARTSPEED)
	elif TST009:
		global TST009_L
		global TST009_R
		global TST009_m
		TST009_L = 0
		TST009_R = TST009_n - 1
		TST009_m = int((TST009_L + TST009_R) / 2)
		return (get_percentageof10Gbs(TST009_S[TST009_m],size))
	else:
		global minspeed
		global maxspeed
		minspeed = 0
		maxspeed = STARTSPEED 
		return (STARTSPEED)

def resolution_achieved():
	if test == 'fixed_rate':
		return (True)
	elif TST009:
		return (TST009_L == TST009_R)
	else:
		return ((maxspeed - minspeed) <= ACCURACY)

def get_percentageof10Gbs(pps_speed,size):
	# speed is given in pps, returning % of 10Gb/s
	return (pps_speed / 1000000.0 * 0.08 * (size+24))

def get_pps(speed,size):
	# speed is given in % of 10Gb/s, returning Mpps
	return (speed * 100.0 / (8*(size+24)))

def get_speed(packet_speed,size):
	# return speed in Gb/s
	return (packet_speed / 1000.0 * (8*(size+24)))

def run_flow_size_test(gensock,sutsock):
	global fieldnames
	global writer
	#fieldnames = ['Flows','PacketSize','Gbps','Mpps','AvgLatency','MaxLatency','PacketsDropped','PacketDropRate']
	fieldnames = ['Flows','PacketSize','RequestedPPS','GeneratedPPS','SentPPS','ForwardedPPS','ReceivedPPS','AvgLatencyUSEC','MaxLatencyUSEC','Sent','Received','Lost','LostTotal']
	writer = csv.DictWriter(data_csv_file, fieldnames=fieldnames)
	writer.writeheader()
	gensock.start(latcores)
	for size in packet_size_list:
		size = size-4
		gensock.set_size(gencores,0,size) # This is setting the frame size
		gensock.set_value(gencores,0,16,(size-14),2) # 18 is the difference between the frame size and IP size = size of (MAC addresses, ethertype and FCS)
		gensock.set_value(gencores,0,38,(size-34),2) # 38 is the difference between the frame size and UDP size = 18 + size of IP header (=20)
		# This will only work when using sending UDP packets. For different protocls and ethernet types, we would need a different calculation
		log.info("+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+")
		log.info("| UDP, "+ '{:>5}'.format(size+4) +" bytes, different number of flows by randomizing SRC & DST UDP port                                                                                                              |")
		log.info("+--------+------------------+-------------+-------------+-------------+------------------------+----------+----------+----------+-----------+-----------+-----------+-----------+-------+----+")
		log.info("| Flows  | Speed requested  | Gen by core | Sent by NIC | Fwrd by SUT | Rec. by core           | Avg. Lat.|" + '{:.0f} '.format(LAT_PERCENTILE*100) +"Pcentil| Max. Lat.|   Sent    |  Received |    Lost   | Total Lost|L.Ratio|Time|")
		log.info("+--------+------------------+-------------+-------------+-------------+------------------------+----------+----------+----------+-----------+-----------+-----------+-----------+-------+----+")
		for flow_number in flow_size_list:
			attempts = 0
			gensock.reset_stats()
			if sutsock!='none':
				sutsock.reset_stats()
			source_port,destination_port = flows[flow_number]
			gensock.set_random(gencores,0,34,source_port,2)
			gensock.set_random(gencores,0,36,destination_port,2)
			endspeed = None
			speed = get_start_speed_and_init(size)
			while True:
				attempts += 1
				endwarning = False
				print(str(flow_number)+' flows: Measurement ongoing at speed: ' + str(round(speed,2)) + '%      ',end='\r')
				sys.stdout.flush()
				# Start generating packets at requested speed (in % of a 10Gb/s link)
				gensock.speed(speed / len(gencores) / len (gentasks), gencores, gentasks)
				##time.sleep(1)
				# Get statistics now that the generation is stable and initial ARP messages are dealt with
				pps_req_tx,pps_tx,pps_sut_tx,pps_rx,lat_avg,lat_perc , lat_perc_max, lat_max, abs_tx,abs_rx,abs_dropped, abs_tx_fail, drop_rate, lat_min, lat_used, r, actual_duration = run_iteration(gensock,sutsock,float(runtime),flow_number,size,speed)
				if r > 1:
					retry_warning = bcolors.WARNING + ' {:1} retries needed'.format(r) +  bcolors.ENDC
				else:
					retry_warning = ''
				# Drop rate is expressed in percentage. lat_used is a ratio (0 to 1). The sum of these 2 should be 100%.
				# If the some is lower than 95, it means that more than 5% of the latency measurements where dropped for accuracy reasons.
				if (drop_rate + lat_used * 100) < 95:
					lat_warning = bcolors.WARNING + ' Latency accuracy issue?: {:>3.0f}%'.format(lat_used*100) +  bcolors.ENDC
				else:
					lat_warning = ''
				if test == 'fixed_rate':
					endspeed = speed
					endpps_req_tx = None
					endpps_tx = None
					endpps_sut_tx = None
					endpps_rx = None
					endlat_avg = lat_avg
					endlat_perc = lat_perc
					endlat_perc_max = lat_perc_max
					endlat_max = lat_max
					endabs_dropped = abs_dropped
					enddrop_rate = drop_rate
					endabs_tx = abs_tx
					endabs_rx = abs_rx
					if lat_warning or gen_warning or retry_warning:
						endwarning = '|        | {:177.177} |'.format(retry_warning + lat_warning + gen_warning)
					success = True
					speed_prefix = lat_avg_prefix = lat_perc_prefix = lat_max_prefix = abs_drop_rate_prefix = drop_rate_prefix = bcolors.ENDC
				# The following if statement is testing if we pass the success criteria of a certain drop rate, average latency and maximum latency below the threshold
				# The drop rate success can be achieved in 2 ways: either the drop rate is below a treshold, either we want that no packet has been lost during the test
				# This can be specified by putting 0 in the .test file
				elif ((drop_rate < DROP_RATE_TRESHOLD) or (abs_dropped==DROP_RATE_TRESHOLD ==0)) and (lat_avg< LAT_AVG_TRESHOLD) and (lat_perc< LAT_PERC_TRESHOLD) and (lat_max < LAT_MAX_TRESHOLD):
					lat_avg_prefix = bcolors.ENDC
					lat_perc_prefix = bcolors.ENDC
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
					endpps_sut_tx = pps_sut_tx
					endpps_rx = pps_rx
					endlat_avg = lat_avg
					endlat_perc = lat_perc
					endlat_perc_max = lat_perc_max
					endlat_max = lat_max
					endabs_dropped = None
					enddrop_rate = drop_rate
					endabs_tx = abs_tx
					endabs_rx = abs_rx
					if lat_warning or gen_warning or retry_warning:
						endwarning = '|        | {:177.177} |'.format(retry_warning + lat_warning + gen_warning)
					success = True
					success_message=' SUCCESS'
					speed_prefix = lat_avg_prefix = lat_perc_prefix = lat_max_prefix = abs_drop_rate_prefix = drop_rate_prefix = bcolors.ENDC
					log.debug(report_result(-attempts,size,speed,pps_req_tx,pps_tx,pps_sut_tx,pps_rx,lat_avg,lat_perc,lat_perc_max,lat_max,abs_tx,abs_rx,abs_dropped,actual_duration,speed_prefix,lat_avg_prefix,lat_max_prefix,abs_drop_rate_prefix,drop_rate_prefix)+ success_message + retry_warning + lat_warning + gen_warning)
				else:
					success_message=' FAILED'
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
					if (lat_perc< LAT_PERC_TRESHOLD):
						lat_perc_prefix = bcolors.ENDC
					else:
						lat_perc_prefix = bcolors.FAIL
					if (lat_max< LAT_MAX_TRESHOLD):
						lat_max_prefix = bcolors.ENDC
					else:
						lat_max_prefix = bcolors.FAIL
					if (((get_pps(speed,size) - pps_tx)/get_pps(speed,size))<0.001):
						speed_prefix = bcolors.ENDC
					else:
						speed_prefix = bcolors.FAIL
					success = False 
					log.debug(report_result(-attempts,size,speed,pps_req_tx,pps_tx,pps_sut_tx,pps_rx,lat_avg,lat_perc,lat_perc_max,lat_max,abs_tx,abs_rx,abs_dropped,actual_duration,speed_prefix,lat_avg_prefix,lat_perc_prefix,lat_max_prefix,abs_drop_rate_prefix,drop_rate_prefix)+ success_message + retry_warning + lat_warning + gen_warning)
				speed = new_speed(speed, size, success)
				if resolution_achieved():
					break
			if endspeed !=  None:
				log.info(report_result(flow_number,size,endspeed,endpps_req_tx,endpps_tx,endpps_sut_tx,endpps_rx,endlat_avg,endlat_perc,endlat_perc_max,endlat_max,endabs_tx,endabs_rx,endabs_dropped,actual_duration,speed_prefix,lat_avg_prefix,lat_perc_prefix,lat_max_prefix,abs_drop_rate_prefix,drop_rate_prefix))
				if endwarning:
					log.info (endwarning)
				log.info("+--------+------------------+-------------+-------------+-------------+------------------------+----------+----------+----------+-----------+-----------+-----------+-----------+-------+----+")
				writer.writerow({'Flows':flow_number,'PacketSize':(size+4),'RequestedPPS':get_pps(endspeed,size),'GeneratedPPS':endpps_req_tx,'SentPPS':endpps_tx,'ForwardedPPS':endpps_sut_tx,'ReceivedPPS':endpps_rx,'AvgLatencyUSEC':endlat_avg,'MaxLatencyUSEC':endlat_max,'Sent':endabs_tx,'Received':endabs_rx,'Lost':endabs_dropped,'LostTotal':endabs_dropped})
				if PushGateway:
					URL     = PushGateway + '/metrics/job/' + TestName + '/instance/' + env
					DATA = 'Flows {}\nPacketSize {}\nRequestedPPS {}\nGeneratedPPS {}\nSentPPS {}\nForwardedPPS {}\nReceivedPPS {}\nAvgLatencyUSEC {}\nMaxLatencyUSEC {}\nSent {}\nReceived {}\nLost {}\nLostTotal {}\n'.format(flow_number,size+4,get_pps(endspeed,size),endpps_req_tx,endpps_tx,endpps_sut_tx,endpps_rx,endlat_avg,endlat_max,endabs_tx,endabs_rx,endabs_Dropped,endabs_dropped)
					HEADERS = {'X-Requested-With': 'Python requests', 'Content-type': 'text/xml'}
					response = requests.post(url=URL, data=DATA,headers=HEADERS)
			else:
				log.info('|{:>7}'.format(str(flow_number))+" | Speed 0 or close to 0")
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
		pps_req_tx,pps_tx,pps_sut_tx_str,pps_rx,lat_avg, lat_perc, lat_perc_max, lat_max, abs_dropped, abs_tx_fail, abs_tx, lat_min, lat_used, r, actual_duration = run_iteration(gensock,sutsock,runtime)
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
	time.sleep(WARMUPTIME)

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
config_file =[]
prox_socket =[]
prox_launch_exit =[]
auto_start =[]
mach_type =[]
sock_type =[]
cores = []
ports = []
tasks = {}
TST009_S = []

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
if testconfig.has_option('DEFAULT', 'lat_percentile'):
	LAT_PERCENTILE = float(testconfig.get('DEFAULT', 'lat_percentile')) /100.0
else:
	LAT_PERCENTILE = 0.99
log.info('Latency percentile measured at {:.0f}%'.format(LAT_PERCENTILE*100))
config = ConfigParser.RawConfigParser()
config.read(env)
machine_map = ConfigParser.RawConfigParser()
machine_map.read(machine_map_file)
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
				if testconfig.has_option('TestM%d'%vm, 'bucket_size_exp'):
					BUCKET_SIZE_EXP = int(testconfig.get('TestM%d'%vm, 'bucket_size_exp'))
				else:
					BUCKET_SIZE_EXP = 11
				f.write('bucket_size_exp="%s"\n'% BUCKET_SIZE_EXP)
				if testconfig.has_option('TestM%d'%vm, 'heartbeat'):
					heartbeat = int(testconfig.get('TestM%d'%vm, 'heartbeat'))
				else:
					heartbeat = 60
				f.write('heartbeat="%s"\n'% heartbeat)
			elif re.match('(l2){0,1}gen_gw.*\.cfg',config_file[-1]):
				if testconfig.has_option('TestM%d'%vm, 'bucket_size_exp'):
					BUCKET_SIZE_EXP = int(testconfig.get('TestM%d'%vm, 'bucket_size_exp'))
				else:
					BUCKET_SIZE_EXP = 11
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
				if testconfig.has_option('TestM%d'%vm, 'bucket_size_exp'):
					BUCKET_SIZE_EXP = int(testconfig.get('TestM%d'%vm, 'bucket_size_exp'))
				else:
					BUCKET_SIZE_EXP = 11
				f.write('bucket_size_exp="%s"\n'% BUCKET_SIZE_EXP)
				if testconfig.has_option('TestM%d'%vm, 'heartbeat'):
					heartbeat = int(testconfig.get('TestM%d'%vm, 'heartbeat'))
				else:
					heartbeat = 60
				f.write('heartbeat="%s"\n'% heartbeat)
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
					cmd = 'sudo ' +rundir + '/prox/build/prox -t -o cli -f ' + rundir + '/%s'%config_file[vm]
				else:
					cmd = 'sudo ' +rundir + '/prox/build/prox -e -t -o cli -f ' + rundir + '/%s'%config_file[vm]
				clients[-1].fork_cmd(cmd, 'PROX Testing on TestM%d'%(vm+1))
			socks_control.append(prox_launch_exit[vm])
			socks.append(connect_socket(clients[-1]))
			sock_type.append(mach_type[vm])

def get_BinarySearchParams() :
	global  DROP_RATE_TRESHOLD
	global  LAT_AVG_TRESHOLD
	global  LAT_PERC_TRESHOLD
	global  LAT_MAX_TRESHOLD
	global  ACCURACY
	global	STARTSPEED
	global  TST009
	global  TST009_MAXr
	global  TST009_MAXz
	DROP_RATE_TRESHOLD = float(testconfig.get('BinarySearchParams', 'drop_rate_threshold'))
	LAT_AVG_TRESHOLD = float(testconfig.get('BinarySearchParams', 'lat_avg_threshold'))
	LAT_PERC_TRESHOLD = float(testconfig.get('BinarySearchParams', 'lat_perc_threshold'))
	LAT_MAX_TRESHOLD = float(testconfig.get('BinarySearchParams', 'lat_max_threshold'))
	ACCURACY = float(testconfig.get('BinarySearchParams', 'accuracy'))
	STARTSPEED = float(testconfig.get('BinarySearchParams', 'startspeed'))
	TST009_MAXr = 1
	TST009_MAXz = inf
	TST009 = False
	
def get_FixedRateParams() :
	global  DROP_RATE_TRESHOLD
	global  LAT_AVG_TRESHOLD
	global  LAT_PERC_TRESHOLD
	global  LAT_MAX_TRESHOLD
	global  flow_size_list
	global  packet_size_list
	global	STARTSPEED
	global  TST009
	global  TST009_MAXr
	global  TST009_MAXz
	DROP_RATE_TRESHOLD = inf
	LAT_AVG_TRESHOLD = inf
	LAT_PERC_TRESHOLD = inf
	LAT_MAX_TRESHOLD = inf
	TST009_MAXr = 1
	TST009_MAXz = inf
	TST009 = False
	packet_size_list = ast.literal_eval(testconfig.get('test%d'%test_nr, 'packetsizes'))
	flow_size_list = ast.literal_eval(testconfig.get('test%d'%test_nr, 'flows'))
	STARTSPEED = float(testconfig.get('test%d'%test_nr, 'speed'))
	
def get_TST009SearchParams() :
	global  DROP_RATE_TRESHOLD
	global  LAT_AVG_TRESHOLD
	global  LAT_PERC_TRESHOLD
	global  LAT_MAX_TRESHOLD
	global  TST009
	global  TST009_MAXr
	global  TST009_MAXz
	global  TST009_MAXFramesAllIngress
	global  TST009_StepSize
	global  TST009_n
	global  TST009_L
	global  TST009_R
	global	TST009_S
	if testconfig.has_option('TST009SearchParams', 'drop_rate_threshold'):
		DROP_RATE_TRESHOLD = float(testconfig.get('TST009SearchParams', 'drop_rate_threshold'))
	else:
		DROP_RATE_TRESHOLD = 0
	LAT_AVG_TRESHOLD = inf
	LAT_PERC_TRESHOLD = inf
	LAT_MAX_TRESHOLD = inf
	TST009_MAXr = float(testconfig.get('TST009SearchParams', 'MAXr'))
	TST009_MAXz = float(testconfig.get('TST009SearchParams', 'MAXz'))
	TST009_MAXFramesAllIngress = int(testconfig.get('TST009SearchParams', 'MAXFramesPerSecondAllIngress'))
	TST009_StepSize = int(testconfig.get('TST009SearchParams', 'StepSize'))
	TST009_n = int(ceil(TST009_MAXFramesAllIngress / TST009_StepSize))
	TST009 = True
	TST009_L = 0
	TST009_R = TST009_n - 1
	for m in range(0, TST009_n):
		TST009_S.append((m+1) * TST009_StepSize)

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
	elif test == 'TST009test':
		get_TST009SearchParams()
		packet_size_list = ast.literal_eval(testconfig.get('test%d'%test_nr, 'packetsizes'))
		flow_size_list = ast.literal_eval(testconfig.get('test%d'%test_nr, 'flows'))
		run_flow_size_test(socks[gensock_index],socks[sutsock_index])
	elif test == 'fixed_rate':
		get_FixedRateParams()
		run_flow_size_test(socks[gensock_index],socks[sutsock_index])
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
