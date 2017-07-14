#!/bin/env python

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

import socket
import sys
import os
from time import *
from datetime import  datetime
from optparse import OptionParser
import time
from remote_system import *
from math import log

# General parameters
accuracy = 0.1 	# in percent of line rate
max_dropped = 0.1		# in percent
all_pkt_size = [64,128,256,512,1024,1280,1494]
all_ip_src = [0,6,12,18]
all_ip_dst = [0,6,12,18]

# Stear parameters
step_time = 0.001		# in seconds
step_delta = 10		# in percent of line rate

##### Use case 1: packet loss and latency #####
low_steps_delta_for_loss = 0.01                 # Use increment of 0.01% from 0 to low_steps
medium_steps_delta_for_loss = 0.1               # Use increment of 0.1% from low_steps to medium_steps
normal_steps_delta_for_loss = 1.0               # Use increment of 1% from medium_steps till 100%
low_steps = 0.1 
medium_steps = 1.0 

# Prox parameters
tx_port0 = [4]
tx_port1 = [6]
tx_port2 = [8]
tx_port3 = [10]
tx_port4 = [12]
tx_port5 = [14]
tx_port6 = [16]
tx_port7 = [18]
tx_task = 0

all_rx_cores = [20,22,24,26,28,30,32,34]
rx_lat_cores = [20,22,24,26,28,30,32,34]
rx_task = 0

# Some variables, do not change

# Program arguments
parser = OptionParser()
parser.add_option("-d", "--duration", dest="test_duration", help="Duration of each steps", metavar="integer", default=10)
parser.add_option("-s", "--speed", dest="init_speed", help="Initial speed", metavar="integer", default=100)
parser.add_option("-r", "--run", dest="run", help="Run test", metavar="integer", default=0)
parser.add_option("-c", "--configure", dest="configure", help="Configure Test", metavar="integer", default=0)
(options, args) = parser.parse_args()

init_speed = int(options.init_speed)
test_duration = int(options.test_duration)
configure = int(options.configure)
run = int(options.run)

nb_cores_per_interface = len(tx_port0)
max_speed = (100.0/nb_cores_per_interface)
init_speed = (init_speed * 1.0/nb_cores_per_interface)
accuracy = (accuracy * 1.0/nb_cores_per_interface)
normal_steps_delta_for_loss = (normal_steps_delta_for_loss /nb_cores_per_interface)
medium_steps_delta_for_loss = (medium_steps_delta_for_loss /nb_cores_per_interface)
low_steps_delta_for_loss = (low_steps_delta_for_loss /nb_cores_per_interface)
medium_steps = (medium_steps /nb_cores_per_interface)
low_steps = (low_steps /nb_cores_per_interface)

max_dropped = max_dropped / 100

def to_str(arr):
    ret = ""
    first = 1;
    for a in arr:
        if (first == 0):
            ret += ","

        ret += str(a)
        first = 0;
    return ret;

tx_cores_cpe = tx_port0 + tx_port1 + tx_port2 + tx_port3 
tx_cores_inet = tx_port4 + tx_port5 + tx_port6 + tx_port7
tx_cores = tx_cores_cpe + tx_cores_inet

def send_all_pkt_size(cores, pkt_size):
    for c in cores:
        sock.sendall("pkt_size " + str(c) + " 0 " + str(pkt_size) + "\n");

def send_all_value(cores, offset, value, len):
    for c in cores:
        sock.sendall("set value " + str(c) + " 0 " + str(offset) + " " + str(value) + " " + str(len)+ "\n");

def send_all_random(cores, offset, rand_str, len):
    for c in cores:
        sock.sendall("set random " + str(c) + " 0 " + str(offset) + " " + str(rand_str) + " " + str(len)+ "\n");
        #print("set random " + str(c) + " 0 " + str(offset) + " " + str(rand_str) + " " + str(len)+ "\n");

def send_all_speed(cores, speed_perc):
    for c in cores:
        sock.sendall("speed " + str(c) + " 0 " + str(speed_perc) + "\n");

def send_reset_random():
        sock.sendall("reset randoms all" + "\n");

def send_reset_value():
        sock.sendall("reset values all" + "\n");

def rx_stats(tx_cores, tx_task, rx_cores, rx_task):
	rx = tx = drop = tsc = tsc_hs = ierrors = 0
	for e in tx_cores:
		sock.sendall("core stats " + str(e) + " " + str(tx_task) +  "\n")
		recv = recv_once()
		rx += int(recv.split(",")[0])
		tx += int(recv.split(",")[1])
		drop += int(recv.split(",")[2])
		tsc = int(recv.split(",")[3])
		tsc_hz = int(recv.split(",")[4])
	for e in rx_cores:
		sock.sendall("core stats " + str(e) + " " + str(rx_task) +  "\n")
		recv = recv_once()
		rx += int(recv.split(",")[0])
		tx += int(recv.split(",")[1])
		drop += int(recv.split(",")[2])
		tsc = int(recv.split(",")[3])
		tsc_hz = int(recv.split(",")[4])
	# Also get the ierrors as generators might be the bottleneck...
	sock.sendall("tot ierrors tot\n")
	recv = recv_once()
	ierrors += int(recv.split(",")[0])
	rx+=ierrors
	return rx,tx,drop,tsc,tsc_hz

def lat_stats(cores,task):
	lat_min = [0 for e in range(127)]
	lat_max = [0 for e in range(127)]
	lat_avg = [0 for e in range(127)]
	for e in cores:
		sock.sendall("lat stats " + str(e) + " " + str(task) + " " +  "\n")
		recv = recv_once()
		lat_min[e] = int(recv.split(",")[0])
		lat_max[e] = int(recv.split(",")[1])
		lat_avg[e] = int(recv.split(",")[2])
	return lat_min, lat_max, lat_avg

def recv_once():
    ret_str = "";
    done = 0;
    while done == 0:
        dat = sock.recv(256);
        i = 0;
        while(i < len(dat)):
            if (dat[i] == '\n'):
                done = 1
            else:
                ret_str += dat[i];
            i = i + 1;
    return ret_str

def set_pkt_sizes(tx_cores, p):
	send_all_pkt_size(tx_cores, p-4)
	# For all cores, need to adapt IP Length (byte 16) and UDP Length (byte 38) to pkt size
	send_all_value(tx_cores, 16, p - 18, 2)		# 14 for MAC (12) EthType (2) 
	send_all_value(tx_cores, 38, p - 38, 2)		# 34 for MAC (12) EthType (2) IP (20)

def set_pkt_sizes_cpe(tx_cores, p):
	send_all_pkt_size(tx_cores, p-4)
	# For all cores, need to adapt IP Length (byte 16) and UDP Length (byte 38) to pkt size
	send_all_value(tx_cores, 24, p - 26, 2)		# 22 for QinQ (8) MAC (12) EthType (2) 
	send_all_value(tx_cores, 46, p - 46, 2)		# 42 for QinQ (8) MAC (12) EthType (2) IP (20)

def set_pkt_sizes_inet(tx_cores, p):
	send_all_pkt_size(tx_cores, p+24-4)
	# For all cores, need to adapt IP Length (byte 16) and UDP Length (byte 38) to pkt size
	send_all_value(tx_cores, 20, p + 2, 2)		# 14 for MAC (12) EthType (2) 
	send_all_value(tx_cores, 48, p - 26, 2)		# 14 for MAC (12) EthType (2) 
	send_all_value(tx_cores, 70, p - 46, 2)		# 34 for MAC (12) EthType (2) IP (20)

def run_measure_throughput(speed, speed_cpe):
	done = 0
	# Intialize tests by stopping cores and resetting stats
	step=0
	steps_done = 0
	sock.sendall("start " + to_str(all_rx_cores) + "\n")
	sleep(2)
	sock.sendall("stop " + to_str(all_rx_cores) + "\n")
	sock.sendall("reset stats\n")
	print "Speed    = " + str(speed * nb_cores_per_interface) 
	sleep(1);
	
	send_all_speed(tx_cores, step);

	# Now starting the steps. First go to the common speed, then increase steps for the faster one.
	sock.sendall("start " + to_str(tx_cores) + "," + to_str(rx_lat_cores) + "\n")
	while (steps_done == 0):
		sleep(step_time)
		if (step + step_delta <= speed):
			step+=step_delta
		else:
			steps_done = 1;
		send_all_speed(tx_cores, step)
	
	# Steps are now OK.  Set speed
	send_all_speed(tx_cores_inet, speed);
	send_all_speed(tx_cores_cpe, speed_cpe);
	sleep(2);

	# Getting statistics to calculate PPS at right speed....
	rx_pps_beg,tx_pps_beg,drop_pps_beg,tsc_pps_beg,tsc_hz = rx_stats(tx_cores, tx_task, all_rx_cores, rx_task);
	sleep(test_duration);

	# Collect statistics before test stops...and stop the test. Important to get stats before stopping as stops take some time...
	rx_pps_end,tx_pps_end,drop_pps_end,tsc_pps_end,tsc_hz = rx_stats(tx_cores, tx_task, all_rx_cores, rx_task);
	lat_min,lat_max,lat_avg = lat_stats(rx_lat_cores, rx_task)
	sock.sendall("stop " + to_str(tx_cores) + "\n")
	sock.sendall("start " + to_str(all_rx_cores) + "\n")
	sleep(3);
	sock.sendall("stop " + to_str(all_rx_cores) + "\n")
	
	rx_end, tx_end,drop_end,tsc_end,tsc_hz = rx_stats(tx_cores, tx_task, all_rx_cores, rx_task);
	rx = rx_pps_end - rx_pps_beg
	tsc = tsc_pps_end - tsc_pps_beg
	mpps = rx / (tsc/float(tsc_hz)) / 1000000
	tx = tx_pps_end - tx_pps_beg
	tx_mpps = tx / (tsc/float(tsc_hz)) / 1000000
	
	#print "Runtime = " +  str((tsc)/float(tsc_hz));
	if (tx_end == 0):
		dropped_tot = tx_end - rx_end
		dropped_pct = 0
	else:
		dropped_tot = tx_end - rx_end
		dropped_pct = ((dropped_tot) * 1.0) / tx_end

	if (dropped_tot > 0):
		if (dropped_pct >= max_dropped):
			print "** FAILED **: lost " + str(100*dropped_pct) + "% packets RX = " + str(rx_end) + " TX = " + str(tx_end) + " DROPPED = " + str(tx_end - rx_end)
		else:
			print "OK but lost " + str(100*dropped_pct) + "% packets RX = " + str(rx_end) + " TX = " + str(tx_end) + " DROPPED = " + str(tx_end - rx_end)
	else:
		if (dropped_tot < 0):
			print "Something wrong happened - received more packets than transmitted"
		else:
			print "**   OK   **: RX = " + str(rx_end) + " TX = " + str(tx_end) + " DROPPED = " + str(tx_end - rx_end) 
	print "MPPS = " + str(mpps)
	print "===================================================="
	return dropped_pct, mpps, tx_mpps, dropped_tot,lat_min,lat_max,lat_avg

def write_results(f, pkt_size, tx_mpps, mpps, dropped_pct, dropped_tot, speed, nb_cores_per_interface, number_flows, lat_min, lat_max, lat_avg):
	f.write(str(pkt_size) + "; " + str(tx_mpps) + "; " + str(mpps) + "; " + str(100 * dropped_pct) + "; " + str(dropped_tot) + "; " + str(speed * nb_cores_per_interface) + "; " + str(number_flows) +  "; " )
	for e in rx_lat_cores:
		f.write(str(lat_min[e]) + "; " + str(lat_max[e]) + "; " + str(lat_avg[e]) + "; ")
	f.write("\n");
	f.flush()

def run_dicho_search(number_flows, pkt_size):
	previous_success_speed = 0.0
	previous_error_speed = max_speed
	speed = init_speed * 1.0
	done = 0;
	good_tx_mpps = 0
	good_mpps = 0
	good_dropped_pct = 0
	good_dropped_tot = 0
	good_speed = 0
	good_lat_min = [0 for e in range(127)]
	good_lat_max = [0 for e in range(127)]
	good_lat_avg = [0 for e in range(127)]

	while done == 0:
		speed_cpe = (speed * (pkt_size + 20)) / (pkt_size + 24 + 20)
		dropped_pct, mpps, tx_mpps, dropped_tot,lat_min,lat_max,lat_avg = run_measure_throughput(speed, speed_cpe)
		if ((dropped_tot >= 0) and (dropped_pct <= max_dropped)):
			good_tx_mpps = tx_mpps
			good_mpps = mpps
			good_dropped_pct = dropped_pct
			good_dropped_tot = dropped_tot
			good_speed = speed
			good_lat_min = lat_min
			good_lat_max = lat_max
			good_lat_avg = lat_avg
			write_results(f, pkt_size, tx_mpps, mpps, dropped_pct, dropped_tot, speed, nb_cores_per_interface, number_flows, lat_min, lat_max, lat_avg);
			write_results(f_all, pkt_size, tx_mpps, mpps, dropped_pct, dropped_tot, speed, nb_cores_per_interface, number_flows, lat_min, lat_max, lat_avg);
		else:
			write_results(f_all, pkt_size, tx_mpps, mpps, dropped_pct, dropped_tot, speed, nb_cores_per_interface, number_flows, lat_min, lat_max, lat_avg);

		if ((speed == max_speed) and (dropped_pct <= max_dropped)):
			write_results(f_minimal, pkt_size, tx_mpps, mpps, dropped_pct, dropped_tot, speed, nb_cores_per_interface, number_flows, lat_min, lat_max, lat_avg);
			done = 1
		if (dropped_pct <= max_dropped):
			previous_success_speed = speed
			if (speed > max_speed - accuracy):
				speed = max_speed
			else:
				if (previous_error_speed - speed < accuracy):
					write_results(f_minimal, pkt_size, good_tx_mpps, good_mpps, good_dropped_pct, good_dropped_tot, good_speed, nb_cores_per_interface, number_flows, good_lat_min, good_lat_max, good_lat_avg);
					done = 1
				else:
					speed = speed + (previous_error_speed - speed)/2;
		else:
			previous_error_speed = speed
			if (speed - previous_success_speed < accuracy):
				write_results(f_minimal, pkt_size, good_tx_mpps, good_mpps, good_dropped_pct, good_dropped_tot, good_speed, nb_cores_per_interface, number_flows, good_lat_min, good_lat_max, good_lat_avg);
				done = 1	
			else:
				speed  = speed - (speed - previous_success_speed) / 2;

	
def set_source_destination_ip(nb_sources, nb_destinations):
	# Destination addressese: "00XXXXXX" "XXXXXXXX" "XXXXXXXX" "XXXXXX10"
	# Starting with 00 to be in class A and skipping 0.x.y.z and 127.x.y.z
	# Ending with 10 to avoid x.y.z.0 and x.y.z.255

	dst_mask = "10"
	for i in range (nb_destinations):
		dst_mask = "X" + str(dst_mask)
	for i in range (32 - nb_destinations - 2):
		dst_mask = "0" + str(dst_mask)
	
	src_mask = "10"
	for i in range (nb_sources):
		src_mask = "X" + str(src_mask)
	for i in range (32 - nb_sources - 2):
		src_mask = "0" + str(src_mask)
	
	for c in tx_port0:
		send_all_random([c], 26, src_mask, 4)
		send_all_random([c], 30, dst_mask, 4)
	for c in tx_port1:
		send_all_random([c], 26, src_mask, 4)
		send_all_random([c], 30, dst_mask, 4)
	for c in tx_port2:
		send_all_random([c], 26, src_mask, 4)
		send_all_random([c], 30, dst_mask, 4)
	for c in tx_port3:
		send_all_random([c], 26, src_mask, 4)
		send_all_random([c], 30, dst_mask, 4)
	for c in tx_port4:
		send_all_random([c], 26, src_mask, 4)
		send_all_random([c], 30, dst_mask, 4)
	for c in tx_port5:
		send_all_random([c], 26, src_mask, 4)
		send_all_random([c], 30, dst_mask, 4)
	for c in tx_port6:
		send_all_random([c], 26, src_mask, 4)
		send_all_random([c], 30, dst_mask, 4)
	for c in tx_port7:
		send_all_random([c], 26, src_mask, 4)
		send_all_random([c], 30, dst_mask, 4)
		
#========================================================================
class TestDefinition():
    "Stores test parameters"
    def __init__(self, number_ip_src, number_ip_dst, pkt_size):
        self.number_ip_src = number_ip_src
        self.number_ip_dst = number_ip_dst
        self.pkt_size = pkt_size

#========================================================================
def run_use_case(number_ip_src, number_ip_dst, pkt_size):
	number_flows = (2 ** number_ip_src) * (2 ** number_ip_dst)
#	send_reset_random()
#	send_reset_value()
#	set_source_destination_ip(number_ip_src, number_ip_dst)
	set_pkt_sizes_inet(tx_cores_inet, pkt_size)
	set_pkt_sizes_cpe(tx_cores_cpe, pkt_size)
	print "Running test with pkt size= " + str(pkt_size) + " number_ip_src = " + str(number_ip_src) + " number_ip_dst = " + str(number_ip_dst) + " Number flows = " + str(number_flows) + "; \n"
	run_dicho_search(number_flows, pkt_size)
	sleep(3)

#========================================================================
def run_all_use_cases():
	use_case_nb = 1
	# Connect to dppd 
	file_path = '/tmp/prox.sock'
	sock.connect(file_path)

	f.write("pkt_size; tx_mpps; rx_mpps; dropped_pct; dropped_tot; percent_line_rate; latency per core\n")
	f_all.write("pkt_size; tx_mpps; rx_mpps; dropped_pct; dropped_tot; percent_line_rate; latency per core\n")
	f_minimal.write("pkt_size; tx_mpps; rx_mpps; dropped_pct; dropped_tot; percent_line_rate; latency per core\n")
	f.flush();
	f_all.flush();
	f_minimal.flush();

	# Starting tests
	print "Stopping all cores and resetting all values and randoms before starting\n"
	sock.sendall("stop " + to_str(all_rx_cores) + "\n")
	sock.sendall("stop " + to_str(tx_cores) + "\n")
	#sock.sendall("stop all")
	sock.sendall("reset stats\n")
	sleep(3);
	for line in file_tests:
		info = line.split(';')
		if (info[0][0] == '#'):
			continue
		if (info[0][0] == ''):
			break
		number_ip_src = int(info[0])
		number_ip_dst = int(info[1])
		pkt_size = int(info[2])
		run_use_case(number_ip_src, number_ip_dst, pkt_size)

#========================================================================
def configure_use_case():
	Tests = []
	number_ip_dst = 0
	number_ip_src = 0
	for pkt_size in all_pkt_size:
		Tests.append(TestDefinition(number_ip_src, number_ip_dst, pkt_size))

	pkt_size = 64
	while (pkt_size < 1494):
		Tests.append(TestDefinition(number_ip_src, number_ip_dst, pkt_size))
		pkt_size = (pkt_size *11) / 10

	file_tests = open('test_description.txt', 'w')
	file_tests.write("# Number_ip_src; number_ip_dst; pkt_size; \n")
	for test in Tests:
		file_tests.write(str(test.number_ip_src) + "; " + str(test.number_ip_dst) + "; " + str(test.pkt_size) + "; " + ";\n")
	file_tests.close()

#========================================================================
if ((configure == 0) and (run == 0)):
	print "Nothing to do - please use -r 1 or -c 1"
if (configure == 1):
	configure_use_case()
if (run == 1):
	print "****************************************************************************************************************"
	print "** Running Characterization with " + str(test_duration) + " seconds steps and starting at " + str(init_speed)   + " percent of line rate **"
	print "****************************************************************************************************************"
	sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	f_all = open('all_results.txt', 'w')
	f = open('detailed_results.txt', 'w')
	f_minimal = open('minimal_results.txt', 'w')
	file_tests = open('test_description.txt', 'r')
	run_all_use_cases()
	f.close();
	sock.close();

