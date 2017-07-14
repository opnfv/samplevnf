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
max_dropped = 0.001		# in percent
all_pkt_size = [64,128,256,512,1024,1280,1518]
#all_pkt_size = [64]

# vRouter parameters, in case commands must be sent
vRouter_host = "192.168.1.96" 

# Stear parameters
step_time = 0.01		# in seconds
step_delta = 0.025		# in percent of line rate

# Use case dependent parameters
##### Use case 0: influence of number of routes and next hops #####
max_number_next_hops = 256			# Maximum number of next-hops per interface
max_number_routes = 8192			# Maximum number of routes per interface
max_number_addresses_local_network = 262144

##### Use case 1: packet loss and latency #####
low_steps_delta_for_loss = 0.01                 # Use increment of 0.01% from 0 to low_steps
medium_steps_delta_for_loss = 0.1               # Use increment of 0.1% from low_steps to medium_steps
normal_steps_delta_for_loss = 1.0               # Use increment of 1% from medium_steps till 100%
low_steps = 0.1 
medium_steps = 1.0 

# Prox parameters
tx_port4 = [19,27,55,63]
tx_port5 = [20,28,56,64]
tx_port6 = [21,29,57,65]
tx_port7 = [22,30,58,66]
tx_port2 = [23,31,59,67]
tx_port3 = [24,32,60,68]
tx_port0 = [25,33,61,69]
tx_port1 = [26,34,62,70]
tx_task = 0

all_rx_cores = [1,2,3,4,5,6,7,10]
rx_lat_cores = [1,2,3,4,5,6,7,10]
rx_task = 1

# Some variables, do not change

# Program arguments
parser = OptionParser()
parser.add_option("-d", "--duration", dest="test_duration", help="Duration of each steps", metavar="integer", default=10)
parser.add_option("-s", "--speed", dest="init_speed", help="Initial speed", metavar="integer", default=100)
parser.add_option("-u", "--use-case", dest="use_case", help="Use Case Number", metavar="integer", default=0)
parser.add_option("-r", "--run", dest="run", help="Run test", metavar="integer", default=0)
parser.add_option("-c", "--configure", dest="configure", help="Configure Test", metavar="integer", default=0)
(options, args) = parser.parse_args()

init_speed = int(options.init_speed)
test_duration = int(options.test_duration)
use_case = int(options.use_case)
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

tx_cores = tx_port0 + tx_port1 + tx_port2 + tx_port3 + tx_port4 + tx_port5 + tx_port6 + tx_port7

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

def wait_vRouter_restarted(host):
	while (1):
		ret = os.system("ping " + host + " -c 1 > /dev/null")
		if ret == 0:
			print "still up..."
		else:
			break;
		sleep(1)
	
	while (1):
		ret = os.system("ping " + host + " -c 1 > /dev/null")
		if (ret == 0):
			print "UP"
			break;
		else:
			print "still down..."
			sleep(1)

def reload_vRouter_config(config):
	print "connecting to vRouter...and copying " + str(config)
	sut = remote_system("root", vRouter_host)
	cmd = "cp /config/prox/" + str(config) + " /config/config.boot"
	sut.run(cmd)
	print "Rebooting system at " + str(datetime.now().time())
	sut.run_forked("reboot")
	sleep(5)
	wait_vRouter_restarted(vRouter_host)
	print "Waiting for last startup scripts to start..."
	last_script = "l2tp"
	while(1):
		dmesg = str(sut.run("dmesg"))
		if last_script in dmesg:
			print "found l2tp - UP"
			break;
		sleep(1)
	print "vRouter started - waiting 5 last seconds before starting test"
	sleep(5)
	print datetime.now().time()

def set_pkt_sizes(tx_cores, p):
	send_all_pkt_size(tx_cores, p-4)
	# For all cores, need to adapt IP Length (byte 16) and UDP Length (byte 38) to pkt size
	send_all_value(tx_cores, 16, p - 18, 2)		# 14 for MAC (12) EthType (2) 
	send_all_value(tx_cores, 38, p - 38, 2)		# 34 for MAC (12) EthType (2) IP (20)

def run_measure_throughput(speed):
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
	send_all_speed(tx_cores, speed);
	sleep(2);

	# Getting statistics to calculate PPS at right speed....
	rx_pps_beg,tx_pps_beg,drop_pps_beg,tsc_pps_beg,tsc_hz = rx_stats(tx_cores, tx_task, all_rx_cores, rx_task);
	sleep(test_duration);

	# Collect statistics before test stops...and stop the test. Important to get stats before stopping as stops take some time...
	rx_pps_end,tx_pps_end,drop_pps_end,tsc_pps_end,tsc_hz = rx_stats(tx_cores, tx_task, all_rx_cores, rx_task);
	lat_min,lat_max,lat_avg = lat_stats(rx_lat_cores, rx_task)
	sock.sendall("stop " + "," + to_str(tx_cores) + "\n")
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

def write_results(f, pkt_size, tx_mpps, mpps, dropped_pct, dropped_tot, speed, nb_cores_per_interface, number_next_hops, number_routes, traffic, lat_min, lat_max, lat_avg):
	f.write(str(pkt_size) + "; " + str(tx_mpps) + "; " + str(mpps) + "; " + str(100 * dropped_pct) + "; " + str(dropped_tot) + "; " + str(speed * nb_cores_per_interface) + "; " + str(number_next_hops) + "; " + str(number_routes) + "; " + str(traffic) + "; ")
	for e in rx_lat_cores:
		f.write(str(lat_min[e]) + "; " + str(lat_max[e]) + "; " + str(lat_avg[e]) + "; ")
	f.write("\n");
	f.flush()

def run_loss_graph(number_next_hops, number_routes, pkt_size, traffic):
	speed = init_speed * 1.0
	done = 0;
	while done == 0:
		dropped_pct, mpps, tx_mpps, dropped_tot,lat_min,lat_max,lat_avg = run_measure_throughput(speed)
		write_results(f, pkt_size, tx_mpps, mpps, dropped_pct, dropped_tot, speed, nb_cores_per_interface, number_next_hops, number_routes, traffic, lat_min, lat_max, lat_avg);
		if (speed <= low_steps_delta_for_loss):
			done = 1
			return
		if (speed >= (medium_steps+normal_steps_delta_for_loss)):
			speed -= normal_steps_delta_for_loss
		else:
			if (speed >= (low_steps+medium_steps_delta_for_loss)):
				speed -= medium_steps_delta_for_loss
			else:
				speed -= low_steps_delta_for_loss

def run_dicho_search(number_next_hops, number_routes, pkt_size, traffic):
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
		dropped_pct, mpps, tx_mpps, dropped_tot,lat_min,lat_max,lat_avg = run_measure_throughput(speed)
		if ((dropped_tot >= 0) and (dropped_pct <= max_dropped)):
			good_tx_mpps = tx_mpps
			good_mpps = mpps
			good_dropped_pct = dropped_pct
			good_dropped_tot = dropped_tot
			good_speed = speed
			good_lat_min = lat_min
			good_lat_max = lat_max
			good_lat_avg = lat_avg
			write_results(f, pkt_size, tx_mpps, mpps, dropped_pct, dropped_tot, speed, nb_cores_per_interface, number_next_hops, number_routes, traffic, lat_min, lat_max, lat_avg);
			write_results(f_all, pkt_size, tx_mpps, mpps, dropped_pct, dropped_tot, speed, nb_cores_per_interface, number_next_hops, number_routes, traffic, lat_min, lat_max, lat_avg);
		else:
			write_results(f_all, pkt_size, tx_mpps, mpps, dropped_pct, dropped_tot, speed, nb_cores_per_interface, number_next_hops, number_routes, traffic, lat_min, lat_max, lat_avg);

		if ((speed == max_speed) and (dropped_pct <= max_dropped)):
			write_results(f_minimal, pkt_size, tx_mpps, mpps, dropped_pct, dropped_tot, speed, nb_cores_per_interface, number_next_hops, number_routes, traffic, lat_min, lat_max, lat_avg);
			done = 1
		if (dropped_pct <= max_dropped):
			previous_success_speed = speed
			if (speed > max_speed - accuracy):
				speed = max_speed
			else:
				if (previous_error_speed - speed < accuracy):
					write_results(f_minimal, pkt_size, good_tx_mpps, good_mpps, good_dropped_pct, good_dropped_tot, good_speed, nb_cores_per_interface, number_next_hops, number_routes, traffic, good_lat_min, good_lat_max, good_lat_avg);
					done = 1
				else:
					speed = speed + (previous_error_speed - speed)/2;
		else:
			previous_error_speed = speed
			if (speed - previous_success_speed < accuracy):
				write_results(f_minimal, pkt_size, good_tx_mpps, good_mpps, good_dropped_pct, good_dropped_tot, good_speed, nb_cores_per_interface, number_next_hops, number_routes, traffic, good_lat_min, good_lat_max, good_lat_avg);
				done = 1	
			else:
				speed  = speed - (speed - previous_success_speed) / 2;

	
def set_destination_ip(use_case, nb_destinations, traffic):
	# minimmum 8 routes i.e. 1 per interface 
	# Destination addressese: "00XXXYY1" "Z00ZZ0ZZ" "AA0AA0AA" "BBBBBB10"
	# Where X = interface id. Starting with 00 to be in class A and skipping 0.x.y.z and 127.x.y.z
	# Y, Z and A = additional routes
	# B = IP in routes. 10 to avoid x.y.z.0 and x.y.z.255
	# Gaps in A and B to void "too good" distributions e.g. using LPM and 
	# First changing Y

	mask = ""
	for i in range (2):
       		mask = str(mask)+"0"
	end_mask = ""
	if (use_case != 2):
		end_mask = "XXXXXX10"		# Last 8 bits

		if (nb_destinations == 1):
			end_mask = "0010000000000000000" + str(end_mask)
		if (nb_destinations == 2):
			end_mask = "X010000000000000000" + str(end_mask)
		if (nb_destinations == 4):
			end_mask = "XX10000000000000000" + str(end_mask)
		if (nb_destinations == 8):
			end_mask = "XX1X000000000000000" + str(end_mask)
		elif (nb_destinations == 16):
			end_mask = "XX1X00X000000000000" + str(end_mask)
		elif (nb_destinations == 32):
			end_mask = "XX1X00XX00000000000" + str(end_mask)
		elif (nb_destinations == 64):
			end_mask = "XX1X00XX0X000000000" + str(end_mask)
		elif (nb_destinations == 128):
			end_mask = "XX1X00XX0XX00000000" + str(end_mask)
		elif (nb_destinations == 256):
			end_mask = "XX1X00XX0XXX0000000" + str(end_mask)
		elif (nb_destinations == 512):
			end_mask = "XX1X00XX0XXXX000000" + str(end_mask)
		elif (nb_destinations == 1024):
			end_mask = "XX1X00XX0XXXX0X0000" + str(end_mask)
		elif (nb_destinations == 2048):
			end_mask = "XX1X00XX0XXXX0XX000" + str(end_mask)
		elif (nb_destinations == 4096):
			end_mask = "XX1X00XX0XXXX0XX0X0" + str(end_mask)
		elif (nb_destinations == 8192):
			end_mask = "XX1X00XX0XXXX0XX0XX" + str(end_mask)
	else:
		if (nb_destinations <= 64 * 1):
			end_mask = "0010000000000000000"
			n_dest = int(log(nb_destinations, 2))
			for i in range (n_dest):
				end_mask = str(end_mask) + "X"
			for i in range (6 - n_dest):
				end_mask = str(end_mask) + "0"
			end_mask = str(end_mask) + "10"
		else:
			end_mask = "XXXXXX10"		# Last 8 bits

		if (nb_destinations == 64 * 2):
			end_mask = "001X000000000000000" + str(end_mask)
		elif (nb_destinations == 64 * 4):
			end_mask = "001X00X000000000000" + str(end_mask)
		elif (nb_destinations == 64 * 8):
			end_mask = "001X00XX00000000000" + str(end_mask)
		elif (nb_destinations == 64 * 16):
			end_mask = "001X00XX0X000000000" + str(end_mask)
		elif (nb_destinations == 64 * 32):
			end_mask = "001X00XX0XX00000000" + str(end_mask)
		elif (nb_destinations == 64 * 64):
			end_mask = "001X00XX0XXX0000000" + str(end_mask)
		elif (nb_destinations == 64 * 128):
			end_mask = "001X00XX0XXXX000000" + str(end_mask)
		elif (nb_destinations == 64 * 256):
			end_mask = "001X00XX0XXXX0X0000" + str(end_mask)
		elif (nb_destinations == 64 * 512):
			end_mask = "001X00XX0XXXX0XX000" + str(end_mask)
		elif (nb_destinations == 64 * 1024):
			end_mask = "001X00XX0XXXX0XX0X0" + str(end_mask)
		elif (nb_destinations == 64 * 2048):
			end_mask = "001X00XX0XXXX0XX0XX" + str(end_mask)
		elif (nb_destinations == 64 * 4096):
			end_mask = "001XX0XX0XXXX0XX0XX" + str(end_mask)
		elif (nb_destinations == 64 * 8192):
			end_mask = "001XXXXX0XXXX0XX0XX" + str(end_mask)
		elif (nb_destinations == 64 * 16384):
			end_mask = "001XXXXXXXXXX0XX0XX" + str(end_mask)
		elif (nb_destinations == 64 * 32768):
			end_mask = "001XXXXXXXXXXXXX0XX" + str(end_mask)
		elif (nb_destinations == 64 * 65536):
			end_mask = "001XXXXXXXXXXXXXXXX" + str(end_mask)
	
	if (traffic == 0):	# One-to-one. From odd interface to even interface and vice versa, no QPI cross
		mask1 = str(mask) + "001" + str(end_mask)
		mask2 = str(mask) + "000" + str(end_mask)
		mask3 = str(mask) + "011" + str(end_mask)
		mask4 = str(mask) + "010" + str(end_mask)
		mask5 = str(mask) + "101" + str(end_mask)
		mask6 = str(mask) + "100" + str(end_mask)
		mask7 = str(mask) + "111" + str(end_mask)
		mask8 = str(mask) + "110" + str(end_mask)

	elif (traffic == 1):	# Full mesh within QPI (i.e. 1 to 4)
		mask1 = str(mask) + "0XX" + str(end_mask)
		mask2 = str(mask) + "0XX" + str(end_mask)
		mask3 = str(mask) + "0XX" + str(end_mask)
		mask4 = str(mask) + "0XX" + str(end_mask)
		mask5 = str(mask) + "1XX" + str(end_mask)
		mask6 = str(mask) + "1XX" + str(end_mask)
		mask7 = str(mask) + "1XX" + str(end_mask)
		mask8 = str(mask) + "1XX" + str(end_mask)
	
	elif (traffic == 2):	# One to one, crossing QPI (100% QPI)
		mask1 = str(mask) + "100" + str(end_mask)
		mask2 = str(mask) + "101" + str(end_mask)
		mask3 = str(mask) + "110" + str(end_mask)
		mask4 = str(mask) + "111" + str(end_mask)
		mask5 = str(mask) + "000" + str(end_mask)
		mask6 = str(mask) + "001" + str(end_mask)
		mask7 = str(mask) + "010" + str(end_mask)
		mask8 = str(mask) + "011" + str(end_mask)

	elif (traffic == 3):	# 1 to 4 crossing QPI (100% QPI)
		mask1 = str(mask) + "1XX" + str(end_mask)
		mask2 = str(mask) + "1XX" + str(end_mask)
		mask3 = str(mask) + "1XX" + str(end_mask)
		mask4 = str(mask) + "1XX" + str(end_mask)
		mask5 = str(mask) + "0XX" + str(end_mask)
		mask6 = str(mask) + "0XX" + str(end_mask)
		mask7 = str(mask) + "0XX" + str(end_mask)
		mask8 = str(mask) + "0XX" + str(end_mask)

	elif (traffic == 4):	# 1 to 4 (50% QPI)
		mask1 = str(mask) + "XX1" + str(end_mask)
		mask2 = str(mask) + "XX0" + str(end_mask)
		mask3 = str(mask) + "XX1" + str(end_mask)
		mask4 = str(mask) + "XX0" + str(end_mask)
		mask5 = str(mask) + "XX1" + str(end_mask)
		mask6 = str(mask) + "XX0" + str(end_mask)
		mask7 = str(mask) + "XX1" + str(end_mask)
		mask8 = str(mask) + "XX0" + str(end_mask)

	elif (traffic == 5):	# Full mesh (50% QPI)
		mask1 = str(mask) + "XXX" + str(end_mask)
		mask2 = str(mask) + "XXX" + str(end_mask)
		mask3 = str(mask) + "XXX" + str(end_mask)
		mask4 = str(mask) + "XXX" + str(end_mask)
		mask5 = str(mask) + "XXX" + str(end_mask)
		mask6 = str(mask) + "XXX" + str(end_mask)
		mask7 = str(mask) + "XXX" + str(end_mask)
		mask8 = str(mask) + "XXX" + str(end_mask)

	for c in tx_port0:
		send_all_random([c], 30, mask1, 4)
	for c in tx_port1:
		send_all_random([c], 30, mask2, 4)
	for c in tx_port2:
		send_all_random([c], 30, mask3, 4)
	for c in tx_port3:
		send_all_random([c], 30, mask4, 4)
	for c in tx_port4:
		send_all_random([c], 30, mask5, 4)
	for c in tx_port5:
		send_all_random([c], 30, mask6, 4)
	for c in tx_port6:
		send_all_random([c], 30, mask7, 4)
	for c in tx_port7:
		send_all_random([c], 30, mask8, 4)
	for c in tx_cores:
		send_all_random([c], 34, "0XXXXXXXXXXXXX10", 2)
		send_all_random([c], 36, "0XXXXXXXXXXXXX10", 2)
		
#========================================================================
class TestDefinition():
    "Stores test parameters"
    def __init__(self, use_case, next_hops, number_routes, pkt_size, traffic, reload):
        self.use_case = use_case
        self.next_hops = next_hops
        self.number_routes = number_routes
        self.pkt_size = pkt_size
        self.traffic = traffic
        self.reload = reload

#========================================================================
# Use case 0 increases input load and measure output load => show dropped packets at low loads, show overload behavior
# Use case 1 and use case 2 run dichotomic searches, searching for 0 packet loss (or whaever loss is configured)
# Use case 1 shows the effect of number of routes and next-hops
# Use case 2 shows the effect of the number of destination, using a fixed (low) number of routes and next-hops
#========================================================================
def run_use_case(use_case, number_next_hops, number_routes, pkt_size, traffic, reload):
	if (reload):
		if (use_case == 2):
			config = "config.1_1" + "_" + str(use_case) + ".boot"
		else:
			config = "config." + str(number_routes) + "_" + str(number_next_hops) + ".boot"
		reload_vRouter_config(config)
	send_reset_random()
	send_reset_value()
	set_destination_ip(use_case, number_routes, traffic)
	set_pkt_sizes(tx_cores, pkt_size)
	print "Running test with pkt size= " + str(pkt_size) + " Next hops = " + str(number_next_hops) + "; number of routes = " + str(number_routes) + "; Traffic = " + str(traffic) + " \n"
	if (use_case == 0):
		run_loss_graph(number_next_hops, number_routes, pkt_size, traffic)
	else:
		run_dicho_search(number_next_hops, number_routes, pkt_size, traffic)
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
	sock.sendall("stop all")
	sock.sendall("reset stats\n")
	sleep(3);
	for line in file_tests:
		info = line.split(';')
		if (info[0][0] == '#'):
			continue
		if (info[0][0] == ''):
			break
		use_case = int(info[0])
		next_hops = int(info[1])
		number_routes = int(info[2])
		pkt_size = int(info[3])
		traffic = int(info[4])
		reload = int(info[5])
		print str(use_case_nb) + " : Running use case " + str(use_case) + " next_hops = " + str(next_hops) + " routes = " + str(number_routes) + " pkt_size = " + str(pkt_size) + " traffic = " + str(traffic) + " reload = " + str(reload)
		run_use_case(use_case, next_hops, number_routes, pkt_size, traffic, reload)
		use_case_nb = use_case_nb + 1

#========================================================================
def configure_use_case(use_case):
	Tests = []
	if (use_case == 0):
		for pkt_size in all_pkt_size:
			Tests.append(TestDefinition("0", "1", "1", pkt_size, "0", "1"))
		for pkt_size in all_pkt_size:
			Tests.append(TestDefinition("0", "1", "1", pkt_size, "1", "1"))
	if (use_case == 1):
		number_next_hops = 1
		reload = 0

		number_routes = number_next_hops	# At least same number of routes that number of next hops
		while number_routes <= max_number_routes:
			reload = 1
			for traffic in range(6):
				for pkt_size in all_pkt_size:
					Tests.append(TestDefinition(use_case, number_next_hops, number_routes, pkt_size, traffic, reload))
					reload = 0
			if (number_routes < max_number_routes / 2):
				number_routes = number_routes * 4
			else:
				number_routes = number_routes * 2

		number_routes = max_number_next_hops
		while number_next_hops <= max_number_next_hops:
			reload = 1
			for traffic in range(6):
				for pkt_size in all_pkt_size:
					Tests.append(TestDefinition(use_case, number_next_hops, number_routes, pkt_size, traffic, reload))
					reload = 0
			number_next_hops = number_next_hops * 2
	if (use_case == 2):
		number_next_hops = 1
		reload = 1
		for traffic in range(6):
			nb_destinations = 1
			while nb_destinations <= max_number_addresses_local_network:
				for pkt_size in all_pkt_size:
					Tests.append(TestDefinition(use_case, number_next_hops, nb_destinations, pkt_size, traffic, reload))
					reload = 0
				nb_destinations = nb_destinations * 2
			reload = 1

	file_tests = open('test_description.txt', 'w')
	file_tests.write("# Use case; next_hops; routes; pkt_size; traffic; reload;\n")
	for test in Tests:
		file_tests.write(str(test.use_case) + "; " + str(test.next_hops) + "; " +  str(test.number_routes) + "; " + str(test.pkt_size) + "; " + str(test.traffic) + "; " + str(test.reload) + ";\n")
	file_tests.close()

#========================================================================
if ((configure == 0) and (run == 0)):
	print "Nothing to do - please use -r 1 or -c 1"
if (configure == 1):
	configure_use_case(use_case)
if (run == 1):
	print "****************************************************************************************************************"
	print "** Running vRouter Characterization with " + str(test_duration) + " seconds steps and starting at " + str(init_speed)   + " percent of line rate **"
	print "****************************************************************************************************************"
	sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	f_all = open('all_results.txt', 'w')
	f = open('detailed_results.txt', 'w')
	f_minimal = open('minimal_results.txt', 'w')
	file_tests = open('test_description.txt', 'r')
	run_all_use_cases()
	f.close();
	sock.close();
