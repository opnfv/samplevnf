#!/usr/bin/env bash
##
## Copyright (c) 2010-2018 Intel Corporation
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
NCPUS="$(lscpu | egrep '^CPU\(s\):' | awk '{ print $2 }')"
MAXCOREID="$((NCPUS-1))"

filename="/etc/tuned/realtime-virtual-guest-variables.conf"
logfile="/home/centos/prox_system_setup.log"
if [ -f "$filename" ]
then
        while read -r line
        do
                case $line in
                        isolated_cores=1-$MAXCOREID*)
                                echo "Isolated CPU(s) OK, no reboot: $line">>$logfile
				modprobe uio
				insmod /root/dpdk/build/kmod/igb_uio.ko
                                exit 0
                        ;;
                        isolated_cores=*)
                                echo "Isolated CPU(s) NOK, change the config and reboot: $line">>$logfile
                                sed -i "/^isolated_cores=.*/c\isolated_cores=1-$MAXCOREID" $filename
				tuned-adm profile realtime-virtual-guest
                                reboot
				exit 0
                        ;;
                        *)
                                echo "$line"
                        ;;
                esac
        done < "$filename"
        echo "isolated_cores=1-$MAXCOREID" >> $filename
	echo "No Isolated CPU(s) defined in config, line added: $line">>$logfile
	tuned-adm profile realtime-virtual-guest
        reboot
else
        echo "$filename not found.">>$logfile
fi
