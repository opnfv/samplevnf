#!/usr/bin/env bash
##
## Copyright (c) 2010-2021 Intel Corporation
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
## This script should run after booting: see check-prox-system-setup.service

NCPUS="$(lscpu | egrep '^CPU\(s\):' | awk '{ print $2 }')"
MAXCOREID="$((NCPUS-1))"

tuned_config="/etc/tuned/realtime-virtual-guest-variables.conf"
log_file="/opt/rapid/prox_system_setup.log"
system_ready="/opt/rapid/system_ready_for_rapid"
tuned_done="/opt/rapid/tuned_done"
after_boot_file="/opt/rapid/after_boot.sh"

tuned_and_reboot () {
  echo "Applying tuned profile">>$log_file
  tuned-adm profile realtime-virtual-guest
  touch "$tuned_done"
  echo "Rebooting...">>$log_file
  reboot
  exit 0
}

if [ -f "$tuned_config" ]
then
    while read -r line
    do
        case $line in
            isolated_cores=1-$MAXCOREID*)
                if test ! -f "$tuned_done"; then
                  tuned_and_reboot
                fi
                if test -f "$after_boot_file"; then
                  echo "Executing: $after_boot_file">>$log_file
                  ("$after_boot_file")
                fi
                echo "Isolated CPU(s) OK, no reboot: $line">>$log_file
                ## rapid scripts will wait for the system_ready file to exist
                ## Only then, they will be able to connect to the PROX instance
                ## and start the testing
                touch "$system_ready"
                exit 0
            ;;
            isolated_cores=*)
                echo "Isolated CPU(s) NOK: $line">>$log_file
                sed -i "/^isolated_cores=.*/c\isolated_cores=1-$MAXCOREID" $tuned_config
                tuned_and_reboot
            ;;
            *)
                echo "$line"
            ;;
        esac
    done < "$tuned_config"
    echo "isolated_cores=1-$MAXCOREID" >> $tuned_config
    echo "No Isolated CPU(s) defined in config, line added: isolated_cores=1-$MAXCOREID">>$log_file
    tuned_and_reboot
else
    echo "$tuned_config not found.">>$log_file
fi
