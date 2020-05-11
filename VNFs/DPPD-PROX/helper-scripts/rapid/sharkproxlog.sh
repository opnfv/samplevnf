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
## This code will help in using tshark to decode packets that were dumped
## in the prox.log file as a result of dump, dump_tx or dump_rx commands

#egrep  '^[0-9]{4}|^[0-9]+\.' prox.log | text2pcap -q - - | tshark -r -
while read -r line ; do
    if [[ $line =~ (^[0-9]{4}\s.*) ]] ;
    then
        echo "$line" >> tempshark.log
    fi
    if [[ $line =~ (^[0-9]+\.[0-9]+)(.*) ]] ;
    then
        date -d@"${BASH_REMATCH[1]}" -u +%H:%M:%S.%N >> tempshark.log
    fi
done < <(cat prox.log)
text2pcap -t "%H:%M:%S." -q tempshark.log - | tshark -r -
rm tempshark.log
