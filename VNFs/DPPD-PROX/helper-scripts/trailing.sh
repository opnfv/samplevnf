#!/bin/bash

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

bad_lines=$(grep -nHr -e "[[:space:]]$" *.c *.h gen/*.cfg config/*.cfg)

if [ -n "$bad_lines" ]; then
    echo "Found trailing white-spaces:"
    echo $bad_lines
    exit 1;
fi

for f in *.c *.h gen/*.cfg config/*.cfg; do
    result=$(tail -n 1 $f | grep "^$" | wc -l)

    if [ "$result" == "1" ]; then
        echo "Trailing newlines at end of file $f"
        exit 1
    fi
done;

prev="dummy"
function findDuplicate() {
    line=1
    while read p; do
	if [ "$prev" == "" ]; then
	    if [ "$p" == "" ]; then
		echo "duplicate empty line at $1:$line"
		bad=1
	    fi
	fi
	prev=$p
	let "line+=1"
    done <$1
}

bad=0
for f in *.c *.h; do
    findDuplicate $f
done;

if [ "$bad" != "0" ]; then
    exit 1
fi

tab="	"
bad_lines=$(grep -nHr -e "^$tab$tab$tab$tab$tab$tab$tab" *.c *.h | head -n1)

if [ -n "$bad_lines" ]; then
    echo "Code nested too deep:"
    echo $bad_lines
    exit 1;
fi

exit 0
