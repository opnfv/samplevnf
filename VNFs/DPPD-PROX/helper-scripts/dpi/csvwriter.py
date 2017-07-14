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

class CsvWriter:
    def __init__(self):
        self._file_name = None;

    def open(self, file_name):
        self._file = open(file_name, 'w');
        self._file_name = file_name;

    def write(self, elements):
        elements_str = map(lambda x: str(x), elements);
        line = ",".join(elements_str);
        self._file.write(line + "\n");
        self._file.flush();

    def close(self):
        self._file.close();
        self._file = None;
