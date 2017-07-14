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

SOURCES = main.cpp
SOURCES += streamextract.cpp
SOURCES += pcapreader.cpp
SOURCES += pcapwriter.cpp
SOURCES += timestamp.cpp
SOURCES += pcappkt.cpp
SOURCES += netsocket.cpp
SOURCES += stream3.cpp
SOURCES += stream2.cpp
SOURCES += stream.cpp
SOURCES += path.cpp
SOURCES += allocator.cpp
SOURCES += halfstream.cpp
SOURCES += bundle.cpp
SOURCES += progress.cpp
SOURCES += mappedfile.cpp
SOURCES += streamsorter.cpp
SOURCES += memreader.cpp
SOURCES += programconfig.cpp

BUILD_DIR = build
OBJECTS = $(SOURCES:%.cpp=$(BUILD_DIR)/%.o)
PROG = flowextract

CXXFLAGS += -D__STDC_LIMIT_MACROS -g -O2 -Wall -ansi -pedantic -Wno-unused -msse4.2
LDFLAGS = -lpcap

$(BUILD_DIR)/$(PROG): $(OBJECTS)
	@echo -e "LD\t$<"
	@$(CXX) $(CXXFLAGS) $(LDFLAGS) $(OBJECTS) -o $@

-include $(SOURCES:%.cpp=$(BUILD_DIR)/%.d)

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(BUILD_DIR)
	@echo -e "CXX\t $<"
	@$(CXX) -c $(CXXFLAGS) $*.cpp -o $@
	@$(CXX) -MM $(CXXFLAGS) $*.cpp -MT $(BUILD_DIR)/$*.o > $(BUILD_DIR)/$*.d
	@cp -f $(BUILD_DIR)/$*.d $(BUILD_DIR)/$*.d.tmp
	@sed -e 's/.*://' -e 's/\\$$//' < $(BUILD_DIR)/$*.d.tmp | fmt -1 | sed -e 's/^ *//' -e 's/$$/:/' >> $(BUILD_DIR)/$*.d
	@rm -f $(BUILD_DIR)/$*.d.tmp
clean:
	@rm -f $(BUILD_DIR)/$(PROG) $(BUILD_DIR)/*.o $(BUILD_DIR)/*.d
