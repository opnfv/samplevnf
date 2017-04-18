# Copyright (c) 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = Protocol

# all source are stored in SRCS-y
SRCS-y := main.c l2_proto.c interface.c lib_arp.c lib_icmpv6.c l3fwd_main.c l3fwd_lpm4.c l3fwd_lpm6.c bond.c tsx.c hle.c

CFLAGS += -I$(SRCDIR)
CFLAGS += -O3 $(USER_FLAGS)
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -O0 -g
CFLAGS += -mrtm -mhle
include $(RTE_SDK)/mk/rte.extapp.mk
