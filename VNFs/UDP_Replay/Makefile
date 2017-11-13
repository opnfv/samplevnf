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
DIRS-y += pipeline

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = UDP_Replay

VPATH += $(VNF_CORE)/common/vnf_common
VPATH += $(VNF_CORE)/common/VIL/pipeline_arpicmp
VPATH += $(VNF_CORE)/common/VIL/conntrack
VPATH += $(VNF_CORE)/common/VIL/pipeline_common
VPATH += $(VNF_CORE)/common/VIL/pipeline_loadb
VPATH += $(VNF_CORE)/common/VIL/pipeline_master
VPATH += $(VNF_CORE)/common/VIL/pipeline_passthrough
VPATH += $(SRCDIR)/pipeline
VPATH += $(VNF_CORE)/common/VIL/pipeline_txrx
VPATH += $(VNF_CORE)/common/VIL/l2l3_stack
VPATH += $(VNF_CORE)/common/VIL/gateway

INC += $(wildcard *.h)
INC += $(wildcard pipeline/*.h)
INC += $(wildcard $(VNF_CORE)/common/vnf_common/*.h)
INC += $(wildcard $(VNF_CORE)/common/VIL/pipeline_arpicmp/*.h)
INC += $(wildcard $(VNF_CORE)/common/VIL/conntrack/*.h)
INC += $(wildcard $(VNF_CORE)/common/VIL/pipeline_loadb/*.h)
INC += $(wildcard $(VNF_CORE)/common/VIL/pipeline_common/*.h)
INC += $(wildcard $(VNF_CORE)/common/VIL/pipeline_master/*.h)
INC += $(wildcard $(VNF_CORE)/common/VIL/pipeline_passthrough/*.h)
INC += $(wildcard $(VNF_CORE)/common/VIL/pipeline_txrx/*.h)
INC += $(wildcard $(VNF_CORE)/common/VIL/l2l3_stack/*.h)
INC += $(wildcard $(VNF_CORE)/common/VIL/gateway/*.h)

CFLAGS += -I$(SRCDIR) -mrtm -mhle -I$(SRCDIR)/pipeline -I$(VNF_CORE)/common/vnf_common
CFLAGS += -I$(VNF_CORE)/common/VIL/conntrack -I$(VNF_CORE)/common/VIL/l2l3_stack
CFLAGS += -I$(VNF_CORE)/common/VIL/pipeline_common -I$(VNF_CORE)/common/VIL/pipeline_loadb
CFLAGS += -I$(VNF_CORE)/common/VIL/pipeline_master -I$(VNF_CORE)/common/VIL/pipeline_passthrough
CFLAGS += -I$(VNF_CORE)/common/VIL/pipeline_txrx
CFLAGS += -I$(VNF_CORE)/common/VIL/pipeline_arpicmp
CFLAGS += -I$(VNF_CORE)/common/VIL/gateway

# all source are stored in SRCS-y
SRCS-y := main.c
SRCS-y += config_parse.c
SRCS-y += config_parse_tm.c
SRCS-y += config_check.c

SRCS-y += lib_arp.c
SRCS-y += lib_icmpv6.c
SRCS-y += interface.c
SRCS-y += hle.c
SRCS-y += tsx.c
SRCS-y += l2_proto.c
SRCS-y += l3fwd_main.c
SRCS-y += l3fwd_lpm4.c
SRCS-y += l3fwd_lpm6.c
SRCS-y += bond.c

SRCS-y += pipeline_common_be.c
SRCS-y += pipeline_common_fe.c
SRCS-y += pipeline_master_be.c
SRCS-y += pipeline_master.c
SRCS-y += pipeline_passthrough_be.c
SRCS-y += pipeline_passthrough.c
SRCS-y += pipeline_arpicmp.c
SRCS-y += pipeline_loadb.c
SRCS-y += pipeline_loadb_be.c
SRCS-y += vnf_common.c
SRCS-y += pipeline_arpicmp_be.c
SRCS-y += gateway.c

CFLAGS += -O3 $(USER_FLAGS)
CFLAGS += $(WERROR_FLAGS)

# workaround for a gcc bug with noreturn attribute
# http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_main.o += -Wno-return-type
endif

include $(RTE_SDK)/mk/rte.extapp.mk
