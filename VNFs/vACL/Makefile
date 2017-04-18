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

ifeq ($(VNF_DIR),)
$(error "Please define VNF_CORE environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

DIRS-(CONFIG_RTE_LIBRTE_PIPELINE) += pipeline

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = vACL


VPATH += $(VNF_CORE)/common/vnf_common
#VPATH += $(VNF_CORE)/common/VIL/arp
VPATH += $(VNF_CORE)/common/VIL/conntrack
VPATH += $(VNF_CORE)/common/VIL/pipeline_common
VPATH += $(VNF_CORE)/common/VIL/pipeline_loadb
VPATH += $(VNF_CORE)/common/VIL/pipeline_master
VPATH += $(VNF_CORE)/common/VIL/pipeline_passthrough
VPATH += $(SRCDIR)/pipeline
VPATH += $(VNF_CORE)/common/VIL/pipeline_txrx
VPATH += $(VNF_CORE)/common/VIL/pipeline_arpicmp

INC += $(wildcard *.h)
INC += $(wildcard pipeline/*.h)
INC += $(wildcard $(VNF_CORE)/common/vnf_common/*.h)
#INC += $(wildcard $(VNF_CORE)/common/VIL/arp/*.h)
INC += $(wildcard $(VNF_CORE)/common/VIL/pipeline_arpicmp/*.h)
INC += $(wildcard $(VNF_CORE)/common/VIL/conntrack/*.h)
INC += $(wildcard $(VNF_CORE)/common/VIL/pipeline_loadb/*.h)
INC += $(wildcard $(VNF_CORE)/common/VIL/pipeline_common/*.h)
INC += $(wildcard $(VNF_CORE)/common/VIL/pipeline_master/*.h)
INC += $(wildcard $(VNF_CORE)/common/VIL/pipeline_passthrough/*.h)
INC += $(wildcard $(VNF_CORE)/common/VIL/pipeline_txrx/*.h)

CFLAGS += -I$(SRCDIR) -I$(SRCDIR)/pipeline -I$(VNF_CORE)/common/vnf_common
CFLAGS += -I$(VNF_CORE)/common/VIL/arp -I$(VNF_CORE)/common/VIL/conntrack
CFLAGS += -I$(VNF_CORE)/common/VIL/pipeline_common -I$(VNF_CORE)/common/VIL/pipeline_loadb
CFLAGS += -I$(VNF_CORE)/common/VIL/pipeline_master -I$(VNF_CORE)/common/VIL/pipeline_passthrough
CFLAGS += -I$(VNF_CORE)/common/VIL/pipeline_txrx
CFLAGS += -I$(VNF_CORE)/common/VIL/pipeline_arpicmp

# all source are stored in SRCS-y
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) := main.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += config_parse.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += config_parse_tm.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += config_check.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += init.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += thread.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += thread_fe.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += cpu_core_map.c

SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += pipeline_common_be.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += pipeline_common_fe.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += pipeline_master_be.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += pipeline_master.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += rte_ct_tcp.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += rte_cnxn_tracking.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += rte_ct_udp.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += rte_ct_synproxy.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += pipeline_loadb.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += pipeline_loadb_be.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += pipeline_acl.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += pipeline_acl_be.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += vnf_common.c
#SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += lib_arp.c
#SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += lib_icmpv6.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += pipeline_txrx.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += pipeline_txrx_be.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += pipeline_arpicmp.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += pipeline_arpicmp_be.c

CFLAGS += -O3
CFLAGS += -DIPV6
CFLAGS += -DVNF_ACL
CFLAGS += -Wno-error=unused-function -Wno-error=unused-variable
#CFLAGS += $(WERROR_FLAGS) -Wno-error=unused-function -Wno-error=unused-variable

include $(RTE_SDK)/mk/rte.extapp.mk
