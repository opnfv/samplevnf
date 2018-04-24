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

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

rte_version_h := $(RTE_SDK)/$(RTE_TARGET)/include/rte_version.h
rte_ver_part = $(shell sed -n -e 's/^\#define\s*$1\s*\(.*\)$$/\1/p' $(rte_version_h))
rte_ver_eval = $(shell printf '%u' $$(printf '0x%02x%02x%02x%02x' $1 $2 $3 $4))
rte_ver_MMLR = $(call rte_ver_eval,$(call \
	rte_ver_part,RTE_VER_MAJOR),$(call \
	rte_ver_part,RTE_VER_MINOR),$(call \
	rte_ver_part,RTE_VER_PATCH_LEVEL),$(call \
	rte_ver_part,RTE_VER_PATCH_RELEASE))
rte_ver_YMMR = $(call rte_ver_eval,$(call \
	rte_ver_part,RTE_VER_YEAR),$(call \
	rte_ver_part,RTE_VER_MONTH),$(call \
	rte_ver_part,RTE_VER_MINOR),$(call \
	rte_ver_part,RTE_VER_RELEASE))
rte_ver_dpdk := $(if $(call rte_ver_part,RTE_VER_MAJOR),$(rte_ver_MMLR),$(rte_ver_YMMR))
rte_ver_comp = $(shell test $(rte_ver_dpdk) $5 $(call rte_ver_eval,$1,$2,$3,$4) && echo 'y')
rte_ver_EQ = $(call rte_ver_comp,$1,$2,$3,$4,-eq)
rte_ver_NE = $(call rte_ver_comp,$1,$2,$3,$4,-ne)
rte_ver_GT = $(call rte_ver_comp,$1,$2,$3,$4,-gt)
rte_ver_LT = $(call rte_ver_comp,$1,$2,$3,$4,-lt)
rte_ver_GE = $(call rte_ver_comp,$1,$2,$3,$4,-ge)
rte_ver_LE = $(call rte_ver_comp,$1,$2,$3,$4,-le)

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = prox
CFLAGS += -DPROGRAM_NAME=\"$(APP)\"

CFLAGS += -O2 -g
CFLAGS += -fno-stack-protector -Wno-deprecated-declarations

ifeq ($(BNG_QINQ),)
CFLAGS += -DUSE_QINQ
else ifeq ($(BNG_QINQ),y)
CFLAGS += -DUSE_QINQ
endif

ifeq ($(MPLS_ROUTING),)
CFLAGS += -DMPLS_ROUTING
else ifeq ($(MPLS_ROUTING),y)
CFLAGS += -DMPLS_ROUTING
endif

LD_LUA  = $(shell pkg-config --silence-errors --libs-only-l lua)
CFLAGS += $(shell pkg-config --silence-errors --cflags lua)
ifeq ($(LD_LUA),)
LD_LUA  = $(shell pkg-config --silence-errors --libs-only-l lua5.2)
CFLAGS += $(shell pkg-config --silence-errors --cflags lua5.2)
ifeq ($(LD_LUA),)
LD_LUA  = $(shell pkg-config --silence-errors --libs-only-l lua5.3)
CFLAGS += $(shell pkg-config --silence-errors --cflags lua5.3)
ifeq ($(LD_LUA),)
LD_LUA =-llua
endif
endif
endif

ifeq ($(CONFIG_RTE_BUILD_SHARED_LIB),y)
LDLIBS += -lrte_pmd_ring -lrte_pmd_null -lrte_pmd_ixgbe -lrte_pmd_i40e  -lrte_pmd_e1000  -lrte_pmd_virtio -lrte_pmd_vmxnet3_uio
endif

LD_TINFO = $(shell pkg-config --silence-errors --libs-only-l tinfo)
LDFLAGS += -lm -lpcap $(LD_TINFO) $(LD_LUA)
LDFLAGS += -lncurses -lncursesw -ledit

PROX_STATS ?= y
ifeq ($(PROX_STATS),y)
CFLAGS += -DPROX_STATS
endif

ifeq ($(DPI_STATS),y)
CFLAGS += -DDPI_STATS
endif

ifeq ($(HW_DIRECT_STATS),y)
CFLAGS += -DPROX_HW_DIRECT_STATS
endif

ifeq ($(dbg),y)
EXTRA_CFLAGS += -ggdb
endif

ifeq ($(log),)
CFLAGS += -DPROX_MAX_LOG_LVL=2
else
CFLAGS += -DPROX_MAX_LOG_LVL=$(log)
endif

# When ipv4 packet is de-encalpusled from ipv6 packet, genaerate IP checksum.
ifeq ($(GEN_DECAP_IPV6_TO_IPV4_CKSUM),y)
CFLAGS += -DGEN_DECAP_IPV6_TO_IPV4_CKSUM
endif

# override any use-case/enviroment specific choices regarding crc and
# always use the sw implementation
ifeq ($(crc),soft)
CFLAGS += -DSOFT_CRC
endif

CFLAGS += -DPROX_PREFETCH_OFFSET=2
#CFLAGS += -DBRAS_RX_BULK
#CFLAGS += -DASSERT
#CFLAGS += -DENABLE_EXTRA_USER_STATISTICS
CFLAGS += -DLATENCY_PER_PACKET
CFLAGS += -DLATENCY_DETAILS
CFLAGS += -DGRE_TP
CFLAGS += -std=gnu99
CFLAGS += -D_GNU_SOURCE                # for PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -Wno-unused
CFLAGS += -Wno-unused-parameter
CFLAGS += -Wno-unused-result

# all source are stored in SRCS-y

SRCS-y := task_init.c

SRCS-y += handle_aggregator.c
SRCS-y += handle_nop.c
SRCS-y += handle_irq.c
SRCS-y += handle_arp.c
SRCS-y += handle_impair.c
SRCS-y += handle_lat.c
SRCS-y += handle_qos.c
SRCS-y += handle_qinq_decap4.c
SRCS-y += handle_routing.c
SRCS-y += handle_untag.c
SRCS-y += handle_mplstag.c
SRCS-y += handle_qinq_decap6.c

# support for GRE encap/decap dropped in latest DPDK versions
SRCS-$(call rte_ver_LT,2,1,0,0) += handle_gre_decap_encap.c

SRCS-y += rw_reg.c
SRCS-y += handle_lb_qinq.c
SRCS-y += handle_lb_pos.c
SRCS-y += handle_lb_net.c
SRCS-y += handle_qinq_encap4.c
SRCS-y += handle_qinq_encap6.c
SRCS-y += handle_classify.c
SRCS-y += handle_l2fwd.c
SRCS-y += handle_swap.c
SRCS-y += handle_police.c
SRCS-y += handle_acl.c
SRCS-y += handle_gen.c
SRCS-y += handle_master.c
SRCS-y += packet_utils.c
SRCS-y += handle_mirror.c
SRCS-y += handle_genl4.c
SRCS-y += handle_ipv6_tunnel.c
SRCS-y += handle_read.c
SRCS-$(CONFIG_RTE_LIBRTE_PMD_AESNI_MB) += handle_esp.c
ifneq ($(CONFIG_RTE_LIBRTE_PMD_AESNI_MB),y)
$(warning "Building w/o IPSEC support")
endif
SRCS-y += handle_cgnat.c
SRCS-y += handle_nat.c
SRCS-y += handle_dump.c
SRCS-y += handle_tsc.c
SRCS-y += handle_fm.c
SRCS-$(call rte_ver_GE,1,8,0,16) += handle_nsh.c
SRCS-y += handle_lb_5tuple.c
SRCS-y += handle_blockudp.c
SRCS-y += toeplitz.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += handle_pf_acl.c

SRCS-y += thread_nop.c
SRCS-y += thread_generic.c
SRCS-$(CONFIG_RTE_LIBRTE_PIPELINE) += thread_pipeline.c

SRCS-y += prox_args.c prox_cfg.c prox_cksum.c prox_port_cfg.c

SRCS-y += cfgfile.c clock.c commands.c cqm.c msr.c defaults.c
SRCS-y += display.c display_latency.c display_mempools.c
SRCS-y += display_ports.c display_rings.c display_priority.c display_pkt_len.c display_l4gen.c display_tasks.c display_irq.c
SRCS-y += log.c hash_utils.c main.c parse_utils.c file_utils.c
SRCS-y += run.c input_conn.c input_curses.c
SRCS-y += rx_pkt.c lconf.c tx_pkt.c expire_cpe.c ip_subnet.c
SRCS-y += stats_port.c stats_mempool.c stats_ring.c stats_l4gen.c
SRCS-y += stats_latency.c stats_global.c stats_core.c stats_task.c stats_prio.c stats_irq.c
SRCS-y += cmd_parser.c input.c prox_shared.c prox_lua_types.c
SRCS-y += genl4_bundle.c heap.c genl4_stream_tcp.c genl4_stream_udp.c cdf.c
SRCS-y += stats.c stats_cons_log.c stats_cons_cli.c stats_parser.c hash_set.c prox_lua.c prox_malloc.c

ifeq ($(FIRST_PROX_MAKE),)
MAKEFLAGS += --no-print-directory
FIRST_PROX_MAKE = 1
export FIRST_PROX_MAKE
all:
	@./helper-scripts/trailing.sh
	@$(MAKE) $@
%::
	@$(MAKE) $@
else
include $(RTE_SDK)/mk/rte.extapp.mk
endif
