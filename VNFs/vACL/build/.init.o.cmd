cmd_init.o = gcc -Wp,-MD,./.init.o.d.tmp -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2  -I/home/isb/patch-submission/samplevnf/VNFs/vACL/build/include -I/home/isb/patch-submission/samplevnf/dpdk/x86_64-native-linuxapp-gcc/include -include /home/isb/patch-submission/samplevnf/dpdk/x86_64-native-linuxapp-gcc/include/rte_config.h -I/home/isb/patch-submission/samplevnf/VNFs/vACL -mrtm -mhle -I/home/isb/patch-submission/samplevnf/VNFs/vACL/pipeline -I/home/isb/patch-submission/samplevnf/common/vnf_common -I/home/isb/patch-submission/samplevnf/common/VIL/l2l3_stack -I/home/isb/patch-submission/samplevnf/common/VIL/conntrack -I/home/isb/patch-submission/samplevnf/common/VIL/pipeline_common -I/home/isb/patch-submission/samplevnf/common/VIL/pipeline_loadb -I/home/isb/patch-submission/samplevnf/common/VIL/pipeline_master -I/home/isb/patch-submission/samplevnf/common/VIL/pipeline_passthrough -I/home/isb/patch-submission/samplevnf/common/VIL/pipeline_txrx -I/home/isb/patch-submission/samplevnf/common/VIL/pipeline_arpicmp -O3 -DIPV6 -Wno-error=unused-function -Wno-error=unused-variable   -o init.o -c /home/isb/patch-submission/samplevnf/VNFs/vACL/init.c 
