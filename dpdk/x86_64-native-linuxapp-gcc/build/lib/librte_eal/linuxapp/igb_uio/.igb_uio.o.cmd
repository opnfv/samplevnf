cmd_/home/isb/samplevnf/dpdk/x86_64-native-linuxapp-gcc/build/lib/librte_eal/linuxapp/igb_uio/igb_uio.o := gcc -Wp,-MD,/home/isb/samplevnf/dpdk/x86_64-native-linuxapp-gcc/build/lib/librte_eal/linuxapp/igb_uio/.igb_uio.o.d  -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/5/include -I/usr/src/linux-headers-lbm- -I/usr/src/linux-headers-4.4.0-31-generic/arch/x86/include -Iarch/x86/include/generated/uapi -Iarch/x86/include/generated  -I/usr/src/linux-headers-4.4.0-31-generic/include -Iinclude -I/usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi -Iarch/x86/include/generated/uapi -I/usr/src/linux-headers-4.4.0-31-generic/include/uapi -Iinclude/generated/uapi -include /usr/src/linux-headers-4.4.0-31-generic/include/linux/kconfig.h -Iubuntu/include -I/usr/src/linux-headers-4.4.0-31-generic/ubuntu/include   -I/home/isb/samplevnf/dpdk/x86_64-native-linuxapp-gcc/build/lib/librte_eal/linuxapp/igb_uio -D__KERNEL__ -fno-pie -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -Wno-format-security -std=gnu89 -fno-pie -no-pie -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -m64 -falign-jumps=1 -falign-loops=1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3 -mskip-rax-setup -mtune=generic -mno-red-zone -mcmodel=kernel -funit-at-a-time -maccumulate-outgoing-args -DCONFIG_X86_X32_ABI -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 -DCONFIG_AS_CFI_SECTIONS=1 -DCONFIG_AS_FXSAVEQ=1 -DCONFIG_AS_SSSE3=1 -DCONFIG_AS_CRC32=1 -DCONFIG_AS_AVX=1 -DCONFIG_AS_AVX2=1 -DCONFIG_AS_SHA1_NI=1 -DCONFIG_AS_SHA256_NI=1 -pipe -Wno-sign-compare -fno-asynchronous-unwind-tables -fno-delete-null-pointer-checks -O2 --param=allow-store-data-races=0 -Wframe-larger-than=1024 -fstack-protector-strong -Wno-unused-but-set-variable -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-var-tracking-assignments -pg -mfentry -DCC_USING_FENTRY -Wdeclaration-after-statement -Wno-pointer-sign -fno-strict-overflow -fconserve-stack -Werror=implicit-int -Werror=strict-prototypes -Werror=date-time -DCC_HAVE_ASM_GOTO   -I/home/isb/samplevnf/dpdk/lib/librte_eal/linuxapp/igb_uio --param max-inline-insns-single=100   -I/home/isb/samplevnf/dpdk/x86_64-native-linuxapp-gcc/include -Winline -Wall -Werror -include /home/isb/samplevnf/dpdk/x86_64-native-linuxapp-gcc/include/rte_config.h  -DMODULE  -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(igb_uio)"  -D"KBUILD_MODNAME=KBUILD_STR(igb_uio)" -c -o /home/isb/samplevnf/dpdk/x86_64-native-linuxapp-gcc/build/lib/librte_eal/linuxapp/igb_uio/.tmp_igb_uio.o /home/isb/samplevnf/dpdk/x86_64-native-linuxapp-gcc/build/lib/librte_eal/linuxapp/igb_uio/igb_uio.c

source_/home/isb/samplevnf/dpdk/x86_64-native-linuxapp-gcc/build/lib/librte_eal/linuxapp/igb_uio/igb_uio.o := /home/isb/samplevnf/dpdk/x86_64-native-linuxapp-gcc/build/lib/librte_eal/linuxapp/igb_uio/igb_uio.c

deps_/home/isb/samplevnf/dpdk/x86_64-native-linuxapp-gcc/build/lib/librte_eal/linuxapp/igb_uio/igb_uio.o := \
    $(wildcard include/config/xen/dom0.h) \
  /home/isb/samplevnf/dpdk/x86_64-native-linuxapp-gcc/include/rte_config.h \
    $(wildcard include/config/h.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/device.h \
    $(wildcard include/config/debug/devres.h) \
    $(wildcard include/config/generic/msi/irq/domain.h) \
    $(wildcard include/config/pinctrl.h) \
    $(wildcard include/config/generic/msi/irq.h) \
    $(wildcard include/config/numa.h) \
    $(wildcard include/config/dma/cma.h) \
    $(wildcard include/config/pm/sleep.h) \
    $(wildcard include/config/of.h) \
    $(wildcard include/config/devtmpfs.h) \
    $(wildcard include/config/printk.h) \
    $(wildcard include/config/dynamic/debug.h) \
    $(wildcard include/config/sysfs/deprecated.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/ioport.h \
    $(wildcard include/config/memory/hotremove.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/compiler.h \
    $(wildcard include/config/sparse/rcu/pointer.h) \
    $(wildcard include/config/trace/branch/profiling.h) \
    $(wildcard include/config/profile/all/branches.h) \
    $(wildcard include/config/kasan.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/enable/warn/deprecated.h) \
    $(wildcard include/config/kprobes.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/compiler-gcc.h \
    $(wildcard include/config/arch/supports/optimized/inlining.h) \
    $(wildcard include/config/optimize/inlining.h) \
    $(wildcard include/config/gcov/kernel.h) \
    $(wildcard include/config/arch/use/builtin/bswap.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/types.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/types.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/asm-generic/types.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/int-ll64.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/asm-generic/int-ll64.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/bitsperlong.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/bitsperlong.h \
    $(wildcard include/config/64bit.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/asm-generic/bitsperlong.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/posix_types.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/stddef.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/stddef.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/posix_types.h \
    $(wildcard include/config/x86/32.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/posix_types_64.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/asm-generic/posix_types.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/types.h \
    $(wildcard include/config/have/uid16.h) \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/lbdaf.h) \
    $(wildcard include/config/arch/dma/addr/t/64bit.h) \
    $(wildcard include/config/phys/addr/t/64bit.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/kobject.h \
    $(wildcard include/config/uevent/helper.h) \
    $(wildcard include/config/debug/kobject/release.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/list.h \
    $(wildcard include/config/debug/list.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/poison.h \
    $(wildcard include/config/illegal/pointer/value.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/const.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/kernel.h \
    $(wildcard include/config/preempt/voluntary.h) \
    $(wildcard include/config/debug/atomic/sleep.h) \
    $(wildcard include/config/mmu.h) \
    $(wildcard include/config/prove/locking.h) \
    $(wildcard include/config/panic/timeout.h) \
    $(wildcard include/config/tracing.h) \
    $(wildcard include/config/ftrace/mcount/record.h) \
  /usr/lib/gcc/x86_64-linux-gnu/5/include/stdarg.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/linkage.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/stringify.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/export.h \
    $(wildcard include/config/have/underscore/symbol/prefix.h) \
    $(wildcard include/config/modules.h) \
    $(wildcard include/config/modversions.h) \
    $(wildcard include/config/unused/symbols.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/linkage.h \
    $(wildcard include/config/x86/64.h) \
    $(wildcard include/config/x86/alignment/16.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/bitops.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/bitops.h \
    $(wildcard include/config/x86/cmov.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/alternative.h \
    $(wildcard include/config/smp.h) \
    $(wildcard include/config/paravirt.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/asm.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/ptrace.h \
    $(wildcard include/config/x86/debugctlmsr.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/segment.h \
    $(wildcard include/config/cc/stackprotector.h) \
    $(wildcard include/config/x86/32/lazy/gs.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/cache.h \
    $(wildcard include/config/x86/l1/cache/shift.h) \
    $(wildcard include/config/x86/internode/cache/shift.h) \
    $(wildcard include/config/x86/vsmp.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/page_types.h \
    $(wildcard include/config/physical/start.h) \
    $(wildcard include/config/physical/align.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/page_64_types.h \
    $(wildcard include/config/randomize/base.h) \
    $(wildcard include/config/randomize/base/max/offset.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/ptrace.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/ptrace-abi.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/processor-flags.h \
    $(wildcard include/config/vm86.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/processor-flags.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/paravirt_types.h \
    $(wildcard include/config/x86/local/apic.h) \
    $(wildcard include/config/pgtable/levels.h) \
    $(wildcard include/config/x86/pae.h) \
    $(wildcard include/config/queued/spinlocks.h) \
    $(wildcard include/config/paravirt/debug.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/desc_defs.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/kmap_types.h \
    $(wildcard include/config/debug/highmem.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/kmap_types.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/pgtable_types.h \
    $(wildcard include/config/kmemcheck.h) \
    $(wildcard include/config/mem/soft/dirty.h) \
    $(wildcard include/config/proc/fs.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/pgtable_64_types.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/sparsemem.h \
    $(wildcard include/config/sparsemem.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/spinlock_types.h \
    $(wildcard include/config/paravirt/spinlocks.h) \
    $(wildcard include/config/nr/cpus.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/qspinlock_types.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/qrwlock_types.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/ptrace.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/rmwcc.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/barrier.h \
    $(wildcard include/config/x86/ppro/fence.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/nops.h \
    $(wildcard include/config/mk7.h) \
    $(wildcard include/config/x86/p6/nop.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/bitops/find.h \
    $(wildcard include/config/generic/find/first/bit.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/bitops/sched.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/arch_hweight.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/cpufeatures.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/required-features.h \
    $(wildcard include/config/x86/minimum/cpu/family.h) \
    $(wildcard include/config/math/emulation.h) \
    $(wildcard include/config/x86/cmpxchg64.h) \
    $(wildcard include/config/x86/use/3dnow.h) \
    $(wildcard include/config/matom.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/disabled-features.h \
    $(wildcard include/config/x86/intel/mpx.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/bitops/const_hweight.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/bitops/le.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/byteorder.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/byteorder/little_endian.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/byteorder/little_endian.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/swab.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/swab.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/swab.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/byteorder/generic.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/bitops/ext2-atomic-setbit.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/log2.h \
    $(wildcard include/config/arch/has/ilog2/u32.h) \
    $(wildcard include/config/arch/has/ilog2/u64.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/typecheck.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/printk.h \
    $(wildcard include/config/message/loglevel/default.h) \
    $(wildcard include/config/early/printk.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/init.h \
    $(wildcard include/config/broken/rodata.h) \
    $(wildcard include/config/lto.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/kern_levels.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/cache.h \
    $(wildcard include/config/arch/has/cache/line/size.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/kernel.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/sysinfo.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/dynamic_debug.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/sysfs.h \
    $(wildcard include/config/debug/lock/alloc.h) \
    $(wildcard include/config/sysfs.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/kernfs.h \
    $(wildcard include/config/kernfs.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/err.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/errno.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/asm-generic/errno.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/asm-generic/errno-base.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/mutex.h \
    $(wildcard include/config/debug/mutexes.h) \
    $(wildcard include/config/mutex/spin/on/owner.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/current.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/percpu.h \
    $(wildcard include/config/x86/64/smp.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/percpu.h \
    $(wildcard include/config/debug/preempt.h) \
    $(wildcard include/config/have/setup/per/cpu/area.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/threads.h \
    $(wildcard include/config/base/small.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/percpu-defs.h \
    $(wildcard include/config/debug/force/weak/per/cpu.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/spinlock_types.h \
    $(wildcard include/config/generic/lockbreak.h) \
    $(wildcard include/config/debug/spinlock.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/lockdep.h \
    $(wildcard include/config/lockdep.h) \
    $(wildcard include/config/lock/stat.h) \
    $(wildcard include/config/trace/irqflags.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/rwlock_types.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/atomic.h \
    $(wildcard include/config/generic/atomic64.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/atomic.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/processor.h \
    $(wildcard include/config/m486.h) \
    $(wildcard include/config/xen.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/math_emu.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/sigcontext.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/page.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/page_64.h \
    $(wildcard include/config/debug/virtual.h) \
    $(wildcard include/config/flatmem.h) \
    $(wildcard include/config/x86/vsyscall/emulation.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/range.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/memory_model.h \
    $(wildcard include/config/discontigmem.h) \
    $(wildcard include/config/sparsemem/vmemmap.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/getorder.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/msr.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/msr-index.h \
    $(wildcard include/config/tdp/nominal.h) \
    $(wildcard include/config/tdp/level/1.h) \
    $(wildcard include/config/tdp/level/2.h) \
    $(wildcard include/config/tdp/control.h) \
    $(wildcard include/config/tdp/level1.h) \
    $(wildcard include/config/tdp/level2.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/cpumask.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/cpumask.h \
    $(wildcard include/config/cpumask/offstack.h) \
    $(wildcard include/config/hotplug/cpu.h) \
    $(wildcard include/config/debug/per/cpu/maps.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/bitmap.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/string.h \
    $(wildcard include/config/binary/printf.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/string.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/string.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/string_64.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/bug.h \
    $(wildcard include/config/generic/bug.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/bug.h \
    $(wildcard include/config/debug/bugverbose.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/bug.h \
    $(wildcard include/config/bug.h) \
    $(wildcard include/config/generic/bug/relative/pointers.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/msr.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/ioctl.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/ioctl.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/ioctl.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/asm-generic/ioctl.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/paravirt.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/special_insns.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/fpu/types.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/personality.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/personality.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/math64.h \
    $(wildcard include/config/arch/supports/int128.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/div64.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/div64.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/irqflags.h \
    $(wildcard include/config/irqsoff/tracer.h) \
    $(wildcard include/config/preempt/tracer.h) \
    $(wildcard include/config/trace/irqflags/support.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/irqflags.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/cmpxchg.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/cmpxchg_64.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/atomic64_64.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/atomic-long.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/osq_lock.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/idr.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/rcupdate.h \
    $(wildcard include/config/tiny/rcu.h) \
    $(wildcard include/config/tree/rcu.h) \
    $(wildcard include/config/preempt/rcu.h) \
    $(wildcard include/config/rcu/trace.h) \
    $(wildcard include/config/preempt/count.h) \
    $(wildcard include/config/rcu/stall/common.h) \
    $(wildcard include/config/no/hz/full.h) \
    $(wildcard include/config/rcu/nocb/cpu.h) \
    $(wildcard include/config/tasks/rcu.h) \
    $(wildcard include/config/debug/objects/rcu/head.h) \
    $(wildcard include/config/prove/rcu.h) \
    $(wildcard include/config/preempt.h) \
    $(wildcard include/config/rcu/boost.h) \
    $(wildcard include/config/rcu/nocb/cpu/all.h) \
    $(wildcard include/config/no/hz/full/sysidle.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/spinlock.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/preempt.h \
    $(wildcard include/config/preempt/notifiers.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/preempt.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/thread_info.h \
    $(wildcard include/config/compat.h) \
    $(wildcard include/config/debug/stack/usage.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/thread_info.h \
    $(wildcard include/config/ia32/emulation.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/cpufeature.h \
    $(wildcard include/config/x86/feature/names.h) \
    $(wildcard include/config/x86/debug/static/cpu/has.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/bottom_half.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/spinlock.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/jump_label.h \
    $(wildcard include/config/jump/label.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/jump_label.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/qspinlock.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/qspinlock.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/qrwlock.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/qrwlock.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/rwlock.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/spinlock_api_smp.h \
    $(wildcard include/config/inline/spin/lock.h) \
    $(wildcard include/config/inline/spin/lock/bh.h) \
    $(wildcard include/config/inline/spin/lock/irq.h) \
    $(wildcard include/config/inline/spin/lock/irqsave.h) \
    $(wildcard include/config/inline/spin/trylock.h) \
    $(wildcard include/config/inline/spin/trylock/bh.h) \
    $(wildcard include/config/uninline/spin/unlock.h) \
    $(wildcard include/config/inline/spin/unlock/bh.h) \
    $(wildcard include/config/inline/spin/unlock/irq.h) \
    $(wildcard include/config/inline/spin/unlock/irqrestore.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/rwlock_api_smp.h \
    $(wildcard include/config/inline/read/lock.h) \
    $(wildcard include/config/inline/write/lock.h) \
    $(wildcard include/config/inline/read/lock/bh.h) \
    $(wildcard include/config/inline/write/lock/bh.h) \
    $(wildcard include/config/inline/read/lock/irq.h) \
    $(wildcard include/config/inline/write/lock/irq.h) \
    $(wildcard include/config/inline/read/lock/irqsave.h) \
    $(wildcard include/config/inline/write/lock/irqsave.h) \
    $(wildcard include/config/inline/read/trylock.h) \
    $(wildcard include/config/inline/write/trylock.h) \
    $(wildcard include/config/inline/read/unlock.h) \
    $(wildcard include/config/inline/write/unlock.h) \
    $(wildcard include/config/inline/read/unlock/bh.h) \
    $(wildcard include/config/inline/write/unlock/bh.h) \
    $(wildcard include/config/inline/read/unlock/irq.h) \
    $(wildcard include/config/inline/write/unlock/irq.h) \
    $(wildcard include/config/inline/read/unlock/irqrestore.h) \
    $(wildcard include/config/inline/write/unlock/irqrestore.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/seqlock.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/completion.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/wait.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/wait.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/debugobjects.h \
    $(wildcard include/config/debug/objects.h) \
    $(wildcard include/config/debug/objects/free.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/ktime.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/time.h \
    $(wildcard include/config/arch/uses/gettimeoffset.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/time64.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/time.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/jiffies.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/timex.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/timex.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/param.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/param.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/param.h \
    $(wildcard include/config/hz.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/asm-generic/param.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/timex.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/tsc.h \
    $(wildcard include/config/x86/tsc.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/generated/timeconst.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/timekeeping.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/rcutree.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/rbtree.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/errno.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/errno.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/kobject_ns.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/stat.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/stat.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/stat.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/uidgid.h \
    $(wildcard include/config/multiuser.h) \
    $(wildcard include/config/user/ns.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/highuid.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/kref.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/workqueue.h \
    $(wildcard include/config/debug/objects/work.h) \
    $(wildcard include/config/freezer.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/timer.h \
    $(wildcard include/config/timer/stats.h) \
    $(wildcard include/config/debug/objects/timers.h) \
    $(wildcard include/config/no/hz/common.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/sysctl.h \
    $(wildcard include/config/sysctl.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/sysctl.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/klist.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/pinctrl/devinfo.h \
    $(wildcard include/config/pm.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/pinctrl/consumer.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/seq_file.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/nodemask.h \
    $(wildcard include/config/highmem.h) \
    $(wildcard include/config/movable/node.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/numa.h \
    $(wildcard include/config/nodes/shift.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/pinctrl/pinctrl-state.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/pm.h \
    $(wildcard include/config/vt/console/sleep.h) \
    $(wildcard include/config/pm/clk.h) \
    $(wildcard include/config/pm/generic/domains.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/ratelimit.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/gfp.h \
    $(wildcard include/config/zone/dma.h) \
    $(wildcard include/config/zone/dma32.h) \
    $(wildcard include/config/zone/device.h) \
    $(wildcard include/config/deferred/struct/page/init.h) \
    $(wildcard include/config/cma.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/mmdebug.h \
    $(wildcard include/config/debug/vm.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/mmzone.h \
    $(wildcard include/config/force/max/zoneorder.h) \
    $(wildcard include/config/memory/isolation.h) \
    $(wildcard include/config/memcg.h) \
    $(wildcard include/config/memory/hotplug.h) \
    $(wildcard include/config/compaction.h) \
    $(wildcard include/config/flat/node/mem/map.h) \
    $(wildcard include/config/page/extension.h) \
    $(wildcard include/config/no/bootmem.h) \
    $(wildcard include/config/numa/balancing.h) \
    $(wildcard include/config/have/memory/present.h) \
    $(wildcard include/config/have/memoryless/nodes.h) \
    $(wildcard include/config/need/node/memmap/size.h) \
    $(wildcard include/config/have/memblock/node/map.h) \
    $(wildcard include/config/need/multiple/nodes.h) \
    $(wildcard include/config/have/arch/early/pfn/to/nid.h) \
    $(wildcard include/config/sparsemem/extreme.h) \
    $(wildcard include/config/have/arch/pfn/valid.h) \
    $(wildcard include/config/holes/in/zone.h) \
    $(wildcard include/config/arch/has/holes/memorymodel.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/pageblock-flags.h \
    $(wildcard include/config/hugetlb/page.h) \
    $(wildcard include/config/hugetlb/page/size/variable.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/page-flags-layout.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/generated/bounds.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/memory_hotplug.h \
    $(wildcard include/config/have/arch/nodedata/extension.h) \
    $(wildcard include/config/have/bootmem/info/node.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/notifier.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/rwsem.h \
    $(wildcard include/config/rwsem/spin/on/owner.h) \
    $(wildcard include/config/rwsem/generic/spinlock.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/rwsem.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/srcu.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/mmzone.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/mmzone_64.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/smp.h \
    $(wildcard include/config/x86/io/apic.h) \
    $(wildcard include/config/x86/32/smp.h) \
    $(wildcard include/config/debug/nmi/selftest.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/mpspec.h \
    $(wildcard include/config/eisa.h) \
    $(wildcard include/config/x86/mpparse.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/mpspec_def.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/x86_init.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/bootparam.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/screen_info.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/screen_info.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/apm_bios.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/apm_bios.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/edd.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/edd.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/e820.h \
    $(wildcard include/config/efi.h) \
    $(wildcard include/config/hibernation.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/e820.h \
    $(wildcard include/config/x86/pmem/legacy.h) \
    $(wildcard include/config/intel/txt.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/ist.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/ist.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/video/edid.h \
    $(wildcard include/config/x86.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/video/edid.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/apicdef.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/apic.h \
    $(wildcard include/config/x86/x2apic.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/fixmap.h \
    $(wildcard include/config/paravirt/clock.h) \
    $(wildcard include/config/provide/ohci1394/dma/init.h) \
    $(wildcard include/config/pci/mmconfig.h) \
    $(wildcard include/config/x86/intel/mid.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/acpi.h \
    $(wildcard include/config/acpi/apei.h) \
    $(wildcard include/config/acpi.h) \
    $(wildcard include/config/acpi/numa.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/acpi/pdc_intel.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/numa.h \
    $(wildcard include/config/numa/emu.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/topology.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/topology.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/mmu.h \
    $(wildcard include/config/modify/ldt/syscall.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/realmode.h \
    $(wildcard include/config/acpi/sleep.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/io.h \
    $(wildcard include/config/mtrr.h) \
  arch/x86/include/generated/asm/early_ioremap.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/early_ioremap.h \
    $(wildcard include/config/generic/early/ioremap.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/iomap.h \
    $(wildcard include/config/has/ioport/map.h) \
    $(wildcard include/config/pci.h) \
    $(wildcard include/config/generic/iomap.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/pci_iomap.h \
    $(wildcard include/config/no/generic/pci/ioport/map.h) \
    $(wildcard include/config/generic/pci/iomap.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/xen/xen.h \
    $(wildcard include/config/xen/pvh.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/xen/interface/xen.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/xen/interface.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/xen/interface_64.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/pvclock-abi.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/xen/hypervisor.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/xen/features.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/xen/interface/features.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/pvclock.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/clocksource.h \
    $(wildcard include/config/arch/clocksource/data.h) \
    $(wildcard include/config/clocksource/watchdog.h) \
    $(wildcard include/config/clksrc/probe.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/clocksource.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/vsyscall.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/fixmap.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/idle.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/io_apic.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/irq_vectors.h \
    $(wildcard include/config/have/kvm.h) \
    $(wildcard include/config/pci/msi.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/topology.h \
    $(wildcard include/config/use/percpu/numa/node/id.h) \
    $(wildcard include/config/sched/smt.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/smp.h \
    $(wildcard include/config/up/late/init.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/llist.h \
    $(wildcard include/config/arch/have/nmi/safe/cmpxchg.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/percpu.h \
    $(wildcard include/config/need/per/cpu/embed/first/chunk.h) \
    $(wildcard include/config/need/per/cpu/page/first/chunk.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/pfn.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/device.h \
    $(wildcard include/config/x86/dev/dma/ops.h) \
    $(wildcard include/config/intel/iommu.h) \
    $(wildcard include/config/amd/iommu.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/pm_wakeup.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/module.h \
    $(wildcard include/config/module/sig.h) \
    $(wildcard include/config/modules/tree/lookup.h) \
    $(wildcard include/config/kallsyms.h) \
    $(wildcard include/config/tracepoints.h) \
    $(wildcard include/config/event/tracing.h) \
    $(wildcard include/config/livepatch.h) \
    $(wildcard include/config/module/unload.h) \
    $(wildcard include/config/constructors.h) \
    $(wildcard include/config/debug/set/module/ronx.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/kmod.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/elf.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/elf.h \
    $(wildcard include/config/x86/x32/abi.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/user.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/user_64.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/auxvec.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/vdso.h \
    $(wildcard include/config/x86/x32.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/mm_types.h \
    $(wildcard include/config/split/ptlock/cpus.h) \
    $(wildcard include/config/arch/enable/split/pmd/ptlock.h) \
    $(wildcard include/config/have/cmpxchg/double.h) \
    $(wildcard include/config/have/aligned/struct/page.h) \
    $(wildcard include/config/transparent/hugepage.h) \
    $(wildcard include/config/userfaultfd.h) \
    $(wildcard include/config/aio.h) \
    $(wildcard include/config/mmu/notifier.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/auxvec.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/auxvec.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/uprobes.h \
    $(wildcard include/config/uprobes.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/uprobes.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/elf.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/elf-em.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/moduleparam.h \
    $(wildcard include/config/alpha.h) \
    $(wildcard include/config/ia64.h) \
    $(wildcard include/config/ppc64.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/rbtree_latch.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/module.h \
    $(wildcard include/config/m586.h) \
    $(wildcard include/config/m586tsc.h) \
    $(wildcard include/config/m586mmx.h) \
    $(wildcard include/config/mcore2.h) \
    $(wildcard include/config/m686.h) \
    $(wildcard include/config/mpentiumii.h) \
    $(wildcard include/config/mpentiumiii.h) \
    $(wildcard include/config/mpentiumm.h) \
    $(wildcard include/config/mpentium4.h) \
    $(wildcard include/config/mk6.h) \
    $(wildcard include/config/mk8.h) \
    $(wildcard include/config/melan.h) \
    $(wildcard include/config/mcrusoe.h) \
    $(wildcard include/config/mefficeon.h) \
    $(wildcard include/config/mwinchipc6.h) \
    $(wildcard include/config/mwinchip3d.h) \
    $(wildcard include/config/mcyrixiii.h) \
    $(wildcard include/config/mviac3/2.h) \
    $(wildcard include/config/mviac7.h) \
    $(wildcard include/config/mgeodegx1.h) \
    $(wildcard include/config/mgeode/lx.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/module.h \
    $(wildcard include/config/have/mod/arch/specific.h) \
    $(wildcard include/config/modules/use/elf/rel.h) \
    $(wildcard include/config/modules/use/elf/rela.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/pci.h \
    $(wildcard include/config/pci/iov.h) \
    $(wildcard include/config/pcieaspm.h) \
    $(wildcard include/config/pci/ats.h) \
    $(wildcard include/config/pci/domains/generic.h) \
    $(wildcard include/config/pci/bus/addr/t/64bit.h) \
    $(wildcard include/config/pcieportbus.h) \
    $(wildcard include/config/pcieaer.h) \
    $(wildcard include/config/pcie/ecrc.h) \
    $(wildcard include/config/ht/irq.h) \
    $(wildcard include/config/pci/domains.h) \
    $(wildcard include/config/pci/quirks.h) \
    $(wildcard include/config/hibernate/callbacks.h) \
    $(wildcard include/config/hotplug/pci.h) \
    $(wildcard include/config/eeh.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/mod_devicetable.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/uuid.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/uuid.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/io.h \
    $(wildcard include/config/have/arch/huge/vmap.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/resource_ext.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/slab.h \
    $(wildcard include/config/debug/slab.h) \
    $(wildcard include/config/failslab.h) \
    $(wildcard include/config/slab.h) \
    $(wildcard include/config/slub.h) \
    $(wildcard include/config/slob.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/kmemleak.h \
    $(wildcard include/config/debug/kmemleak.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/kasan.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/pci.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/pci_regs.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/pci_ids.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/pci-dma.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/dmapool.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/scatterlist.h \
    $(wildcard include/config/debug/sg.h) \
    $(wildcard include/config/need/sg/dma/length.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/mm.h \
    $(wildcard include/config/ppc.h) \
    $(wildcard include/config/parisc.h) \
    $(wildcard include/config/metag.h) \
    $(wildcard include/config/stack/growsup.h) \
    $(wildcard include/config/shmem.h) \
    $(wildcard include/config/debug/vm/rb.h) \
    $(wildcard include/config/debug/pagealloc.h) \
    $(wildcard include/config/hugetlbfs.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/debug_locks.h \
    $(wildcard include/config/debug/locking/api/selftests.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/bit_spinlock.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/shrinker.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/resource.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/resource.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/resource.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/resource.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/asm-generic/resource.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/page_ext.h \
    $(wildcard include/config/idle/page/tracking.h) \
    $(wildcard include/config/page/owner.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/stacktrace.h \
    $(wildcard include/config/stacktrace.h) \
    $(wildcard include/config/user/stacktrace/support.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/pgtable.h \
    $(wildcard include/config/debug/wx.h) \
    $(wildcard include/config/have/arch/soft/dirty.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/pgtable_64.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/pgtable.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/page-flags.h \
    $(wildcard include/config/arch/uses/pg/uncached.h) \
    $(wildcard include/config/memory/failure.h) \
    $(wildcard include/config/swap.h) \
    $(wildcard include/config/ksm.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/huge_mm.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/vmstat.h \
    $(wildcard include/config/vm/event/counters.h) \
    $(wildcard include/config/debug/tlbflush.h) \
    $(wildcard include/config/debug/vm/vmacache.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/vm_event_item.h \
    $(wildcard include/config/migration.h) \
    $(wildcard include/config/memory/balloon.h) \
    $(wildcard include/config/balloon/compaction.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/pci.h \
    $(wildcard include/config/pci/msi/irq/domain.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/pci_64.h \
    $(wildcard include/config/calgary/iommu.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/pci-dma-compat.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/dma-mapping.h \
    $(wildcard include/config/has/dma.h) \
    $(wildcard include/config/arch/has/dma/set/coherent/mask.h) \
    $(wildcard include/config/have/dma/attrs.h) \
    $(wildcard include/config/need/dma/map/state.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/sizes.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/dma-attrs.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/dma-direction.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/dma-mapping.h \
    $(wildcard include/config/isa.h) \
    $(wildcard include/config/x86/dma/remap.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/kmemcheck.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/dma-debug.h \
    $(wildcard include/config/dma/api/debug.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/swiotlb.h \
    $(wildcard include/config/swiotlb.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/swiotlb.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/dma-contiguous.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/dma-mapping-common.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/dma-coherent.h \
    $(wildcard include/config/have/generic/dma/coherent.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/pci.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/uio_driver.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/fs.h \
    $(wildcard include/config/fs/posix/acl.h) \
    $(wildcard include/config/security.h) \
    $(wildcard include/config/cgroup/writeback.h) \
    $(wildcard include/config/ima.h) \
    $(wildcard include/config/fsnotify.h) \
    $(wildcard include/config/epoll.h) \
    $(wildcard include/config/file/locking.h) \
    $(wildcard include/config/quota.h) \
    $(wildcard include/config/blk/dev/loop.h) \
    $(wildcard include/config/fs/dax.h) \
    $(wildcard include/config/block.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/kdev_t.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/kdev_t.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/dcache.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/rculist.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/rculist_bl.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/list_bl.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/lockref.h \
    $(wildcard include/config/arch/use/cmpxchg/lockref.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/path.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/list_lru.h \
    $(wildcard include/config/memcg/kmem.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/radix-tree.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/pid.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/capability.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/capability.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/semaphore.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/fiemap.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/migrate_mode.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/percpu-rwsem.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/rcu_sync.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/blk_types.h \
    $(wildcard include/config/blk/cgroup.h) \
    $(wildcard include/config/blk/dev/integrity.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/fs.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/limits.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/quota.h \
    $(wildcard include/config/quota/netlink/interface.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/percpu_counter.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/dqblk_xfs.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/dqblk_v1.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/dqblk_v2.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/dqblk_qtree.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/projid.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/quota.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/nfs_fs_i.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/fcntl.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/fcntl.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/uapi/asm/fcntl.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/asm-generic/fcntl.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/interrupt.h \
    $(wildcard include/config/irq/forced/threading.h) \
    $(wildcard include/config/generic/irq/probe.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/irqreturn.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/irqnr.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/uapi/linux/irqnr.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/hardirq.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/ftrace_irq.h \
    $(wildcard include/config/ftrace/nmi/enter.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/vtime.h \
    $(wildcard include/config/virt/cpu/accounting/native.h) \
    $(wildcard include/config/virt/cpu/accounting/gen.h) \
    $(wildcard include/config/virt/cpu/accounting.h) \
    $(wildcard include/config/irq/time/accounting.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/context_tracking_state.h \
    $(wildcard include/config/context/tracking.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/static_key.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/hardirq.h \
    $(wildcard include/config/x86/thermal/vector.h) \
    $(wildcard include/config/x86/mce/threshold.h) \
    $(wildcard include/config/x86/mce/amd.h) \
    $(wildcard include/config/hyperv.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/irq.h \
    $(wildcard include/config/irq/domain/hierarchy.h) \
    $(wildcard include/config/generic/pending/irq.h) \
    $(wildcard include/config/hardirqs/sw/resend.h) \
    $(wildcard include/config/generic/irq/legacy/alloc/hwirq.h) \
    $(wildcard include/config/generic/irq/legacy.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/irqhandler.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/irq.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/irq_regs.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/irqdesc.h \
    $(wildcard include/config/irq/preflow/fasteoi.h) \
    $(wildcard include/config/sparse/irq.h) \
    $(wildcard include/config/handle/domain/irq.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/hw_irq.h \
    $(wildcard include/config/hpet/timer.h) \
    $(wildcard include/config/dmar/table.h) \
    $(wildcard include/config/x86/uv.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/profile.h \
    $(wildcard include/config/profiling.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/sections.h \
    $(wildcard include/config/debug/rodata.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/asm-generic/sections.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/uaccess.h \
    $(wildcard include/config/x86/intel/usercopy.h) \
    $(wildcard include/config/debug/strict/user/copy/checks.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/smap.h \
    $(wildcard include/config/x86/smap.h) \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/uaccess_64.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/hrtimer.h \
    $(wildcard include/config/high/res/timers.h) \
    $(wildcard include/config/time/low/res.h) \
    $(wildcard include/config/timerfd.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/timerqueue.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/msi.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/msi.h \
  /usr/src/linux-headers-4.4.0-31-generic/arch/x86/include/asm/irqdomain.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/irqdomain.h \
    $(wildcard include/config/irq/domain.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/of.h \
    $(wildcard include/config/sparc.h) \
    $(wildcard include/config/of/dynamic.h) \
    $(wildcard include/config/attach/node.h) \
    $(wildcard include/config/detach/node.h) \
    $(wildcard include/config/add/property.h) \
    $(wildcard include/config/remove/property.h) \
    $(wildcard include/config/update/property.h) \
    $(wildcard include/config/of/numa.h) \
    $(wildcard include/config/no/change.h) \
    $(wildcard include/config/change/add.h) \
    $(wildcard include/config/change/remove.h) \
    $(wildcard include/config/of/resolve.h) \
    $(wildcard include/config/of/overlay.h) \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/property.h \
  /usr/src/linux-headers-4.4.0-31-generic/include/linux/fwnode.h \
  include/generated/uapi/linux/version.h \
  /home/isb/samplevnf/dpdk/x86_64-native-linuxapp-gcc/include/rte_pci_dev_features.h \
  /home/isb/samplevnf/dpdk/x86_64-native-linuxapp-gcc/include/rte_pci_dev_feature_defs.h \
  /home/isb/samplevnf/dpdk/lib/librte_eal/linuxapp/igb_uio/compat.h \

/home/isb/samplevnf/dpdk/x86_64-native-linuxapp-gcc/build/lib/librte_eal/linuxapp/igb_uio/igb_uio.o: $(deps_/home/isb/samplevnf/dpdk/x86_64-native-linuxapp-gcc/build/lib/librte_eal/linuxapp/igb_uio/igb_uio.o)

$(deps_/home/isb/samplevnf/dpdk/x86_64-native-linuxapp-gcc/build/lib/librte_eal/linuxapp/igb_uio/igb_uio.o):
