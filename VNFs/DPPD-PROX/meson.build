##
## Copyright (c) 2021 Heinrich Kuhn <heinrich.kuhn@corigine.com>
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##	   http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##

project('dppd-prox', 'C',
	version:
	run_command(['git', 'describe',
		     '--abbrev=8', '--dirty', '--always']).stdout().strip(),
	license: 'Apache',
	default_options: ['buildtype=release', 'c_std=gnu99'],
	meson_version: '>= 0.47'
)

cc = meson.get_compiler('c')

# Configure options for prox
# Grab the DPDK version here "manually" as it is not available in the dpdk_dep
# object
dpdk_version = run_command('pkg-config', '--modversion', 'libdpdk').stdout()

if get_option('bng_qinq').enabled()
	add_project_arguments('-DUSE_QINQ', language: 'c')
endif

if get_option('mpls_routing').enabled()
	add_project_arguments('-DMPLS_ROUTING',  language: 'c')
endif

if get_option('prox_stats').enabled()
	add_project_arguments('-DPROX_STATS',  language: 'c')
endif

if get_option('hw_direct_stats').enabled()
	add_project_arguments('-DPROX_HW_DIRECT_STATS',  language: 'c')
endif

if get_option('dbg')
	add_project_arguments('-ggdb',	language: 'c')
endif

if get_option('log')
	add_project_arguments('-DPROX_MAX_LOG_LVL=2',  language: 'c')
endif

if get_option('gen_decap_ipv6_to_ipv4_cksum').enabled()
	add_project_arguments('-DGEN_DECAP_IPV6_TO_IPV4_CKSUM',  language: 'c')
endif

if get_option('crc') == 'soft'
	add_project_arguments('-DSOFT_CRC',  language: 'c')
endif

cflags = [
	'-DPROGRAM_NAME="prox"',
	'-fno-stack-protector',
	'-DPROX_PREFETCH_OFFSET=2',
	'-DLATENCY_PER_PACKET',
	'-DLATENCY_HISTOGRAM',
	'-DGRE_TP',
	'-D_GNU_SOURCE']	# for PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP

# Add configured cflags to arguments
foreach arg: cflags
	add_project_arguments(arg, language: 'c')
endforeach

# enable warning flags if they are supported by the compiler
warning_flags = [
	'-Wno-unused',
	'-Wno-unused-parameter',
	'-Wno-unused-result',
	'-Wno-deprecated-declarations']

foreach arg: warning_flags
	if cc.has_argument(arg)
		add_project_arguments(arg, language: 'c')
	endif
endforeach

# Attempt to find a suitable lua and add to deps
lua_versions = ['lua', 'lua5.2', 'lua5.3']
foreach i:lua_versions
	lua_dep = dependency(i, required: false)
	if not lua_dep.found()
	lua_dep = cc.find_library(i, required: false)
	endif
	if lua_dep.found()
	break
	endif
endforeach
if not lua_dep.found()
	error('Suitable lua version not found')
endif

has_sym_args = [
        [ 'HAVE_LIBEDIT_EL_RFUNC_T', 'histedit.h',
        'el_rfunc_t' ],
]
config = configuration_data()
foreach arg:has_sym_args
        config.set(arg[0], cc.has_header_symbol(arg[1], arg[2]))
endforeach
configure_file(output : 'libedit_autoconf.h', configuration : config)

# All other dependencies
dpdk_dep = dependency('libdpdk', required: true)
tinfo_dep = dependency('tinfo', required: false)
threads_dep = dependency('threads', required: true)
pcap_dep = dependency('pcap', required: true)
ncurses_dep = dependency('ncurses', required: true)
ncursesw_dep = dependency('ncursesw', required: true)
libedit_dep = dependency('libedit', required: true)
math_dep = cc.find_library('m', required : false)
dl_dep = cc.find_library('dl', required : true)

deps = [dpdk_dep,
	tinfo_dep,
	threads_dep,
	pcap_dep,
	ncurses_dep,
	ncursesw_dep,
	libedit_dep,
	math_dep,
	dl_dep,
	lua_dep]

# Explicitly add these to the dependency list
deps += [cc.find_library('rte_bus_pci', required: true)]
deps += [cc.find_library('rte_bus_vdev', required: true)]

if dpdk_version.version_compare('<20.11.0')
deps += [cc.find_library('rte_pmd_ring', required: true)]
else
deps += [cc.find_library('rte_net_ring', required: true)]
endif

sources = files(
	'task_init.c', 'handle_aggregator.c', 'handle_nop.c', 'handle_irq.c',
	'handle_arp.c', 'handle_impair.c', 'handle_lat.c', 'handle_qos.c',
	'handle_qinq_decap4.c', 'handle_routing.c', 'handle_untag.c',
	'handle_mplstag.c', 'handle_qinq_decap6.c',
	'handle_lb_qinq.c', 'handle_lb_pos.c', 'handle_lb_net.c',
	'handle_qinq_encap4.c', 'handle_qinq_encap6.c', 'handle_classify.c',
	'handle_l2fwd.c', 'handle_swap.c', 'handle_police.c', 'handle_acl.c',
	'handle_gen.c', 'handle_master.c', 'packet_utils.c', 'handle_mirror.c',
	'handle_genl4.c', 'handle_ipv6_tunnel.c', 'handle_read.c',
	'handle_cgnat.c', 'handle_nat.c', 'handle_dump.c', 'handle_tsc.c',
	'handle_fm.c', 'handle_lb_5tuple.c', 'handle_blockudp.c', 'toeplitz.c',
	'thread_nop.c', 'thread_generic.c', 'prox_args.c', 'prox_cfg.c',
	'prox_cksum.c', 'prox_port_cfg.c', 'cfgfile.c', 'clock.c',
	'commands.c', 'cqm.c', 'msr.c', 'defaults.c', 'display.c',
	'display_latency.c', 'display_latency_distr.c', 'display_mempools.c',
	'display_ports.c', 'display_rings.c', 'display_priority.c',
	'display_pkt_len.c', 'display_l4gen.c', 'display_tasks.c',
	'display_irq.c', 'log.c', 'hash_utils.c', 'main.c', 'parse_utils.c',
	'file_utils.c', 'run.c', 'input_conn.c', 'input_curses.c', 'rx_pkt.c',
	'lconf.c', 'tx_pkt.c', 'expire_cpe.c', 'ip_subnet.c', 'stats_port.c',
	'stats_mempool.c', 'stats_ring.c', 'stats_l4gen.c', 'stats_latency.c',
	'stats_global.c', 'stats_core.c', 'stats_task.c', 'stats_prio.c',
	'stats_irq.c', 'cmd_parser.c', 'input.c', 'prox_shared.c',
	'prox_lua_types.c', 'genl4_bundle.c', 'heap.c', 'genl4_stream_tcp.c',
	'genl4_stream_udp.c', 'cdf.c', 'stats.c', 'stats_cons_log.c',
	'stats_cons_cli.c', 'stats_parser.c', 'hash_set.c', 'prox_lua.c',
	'prox_malloc.c', 'prox_ipv6.c', 'prox_compat.c', 'handle_nsh.c')

sources += files('rw_reg.c')

# Include a couple of source files depending on DPDK support
if cc.find_library('rte_pmd_aesni', required: false).found()
	sources += files('handle_esp.c')
else
	warning('Building w/o IPSEC support')
endif

if cc.find_library('rte_pipeline', required: false).found()
	sources += files('handle_pf_acl.c', 'thread_pipeline.c')
endif

# Generate the git_version.c file and add to sources
git_version = configuration_data()
git_version.set('GIT_VERSION', '@0@'.format(meson.project_version()))
git_version_c = configure_file(input: 'git_version.c.in',
	output: 'git_version.c',
	configuration: git_version)

git_version_file = join_paths(meson.current_build_dir(), 'git_version.c')
sources += files(git_version_file)

executable('prox',
	sources,
	c_args: cflags,
	dependencies: deps,
	install: true)
