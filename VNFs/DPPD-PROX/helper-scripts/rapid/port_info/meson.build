##
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##         http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##

project('port-info', 'C',
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


cflags = [
        '-DPROGRAM_NAME="port_info_app"',
        '-fno-stack-protector',
        '-DGRE_TP',
        '-D_GNU_SOURCE']        # for PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP

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
libedit_dep = dependency('libedit', required: true)
math_dep = cc.find_library('m', required : false)
dl_dep = cc.find_library('dl', required : true)

deps = [dpdk_dep,
        tinfo_dep,
        threads_dep,
        pcap_dep,
        libedit_dep,
        math_dep,
        dl_dep]

# Explicitly add these to the dependency list
deps += [cc.find_library('rte_bus_pci', required: true)]
deps += [cc.find_library('rte_bus_vdev', required: true)]

if dpdk_version.version_compare('<20.11.0')
deps += [cc.find_library('rte_pmd_ring', required: true)]
else
deps += [cc.find_library('rte_net_ring', required: true)]
endif

sources = files(
        'port_info.c')

executable('port_info_app',
        sources,
        c_args: cflags,
        dependencies: deps,
        install: true)
