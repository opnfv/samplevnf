/*
// Copyright (c) 2010-2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef _PROX_ARGS_H_
#define _PROX_ARGS_H_

#include "lconf.h"

struct rte_cfg {
	/* DPDK standard options */
	uint32_t memory;	 /* amount of asked memory */
	uint32_t force_nchannel; /* force number of channels */
	uint32_t force_nrank;	 /* force number of ranks */
	uint32_t no_hugetlbfs;	 /* true to disable hugetlbfs */
	uint32_t no_pci;	 /* true to disable PCI */
	uint32_t no_hpet;	 /* true to disable HPET */
	uint32_t no_shconf;	 /* true if there is no shared config */
	char    *hugedir;	 /* dir where hugetlbfs is mounted */
	char    *eal;            /* any additional eal option */
	uint32_t no_output;	 /* disable EAL debug output */
};

int prox_parse_args(int argc, char **argv);
int prox_read_config_file(void);
int prox_setup_rte(const char *prog_name);
const char *get_cfg_dir(void);

#endif /* _PROX_ARGS_H_ */
