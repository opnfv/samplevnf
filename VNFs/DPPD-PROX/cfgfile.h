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

#ifndef _CFG_FILE_H_
#define _CFG_FILE_H_

#include <stdio.h>
#include "defaults.h"

#define DEFAULT_CONFIG_FILE	"./prox.cfg"

/* configuration file line parser procedure */
typedef int (*cfg_parser)(unsigned sindex, char *str, void *data);

#define CFG_INDEXED	0x80000000	/* section contains index [name #] */
#define MAX_INDEX	64

struct cfg_section {
	const char	*name;	/* section name without [] */
	cfg_parser	parser;	/* section parser function */
	void		*data;	/* data to be passed to the parser */
	/* set by parsing procedure */
	unsigned	indexp[MAX_INDEX];
	int             raw_lines; /* if set, do not remove text after ';' */
	int		nbindex;
	int		error;
};

#define MAX_CFG_STRING_LEN (3 * MAX_PKT_SIZE)
#define STRING_TERMINATOR_LEN 4

struct cfg_file {
	char		*name;
	FILE		*pfile;
	unsigned	line;
	unsigned	index_line;
	/* set in case of any error */
	unsigned	err_line;
	char		*err_section;
	unsigned	err_entry;
	char		cur_line[MAX_CFG_STRING_LEN + STRING_TERMINATOR_LEN];
};

struct cfg_file *cfg_open(const char *cfg_name);
int cfg_parse(struct cfg_file *pcfg, struct cfg_section *psec);
int cfg_close(struct cfg_file *pcfg);

#endif /* _CFGFILE_H_ */
