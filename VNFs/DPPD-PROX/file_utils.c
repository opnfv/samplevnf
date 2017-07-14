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

#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "prox_args.h"
#include "file_utils.h"

static char file_error_string[128] = {0};

const char *file_get_error(void)
{
	return file_error_string;
}

__attribute__((format(printf, 1 ,2))) static void file_set_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(file_error_string, sizeof(file_error_string), fmt, ap);
	va_end(ap);
}

static void resolve_path_cfg_dir(char *file_name, size_t len, const char *path)
{
	if (path[0] != '/')
		snprintf(file_name, len, "%s/%s", get_cfg_dir(), path);
	else
		strncpy(file_name, path, len);
}

long file_get_size(const char *path)
{
	char file_name[PATH_MAX];
	struct stat s;

	resolve_path_cfg_dir(file_name, sizeof(file_name), path);

	if (stat(file_name, &s)) {
		file_set_error("Stat failed on '%s': %s", path, strerror(errno));
		return -1;
	}

	if ((s.st_mode & S_IFMT) != S_IFREG) {
		snprintf(file_error_string, sizeof(file_error_string), "'%s' is not a file", path);
		return -1;
	}

	return s.st_size;
}

int file_read_content(const char *path, uint8_t *mem, size_t beg, size_t len)
{
	char file_name[PATH_MAX];
	FILE *f;

	resolve_path_cfg_dir(file_name, sizeof(file_name), path);
	f = fopen(file_name, "r");
	if (!f) {
		file_set_error("Failed to read '%s': %s", path, strerror(errno));
		return -1;
	}

	fseek(f, beg, SEEK_SET);

	size_t ret = fread(mem, 1, len, f);
	if ((uint32_t)ret !=  len) {
		file_set_error("Failed to read '%s:%zu' for %zu bytes: got %zu\n", file_name, beg, len, ret);
		return -1;
	}

	fclose(f);
	return 0;
}
