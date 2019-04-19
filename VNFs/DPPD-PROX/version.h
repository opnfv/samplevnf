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

#ifndef _VERSION_H_
#define _VERSION_H_

/* PROGRAM_NAME defined through Makefile */
#define VERSION_MAJOR 0      // Pre-production
#define VERSION_MINOR 1904   // 19.04 i.e. April 2019
#define VERSION_REV   0

static inline char *VERSION_STR(void)
{
	static char version_buffer[32];
	snprintf(version_buffer, sizeof(version_buffer), "%02d.%02d", VERSION_MINOR / 100, VERSION_MINOR % 100);
#if VERSION_REV > 0
	snprintf(version_buffer + strlen(version_buffer), sizeof(version_buffer) - strlen(version_buffer), ".%02d", VERSION_REV);
#endif
	return version_buffer;
#endif /* _VERSION_H_ */
}
