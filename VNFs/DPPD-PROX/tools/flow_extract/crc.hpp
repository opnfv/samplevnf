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

#ifndef _CRC_H_
#define _CRC_H_

static uint32_t crc32(const uint8_t *buf, size_t len, int init)
{
	uint32_t ret = init;

	while (len/8) {
		ret = __builtin_ia32_crc32di(ret, *((uint64_t*)buf));
		len -= 8;
		buf += 8;
	}

	while (len/4) {
		ret = __builtin_ia32_crc32si(ret, *((uint32_t*)buf));
		len -= 4;
		buf += 4;
	}

	while (len/2) {
		ret = __builtin_ia32_crc32hi(ret, *((uint16_t*)buf));
		len -= 2;
		buf += 2;
	}

	while (len) {
		ret = __builtin_ia32_crc32qi(ret, *((uint8_t*)buf));
		len -= 1;
		buf += 1;
	}

	return ret;
}

#endif /* _CRC_H_ */
