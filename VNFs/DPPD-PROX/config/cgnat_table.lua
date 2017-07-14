--
-- Copyright (c) 2010-2017 Intel Corporation
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

local cgnat = {}
cgnat.dynamic = {
   {public_ip_range_start = ip("20.0.1.0"),public_ip_range_stop = ip("20.0.1.15"), public_port = val_range(0,65535)},
   {public_ip_range_start = ip("20.0.1.16"),public_ip_range_stop = ip("20.0.1.31"), public_port = val_range(0,65535)},
}
cgnat.static_ip_port = {
   {src_ip = ip("192.168.2.1"), src_port = 68, dst_ip = ip("20.0.2.1"), dst_port = 68},
   {src_ip = ip("192.168.2.1"), src_port = 168, dst_ip = ip("20.0.2.1"), dst_port = 5000},
   {src_ip = ip("192.168.2.1"), src_port = 268, dst_ip = ip("20.0.2.1"), dst_port = 5001},
   {src_ip = ip("192.168.2.1"), src_port = 368, dst_ip = ip("20.0.2.1"), dst_port = 5002},
}
cgnat.static_ip = {
   {src_ip = ip("192.168.3.1"), dst_ip = ip("20.0.3.1")},
   {src_ip = ip("192.168.3.2"), dst_ip = ip("20.0.3.2")},
   {src_ip = ip("192.168.3.3"), dst_ip = ip("20.0.3.3")},
   {src_ip = ip("192.168.3.4"), dst_ip = ip("20.0.3.4")},
   {src_ip = ip("192.168.3.5"), dst_ip = ip("20.0.3.5")},
   {src_ip = ip("192.168.3.6"), dst_ip = ip("20.0.3.6")},
   {src_ip = ip("192.168.3.7"), dst_ip = ip("20.0.3.7")},
   {src_ip = ip("192.168.3.8"), dst_ip = ip("20.0.3.8")},
}
return cgnat
