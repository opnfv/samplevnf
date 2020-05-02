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

local lpm4 = {}
lpm4.next_hops = {
   {id = 0,  port_id = 0, ip = ip("192.168.122.240")},
   {id = 1,  port_id = 0, ip = ip("192.168.122.246")},
   {id = 2,  port_id = 0, ip = ip("192.168.122.247")}
}

lpm4.routes = {
   {cidr = {ip = ip("192.168.123.0"), depth = 24}, next_hop_id = 0},
   {cidr = {ip = ip("192.168.124.0"), depth = 24}, next_hop_id = 1},
   {cidr = {ip = ip("192.168.125.0"), depth = 24}, next_hop_id = 2},
}
return lpm4
