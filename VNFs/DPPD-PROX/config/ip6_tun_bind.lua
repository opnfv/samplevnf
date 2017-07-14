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

-- Bindings for lwaftr: lwB4 IPv6 address, next hop MAC address
-- towards lwB4, IPv4 Public address, IPv4 Public Port Set

return {
   {ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0000"), mac = mac("fe:80:00:00:00:00"), ip = ip("171.205.239.1"), port = 4608},
   {ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0001"), mac = mac("fe:80:00:00:00:00"), ip = ip("171.205.239.1"), port = 4672},
   {ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0002"), mac = mac("fe:80:00:00:00:00"), ip = ip("171.205.239.1"), port = 4736},
   {ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0003"), mac = mac("fe:80:00:00:00:00"), ip = ip("171.205.239.1"), port = 4800},
}
