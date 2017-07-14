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

lpm6 = {}
lpm6.next_hops6 = {
   {id = 0,  port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0000"), mac = mac("fe:80:00:00:00:00"), mpls = 4660},
   {id = 1,  port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0001"), mac = mac("fe:80:00:00:00:00"), mpls = 4661},
   {id = 2,  port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0002"), mac = mac("fe:80:00:00:00:00"), mpls = 4662},
   {id = 3,  port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0003"), mac = mac("fe:80:00:00:00:00"), mpls = 4663},
   {id = 4,  port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0004"), mac = mac("fe:80:00:00:00:00"), mpls = 4664},
   {id = 5,  port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0005"), mac = mac("fe:80:00:00:00:00"), mpls = 4665},
   {id = 6,  port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0006"), mac = mac("fe:80:00:00:00:00"), mpls = 4666},
   {id = 7,  port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0007"), mac = mac("fe:80:00:00:00:00"), mpls = 4667},
   {id = 8,  port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0008"), mac = mac("fe:80:00:00:00:00"), mpls = 4668},
   {id = 9,  port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0009"), mac = mac("fe:80:00:00:00:00"), mpls = 4669},
   {id = 10, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:000a"), mac = mac("fe:80:00:00:00:00"), mpls = 4670},
   {id = 11, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:000b"), mac = mac("fe:80:00:00:00:00"), mpls = 4671},
   {id = 12, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:000c"), mac = mac("fe:80:00:00:00:00"), mpls = 4672},
   {id = 13, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:000d"), mac = mac("fe:80:00:00:00:00"), mpls = 4673},
   {id = 14, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:000e"), mac = mac("fe:80:00:00:00:00"), mpls = 4674},
   {id = 15, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:000f"), mac = mac("fe:80:00:00:00:00"), mpls = 4675},
   {id = 16, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0010"), mac = mac("fe:80:00:00:00:00"), mpls = 4676},
   {id = 17, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0011"), mac = mac("fe:80:00:00:00:00"), mpls = 4677},
   {id = 18, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0012"), mac = mac("fe:80:00:00:00:00"), mpls = 4678},
   {id = 19, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0013"), mac = mac("fe:80:00:00:00:00"), mpls = 4679},
   {id = 20, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0014"), mac = mac("fe:80:00:00:00:00"), mpls = 4680},
   {id = 21, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0015"), mac = mac("fe:80:00:00:00:00"), mpls = 4681},
   {id = 22, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0016"), mac = mac("fe:80:00:00:00:00"), mpls = 4682},
   {id = 23, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0017"), mac = mac("fe:80:00:00:00:00"), mpls = 4683},
   {id = 24, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0018"), mac = mac("fe:80:00:00:00:00"), mpls = 4684},
   {id = 25, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0019"), mac = mac("fe:80:00:00:00:00"), mpls = 4685},
   {id = 26, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:001a"), mac = mac("fe:80:00:00:00:00"), mpls = 4686},
   {id = 27, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:001b"), mac = mac("fe:80:00:00:00:00"), mpls = 4687},
   {id = 28, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:001c"), mac = mac("fe:80:00:00:00:00"), mpls = 4688},
   {id = 29, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:001d"), mac = mac("fe:80:00:00:00:00"), mpls = 4689},
   {id = 30, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:001e"), mac = mac("fe:80:00:00:00:00"), mpls = 4690},
   {id = 31, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:001f"), mac = mac("fe:80:00:00:00:00"), mpls = 4691},
   {id = 32, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0020"), mac = mac("fe:80:00:00:00:00"), mpls = 4692},
   {id = 33, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0021"), mac = mac("fe:80:00:00:00:00"), mpls = 4693},
   {id = 34, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0022"), mac = mac("fe:80:00:00:00:00"), mpls = 4694},
   {id = 35, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0023"), mac = mac("fe:80:00:00:00:00"), mpls = 4695},
   {id = 36, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0024"), mac = mac("fe:80:00:00:00:00"), mpls = 4696},
   {id = 37, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0025"), mac = mac("fe:80:00:00:00:00"), mpls = 4697},
   {id = 38, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0026"), mac = mac("fe:80:00:00:00:00"), mpls = 4698},
   {id = 39, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0027"), mac = mac("fe:80:00:00:00:00"), mpls = 4699},
   {id = 40, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0028"), mac = mac("fe:80:00:00:00:00"), mpls = 4700},
   {id = 41, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0029"), mac = mac("fe:80:00:00:00:00"), mpls = 4701},
   {id = 42, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:002a"), mac = mac("fe:80:00:00:00:00"), mpls = 4702},
   {id = 43, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:002b"), mac = mac("fe:80:00:00:00:00"), mpls = 4703},
   {id = 44, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:002c"), mac = mac("fe:80:00:00:00:00"), mpls = 4704},
   {id = 45, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:002d"), mac = mac("fe:80:00:00:00:00"), mpls = 4705},
   {id = 46, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:002e"), mac = mac("fe:80:00:00:00:00"), mpls = 4706},
   {id = 47, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:002f"), mac = mac("fe:80:00:00:00:00"), mpls = 4707},
   {id = 48, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0030"), mac = mac("fe:80:00:00:00:00"), mpls = 4708},
   {id = 49, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0031"), mac = mac("fe:80:00:00:00:00"), mpls = 4709},
   {id = 50, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0032"), mac = mac("fe:80:00:00:00:00"), mpls = 4710},
   {id = 51, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0033"), mac = mac("fe:80:00:00:00:00"), mpls = 4711},
   {id = 52, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0034"), mac = mac("fe:80:00:00:00:00"), mpls = 4712},
   {id = 53, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0035"), mac = mac("fe:80:00:00:00:00"), mpls = 4713},
   {id = 54, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0036"), mac = mac("fe:80:00:00:00:00"), mpls = 4714},
   {id = 55, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0037"), mac = mac("fe:80:00:00:00:00"), mpls = 4715},
   {id = 56, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0038"), mac = mac("fe:80:00:00:00:00"), mpls = 4716},
   {id = 57, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0039"), mac = mac("fe:80:00:00:00:00"), mpls = 4717},
   {id = 58, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:003a"), mac = mac("fe:80:00:00:00:00"), mpls = 4718},
   {id = 59, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:003b"), mac = mac("fe:80:00:00:00:00"), mpls = 4719},
   {id = 60, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:003c"), mac = mac("fe:80:00:00:00:00"), mpls = 4720},
   {id = 61, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:003d"), mac = mac("fe:80:00:00:00:00"), mpls = 4721},
   {id = 62, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:003e"), mac = mac("fe:80:00:00:00:00"), mpls = 4722},
   {id = 63, port_id = 0, ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:003f"), mac = mac("fe:80:00:00:00:00"), mpls = 4723},
}

lpm6.routes6 = {}

-- add 1K routes with depth /128
for i = 1,2^10 do
   lpm6.routes6[i] = {
      cidr6 = cidr6("fe80:0000:0000:0000:0200:00ff:fe00:".. string.format("%04x", i - 1) .."/128"),
      next_hop_id = (i - 1) % 64,
   }
end

-- add 1K routes with depth /64
for i = 1,2^10 do
   lpm6.routes6[i + 2^10] = {
      cidr6 = cidr6("fe80:0000:0000:" .. string.format("%04x", i - 1) .. ":0200:00ff:fe00:03e7/64"),
      next_hop_id = (i - 1) % 64,
   }
end

-- -- add fallback routes
lpm6.routes6[2^11] = {
   cidr6 = cidr6("fe80:0000:0000:03e7:0200:00ff:fe00:03e7/1"),
   next_hop_id = 0,
}
lpm6.routes6[2^11 + 1] = {
   cidr6 = cidr6("7e80:0000:0000:03e7:0200:00ff:fe00:03e7/1"),
   next_hop_id = 0,
}
