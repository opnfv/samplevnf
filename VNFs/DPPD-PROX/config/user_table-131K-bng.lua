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

-- This script generates a user table containing 131072 users. It is
-- meant to be used in a BNG with 4 CPE facing ports. Each of the CPE
-- facing ports has 32768 users behind it. Each user has a unique
-- svlan/cvlan combination. The only difference between the two sets
-- of users is the svlan id. Note that any arbitrary configuration is
-- possible.

local user_table = {}

for i = 1,2^15 do
   idx = i - 1
   user_table[i] = {
      gre_id   = idx,
      -- svlan_id is 000000000XXXXXXX at the bit level
      -- cvlan_id is 0000XXXX00XX00XX at the bit level
      svlan_id = mask(idx, 0x7f00) / 2^8,
      cvlan_id = mask(idx, 0xf0) * 2^4 + mask(idx, 0xc) * 2^2 + mask(idx, 0x3),
      user_id  = idx,
   }
end

for i = 1,2^15 do
   idx = i - 1
   user_table[2^15 + i] = {
      gre_id   = 2^15 + idx,
      -- svlan_id is 000000001XXXXXXX at the bit level
      -- cvlan_id is 0000XXXX00XX00XX at the bit level
      svlan_id = mask(idx, 0x7f00) / 2^8 + 0x80,
      cvlan_id = mask(idx, 0xf0) * 2^4 + mask(idx, 0xc) * 2^2 + mask(idx, 0x3),
      user_id  = idx,
   }
end

for i = 1,2^15 do
   idx = i - 1
   user_table[2*2^15 + i] = {
      gre_id   = 2*2^15 + idx,
      -- svlan_id is 000000010XXXXXXX at the bit level
      -- cvlan_id is 0000XXXX00XX00XX at the bit level
      svlan_id = mask(idx, 0x7f00) / 2^8 + 0x100,
      cvlan_id = mask(idx, 0xf0) * 2^4 + mask(idx, 0xc) * 2^2 + mask(idx, 0x3),
      user_id  = idx,
   }
end

for i = 1,2^15 do
   idx = i - 1
   user_table[3*2^15 + i] = {
      gre_id   = 3*2^15 + idx,
      -- svlan_id is 000000011XXXXXXX at the bit level
      -- cvlan_id is 0000XXXX00XX00XX at the bit level
      svlan_id = mask(idx, 0x7f00) / 2^8 + 0x180,
      cvlan_id = mask(idx, 0xf0) * 2^4 + mask(idx, 0xc) * 2^2 + mask(idx, 0x3),
      user_id  = idx,
   }
end

return user_table
