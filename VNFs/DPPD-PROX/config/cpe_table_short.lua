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

t2={}
svlan_id=0
ip1=2^24*192 + 2^16*168 + 2^8*0 + 0;
for id1=0,3,1 do
  for cvlan_id=0,255,1 do
    mac_s=string.format("00:00:01:00:00:%02x", cvlan_id);
    table.insert(t2,{dest_id=id1, gre_id=0, svlan_id=svlan_id, cvlan_id=cvlan_id, cidr = {ip=ip(ip1),depth=29}, mac = mac(mac_s), user_id=cvlan_id});
    ip1=ip1+8
    table.insert(t2,{dest_id=id1, gre_id=0, svlan_id=svlan_id+1, cvlan_id=cvlan_id, cidr = {ip=ip(ip1),depth=29}, mac = mac(mac_s), user_id=cvlan_id});
    ip1=ip1+8
  end
  svlan_id=svlan_id+16
end

return t;

