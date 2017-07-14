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

seven_tuple = function(svlan, cvlan, ip_proto, src, dst, sport, dport, action)
   return {
      svlan_id = svlan,
      cvlan_id = cvlan,
      ip_proto = ip_proto,
      src_cidr = src,
      dst_cidr = dst,
      sport    = sport,
      dport    = dport,
      action   = action,
   }
end

return {
   seven_tuple(val_mask(0, 0x0000), val_mask(0, 0x0000), val_mask(17, 0xff), cidr("192.168.0.0/18"), cidr("10.0.0.0/7"), val_range(0,65535), val_range(0,65535), "allow"),
   seven_tuple(val_mask(0, 0x0000), val_mask(0, 0x0000), val_mask(17, 0xff), cidr("192.168.0.0/18"), cidr("74.0.0.0/7"), val_range(0,65535), val_range(0,65535), "allow"),
}
