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

dofile("bundle_maker.lua")

if (test_system_id == nil) then
   error("test_system_id not set")
end

offset = 8 * test_system_id

c_2s0, s_3s0   = setup_bundles(128 + offset, ss)
c_4s0, s_5s0   = setup_bundles(129 + offset, ss)
c_2s0h, s_3s0h = setup_bundles(130 + offset, ss)
c_4s0h, s_5s0h = setup_bundles(131 + offset, ss)

c_6s0, s_7s0   = setup_bundles(132 + offset, ss)
c_8s0, s_9s0   = setup_bundles(133 + offset, ss)
c_6s0h, s_7s0h = setup_bundles(134 + offset, ss)
c_8s0h, s_9s0h = setup_bundles(135 + offset, ss)

----------------

c_2s1, s_3s1   = setup_bundles(64 + offset, ss)
c_4s1, s_5s1   = setup_bundles(65 + offset, ss)
c_2s1h, s_3s1h = setup_bundles(66 + offset, ss)
c_4s1h, s_5s1h = setup_bundles(67 + offset, ss)

c_6s1, s_7s1   = setup_bundles(68 + offset, ss)
c_8s1, s_9s1   = setup_bundles(69 + offset, ss)
c_6s1h, s_7s1h = setup_bundles(70 + offset, ss)
c_8s1h, s_9s1h = setup_bundles(71 + offset, ss)

if (max_setup_rate == nil) then
   error("max_setup_rate not set")
end

if (connections == nil) then
   error("connections not set")
end

port_a_clients="2s0,4s0,2s0h,4s0h,6s0,8s0,6s0h,8s0h"
port_b_servers="3s0,5s0,3s0h,5s0h,7s0,9s0,7s0h,9s0h"


port_c_clients="2s1,4s1,2s1h,4s1h,6s1,8s1,6s1h,8s1h"
port_d_servers="3s1,5s1,3s1h,5s1h,7s1,9s1,7s1h,9s1h"

all_clients = port_a_clients
   .. "," .. port_c_clients

all_servers = port_b_servers
   .. "," .. port_d_servers

all_workers =  all_clients .. "," .. all_servers

all_ld = "1s0,1s0h,1s1,1s1h"

client_port_count = 2;

bps = 1250000000/task_count(port_a_clients)
msr = max_setup_rate/client_port_count/task_count(port_a_clients)
conn = connections/client_port_count/task_count(port_a_clients)

mempool_size = connections
if (mempool_size > 100000) then
   mempool_size = 100000
elseif (mempool_size < 2048) then
   mempool_size = 2048
end
