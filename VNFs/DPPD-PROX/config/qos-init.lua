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

-- This script assumes the following arguments/global values are assigned:
-- port_id             DPDK port device number
-- leaf_queue_num      Number of leaf nodes/ingress queues
-- leafs_per_sp        Number of leaf nodes/ingress queues per level 2 SP schedulers
-- shaper_bytes_per_s  Shaper bytes/s peak rate on each of the SP schedulers,
--                     if 0 shaper is disabled
-- fail_on_api_errors  True to fail on errors, false to continue

local tm = require "tmapi"

-- We always fail on capability errors
fail_on_cap_errors = 1

printf = function(s,...)
           return io.write(s:format(...))
         end

printf("=== Starting Lua TM basic init (port %u) ===\n", port_id)
if not fail_on_api_errors then
  printf("** fail_on_api_errors DISABLED!\n")
end

ret,first_nonleaf_node_id = rte_tm_get_number_of_leaf_nodes(port_id)
if ret ~= 0 then
  printf("rte_tm_level_capabilities_get() failed, err=%d\n", ret)
  if fail_on_api_errors then
    os.exit(ret)
  end
end

-- Number of nodes on level 1 - the SP nodes
N1 = leaf_queue_num/leafs_per_sp  -- Nonleafs on level 1
root_node_id = first_nonleaf_node_id+N1

if shaper_bytes_per_s == 0 then
  printf("Configuring hierarchical scheduler using: queues=%u, SP schedulers=%u, shaper disabled\n",
    leaf_queue_num, N1);
else
  printf("Configuring hierarchical scheduler using: queues=%u, SP schedulers=%u, bw=%uBps\n",
    leaf_queue_num, N1, shaper_bytes_per_s)
end

-- ----------------------------------------------------
-- Check that configuration is supported
-- ----------------------------------------------------
ret,caps = rte_tm_capabilities_get(port_id)
if ret ~= 0 then
  printf("rte_tm_capabilities_get() failed, err=%d\n", ret)
  if fail_on_api_errors then
    os.exit(ret)
  end
end
if caps["n_levels_max"] < 3 or
  caps["n_nodes_max"] < (1+N1+leaf_queue_num) then
  printf("*** Capability error, configuration not supported %u %u %u\n", caps["n_nodes_max"], N1, leaf_queue_num)
  if fail_on_cap_errors then
    os.exit(ret)
  end
end
-- Level capabilities, level 0 is root
lvlcaps = {}
for lvl = 0,2 do
  ret,level_caps = rte_tm_level_capabilities_get(port_id, lvl)
  if ret ~= 0 then
    printf("rte_tm_level_capabilities_get() failed, err=%d\n", ret)
    if fail_on_api_errors then
      os.exit(ret)
    end
  end
  lvlcaps[lvl] = level_caps
end
if lvlcaps[0]["n_nodes_max"] < 1 or
  lvlcaps[1]["n_nodes_max"] < N1 or
  lvlcaps[2]["n_nodes_max"] < leaf_queue_num then
  printf("*** Capability error - too many nodes requested\n")
  if fail_on_cap_errors then
    os.exit(ret)
  end
end

-- ----------------------------------------------------
-- Weighted RED profile for leaf nodes (ingress queues)
--   Not supported
-- ----------------------------------------------------

-- red_profile = {
--   red_params = {
--     green = {
--       min_th = 20,
--       max_th = 40,
--       maxp_inv = 10,
--       wq_log2 = 4
--     },
--     yellow = {
--       min_th = 20,
--       max_th = 40,
--       maxp_inv = 10,
--       wq_log2 = 4
--     },
--     red = {
--       min_th = 20,
--       max_th = 40,
--       maxp_inv = 10,
--       wq_log2 = 4
--     }
--   }
-- }

-- ret = rte_tm_wred_profile_add(port_id, wred_profile_id, red_profile)
-- printf("Expect not supported\n");
-- if ret ~= 0 then
--   printf("rte_tm_wred_profile_add() failed, err=%d\n", ret)
-- end

-- ----------------------------------------------------
-- Shaper profile for nonleaf nodes
-- ----------------------------------------------------
root_shaper_profile_id = 1000000
root_shaper_profile = {
  committed = {
    rate = 0,
    size = 0
  },
  peak = {
    rate = 5000000000,
    size = 0
  },
  pkt_length_adjust = 24
}

if shaper_bytes_per_s == 0 then
  nonleaf_shaper_profile_id = tm.RTE_TM_SHAPER_PROFILE_ID_NONE
else
  nonleaf_shaper_profile_id = 0
  shaper_profile = {
    committed = {
      rate = 0,
      size = 0
    },
    peak = {
      rate = shaper_bytes_per_s,
      size = 0
    },
    pkt_length_adjust = 24
  }
end

ret = rte_tm_shaper_profile_add(port_id, root_shaper_profile_id, root_shaper_profile)
if ret ~= 0 then
  printf("rte_tm_shaper_profile_add() failed, err=%d\n", ret)
  if fail_on_api_errors then
    os.exit(ret)
  end
end

if nonleaf_shaper_profile_id ~= tm.RTE_TM_SHAPER_PROFILE_ID_NONE then
  ret = rte_tm_shaper_profile_add(port_id, nonleaf_shaper_profile_id, shaper_profile)
  if ret ~= 0 then
    printf("rte_tm_shaper_profile_add() failed, err=%d\n", ret)
    if fail_on_api_errors then
      os.exit(ret)
    end
  end
end

-- ----------------------------------------------------
-- Node parameters (root_node_params is root)
-- ----------------------------------------------------
root_node_params = {
    shaper_profile_id = root_shaper_profile_id,
    shared_shaper_id = {},
    nonleaf = {
        wfq_weight_mode = {}
    },
    stats_mask = 0
}

nonleaf_node_params = {
    shaper_profile_id = nonleaf_shaper_profile_id,
    shared_shaper_id = {},
    nonleaf = {
        wfq_weight_mode = {}
    },
    stats_mask = 0
}

leaf_node_params = {
    shaper_profile_id = tm.RTE_TM_SHAPER_PROFILE_ID_NONE,
    shared_shaper_id = {},
    leaf = {
        cman = tm.RTE_TM_CMAN_TAIL_DROP,
        wred = {
            wred_profile_id = tm.RTE_TM_WRED_PROFILE_ID_NONE,
            shared_wred_context_id = {},
        }
    },
    stats_mask = 0
}

-- ----------------------------------------------------
-- Root node, level 0
-- ----------------------------------------------------
ret = rte_tm_node_add(port_id, root_node_id, tm.RTE_TM_NODE_ID_NULL, 0, 0, root_node_params)
if ret ~= 0 then
  printf("rte_tm_node_add(node_id=%u) failed, level=0, err=%d\n", root_node_id, ret)
  if fail_on_api_errors then
    os.exit(ret)
  end
end

-- ----------------------------------------------------
-- WRR nodes - level 1
-- ----------------------------------------------------
for l1_id = 0,N1-1 do
  node_id = first_nonleaf_node_id+l1_id
  ret = rte_tm_node_add(port_id, node_id, root_node_id, 0, 1, nonleaf_node_params)
  if ret ~= 0 then
    printf("rte_tm_node_add(node_id=%u) failed, level=1, err=%d\n", node_id, ret)
    if fail_on_api_errors then
      os.exit(ret)
    end
  end

  -- ----------------------------------------------------
  -- SP nodes - level 2
  -- ----------------------------------------------------
  for leaf_id = 0,leafs_per_sp-1 do
    leaf_node_id = l1_id*leafs_per_sp+leaf_id
    -- leaf_id used as priority, API have zero as highest priority
    priority = leaf_id
    ret = rte_tm_node_add(port_id, leaf_node_id, node_id, priority, 1, leaf_node_params)
    if ret ~= 0 then
      printf("rte_tm_node_add(node_id=%u) failed, level=2, err=%d\n", leaf_node_id, ret)
      if fail_on_api_errors then
        os.exit(ret)
      end
    end
  end
end


ret = rte_tm_hierarchy_commit(port_id, 0)
if ret ~= 0 then
  printf("ipsg_tm_hierarchy_commit failed, err=%d\n", ret)
  if fail_on_api_errors then
    os.exit(ret)
  end
end

printf("=== End Lua TM basic init ===\n")
