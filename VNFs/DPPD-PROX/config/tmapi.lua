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

-- Ethernet device TM API Lua module

local tm = {}

tm.RTE_TM_ETH_FRAMING_OVERHEAD     = 20
tm.RTE_TM_ETH_FRAMING_OVERHEAD_FCS = 24
tm.RTE_TM_WRED_PROFILE_ID_NONE     = 0xffffffff
tm.RTE_TM_SHAPER_PROFILE_ID_NONE   = 0xffffffff
tm.RTE_TM_NODE_ID_NULL             = 0xffffffff

tm.RTE_TM_GREEN         = 0
tm.RTE_TM_YELLOW        = 1
tm.RTE_TM_RED           = 2
tm.RTE_TM_COLORS        = 3

tm.RTE_TM_STATS_N_PKTS                 = 1
tm.RTE_TM_STATS_N_BYTES                = 2
tm.RTE_TM_STATS_N_PKTS_GREEN_DROPPED   = 4
tm.RTE_TM_STATS_N_PKTS_YELLOW_DROPPED  = 8
tm.RTE_TM_STATS_N_PKTS_RED_DROPPED     = 16
tm.RTE_TM_STATS_N_BYTES_GREEN_DROPPED  = 32
tm.RTE_TM_STATS_N_BYTES_YELLOW_DROPPED = 64
tm.RTE_TM_STATS_N_BYTES_RED_DROPPED    = 128
tm.RTE_TM_STATS_N_PKTS_QUEUED          = 256
tm.RTE_TM_STATS_N_BYTES_QUEUED         = 512

tm.RTE_TM_UPDATE_NODE_PARENT_KEEP_LEVEL   = 1
tm.RTE_TM_UPDATE_NODE_PARENT_CHANGE_LEVEL = 2
tm.RTE_TM_UPDATE_NODE_ADD_DELETE          = 4
tm.RTE_TM_UPDATE_NODE_SUSPEND_RESUME      = 8
tm.RTE_TM_UPDATE_NODE_WFQ_WEIGHT_MODE     = 16
tm.RTE_TM_UPDATE_NODE_N_SP_PRIORITIES     = 32
tm.RTE_TM_UPDATE_NODE_CMAN                = 64
tm.RTE_TM_UPDATE_NODE_STATS               = 128

tm.RTE_TM_CMAN_TAIL_DROP = 0
tm.RTE_TM_CMAN_HEAD_DROP = 1
tm.RTE_TM_CMAN_WRED      = 2

tm.RTE_TM_ERROR_TYPE_NONE = 0
tm.RTE_TM_ERROR_TYPE_UNSPECIFIED = 1
tm.RTE_TM_ERROR_TYPE_CAPABILITIES = 2
tm.RTE_TM_ERROR_TYPE_LEVEL_ID = 3
tm.RTE_TM_ERROR_TYPE_WRED_PROFILE = 4
tm.RTE_TM_ERROR_TYPE_WRED_PROFILE_GREEN = 5
tm.RTE_TM_ERROR_TYPE_WRED_PROFILE_YELLOW = 6
tm.RTE_TM_ERROR_TYPE_WRED_PROFILE_RED = 7
tm.RTE_TM_ERROR_TYPE_WRED_PROFILE_ID = 8
tm.RTE_TM_ERROR_TYPE_SHARED_WRED_CONTEXT_ID = 9
tm.RTE_TM_ERROR_TYPE_SHAPER_PROFILE = 10
tm.RTE_TM_ERROR_TYPE_SHAPER_PROFILE_COMMITTED_RATE = 11
tm.RTE_TM_ERROR_TYPE_SHAPER_PROFILE_COMMITTED_SIZE = 12
tm.RTE_TM_ERROR_TYPE_SHAPER_PROFILE_PEAK_RATE = 13
tm.RTE_TM_ERROR_TYPE_SHAPER_PROFILE_PEAK_SIZE = 14
tm.RTE_TM_ERROR_TYPE_SHAPER_PROFILE_PKT_ADJUST_LEN = 15
tm.RTE_TM_ERROR_TYPE_SHAPER_PROFILE_ID = 16
tm.RTE_TM_ERROR_TYPE_SHARED_SHAPER_ID = 17
tm.RTE_TM_ERROR_TYPE_NODE_PARENT_NODE_ID = 18
tm.RTE_TM_ERROR_TYPE_NODE_PRIORITY = 19
tm.RTE_TM_ERROR_TYPE_NODE_WEIGHT = 20
tm.RTE_TM_ERROR_TYPE_NODE_PARAMS = 21
tm.RTE_TM_ERROR_TYPE_NODE_PARAMS_SHAPER_PROFILE_ID = 22
tm.RTE_TM_ERROR_TYPE_NODE_PARAMS_SHARED_SHAPER_ID = 23
tm.RTE_TM_ERROR_TYPE_NODE_PARAMS_N_SHARED_SHAPERS = 24
tm.RTE_TM_ERROR_TYPE_NODE_PARAMS_WFQ_WEIGHT_MODE = 25
tm.RTE_TM_ERROR_TYPE_NODE_PARAMS_N_SP_PRIORITIES = 26
tm.RTE_TM_ERROR_TYPE_NODE_PARAMS_CMAN = 27
tm.RTE_TM_ERROR_TYPE_NODE_PARAMS_WRED_PROFILE_ID = 28
tm.RTE_TM_ERROR_TYPE_NODE_PARAMS_SHARED_WRED_CONTEXT_ID = 29
tm.RTE_TM_ERROR_TYPE_NODE_PARAMS_N_SHARED_WRED_CONTEXTS = 30
tm.RTE_TM_ERROR_TYPE_NODE_PARAMS_STATS = 31
tm.RTE_TM_ERROR_TYPE_NODE_ID = 32

-- ----------------------
-- Helper functions below
-- ----------------------

printf = function(s,...)
           return io.write(s:format(...))
         end

-- Print device TM capabilities
-- caps:  Capability table as returned from  rte_tm_capabilities_get
--
function tm.print_caps(caps)
  printf("Capabilities:\n")
  printf("  n_nodes_max=%u\n", caps["n_nodes_max"])
  printf("  n_levels_max=%u\n", caps["n_levels_max"])
  printf("  non_leaf_nodes_identical=%u\n", caps["non_leaf_nodes_identical"])
  printf("  leaf_nodes_identical=%u\n", caps["leaf_nodes_identical"])
  printf("  shaper_n_max=%u\n", caps["shaper_n_max"])
  printf("  shaper_private_n_max=%u\n", caps["shaper_private_n_max"])
  printf("  shaper_private_dual_rate_n_max=%u\n", caps["shaper_private_dual_rate_n_max"])
  printf("  shaper_private_rate_min=%u\n", caps["shaper_private_rate_min"])
  printf("  shaper_private_rate_max=%u\n", caps["shaper_private_rate_max"])
  printf("  shaper_shared_n_max=%u\n", caps["shaper_shared_n_max"])
  printf("  shaper_shared_n_nodes_per_shaper_max=%u\n", caps["shaper_shared_n_nodes_per_shaper_max"])
  printf("  shaper_shared_n_shapers_per_node_max=%u\n", caps["shaper_shared_n_shapers_per_node_max"])
  printf("  shaper_shared_dual_rate_n_max=%u\n", caps["shaper_shared_dual_rate_n_max"])
  printf("  shaper_shared_rate_min=%u\n", caps["shaper_shared_rate_min"])
  printf("  shaper_shared_rate_max=%u\n", caps["shaper_shared_rate_max"])
  printf("  shaper_pkt_length_adjust_min=%i\n", caps["shaper_pkt_length_adjust_min"])
  printf("  shaper_pkt_length_adjust_max=%u\n", caps["shaper_pkt_length_adjust_max"])
  printf("  sched_n_children_max=%u\n", caps["sched_n_children_max"])
  printf("  sched_sp_n_priorities_max=%u\n", caps["sched_sp_n_priorities_max"])
  printf("  sched_wfq_n_children_per_group_max=%u\n", caps["sched_wfq_n_children_per_group_max"])
  printf("  sched_wfq_n_groups_max=%u\n", caps["sched_wfq_n_groups_max"])
  printf("  sched_wfq_weight_max=%u\n", caps["sched_wfq_weight_max"])
  printf("  cman_head_drop_supported=%u\n", caps["cman_head_drop_supported"])
  printf("  cman_wred_context_n_max=%u\n", caps["cman_wred_context_n_max"])
  printf("  cman_wred_context_private_n_max=%u\n", caps["cman_wred_context_private_n_max"])
  printf("  cman_wred_context_shared_n_max=%u\n", caps["cman_wred_context_shared_n_max"])
  printf("  cman_wred_context_shared_n_nodes_per_context_max=%u\n", caps["cman_wred_context_shared_n_nodes_per_context_max"])
  printf("  cman_wred_context_shared_n_contexts_per_node_max=%u\n", caps["cman_wred_context_shared_n_contexts_per_node_max"])
  for col = 1,tm.RTE_TM_COLORS do
    printf("  Color %u:\n", col-1);
    printf("    mark_vlan_dei_supported=%u\n", caps["mark_vlan_dei_supported"][col])
    printf("    mark_ip_ecn_tcp_supported=%u\n", caps["mark_ip_ecn_tcp_supported"][col])
    printf("    mark_ip_ecn_sctp_supported=%u\n", caps["mark_ip_ecn_sctp_supported"][col])
    printf("    mark_ip_dscp_supported=%u\n", caps["mark_ip_dscp_supported"][col])
  end
  printf("  dynamic_update_mask=%u\n", caps["dynamic_update_mask"])
  printf("  stats_mask=%u\n", caps["stats_mask"])
end

-- Print TM level capabilities
-- caps: Capability table as returned from  rte_tm_level_capabilities_get
-- lvl:  Level
function tm.print_level_caps(caps, lvl)
  printf("Level capabilities (level %u):\n", lvl)
  printf("  n_nodes_max=%u\n", caps["n_nodes_max"])
  printf("  n_nodes_nonleaf_max=%u\n", caps["n_nodes_nonleaf_max"])
  printf("  n_nodes_leaf_max=%u\n", caps["n_nodes_leaf_max"])
  printf("  non_leaf_nodes_identical=%u\n", caps["non_leaf_nodes_identical"])
  printf("  leaf_nodes_identical=%u\n", caps["leaf_nodes_identical"])
  if type(caps["nonleaf"]) ~= "nil" then
    printf("  nonleaf.shaper_private_supported=%u\n", caps["nonleaf"]["shaper_private_supported"])
    printf("  nonleaf.shaper_private_dual_rate_supported=%u\n", caps["nonleaf"]["shaper_private_dual_rate_supported"])
    printf("  nonleaf.shaper_private_rate_min=%u\n", caps["nonleaf"]["shaper_private_rate_min"])
    printf("  nonleaf.shaper_private_rate_max=%u\n", caps["nonleaf"]["shaper_private_rate_max"])
    printf("  nonleaf.shaper_shared_n_max=%u\n", caps["nonleaf"]["shaper_shared_n_max"])
    printf("  nonleaf.sched_n_children_max=%u\n", caps["nonleaf"]["sched_n_children_max"])
    printf("  nonleaf.sched_sp_n_priorities_max=%u\n", caps["nonleaf"]["sched_sp_n_priorities_max"])
    printf("  nonleaf.sched_wfq_n_children_per_group_max=%u\n", caps["nonleaf"]["sched_wfq_n_children_per_group_max"])
    printf("  nonleaf.sched_wfq_n_groups_max=%u\n", caps["nonleaf"]["sched_wfq_n_groups_max"])
    printf("  nonleaf.sched_wfq_weight_max=%u\n", caps["nonleaf"]["sched_wfq_weight_max"])
    printf("  nonleaf.stats_mask=%u\n", caps["nonleaf"]["stats_mask"])
  end
  if type(caps["leaf"]) ~= "nil" then
    printf("  leaf.shaper_private_supported=%u\n", caps["leaf"]["shaper_private_supported"])
    printf("  leaf.shaper_private_dual_rate_supported=%u\n", caps["leaf"]["shaper_private_dual_rate_supported"])
    printf("  leaf.shaper_private_rate_min=%u\n", caps["leaf"]["shaper_private_rate_min"])
    printf("  leaf.shaper_private_rate_max=%u\n", caps["leaf"]["shaper_private_rate_max"])
    printf("  leaf.shaper_shared_n_max=%u\n", caps["leaf"]["shaper_shared_n_max"])
    printf("  leaf.cman_head_drop_supported=%u\n", caps["leaf"]["cman_head_drop_supported"])
    printf("  leaf.cman_wred_context_private_supported=%u\n", caps["leaf"]["cman_wred_context_private_supported"])
    printf("  leaf.cman_wred_context_shared_n_max=%u\n", caps["leaf"]["cman_wred_context_shared_n_max"])
    printf("  leaf.stats_mask=%u\n", caps["leaf"]["stats_mask"])
  end
end

-- Print TM node capabilities
-- caps: Capability table as returned from  rte_tm_node_capabilities_get
-- node_id:  id
function tm.print_node_caps(caps, node_id)
  printf("Node capabilities (node_id %u, %s):\n", node_id, type(caps["leaf"]) ~= "nil" and "leaf" or "nonleaf")
  printf("  shaper_private_supported=%u\n", caps["shaper_private_supported"])
  printf("  shaper_private_dual_rate_supported=%u\n", caps["shaper_private_dual_rate_supported"]);
  printf("  shaper_private_rate_min=%u\n", caps["shaper_private_rate_min"]);
  printf("  shaper_private_rate_max=%u\n", caps["shaper_private_rate_max"]);
  printf("  shaper_shared_n_max=%u\n", caps["shaper_shared_n_max"]);
  printf("  stats_mask=%u\n", caps["stats_mask"]);
  if type(caps["leaf"]) ~= "nil" then
    printf("  cman_head_drop_supported=%u\n", caps["leaf"]["cman_head_drop_supported"]);
    printf("  cman_wred_context_private_supported=%u\n", caps["leaf"]["cman_wred_context_private_supported"]);
    printf("  cman_wred_context_shared_n_max=%u\n", caps["leaf"]["cman_wred_context_shared_n_max"]);
  end
  if type(caps["nonleaf"]) ~= "nil" then
    printf("  sched_n_children_max=%u\n", caps["nonleaf"]["sched_n_children_max"]);
    printf("  sched_sp_n_priorities_max=%u\n", caps["nonleaf"]["sched_sp_n_priorities_max"]);
    printf("  sched_wfq_n_children_per_group_max=%u\n", caps["nonleaf"]["sched_wfq_n_children_per_group_max"]);
    printf("  sched_wfq_n_groups_max=%u\n", caps["nonleaf"]["sched_wfq_n_groups_max"]);
    printf("  sched_wfq_weight_max=%u\n", caps["nonleaf"]["sched_wfq_weight_max"]);
  end
end

-- Print node statsistics
-- stats: Node statistics as returned from rte_tm_node_stats_read
function tm.print_node_stats(stats)
  printf("Node statistics:\n")
  printf("  n_pkts=%u\n", stats["n_pkts"])
  printf("  n_bytes=%u\n", stats["n_bytes"])
  for col = 1,tm.RTE_TM_COLORS do
    printf("  Color %u:\n", col-1);
    printf("  leaf.n_pkts_dropped=%u\n", stats["leaf"]["n_pkts_dropped"][col])
    printf("  leaf.n_bytes_dropped=%u\n", stats["leaf"]["n_bytes_dropped"][col])
  end
  printf("  leaf.n_pkts_queued=%u\n", stats["leaf"]["n_pkts_queued"])
  printf("  leaf.n_bytes_queued=%u\n", stats["leaf"]["n_bytes_queued"])
end

return tm
