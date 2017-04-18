/*
// Copyright (c) 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include <stdlib.h>
#include <string.h>
#include "rte_ct_tcp.h"
#include "rte_cnxn_tracking.h"

uint8_t rte_ct_udp_new_connection(__rte_unused struct rte_ct_cnxn_tracker *ct,
		struct rte_ct_cnxn_data *cd,
		__rte_unused struct rte_mbuf *pkt)
{
	/* printf("New connection UDP packet received\n"); */
	cd->connstatus = RTE_INIT_CONN;
	return 1;
}
enum rte_ct_packet_action rte_ct_udp_packet(struct rte_ct_cnxn_tracker *ct,
		struct rte_ct_cnxn_data *cd,
		__rte_unused struct rte_mbuf *pkt,
		uint8_t  key_was_flipped)
{
	enum rte_ct_pkt_direction dir;

	dir = (cd->key_is_client_order == !key_was_flipped);
	/* printf("packet received verify"); */
	if (dir == RTE_CT_DIR_REPLY &&
			cd->connstatus == RTE_INIT_CONN) {
		rte_ct_set_cnxn_timer_for_udp(ct, cd, RTE_CT_UDP_REPLIED);
		cd->connstatus = RTE_ASSURED_CONN;
	} else if (dir == RTE_CT_DIR_REPLY &&
			cd->connstatus == RTE_ASSURED_CONN)
		rte_ct_set_cnxn_timer_for_udp(ct, cd, RTE_CT_UDP_REPLIED);
	else
		rte_ct_set_cnxn_timer_for_udp(ct, cd, RTE_CT_UDP_UNREPLIED);
	return RTE_CT_FORWARD_PACKET;
}
