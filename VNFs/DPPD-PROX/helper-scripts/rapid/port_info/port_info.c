/*
// Copyright (c) 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_version.h>

static const uint16_t rx_rings = 1, tx_rings = 1;
static const struct rte_eth_conf port_conf = { .link_speeds = ETH_LINK_SPEED_AUTONEG };

static inline int
port_info(void)
{
	uint8_t port_id;
	int ret_val;

	RTE_ETH_FOREACH_DEV(port_id) {
		ret_val = rte_eth_dev_configure(port_id, rx_rings, tx_rings, &port_conf);
		if (ret_val != 0)
			return ret_val;

#if RTE_VERSION < RTE_VERSION_NUM(19,8,0,0)
		struct ether_addr addr;
#else
		struct rte_ether_addr addr;
#endif
		rte_eth_macaddr_get(port_id, &addr);
		printf("Port %u MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
				   ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
				(unsigned) port_id,
				addr.addr_bytes[0], addr.addr_bytes[1],
				addr.addr_bytes[2], addr.addr_bytes[3],
				addr.addr_bytes[4], addr.addr_bytes[5]);
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	return port_info();
}
