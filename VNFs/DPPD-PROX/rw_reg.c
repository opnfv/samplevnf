/*
// Copyright (c) 2010-2017 Intel Corporation
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

#include <rte_version.h>
#if RTE_VERSION >= RTE_VERSION_NUM(21,11,0,0)
#include <ethdev_driver.h>	// Please configure DPDK with meson option -Denable_driver_sdk=true
#endif
#include <rte_ethdev.h>
#include <rte_bus.h>
#include <rte_byteorder.h>
#include "rw_reg.h"
#include "prox_port_cfg.h"
#include "log.h"

/*
 * registers' read and write operations require a pci device.
 * We can follow the dpdk community's logic and commit id is:
 * cd8c7c7ce241d2ea7c059a9df07caa9411ef19ed.
 */
int read_reg(uint8_t port_id, uint32_t addr, uint32_t *reg)
{
#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
	struct rte_eth_dev_info *dev_info;
	const struct rte_bus *bus;
	const struct rte_pci_device *pci_dev;
	void *reg_addr;

	*reg = 0;

	if (port_id >= PROX_MAX_PORTS) {
		plog_err("read_reg(): The port_id is invalid\n");
		return 1;
	}

	dev_info = &(prox_port_cfg[port_id].dev_info);

	if (!dev_info->device) {
		plog_err("read_reg(): The port device is NULL\n");
		return 1;
	}

	bus = rte_bus_find_by_device(dev_info->device);
	if (bus && !strcmp(bus->name, "pci")) {
		pci_dev = RTE_DEV_TO_PCI(dev_info->device);
	} else {
		plog_err("read_reg(): The bus is not pci\n");
		return 1;
	}

	reg_addr = (void *)((char *)pci_dev->mem_resource[0].addr + addr);
	*reg = rte_le_to_cpu_32(*((volatile uint32_t *)reg_addr));
#else
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct _dev_hw *hw = (struct _dev_hw *)dev->data->dev_private;

	*reg = PROX_READ_REG(hw, addr);
#endif
	return 0;
}

int write_reg(uint8_t port_id, uint32_t reg, uint32_t val)
{
#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
	struct rte_eth_dev_info *dev_info;
	const struct rte_bus *bus;
	const struct rte_pci_device *pci_dev;
	void *reg_addr;

	if (port_id >= PROX_MAX_PORTS) {
		plog_err("write_reg(): The port_id is invalid\n");
		return 1;
	}

	dev_info = &(prox_port_cfg[port_id].dev_info);

	if (!dev_info->device) {
		plog_err("write_reg(): The port device is NULL\n");
		return 1;
	}

	bus = rte_bus_find_by_device(dev_info->device);
	if (bus && !strcmp(bus->name, "pci")) {
		pci_dev = RTE_DEV_TO_PCI(dev_info->device);
	} else {
		plog_err("write_reg(): The bus is not pci\n");
		return 1;
	}

	reg_addr = (void *)((char *)pci_dev->mem_resource[0].addr + reg);
	*((volatile uint32_t *)reg_addr) = rte_cpu_to_le_32(val);
#else
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct _dev_hw *hw = (struct _dev_hw *)dev->data->dev_private;

	PROX_WRITE_REG(hw, reg, val);
#endif
	return 0;
}
