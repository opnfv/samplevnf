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

#include <rte_ethdev.h>
#include "rw_reg.h"

int read_reg(uint8_t port_id, uint32_t addr, uint32_t *reg)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct _dev_hw *hw = (struct _dev_hw *)dev->data->dev_private;

	*reg = PROX_READ_REG(hw, addr);
	return 0;
}

int write_reg(uint8_t port_id, uint32_t reg, uint32_t val)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct _dev_hw *hw = (struct _dev_hw *)dev->data->dev_private;

	PROX_WRITE_REG(hw, reg, val);
	return 0;
}
