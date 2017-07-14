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

#ifndef __RW_REG_H__
#define __RW_REG_H__

/* Simplified, from DPDK 1.8 */
struct _dev_hw {
	uint8_t *hw_addr;
};
/* Registers access */

#define PROX_PCI_REG_ADDR(hw, reg) \
	((volatile uint32_t *)((char *)(hw)->hw_addr + (reg)))
#define PROX_READ_REG(hw, reg) \
	prox_read_addr(PROX_PCI_REG_ADDR((hw), (reg)))
#define PROX_PCI_REG(reg) (*((volatile uint32_t *)(reg)))
#define PROX_PCI_REG_WRITE(reg_addr, value) \
	*((volatile uint32_t *) (reg_addr)) = (value)
#define PROX_WRITE_REG(hw,reg,value) \
	PROX_PCI_REG_WRITE(PROX_PCI_REG_ADDR((hw), (reg)), (value))

static inline uint32_t prox_read_addr(volatile void* addr)
{
        return rte_le_to_cpu_32(PROX_PCI_REG(addr));
}

int read_reg(uint8_t portid, uint32_t addr, uint32_t *reg);
int write_reg(uint8_t portid, uint32_t reg, uint32_t val);
#endif
