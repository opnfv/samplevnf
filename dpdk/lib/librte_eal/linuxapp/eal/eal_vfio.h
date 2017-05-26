/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef EAL_VFIO_H_
#define EAL_VFIO_H_

/*
 * determine if VFIO is present on the system
 */
#ifdef RTE_EAL_VFIO
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
#include <linux/vfio.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
#define RTE_PCI_MSIX_TABLE_BIR    0x7
#define RTE_PCI_MSIX_TABLE_OFFSET 0xfffffff8
#define RTE_PCI_MSIX_FLAGS_QSIZE  0x07ff
#else
#define RTE_PCI_MSIX_TABLE_BIR    PCI_MSIX_TABLE_BIR
#define RTE_PCI_MSIX_TABLE_OFFSET PCI_MSIX_TABLE_OFFSET
#define RTE_PCI_MSIX_FLAGS_QSIZE  PCI_MSIX_FLAGS_QSIZE
#endif

#define RTE_VFIO_TYPE1 VFIO_TYPE1_IOMMU

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
#define RTE_VFIO_NOIOMMU 8
#else
#define RTE_VFIO_NOIOMMU VFIO_NOIOMMU_IOMMU
#endif

#define VFIO_PRESENT
#endif /* kernel version */
#endif /* RTE_EAL_VFIO */

#endif /* EAL_VFIO_H_ */
