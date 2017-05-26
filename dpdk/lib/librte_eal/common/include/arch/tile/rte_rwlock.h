/*
 *   BSD LICENSE
 *
 *   Copyright (C) EZchip Semiconductor Ltd. 2015.
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
 *     * Neither the name of EZchip Semiconductor nor the names of its
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

#ifndef _RTE_RWLOCK_TILE_H_
#define _RTE_RWLOCK_TILE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "generic/rte_rwlock.h"

static inline void
rte_rwlock_read_lock_tm(rte_rwlock_t *rwl)
{
	rte_rwlock_read_lock(rwl);
}

static inline void
rte_rwlock_read_unlock_tm(rte_rwlock_t *rwl)
{
	rte_rwlock_read_unlock(rwl);
}

static inline void
rte_rwlock_write_lock_tm(rte_rwlock_t *rwl)
{
	rte_rwlock_write_lock(rwl);
}

static inline void
rte_rwlock_write_unlock_tm(rte_rwlock_t *rwl)
{
	rte_rwlock_write_unlock(rwl);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_RWLOCK_TILE_H_ */
