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

#ifndef _RTE_DISTRIBUTE_H_
#define _RTE_DISTRIBUTE_H_

/**
 * @file
 * RTE distributor
 *
 * The distributor is a component which is designed to pass packets
 * one-at-a-time to workers, with dynamic load balancing.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define RTE_DISTRIBUTOR_NAMESIZE 32 /**< Length of name for instance */

struct rte_distributor;
struct rte_mbuf;

/**
 * Function to create a new distributor instance
 *
 * Reserves the memory needed for the distributor operation and
 * initializes the distributor to work with the configured number of workers.
 *
 * @param name
 *   The name to be given to the distributor instance.
 * @param socket_id
 *   The NUMA node on which the memory is to be allocated
 * @param num_workers
 *   The maximum number of workers that will request packets from this
 *   distributor
 * @return
 *   The newly created distributor instance
 */
struct rte_distributor *
rte_distributor_create(const char *name, unsigned socket_id,
		unsigned num_workers);

/*  *** APIS to be called on the distributor lcore ***  */
/*
 * The following APIs are the public APIs which are designed for use on a
 * single lcore which acts as the distributor lcore for a given distributor
 * instance. These functions cannot be called on multiple cores simultaneously
 * without using locking to protect access to the internals of the distributor.
 *
 * NOTE: a given lcore cannot act as both a distributor lcore and a worker lcore
 * for the same distributor instance, otherwise deadlock will result.
 */

/**
 * Process a set of packets by distributing them among workers that request
 * packets. The distributor will ensure that no two packets that have the
 * same flow id, or tag, in the mbuf will be procesed at the same time.
 *
 * The user is advocated to set tag for each mbuf before calling this function.
 * If user doesn't set the tag, the tag value can be various values depending on
 * driver implementation and configuration.
 *
 * This is not multi-thread safe and should only be called on a single lcore.
 *
 * @param d
 *   The distributor instance to be used
 * @param mbufs
 *   The mbufs to be distributed
 * @param num_mbufs
 *   The number of mbufs in the mbufs array
 * @return
 *   The number of mbufs processed.
 */
int
rte_distributor_process(struct rte_distributor *d,
		struct rte_mbuf **mbufs, unsigned num_mbufs);

/**
 * Get a set of mbufs that have been returned to the distributor by workers
 *
 * This should only be called on the same lcore as rte_distributor_process()
 *
 * @param d
 *   The distributor instance to be used
 * @param mbufs
 *   The mbufs pointer array to be filled in
 * @param max_mbufs
 *   The size of the mbufs array
 * @return
 *   The number of mbufs returned in the mbufs array.
 */
int
rte_distributor_returned_pkts(struct rte_distributor *d,
		struct rte_mbuf **mbufs, unsigned max_mbufs);

/**
 * Flush the distributor component, so that there are no in-flight or
 * backlogged packets awaiting processing
 *
 * This should only be called on the same lcore as rte_distributor_process()
 *
 * @param d
 *   The distributor instance to be used
 * @return
 *   The number of queued/in-flight packets that were completed by this call.
 */
int
rte_distributor_flush(struct rte_distributor *d);

/**
 * Clears the array of returned packets used as the source for the
 * rte_distributor_returned_pkts() API call.
 *
 * This should only be called on the same lcore as rte_distributor_process()
 *
 * @param d
 *   The distributor instance to be used
 */
void
rte_distributor_clear_returns(struct rte_distributor *d);

/*  *** APIS to be called on the worker lcores ***  */
/*
 * The following APIs are the public APIs which are designed for use on
 * multiple lcores which act as workers for a distributor. Each lcore should use
 * a unique worker id when requesting packets.
 *
 * NOTE: a given lcore cannot act as both a distributor lcore and a worker lcore
 * for the same distributor instance, otherwise deadlock will result.
 */

/**
 * API called by a worker to get a new packet to process. Any previous packet
 * given to the worker is assumed to have completed processing, and may be
 * optionally returned to the distributor via the oldpkt parameter.
 *
 * @param d
 *   The distributor instance to be used
 * @param worker_id
 *   The worker instance number to use - must be less that num_workers passed
 *   at distributor creation time.
 * @param oldpkt
 *   The previous packet, if any, being processed by the worker
 *
 * @return
 *   A new packet to be processed by the worker thread.
 */
struct rte_mbuf *
rte_distributor_get_pkt(struct rte_distributor *d,
		unsigned worker_id, struct rte_mbuf *oldpkt);

/**
 * API called by a worker to return a completed packet without requesting a
 * new packet, for example, because a worker thread is shutting down
 *
 * @param d
 *   The distributor instance to be used
 * @param worker_id
 *   The worker instance number to use - must be less that num_workers passed
 *   at distributor creation time.
 * @param mbuf
 *   The previous packet being processed by the worker
 */
int
rte_distributor_return_pkt(struct rte_distributor *d, unsigned worker_id,
		struct rte_mbuf *mbuf);

/**
 * API called by a worker to request a new packet to process.
 * Any previous packet given to the worker is assumed to have completed
 * processing, and may be optionally returned to the distributor via
 * the oldpkt parameter.
 * Unlike rte_distributor_get_pkt(), this function does not wait for a new
 * packet to be provided by the distributor.
 *
 * NOTE: after calling this function, rte_distributor_poll_pkt() should
 * be used to poll for the packet requested. The rte_distributor_get_pkt()
 * API should *not* be used to try and retrieve the new packet.
 *
 * @param d
 *   The distributor instance to be used
 * @param worker_id
 *   The worker instance number to use - must be less that num_workers passed
 *   at distributor creation time.
 * @param oldpkt
 *   The previous packet, if any, being processed by the worker
 */
void
rte_distributor_request_pkt(struct rte_distributor *d,
		unsigned worker_id, struct rte_mbuf *oldpkt);

/**
 * API called by a worker to check for a new packet that was previously
 * requested by a call to rte_distributor_request_pkt(). It does not wait
 * for the new packet to be available, but returns NULL if the request has
 * not yet been fulfilled by the distributor.
 *
 * @param d
 *   The distributor instance to be used
 * @param worker_id
 *   The worker instance number to use - must be less that num_workers passed
 *   at distributor creation time.
 *
 * @return
 *   A new packet to be processed by the worker thread, or NULL if no
 *   packet is yet available.
 */
struct rte_mbuf *
rte_distributor_poll_pkt(struct rte_distributor *d,
		unsigned worker_id);

#ifdef __cplusplus
}
#endif

#endif
