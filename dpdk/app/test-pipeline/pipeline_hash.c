/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <rte_log.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_byteorder.h>

#include <rte_port_ring.h>
#include <rte_table_hash.h>
#include <rte_pipeline.h>

#include "main.h"

static void
translate_options(uint32_t *special, uint32_t *ext, uint32_t *key_size)
{
	switch (app.pipeline_type) {
	case e_APP_PIPELINE_HASH_KEY8_EXT:
		*special = 0; *ext = 1; *key_size = 8; return;
	case e_APP_PIPELINE_HASH_KEY8_LRU:
		*special = 0; *ext = 0; *key_size = 8; return;
	case e_APP_PIPELINE_HASH_KEY16_EXT:
		*special = 0; *ext = 1; *key_size = 16; return;
	case e_APP_PIPELINE_HASH_KEY16_LRU:
		*special = 0; *ext = 0; *key_size = 16; return;
	case e_APP_PIPELINE_HASH_KEY32_EXT:
		*special = 0; *ext = 1; *key_size = 32; return;
	case e_APP_PIPELINE_HASH_KEY32_LRU:
		*special = 0; *ext = 0; *key_size = 32; return;

	case e_APP_PIPELINE_HASH_SPEC_KEY8_EXT:
		*special = 1; *ext = 1; *key_size = 8; return;
	case e_APP_PIPELINE_HASH_SPEC_KEY8_LRU:
		*special = 1; *ext = 0; *key_size = 8; return;
	case e_APP_PIPELINE_HASH_SPEC_KEY16_EXT:
		*special = 1; *ext = 1; *key_size = 16; return;
	case e_APP_PIPELINE_HASH_SPEC_KEY16_LRU:
		*special = 1; *ext = 0; *key_size = 16; return;
	case e_APP_PIPELINE_HASH_SPEC_KEY32_EXT:
		*special = 1; *ext = 1; *key_size = 32; return;
	case e_APP_PIPELINE_HASH_SPEC_KEY32_LRU:
		*special = 1; *ext = 0; *key_size = 32; return;

	default:
		rte_panic("Invalid hash table type or key size\n");
	}
}
void
app_main_loop_worker_pipeline_hash(void) {
	struct rte_pipeline_params pipeline_params = {
		.name = "pipeline",
		.socket_id = rte_socket_id(),
	};

	struct rte_pipeline *p;
	uint32_t port_in_id[APP_MAX_PORTS];
	uint32_t port_out_id[APP_MAX_PORTS];
	uint32_t table_id;
	uint32_t i;
	uint32_t special, ext, key_size;

	translate_options(&special, &ext, &key_size);

	RTE_LOG(INFO, USER1, "Core %u is doing work "
		"(pipeline with hash table, %s, %s, %d-byte key)\n",
		rte_lcore_id(),
		special ? "specialized" : "non-specialized",
		ext ? "extendible bucket" : "LRU",
		key_size);

	/* Pipeline configuration */
	p = rte_pipeline_create(&pipeline_params);
	if (p == NULL)
		rte_panic("Unable to configure the pipeline\n");

	/* Input port configuration */
	for (i = 0; i < app.n_ports; i++) {
		struct rte_port_ring_reader_params port_ring_params = {
			.ring = app.rings_rx[i],
		};

		struct rte_pipeline_port_in_params port_params = {
			.ops = &rte_port_ring_reader_ops,
			.arg_create = (void *) &port_ring_params,
			.f_action = NULL,
			.arg_ah = NULL,
			.burst_size = app.burst_size_worker_read,
		};

		if (rte_pipeline_port_in_create(p, &port_params,
			&port_in_id[i]))
			rte_panic("Unable to configure input port for "
				"ring %d\n", i);
	}

	/* Output port configuration */
	for (i = 0; i < app.n_ports; i++) {
		struct rte_port_ring_writer_params port_ring_params = {
			.ring = app.rings_tx[i],
			.tx_burst_sz = app.burst_size_worker_write,
		};

		struct rte_pipeline_port_out_params port_params = {
			.ops = &rte_port_ring_writer_ops,
			.arg_create = (void *) &port_ring_params,
			.f_action = NULL,
			.arg_ah = NULL,
		};

		if (rte_pipeline_port_out_create(p, &port_params,
			&port_out_id[i]))
			rte_panic("Unable to configure output port for "
				"ring %d\n", i);
	}

	/* Table configuration */
	switch (app.pipeline_type) {
	case e_APP_PIPELINE_HASH_KEY8_EXT:
	case e_APP_PIPELINE_HASH_KEY16_EXT:
	case e_APP_PIPELINE_HASH_KEY32_EXT:
	{
		struct rte_table_hash_ext_params table_hash_params = {
			.key_size = key_size,
			.n_keys = 1 << 24,
			.n_buckets = 1 << 22,
			.n_buckets_ext = 1 << 21,
			.f_hash = test_hash,
			.seed = 0,
			.signature_offset = APP_METADATA_OFFSET(0),
			.key_offset = APP_METADATA_OFFSET(32),
		};

		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_hash_ext_ops,
			.arg_create = &table_hash_params,
			.f_action_hit = NULL,
			.f_action_miss = NULL,
			.arg_ah = NULL,
			.action_data_size = 0,
		};

		if (rte_pipeline_table_create(p, &table_params, &table_id))
			rte_panic("Unable to configure the hash table\n");
	}
	break;

	case e_APP_PIPELINE_HASH_KEY8_LRU:
	case e_APP_PIPELINE_HASH_KEY16_LRU:
	case e_APP_PIPELINE_HASH_KEY32_LRU:
	{
		struct rte_table_hash_lru_params table_hash_params = {
			.key_size = key_size,
			.n_keys = 1 << 24,
			.n_buckets = 1 << 22,
			.f_hash = test_hash,
			.seed = 0,
			.signature_offset = 0,
			.key_offset = 32,
		};

		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_hash_lru_ops,
			.arg_create = &table_hash_params,
			.f_action_hit = NULL,
			.f_action_miss = NULL,
			.arg_ah = NULL,
			.action_data_size = 0,
		};

		if (rte_pipeline_table_create(p, &table_params, &table_id))
			rte_panic("Unable to configure the hash table\n");
	}
	break;

	case e_APP_PIPELINE_HASH_SPEC_KEY8_EXT:
	{
		struct rte_table_hash_key8_ext_params table_hash_params = {
			.n_entries = 1 << 24,
			.n_entries_ext = 1 << 23,
			.signature_offset = APP_METADATA_OFFSET(0),
			.key_offset = APP_METADATA_OFFSET(32),
			.key_mask = NULL,
			.f_hash = test_hash,
			.seed = 0,
		};

		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_hash_key8_ext_ops,
			.arg_create = &table_hash_params,
			.f_action_hit = NULL,
			.f_action_miss = NULL,
			.arg_ah = NULL,
			.action_data_size = 0,
		};

		if (rte_pipeline_table_create(p, &table_params, &table_id))
			rte_panic("Unable to configure the hash table\n");
	}
	break;

	case e_APP_PIPELINE_HASH_SPEC_KEY8_LRU:
	{
		struct rte_table_hash_key8_lru_params table_hash_params = {
			.n_entries = 1 << 24,
			.signature_offset = APP_METADATA_OFFSET(0),
			.key_offset = APP_METADATA_OFFSET(32),
			.key_mask = NULL,
			.f_hash = test_hash,
			.seed = 0,
		};

		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_hash_key8_lru_ops,
			.arg_create = &table_hash_params,
			.f_action_hit = NULL,
			.f_action_miss = NULL,
			.arg_ah = NULL,
			.action_data_size = 0,
		};

		if (rte_pipeline_table_create(p, &table_params, &table_id))
			rte_panic("Unable to configure the hash table\n");
	}
	break;

	case e_APP_PIPELINE_HASH_SPEC_KEY16_EXT:
	{
		struct rte_table_hash_key16_ext_params table_hash_params = {
			.n_entries = 1 << 24,
			.n_entries_ext = 1 << 23,
			.signature_offset = APP_METADATA_OFFSET(0),
			.key_offset = APP_METADATA_OFFSET(32),
			.f_hash = test_hash,
			.seed = 0,
			.key_mask = NULL,
		};

		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_hash_key16_ext_ops,
			.arg_create = &table_hash_params,
			.f_action_hit = NULL,
			.f_action_miss = NULL,
			.arg_ah = NULL,
			.action_data_size = 0,
		};

		if (rte_pipeline_table_create(p, &table_params, &table_id))
			rte_panic("Unable to configure the hash table)\n");
	}
	break;

	case e_APP_PIPELINE_HASH_SPEC_KEY16_LRU:
	{
		struct rte_table_hash_key16_lru_params table_hash_params = {
			.n_entries = 1 << 24,
			.signature_offset = APP_METADATA_OFFSET(0),
			.key_offset = APP_METADATA_OFFSET(32),
			.f_hash = test_hash,
			.seed = 0,
			.key_mask = NULL,
		};

		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_hash_key16_lru_ops,
			.arg_create = &table_hash_params,
			.f_action_hit = NULL,
			.f_action_miss = NULL,
			.arg_ah = NULL,
			.action_data_size = 0,
		};

		if (rte_pipeline_table_create(p, &table_params, &table_id))
			rte_panic("Unable to configure the hash table\n");
	}
	break;

	case e_APP_PIPELINE_HASH_SPEC_KEY32_EXT:
	{
		struct rte_table_hash_key32_ext_params table_hash_params = {
			.n_entries = 1 << 24,
			.n_entries_ext = 1 << 23,
			.signature_offset = APP_METADATA_OFFSET(0),
			.key_offset = APP_METADATA_OFFSET(32),
			.f_hash = test_hash,
			.seed = 0,
		};

		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_hash_key32_ext_ops,
			.arg_create = &table_hash_params,
			.f_action_hit = NULL,
			.f_action_miss = NULL,
			.arg_ah = NULL,
			.action_data_size = 0,
		};

		if (rte_pipeline_table_create(p, &table_params, &table_id))
			rte_panic("Unable to configure the hash table\n");
	}
	break;


	case e_APP_PIPELINE_HASH_SPEC_KEY32_LRU:
	{
		struct rte_table_hash_key32_lru_params table_hash_params = {
			.n_entries = 1 << 24,
			.signature_offset = APP_METADATA_OFFSET(0),
			.key_offset = APP_METADATA_OFFSET(32),
			.f_hash = test_hash,
			.seed = 0,
		};

		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_hash_key32_lru_ops,
			.arg_create = &table_hash_params,
			.f_action_hit = NULL,
			.f_action_miss = NULL,
			.arg_ah = NULL,
			.action_data_size = 0,
		};

		if (rte_pipeline_table_create(p, &table_params, &table_id))
			rte_panic("Unable to configure the hash table\n");
	}
	break;

	default:
		rte_panic("Invalid hash table type or key size\n");
	}

	/* Interconnecting ports and tables */
	for (i = 0; i < app.n_ports; i++)
		if (rte_pipeline_port_in_connect_to_table(p, port_in_id[i],
			table_id))
			rte_panic("Unable to connect input port %u to "
				"table %u\n", port_in_id[i],  table_id);

	/* Add entries to tables */
	for (i = 0; i < (1 << 24); i++) {
		struct rte_pipeline_table_entry entry = {
			.action = RTE_PIPELINE_ACTION_PORT,
			{.port_id = port_out_id[i & (app.n_ports - 1)]},
		};
		struct rte_pipeline_table_entry *entry_ptr;
		uint8_t key[32];
		uint32_t *k32 = (uint32_t *) key;
		int key_found, status;

		memset(key, 0, sizeof(key));
		k32[0] = rte_be_to_cpu_32(i);

		status = rte_pipeline_table_entry_add(p, table_id, key, &entry,
			&key_found, &entry_ptr);
		if (status < 0)
			rte_panic("Unable to add entry to table %u (%d)\n",
				table_id, status);
	}

	/* Enable input ports */
	for (i = 0; i < app.n_ports; i++)
		if (rte_pipeline_port_in_enable(p, port_in_id[i]))
			rte_panic("Unable to enable input port %u\n",
				port_in_id[i]);

	/* Check pipeline consistency */
	if (rte_pipeline_check(p) < 0)
		rte_panic("Pipeline consistency check failed\n");

	/* Run-time */
#if APP_FLUSH == 0
	for ( ; ; )
		rte_pipeline_run(p);
#else
	for (i = 0; ; i++) {
		rte_pipeline_run(p);

		if ((i & APP_FLUSH) == 0)
			rte_pipeline_flush(p);
	}
#endif
}

uint64_t test_hash(
	void *key,
	__attribute__((unused)) uint32_t key_size,
	__attribute__((unused)) uint64_t seed)
{
	uint32_t *k32 = (uint32_t *) key;
	uint32_t ip_dst = rte_be_to_cpu_32(k32[0]);
	uint64_t signature = (ip_dst >> 2) | ((ip_dst & 0x3) << 30);

	return signature;
}

void
app_main_loop_rx_metadata(void) {
	uint32_t i, j;
	int ret;

	RTE_LOG(INFO, USER1, "Core %u is doing RX (with meta-data)\n",
		rte_lcore_id());

	for (i = 0; ; i = ((i + 1) & (app.n_ports - 1))) {
		uint16_t n_mbufs;

		n_mbufs = rte_eth_rx_burst(
			app.ports[i],
			0,
			app.mbuf_rx.array,
			app.burst_size_rx_read);

		if (n_mbufs == 0)
			continue;

		for (j = 0; j < n_mbufs; j++) {
			struct rte_mbuf *m;
			uint8_t *m_data, *key;
			struct ipv4_hdr *ip_hdr;
			struct ipv6_hdr *ipv6_hdr;
			uint32_t ip_dst;
			uint8_t *ipv6_dst;
			uint32_t *signature, *k32;

			m = app.mbuf_rx.array[j];
			m_data = rte_pktmbuf_mtod(m, uint8_t *);
			signature = RTE_MBUF_METADATA_UINT32_PTR(m,
					APP_METADATA_OFFSET(0));
			key = RTE_MBUF_METADATA_UINT8_PTR(m,
					APP_METADATA_OFFSET(32));

			if (RTE_ETH_IS_IPV4_HDR(m->packet_type)) {
				ip_hdr = (struct ipv4_hdr *)
					&m_data[sizeof(struct ether_hdr)];
				ip_dst = ip_hdr->dst_addr;

				k32 = (uint32_t *) key;
				k32[0] = ip_dst & 0xFFFFFF00;
			} else if (RTE_ETH_IS_IPV6_HDR(m->packet_type)) {
				ipv6_hdr = (struct ipv6_hdr *)
					&m_data[sizeof(struct ether_hdr)];
				ipv6_dst = ipv6_hdr->dst_addr;

				memcpy(key, ipv6_dst, 16);
			} else
				continue;

			*signature = test_hash(key, 0, 0);
		}

		do {
			ret = rte_ring_sp_enqueue_bulk(
				app.rings_rx[i],
				(void **) app.mbuf_rx.array,
				n_mbufs);
		} while (ret < 0);
	}
}
