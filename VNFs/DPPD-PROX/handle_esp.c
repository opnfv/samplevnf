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

/*
 * Non compatible implementation of RFC3686(CTR-AES 128 bit key), RFC4303 (tunnel ipv4 ESP)
 * Limitations:
 * 1. Crypto not safe!!!!! (underlying AES-CTR implementation is OK, but ESP implementation is lousy)
 * 2. Only ESP/tunnel/ipv4/AES-CTR
 * 3. Not fully implemented
 * 4. No proper key / SADB
 * So performance demonstrator only
 */

#include "task_init.h"
#include "task_base.h"
#include "etypes.h"
#include "stats.h"
#include "cfgfile.h"
#include "log.h"
#include "prox_cksum.h"
#include "defines.h"
#include <rte_ip.h>
#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>
#include <rte_bus_vdev.h>
#include "prox_port_cfg.h"
#include "prox_compat.h"

typedef unsigned int u32;
typedef unsigned char u8;

#define BYTE_LENGTH(x) (x/8)
#define DIGEST_BYTE_LENGTH_SHA1 (BYTE_LENGTH(160))

//#define CIPHER_KEY_LENGTH_AES_CBC (32)
#define CIPHER_KEY_LENGTH_AES_CBC (16)//==TEST
#define CIPHER_IV_LENGTH_AES_CBC 16

#define MAXIMUM_IV_LENGTH 16
#define IV_OFFSET (sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op))

#define MAX_SESSIONS 1024
#define POOL_CACHE_SIZE 128

#define NUM_OPS 256

struct task_esp_enc {
	struct task_base base;
	uint8_t cdev_id;
	uint16_t qp_id;
	uint32_t local_ipv4;
	struct ether_addr local_mac;
	uint32_t remote_ipv4;
	struct ether_addr dst_mac;
	struct rte_mempool *crypto_op_pool;
	struct rte_mempool *session_pool;
	struct rte_cryptodev_sym_session *sess;
	struct rte_crypto_op *ops_burst[NUM_OPS];
};

struct task_esp_dec {
	struct task_base base;
	uint8_t cdev_id;
	uint16_t qp_id;
	uint32_t local_ipv4;
	struct ether_addr local_mac;
	struct ether_addr dst_mac;
	struct rte_mempool *crypto_op_pool;
	struct rte_mempool *session_pool;
	struct rte_cryptodev_sym_session *sess;
	struct rte_crypto_op *ops_burst[NUM_OPS];
};

static uint8_t hmac_sha1_key[] = {
	0xF8, 0x2A, 0xC7, 0x54, 0xDB, 0x96, 0x18, 0xAA,
	0xC3, 0xA1, 0x53, 0xF6, 0x1F, 0x17, 0x60, 0xBD,
	0xDE, 0xF4, 0xDE, 0xAD };

static uint8_t aes_cbc_key[] = {
	0xE4, 0x23, 0x33, 0x8A, 0x35, 0x64, 0x61, 0xE2,
	0x49, 0x03, 0xDD, 0xC6, 0xB8, 0xCA, 0x55, 0x7A,
	0xE4, 0x23, 0x33, 0x8A, 0x35, 0x64, 0x61, 0xE2,
	0x49, 0x03, 0xDD, 0xC6, 0xB8, 0xCA, 0x55, 0x7A };

static uint8_t aes_cbc_iv[] = {
	0xE4, 0x23, 0x33, 0x8A, 0x35, 0x64, 0x61, 0xE2,
	0x49, 0x03, 0xDD, 0xC6, 0xB8, 0xCA, 0x55, 0x7A };

//RFC4303
struct esp_hdr {
	uint32_t spi;
	uint32_t sn;
};

static void printf_cdev_info(uint8_t cdev_id)
{
	struct rte_cryptodev_info dev_info;
	rte_cryptodev_info_get(cdev_id, &dev_info);
	plog_info("!!!numdevs:%d\n", rte_cryptodev_count());
	//uint16_t rte_cryptodev_queue_pair_count(uint8_t dev_id);
	plog_info("dev:%d name:%s nb_queue_pairs:%d max_nb_sessions:%d\n",
		cdev_id, dev_info.driver_name, dev_info.max_nb_queue_pairs, dev_info.sym.max_nb_sessions);
	const struct rte_cryptodev_capabilities *cap = &dev_info.capabilities[0];
	int i=0;
	while (cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED) {
		//plog_info("cap->sym.xform_type:%d,");
		if (cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_CIPHER)
			plog_info("RTE_CRYPTO_SYM_XFORM_CIPHER: %d\n", cap->sym.cipher.algo);
		cap = &dev_info.capabilities[++i];
	}
}

#if 0
static uint8_t get_cdev_id(void)
{
	//crypto devices must be configured in the config file
	//eal=-b 0000:00:03.0 --vdev crypto_aesni_mb0 --vdev crypto_aesni_mb1

	static uint8_t cdev_id=0;
	PROX_PANIC(cdev_id+1 > rte_cryptodev_count(), "not enough crypto devices\n");
	//eal=-b 0000:00:03.0 --vdev crypto_aesni_mb0 --vdev crypto_aesni_mb1
	return cdev_id++;
}
#else
static uint8_t get_cdev_id(void)
{
	static uint8_t cdev_id=0;
	char name[64]={0};

	sprintf(name, "crypto_aesni_mb%d", cdev_id);

	int cdev_id1 = rte_cryptodev_get_dev_id(name);
	if (cdev_id1 >= 0){
		plog_info("crypto dev %d preconfigured\n", cdev_id1);
		++cdev_id;
		return cdev_id1;
	}
#if RTE_VERSION < RTE_VERSION_NUM(18,8,0,0)
	int ret = rte_vdev_init(name, "max_nb_queue_pairs=8,max_nb_sessions=1024,socket_id=0");
#else
	int ret = rte_vdev_init(name, "max_nb_queue_pairs=8,socket_id=0");
#endif
	PROX_PANIC(ret != 0, "Failed rte_vdev_init\n");

	return cdev_id++;
}
#endif

static void init_task_esp_enc(struct task_base *tbase, struct task_args *targ)
{
	struct task_esp_enc *task = (struct task_esp_enc *)tbase;

	tbase->flags |= FLAG_NEVER_FLUSH;

	uint8_t lcore_id = targ->lconf->id;
	char name[64];
	sprintf(name, "core_%03u_crypto_pool", lcore_id);
	task->crypto_op_pool = rte_crypto_op_pool_create(name, RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		8192, 128, MAXIMUM_IV_LENGTH, rte_socket_id());
	PROX_PANIC(task->crypto_op_pool == NULL, "Can't create ENC CRYPTO_OP_POOL\n");

	task->cdev_id = get_cdev_id();

	struct rte_cryptodev_config cdev_conf;
	cdev_conf.nb_queue_pairs = 2;
	//cdev_conf.socket_id = SOCKET_ID_ANY;
	cdev_conf.socket_id = rte_socket_id();
	rte_cryptodev_configure(task->cdev_id, &cdev_conf);

	unsigned int session_size = rte_cryptodev_sym_get_private_session_size(task->cdev_id);
	plog_info("rte_cryptodev_sym_get_private_session_size=%d\n", session_size);
	sprintf(name, "core_%03u_session_pool", lcore_id);
	task->session_pool = rte_mempool_create(name,
				MAX_SESSIONS,
				session_size,
				POOL_CACHE_SIZE,
				0, NULL, NULL, NULL,
				NULL, rte_socket_id(),
				0);
	PROX_PANIC(task->session_pool == NULL, "Failed rte_mempool_create\n");

	task->qp_id=0;
	plog_info("enc: task->qp_id=%u\n", task->qp_id);
	struct rte_cryptodev_qp_conf qp_conf;
	//qp_conf.nb_descriptors = 4096;
	qp_conf.nb_descriptors = 128;
	rte_cryptodev_queue_pair_setup(task->cdev_id, task->qp_id,
		&qp_conf, rte_cryptodev_socket_id(task->cdev_id), task->session_pool);

	int ret = rte_cryptodev_start(task->cdev_id);
	PROX_PANIC(ret < 0, "Failed to start device\n");

	struct rte_cryptodev *dev;
	dev = rte_cryptodev_pmd_get_dev(task->cdev_id);
	PROX_PANIC(dev->attached != RTE_CRYPTODEV_ATTACHED, "No ENC cryptodev attached\n");

	//Setup Cipher Parameters
	struct rte_crypto_sym_xform cipher_xform = {0};
	struct rte_crypto_sym_xform auth_xform = {0};

	cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	cipher_xform.next = &auth_xform;

	cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_AES_CBC;
	cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
	cipher_xform.cipher.key.data = aes_cbc_key;
	cipher_xform.cipher.key.length = CIPHER_KEY_LENGTH_AES_CBC;

	cipher_xform.cipher.iv.offset = IV_OFFSET;
	cipher_xform.cipher.iv.length = CIPHER_IV_LENGTH_AES_CBC;

	//Setup HMAC Parameters
	auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
	auth_xform.next = NULL;
	auth_xform.auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;
	auth_xform.auth.algo = RTE_CRYPTO_AUTH_SHA1_HMAC;
	auth_xform.auth.key.length = DIGEST_BYTE_LENGTH_SHA1;
	auth_xform.auth.key.data = hmac_sha1_key;
	auth_xform.auth.digest_length = DIGEST_BYTE_LENGTH_SHA1;

	auth_xform.auth.iv.offset = 0;
	auth_xform.auth.iv.length = 0;

	task->sess = rte_cryptodev_sym_session_create(task->session_pool);
	PROX_PANIC(task->sess == NULL, "Failed to create ENC session\n");

	ret = rte_cryptodev_sym_session_init(task->cdev_id, task->sess, &cipher_xform, task->session_pool);
	PROX_PANIC(ret < 0, "Failed sym_session_init\n");

	//TODO: doublecheck task->ops_burst lifecycle!
	if (rte_crypto_op_bulk_alloc(task->crypto_op_pool,
			RTE_CRYPTO_OP_TYPE_SYMMETRIC,
			task->ops_burst, NUM_OPS) != NUM_OPS) {
		PROX_PANIC(1, "Failed to allocate ENC crypto operations\n");
	}

	task->local_ipv4 = rte_cpu_to_be_32(targ->local_ipv4);
	task->remote_ipv4 = rte_cpu_to_be_32(targ->remote_ipv4);
	//memcpy(&task->src_mac, &prox_port_cfg[task->base.tx_params_hw.tx_port_queue->port].eth_addr, sizeof(struct ether_addr));
	struct prox_port_cfg *port = find_reachable_port(targ);
	memcpy(&task->local_mac, &port->eth_addr, sizeof(struct ether_addr));

	if (targ->flags & TASK_ARG_DST_MAC_SET){
		memcpy(&task->dst_mac, &targ->edaddr, sizeof(task->dst_mac));
		plog_info("TASK_ARG_DST_MAC_SET ("MAC_BYTES_FMT")\n", MAC_BYTES(task->dst_mac.addr_bytes));
		//ether_addr_copy(&ptask->dst_mac, &peth->d_addr);
		//rte_memcpy(hdr, task->src_dst_mac, sizeof(task->src_dst_mac));
	}
}

static void init_task_esp_dec(struct task_base *tbase, struct task_args *targ)
{
	struct task_esp_dec *task = (struct task_esp_dec *)tbase;

	tbase->flags |= FLAG_NEVER_FLUSH;

	uint8_t lcore_id = targ->lconf->id;
	char name[64];
	sprintf(name, "core_%03u_crypto_pool", lcore_id);
	task->crypto_op_pool = rte_crypto_op_pool_create(name, RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		8192, 128, MAXIMUM_IV_LENGTH, rte_socket_id());
	PROX_PANIC(task->crypto_op_pool == NULL, "Can't create DEC CRYPTO_OP_POOL\n");

	task->cdev_id = get_cdev_id();
	struct rte_cryptodev_config cdev_conf;
	cdev_conf.nb_queue_pairs = 2;
	cdev_conf.socket_id = SOCKET_ID_ANY;
	cdev_conf.socket_id = rte_socket_id();
	rte_cryptodev_configure(task->cdev_id, &cdev_conf);

	unsigned int session_size = rte_cryptodev_sym_get_private_session_size(task->cdev_id);
	plog_info("rte_cryptodev_sym_get_private_session_size=%d\n", session_size);
	sprintf(name, "core_%03u_session_pool", lcore_id);
	task->session_pool = rte_mempool_create(name,
				MAX_SESSIONS,
				session_size,
				POOL_CACHE_SIZE,
				0, NULL, NULL, NULL,
				NULL, rte_socket_id(),
				0);
	PROX_PANIC(task->session_pool == NULL, "Failed rte_mempool_create\n");

	task->qp_id=0;
	plog_info("dec: task->qp_id=%u\n", task->qp_id);
	struct rte_cryptodev_qp_conf qp_conf;
	//qp_conf.nb_descriptors = 4096;
	qp_conf.nb_descriptors = 128;
	rte_cryptodev_queue_pair_setup(task->cdev_id, task->qp_id,
		&qp_conf, rte_cryptodev_socket_id(task->cdev_id), task->session_pool);

	int ret = rte_cryptodev_start(task->cdev_id);
	PROX_PANIC(ret < 0, "Failed to start device\n");

	struct rte_cryptodev *dev;
	dev = rte_cryptodev_pmd_get_dev(task->cdev_id);
	PROX_PANIC(dev->attached != RTE_CRYPTODEV_ATTACHED, "No ENC cryptodev attached\n");

	//Setup Cipher Parameters
	struct rte_crypto_sym_xform cipher_xform = {0};
	struct rte_crypto_sym_xform auth_xform = {0};

	cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	cipher_xform.next = NULL;
	cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_AES_CBC;
	cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
	cipher_xform.cipher.key.data = aes_cbc_key;
	cipher_xform.cipher.key.length = CIPHER_KEY_LENGTH_AES_CBC;

	cipher_xform.cipher.iv.offset = IV_OFFSET;
	cipher_xform.cipher.iv.length = CIPHER_IV_LENGTH_AES_CBC;

	//Setup HMAC Parameters
	auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
	auth_xform.next = &cipher_xform;
	auth_xform.auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;
	auth_xform.auth.algo = RTE_CRYPTO_AUTH_SHA1_HMAC;
	auth_xform.auth.key.length = DIGEST_BYTE_LENGTH_SHA1;
	auth_xform.auth.key.data = hmac_sha1_key;
	auth_xform.auth.digest_length = DIGEST_BYTE_LENGTH_SHA1;

	auth_xform.auth.iv.offset = 0;
	auth_xform.auth.iv.length = 0;

	task->sess = rte_cryptodev_sym_session_create(task->session_pool);
	PROX_PANIC(task->sess == NULL, "Failed to create ENC session\n");

	ret = rte_cryptodev_sym_session_init(task->cdev_id, task->sess, &cipher_xform, task->session_pool);
	PROX_PANIC(ret < 0, "Failed sym_session_init\n");

	//TODO: doublecheck task->ops_burst lifecycle!
	if (rte_crypto_op_bulk_alloc(task->crypto_op_pool,
			RTE_CRYPTO_OP_TYPE_SYMMETRIC,
			task->ops_burst, NUM_OPS) != NUM_OPS) {
		PROX_PANIC(1, "Failed to allocate DEC crypto operations\n");
	}

	task->local_ipv4 = rte_cpu_to_be_32(targ->local_ipv4);
	//memcpy(&task->src_mac, &prox_port_cfg[task->base.tx_params_hw.tx_port_queue->port].eth_addr, sizeof(struct ether_addr));
	struct prox_port_cfg *port = find_reachable_port(targ);
	memcpy(&task->local_mac, &port->eth_addr, sizeof(struct ether_addr));

	if (targ->flags & TASK_ARG_DST_MAC_SET){
		memcpy(&task->dst_mac, &targ->edaddr, sizeof(task->dst_mac));
		plog_info("TASK_ARG_DST_MAC_SET ("MAC_BYTES_FMT")\n", MAC_BYTES(task->dst_mac.addr_bytes));
		//ether_addr_copy(&ptask->dst_mac, &peth->d_addr);
		//rte_memcpy(hdr, task->src_dst_mac, sizeof(task->src_dst_mac));
	}

}

static inline uint8_t handle_esp_ah_enc(struct task_esp_enc *task, struct rte_mbuf *mbuf, struct rte_crypto_op *cop)
{
	u8 *data;
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	struct ipv4_hdr* pip4 = (struct ipv4_hdr *)(peth + 1);
	uint16_t ipv4_length = rte_be_to_cpu_16(pip4->total_length);
	struct rte_crypto_sym_op *sym_cop = cop->sym;

	if (unlikely((pip4->version_ihl >> 4) != 4)) {
		plog_info("Received non IPv4 packet at esp enc %i\n", pip4->version_ihl);
		plogdx_info(mbuf, "ENC RX: ");
		return OUT_DISCARD;
	}
	if (pip4->time_to_live) {
		pip4->time_to_live--;
	}
	else {
		plog_info("TTL = 0 => Dropping\n");
		return OUT_DISCARD;
	}

	// Remove padding if any (we don't want to encapsulate garbage at end of IPv4 packet)
	int l1 = rte_pktmbuf_pkt_len(mbuf);
	int padding = l1 - (ipv4_length + sizeof(struct ether_hdr));
	if (unlikely(padding > 0)) {
		rte_pktmbuf_trim(mbuf, padding);
	}

	l1 = rte_pktmbuf_pkt_len(mbuf);
	int encrypt_len = l1 - sizeof(struct ether_hdr) + 2; // According to RFC4303 table 1, encrypt len is ip+tfc_pad(o)+pad+pad len(1) + next header(1)
	padding = 0;
	if ((encrypt_len & 0xf) != 0){
		padding = 16 - (encrypt_len % 16);
		encrypt_len += padding;
	}

	const int extra_space = sizeof(struct ipv4_hdr) + sizeof(struct esp_hdr) + CIPHER_IV_LENGTH_AES_CBC;

	struct ether_addr src_mac = peth->s_addr;
	struct ether_addr dst_mac = peth->d_addr;
	uint32_t src_addr = pip4->src_addr;
	uint32_t dst_addr = pip4->dst_addr;
	uint8_t ttl = pip4->time_to_live;
	uint8_t version_ihl = pip4->version_ihl;

	peth = (struct ether_hdr *)rte_pktmbuf_prepend(mbuf, extra_space); // encap + prefix
	peth = (struct ether_hdr *)rte_pktmbuf_append(mbuf, 0 + 1 + 1 + padding + 4 + DIGEST_BYTE_LENGTH_SHA1); // padding + pad_len + next_head + seqn + ICV pad + ICV
	peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	l1 = rte_pktmbuf_pkt_len(mbuf);
	peth->ether_type = ETYPE_IPv4;
#if 0
	//send it back
	ether_addr_copy(&dst_mac, &peth->s_addr);
	ether_addr_copy(&src_mac, &peth->d_addr);
#else
	ether_addr_copy(&task->local_mac, &peth->s_addr);
	//ether_addr_copy(&dst_mac, &peth->d_addr);//IS: dstmac should be rewritten by arp
	ether_addr_copy(&task->dst_mac, &peth->d_addr);
#endif

	pip4 = (struct ipv4_hdr *)(peth + 1);
	pip4->src_addr = task->local_ipv4;
	pip4->dst_addr = task->remote_ipv4;
	pip4->time_to_live = ttl;
	pip4->next_proto_id = IPPROTO_ESP; // 50 for ESP, ip in ip next proto trailer
	pip4->version_ihl = version_ihl; // 20 bytes, ipv4
	pip4->total_length = rte_cpu_to_be_16(ipv4_length + sizeof(struct ipv4_hdr) + sizeof(struct esp_hdr) + CIPHER_IV_LENGTH_AES_CBC + padding + 1 + 1 + DIGEST_BYTE_LENGTH_SHA1); // iphdr+SPI+SN+IV+payload+padding+padlen+next header + crc + auth
	pip4->packet_id = 0x0101;
	pip4->type_of_service = 0;
	pip4->time_to_live = 64;
	prox_ip_cksum(mbuf, pip4, sizeof(struct ether_hdr), sizeof(struct ipv4_hdr), 1);

	data = (u8*)(pip4 + 1);
#if 0
	*((u32*) data) = 0x2016; // FIXME SPI
	*((u32*) data + 1) = 0x2; // FIXME SN
#else
	struct esp_hdr *pesp = (struct esp_hdr*)(pip4+1);
	pesp->spi = src_addr;//for simplicity assume 1 tunnel per source ip
	static u32 sn = 0;
	pesp->sn = ++sn;
	pesp->spi=0xAAAAAAAA;//debug
	pesp->sn =0xBBBBBBBB;//debug
#endif
	u8 *padl = (u8*)data + (8 + encrypt_len - 2 + CIPHER_IV_LENGTH_AES_CBC); // No ESN yet. (-2 means NH is crypted)
	//padl += CIPHER_IV_LENGTH_AES_CBC;
	*padl = padding;
	*(padl + 1) = 4; // ipv4 in 4

	sym_cop->auth.digest.data = data + 8 + CIPHER_IV_LENGTH_AES_CBC + encrypt_len;
	//sym_cop->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(mbuf, (sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 8 + CIPHER_IV_LENGTH_AES_CBC + encrypt_len));
	sym_cop->auth.digest.phys_addr = rte_pktmbuf_iova_offset(mbuf, (sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 8 + CIPHER_IV_LENGTH_AES_CBC + encrypt_len));
	//sym_cop->auth.digest.length = DIGEST_BYTE_LENGTH_SHA1;

	//sym_cop->cipher.iv.data = data + 8;
	//sym_cop->cipher.iv.phys_addr = rte_pktmbuf_mtophys(mbuf) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 4 + 4;
	//sym_cop->cipher.iv.length = CIPHER_IV_LENGTH_AES_CBC;

	//rte_memcpy(sym_cop->cipher.iv.data, aes_cbc_iv, CIPHER_IV_LENGTH_AES_CBC);

	uint8_t *iv_ptr = rte_crypto_op_ctod_offset(cop, uint8_t *, IV_OFFSET);
	rte_memcpy(iv_ptr, aes_cbc_iv, CIPHER_IV_LENGTH_AES_CBC);

#if 0//old
	sym_cop->cipher.data.offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 4 + 4 + CIPHER_IV_LENGTH_AES_CBC;
	sym_cop->cipher.data.length = encrypt_len;

	uint64_t *iv = (uint64_t *)(pesp + 1);
	memset(iv, 0, CIPHER_IV_LENGTH_AES_CBC);
#else
	//uint64_t *iv = (uint64_t *)(pesp + 1);
	//memset(iv, 0, CIPHER_IV_LENGTH_AES_CBC);
	sym_cop->cipher.data.offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct esp_hdr);
	sym_cop->cipher.data.length = encrypt_len + CIPHER_IV_LENGTH_AES_CBC;
#endif

	sym_cop->auth.data.offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
	sym_cop->auth.data.length = sizeof(struct esp_hdr) + CIPHER_IV_LENGTH_AES_CBC + encrypt_len;// + 4;// FIXME

	sym_cop->m_src = mbuf;
	rte_crypto_op_attach_sym_session(cop, task->sess);
	//cop->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
	//cop->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;

	return 0;
}

static inline uint8_t handle_esp_ah_dec(struct task_esp_dec *task, struct rte_mbuf *mbuf, struct rte_crypto_op *cop)
{
	struct rte_crypto_sym_op *sym_cop = cop->sym;
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	struct ipv4_hdr* pip4 = (struct ipv4_hdr *)(peth + 1);
	uint16_t ipv4_length = rte_be_to_cpu_16(pip4->total_length);
	u8 *data = (u8*)(pip4 + 1);

	if (pip4->next_proto_id != IPPROTO_ESP){
		plog_info("Received non ESP packet on esp dec\n");
		plogdx_info(mbuf, "DEC RX: ");
		return OUT_DISCARD;
	}

	rte_crypto_op_attach_sym_session(cop, task->sess);

	sym_cop->auth.digest.data = (unsigned char *)((unsigned char*)pip4 + ipv4_length - DIGEST_BYTE_LENGTH_SHA1);
	//sym_cop->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(mbuf, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct esp_hdr)); // FIXME
	sym_cop->auth.digest.phys_addr = rte_pktmbuf_iova_offset(mbuf, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct esp_hdr));
	//sym_cop->auth.digest.length = DIGEST_BYTE_LENGTH_SHA1;

	//sym_cop->cipher.iv.data = (uint8_t *)data + 8;
	//sym_cop->cipher.iv.phys_addr = rte_pktmbuf_mtophys(mbuf) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 4 + 4;
	//sym_cop->cipher.iv.length = CIPHER_IV_LENGTH_AES_CBC;

#if 0
	rte_memcpy(rte_crypto_op_ctod_offset(cop, uint8_t *, IV_OFFSET),
				aes_cbc_iv,
				CIPHER_IV_LENGTH_AES_CBC);
#else
	uint8_t * iv = (uint8_t *)(pip4 + 1) + sizeof(struct esp_hdr);
	rte_memcpy(rte_crypto_op_ctod_offset(cop, uint8_t *, IV_OFFSET),
				iv,
				CIPHER_IV_LENGTH_AES_CBC);
#endif

	sym_cop->auth.data.offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
	sym_cop->auth.data.length = ipv4_length - sizeof(struct ipv4_hdr) - 4 - CIPHER_IV_LENGTH_AES_CBC;

	sym_cop->cipher.data.offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct esp_hdr) + CIPHER_IV_LENGTH_AES_CBC;
	sym_cop->cipher.data.length = ipv4_length - sizeof(struct ipv4_hdr) - CIPHER_IV_LENGTH_AES_CBC - 28; // FIXME

	sym_cop->m_src = mbuf;
	return 0;
}

static inline void do_ipv4_swap(struct task_esp_dec *task, struct rte_mbuf *mbuf)
{
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	struct ether_addr src_mac = peth->s_addr;
	struct ether_addr dst_mac = peth->d_addr;
	uint32_t src_ip, dst_ip;

	struct ipv4_hdr* pip4 = (struct ipv4_hdr *)(peth + 1);
	src_ip = pip4->src_addr;
	dst_ip = pip4->dst_addr;

	//peth->s_addr = dst_mac;
	peth->d_addr = src_mac;//should be replaced by arp
	pip4->src_addr = dst_ip;
	pip4->dst_addr = src_ip;
	ether_addr_copy(&task->local_mac, &peth->s_addr);
}

static inline uint8_t handle_esp_ah_dec_finish(struct task_esp_dec *task, struct rte_mbuf *mbuf)
{
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	rte_memcpy(((u8*)peth) + sizeof(struct ether_hdr), ((u8*)peth) + sizeof(struct ether_hdr) +
			+ sizeof(struct ipv4_hdr) + 4 + 4 + CIPHER_IV_LENGTH_AES_CBC, sizeof(struct ipv4_hdr));// next hdr, padding
	struct ipv4_hdr* pip4 = (struct ipv4_hdr *)(peth + 1);

	if (unlikely((pip4->version_ihl >> 4) != 4)) {
		plog_info("non IPv4 packet after esp dec %i\n", pip4->version_ihl);
		plogdx_info(mbuf, "DEC TX: ");
		return OUT_DISCARD;
	}
	if (pip4->time_to_live) {
		pip4->time_to_live--;
	}
	else {
		plog_info("TTL = 0 => Dropping\n");
		return OUT_DISCARD;
	}
	uint16_t ipv4_length = rte_be_to_cpu_16(pip4->total_length);
	rte_memcpy(((u8*)peth) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr),
		((u8*)peth) + sizeof(struct ether_hdr) +
		+ 2 * sizeof(struct ipv4_hdr) + 4 + 4 + CIPHER_IV_LENGTH_AES_CBC, ipv4_length - sizeof(struct ipv4_hdr));

	int len = rte_pktmbuf_pkt_len(mbuf);
	rte_pktmbuf_trim(mbuf, len - sizeof(struct ether_hdr) - ipv4_length);
	peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

#if 0
	do_ipv4_swap(task, mbuf);
#else
	ether_addr_copy(&task->local_mac, &peth->s_addr);
	ether_addr_copy(&task->dst_mac, &peth->d_addr);
	//rte_memcpy(peth, task->dst_mac, sizeof(task->dst_mac));
#endif
	prox_ip_cksum(mbuf, pip4, sizeof(struct ether_hdr), sizeof(struct ipv4_hdr), 1);

	return 0;
}

static inline uint8_t handle_esp_ah_dec_finish2(struct task_esp_dec *task, struct rte_mbuf *mbuf)
{
	u8* m = rte_pktmbuf_mtod(mbuf, u8*);
	rte_memcpy(m+sizeof(struct ipv4_hdr)+sizeof(struct esp_hdr)+CIPHER_IV_LENGTH_AES_CBC,
		m, sizeof(struct ether_hdr));
	m = (u8*)rte_pktmbuf_adj(mbuf, sizeof(struct ipv4_hdr)+sizeof(struct esp_hdr)+CIPHER_IV_LENGTH_AES_CBC);
	struct ipv4_hdr* pip4 = (struct ipv4_hdr *)(m+sizeof(struct ether_hdr));

	if (unlikely((pip4->version_ihl >> 4) != 4)) {
		plog_info("non IPv4 packet after esp dec %i\n", pip4->version_ihl);
		plogdx_info(mbuf, "DEC TX: ");
		return OUT_DISCARD;
	}
	if (pip4->time_to_live) {
		pip4->time_to_live--;
	}
	else {
		plog_info("TTL = 0 => Dropping\n");
		return OUT_DISCARD;
	}
	uint16_t ipv4_length = rte_be_to_cpu_16(pip4->total_length);
	int len = rte_pktmbuf_pkt_len(mbuf);
	rte_pktmbuf_trim(mbuf, len - sizeof(struct ether_hdr) - ipv4_length);

#if 0
	do_ipv4_swap(task, mbuf);
#else
	struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	ether_addr_copy(&task->local_mac, &peth->s_addr);
	ether_addr_copy(&task->dst_mac, &peth->d_addr);
	//rte_memcpy(peth, task->dst_mac, sizeof(task->dst_mac));
#endif

	prox_ip_cksum(mbuf, pip4, sizeof(struct ether_hdr), sizeof(struct ipv4_hdr), 1);
	return 0;
}

static int handle_esp_enc_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_esp_enc *task = (struct task_esp_enc *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint16_t i = 0, nb_rx = 0, nb_enc=0, j = 0;

	for (uint16_t j = 0; j < n_pkts; ++j) {
		out[j] = handle_esp_ah_enc(task, mbufs[j], task->ops_burst[nb_enc]);
		if (out[j] != OUT_DISCARD)
			++nb_enc;
	}

	if (rte_cryptodev_enqueue_burst(task->cdev_id, task->qp_id, task->ops_burst, nb_enc) != nb_enc) {
		plog_info("Error enc enqueue_burst\n");
		return -1;
	}

	do {
		nb_rx = rte_cryptodev_dequeue_burst(task->cdev_id, task->qp_id,	task->ops_burst+i, nb_enc-i);
		i += nb_rx;
	} while (i < nb_enc);

	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static int handle_esp_dec_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_esp_dec *task = (struct task_esp_dec *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint16_t j, nb_dec=0, nb_rx=0;

	for (j = 0; j < n_pkts; ++j) {
		out[j] = handle_esp_ah_dec(task, mbufs[j], task->ops_burst[nb_dec]);
		if (out[j] != OUT_DISCARD)
			++nb_dec;
	}

	if (rte_cryptodev_enqueue_burst(task->cdev_id, task->qp_id, task->ops_burst, nb_dec) != nb_dec) {
		plog_info("Error dec enqueue_burst\n");
		return -1;
	}

	j=0;
	do {
		nb_rx = rte_cryptodev_dequeue_burst(task->cdev_id, task->qp_id,
					task->ops_burst+j, nb_dec-j);
		j += nb_rx;
	} while (j < nb_dec);

	for (j = 0; j < nb_dec; ++j) {
		if (task->ops_burst[j]->status != RTE_CRYPTO_OP_STATUS_SUCCESS){
			plog_info("err: task->ops_burst[%d].status=%d\n", j, task->ops_burst[j]->status);
			//!!!TODO!!! find mbuf and discard it!!!
			//for now just send it further
			//plogdx_info(mbufs[j], "RX: ");
		}
		if (task->ops_burst[j]->status == RTE_CRYPTO_OP_STATUS_SUCCESS) {
			struct rte_mbuf *mbuf = task->ops_burst[j]->sym->m_src;
			handle_esp_ah_dec_finish2(task, mbuf);//TODO set out[j] properly
		}
	}

	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

struct task_init task_init_esp_enc = {
        .mode = ESP_ENC,
        .mode_str = "esp_enc",
        .init = init_task_esp_enc,
        .handle = handle_esp_enc_bulk,
        .size = sizeof(struct task_esp_enc),
};

struct task_init task_init_esp_dec = {
        .mode = ESP_ENC,
        .mode_str = "esp_dec",
        .init = init_task_esp_dec,
        .handle = handle_esp_dec_bulk,
        .size = sizeof(struct task_esp_dec),
};

__attribute__((constructor)) static void reg_task_esp_enc(void)
{
	reg_task(&task_init_esp_enc);
}

__attribute__((constructor)) static void reg_task_esp_dec(void)
{
	reg_task(&task_init_esp_dec);
}
