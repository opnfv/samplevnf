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
#include <rte_ip.h>
#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>
#include "prox_port_cfg.h"

typedef unsigned int u32;
typedef unsigned char u8;

#define BYTE_LENGTH(x)                          (x/8)
#define DIGEST_BYTE_LENGTH_SHA1                 (BYTE_LENGTH(160))

//#define CIPHER_KEY_LENGTH_AES_CBC       (32)
#define CIPHER_KEY_LENGTH_AES_CBC       (16)//==TEST
#define CIPHER_IV_LENGTH_AES_CBC        16

static inline void *get_sym_cop(struct rte_crypto_op *cop)
{
        //return (cop + 1);//makes no sense on dpdk_17.05.2; TODO: doublecheck
        return cop->sym;
}

struct task_esp_enc {
        struct task_base    base;
        int crypto_dev_id;
        u8 iv[16];
        uint32_t                local_ipv4;
        struct ether_addr       local_mac;
        uint32_t                remote_ipv4;
        u8 key[16];
        uint32_t  ipaddr;
        struct rte_cryptodev_sym_session *sess;
        struct rte_crypto_sym_xform cipher_xform;
        struct rte_crypto_sym_xform auth_xform;
        struct rte_crypto_op *ops_burst[MAX_PKT_BURST];
};

struct task_esp_dec {
        struct task_base    base;
        int crypto_dev_id;
        u8 iv[16];
        uint32_t                local_ipv4;
        struct ether_addr       local_mac;
        u8 key[16];
        uint32_t  ipaddr;
        struct rte_cryptodev_sym_session *sess;
        struct rte_crypto_sym_xform cipher_xform;
        struct rte_crypto_sym_xform auth_xform;
        struct rte_crypto_op *ops_burst[MAX_PKT_BURST];
};

struct crypto_testsuite_params {
        struct rte_mempool *mbuf_ol_pool_enc;
        struct rte_mempool *mbuf_ol_pool_dec;

        struct rte_cryptodev_config conf;
        struct rte_cryptodev_qp_conf qp_conf;
};

static struct crypto_testsuite_params testsuite_params = { NULL };
static enum rte_cryptodev_type gbl_cryptodev_preftest_devtype = RTE_CRYPTODEV_AESNI_MB_PMD;

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

static void init_task_esp_common(void)
{
        static int vdev_initialized = 0;
        struct crypto_testsuite_params *ts_params = &testsuite_params;

        if (!vdev_initialized) {
                rte_vdev_init(RTE_STR(CRYPTODEV_NAME_AESNI_MB_PMD), NULL);
                int nb_devs = rte_cryptodev_count_devtype(RTE_CRYPTODEV_AESNI_MB_PMD);
                PROX_PANIC(nb_devs < 1, "No crypto devices found?\n");
                vdev_initialized = 1;
        }
        ts_params->conf.nb_queue_pairs = 2;
        ts_params->conf.socket_id = SOCKET_ID_ANY;
        ts_params->conf.session_mp.nb_objs = 2048;
        ts_params->qp_conf.nb_descriptors = 4096;

        /*Now reconfigure queues to size we actually want to use in this testsuite.*/
        ts_params->qp_conf.nb_descriptors = 128;
        rte_cryptodev_configure(0, &ts_params->conf);
		//rte_cryptodev_start(task->crypto_dev_id);
}

static void init_task_esp_enc(struct task_base *tbase, struct task_args *targ)
{
        int i, nb_devs, valid_dev_id = 0;
        uint16_t qp_id;
        struct rte_cryptodev_info info;
        struct crypto_testsuite_params *ts_params = &testsuite_params;

        init_task_esp_common();
        tbase->flags |= FLAG_NEVER_FLUSH;

        ts_params->mbuf_ol_pool_enc = rte_crypto_op_pool_create("crypto_op_pool_enc",
                        RTE_CRYPTO_OP_TYPE_SYMMETRIC, (2*1024*1024), 128, 0,
                        rte_socket_id());
        PROX_PANIC(ts_params->mbuf_ol_pool_enc == NULL, "Can't create ENC CRYPTO_OP_POOL\n");

        struct task_esp_enc *task = (struct task_esp_enc *)tbase;
        task->crypto_dev_id = 0;

        /*
         * Since we can't free and re-allocate queue memory always set the queues
         * on this device up to max size first so enough memory is allocated for
         * any later re-configures needed by other tests
         */

        rte_cryptodev_queue_pair_setup(task->crypto_dev_id, 0,
                                &ts_params->qp_conf, rte_cryptodev_socket_id(task->crypto_dev_id));

        struct rte_cryptodev *dev;
        dev = rte_cryptodev_pmd_get_dev(task->crypto_dev_id);
        PROX_PANIC(dev->attached != RTE_CRYPTODEV_ATTACHED, "No ENC cryptodev attached\n");

        /* Setup Cipher Parameters */
        task->cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
        task->cipher_xform.next = &(task->auth_xform);

        task->cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_AES_CBC;
        task->cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
        task->cipher_xform.cipher.key.data = aes_cbc_key;
        task->cipher_xform.cipher.key.length = CIPHER_KEY_LENGTH_AES_CBC;

        /* Setup HMAC Parameters */
        task->auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
        task->auth_xform.next = NULL;
        task->auth_xform.auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;
        task->auth_xform.auth.algo = RTE_CRYPTO_AUTH_SHA1_HMAC;
        task->auth_xform.auth.key.length = DIGEST_BYTE_LENGTH_SHA1;
        task->auth_xform.auth.key.data = hmac_sha1_key;
        task->auth_xform.auth.digest_length = DIGEST_BYTE_LENGTH_SHA1;

        task->sess = rte_cryptodev_sym_session_create(task->crypto_dev_id, &task->cipher_xform);
        PROX_PANIC(task->sess == NULL, "Failed to create ENC session\n");

        //TODO: doublecheck task->ops_burst lifecycle!
        if (rte_crypto_op_bulk_alloc(ts_params->mbuf_ol_pool_enc,
                     RTE_CRYPTO_OP_TYPE_SYMMETRIC,
                     task->ops_burst, MAX_PKT_BURST) != MAX_PKT_BURST) {
                PROX_PANIC(1, "Failed to allocate ENC crypto operations\n");
        }
        //to clean up after rte_crypto_op_bulk_alloc:
        //for (j = 0; j < MAX_PKT_BURST; j++) {
        //   rte_crypto_op_free(task->ops_burst[j]);
        //}

        // Read config file with SAs
        task->local_ipv4 = rte_cpu_to_be_32(targ->local_ipv4);
        task->remote_ipv4 = rte_cpu_to_be_32(targ->remote_ipv4);
        //memcpy(&task->src_mac, &prox_port_cfg[task->base.tx_params_hw.tx_port_queue->port].eth_addr, sizeof(struct ether_addr));
        struct prox_port_cfg *port = find_reachable_port(targ);
        memcpy(&task->local_mac, &port->eth_addr, sizeof(struct ether_addr));

        for (i = 0; i < 16; i++) task->key[i] = i+2;
        for (i = 0; i < 16; i++) task->iv[i] = i;
}

static void init_task_esp_dec(struct task_base *tbase, struct task_args *targ)
{
        int i, nb_devs;
        struct crypto_testsuite_params *ts_params = &testsuite_params;
        init_task_esp_common();

        tbase->flags |= FLAG_NEVER_FLUSH;
        ts_params->mbuf_ol_pool_dec = rte_crypto_op_pool_create("crypto_op_pool_dec",
                        RTE_CRYPTO_OP_TYPE_SYMMETRIC, (2*1024*1024), 128, 0,
                        rte_socket_id());
        PROX_PANIC(ts_params->mbuf_ol_pool_dec == NULL, "Can't create DEC CRYPTO_OP_POOL\n");

        struct task_esp_dec *task = (struct task_esp_dec *)tbase;

        static struct rte_cryptodev_session *sess_dec = NULL;
        // Read config file with SAs
        task->local_ipv4 = rte_cpu_to_be_32(targ->local_ipv4);

        task->cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
        task->cipher_xform.next = NULL;
        task->cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_AES_CBC;
        task->cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
        task->cipher_xform.cipher.key.data = aes_cbc_key;
        task->cipher_xform.cipher.key.length = CIPHER_KEY_LENGTH_AES_CBC;

        /* Setup HMAC Parameters */
        task->auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
        task->auth_xform.next = &task->cipher_xform;
        task->auth_xform.auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;
        task->auth_xform.auth.algo = RTE_CRYPTO_AUTH_SHA1_HMAC;
        task->auth_xform.auth.key.length = DIGEST_BYTE_LENGTH_SHA1;
        task->auth_xform.auth.key.data = hmac_sha1_key;
        task->auth_xform.auth.digest_length = DIGEST_BYTE_LENGTH_SHA1;

        rte_cryptodev_queue_pair_setup(task->crypto_dev_id, 1, &ts_params->qp_conf, rte_cryptodev_socket_id(task->crypto_dev_id));

        struct rte_cryptodev *dev;
        dev = rte_cryptodev_pmd_get_dev(task->crypto_dev_id);
        PROX_PANIC(dev->attached != RTE_CRYPTODEV_ATTACHED, "No DEC cryptodev attached\n");

        ts_params->qp_conf.nb_descriptors = 128;

        task->sess = rte_cryptodev_sym_session_create(task->crypto_dev_id, &task->auth_xform);
        PROX_PANIC(task->sess == NULL, "Failed to create DEC session\n");

        if (rte_crypto_op_bulk_alloc(ts_params->mbuf_ol_pool_dec,
                     RTE_CRYPTO_OP_TYPE_SYMMETRIC,
                     task->ops_burst, MAX_PKT_BURST) != MAX_PKT_BURST) {
                PROX_PANIC(1, "Failed to allocate DEC crypto operations\n");
        }
        //to clean up after rte_crypto_op_bulk_alloc:
        //for (int j = 0; j < MAX_PKT_BURST; j++) {
        //    rte_crypto_op_free(task->ops_burst[j]);
        //}

        struct prox_port_cfg *port = find_reachable_port(targ);
        memcpy(&task->local_mac, &port->eth_addr, sizeof(struct ether_addr));

// FIXME debug data
        for (i = 0; i < 16; i++) task->key[i] = i+2;
        for (i = 0; i < 16; i++) task->iv[i] = i;
}

static inline uint8_t handle_esp_ah_enc(struct task_esp_enc *task, struct rte_mbuf *mbuf, struct rte_crypto_op *cop)
{
        u8 *data;
        struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
        struct ipv4_hdr* pip4 = (struct ipv4_hdr *)(peth + 1);
        uint16_t ipv4_length = rte_be_to_cpu_16(pip4->total_length);
        struct rte_crypto_sym_op *sym_cop = get_sym_cop(cop);

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
        if ((encrypt_len & 0xf) != 0)
        {
                padding = 16 - (encrypt_len % 16);
                encrypt_len += padding;
        }

        // Encapsulate, crypt in a separate buffer
        const int extra_space = sizeof(struct ipv4_hdr) + 4 + 4 + CIPHER_IV_LENGTH_AES_CBC; // + new IP header, SPI, SN, IV
        struct ether_addr src_mac  = peth->s_addr;
        struct ether_addr dst_mac  = peth->d_addr;
        uint32_t          src_addr = pip4->src_addr;
        uint32_t          dst_addr = pip4->dst_addr;
        uint8_t           version_ihl = pip4->version_ihl;

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
        ether_addr_copy(&dst_mac, &peth->d_addr);//IS: dstmac should be rewritten by arp
#endif

        pip4 = (struct ipv4_hdr *)(peth + 1);
        pip4->src_addr = task->local_ipv4;
        pip4->dst_addr = task->remote_ipv4;
        pip4->next_proto_id = IPPROTO_ESP; // 50 for ESP, ip in ip next proto trailer
        pip4->version_ihl = version_ihl; // 20 bytes, ipv4
        pip4->total_length = rte_cpu_to_be_16(ipv4_length + sizeof(struct ipv4_hdr) + 4 + 4 + CIPHER_IV_LENGTH_AES_CBC + padding + 1 + 1 + DIGEST_BYTE_LENGTH_SHA1); // iphdr+SPI+SN+IV+payload+padding+padlen+next header + crc + auth
        pip4->packet_id = 0x0101;
        pip4->type_of_service = 0;
        pip4->time_to_live = 64;
        pip4->fragment_offset = rte_cpu_to_be_16(0x4000);
	pip4->hdr_checksum = 0;
        prox_ip_cksum_sw(pip4);

        //find the SA when there will be more than one
        if (task->ipaddr == pip4->src_addr)
        {
        }
        data = (u8*)(pip4 + 1);
        *((u32*) data) = 0x2016; // FIXME SPI
        *((u32*) data + 1) = 0x2; // FIXME SN
        u8 *padl = (u8*)data + (8 + encrypt_len - 2 + CIPHER_IV_LENGTH_AES_CBC); // No ESN yet. (-2 means NH is crypted)
        //padl += CIPHER_IV_LENGTH_AES_CBC;
        *padl = padding;
        *(padl + 1) = 4; // ipv4 in 4

        //one key for them all for now
        rte_crypto_op_attach_sym_session(cop, task->sess);

        sym_cop->auth.digest.data = data + 8 + CIPHER_IV_LENGTH_AES_CBC + encrypt_len;
        sym_cop->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(mbuf, (sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr) + 8 + CIPHER_IV_LENGTH_AES_CBC + encrypt_len));
        sym_cop->auth.digest.length = DIGEST_BYTE_LENGTH_SHA1;

        sym_cop->cipher.iv.data = data + 8;
        sym_cop->cipher.iv.phys_addr = rte_pktmbuf_mtophys(mbuf) + sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr) + 4 + 4;
        sym_cop->cipher.iv.length = CIPHER_IV_LENGTH_AES_CBC;

        rte_memcpy(sym_cop->cipher.iv.data, aes_cbc_iv, CIPHER_IV_LENGTH_AES_CBC);

        sym_cop->cipher.data.offset = sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr) + 4 + 4 + CIPHER_IV_LENGTH_AES_CBC;
        sym_cop->cipher.data.length = encrypt_len;

        sym_cop->auth.data.offset = sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr);
        sym_cop->auth.data.length = 4 + 4 + CIPHER_IV_LENGTH_AES_CBC + encrypt_len ;// + 4;// FIXME

        sym_cop->m_src = mbuf;
        //cop->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
        //cop->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;

        return 0;
}

static inline uint8_t handle_esp_ah_dec(struct task_esp_dec *task, struct rte_mbuf *mbuf, struct rte_crypto_op *cop)
{
        struct rte_crypto_sym_op *sym_cop = get_sym_cop(cop);
        struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
        struct ipv4_hdr* pip4 = (struct ipv4_hdr *)(peth + 1);
        uint16_t ipv4_length = rte_be_to_cpu_16(pip4->total_length);
        u8 *data = (u8*)(pip4 + 1);
        //find the SA
        if (pip4->next_proto_id != IPPROTO_ESP)
        {
                plog_info("Received non ESP packet on esp dec\n");
                plogdx_info(mbuf, "DEC RX: ");
                return OUT_DISCARD;
        }
        if (task->ipaddr == pip4->src_addr)
        {
        }

        rte_crypto_op_attach_sym_session(cop, task->sess);

        sym_cop->auth.digest.data = (unsigned char *)((unsigned char*)pip4 + ipv4_length - DIGEST_BYTE_LENGTH_SHA1);
        sym_cop->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(mbuf, sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr) + 4 + 4); // FIXME
        sym_cop->auth.digest.length = DIGEST_BYTE_LENGTH_SHA1;

        sym_cop->cipher.iv.data = (uint8_t *)data + 8;
        sym_cop->cipher.iv.phys_addr = rte_pktmbuf_mtophys(mbuf) + sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr) + 4 + 4;
        sym_cop->cipher.iv.length = CIPHER_IV_LENGTH_AES_CBC;

        sym_cop->auth.data.offset = sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr);
        sym_cop->auth.data.length = ipv4_length - sizeof(struct ipv4_hdr) - 4 - CIPHER_IV_LENGTH_AES_CBC;

        sym_cop->cipher.data.offset = sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr) + 4 + 4 + CIPHER_IV_LENGTH_AES_CBC;
        sym_cop->cipher.data.length = ipv4_length - sizeof(struct ipv4_hdr) - CIPHER_IV_LENGTH_AES_CBC - 28; // FIXME

        sym_cop->m_src = mbuf;
        return 0;
}

static inline void do_ipv4_swap(struct task_esp_dec *task, struct rte_mbuf *mbuf)
{
        struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
        struct ether_addr src_mac  = peth->s_addr;
        struct ether_addr dst_mac  = peth->d_addr;
        uint32_t src_ip, dst_ip;

        struct ipv4_hdr* pip4 = (struct ipv4_hdr *)(peth + 1);
        src_ip = pip4->src_addr;
        dst_ip = pip4->dst_addr;

        //peth->s_addr = dst_mac;
        peth->d_addr = src_mac;//should be replaced by arp
        //pip4->src_addr = dst_ip;
        pip4->dst_addr = src_ip;
        ether_addr_copy(&task->local_mac, &peth->s_addr);
}

static inline uint8_t handle_esp_ah_dec_finish(struct task_esp_dec *task, struct rte_mbuf *mbuf)
{
        struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
        rte_memcpy(((u8*)peth) + sizeof (struct ether_hdr), ((u8*)peth) + sizeof (struct ether_hdr) +
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
        rte_memcpy(((u8*)peth) + sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr),
                   ((u8*)peth) + sizeof (struct ether_hdr) +
                        + 2 * sizeof(struct ipv4_hdr) + 4 + 4 + CIPHER_IV_LENGTH_AES_CBC, ipv4_length - sizeof(struct ipv4_hdr));

        int len = rte_pktmbuf_pkt_len(mbuf);
        rte_pktmbuf_trim(mbuf, len - sizeof (struct ether_hdr) - ipv4_length);
#if 1
        do_ipv4_swap(task, mbuf);
#endif
        pip4->hdr_checksum = 0;
        prox_ip_cksum_sw(pip4);
//              one key for them all for now
//              set key
//      struct crypto_aes_ctx ctx;
//      ctx.iv = (u8*)&iv_onstack;
//      *((u32*)ctx.iv) = *((u32*)data + 2);
//      aes_set_key(&ctx, task->key, 16);//
//
//      result = ctr_crypt(&ctx, dest, data + 12, len);//
//      memcpy(pip4, dest, len);

        return 0;
}

static int handle_esp_enc_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
        struct task_esp_enc *task = (struct task_esp_enc *)tbase;
        struct crypto_testsuite_params *ts_params = &testsuite_params;
        uint8_t out[MAX_PKT_BURST];
        uint16_t i = 0, nb_rx = 0, nb_enc=0, j = 0;

        for (uint16_t j = 0; j < n_pkts; ++j) {
                out[j] = handle_esp_ah_enc(task, mbufs[j], task->ops_burst[nb_enc]);
                if (out[j] != OUT_DISCARD)
                        ++nb_enc;
        }

        if (rte_cryptodev_enqueue_burst(task->crypto_dev_id, 0, task->ops_burst, nb_enc) != nb_enc) {
                plog_info("Error enc enqueue_burst\n");
                return -1;
        }

        //do not call rte_cryptodev_dequeue_burst() on already dequeued packets
        //otherwise handle_completed_jobs() screws up the content of the ops_burst array!
        do {
                nb_rx = rte_cryptodev_dequeue_burst(
                                   task->crypto_dev_id, 0,// FIXME AK
                                   task->ops_burst+i, nb_enc-i);
                i += nb_rx;
        } while (i < nb_enc);

        return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static int handle_esp_dec_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
        struct task_esp_dec *task = (struct task_esp_dec *)tbase;
        struct crypto_testsuite_params *ts_params = &testsuite_params;
        uint8_t out[MAX_PKT_BURST];
        uint16_t j, nb_dec=0, nb_rx=0;

        for (j = 0; j < n_pkts; ++j) {
                out[j] = handle_esp_ah_dec(task, mbufs[j], task->ops_burst[nb_dec]);
                if (out[j] != OUT_DISCARD)
                        ++nb_dec;
        }

        if (rte_cryptodev_enqueue_burst(task->crypto_dev_id, 1, task->ops_burst, nb_dec) != nb_dec) {
                plog_info("Error dec enqueue_burst\n");
                return -1;
        }

        j=0;
        do {
                nb_rx = rte_cryptodev_dequeue_burst(task->crypto_dev_id, 1,// FIXME AK
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
                        handle_esp_ah_dec_finish(task, mbuf);//TODO set out[j] properly
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
        .mbuf_size = 2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM
};

struct task_init task_init_esp_dec = {
        .mode = ESP_ENC,
        .mode_str = "esp_dec",
        .init = init_task_esp_dec,
        .handle = handle_esp_dec_bulk,
        .size = sizeof(struct task_esp_dec),
        .mbuf_size = 2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM
};

__attribute__((constructor)) static void reg_task_esp_enc(void)
{
        reg_task(&task_init_esp_enc);
}

__attribute__((constructor)) static void reg_task_esp_dec(void)
{
        reg_task(&task_init_esp_dec);
}
