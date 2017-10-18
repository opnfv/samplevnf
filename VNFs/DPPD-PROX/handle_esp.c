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

typedef unsigned int u32;
typedef unsigned char u8;
#define NUM_MBUFS                       (8191)
#define MBUF_CACHE_SIZE                 (250)

#define BYTE_LENGTH(x)                          (x/8)
#define DIGEST_BYTE_LENGTH_SHA1                 (BYTE_LENGTH(160))

#define CIPHER_KEY_LENGTH_AES_CBC       (32)
#define CIPHER_IV_LENGTH_AES_CBC        16

static inline void *get_sym_cop(struct rte_crypto_op *cop)
{
        return (cop + 1);
}

struct task_esp_enc {
        struct task_base    base;
        int crypto_dev_id;
        u8 iv[16];
        uint32_t                local_ipv4;
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

        uint16_t nb_queue_pairs;

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

static void init_task_esp_enc(struct task_base *tbase, __attribute__((unused)) struct task_args *targ)
{
        int i, nb_devs, valid_dev_id = 0;
        uint16_t qp_id;
        struct crypto_testsuite_params *ts_params = &testsuite_params;
        struct rte_cryptodev_info info;

        tbase->flags |= FLAG_NEVER_FLUSH;

        ts_params->mbuf_ol_pool_enc = rte_crypto_op_pool_create("crypto_op_pool_enc",
                        RTE_CRYPTO_OP_TYPE_SYMMETRIC, (2*1024*1024), 128, 0,
                        rte_socket_id());

        struct task_esp_enc *task = (struct task_esp_enc *)tbase;
        task->crypto_dev_id = rte_vdev_init(RTE_STR(CRYPTODEV_NAME_AESNI_MB_PMD), NULL);
        nb_devs = rte_cryptodev_count_devtype(RTE_CRYPTODEV_AESNI_MB_PMD);

        if (nb_devs < 1) {
                RTE_LOG(ERR, USER1, "No crypto devices found?");
                exit(-1);
        }

        /* Search for the first valid */
        for (i = 0; i < nb_devs; i++) {
                rte_cryptodev_info_get(i, &info);
                if (info.dev_type == gbl_cryptodev_preftest_devtype) {
                        task->crypto_dev_id = i;
                        valid_dev_id = 1;
                        break;
                }
        }

        if (!valid_dev_id)
        {
                RTE_LOG(ERR, USER1, "invalid crypto devices found?");
                return ;
        }

        /*
 *          * Since we can't free and re-allocate queue memory always set the queues
 *                   * on this device up to max size first so enough memory is allocated for
 *                            * any later re-configures needed by other tests */

        ts_params->conf.nb_queue_pairs = 2;
        ts_params->conf.socket_id = SOCKET_ID_ANY;
        ts_params->conf.session_mp.nb_objs = 2048;
        ts_params->qp_conf.nb_descriptors = 4096;

        /*Now reconfigure queues to size we actually want to use in this testsuite.*/
        ts_params->qp_conf.nb_descriptors = 128;
        rte_cryptodev_configure(task->crypto_dev_id, &ts_params->conf);
        rte_cryptodev_queue_pair_setup(task->crypto_dev_id, 0,
                                &ts_params->qp_conf, rte_cryptodev_socket_id(task->crypto_dev_id));
        rte_cryptodev_configure(task->crypto_dev_id, &ts_params->conf);

       struct rte_cryptodev *dev;

        dev = rte_cryptodev_pmd_get_dev(task->crypto_dev_id);
        if (dev->attached != RTE_CRYPTODEV_ATTACHED)
                return ;

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

        /* Create Crypto session*/
        task->sess = rte_cryptodev_sym_session_create(task->crypto_dev_id, &task->cipher_xform);
        if (task->sess == NULL)
        {
                printf("not ok\n");
                return ;
        }

        // Read config file with SAs
        task->local_ipv4 = targ->local_ipv4;
        task->remote_ipv4 = targ->remote_ipv4;

        for (i = 0; i < 16; i++) task->key[i] = i+2;
        for (i = 0; i < 16; i++) task->iv[i] = i;
}

static void init_task_esp_dec(struct task_base *tbase, __attribute__((unused)) struct task_args *targ)
{
        int i;
        struct crypto_testsuite_params *ts_params = &testsuite_params;
        tbase->flags |= FLAG_NEVER_FLUSH;
        ts_params->mbuf_ol_pool_dec = rte_crypto_op_pool_create("crypto_op_pool_dec",
                        RTE_CRYPTO_OP_TYPE_SYMMETRIC, (2*1024*1024), 128, 0,
                        rte_socket_id());
        if (ts_params->mbuf_ol_pool_dec == NULL) {
                RTE_LOG(ERR, USER1, "Can't create CRYPTO_OP_POOL\n");
                exit(-1);
        }

        static struct rte_cryptodev_session *sess_dec = NULL;
        // Read config file with SAs
        struct task_esp_dec *task = (struct task_esp_dec *)tbase;
        task->local_ipv4 = targ->local_ipv4;

        task->cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
        task->cipher_xform.next = NULL;
        task->cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_AES_CBC;
        task->cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
        task->cipher_xform.cipher.key.data = aes_cbc_key;
        task->cipher_xform.cipher.key.length = CIPHER_KEY_LENGTH_AES_CBC;

        /* Setup HMAC Parameters */
        struct rte_crypto_sym_xform auth_xform;
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
        if (dev->attached != RTE_CRYPTODEV_ATTACHED)
                return ;

        ts_params->qp_conf.nb_descriptors = 128;

        rte_cryptodev_stats_reset(task->crypto_dev_id);

        task->sess = rte_cryptodev_sym_session_create(task->crypto_dev_id, &task->auth_xform);
        if (task->sess == NULL)
        {
                printf("not ok dec\n");
                        return ;
        }
        rte_cryptodev_stats_reset(task->crypto_dev_id);
        rte_cryptodev_start(task->crypto_dev_id);

// FIXME debug data
        for (i = 0; i < 16; i++) task->key[i] = i+2;
        for (i = 0; i < 16; i++) task->iv[i] = i;
}

static uint8_t aes_cbc_iv[] = {
        0xE4, 0x23, 0x33, 0x8A, 0x35, 0x64, 0x61, 0xE2,
        0x49, 0x03, 0xDD, 0xC6, 0xB8, 0xCA, 0x55, 0x7A };

static int enqueue_crypto_request(struct task_esp_enc *task, struct rte_crypto_op *cop, int dir)
{
        if (rte_cryptodev_enqueue_burst(task->crypto_dev_id, dir, &cop, 1) != 1) {
             //   printf("Error sending packet for encryption");
                return -1;
        }

        return 0;
}

static int debug_counter = 0;
static inline uint8_t handle_esp_ah_enc(struct task_esp_enc *task, struct rte_mbuf *mbuf, struct rte_crypto_op *cop)
{
        struct crypto_testsuite_params *ts_params = &testsuite_params;
        debug_counter++;
        int result;
        u8 dest[8192]; // scratch buf, maximum packet
        u8 *data;
        struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
        struct ipv4_hdr* pip4 = (struct ipv4_hdr *)(peth + 1);
        uint16_t ipv4_length = rte_be_to_cpu_16(pip4->total_length);
        struct rte_crypto_sym_op *sym_cop = get_sym_cop(cop);

        if (unlikely((pip4->version_ihl >> 4) != 4)) {
                plog_info("Received non IPv4 packet at esp tunnel input %i\n", pip4->version_ihl);
                // Drop packet
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
        // now add padding
                padding = 16 - (encrypt_len % 16);
                encrypt_len += padding;
        }

        // Encapsulate, crypt in a separate buffer
//      memcpy(dest, pip4, encrypt_len);
        const int extra_space = sizeof(struct ipv4_hdr) + 4 + 4 + CIPHER_IV_LENGTH_AES_CBC; // + new IP header, SPI, SN, IV
        struct ether_addr src_mac  = peth->s_addr;
        struct ether_addr dst_mac  = peth->d_addr;
        uint32_t          src_addr = pip4->src_addr;
        uint32_t          dst_addr = pip4->dst_addr;
        uint8_t           ttl      = pip4->time_to_live;
        uint8_t           version_ihl = pip4->version_ihl;

        peth = (struct ether_hdr *)rte_pktmbuf_prepend(mbuf, extra_space); // encap + prefix
        peth = (struct ether_hdr *)rte_pktmbuf_append(mbuf, 0 + 1 + 1 + padding + 4 + DIGEST_BYTE_LENGTH_SHA1); // padding + pad_len + next_head + seqn + ICV pad + ICV
        peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
        l1 = rte_pktmbuf_pkt_len(mbuf);
        peth->ether_type = ETYPE_IPv4;
        ether_addr_copy(&src_mac, &peth->s_addr);
        ether_addr_copy(&dst_mac, &peth->d_addr);

        pip4 = (struct ipv4_hdr *)(peth + 1);
        pip4->src_addr = task->local_ipv4;
        pip4->dst_addr = task->remote_ipv4;
        pip4->time_to_live = ttl;
        pip4->next_proto_id = 50; // 50 for ESP, ip in ip next proto trailer
        pip4->version_ihl = version_ihl; // 20 bytes, ipv4
        pip4->total_length = rte_cpu_to_be_16(ipv4_length + sizeof(struct ipv4_hdr) + 4 + 4 + CIPHER_IV_LENGTH_AES_CBC + padding + 1 + 1 + DIGEST_BYTE_LENGTH_SHA1); // iphdr+SPI+SN+IV+payload+padding+padlen+next header + crc + auth
        prox_ip_cksum_sw(pip4);

//      find the SA when there will be more than one
        if (task->ipaddr == pip4->src_addr)
        {
        }
        data = (u8*)(pip4 + 1);
        *((u32*) data) = 0x2016; // FIXME SPI
        *((u32*) data + 1) = 0x2; // FIXME SN
        u8 *padl = (u8*)data + (8 + encrypt_len - 2 + CIPHER_IV_LENGTH_AES_CBC); // No ESN yet. (-2 means NH is crypted)
//      padl += CIPHER_IV_LENGTH_AES_CBC;
        *padl = padding;
        *(padl + 1) = 4; // ipv4 in 4

//              one key for them all for now
        rte_crypto_op_attach_sym_session(cop, task->sess);

        sym_cop->auth.digest.data = data + 8 + CIPHER_IV_LENGTH_AES_CBC + encrypt_len + 2;
        sym_cop->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(mbuf, (sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr) + 8 + CIPHER_IV_LENGTH_AES_CBC + encrypt_len + 2));
        sym_cop->auth.digest.length = DIGEST_BYTE_LENGTH_SHA1;

        sym_cop->cipher.iv.data = data + 8;
        sym_cop->cipher.iv.phys_addr = rte_pktmbuf_mtophys(mbuf) + sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr) + 4 + 4;
        sym_cop->cipher.iv.length = CIPHER_IV_LENGTH_AES_CBC;

        rte_memcpy(sym_cop->cipher.iv.data, aes_cbc_iv, CIPHER_IV_LENGTH_AES_CBC);

        sym_cop->cipher.data.offset = sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr) + 4 + 4 + CIPHER_IV_LENGTH_AES_CBC;
        sym_cop->cipher.data.length = encrypt_len;

        sym_cop->auth.data.offset = sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr);
        sym_cop->auth.data.length = 4 + 4 + CIPHER_IV_LENGTH_AES_CBC + encrypt_len ;// + 4;// FIXME

        /* Process crypto operation */
        sym_cop->m_src = mbuf;
        return enqueue_crypto_request(task, cop, 0);
}

static inline uint8_t handle_esp_ah_dec(struct task_esp_dec *task, struct rte_mbuf *mbuf, struct rte_crypto_op *cop)
{
        struct crypto_testsuite_params *ts_params = &testsuite_params;
debug_counter++;
        struct rte_crypto_sym_op *sym_cop = get_sym_cop(cop);
        int result;
        struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
        struct ipv4_hdr* pip4 = (struct ipv4_hdr *)(peth + 1);
        uint16_t ipv4_length = rte_be_to_cpu_16(pip4->total_length);
        int l1 = rte_pktmbuf_pkt_len(mbuf);
        u32 iv_onstack;
        u8 *data = (u8*)(pip4 + 1);
//              find the SA
        if (pip4->next_proto_id != 50)
        {
                plog_info("Received non ip in ip tunnel packet esp tunnel output\n");
                return OUT_DISCARD;//NO_PORT_AVAIL;
        }
        if (task->ipaddr == pip4->src_addr)
        {
        }

        /* Create Crypto session*/
        rte_crypto_op_attach_sym_session(cop, task->sess);

        sym_cop->auth.digest.data = (unsigned char *)((unsigned char*)pip4 + ipv4_length - 20);
        sym_cop->auth.digest.phys_addr = rte_pktmbuf_mtophys_offset(mbuf, sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr) + 4 + 4); // FIXME
        sym_cop->auth.digest.length = DIGEST_BYTE_LENGTH_SHA1;

        sym_cop->cipher.iv.data = (uint8_t *)data + 8;
        sym_cop->cipher.iv.phys_addr = rte_pktmbuf_mtophys(mbuf) + sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr) + 4 + 4;
        sym_cop->cipher.iv.length = CIPHER_IV_LENGTH_AES_CBC;

        sym_cop->auth.data.offset = sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr);
        sym_cop->auth.data.length = ipv4_length - sizeof(struct ipv4_hdr) - 4 - CIPHER_IV_LENGTH_AES_CBC;

        sym_cop->cipher.data.offset = sizeof (struct ether_hdr) + sizeof(struct ipv4_hdr) + 4 + 4 + CIPHER_IV_LENGTH_AES_CBC;
        sym_cop->cipher.data.length = ipv4_length - sizeof(struct ipv4_hdr) - CIPHER_IV_LENGTH_AES_CBC - 28; // FIXME

        /* Process crypto operation */
        sym_cop->m_src = mbuf;
        return enqueue_crypto_request((struct task_esp_enc *)task, cop, 1);
}

static inline uint8_t handle_esp_ah_dec_finish(struct task_esp_dec *task, struct rte_mbuf *mbuf, struct rte_crypto_op *cop)
{
        struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
        rte_memcpy(((u8*)peth) + sizeof (struct ether_hdr), ((u8*)peth) + sizeof (struct ether_hdr) +
                        + sizeof(struct ipv4_hdr) + 4 + 4 + CIPHER_IV_LENGTH_AES_CBC, sizeof(struct ipv4_hdr));// next hdr, padding
        struct ipv4_hdr* pip4 = (struct ipv4_hdr *)(peth + 1);
        if (unlikely((pip4->version_ihl >> 4) != 4)) {
                plog_info("Received non IPv4 packet at esp tunnel input %i\n", pip4->version_ihl);
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
        peth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

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

static void handle_esp_enc_bulk(__attribute__((unused)) struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
        struct task_esp_enc *task = (struct task_esp_enc *)tbase;
        struct crypto_testsuite_params *ts_params = &testsuite_params;
        uint8_t out[MAX_PKT_BURST];
        uint16_t i = 0, nb_rx = 0, j = 0;

        if (rte_crypto_op_bulk_alloc( ts_params->mbuf_ol_pool_enc,
                     RTE_CRYPTO_OP_TYPE_SYMMETRIC,
                     task->ops_burst, n_pkts) != n_pkts) {
                // FXIME AK shit..
                printf("out of memory\n");
                return;
        }

        for (uint16_t j = 0; j < n_pkts; ++j) {
                out[j] = handle_esp_ah_enc(task, mbufs[j], task->ops_burst[j]);
        }
        /* Dequeue packets from Crypto device */
        do {
            if (out[j] == 0)
                    nb_rx = rte_cryptodev_dequeue_burst(
                                   task->crypto_dev_id, 0,// FIXME AK
                                   task->ops_burst, n_pkts);

            i += nb_rx;
        } while (i < n_pkts);

        for (j = 0; j < n_pkts; j++) {
            rte_crypto_op_free(task->ops_burst[j]);
        }

        task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static void handle_esp_dec_bulk(__attribute__((unused)) struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
        uint8_t out[MAX_PKT_BURST];
        struct task_esp_dec *task = (struct task_esp_dec *)tbase;
        struct crypto_testsuite_params *ts_params = &testsuite_params;
//__itt_frame_begin_v3(pD, NULL);

        if (rte_crypto_op_bulk_alloc(
                     ts_params->mbuf_ol_pool_dec,
                     RTE_CRYPTO_OP_TYPE_SYMMETRIC,
                     task->ops_burst, n_pkts) !=
                                  n_pkts) {

                printf("out of memory\n");
                exit(-1);
        }
        uint16_t i = 0, nb_rx, j;

        for (uint16_t j = 0; j < n_pkts; ++j) {

                out[j] = handle_esp_ah_dec(task, mbufs[j], task->ops_burst[j]);
        }
        for (j = 0; j < n_pkts; j++) {
            rte_crypto_op_free(task->ops_burst[j]);
        }

        task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

struct task_init task_init_esp_enc = {
        .mode = ESP_ENC,
        .mode_str = "esp_enc",
        .init = init_task_esp_enc,
        .handle = handle_esp_enc_bulk,
        .size = sizeof(struct task_esp_enc)
};

struct task_init task_init_esp_dec = {
        .mode = ESP_ENC,
        .mode_str = "esp_dec",
        .init = init_task_esp_dec,
        .handle = handle_esp_dec_bulk,
        .size = sizeof(struct task_esp_dec)
};

__attribute__((constructor)) static void reg_task_esp_enc(void)
{
        reg_task(&task_init_esp_enc);
}

__attribute__((constructor)) static void reg_task_esp_dec(void)
{
        reg_task(&task_init_esp_dec);
}
