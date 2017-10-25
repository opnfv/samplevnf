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

#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include "log.h"
#include "display.h"
#include "defaults.h"
#include "etypes.h"
#include "prox_cfg.h"

static pthread_mutex_t file_mtx = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
int log_lvl = PROX_MAX_LOG_LVL;
static uint64_t tsc_off;
static FILE *fp;
static int n_warnings = 0;
char last_warn[5][1024];
int get_n_warnings(void)
{
#if PROX_MAX_LOG_LVL < PROX_LOG_WARN
	return -1;
#endif
	return n_warnings;
}

const char *get_warning(int i)
{
#if PROX_MAX_LOG_LVL < PROX_LOG_WARN
	return NULL;
#endif
	if (i > 0 || i < -4)
		return NULL;
	return last_warn[(n_warnings - 1 + i + 5) % 5];
}

static void store_warning(const char *warning)
{
	strncpy(last_warn[n_warnings % 5], warning, sizeof(last_warn[0]));
	n_warnings++;
}

void plog_init(const char *log_name, int log_name_pid)
{
	pid_t pid;
	char buf[128];

	if (*log_name == 0) {
		if (log_name_pid)
			snprintf(buf, sizeof(buf), "%s-%u.log", "prox", getpid());
		else
			strncpy(buf, "prox.log", sizeof(buf));
	}
	else {
		strncpy(buf, log_name, sizeof(buf));
	}

	fp = fopen(buf, "w");

	tsc_off = rte_rdtsc() + 2500000000;
}

int plog_set_lvl(int lvl)
{
	if (lvl <= PROX_MAX_LOG_LVL) {
		log_lvl = lvl;
		return 0;
	}

	return -1;
}

static void file_lock(void)
{
	pthread_mutex_lock(&file_mtx);
}

static void file_unlock(void)
{
	pthread_mutex_unlock(&file_mtx);
}

void file_print(const char *str)
{
	file_lock();
	if (fp != NULL) {
		fputs(str, fp);
		fflush(fp);
	}
	file_unlock();
}
static void plog_buf(const char* buf)
{
	if (prox_cfg.logbuf) {
		file_lock();
		if (prox_cfg.logbuf_pos + strlen(buf) + 1 < prox_cfg.logbuf_size) {
			memcpy(prox_cfg.logbuf + prox_cfg.logbuf_pos, buf, strlen(buf));
			prox_cfg.logbuf_pos += strlen(buf);
		}
		file_unlock();
	} else {
		file_print(buf);
#ifdef PROX_STATS
		display_print(buf);
#else
	/* ncurses never initialized */
		fputs(buf, stdout);
		fflush(stdout);
#endif
	}
}

static const char* lvl_to_str(int lvl, int always)
{
	switch (lvl) {
	case PROX_LOG_ERR:  return "error ";
	case PROX_LOG_WARN: return "warn ";
	case PROX_LOG_INFO: return always? "info " : "";
	case PROX_LOG_DBG:  return "debug ";
	default: return "?";
	}
}

static	int dump_pkt(char *dst, size_t dst_size, const struct rte_mbuf *mbuf)
{
	const struct ether_hdr *peth = rte_pktmbuf_mtod(mbuf, const struct ether_hdr *);
	const struct ipv4_hdr *dpip = (const struct ipv4_hdr *)(peth + 1);
	const uint8_t *pkt_bytes = (const uint8_t *)peth;
	const uint16_t len = rte_pktmbuf_pkt_len(mbuf);
	size_t str_len = 0;

	if (peth->ether_type == ETYPE_IPv4)
		str_len = snprintf(dst, dst_size, "pkt_len=%u, Eth=%x, Proto=%#06x",
			   	len, peth->ether_type, dpip->next_proto_id);
	else
		str_len = snprintf(dst, dst_size, "pkt_len=%u, Eth=%x",
				len, peth->ether_type);

	for (uint16_t i = 0; i < len && i < DUMP_PKT_LEN && str_len < dst_size; ++i) {
		if (i % 16 == 0) {
			str_len += snprintf(dst + str_len, dst_size - str_len, "\n%04x  ", i);
		}
		else if (i % 8 == 0) {
			str_len += snprintf(dst + str_len, dst_size - str_len, " ");
		}
		str_len += snprintf(dst + str_len, dst_size - str_len, "%02x ", pkt_bytes[i]);
	}
	if (str_len < dst_size)
		snprintf(dst + str_len, dst_size - str_len, "\n");
	return str_len + 1;
}

static int vplog(int lvl, const char *format, va_list ap, const struct rte_mbuf *mbuf, int extended)
{
	char buf[32768];
	uint64_t hz, rtime_tsc, rtime_sec, rtime_usec;
	int ret = 0;

	if (lvl > log_lvl)
		return ret;

	if (format == NULL && mbuf == NULL)
		return ret;

	*buf = 0;
	if (extended) {
		hz = rte_get_tsc_hz();
		rtime_tsc = rte_rdtsc() - tsc_off;
		rtime_sec = rtime_tsc / hz;
		rtime_usec = (rtime_tsc - rtime_sec * hz) / (hz / 1000000);
		ret += snprintf(buf, sizeof(buf) - ret, "%2"PRIu64".%06"PRIu64" C%u %s%s",
				rtime_sec, rtime_usec, rte_lcore_id(), lvl_to_str(lvl, 1), format? " " : "");
	}
	else {
		ret += snprintf(buf, sizeof(buf) - ret, "%s%s", lvl_to_str(lvl, 0), format? " " : "");
	}

	if (format) {
		ret--;
		ret += vsnprintf(buf + ret, sizeof(buf) - ret, format, ap);
	}

	if (mbuf) {
		ret--;
		ret += dump_pkt(buf + ret, sizeof(buf) - ret, mbuf);
	}
	plog_buf(buf);

	if (lvl == PROX_LOG_WARN) {
		store_warning(buf);
	}
	return ret;
}

#if PROX_MAX_LOG_LVL >= PROX_LOG_INFO
int plog_info(const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vplog(PROX_LOG_INFO, fmt, ap, NULL, 0);
	va_end(ap);
	return ret;
}

int plogx_info(const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vplog(PROX_LOG_INFO, fmt, ap, NULL, 1);
	va_end(ap);
	return ret;
}

int plogd_info(const struct rte_mbuf *mbuf, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vplog(PROX_LOG_INFO, fmt, ap, mbuf, 0);
	va_end(ap);
	return ret;
}

int plogdx_info(const struct rte_mbuf *mbuf, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vplog(PROX_LOG_INFO, fmt, ap, mbuf, 1);
	va_end(ap);
	return ret;
}
#endif

#if PROX_MAX_LOG_LVL >= PROX_LOG_ERR
int plog_err(const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vplog(PROX_LOG_ERR, fmt, ap, NULL, 0);
	va_end(ap);
	return ret;
}

int plogx_err(const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vplog(PROX_LOG_ERR, fmt, ap, NULL, 1);
	va_end(ap);
	return ret;
}

int plogd_err(const struct rte_mbuf *mbuf, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vplog(PROX_LOG_ERR, fmt, ap, mbuf, 1);
	va_end(ap);
	return ret;
}

int plogdx_err(const struct rte_mbuf *mbuf, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vplog(PROX_LOG_ERR, fmt, ap, mbuf, 1);
	va_end(ap);

	return ret;
}
#endif

#if PROX_MAX_LOG_LVL >= PROX_LOG_WARN
int plog_warn(const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vplog(PROX_LOG_WARN, fmt, ap, NULL, 0);
	va_end(ap);
	return ret;
}

int plogx_warn(const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vplog(PROX_LOG_WARN, fmt, ap, NULL, 1);
	va_end(ap);
	return ret;
}

int plogd_warn(const struct rte_mbuf *mbuf, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vplog(PROX_LOG_WARN, fmt, ap, mbuf, 0);
	va_end(ap);
	return ret;
}

int plogdx_warn(const struct rte_mbuf *mbuf, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vplog(PROX_LOG_WARN, fmt, ap, mbuf, 1);
	va_end(ap);
	return ret;
}
#endif

#if PROX_MAX_LOG_LVL >= PROX_LOG_DBG
int plog_dbg(const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vplog(PROX_LOG_DBG, fmt, ap, NULL, 0);
	va_end(ap);
	return ret;
}

int plogx_dbg(const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vplog(PROX_LOG_DBG, fmt, ap, NULL, 1);
	va_end(ap);
	return ret;
}

int plogd_dbg(const struct rte_mbuf *mbuf, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vplog(PROX_LOG_DBG, fmt, ap, mbuf, 0);
	va_end(ap);
	return ret;
}

int plogdx_dbg(const struct rte_mbuf *mbuf, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vplog(PROX_LOG_DBG, fmt, ap, mbuf, 1);
	va_end(ap);
	return ret;
}
#endif
