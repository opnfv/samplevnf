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

#ifndef _LOG_H_
#define _LOG_H_

#define PROX_LOG_ERR  0
#define PROX_LOG_WARN 1
#define PROX_LOG_INFO 2
#define PROX_LOG_DBG  3

#if PROX_MAX_LOG_LVL > PROX_LOG_DBG
#error Highest supported log level is 3
#endif

int get_n_warnings(void);
/* Return previous warnings, only stores last 5 warnings and invalid i return NULL*/
const char* get_warning(int i);

struct rte_mbuf;

#if PROX_MAX_LOG_LVL >= PROX_LOG_ERR
int plog_err(const char *fmt, ...) __attribute__((format(printf, 1, 2), cold));
int plogx_err(const char *fmt, ...) __attribute__((format(printf, 1, 2), cold));
int plogd_err(const struct rte_mbuf *mbuf, const char *fmt, ...) __attribute__((format(printf, 2, 3), cold));
int plogdx_err(const struct rte_mbuf *mbuf, const char *fmt, ...) __attribute__((format(printf, 2, 3), cold));
#else
__attribute__((format(printf, 1, 2))) static inline int plog_err(__attribute__((unused)) const char *fmt, ...) {return 0;}
__attribute__((format(printf, 1, 2))) static inline int plogx_err(__attribute__((unused)) const char *fmt, ...) {return 0;}
__attribute__((format(printf, 2, 3))) static inline int plogd_err(__attribute__((unused)) const struct rte_mbuf *mbuf, __attribute__((unused)) const char *fmt, ...) {return 0;}
__attribute__((format(printf, 2, 3))) static inline int plogdx_err(__attribute__((unused)) const struct rte_mbuf *mbuf, __attribute__((unused)) const char *fmt, ...) {return 0;}
#endif

#if PROX_MAX_LOG_LVL >= PROX_LOG_WARN
int plog_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2), cold));
int plogx_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2), cold));
int plogd_warn(const struct rte_mbuf *mbuf, const char *fmt, ...) __attribute__((format(printf, 2, 3), cold));
int plogdx_warn(const struct rte_mbuf *mbuf, const char *fmt, ...) __attribute__((format(printf, 2, 3), cold));
#else
__attribute__((format(printf, 1, 2))) static inline int plog_warn(__attribute__((unused)) const char *fmt, ...) {return 0;}
__attribute__((format(printf, 1, 2))) static inline int plogx_warn(__attribute__((unused)) const char *fmt, ...) {return 0;}
__attribute__((format(printf, 2, 3))) static inline int plogd_warn(__attribute__((unused)) const struct rte_mbuf *mbuf, __attribute__((unused)) const char *fmt, ...) {return 0;}
__attribute__((format(printf, 2, 3))) static inline int plogdx_warn(__attribute__((unused)) const struct rte_mbuf *mbuf, __attribute__((unused)) const char *fmt, ...) {return 0;}
#endif

#if PROX_MAX_LOG_LVL >= PROX_LOG_INFO
int plog_info(const char *fmt, ...) __attribute__((format(printf, 1, 2), cold));
int plogx_info(const char *fmt, ...) __attribute__((format(printf, 1, 2), cold));
int plogd_info(const struct rte_mbuf *mbuf, const char *fmt, ...) __attribute__((format(printf, 2, 3), cold));
int plogdx_info(const struct rte_mbuf *mbuf, const char *fmt, ...) __attribute__((format(printf, 2, 3), cold));
#else
__attribute__((format(printf, 1, 2))) static inline int plog_info(__attribute__((unused)) const char *fmt, ...) {return 0;}
__attribute__((format(printf, 1, 2))) static inline int plogx_info(__attribute__((unused)) const char *fmt, ...) {return 0;}
__attribute__((format(printf, 2, 3))) static inline int plogd_info(__attribute__((unused)) const struct rte_mbuf *mbuf, __attribute__((unused)) const char *fmt, ...) {return 0;}
__attribute__((format(printf, 2, 3))) static inline int plogdx_info(__attribute__((unused)) const struct rte_mbuf *mbuf, __attribute__((unused)) const char *fmt, ...) {return 0;}
#endif

#if PROX_MAX_LOG_LVL >= PROX_LOG_DBG
int plog_dbg(const char *fmt, ...) __attribute__((format(printf, 1, 2), cold));
int plogx_dbg(const char *fmt, ...) __attribute__((format(printf, 1, 2), cold));
int plogd_dbg(const struct rte_mbuf *mbuf, const char *fmt, ...) __attribute__((format(printf, 2, 3), cold));
int plogdx_dbg(const struct rte_mbuf *mbuf, const char *fmt, ...) __attribute__((format(printf, 2, 3), cold));
#else
__attribute__((format(printf, 1, 2))) static inline int plog_dbg(__attribute__((unused)) const char *fmt, ...) {return 0;}
__attribute__((format(printf, 1, 2))) static inline int plogx_dbg(__attribute__((unused)) const char *fmt, ...) {return 0;}
__attribute__((format(printf, 2, 3))) static inline int plogd_dbg(__attribute__((unused)) const struct rte_mbuf *mbuf, __attribute__((unused)) const char *fmt, ...) {return 0;}
__attribute__((format(printf, 2, 3))) static inline int plogdx_dbg(__attribute__((unused)) const struct rte_mbuf *mbuf, __attribute__((unused)) const char *fmt, ...) {return 0;}
#endif

void plog_init(const char *log_name, int log_name_pid);
void file_print(const char *str);

int plog_set_lvl(int lvl);

#endif /* _LOG_H_ */
