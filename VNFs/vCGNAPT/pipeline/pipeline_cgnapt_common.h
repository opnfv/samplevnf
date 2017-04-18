/*
// Copyright (c) 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef __INCLUDE_PIPELINE_CGNAPT_COMMON_H__
#define __INCLUDE_PIPELINE_CGNAPT_COMMON_H__

#include "pipeline_common_fe.h"

extern uint8_t CGNAPT_DEBUG;

struct pipeline_cgnapt_entry_key {
	uint32_t ip;
	uint16_t port;		/* L4 port */
	uint16_t pid;		/* if port id */
};

/*
 * CGNAPY Entry
 */
enum cgnapt_entry_type {
	CGNAPT_ENTRY_IPV4,
	CGNAPT_ENTRY_IPV6
};

#ifdef PCP_ENABLE
/**
 * An enum defining the CG-NAPT entry creation type
 */

enum {
	STATIC_CGNAPT_ENTRY,
	DYNAMIC_CGNAPT_ENTRY,
	PCP_CGNAPT_ENTRY,
};
#endif

struct app_pipeline_cgnapt_entry_params {
	enum cgnapt_entry_type type;
	union {
		uint32_t prv_ip;	/* private ip address */
		uint8_t prv_ipv6[16];
		uint16_t u16_prv_ipv6[8];
		uint32_t u32_prv_ipv6[4];
	} u;
	uint32_t prv_ip;
	uint16_t prv_port;	/* private port */
	uint32_t pub_ip;	/* public ip address */
	uint16_t pub_port;	/* public port */
	uint16_t prv_phy_port;	/* physical port on private side */
	uint16_t pub_phy_port;	/* physical port on public side */
	uint32_t ttl;		/* time to live */
	long long int timeout;
	#ifdef PCP_ENABLE
	struct rte_timer *timer;
	#endif
};

/*
 *CGNAPT table
 */

struct cgnapt_table_entry {
	struct rte_pipeline_table_entry head;
	struct app_pipeline_cgnapt_entry_params data;
} __rte_cache_aligned;

/**
 * A structure defining the CG-NAPT multiple entry parameter.
 */
struct app_pipeline_cgnapt_mentry_params {
	enum cgnapt_entry_type type;
	union {
		uint32_t prv_ip;	/* private ip address */
		uint8_t prv_ipv6[16];
		uint16_t u16_prv_ipv6[8];
		uint32_t u32_prv_ipv6[4];
	} u;
	uint32_t prv_ip;	/* private ip address */
	uint16_t prv_port;	/* private port start */
	uint32_t pub_ip;	/* public ip address */
	uint16_t pub_port;	/* public port start */
	uint16_t prv_phy_port;	/* physical port on private side */
	uint16_t pub_phy_port;	/* physical port on public side */
	uint32_t ttl;		/* time to live */
	uint32_t num_ue;	/* number of UEs to add */
	uint16_t prv_port_max;	/* max value for private port */
	uint16_t pub_port_max;	/* max value for public port */
};

/**
 * A structure defining the NAT64 Network Specific Prefix.
 */
struct pipeline_cgnapt_nsp_t {
	uint8_t prefix[16];
	uint8_t depth;
};


/*
 * Messages
 */
enum pipeline_cgnapt_msg_req_type {
	PIPELINE_CGNAPT_MSG_REQ_ENTRY_ADD,
	PIPELINE_CGNAPT_MSG_REQ_ENTRY_DEL,
	/* to be used for periodic synchronization */
	PIPELINE_CGNAPT_MSG_REQ_ENTRY_SYNC,
	/* to be used for debug purposes */
	PIPELINE_CGNAPT_MSG_REQ_ENTRY_DBG,
	/* Multiple (bulk) add */
	PIPELINE_CGNAPT_MSG_REQ_ENTRY_ADDM,
	PIPELINE_CGNAPT_MSG_REQ_VER,
	PIPELINE_CGNAPT_MSG_REQ_NSP_ADD,
	PIPELINE_CGNAPT_MSG_REQ_NSP_DEL,
	#ifdef PCP_ENABLE
	PIPELINE_CGNAPT_MSG_REQ_PCP,
	#endif
	PIPELINE_CGNAPT_MSG_REQS
};

/**
 * A structure defining MSG ENTRY ADD request.
 */
struct pipeline_cgnapt_entry_add_msg_req {
	enum pipeline_msg_req_type type;
	enum pipeline_cgnapt_msg_req_type subtype;

	/* key */
	struct pipeline_cgnapt_entry_key key;

	/* data */
	struct app_pipeline_cgnapt_entry_params data;
};

/**
 * A structure defining MSG ENTRY ADD response.
 */
struct pipeline_cgnapt_entry_add_msg_rsp {
	int status;
	int key_found;
	void *entry_ptr;
};

/**
 * A structure defining MSG ENTRY MADD request.
 */
struct pipeline_cgnapt_entry_addm_msg_req {
	enum pipeline_msg_req_type type;
	enum pipeline_cgnapt_msg_req_type subtype;

	/* data */
	struct app_pipeline_cgnapt_mentry_params data;
};

struct pipeline_cgnapt_entry_addm_msg_rsp {
	int status;
	int key_found;
	void *entry_ptr;
};

/**
 * A structure defining MSG ENTRY DELETE request.
 */
struct pipeline_cgnapt_entry_delete_msg_req {
	enum pipeline_msg_req_type type;
	enum pipeline_cgnapt_msg_req_type subtype;

	/* key */
	struct pipeline_cgnapt_entry_key key;
};

/**
 * A structure defining MSG ENTRY DELETE response.
 */
struct pipeline_cgnapt_entry_delete_msg_rsp {
	int status;
	int key_found;
};

/*
 * MSG ENTRY SYNC
 */
struct pipeline_cgnapt_entry_sync_msg_req {
	enum pipeline_msg_req_type type;
	enum pipeline_cgnapt_msg_req_type subtype;

	/* data */
	struct app_pipeline_cgnapt_entry_params data;
};

struct pipeline_cgnapt_entry_sync_msg_rsp {
	int status;
	void *entry_ptr;
};

/**
 * A structure defining the debug command response message.
 */
struct pipeline_cgnapt_entry_dbg_msg_rsp {
	int status;
	void *entry_ptr;
};

/**
 * A structure defining the NSP add request.
 */
struct pipeline_cgnapt_nsp_add_msg_req {
	enum pipeline_msg_req_type type;
	enum pipeline_cgnapt_msg_req_type subtype;

	/* Network Specific Prefix and prefix length */
	struct pipeline_cgnapt_nsp_t nsp;
};

/**
 * A structure defining the NSP add response.
 */
struct pipeline_cgnapt_nsp_add_msg_rsp {
	int status;
	int key_found;
};

/**
 * A structure defining MSG NSP DEL request
 */
struct pipeline_cgnapt_nsp_del_msg_req {
	enum pipeline_msg_req_type type;
	enum pipeline_cgnapt_msg_req_type subtype;

	/* Network Specific Prefix and prefix length */
	struct pipeline_cgnapt_nsp_t nsp;

};

/**
 * A structure defining MSG NSP DEL response
 */
struct pipeline_cgnapt_nsp_del_msg_rsp {
	int status;
	int key_found;
};

/**
 * A structure defining the debug command request message.
 */
struct pipeline_cgnapt_entry_dbg_msg_req {
	enum pipeline_msg_req_type type;
	enum pipeline_cgnapt_msg_req_type subtype;

	/* data */
	uint8_t data[5];
};

extern struct pipeline_be_ops pipeline_cgnapt_be_ops;
void print_num_ip_clients(void);
void all_cgnapt_stats(void);
void all_cgnapt_clear_stats(void);
void print_static_cgnapt_entries(void);
#endif
