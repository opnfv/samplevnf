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
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/queue.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_hash.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_debug.h>
#include <rte_cfgfile.h>
#include <fcntl.h>
#include <unistd.h>
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_etheraddr.h>
#include <cmdline_socket.h>
#include <cmdline.h>

#include "pipeline_common_fe.h"
#include "pipeline_arpicmp.h"

#include <civetweb.h>
#include <json/json.h>
#include "app.h"
#include "lib_arp.h"
#include "interface.h"
#include "tsx.h"
#include "gateway.h"

#define MAX_PIPELINES		30
#define MAX_VNFS		3
#define CFG_NAME_LEN		64
#define MAX_CORES		64
#define MAX_SOCKET		2
#define MAX_BUF_SIZE		2048
#define MAX_SIZE		24
#define MAX_LINKS		64
#define MAX_LB			20
#define        msleep(x)               rte_delay_us(x * 1000)

const char *pipelines[9] = {"MASTER", "ARPICMP", "TIMER", "TXRX-BEGIN",
			 "TXRX-END", "LOADB", "VACL", "VCGNAPT", "VFW"};
const char *VNFS[] = {"VACL", "VCGNAPT", "VFW"};
struct mg_context *ctx;
struct pub_ip_range {
	char value[MAX_BUF_SIZE];
};

struct stat_cfg {
	uint8_t num_workers;
	uint8_t num_lb;
	uint8_t num_ports;
	uint8_t hyper_thread;
	uint8_t sock_in;
	uint8_t sw_lb;
	char vnf_type[MAX_SIZE];
	char pkt_type[MAX_SIZE];
	char pci_white_list[MAX_BUF_SIZE];
	struct pub_ip_range ip_range[MAX_LB];
};

struct arp_params {
	uint8_t family;
	uint8_t action;
	union {
		uint32_t ip;
		uint8_t ipv6[16];
	};
	uint32_t portid;
	struct ether_addr mac_addr;
};

struct link_params {
	uint32_t id;
	uint32_t state;
	union {
		uint32_t ip;
		uint8_t ipv6[16];
	};
	uint32_t depth;
	uint32_t family;
};

struct route_params {
	uint32_t enable;
	union {
		uint32_t ip;
		uint8_t ipv6[16];
	};
	uint32_t depth;
	uint32_t family;
	char type[255];
};

struct dbg_mode {
	uint32_t  cmd;
	uint32_t  d1;
	uint32_t  pipe_num;
};

struct dbg_mode 	current_dbg;
struct link_params 	current_link_parms[MAX_LINKS];
struct stat_cfg		current_cfg;
struct arp_params 	current_arp_parms;
struct route_params	current_route_parms[MAX_LINKS];

static int static_cfg_set = 0;
uint8_t pipe_arr[MAX_PIPELINES];
uint8_t num_pipelines;
uint8_t num_workers, pub_ip = 0, ip_range = 0, num_lb = 1, num_ports;
uint8_t num_entries, start_lb, end_lb, start_lbout;
uint8_t swq_index = 0, workers = 0;
uint8_t txq_index = 0, sw_lb = 1;
uint8_t rxq_index = 0;
uint8_t arp_index = 0, tx_start_port = 0, rx_start_port = 0;
uint8_t pipenum = 0, hyper_thread = 0;
char traffic_type[4] = "4";
struct rte_cfgfile_entry entries[30];
int n_entries1 = 0;
char loadb_in[256];
char vnf_type[256];
uint8_t sock_cpus[MAX_SOCKET][MAX_CORES];
uint8_t sock_in = 0, sock0 = 0, sock1 = 0, sock_index = 0;
int hyper = 0;
uint32_t flow_dir_cfg = 0;
struct app_params *rapp;

extern uint32_t nd_route_tbl_index;
extern struct arp_data *p_arp_data;
extern int USE_RTM_LOCKS;
extern rte_rwlock_t rwlock;
extern interface_main_t ifm;
extern struct cmdline *pipe_cl;
extern uint16_t str2flowtype(const char *string);
extern void app_run_file(cmdline_parse_ctx_t *ctx, const char *file_name);
extern int parse_flexbytes(const char *q_arg, uint8_t *flexbytes,
			 uint16_t max_num);
extern int app_pipeline_arpicmp_entry_dbg(struct app_params *app,
                                    uint32_t pipeline_id, uint8_t *msg);
extern unsigned eal_cpu_socket_id(unsigned cpu_id);
extern int app_routeadd_config_ipv4(__attribute__((unused))
					 struct app_params *app,
				        uint32_t port_id, uint32_t ip,
					 uint32_t mask);
extern int app_routeadd_config_ipv6(__attribute__((unused))
					 struct app_params *app,
				        uint32_t port_id, uint8_t ipv6[],
					 uint32_t depth);

enum rte_eth_input_set_field str2inset(const char *string);

enum {
	MASTER = 0,
	ARPICMP,
	TIMER,
	TXRX_BEGIN,
	TXRX_END,
	LOADB,
	VNF_VACL,
	VNF_VCGNAPT,
	VNF_VFW,
	PIPE_MAX
};

struct json_data {
	char key[256];
	char value[256];
};

struct json_data static_cfg[40];
uint32_t post_not_received = 1;

int flow_director_handler(struct mg_connection *conn,
	 __rte_unused void *cbdata);
int vnf_handler(struct mg_connection *conn, __rte_unused void *cbdata);
void init_stat_cfg(void);
void bind_the_ports(struct mg_connection *conn, char *pci_white_list);
int route_handler(struct mg_connection *conn, __rte_unused void *cbdata);
int dbg_pipelines_handler(struct mg_connection *conn,
	 __rte_unused void *cbdata);
int dbg_pipelines_id_handler(struct mg_connection *conn,
	 __rte_unused void *cbdata);
int get_pipelines_tokens(char *buf);
void get_swq_offset(uint8_t start, uint8_t num, char *buf);
void get_swq(uint8_t num, char *buf);
void get_txq(uint8_t start_q, uint8_t queue_num, uint8_t ports, char *buf);
void get_rxq(uint8_t start_q, uint8_t queue_num, uint8_t ports, char *buf);
void fix_pipelines_data_types(FILE *f, const char *sect_name,
			 struct rte_cfgfile *tcfg);
void print_to_file(FILE *f, struct rte_cfgfile *tcfg);
int get_vnf_index(void);
void build_pipeline(void);
void get_pktq_in_prv(char *buf);
void get_prv_to_pub_map(char *buf);
void get_prv_que_handler(char *buf);
int static_cfg_handler(struct mg_connection *conn, void *cbdata);
int link_handler(struct mg_connection *conn, void *cbdata);
int linkid_handler(struct mg_connection *conn, __rte_unused void *cbdata);
int arp_handler(struct mg_connection *conn, void *cbdata);
int arpls_handler(struct mg_connection *conn, void *cbdata);
int nd_handler(struct mg_connection *conn, void *cbdata);
int linkls_handler(struct mg_connection *conn, void *cbdata);
int set_hash_input_set_2(struct mg_connection *conn, uint32_t port_id,
	 const char *flow_type, const char *inset_field0,
	 const char *inset_field1, const char *select);
int set_hash_input_set_4(struct mg_connection *conn, uint32_t port_id,
	char *flow_type, char *inset_field0, char *inset_field1,
	char *inset_field2, char *inset_field3, const char *select);
int set_hash_global_config(struct mg_connection *conn, uint32_t port_id,
	char *flow_type, const char *hash_func, const char *enable);
int set_sym_hash_per_port(struct mg_connection *conn, uint32_t port_id);
int cmd_quit_handler(struct mg_connection *conn, void *cbdata);
int dbg_run_handler(struct mg_connection *conn, void *cbdata);
int dbg_handler(struct mg_connection *conn, __rte_unused void *cbdata);
int dbg_cmd_handler(struct mg_connection *conn, void *cbdata);
int run_field_found(const char *key, const char *filename, char *path,
            size_t pathlen, void *user_data);
int run_field_get(const char *key, const char *value, size_t valuelen,
	 void *user_data);
int run_field_stored(const char *path, long long file_size, void *user_data);
void print_interface_details_rest(struct mg_connection *conn, uint32_t link);
void print_link_info(struct app_link_params *p, struct mg_connection *conn);
int get_link_tokens(char *buf);
void get_mac(struct ether_addr *mac_addr, char *buf);

int run_field_found(const char *key, const char *filename, char *path,
	size_t pathlen, void *user_data)
{
        struct mg_connection *conn = (struct mg_connection *)user_data;

        mg_printf(conn, "\r\n\r\n%s:\r\n", key);

        if (filename && *filename) {
		snprintf(path, pathlen, "%s", filename);
		int fd;

		/* Make sure file exists before clearing rules and actions */
		fd = open(filename, O_RDONLY);
		if (fd < 0) {
			mg_printf(conn, "Cannot open file \"%s\"\n", filename);
			return FORM_FIELD_STORAGE_GET;
		}

		close(fd);
		mg_printf(conn, "file to be loaded is %s\n", filename);
		app_run_file(pipe_cl->ctx, filename);

		return FORM_FIELD_STORAGE_STORE;
	}
        
	return FORM_FIELD_STORAGE_GET;
}

int run_field_get(const char *key, const char *value, size_t valuelen,
	 void *user_data)
{
        struct mg_connection *conn = (struct mg_connection *)user_data;

        if (key[0]) {
                mg_printf(conn, "%s = ", key);
        }
        mg_write(conn, value, valuelen);

        return 0;
}

int run_field_stored(const char *path, long long file_size, void *user_data)
{
        struct mg_connection *conn = (struct mg_connection *)user_data;

        mg_printf(conn,
                  "stored as %s (%lu bytes)\r\n\r\n",
                  path,
                  (unsigned long)file_size);

        return 0;
}

int dbg_run_handler(struct mg_connection *conn, __rte_unused void *cbdata)
{
        /* Handler may access the request info using mg_get_request_info */
        const struct mg_request_info *req_info = mg_get_request_info(conn);
        struct mg_form_data_handler fdh = {run_field_found, run_field_get,
					 run_field_stored, NULL};

        if (strcmp(req_info->request_method, "POST")) {

                mg_printf(conn,
                          "HTTP/1.1 405 Method Not Allowed\r\nConnection:");
		mg_printf(conn," close\r\n");
                mg_printf(conn, "Content-Type: text/plain\r\n\r\n");
                mg_printf(conn,
                          "%s method not allowed in the POST handler\n",
                          req_info->request_method);
                return 1; 
        }


        /* It would be possible to check the request info here before calling
         * mg_handle_form_request. */
        (void)req_info;

        mg_printf(conn, "HTTP/1.1 200 OK\r\nContent-Type: ");
        mg_printf(conn, "text/plain\r\nConnection: close\r\n\r\n");
        if (strcmp(req_info->request_method, "PUT")) {
        	mg_printf(conn, "Only PUT method allowed");
		return 1;
	}

        fdh.user_data = (void *)conn;

        /* Call the form handler */
        mg_handle_form_request(conn, &fdh);
        mg_printf(conn, "\r\n script file handled");

        return 1;
}

int cmd_quit_handler(__rte_unused struct mg_connection *conn,
		 __rte_unused void *cbdata)
{
	cmdline_quit(pipe_cl);
	return 0;
}

int dbg_handler(struct mg_connection *conn, __rte_unused void *cbdata)
{

        const struct mg_request_info *ri = mg_get_request_info(conn);

        if (!strcmp(ri->request_method, "GET")) {
        	mg_printf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n");
		mg_printf(conn, "Connection: close\r\n\r\n");
        	mg_printf(conn, "<html><body>");
        	mg_printf(conn, "<h2> These are the methods supported</h2>");
        	mg_printf(conn, "<h3>     /pipelines\n</h3>");
        	mg_printf(conn, "<h3>     /cmd \n</h3>");
        	mg_printf(conn, "<h3>     /run\n</h3>");
        	mg_printf(conn, "</body></html>");
	}

	return 1;

}

int get_pipelines_tokens(char *buf)
{
        char *token;
        uint32_t id;

        token = strtok(buf, "/ ");
	if (!token)
		return -1;

        if (strcmp(token, "pipelines")) {
                return -1;
        }

        token = strtok(NULL, "/ ");
	if (!token)
		return -1;

        id = atoi(token);
        if (id > rapp->n_pipelines) {
                return -1;
        }

        return id;
}


int dbg_pipelines_id_handler(struct mg_connection *conn,
			 __rte_unused void *cbdata)
{
	struct app_eal_params *p = &rapp->eal_params;
        const struct mg_request_info *ri = mg_get_request_info(conn);
        //uint32_t id = (uint32_t *)cbdata;

	mg_printf(conn, "Inside dbg_pipelines_id_handler\n");

        if (!strcmp(ri->request_method, "GET")) {
        	mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
        	mg_printf(conn, "<html><body>");
		if (p->log_level_present) {
	               mg_printf(conn, "<h2> The pipeline log level is %d</h2>",
				p->log_level);
		} else {
	               mg_printf(conn, "<h2> No log level found in the\
				pipeline</h2>");
		}
        	mg_printf(conn, "</body></html>");
	}

	return 1;

}


int dbg_pipelines_handler(struct mg_connection *conn, __rte_unused void *cbdata)
{

	uint32_t i;
        const struct mg_request_info *ri = mg_get_request_info(conn);

        if (!strcmp(ri->request_method, "GET")) {
        	mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
        	mg_printf(conn, "<html><body>");
        	mg_printf(conn, "<h2> These are pipelines available</h2>");
		for (i = 0; i < rapp->n_pipelines; i++) {
			mg_printf(conn, "<h3> pipeline %d:	%s\n</h3>",i,
				rapp->pipeline_params[i].type);
		}
        	mg_printf(conn, "</body></html>");
	}

	return 1;

}

int dbg_cmd_handler(struct mg_connection *conn, __rte_unused void *cbdata)
{
        struct app_params *app = rapp;
        uint8_t msg[2];
        int status;
        const struct mg_request_info *req_info = mg_get_request_info(conn);
	char buf[MAX_BUF_SIZE];
        
	if (!strcmp(req_info->request_method, "GET")) {
        	mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
        	mg_printf(conn, "<html><body>");
        	mg_printf(conn, "<h2> The last command executed </h2>");
        	mg_printf(conn, "<h3>     cmd: %d\n </h3>", current_dbg.cmd);
        	mg_printf(conn, "<h3>     d1 : %d\n </h3>", current_dbg.d1);
        	mg_printf(conn, "<h3>     pipeline : %d\n </h3>",
				 current_dbg.pipe_num);
        	mg_printf(conn, "</body></html>\n");

	}

        if (strcmp(req_info->request_method, "POST")) {
                mg_printf(conn,
                       "HTTP/1.1 405 Method Not Allowed\r\nConnection:");
		mg_printf(conn, " close\r\n");
                mg_printf(conn, "Content-Type: text/plain\r\n\r\n");
                mg_printf(conn, "%s method not allowed in the POST handler\n",
                          req_info->request_method);
                return 1; 
        }

        mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
        mg_printf(conn, "<html><body>");
        mg_printf(conn, "</body></html>\n");
        
	mg_read(conn, buf, sizeof(buf));
	json_object * jobj = json_tokener_parse(buf);
	json_object_object_foreach(jobj, key, val) {
		if (!strcmp(key, "cmd")) {
			current_dbg.cmd = atoi(json_object_get_string(val));
		} else if (!strcmp(key, "d1")) {
			current_dbg.d1 = atoi(json_object_get_string(val));
		} else if (!strcmp(key, "pipeline")) {
			current_dbg.pipe_num = atoi(json_object_get_string(val));
		}
	}


        msg[0] = current_dbg.cmd;
        msg[1] = current_dbg.d1;
        status = app_pipeline_arpicmp_entry_dbg(app, current_dbg.pipe_num, msg);

        if (status != 0) {
                mg_printf(conn, "Dbg Command failed\n");
                return 1;
        }

	return 1;
}

int set_sym_hash_per_port(struct mg_connection *conn, uint32_t port_id)
{
        int ret;
        struct rte_eth_hash_filter_info info;

        if (rte_eth_dev_filter_supported(port_id,
                 RTE_ETH_FILTER_HASH) < 0) {
                mg_printf(conn, "RTE_ETH_FILTER_HASH not supported on port: %d\n",
                        port_id);
                return 1;
        }

        memset(&info, 0, sizeof(info));
        info.info_type = RTE_ETH_HASH_FILTER_SYM_HASH_ENA_PER_PORT;

        ret = rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_HASH,
                                 RTE_ETH_FILTER_SET, &info);
        if (ret < 0) {
                mg_printf(conn, "Cannot set symmetric hash enable per port on "
                        "port %u\n", port_id);
                return 1;
        }

	return 1;
}

int set_hash_input_set_4(struct mg_connection *conn, uint32_t port_id,
	char *flow_type, char *inset_field0, char *inset_field1,
	char *inset_field2, char *inset_field3,	const char *select)
{
        struct rte_eth_hash_filter_info info;

        if (enable_flow_dir) {
                mg_printf(conn, "FDIR Filter is Defined!\n");
                mg_printf(conn, "Please undefine FDIR_FILTER flag and define "
                        "HWLD flag\n");
                return 1;
        }

        memset(&info, 0, sizeof(info));
        info.info_type = RTE_ETH_HASH_FILTER_INPUT_SET_SELECT;
        info.info.input_set_conf.flow_type = str2flowtype(flow_type);

        info.info.input_set_conf.field[0] = str2inset(inset_field0);
        info.info.input_set_conf.field[1] = str2inset(inset_field1);
        info.info.input_set_conf.field[2] = str2inset(inset_field2);
        info.info.input_set_conf.field[3] = str2inset(inset_field3);

        info.info.input_set_conf.inset_size = 4;
        if (!strcmp(select, "select"))
                info.info.input_set_conf.op = RTE_ETH_INPUT_SET_SELECT;
        else if (!strcmp(select, "add"))
                info.info.input_set_conf.op = RTE_ETH_INPUT_SET_ADD;

        rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_HASH,
                RTE_ETH_FILTER_SET, &info);

        mg_printf(conn, "Command Passed!\n");
	return 1;
}

int set_hash_input_set_2(struct mg_connection *conn, uint32_t port_id,
	 const char *flow_type, const char *inset_field0,
	 const char *inset_field1, const char *select)
{
        struct rte_eth_hash_filter_info info;
        const struct mg_request_info *req_info = mg_get_request_info(conn);

        if (strcmp(req_info->request_method, "POST")) {
                mg_printf(conn,
                    "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n");
                mg_printf(conn, "Content-Type: text/plain\r\n\r\n");
                mg_printf(conn,
                          "%s method not allowed in the POST handler\n",
                          req_info->request_method);
                return 1; 
        }

        mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
        mg_printf(conn, "<html><body>");
        mg_printf(conn, "</body></html>\n");

	if (!inset_field0 || !inset_field1 || !flow_type) {
                mg_printf(conn, "inset_field0/1 or flow_type may be NULL!\n");
		return 1;
	}

        if (enable_flow_dir) {
                mg_printf(conn, "FDIR Filter is Defined!\n");
                mg_printf(conn, "Please undefine FDIR_FILTER flag and define "
                        "HWLD flag\n");
                return 1;
        }

        if (enable_flow_dir) {
                mg_printf(conn, "FDIR Filter is Defined!\n");
                mg_printf(conn, "Please undefine FDIR_FILTER flag and define "
                        "HWLD flag\n");
                return 1;
        }

        memset(&info, 0, sizeof(info));
        info.info_type = RTE_ETH_HASH_FILTER_INPUT_SET_SELECT;
        info.info.input_set_conf.flow_type = str2flowtype(flow_type);

	if (inset_field0)
	        info.info.input_set_conf.field[0] = str2inset(inset_field0);

	if (inset_field1)
	        info.info.input_set_conf.field[1] = str2inset(inset_field1);

        info.info.input_set_conf.inset_size = 2;

        if (!strcmp(select, "select"))
                info.info.input_set_conf.op = RTE_ETH_INPUT_SET_SELECT;
        else if (!strcmp(select, "add"))
                info.info.input_set_conf.op = RTE_ETH_INPUT_SET_ADD;

        rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_HASH,
                RTE_ETH_FILTER_SET, &info);

        mg_printf(conn, "Command Passed!\n");
	return 1;
}

void print_interface_details_rest(struct mg_connection *conn, uint32_t link)
{
	l2_phy_interface_t *port;
	int i = 0;
	struct sockaddr_in ip;
	mg_printf(conn, "\n\r");

	if (USE_RTM_LOCKS)
		rtm_lock();
	else
		rte_rwlock_read_lock(&rwlock);

	i = link;
	port = ifm.port_list[i];
	mg_printf(conn, "%u", port->pmdid);
	if (port->ifname && strlen(port->ifname)) {
		mg_printf(conn, " (%s)\t", port->ifname);
	} else
		mg_printf(conn, "\t\t");
	mg_printf(conn, "MAC:%02x:%02x:%02x:%02x:%02x:%02x Adminstate:%s"
				 " Operstate:%s \n\r<br/>",
				 port->macaddr[0], port->macaddr[1],
				 port->macaddr[2], port->macaddr[3],
				 port->macaddr[4], port->macaddr[5],
				 port->admin_status ? "UP" : "DOWN",
				 port->link_status ? "UP" : "DOWN");
	mg_printf(conn, "\t\t");
	mg_printf(conn, "Speed: %u, %s-duplex\n\r<br/>", port->link_speed,
				 port->link_duplex ? "full" : "half");
	mg_printf(conn, "\t\t");

	if (port->ipv4_list != NULL) {
		ip.sin_addr.s_addr =
				(unsigned long)((ipv4list_t *) (port->ipv4_list))->
				ipaddr;
		mg_printf(conn, "IP: %s/%d", inet_ntoa(ip.sin_addr),
					 ((ipv4list_t *) (port->ipv4_list))->addrlen);
	} else {
		mg_printf(conn, "IP: NA");
	}

	mg_printf(conn, "\r\n<br/>");
	mg_printf(conn, "\t\t");
	if (port->ipv6_list != NULL) {
		uint8_t *addr =
				((ipv6list_t *) (port->ipv6_list))->ipaddr;
		mg_printf(conn, "IPv6: %02x%02x:%02x%02x:%02x%02x:"
				"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
				 addr[0], addr[1], addr[2], addr[3], addr[4],
				 addr[5], addr[6], addr[7], addr[8], addr[9],
				 addr[10], addr[11], addr[12], addr[13], addr[14],
				 addr[15]);
	} else {
		mg_printf(conn, "IPv6: NA");
	}

	if (port->flags & IFM_SLAVE) {
		mg_printf(conn, "  IFM_SLAVE ");
		mg_printf(conn, " MasterPort: %u",
					 port->bond_config->bond_portid);
	}
	if (port->flags & IFM_MASTER) {
		mg_printf(conn, "  IFM_MASTER ");
		mg_printf(conn, "  Mode: %u", port->bond_config->mode);
		mg_printf(conn, "  PrimaryPort: %u",
				 port->bond_config->primary);
		mg_printf(conn, "\n\r<br/>");
		mg_printf(conn, "\t\tSlavePortCount: %u",
					 port->bond_config->slave_count);
		mg_printf(conn, " SlavePorts:");
		int i;
		for (i = 0; i < port->bond_config->slave_count; i++) {
			mg_printf(conn, " %u ",
				 port->bond_config->slaves[i]);
		}
		mg_printf(conn, " ActivePortCount: %u",
					 port->bond_config->active_slave_count);
		mg_printf(conn, " ActivePorts:");
		for (i = 0; i < port->bond_config->active_slave_count;
				 i++) {
			mg_printf(conn, " %u ",
					 port->bond_config->active_slaves[i]);
		}
		mg_printf(conn, "\n\r<br/>");
		mg_printf(conn, "\t\t");
		mg_printf(conn, "Link_monitor_freq: %u ms ",
					 port->bond_config->internal_ms);
		mg_printf(conn, " Link_up_prop_delay: %u ms ",
					 port->bond_config->link_up_delay_ms);
		mg_printf(conn, " Link_down_prop_delay: %u ms ",
					 port->bond_config->link_down_delay_ms);
		mg_printf(conn, "\n\r<br/>");
		mg_printf(conn, "\t\t");
		mg_printf(conn, "Xmit_policy: %u",
					 port->bond_config->xmit_policy);
	}
	mg_printf(conn, "\n\r<br/>");
	mg_printf(conn, "\t\t");
	mg_printf(conn, "n_rxpkts: %" PRIu64 " ,n_txpkts: %" PRIu64 " ,",
				 port->n_rxpkts, port->n_txpkts);
	struct rte_eth_stats eth_stats;
	rte_eth_stats_get(port->pmdid, &eth_stats);
	mg_printf(conn, "pkts_in: %" PRIu64 " ,", eth_stats.ipackets);
	mg_printf(conn, "pkts_out: %" PRIu64 " ", eth_stats.opackets);
	mg_printf(conn, "\n\r<br/>");
	mg_printf(conn, "\t\t");
	mg_printf(conn, "in_errs: %" PRIu64 " ,", eth_stats.ierrors);
	mg_printf(conn, "in_missed: %" PRIu64 " ,", eth_stats.imissed);
	mg_printf(conn, "out_errs: %" PRIu64 " ,", eth_stats.oerrors);
	mg_printf(conn, "mbuf_errs: %" PRIu64 " ", eth_stats.rx_nombuf);
	mg_printf(conn, "\n\r<br/>");
	mg_printf(conn, "\n\r");

	if (USE_RTM_LOCKS)
		rtm_unlock();
	else
		rte_rwlock_read_unlock(&rwlock);
}

void print_link_info(struct app_link_params *p, struct mg_connection *conn)
{
        struct rte_eth_stats stats;
        struct ether_addr *mac_addr;
        uint32_t netmask = (~0U) << (32 - p->depth);
        uint32_t host = p->ip & netmask;
        uint32_t bcast = host | (~netmask);

        memset(&stats, 0, sizeof(stats));
        rte_eth_stats_get(p->pmd_id, &stats);

        mac_addr = (struct ether_addr *) &p->mac_addr;

        if (strlen(p->pci_bdf))
                mg_printf(conn, "%s(%s): flags=%s\r\n<br/>",
                        p->name,
                        p->pci_bdf,
                        (p->state) ? "UP" : "DOWN");
        else
                mg_printf(conn, "%s: flags=%s\r\n<br/>",
                        p->name,
                        (p->state) ? "UP" : "DOWN");
        if (p->ip)
                mg_printf(conn, "\tinet %" PRIu32 ".%" PRIu32
                        ".%" PRIu32 ".%" PRIu32
                        " netmask %" PRIu32 ".%" PRIu32
                        ".%" PRIu32 ".%" PRIu32 " "
                        "broadcast %" PRIu32 ".%" PRIu32
                        ".%" PRIu32 ".%" PRIu32 "\r\n<br/>",
                        (p->ip >> 24) & 0xFF,
                        (p->ip >> 16) & 0xFF,
                        (p->ip >> 8) & 0xFF,
                        p->ip & 0xFF,
                        (netmask >> 24) & 0xFF,
                        (netmask >> 16) & 0xFF,
                        (netmask >> 8) & 0xFF,
                        netmask & 0xFF,
                        (bcast >> 24) & 0xFF,
                        (bcast >> 16) & 0xFF,
                        (bcast >> 8) & 0xFF,
                        bcast & 0xFF);
        mg_printf(conn, "\tether %02" PRIx32 ":%02" PRIx32 ":%02" PRIx32
                ":%02" PRIx32 ":%02" PRIx32 ":%02" PRIx32 "\r\n<br/>",
                mac_addr->addr_bytes[0],
                mac_addr->addr_bytes[1],
                mac_addr->addr_bytes[2],
                mac_addr->addr_bytes[3],
                mac_addr->addr_bytes[4],
                mac_addr->addr_bytes[5]);

        mg_printf(conn, "\tRX packets %" PRIu64
                "  bytes %" PRIu64
                "\r\n<br/>",
                stats.ipackets,
                stats.ibytes);

        mg_printf(conn, "\tRX errors %" PRIu64
                "  missed %" PRIu64
                "  no-mbuf %" PRIu64
                "\r\n<br/>",
                stats.ierrors,
                stats.imissed,
                stats.rx_nombuf);

        mg_printf(conn, "\tTX packets %" PRIu64
                "  bytes %" PRIu64 "\r\n<br/>",
                stats.opackets,
                stats.obytes);

        mg_printf(conn, "\tTX errors %" PRIu64
                "\r\n<br/>",
                stats.oerrors);

        mg_printf(conn, "\r\n<br/>");
}

int get_link_tokens(char *buf)
{
        char *token;
        int linkid;

        token = strtok(buf, "/ ");
	if (!token)
		return -1;

        if (strcmp(token, "link")) {
                return -1;
        }

        token = strtok(NULL, "/ ");
	if (!token)
		return -1;

        linkid = atoi(token);
        if (linkid > current_cfg.num_ports) {
                return -1;
        }

        return linkid;
}

int linkls_handler(struct mg_connection *conn, void *cbdata)
{
        struct app_params *app = rapp;

	struct app_link_params *p;

	APP_PARAM_FIND_BY_ID(app->link_params, "LINK", *(uint32_t *)cbdata, p);
	if (p) {
		print_link_info(p, conn);
	}

	print_interface_details_rest(conn, *(uint32_t *)cbdata);
	return 1;
}

static const char* arp_status[] = {"INCOMPLETE", "COMPLETE", "PROBE", "STALE"};

/* ND IPv6 */
int nd_handler(struct mg_connection *conn, __rte_unused void *cbdata)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;
	uint8_t ii = 0;
	mg_printf(conn, "----------------------------------------------------");
	mg_printf(conn, "-------------------------------------------------\n<br/>");
	mg_printf(conn, "\tport  hw addr            status         ip addr\n<br/>");

	mg_printf(conn, "-----------------------------------------------------");
	mg_printf(conn, "-------------------------------------------------\n<br/>");
	while (rte_hash_iterate(nd_hash_handle, &next_key, &next_data, &iter) >=
				 0) {

		struct nd_entry_data *tmp_nd_data =
				(struct nd_entry_data *)next_data;
		struct nd_key_ipv6 tmp_nd_key;
		memcpy(&tmp_nd_key, next_key, sizeof(struct nd_key_ipv6));
		mg_printf(conn, "\t%4d  %02X:%02X:%02X:%02X:%02X:%02X  %10s",
					 tmp_nd_data->port,
					 tmp_nd_data->eth_addr.addr_bytes[0],
					 tmp_nd_data->eth_addr.addr_bytes[1],
					 tmp_nd_data->eth_addr.addr_bytes[2],
					 tmp_nd_data->eth_addr.addr_bytes[3],
					 tmp_nd_data->eth_addr.addr_bytes[4],
					 tmp_nd_data->eth_addr.addr_bytes[5],
					 arp_status[tmp_nd_data->status]);
		mg_printf(conn, "\t");
		for (ii = 0; ii < ND_IPV6_ADDR_SIZE; ii += 2) {
			mg_printf(conn, "%02X%02X ", tmp_nd_data->ipv6[ii],
						 tmp_nd_data->ipv6[ii + 1]);
		}
		mg_printf(conn, "\n<br/>");
	}

	mg_printf(conn, "\nND IPV6 Stats: \nTotal Queries %u, ok_NH %u,"
			" no_NH %u, ok_Entry %u, "
			"no_Entry %u, PopulateCall %u, Del %u, Dup %u\n<br/>",
			 lib_nd_get_mac_req, lib_nd_nh_found, lib_nd_no_nh_found,
			 lib_nd_nd_entry_found, lib_nd_no_arp_entry_found,
			 lib_nd_populate_called, lib_nd_delete_called,
			 lib_nd_duplicate_found);
	mg_printf(conn, "ND table key len is %lu\n\n<br/>", sizeof(struct nd_key_ipv6));
	return 0;
}

int arpls_handler(struct mg_connection *conn, __rte_unused void *cbdata)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0, len = 0;
	char buf[1024];
        
	len += sprintf
	(buf + len, "---------------------- ARP CACHE ---------------------\n<br/>");
	len += sprintf
	(buf + len, "------------------------------------------------------\n<br/>");
	len += sprintf(buf + len, "\tport  hw addr            status     ip addr\n<br/>");
	len += sprintf
	(buf + len, "------------------------------------------------------\n<br/>");

	while (rte_hash_iterate(arp_hash_handle, &next_key, &next_data, &iter)
				 >= 0) {

		struct arp_entry_data *tmp_arp_data =
				(struct arp_entry_data *)next_data;
		struct arp_key_ipv4 tmp_arp_key;
		memcpy(&tmp_arp_key, next_key, sizeof(struct arp_key_ipv4));
		len += sprintf
			(buf + len, "\t%4d  %02X:%02X:%02X:%02X:%02X:%02X"
			"  %10s %d.%d.%d.%d\n<br/>",
			 tmp_arp_data->port, tmp_arp_data->eth_addr.addr_bytes[0],
			 tmp_arp_data->eth_addr.addr_bytes[1],
			 tmp_arp_data->eth_addr.addr_bytes[2],
			 tmp_arp_data->eth_addr.addr_bytes[3],
			 tmp_arp_data->eth_addr.addr_bytes[4],
			 tmp_arp_data->eth_addr.addr_bytes[5],
			 arp_status[tmp_arp_data->status],
			 (tmp_arp_data->ip >> 24),
			 ((tmp_arp_data->ip & 0x00ff0000) >> 16),
			 ((tmp_arp_data->ip & 0x0000ff00) >> 8),
			 ((tmp_arp_data->ip & 0x000000ff)));
	}

	uint32_t i = 0, j;
	len += sprintf(buf + len, "\n<br/>IP_Address    Mask          Port\n<br/>");
	for (j = 0; j < gw_get_num_ports(); j++) {
		for (i = 0; i < p_route_data[j]->route_ent_cnt; i++) {
			len += sprintf(buf + len, "0x%08x \t 0x%08x \t %d\n<br/>",
			p_route_data[j]->route_table[i].nh,
			p_route_data[j]->route_table[i].mask,
			p_route_data[j]->route_table[i].port);
		}
	}

	len += sprintf
			(buf + len, "\nARP Stats: Total Queries %u, ok_NH %u,"
			" no_NH %u, ok_Entry %u, no_Entry %u, PopulateCall %u,"
			" Del %u, Dup %u\n<br/>",
			 lib_arp_get_mac_req, lib_arp_nh_found, lib_arp_no_nh_found,
			 lib_arp_arp_entry_found, lib_arp_no_arp_entry_found,
			 lib_arp_populate_called, lib_arp_delete_called,
			 lib_arp_duplicate_found);

	len += sprintf(buf + len, "ARP table key len is %d\n<br/>",
			 (uint32_t) sizeof(struct arp_key_ipv4));
        mg_printf(conn, "%s\n<br/>", &buf[0]);
        return 1; 
}

void get_mac(struct ether_addr *mac_addr, char *buf)
{
	uint32_t i = 0, j = 0, k = 0, MAC_NUM_BYTES = 6;

	char byteStr[MAC_NUM_BYTES][3];

	char *token = strtok(buf, " ");
	while (token) {
		k = 0;
		for (i = 0; i < MAC_NUM_BYTES; i++) {
			for (j = 0; j < 2; j++) {
				byteStr[i][j] = token[k++];
			}
			byteStr[i][j] = '\0';
		k++;
		}
		token = strtok(NULL, " ");
	}

	for (i = 0; i < MAC_NUM_BYTES; i++) {
		mac_addr->addr_bytes[i] = strtoul(byteStr[i], NULL, 16);
	}
	free(buf);
}

int arp_handler(struct mg_connection *conn, __rte_unused void *cbdata)
{
        const struct mg_request_info *req_info = mg_get_request_info(conn);
	char buf[MAX_BUF_SIZE];

        if (!strcmp(req_info->request_method, "GET")) {
        	mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
		/* prints arp table */
		mg_printf(conn, "<html><body>");
		arpls_handler(conn, cbdata);

		/* prints nd table */
		nd_handler(conn, cbdata);
		mg_printf(conn, "</body></html>");
		return 1;
	}

        if (strcmp(req_info->request_method, "POST")) {
                mg_printf(conn,
                    "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n");
                mg_printf(conn, "Content-Type: text/plain\r\n\r\n");
                mg_printf(conn,
                          "%s method not allowed in the POST handler\n",
                          req_info->request_method);
                return 1; 
        }

        mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
        mg_printf(conn, "<html><body>");

        mg_read(conn, buf, sizeof(buf));
	json_object * jobj = json_tokener_parse(buf);
	json_object_object_foreach(jobj, key, val) {
		if (!strcmp(key, "ipv4")) {
			current_arp_parms.ip = rte_bswap32(inet_addr(
				json_object_get_string(val)));
			current_arp_parms.family = AF_INET;
		} else if (!strcmp(key, "ipv6")) {
			my_inet_pton_ipv6(AF_INET6,
		 	json_object_get_string(val),
				 &current_arp_parms.ipv6[0]);
			current_arp_parms.family = AF_INET6;
		} else if (!strcmp(key, "action")) {
			if (!strcmp(json_object_get_string(val), "add"))
				current_arp_parms.action = 1;
			else if (!strcmp(json_object_get_string(val), "del"))
				current_arp_parms.action = 2;
			else if (!strcmp(json_object_get_string(val), "req"))
				current_arp_parms.action = 3;
		} else if (!strcmp(key, "portid")) {
			current_arp_parms.portid =
				 atoi(json_object_get_string(val));
		} else if (!strcmp(key, "macaddr")) {
			get_mac(&current_arp_parms.mac_addr,
				 strdup(json_object_get_string(val)));
		}
	}

        struct arp_key_ipv4 arp_key;
	struct arp_timer_key *callback_key;
        struct arp_entry_data *new_arp_data;
        struct nd_key_ipv6 nd_key;
        struct nd_entry_data *new_nd_data;

        if (current_arp_parms.family == AF_INET) {
		switch(current_arp_parms.action) {
			case 1:
                		populate_arp_entry(&current_arp_parms.mac_addr,
				current_arp_parms.ip, current_arp_parms.portid,
						 STATIC_ARP);
				break;
			case 2:
				callback_key =
				 (struct arp_timer_key*) rte_malloc(NULL,
                               	sizeof(struct  arp_timer_key*),
				RTE_CACHE_LINE_SIZE);
                		arp_key.port_id = current_arp_parms.portid;
                		arp_key.ip = current_arp_parms.ip;
                		arp_key.filler1 = 0;
                		arp_key.filler2 = 0;
                		arp_key.filler3 = 0;
                		new_arp_data = retrieve_arp_entry(arp_key,
							 STATIC_ARP);
                		callback_key->port_id = current_arp_parms.portid;
                		callback_key->ip = current_arp_parms.ip;

				mg_printf(conn, "removing entry now\n");
				remove_arp_entry(new_arp_data, callback_key);
				break;
			case 3:
			        arp_key.ip = current_arp_parms.ip;
			        arp_key.port_id = current_arp_parms.portid;
			        arp_key.filler1 = 0;
			        arp_key.filler2 = 0;
			        arp_key.filler3 = 0;

			        new_arp_data = retrieve_arp_entry(arp_key, STATIC_ARP);

			        if (new_arp_data) {
			        	mg_printf(conn, "<p>ARP entry exists for"
						" ip 0x%x, port %d</p>",
						 current_arp_parms.ip, current_arp_parms.portid);
			                return 1;
        			}

			        mg_printf(conn, "<p>ARP - requesting arp for ip 0x%x, port %d</p>",
					current_arp_parms.ip, current_arp_parms.portid);

			        request_arp(current_arp_parms.portid, current_arp_parms.ip);
				break;
			default:
				break;
		};
        } else {
		switch(current_arp_parms.action) {
			case 1:
                		populate_nd_entry(&current_arp_parms.mac_addr,
				current_arp_parms.ipv6, current_arp_parms.portid, STATIC_ND);
				break;
			case 2:
		                nd_key.port_id = current_arp_parms.portid;
                		memcpy(&nd_key.ipv6[0], &current_arp_parms.ipv6[0], 16);
		                nd_key.filler1 = 0;
        		        nd_key.filler2 = 0;
		                nd_key.filler3 = 0;
                		new_nd_data = retrieve_nd_entry(nd_key, STATIC_ND);

				if(new_nd_data == NULL) {
					/* KW Fix */
					mg_printf(conn,"Retrieve ND returned NULL\n");
					return 1;
				}
		                remove_nd_entry_ipv6(new_nd_data, &nd_key);
				break;
			case 3:
			        mg_printf(conn, "<p>ND REQ is not supported Yet!!!</p>");
				break;
			default:
				break;
		};
        }

        mg_printf(conn, "<p>Command Passed</p>");
        mg_printf(conn, "</body></html>\n");
	return 1;
}

int route_handler(struct mg_connection *conn, __rte_unused void *cbdata)
{
        /* Handler may access the request info using mg_get_request_info */
        const struct mg_request_info *req_info = mg_get_request_info(conn);
        uint32_t portid = 0;
	uint32_t i, j, status, p;
	char buf[MAX_BUF_SIZE];
	uint32_t mask = 0, num = 31;

        if (!strcmp(req_info->request_method, "GET")) {
        	mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
		mg_printf(conn, "<pre>\nIP_Address    Mask          Port\n<br/>");

		for (j = 0; j < gw_get_num_ports(); j++) {
			for (i = 0; i < p_route_data[j]->route_ent_cnt; i++) {
				mg_printf(conn, "0x%08x \t 0x%08x \t %d\n<br/>",
				p_route_data[j]->route_table[i].nh,
				p_route_data[j]->route_table[i].mask,
				p_route_data[j]->route_table[i].port);
			}
		}

		mg_printf(conn, "\n\nND IPV6 routing table ...\n<br/>");
		mg_printf(conn, "\nNH_IP_Address				"
				"	Depth          Port \n<br/>");
		for(p = 0; p < gw_get_num_ports(); p++ ) {
			for (i = 0; i < p_nd_route_data[p]->nd_route_ent_cnt; i++) {
				for (j = 0; j < ND_IPV6_ADDR_SIZE; j += 2) {
					mg_printf(conn, "%02X%02X ",
					 p_nd_route_data[p]->nd_route_table[i].nhipv6[j],
					p_nd_route_data[p]->nd_route_table[i].nhipv6[j + 1]);
				}

				mg_printf(conn, "\t%d		%d		"
					"			\n<br/></pre>",
					p_nd_route_data[p]->nd_route_table[i].depth,
					p_nd_route_data[p]->nd_route_table[i].port);
			}
		}

		return 1;
	}

        if (strcmp(req_info->request_method, "POST")) {
                mg_printf(conn,
                          "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n");
                mg_printf(conn, "Content-Type: text/plain\r\n\r\n");
                mg_printf(conn,
                          "%s method not allowed in the POST handler\n",
                          req_info->request_method);
                return 1; 
        }

        mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
        mg_printf(conn, "<html><body>");
        
	mg_read(conn, buf, sizeof(buf));
	json_object * jobj = json_tokener_parse(buf);
	json_object_object_foreach(jobj, key, val) {
		if (!strcmp(key, "portid")) {
			portid = atoi(json_object_get_string(val));
			if (portid >= 64) {
				mg_printf(conn, "Port not supported!!!\n");
				return 1;
			} else if (current_route_parms[portid].enable) {
				mg_printf(conn, "Already configured\n");
			}
		} else if (!strcmp(key, "nhipv4")) {
			current_route_parms[portid].ip =
				 rte_bswap32(inet_addr(json_object_get_string(val)));
			current_route_parms[portid].family = AF_INET;
		} else if (!strcmp(key, "nhipv6")) {
			my_inet_pton_ipv6(AF_INET6,
		 	json_object_get_string(val), &current_route_parms[portid].ipv6[0]);
			current_route_parms[portid].family = AF_INET6;
		} else if (!strcmp(key, "depth")) {
			current_route_parms[portid].depth = atoi(json_object_get_string(val));
			current_route_parms[portid].enable = 1;	
		} else if (!strcmp(key, "type")) {
			memcpy(current_route_parms[portid].type, json_object_get_string(val), 
				strlen(json_object_get_string(val)));
		} 
	}

	if (current_route_parms[portid].family == AF_INET) {
		if (!strcmp(current_route_parms[portid].type, "net"))  {
			for (i = 0; i < current_route_parms[portid].depth; i++) {
				mask |= (1 << num);
				num--;
			}
		} else
			mask = 0xFFFFFFFF;

		status = app_routeadd_config_ipv4(rapp, portid,
				 current_route_parms[portid].ip,
				 mask);
		if (status != 0)
			mg_printf(conn, "Setting route entry failed\n");
	} else {

		if (!strcmp(current_route_parms[portid].type, "host"))  {
			current_route_parms[portid].depth = 128;
		}
		status = app_routeadd_config_ipv6(rapp, portid,
			 current_route_parms[portid].ipv6,
			 current_route_parms[portid].depth);
		if (status != 0)
			mg_printf(conn, "Setting route entry failed\n");
	}


        mg_printf(conn, "</body></html>\n");
        return 1;
}

int link_handler(struct mg_connection *conn, __rte_unused void *cbdata)
{
        /* Handler may access the request info using mg_get_request_info */
        const struct mg_request_info *req_info = mg_get_request_info(conn);
	int i, status = 0, link = 0, link_read = 0;
	char buf[MAX_BUF_SIZE];

        if (!strcmp(req_info->request_method, "GET")) {
        	mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
		mg_printf(conn, "<html><body>\n");
		for (i = 0; i < MAX_LINKS; i++) {
			if (current_link_parms[i].state)
				mg_printf(conn, "link %d is enabled\r\n", i);
		}
		mg_printf(conn, "</body></html>\n");
		return 1;
	}

        if (strcmp(req_info->request_method, "POST")) {
                mg_printf(conn,
                          "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n");
                mg_printf(conn, "Content-Type: text/plain\r\n\r\n");
                mg_printf(conn,
                          "%s method not allowed in the POST handler\n",
                          req_info->request_method);
                return 1; 
        }

	mg_read(conn, buf, sizeof(buf));
	json_object * jobj = json_tokener_parse(buf);
	json_object_object_foreach(jobj, key, val) {
		if (!strcmp(key, "linkid")) {
			link = atoi(json_object_get_string(val));
			mg_printf(conn, "linkid:%d \n", link);
			if (link >= 64) {
				mg_printf(conn, "Link id not supported beyond 64\n");
				return 1;
			}
			current_link_parms[link].id = link;
			link_read = 1;
		} else if (!strcmp(key, "state")) {
			if (link_read) {
				current_link_parms[link].state =
					 atoi(json_object_get_string(val));
			}
			mg_printf(conn, "state:%d \n", current_link_parms[link].state);
		} 

	}


	if (current_link_parms[link].state == 0) {
		/* link down */
        	status = app_link_down(rapp, current_link_parms[link].id);
        	if (status != 0) {
        		mg_printf(conn, "<p>command failed</p>");
		} else {
        		mg_printf(conn, "<p>command Passed</p>");
		}
	} else if (current_link_parms[link].state == 1) {
		/* link up */
		mg_printf(conn, "setting up the link \n");
        	status = app_link_up(rapp, current_link_parms[link].id);
        	if (status != 0) {
        		mg_printf(conn, "<p>command failed</p>");
		} else {
        		mg_printf(conn, "<p>command Passed</p>");
		}

	}

	sprintf(buf, "/vnf/config/link/%d", link);
	mg_set_request_handler(ctx, buf, linkid_handler, (void *)&link);

        mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
        return 1;
}

int linkid_handler(struct mg_connection *conn, void *cbdata)
{
        /* Handler may access the request info using mg_get_request_info */
        const struct mg_request_info *req_info = mg_get_request_info(conn);
	int status = 0;
	char buf[MAX_BUF_SIZE];

        if (!strcmp(req_info->request_method, "GET")) {
		mg_printf(conn,
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
			"close\r\n\r\n");
		mg_printf(conn, "<html><body>\n");
		linkls_handler(conn, cbdata);
		mg_printf(conn, "</body></html>\n");
		return 1;
	}

        if (strcmp(req_info->request_method, "POST")) {
                mg_printf(conn,
                          "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n");
                mg_printf(conn, "Content-Type: text/plain\r\n\r\n");
                mg_printf(conn,
                          "%s method not allowed in the POST handler\n",
                          req_info->request_method);
                return 1; 
        }

        mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
        mg_printf(conn, "<html><body>");
        
        uint32_t linkid = *(uint32_t *)cbdata;
        mg_printf(conn, "link id :%d ", linkid);

	if (!current_link_parms[linkid].state) {
        	mg_printf(conn, "<p>link not enabled!! </p>");
        	mg_printf(conn, "</body></html>\n");
		return 1;
	}
		
	mg_read(conn, buf, sizeof(buf));
	json_object * jobj = json_tokener_parse(buf);
	json_object_object_foreach(jobj, key, val) {
		if (!strcmp(key, "ipv4")) {
			current_link_parms[linkid].ip =
				 rte_bswap32(inet_addr(json_object_get_string(val)));
			current_link_parms[linkid].family = AF_INET;
		} else if (!strcmp(key, "ipv6")) {
			my_inet_pton_ipv6(AF_INET6,
		 	json_object_get_string(val), &current_link_parms[linkid].ipv6[0]);
			current_link_parms[linkid].family = AF_INET6;
		} else if (!strcmp(key, "depth")) {
			current_link_parms[linkid].depth = atoi(json_object_get_string(val));
		} 
	}


	/* bring the link down */
        status = app_link_down(rapp, linkid);
        if (status != 0) {
        	mg_printf(conn, "<p>command down failed</p>");
	} else {
        	mg_printf(conn, "<p>command Passed</p>");
	}

	/* configure the ip address */
        if (current_link_parms[linkid].family == AF_INET) {
               	status = app_link_config(rapp, linkid, current_link_parms[linkid].ip,
			current_link_parms[linkid].depth);
	} else {
               	status = app_link_config_ipv6(rapp, linkid,
			current_link_parms[linkid].ipv6, current_link_parms[linkid].depth);
	}

       	if (status != 0) {
       		mg_printf(conn, "<p>command config failed</p>");
	} else {
       		mg_printf(conn, "<p>command Passed</p>");
	}

	/* bring the link up */
       	status = app_link_up(rapp, linkid);
       	if (status != 0) {
       		mg_printf(conn, "<p>command up failed</p>");
	} else {
       		mg_printf(conn, "<p>command Passed</p>");
	}


        mg_printf(conn, "</body></html>\n");
        return 1;
}

void set_vnf_type(const char *type)
{
	memcpy(current_cfg.vnf_type, type, strlen(type));
}

void init_stat_cfg(void)
{
	char buf[256] = "98103214:(1, 65535)";
	uint32_t i;

	current_cfg.num_workers = 4;
	current_cfg.num_lb = 1;
	current_cfg.num_ports = 2;
	current_cfg.hyper_thread = 0;
	current_cfg.sock_in = 0;
	current_cfg.sw_lb = 1;
	memcpy(current_cfg.pkt_type, "ipv4", 4);

	for (i=0;i<MAX_LB;i++) {
		memcpy(current_cfg.ip_range[i].value, &buf,
			sizeof(buf));
	}
}

static void set_port_mask(uint64_t num_ports)
{
	uint64_t i;
	uint64_t mask = 0;

	for (i = 0; i < num_ports; i++) {
		mask |= (0x1 << i);
	}
	rapp->port_mask = mask;
}

void bind_the_ports(struct mg_connection *conn, char *pci_white_list)
{
	char *token;
	char buf[MAX_BUF_SIZE];
	int x = 0, ret;

	token = strtok(pci_white_list, " ");

	while(token != NULL) {
		mg_printf(conn, "%s ****\n", token);
		sprintf(buf, "dpdk-devbind -u %s", token);
		ret = system(buf);
		if (ret)
			mg_printf(conn, "wrong parameter sent\n");

		sprintf(buf, "dpdk-devbind -b igb_uio %s", token);
		ret = system(buf);
		if (ret)
			mg_printf(conn, "wrong parameter sent\n");

		token = strtok(NULL, " ");

		x++;
	}
	current_cfg.num_ports = x;
	set_port_mask(x);
}

int static_cfg_handler(struct mg_connection *conn, __rte_unused void *cbdata)
{
        int i;
	unsigned int len;
        char buf[MAX_BUF_SIZE];

        const struct mg_request_info *ri = mg_get_request_info(conn);

        if (!strcmp(ri->request_method, "GET")) {
        	mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
        	mg_printf(conn, "<html><body>");
        	mg_printf(conn, "<h2> These are the values set in config</h2>");
        	mg_printf(conn, "<h3> num_workers: %d\n</h3>",
					 current_cfg.num_workers);
        	mg_printf(conn, "<h3> num_lb: %d\n</h3>",
					 current_cfg.num_lb);
        	mg_printf(conn, "<h3> num_ports: %d\n</h3>",
					 current_cfg.num_ports);
        	mg_printf(conn, "<h3> hyper_thread: %d\n</h3>",
					 current_cfg.hyper_thread);
        	mg_printf(conn, "<h3> socket_id : %d\n</h3>",
					 current_cfg.sock_in);
        	mg_printf(conn, "<h3> sw_lb: %d\n</h3>",
					 current_cfg.sw_lb);
        	mg_printf(conn, "<h3> vnf_type: %s\n</h3>",
					current_cfg.vnf_type);
        	mg_printf(conn, "<h3> pkt_type: %s\n</h3>",
					 current_cfg.pkt_type);
        	mg_printf(conn, "<h3> pci_white_list: %s\n</h3>",
					 current_cfg.pci_white_list);
        	mg_printf(conn, "</body></html>\n");
		return 1;
	}

        if (strcmp(ri->request_method, "POST")) {
                mg_printf(conn,
                          "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n");
                mg_printf(conn, "Content-Type: text/plain\r\n\r\n");
                mg_printf(conn,
                          "%s method not allowed in the POST handler\n",
                          ri->request_method);
                return 1; 
        }

	if (static_cfg_set) {
        	mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
		return 1;
	}
		
        mg_read(conn, buf, sizeof(buf));
	json_object * jobj = json_tokener_parse(buf);
	len = 0;
	struct json_object *values;

	i = 0;
	json_object_object_foreach(jobj, key, val) {
		memcpy(static_cfg[i].key, key, strlen(key));
		memcpy(static_cfg[i].value, json_object_get_string(val),
				 strlen(json_object_get_string(val)));
		sprintf(buf, "public_ip_port_range_%d", pub_ip);
		if (!strcmp(static_cfg[i].key, buf)) {
			memcpy(&current_cfg.ip_range[pub_ip].value,
				static_cfg[i].value,
				 sizeof(static_cfg[i].value));
			pub_ip++;
		}
		i++;
	}
	n_entries1 = i;

	json_object_object_get_ex(jobj, "num_worker", &values);
	if (values) {
		memcpy(&current_cfg.ip_range[pub_ip++].value, json_object_get_string(values),
			 strlen(json_object_get_string(values)));
		current_cfg.num_workers = atoi(json_object_get_string(values));
	}

	json_object_object_get_ex(jobj, "pkt_type", &values);
	if (values) {
		memcpy(&current_cfg.pkt_type, json_object_get_string(values),
			 sizeof(current_cfg.pkt_type));
	}

	json_object_object_get_ex(jobj, "num_lb", &values);
	if (values) {
		current_cfg.num_lb = atoi(json_object_get_string(values));
	}

	json_object_object_get_ex(jobj, "num_ports", &values);
	if (values) {
		current_cfg.num_ports = atoi(json_object_get_string(values));
	}
	
	json_object_object_get_ex(jobj, "sw_lb", &values);
	if (values) {
		current_cfg.sw_lb = atoi(json_object_get_string(values));
	}

	json_object_object_get_ex(jobj, "sock_in", &values);
	if (values) {
		current_cfg.sock_in = atoi(json_object_get_string(values));
	}

	json_object_object_get_ex(jobj, "hyperthread", &values);
	if (values) {
		current_cfg.hyper_thread = atoi(json_object_get_string(values));
	}

	json_object_object_get_ex(jobj, "vnf_type", &values);
	if (values) {
		memcpy(&current_cfg.vnf_type, json_object_get_string(values),
			 sizeof(current_cfg.vnf_type));
	}

	json_object_object_get_ex(jobj, "pci_white_list", &values);
	if (values) {
		memcpy(&current_cfg.pci_white_list, json_object_get_string(values),
			sizeof(current_cfg.pci_white_list));
		mg_printf(conn, " Binding the ports \n");
		bind_the_ports(conn, &current_cfg.pci_white_list[0]);
	}

	len = sprintf(buf, "POST DATA RECEIVED\n");
	
	mg_printf(conn,
	          "HTTP/1.1 200 OK\r\n"
	          "Content-Length: %u\r\n"
	          "Content-Type: text/plain\r\n"
	          "Connection: close\r\n\r\n",
	          len);

	mg_write(conn, buf, len);
	post_not_received = 0;
	static_cfg_set++;
        return 1;
}

int vnf_handler(struct mg_connection *conn, __rte_unused void *cbdata)
{
        /* Handler may access the request info using mg_get_request_info */
        const struct mg_request_info *req_info = mg_get_request_info(conn);

        if (!strcmp(req_info->request_method, "GET")) {
        	mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
        	mg_printf(conn, "<html><body>");
        	mg_printf(conn, "<h2>These are the methods that are supported</h2>");
        	mg_printf(conn, "<h3> /vnf/config</h3>");
        	mg_printf(conn, "<h3> /vnf/config/arp</h3>");
        	mg_printf(conn, "<h3> /vnf/config/link</h3>");
        	mg_printf(conn, "<h3> /vnf/config/route</h3>");
        	mg_printf(conn, "<h3> /vnf/config/rules(vFW/vACL only)</h3>");
        	mg_printf(conn, "<h3> /vnf/config/rules/load(vFW/vACL only)</h3>");
        	mg_printf(conn, "<h3> /vnf/config/rules/clear(vFW/vACL only)</h3>");
        	mg_printf(conn, "<h3> /vnf/config/nat(vCGNAPT only)</h3>");
        	mg_printf(conn, "<h3> /vnf/config/nat/load(vFW/vACL only)</h3>");
        	mg_printf(conn, "<h3> /vnf/config/dbg</h3>");
        	mg_printf(conn, "<h3> /vnf/config/dbg/pipelines</h3>");
        	mg_printf(conn, "<h3> /vnf/config/dbg/cmd</h3>");
        	mg_printf(conn, "<h3> /vnf/log</h3>");
        	mg_printf(conn, "<h3> /vnf/flowdirector</h3>");
        	mg_printf(conn, "<h3> /vnf/status</h3>");
        	mg_printf(conn, "<h3> /vnf/stats</h3>");
        	mg_printf(conn, "<h3> /vnf/quit</h3>");
        	mg_printf(conn, "</body></html>");


		return 1;
	}

        if (strcmp(req_info->request_method, "POST")) {
                mg_printf(conn,
                          "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n");
                mg_printf(conn, "Content-Type: text/plain\r\n\r\n");
                mg_printf(conn,
                          "%s method not allowed in the POST handler\n",
                          req_info->request_method);
                return 1; 
        }

	return 1;
}

void get_pktq_in_prv(char *buf)
{
	int j;
	uint32_t len = 0;
	for (j = 0; j < current_cfg.num_ports; j+=2) {
		len += sprintf(buf + len, "RXQ%d.0 ", j);
	}
}

void fix_pipelines_data_types(FILE *f, const char *sect_name, struct rte_cfgfile *tcfg)
{
	int i, j, n_entries, tmp = 0;
	char str[256], str1[40];

	n_entries = rte_cfgfile_section_num_entries(tcfg, sect_name);

	rte_cfgfile_section_entries(tcfg, sect_name, entries, n_entries);

	for (i = 0; i < n_entries; i++) {
		for (j = 0; j < n_entries1; j++) {
			if (strncmp(entries[i].name, static_cfg[i].key,
				 strlen(entries[i].name)) == 0) {
				memcpy(entries[i].value, static_cfg[i].value,
				 strlen(entries[i].value));
				tmp++;
			}

			if (strncmp(entries[i].name, "pkt_type",
                                 strlen("pkt_type")) == 0) {
				memcpy(entries[i].value, current_cfg.pkt_type, 24);
				if (!strcmp(current_cfg.pkt_type, "ipv4"))
					memcpy(&traffic_type, "4", 1);
				else
					memcpy(&traffic_type, "6", 1);
			}

			if (strncmp(entries[i].name, "traffic_type",
                                 sizeof("traffic_type")) == 0) {
				memcpy(entries[i].value, &traffic_type, 4);
			}
		}

		if (strncmp(entries[i].name, "core", strlen(entries[i].name)) == 0) {
			if (((strncmp(sect_name, "MASTER", strlen(sect_name)) == 0) ||
                            (strncmp(sect_name, "TIMER", strlen(sect_name)) == 0) ||
                            (strncmp(sect_name, "ARPICMP", strlen(sect_name)) == 0)) && 
				!current_cfg.sock_in) {
				sprintf(str, "s%dc%d", current_cfg.sock_in,
					 sock_cpus[current_cfg.sock_in][sock_index]);
				memcpy(entries[i].value, &str, 8);
				hyper = 0;
				continue;
			}

                        if ((strncmp(sect_name, "TXRX-BEGIN", strlen(sect_name)) == 0) || (strncmp(sect_name, "LOADB", strlen(sect_name)) == 0) ||
                            (strncmp(sect_name, "TXRX-END", strlen(sect_name)) == 0)) {
                             sock_index++;
			     sprintf(str, "s%dc%d", current_cfg.sock_in,
			   	     sock_cpus[current_cfg.sock_in][sock_index]);
			     memcpy(entries[i].value, &str, 8);
		             hyper = 0;
                             continue;
                        } else {
                             if (!hyper) {
                                  sock_index++;
                                  sprintf(str, "s%dc%d", current_cfg.sock_in, sock_cpus[current_cfg.sock_in][sock_index]);
                                  if (current_cfg.hyper_thread)
				      hyper = 1;
                             } else {
			          sprintf(str, "s%dc%dh", current_cfg.sock_in, sock_cpus[current_cfg.sock_in][sock_index]);
				  hyper = 0;
                             }
                        }
			memcpy(entries[i].value, &str, 8);
		}
	}
	num_entries = i;

	if (strncmp(sect_name, "ARPICMP", strlen(sect_name)) == 0) {
		for (j = 0; j < n_entries1; j++) {
			if ((strncmp(static_cfg[j].key, "arp_route_tbl",
				 strlen(static_cfg[j].key)) == 0) ||
		 		(strncmp(static_cfg[j].key, "nd_route_tbl",
				 strlen(static_cfg[j].key)) == 0)) {
				memcpy(&entries[i].name, &static_cfg[j].key,
					 strlen(entries[i].name));
				memcpy(&entries[i].value, &static_cfg[j].value,
				 strlen(static_cfg[j].value));
				i++;
			}
		}
		num_entries = i;
		/* update pktq_in/pktq_out */
		for (i=0; i < n_entries; i++) {
			memset(str, 0, 256);
			if (strncmp(entries[i].name, "pktq_in",
				 strlen(entries[i].name)) == 0) {
				tmp = (current_cfg.sw_lb)? current_cfg.num_lb: current_cfg.num_workers;
				get_swq(tmp, &str[0]);
				memcpy(&entries[i].value, &str, strlen(str));
				continue;
			}

			if (strncmp(entries[i].name, "pktq_out",
				 strlen(entries[i].name)) == 0) {
				//tmp = (current_cfg.sw_lb)? current_cfg.num_lb: current_cfg.num_workers / 2;
				//tmp = (current_cfg.sw_lb)? current_cfg.num_lb: current_cfg.num_ports;
				get_txq(0, 1, current_cfg.num_ports, &str[0]);
				memcpy(&entries[i].value, &str, strlen(str));
				continue;
			}

			if (strncmp(entries[i].name, "pktq_in_prv",
				 strlen(entries[i].name)) == 0) {
				get_pktq_in_prv(&str[0]);
				memset(&entries[i].value, 0, sizeof(entries[i].value));
				memcpy(&entries[i].value, &str, strlen(str));
				continue;
			}

			if (strncmp(entries[i].name, "prv_to_pub_map",
				 strlen(entries[i].name)) == 0) {
				get_prv_to_pub_map(&str[0]);
				memcpy(&entries[i].value, &str, strlen(str));
				continue;
			}

			if (strncmp(entries[i].name, "prv_que_handler",
				 strlen(entries[i].name)) == 0) {
				get_prv_que_handler(&str[0]);
				memcpy(&entries[i].value, &str, strlen(str));
				continue;
			}
		}
	}

	if (strncmp(sect_name, "TXRX-BEGIN", strlen(sect_name)) == 0) {
		for (i=0; i < n_entries; i++) {
			if (strncmp(entries[i].name, "pktq_in",
				 strlen(entries[i].name)) == 0) {
				get_rxq(0, 1, 2, &str[0]);
				memcpy(entries[i].value, &str, sizeof(str));
			}

			if (strncmp(entries[i].name, "pktq_out",
				 strlen(entries[i].name)) == 0) {
				get_swq(2, &str[0]);
				memcpy(loadb_in, str, sizeof(str));
				sprintf(str1," SWQ%d", arp_index++);
				strcat(str, str1);	
				memcpy(entries[i].value, &str, sizeof(str));
			}
		}
	}

	if (strncmp(sect_name, "LOADB", strlen(sect_name)) == 0) {
		for (i=0; i < n_entries; i++) {
			if (strncmp(entries[i].name, "pktq_in",
				 strlen(entries[i].name)) == 0) {
				memcpy(entries[i].value, &loadb_in, sizeof(str));
			}

			if (strncmp(entries[i].name, "pktq_out",
				 strlen(entries[i].name)) == 0) {
				if (current_cfg.num_ports > 2)
					tmp = (current_cfg.num_workers/current_cfg.num_lb * 2);
				else
					tmp = current_cfg.num_workers * 2;
				start_lb = swq_index;
				end_lb = tmp;
				start_lbout = start_lb + end_lb;
				get_swq(tmp, &str[0]);
				memcpy(entries[i].value, &str, sizeof(str));
			}
			if (strncmp(entries[i].name, "n_vnf_threads",
				 strlen(entries[i].name)) == 0) {
				sprintf(str1, "%d", current_cfg.num_workers/current_cfg.num_lb);
				memcpy(entries[i].value, &str1, sizeof(str1));
			}
		}
	}

	if (strncmp(sect_name, "VACL", strlen(sect_name)) == 0) {
		for (i=0; i < n_entries; i++) {
			if (strncmp(entries[i].name, "pktq_in",
				 strlen(entries[i].name)) == 0) {
				if (current_cfg.sw_lb) {
					get_swq_offset(start_lb, 2, &str[0]);
					start_lb += 2;
				} else
					get_rxq(workers, 1, 2, &str[0]);

				memcpy(entries[i].value, &str, sizeof(str));
			}

			if (strncmp(entries[i].name, "pktq_out",
				 strlen(entries[i].name)) == 0) {
				if (current_cfg.sw_lb)
					get_swq(2, &str[0]);
				else {
					get_txq(workers+1, 1, 2, &str[0]);
					sprintf(str1," SWQ%d", arp_index++);
					strcat(str, str1);
				}
				memcpy(entries[i].value, &str, sizeof(str));
			}
		}

		workers++;
		if (current_cfg.sw_lb) {
			if (((workers % current_cfg.num_workers/current_cfg.num_lb) == 0) &&
				 (workers != current_cfg.num_workers)) {
				workers = 0;
			}
		} else {
			if ((workers % current_cfg.num_workers/current_cfg.num_lb) == 0) {
				tx_start_port += 2;
				rx_start_port += 2;
				workers = 0;
			}
		}
	}

	if (strncmp(sect_name, "VCGNAPT", strlen(sect_name)) == 0) {
		for (i=0; i < n_entries; i++) {
			if (strncmp(entries[i].name, "pktq_in",
				 strlen(entries[i].name)) == 0) {
				if (current_cfg.sw_lb) {
					get_swq_offset(start_lb, 2, &str[0]);
					start_lb += 2;
				} else
					get_rxq(workers, 1, 2, &str[0]);

				memcpy(entries[i].value, &str, sizeof(str));
			}

			if (strncmp(entries[i].name, "pktq_out",
				 strlen(entries[i].name)) == 0) {
				if (current_cfg.sw_lb)
					get_swq(2, &str[0]);
				else {
					get_txq(workers+1, 1, 2, &str[0]);
					sprintf(str1," SWQ%d", arp_index++);
					strcat(str, str1);
				}
				memcpy(entries[i].value, &str, sizeof(str));
			}
		}

		if (workers == 0) {
			char *token;
			sprintf(str1, "vnf_set");
			memcpy(entries[i].name, &str1, sizeof(str1));
			sprintf(str1, "(3,4,5)");
			memcpy(entries[i].value, &str1, sizeof(str1));
			num_entries++;
			i++;

			token = strtok(current_cfg.ip_range[ip_range].value, "/");
			while(token) {
				sprintf(str1, "public_ip_port_range");
				memcpy(entries[i].name, &str1, sizeof(str1));
				memcpy(entries[i].value, token, strlen(token));
				i++;
				num_entries++;
				token = strtok(NULL, "/");
			}
			ip_range++;
		}

		workers++;
		if (current_cfg.sw_lb) {
			if (((workers % (current_cfg.num_workers/current_cfg.num_lb)) == 0) &&
				 (workers != current_cfg.num_workers)) {
				workers = 0;
			}
		} else {
			if (workers == (current_cfg.num_workers/current_cfg.num_lb)) {
				tx_start_port += 2;
				rx_start_port += 2;
				workers = 0;
			}
		}
	}

	if (strncmp(sect_name, "VFW", strlen(sect_name)) == 0) {
		for (i=0; i < n_entries; i++) {
			if (strncmp(entries[i].name, "pktq_in",
				 strlen(entries[i].name)) == 0) {
				if (current_cfg.sw_lb) {
					get_swq_offset(start_lb, 2, &str[0]);
					start_lb += 2;
				} else
					get_rxq(workers, 1, 2, &str[0]);

				memcpy(entries[i].value, &str, sizeof(str));
			}

			if (strncmp(entries[i].name, "pktq_out",
				 strlen(entries[i].name)) == 0) {
				if (current_cfg.sw_lb)
					get_swq(2, &str[0]);
				else {
					get_txq(workers+1, 1, 2, &str[0]);
					sprintf(str1," SWQ%d", arp_index++);
					strcat(str, str1);
				}
				memcpy(entries[i].value, &str, sizeof(str));
			}
		}

		workers++;
		if (current_cfg.sw_lb) {
			if (((workers % current_cfg.num_workers/current_cfg.num_lb) == 0)
				 && (workers != current_cfg.num_workers)) {
				workers = 0;
			}
		} else {
			if (workers == (current_cfg.num_workers/current_cfg.num_lb)) {
				tx_start_port += 2;
				rx_start_port += 2;
				workers = 0;
			}
		}
	}

	if (strncmp(sect_name, "TXRX-END", strlen(sect_name)) == 0) {
		for (i=0; i < n_entries; i++) {
			if (strncmp(entries[i].name, "pktq_in",
				 strlen(entries[i].name)) == 0) {
				get_swq_offset(start_lbout, end_lb, &str[0]);
				memcpy(entries[i].value, &str, sizeof(str));
			}

			if (strncmp(entries[i].name, "pktq_out",
				 strlen(entries[i].name)) == 0) {
				get_txq(1, end_lb / 2, 2, &str[0]);
				memcpy(entries[i].value, &str, sizeof(str));
			}
		}
		tx_start_port += 2;
		rx_start_port += 2;
	}

	fprintf(f, "[PIPELINE%d]\n", pipenum);
	for (i=0;i<num_entries;i++) {
		fprintf(f, "%s = %s\n", entries[i].name, entries[i].value);
	}
	fprintf(f, "\n");
	pipenum++;
}

void print_to_file(FILE *f, struct rte_cfgfile *tcfg)
{
	int i;
	for (i=0;i<num_pipelines;i++) {
		fix_pipelines_data_types(f, pipelines[pipe_arr[i]], tcfg);
	}
	fclose(f);
}

int get_vnf_index(void)
{

	int i;

	for (i = 0; i < PIPE_MAX; i++) {
		if (strncmp(pipelines[i], current_cfg.vnf_type,
				 strlen(current_cfg.vnf_type)) == 0)
			return i;
	}
	return -1;
}

void build_pipeline(void)
{
	int i = 2, j, k, vnf_index;

	pipe_arr[0] = 0;
	pipe_arr[1] = 1;
	vnf_index = get_vnf_index();
	if (vnf_index == -1)
		printf("Wrong VNF TYPE\n");

	if (vnf_index == VNF_VCGNAPT)
	    pipe_arr[i++] = 2;

	if (!current_cfg.sw_lb) {
		for (k = 0; k < current_cfg.num_workers; k++)
			pipe_arr[i++] = vnf_index;
		num_pipelines = i;
		return;
	}

	for (j = 0; j < current_cfg.num_lb; j++) {
			/* put TXRX-BEGIN & LOADB pipelines */
		pipe_arr[i++] = TXRX_BEGIN;
		pipe_arr[i++] = LOADB;

		/* place the worker threads */
		int limit = current_cfg.num_workers / current_cfg.num_lb;
		for (k = 0; k < limit; k++)
			pipe_arr[i++] = vnf_index;

		/* end the TXRX pipeline */
		pipe_arr[i++] = TXRX_END;
	}
	num_pipelines = i;
}

int set_hash_global_config(struct mg_connection *conn, uint32_t port_id,
	 char *flow_type, const char *hash_func, const char *enable)
{
        struct rte_eth_hash_filter_info info;
        uint32_t ftype, idx, offset;
        int ret;

        if (rte_eth_dev_filter_supported(port_id,
                                RTE_ETH_FILTER_HASH) < 0) {
                mg_printf(conn, "RTE_ETH_FILTER_HASH not supported on port %d\n",
                                port_id);
                return 1;
        }
        memset(&info, 0, sizeof(info));
        info.info_type = RTE_ETH_HASH_FILTER_GLOBAL_CONFIG;
        if (!strcmp(hash_func, "toeplitz"))
                info.info.global_conf.hash_func =
                        RTE_ETH_HASH_FUNCTION_TOEPLITZ;
        else if (!strcmp(hash_func, "simple_xor"))
                info.info.global_conf.hash_func =
                        RTE_ETH_HASH_FUNCTION_SIMPLE_XOR;
        else if (!strcmp(hash_func, "default"))
                info.info.global_conf.hash_func =
                        RTE_ETH_HASH_FUNCTION_DEFAULT;

        ftype = str2flowtype(flow_type);
        idx = ftype / (CHAR_BIT * sizeof(uint32_t));
        offset = ftype % (CHAR_BIT * sizeof(uint32_t));
        info.info.global_conf.valid_bit_mask[idx] |= (1UL << offset);
        if (!strcmp(enable, "enable"))
                if(idx < RTE_SYM_HASH_MASK_ARRAY_SIZE)
                info.info.global_conf.sym_hash_enable_mask[idx] |=
                        (1UL << offset);
        ret = rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_HASH,
                        RTE_ETH_FILTER_SET, &info);
        if (ret < 0)
                mg_printf(conn, "Cannot set global hash configurations by port %d\n",
                                port_id);
        else
                mg_printf(conn, "Global hash configurations have been set "
                                "succcessfully by port %d\n", port_id);
	return 1;
}

int flow_director_handler(struct mg_connection *conn, __rte_unused void *cbdata)
{
        /* Handler may access the request info using mg_get_request_info */
        const struct mg_request_info *req_info = mg_get_request_info(conn);
        uint32_t port_id = 0, tuple = 0;
        char buf[MAX_BUF_SIZE];
	char field0[MAX_SIZE], field1[MAX_SIZE], field2[MAX_SIZE],
		 field3[MAX_SIZE], flow_type[MAX_SIZE];

        if (!strcmp(req_info->request_method, "GET")) {
        	mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
        	mg_printf(conn, "<html><body>");
		if (flow_dir_cfg)
        		mg_printf(conn, "<h3> Flow is configured </h3>");
		else
        		mg_printf(conn, "<h3> Flow is NOT configured </h3>");
        	mg_printf(conn, "</body></html>");
		return 1;
	}

        if (strcmp(req_info->request_method, "POST")) {
        	mg_printf(conn,
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                  "close\r\n\r\n");
        	mg_printf(conn, "<html><body>");
		mg_printf(conn, "This method is not supported\n");
        	mg_printf(conn, "</body></html>");
		return 1;

	}

	mg_read(conn, buf, sizeof(buf));
	json_object * jobj = json_tokener_parse(buf);
	json_object_object_foreach(jobj, key, val) {
		if (!strcmp(key, "trans_type")) {
			if (!strcmp(key, "udp")) {
				memcpy(field2,"udp-src-port", sizeof("udp-src-port"));
				memcpy(field3,"udp-dst-port", sizeof("udp-dst-port"));
				if (!strcmp(current_cfg.pkt_type, "ipv4")) {
					memcpy(flow_type,"ipv4-udp", sizeof("ipv4-udp"));
					memcpy(field0,"src-ipv4", sizeof("src-ipv4"));
					memcpy(field1,"dst-ipv4", sizeof("dst-ipv4"));
				} else if (!strcmp(current_cfg.pkt_type, "ipv6")) {
					memcpy(flow_type,"ipv6-udp", sizeof("ipv6-udp"));
					memcpy(field0,"src-ipv6", sizeof("src-ipv6"));
					memcpy(field1,"dst-ipv6", sizeof("dst-ipv6"));
				}
			} else if (!strcmp(key, "tcp")) {
				memcpy(field2,"tcp-src-port", sizeof("tcp-src-port"));
				memcpy(field3,"tcp-dst-port", sizeof("tcp-dst-port"));
				if (!strcmp(current_cfg.pkt_type, "ipv4")) {
					memcpy(flow_type,"ipv4-tcp", sizeof("ipv4-tcp"));
					memcpy(field0,"src-ipv4", sizeof("src-ipv4"));
					memcpy(field1,"dst-ipv4", sizeof("dst-ipv4"));
				} else if (!strcmp(current_cfg.pkt_type, "ipv6")) {
					memcpy(flow_type,"ipv6-tcp", sizeof("ipv6-tcp"));
					memcpy(field0,"src-ipv6", sizeof("src-ipv6"));
					memcpy(field1,"dst-ipv6", sizeof("dst-ipv6"));
				}
			}
		} else if (!strcmp(key, "tuple")) {
			tuple = atoi(json_object_get_string(val));
			if ((tuple != 2) || (tuple != 5))
				return 1;
		} 
	}

	if (tuple == 2) {
		set_pkt_forwarding_mode("rxonly");
		for (port_id = 0; port_id < current_cfg.num_ports; port_id++) {
			set_sym_hash_per_port(conn, port_id);
			set_hash_global_config(conn, port_id, flow_type,
			 "simple_xor", "enable");
		}

		for (port_id = 0; port_id < current_cfg.num_ports; port_id+=2) {
			set_hash_input_set_2(conn, port_id, "ipv4-udp", "src-ipv4",
				 "udp-src-port", "add"); 
			set_hash_input_set_2(conn, port_id, "ipv4-udp", "dst-ipv4",
				 "udp-dst-port", "add"); 
			set_hash_input_set_2(conn, port_id, "ipv4-udp", "src-ipv6",
				 "udp-src-port", "add"); 
			set_hash_input_set_2(conn, port_id, "ipv4-udp", "dst-ipv6",
				 "udp-dst-port", "add");
		}
	} else if (tuple == 5) {
		set_pkt_forwarding_mode("rxonly");
		for (port_id = 0; port_id < current_cfg.num_ports; port_id++) {
			set_sym_hash_per_port(conn, port_id);
			set_hash_global_config(conn, port_id, flow_type,
			"simple_xor", "enable");
		}

		for (port_id = 0; port_id < current_cfg.num_ports; port_id+=2) {
			set_hash_input_set_4(conn, port_id, flow_type, field0, field1,
				field2, field3, "add");
		}
	}
	flow_dir_cfg = 1;
	return 1;
}

void get_swq_offset(uint8_t start, uint8_t num, char *buf)
{
	int i;
	uint32_t len = 0;

	for (i = start; i < start+num; i++) {
		sprintf(buf + len, "SWQ%d ", i);
		len = strlen(buf);
	}
}

void get_swq(uint8_t num, char *buf)
{
	int i;
	uint32_t len = 0;

	for (i=0;i<num;i++) {
		sprintf(buf + len, "SWQ%d ", swq_index++);
		len = strlen(buf);
	}
}

void get_prv_to_pub_map(char *buf)
{
	int j;
	uint32_t len = 0;
	for (j = 0; j < current_cfg.num_ports; j+=2) {
		sprintf(buf + len, "(%d,%d)", j, j+1);
		len = strlen(buf);
	}
}

void get_prv_que_handler(char *buf)
{
	int j;
	uint32_t len = 0;
	sprintf(buf + len, "(");
	len = strlen(buf);
	for (j = 0; j < current_cfg.num_ports; j+=2) {
		sprintf(buf + len, "%d,", j);
		len = strlen(buf);
	}
	sprintf(buf + len, ")");
}

void get_txq(uint8_t start_q, uint8_t queue_num, uint8_t ports, char *buf)
{
	int i, j;
	uint32_t len = 0;
	for (i=tx_start_port;i<tx_start_port + ports;i+=2)
	{
		for (j=start_q;j<(start_q + queue_num);j++)
		{
			sprintf(buf + len, " TXQ%d.%d TXQ%d.%d", i, j, i+1, j);
			len = strlen(buf);
		}
	}

}

void get_rxq(uint8_t start_q, uint8_t queue_num, uint8_t ports, char *buf)
{
	int i, j;
	uint32_t len = 0;

	for (i=rx_start_port;i<rx_start_port + ports;i+=2)
	{
		for (j=start_q;j<(start_q + queue_num);j++)
		{
			sprintf(buf + len, " RXQ%d.%d RXQ%d.%d", i, j, i+1, j);
			len = strlen(buf);
		}
	}

}

struct mg_context *
rest_api_init(struct app_params *app)
{
        struct rte_cfgfile *tcfg;
	FILE *f;
	char buf[256];
    	const char *options[] = {"listening_ports", "80", NULL};
	uint32_t i, lcore_id = 0;
	uint32_t sock, index;
	
	/* Server context handle */
	rapp = app;

	for (lcore_id=0;lcore_id<64;lcore_id++) {
		//lcore_id = rte_get_next_lcore(lcore_id, 0, 0);
		sock = eal_cpu_socket_id(lcore_id);
		index = (sock == 0)? sock0++ : sock1++;
		sock_cpus[sock][index] = lcore_id;
	}


	/* Initialize the icivetweb library */
	mg_init_library(0);

	/* Start the server */
	ctx = mg_start(NULL, 0, options);
	if (ctx == NULL) {
		printf("REST server did not start\n");
		printf("REST services will not be supported.. Try again ");
		printf("by disabling other webservers running on port 80\n");
		goto end;
	}
	
	/* init handlers being called here */
	init_stat_cfg();

	/* static config handler */
	mg_set_request_handler(ctx, "/vnf", vnf_handler, 0);
	mg_set_request_handler(ctx, "/vnf/config", static_cfg_handler, 0);
	
	/* arp handler */
        mg_set_request_handler(ctx, "/vnf/config/arp", arp_handler, 0);

	/* route handler */
        mg_set_request_handler(ctx, "/vnf/config/route", route_handler, 0);


	/* link related handlers */
        mg_set_request_handler(ctx, "/vnf/config/link", link_handler, 0);
        //mg_set_request_handler(ctx, "/vnf/config/link/*", linkid_handler, 0);

	/* dbg related handlers */
        mg_set_request_handler(ctx, "/vnf/config/dbg", dbg_handler, 0);
        mg_set_request_handler(ctx, "/vnf/config/dbg/pipelines", dbg_pipelines_handler, 0);
        mg_set_request_handler(ctx, "/vnf/config/dbg/cmd", dbg_cmd_handler, 0);
        mg_set_request_handler(ctx, "/vnf/config/dbg/run", dbg_run_handler, 0);

        mg_set_request_handler(ctx, "/vnf/quit", cmd_quit_handler, 0);

	printf("Waiting for config input.... via rest\n");
	index = 0;
	while(1) {
		if (post_not_received == 0)
			break;
		sleep(1);
		index++;
	}

	if (index == 30 && (post_not_received != 0))
		printf("Input not received for 30 secs, going with default");

	const char *name = "vnf_template.txt";
        /* Load application configuration file */
        tcfg = rte_cfgfile_load(name, 0);
	if (tcfg == NULL)
		printf("File could not be loaded\n");

//	if (!current_cfg.sw_lb)
//		current_cfg.num_lb = 1;

	/* build pipelines based on the input given */
	build_pipeline();

	for (i = 0; i < num_pipelines; i++) {
		sprintf(buf, "/vnf/config/dbg/pipelines/%d", i);
	        mg_set_request_handler(ctx, buf, dbg_pipelines_id_handler, (void *)&i);
	}

	/* create a file for writing the config */
	if (!current_cfg.sw_lb) {
		mg_set_request_handler(ctx, "/vnf/flowdirector", flow_director_handler, 0);
		sprintf(buf, "%s_%s_%dP_%dT.cfg", current_cfg.vnf_type, "HWLB",
			 current_cfg.num_ports, current_cfg.num_workers);
	} else
		sprintf(buf, "%s_%s_%dP_%dLB_%dT.cfg", current_cfg.vnf_type, "SWLB",
			 current_cfg.num_ports, current_cfg.num_lb, current_cfg.num_workers);

	/* create a file which is more readable */
	f = fopen(buf, "w");

	print_to_file(f, tcfg);

	app->config_file = strdup(buf);
	app->parser_file = strdup(buf);

end:
	return ctx;
}
