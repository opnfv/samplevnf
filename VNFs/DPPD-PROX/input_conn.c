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

#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "input_conn.h"
#include "input.h"
#include "run.h"
#include "cmd_parser.h"

static struct input tcp_server;
int tcp_server_started;
static struct input uds_server;
int uds_server_started;

/* Active clients */
struct client_conn {
	struct input input;
	int          enabled;
	int          n_buf;
	char         buf[32768];
};

struct client_conn clients[32];

static int start_listen_tcp(void)
{
	struct sockaddr_in server;
	int ret, sock;
	int optval = 1;

	memset(&server, 0, sizeof(server));
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (sock == -1)
		return -1;

	server.sin_family = AF_INET;
	server.sin_port = ntohs(8474);
	server.sin_addr.s_addr = ntohl(INADDR_ANY);

	ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));

	if (ret)
		return -1;

	if (bind(sock, (struct sockaddr *) &server, sizeof(server)) == -1)
		return -1;

	if (listen(sock, 1) == -1)
		return -1;

	return sock;
}

static int start_listen_uds(void)
{
	int sock;
	struct sockaddr_un server = {
		.sun_path = "/tmp/prox.sock",
		.sun_family = AF_UNIX
	};

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1)
		return -1;

	/* Unlink can fail, i.e. when /tmp/prox.sock does not
	   exists. This is not fatal. */
	unlink(server.sun_path);

	if (bind(sock, (struct sockaddr *) &server, sizeof(server)) == -1)
		return -1;

	if (listen(sock, 1) == -1)
		return -1;

	return sock;
}

static void write_client(struct input *input, const char *buf, size_t len)
{
	int ret;

	while ((ret = write(input->fd, buf, len)) != (int)len) {
		buf += ret;
		len -= ret;
	}
}

static void handle_client(struct input* client_input)
{
	char cur[1024];
	size_t i;
	int ret;
	struct client_conn *c = NULL;

	/* Get the client structure that uses this input */
	for (i = 0; i < sizeof(clients)/sizeof(clients[0]); ++i) {
		if (&clients[i].input == client_input) {
			c = &clients[i];
			break;
		}
	}

	/* handle_client function called non-tcp client */
	if (c == NULL)
		return ;

	ret = read(c->input.fd, cur, sizeof(cur));

	if (ret == 0) {
		c->enabled = 0;
		unreg_input(&c->input);
		return ;
	}

	/* Scan in data until \n (\r skipped if followed by \n) */
	for (int i = 0; i < ret; ++i) {
		if (cur[i] == '\r' && i + 1 < ret && cur[i + 1] == '\n')
			continue;

		if (cur[i] == '\n') {
			c->buf[c->n_buf] = 0;
			if (c->n_buf)
				cmd_parser_parse(c->buf, client_input);
			c->n_buf = 0;
		}
		else if (c->n_buf + 1 < (int)sizeof(c->buf))
			c->buf[c->n_buf++] = cur[i];
		else
			c->n_buf = 0;
	}
}

static void handle_new_client(struct input* server)
{
	size_t i;

	int new_client = accept(server->fd, NULL, NULL);

	for (i = 0; i < sizeof(clients)/sizeof(clients[0]); ++i) {
		if (clients[i].enabled == 0) {
			break;
		}
	}

	if (i == sizeof(clients)/sizeof(clients[0])) {
		close(new_client);
		return ;
	}

	clients[i].enabled = 1;
	clients[i].n_buf = 0;
	clients[i].input.fd = new_client;
	clients[i].input.reply = server->reply;
	clients[i].input.proc_input = handle_client;

	reg_input(&clients[i].input);
}

int reg_input_tcp(void)
{
	int fd;

	if (tcp_server_started)
		return -1;
	if ((fd = start_listen_tcp()) < 0)
		return -1;

	tcp_server.fd = fd;
	tcp_server.proc_input = handle_new_client;
	tcp_server.reply = write_client;
	if (reg_input(&tcp_server) != 0) {
		close(fd);
		return -1;
	}
	tcp_server_started = 1;
	return 0;
}

int reg_input_uds(void)
{
	int fd;

	if (uds_server_started)
		return -1;

	if ((fd = start_listen_uds()) < 0)
		return -1;

	uds_server.fd = fd;
	uds_server.proc_input = handle_new_client;
	uds_server.reply = write_client;
	if (reg_input(&uds_server) != 0) {
		close(fd);
		return -1;
	}
	uds_server_started = 1;
	return 0;
}

void unreg_input_tcp(void)
{
	if (!tcp_server_started)
		return;
	tcp_server_started = 0;
	close(tcp_server.fd);
	unreg_input(&tcp_server);
}

void unreg_input_uds(void)
{
	if (!uds_server_started)
		return;
	uds_server_started = 0;
	close(tcp_server.fd);
	unreg_input(&tcp_server);
}
