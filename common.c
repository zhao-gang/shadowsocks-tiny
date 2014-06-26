#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "log.h"
#include "common.h"

struct pollfd *clients;
int nfds;
struct link *link_head;

void _pr_link(const char *level, struct link *ln)
{
	enum link_state state = ln->state;
	char state_str[128] = {'\0'};

	if (state & LOCAL && state & SERVER)
		strcat(state_str, "linked");
	else if (state & LOCAL)
		strcat(state_str, "local");
	else if (state & SERVER)
		strcat(state_str, "server");

	if (state & SS_UDP)
		strcat(state_str, ", udp");

	if (state & TEXT_PENDING)
		strcat(state_str, ", text pending");

	if (state & CIPHER_PENDING)
		strcat(state_str, ", cipher pending");

	if (state & SOCKS5_CMD_REPLY_SENT)
		strcat(state_str, ", socks5 cmd reply sent");
	else if (state & SOCKS5_CMD_REQUEST_RECEIVED)
		strcat(state_str, ", socks5 cmd request received");
	else if (state & SOCKS5_AUTH_REPLY_SENT)
		strcat(state_str, ", socks5 auth reply sent");
	else if (state & SOCKS5_AUTH_REQUEST_RECEIVED)
		strcat(state_str, ", socks5 auth request received");

	if (state = SS_TCP_HEADER_SENT)
		strcat(state_str, ", ss tcp header sent");
	else if (state = SS_TCP_HEADER_RECEIVED)
		strcat(state_str, ", ss tcp header received");

	printf("%s: state: %s; local sockfd: %d; server sockfd: %d; "
	       "text len: %d; cipher len: %d;\n",
	       level, state_str, ln->local_sockfd, ln->server_sockfd,
	       ln->text_len, ln->cipher_len);
}

void pr_link_debug(struct link *ln)
{
	if (!debug)
		return;

	_pr_link("debug", ln);
}

void pr_link_info(struct link *ln)
{
	if (!verbose)
		return;

	_pr_link("info", ln);
}

void pr_link_warn(struct link *ln)
{
	_pr_link("WARNING", ln);
}

static void pr_data(struct link *ln, const char *type)
{
	int i, len;
	unsigned char *data;

	if (!debug)
		return;

	if (strcmp(type, "iv") == 0) {
		len = EVP_CIPHER_iv_length(ln->evp_cipher);
		data = ln->iv;
	} else if (strcmp(type, "key") == 0) {
		len = EVP_CIPHER_key_length(ln->evp_cipher);
		data = ln->key;
	} else if (strcmp(type, "text") == 0) {
		len = ln->text_len;
		data = ln->text;
	} else if (strcmp(type, "cipher") == 0) {
		len = ln->cipher_len;
		data = ln->cipher;
	} else {
		pr_warn("%s: unknown type: %s\n", __func__, type);
		return;
	}

	printf("%s:\n", type);

	for (i = 0; i < len - 1; i++) {
		if (i % 10 == 9)
			printf("%02X\n", data[i]);
		else
			printf("%02X ", data[i]);
	}

	printf("%02X\n", data[i]);
}

void pr_iv(struct link *ln)
{
	pr_data(ln, "iv");
}

void pr_key(struct link *ln)
{
	pr_data(ln, "key");
}

void pr_text(struct link *ln)
{
	pr_data(ln, "text");
}

void pr_cipher(struct link *ln)
{
	pr_data(ln, "cipher");
}

static int get_max_clients(void)
{
	struct rlimit lmt;

	if (getrlimit(RLIMIT_NOFILE, &lmt) == -1) {
		perror("getrlimit");
		return -1;
	} else
		return lmt.rlim_cur;
}

struct pollfd *poll_alloc(void)
{
	nfds = get_max_clients();
	if (nfds == -1)
		nfds = DEFAULT_MAX_CONNECTION;

	clients = calloc(nfds, sizeof(struct pollfd));
	if (clients == NULL)
		pr_exit("%s: calloc failed", __func__);

	pr_info("%s succeeded nfds = %d\n", __func__, nfds);
	return clients;
}

void poll_init(void)
{
	int i;

	for (i = 0; i < nfds; i++)
		clients[i].fd = -1;

	pr_info("poll: initialized\n");
}

void poll_events_string(short events, char *events_str)
{
	if (events & POLLIN)
		if (strlen(events_str) == 0)
			strcat(events_str, "POLLIN");
		else
			strcat(events_str, " POLLIN");

	if (events & POLLOUT)
		if (strlen(events_str) == 0)
			strcat(events_str, "POLLOUT");
		else
			strcat(events_str, " POLLOUT");
}

int poll_set(int sockfd, short events)
{
	int i;
	char events_str[42] = {'\0'};

	poll_events_string(events, events_str);

	/* i == 0 is listen sockfd, it's not needed to be checked by now */
	for (i = 1; i < nfds; i++) {
		if (clients[i].fd == sockfd) {
			sock_warn(sockfd, "%s: already in poll(%s)",
				  __func__, events_str);
			clients[i].events = events;
			return 0;
		}
	}

	for (i = 1; i < nfds; i++) {
		if (clients[i].fd == -1) {
			clients[i].fd = sockfd;
			clients[i].events = events;
			sock_info(sockfd, "%s: added to poll(%s)",
				  __func__, events_str);
			return 0;
		}
	}

	sock_warn(sockfd, "too many connections!");
	return -1;
}

int poll_add(int sockfd, short events)
{
	int i;
	char events_str[42] = {'\0'};

	poll_events_string(events, events_str);

	/* i == 0 is listen sockfd, it's not needed to be checked by now */
	for (i = 1; i < nfds; i++)
		if (clients[i].fd == sockfd)
			break;

	if (i == nfds) {
		sock_warn(sockfd, "%s: not found", __func__);
		return poll_set(sockfd, events);
	}

	clients[i].events |= events;
	sock_info(sockfd, "%s: added event(%s)", __func__, events_str);
	return 0;
}

int poll_rm(int sockfd, short events)
{
	int i;
	char events_str[42] = {'\0'};

	poll_events_string(events, events_str);

	/* i == 0 is listen sockfd, it's not needed to be checked by now */
	for (i = 1; i < nfds; i++)
		if (clients[i].fd == sockfd)
			break;

	if (i == nfds) {
		sock_warn(sockfd, "%s: not found", __func__);
		return poll_set(sockfd, events);
	}

	clients[i].events &= ~events;
	sock_info(sockfd, "%s: remove event(%s)", __func__, events_str);
	return 0;
}

int poll_del(int sockfd)
{
	int i;
	char events_str[42] = {'\0'};

	for (i = 0; i < nfds; i++) {
		if (clients[i].fd == sockfd) {
			clients[i].fd = -1;
			poll_events_string(clients[i].events, events_str);
			sock_info(sockfd, "deleted from poll(%s)",
				  events_str);
			return 0;
		}
	}

	sock_warn(sockfd, "%s: socket not in poll", __func__);
	return -1;
}

struct link *create_link(int sockfd, const char *type)
{
	struct link *ln;
	struct link *head = link_head;

	ln = calloc(1, sizeof(*ln));
	if (ln == NULL)
		goto err;

	if (strcmp(type, "tcp") == 0) {
		ln->text = malloc(TCP_TEXT_BUF_SIZE);
		if (ln->text == NULL)
			goto err;

		ln->cipher = malloc(TCP_CIPHER_BUF_SIZE);
		if (ln->cipher == NULL)
			goto err;
	} else if (strcmp(type, "udp") == 0) {
		ln->text = malloc(UDP_TEXT_BUF_SIZE);
		if (ln->text == NULL)
			goto err;

		ln->cipher = malloc(UDP_CIPHER_BUF_SIZE);
		if (ln->cipher == NULL)
			goto err;

		ln->udp_header = malloc(UDP_HEADER_SIZE);
		if (ln->udp_header == NULL)
			goto err;

		ln->state |= SS_UDP;
	} else {
		sock_warn(sockfd, "%s: unknown type %s",
			  __func__, type);
		return NULL;
	}

	ln->state |= LOCAL;
	ln->local_sockfd = sockfd;
	ln->server_sockfd = -1;

	if (head) {
		while (head->next != NULL)
			head = head->next;
		head->next = ln;
	} else {
		link_head = ln;
	}

	sock_info(sockfd, "%s(%s): added to link",
		  __func__, type);
	return ln;

err:
	if (ln->text)
		free(ln->text);
	if (ln->cipher)
		free(ln->cipher);
	if (ln->udp_header)
		free(ln->udp_header);
	if (ln)
		free(ln);
	sock_warn(sockfd, "%s(%s): can't allocate memory for link",
		  __func__, type);
	return NULL;
}

struct link *get_link(int sockfd)
{
	struct link *head = link_head;

	while (head) {
		if (head->local_sockfd == sockfd ||
		    head->server_sockfd == sockfd) {
			pr_link_debug(head);
			sock_debug(sockfd, "%s: succeeded", __func__);
			return head;
		} else {
			head = head->next;
		}
	}

	sock_warn(sockfd, "%s: failed", __func__);
	return NULL;
}

static int unlink_link(struct link *ln)
{
	struct link *head = link_head;
	struct link *previous = link_head;

	if (head == NULL) {
		pr_warn("%s: link list is empty\n", __func__);
		return -1;
	} else if (head->local_sockfd == ln->local_sockfd ||
		   head->server_sockfd == ln->server_sockfd) {
		link_head = head->next;
		goto out;
	} else {
		head = head->next;

		while (head) {
			if (head->local_sockfd == ln->local_sockfd ||
			    head->server_sockfd == ln->local_sockfd) {
				previous->next = head->next;
				goto out;
			}

			previous = head;
			head = head->next;
		}
	}

	pr_link_warn(ln);
	pr_warn("%s failed: link not found\n", __func__);
	return -1;

out:
	pr_link_debug(ln);
	pr_debug("%s succeeded\n", __func__);
	return 0;
}

static void free_link(struct link *ln)
{
	if (ln->ctx)
		EVP_CIPHER_CTX_free(ln->ctx);

	if (ln->text)
		free(ln->text);

	if (ln->cipher)
		free(ln->cipher);

	if (ln->udp_header)
		free(ln->udp_header);

	if (ln)
		free(ln);

	pr_debug("%s: succeeded\n", __func__);
}

void destroy_link(struct link *ln)
{
	if ((unlink_link(ln)) == -1) {
		pr_link_warn(ln);
		pr_warn("%s: unlink_link failed\n", __func__);
	}

	poll_del(ln->local_sockfd);
	poll_del(ln->server_sockfd);
	close(ln->local_sockfd);
	close(ln->server_sockfd);
	free_link(ln);
}

int do_listen(struct addrinfo *info, const char *type_str)
{
	int sockfd, type;
	struct addrinfo *lp = info;

	if (strcmp(type_str, "tcp") == 0)
		type = SOCK_STREAM;
	else if (strcmp(type_str, "udp") == 0)
		type = SOCK_DGRAM;
	else
		pr_exit("%s: unknown socket type\n", __func__);

	while (lp) {
		if (lp->ai_socktype == type) {
			type |= SOCK_NONBLOCK;
			sockfd = socket(lp->ai_family, type, 0);
			if (sockfd == -1)
				goto err;

			if (bind(sockfd, lp->ai_addr, lp->ai_addrlen) == -1)
				goto err;

			if (listen(sockfd, SOMAXCONN) == -1)
				goto err;

			return sockfd;
		}

		lp = lp->ai_next;
	}

err:
	err_exit("do_listen");
}

int connect_server(struct link *ln)
{
	int sockfd, type, ret;
	struct addrinfo *sp = ln->server;

	if (ln->state & SS_UDP)
		type == SOCK_DGRAM;
	else
		type == SOCK_STREAM;

	while (sp) {
		if (sp->ai_socktype == type) {
			type |= SOCK_NONBLOCK;
			sockfd = socket(sp->ai_family, type, 0);
			if (sockfd == -1)
				goto err;
			ln->server_sockfd = sockfd;
			ret = connect(sockfd, sp->ai_addr, sp->ai_addrlen);
			if (ret == -1) {
				/* it's ok to return inprogress, will
				 * handle it later */
				if (errno == EINPROGRESS) {
					poll_set(sockfd, POLLOUT);
					sock_info(sockfd, "%s: connect() %s",
						  __func__, strerror(errno));
					return 0;
				} else {
					goto err;
				}
			}

			/* sucessfully connected */
			ln->state |= SERVER;
			poll_add(sockfd, POLLIN);
			sock_info(sockfd, "%s: connected", __func__);
			return 0;
		}

		sp = sp->ai_next;
	}

err:
	perror("connect_server");
	return -1;
}

int add_data(int sockfd, struct link *ln,
	     const char *type, char *data, int size)
{
	unsigned char *buf;
	int i, len, max_text_size, max_cipher_size;

	if (ln->state & SS_UDP) {
		max_text_size = UDP_TEXT_BUF_SIZE;
		max_cipher_size = UDP_CIPHER_BUF_SIZE;
	} else {
		max_text_size = TCP_TEXT_BUF_SIZE;
		max_cipher_size = TCP_CIPHER_BUF_SIZE;
	}

	if (strcmp(type, "text") == 0) {
		buf = ln->text;
		len = ln->text_len;

		if (len + size > max_text_size) {
			sock_warn(sockfd, "%s: data exceed max length(%d/%d)",
				  __func__, len + size, max_text_size);
			return -1;
		}

		ln->text_len += size;
	} else if (strcmp(type, "cipher") == 0) {
		buf = ln->cipher;
		len = ln->text_len;

		if (len + size > max_cipher_size) {
			sock_warn(sockfd, "%s: data exceed max length(%d/%d)",
				  __func__, len + size, max_cipher_size);
			return -1;
		}

		ln->cipher_len += size;
	} else {
		sock_warn(sockfd, "%s: unknown type", __func__);
		return -1;
	}

	/* if len == 0, no data need to be moved */
	if (len > 0) {
		for (i = len - 1; i >= 0; i--)
			buf[i + size] = buf[i];
	}

	for (i = 0; i < size; i++)
		buf[i] = data[i];

	sock_info(sockfd, "%s: successfully added %d bytes",
		  __func__, size);
	return 0;
}

int rm_data(int sockfd, struct link *ln, const char *type, int size)
{
	unsigned char *buf;
	int i, len;

	if (strcmp(type, "text") == 0) {
		buf = ln->text;
		len = ln->text_len;

		if (len < size) {
			sock_warn(sockfd, "%s: size is too big(%d/%d)",
				  __func__, size, len);
			return -1;
		}

		ln->text_len -= size;
	} else if (strcmp(type, "cipher") == 0) {
		buf = ln->cipher;
		len = ln->text_len;
		
		if (len < size) {
			sock_warn(sockfd, "%s: size is too big(%d/%d)",
				  __func__, size, len);
			return -1;
		}

		ln->cipher_len -= size;
	} else {
		sock_warn(sockfd, "%s: unknown type", __func__);
		return -1;
	}

	for (i = size; i < len; i++)
		buf[i - size] = buf[i];

	sock_info(sockfd, "%s: successfully removed %d bytes",
		  __func__, size);
	return 0;
}

int check_ss_header(int sockfd, struct link *ln)
{
	int ret;
	unsigned char atyp;
	unsigned char addr[256];
	unsigned short port;
	unsigned char port_str[6];
	unsigned short addr_len;
	struct ss_header *req;
	struct addrinfo hint;
	struct addrinfo *res;

	/* atyp(1) + address(4) + port(2) */
	if (ln->text_len < 7) {
		sock_warn(sockfd, "%s: text is too short",
			  __func__);
		pr_text(ln);
		return -1;
	}

	req = (void *)ln->text;

	if (ln->state & SS_UDP) {
		hint.ai_socktype = SOCK_DGRAM;
	} else {
		hint.ai_socktype = SOCK_STREAM;
	}
	
	atyp = req->atyp;
	if (atyp == SOCKS5_ADDR_IPV4) {
		hint.ai_family = AF_INET;
		addr_len = 4;

		if (inet_ntop(AF_INET, req->dst, addr, sizeof(addr)) == NULL) {
			sock_warn(sockfd, "%s: inet_ntop() %s",
				  __func__, strerror(errno));
			return -1;
		}

		port = ntohs((unsigned short)req->dst[addr_len]);
	} else if (atyp == SOCKS5_ADDR_DOMAIN) {
		hint.ai_family = AF_UNSPEC;
		addr_len = req->dst[0];
		strncpy(addr, req->dst + 1, addr_len);
		addr[addr_len] = '\0';
		port = ntohs((unsigned short)req->dst[addr_len + 1]);
		/* to compute the right data length(except header) */
		addr_len += 1;
	} else if (atyp == SOCKS5_ADDR_IPV6) {
		hint.ai_family = AF_INET6;
		addr_len = 16;

		if (inet_ntop(AF_INET6, req->dst, addr, sizeof(addr)) == NULL) {
			sock_warn(sockfd, "%s: inet_ntop() %s",
				  __func__, strerror(errno));
			return -1;
		}

		port = ntohs((unsigned short)req->dst[addr_len]);
	} else {
		sock_warn(sockfd, "%s: ATYP(%d) isn't legal");
		return -1;
	}

	sock_info(sockfd, "%s: address: %s; port: %d",
		  __func__, addr, port);
	sprintf(port_str, "%d", port);
	ret = getaddrinfo(addr, port_str, &hint, &res);
	if (ret != 0) {
		pr_warn("getaddrinfo error: %s\n", gai_strerror(ret));
		return -1;
	}

	ln->text_len -= 1 + addr_len;
	ln->server = res;
	return 0;
}

int check_socks5_auth_header(int sockfd, struct link *ln)
{
	unsigned short i;
	struct socks5_auth_request *req;

	if (ln->text_len < 3) {
		sock_warn(sockfd, "%s: text len is smaller than auth request",
			  __func__);
		return -1;
	}

	req = (void *)ln->text;

	if (req->ver != 0x05) {
		sock_warn(sockfd, "%s: VER(%d) is not 5",
			  __func__, req->ver);
		return -1;
	}

	i = req->nmethods;
	if ((i + 2) != ln->text_len) {
		sock_warn(sockfd, "%s: NMETHODS(%d) isn't correct",
			  __func__, i);
		return -1;
	}

	while (i-- > 0)
		if (req->methods[i] == 0x00)
			return 0;

	sock_warn(sockfd, "%s: only support NO AUTHENTICATION");
	return -1;
}

int check_socks5_cmd_header(int sockfd, struct link *ln)
{
	unsigned char cmd;
	unsigned char atyp;
	struct socks5_cmd_request *req;

	req = (void *)ln->text;

	if (req->ver != 0x05) {
		sock_warn(sockfd, "%s: VER(%d) is not 5",
			  __func__, req->ver);
		return -1;
	}

	cmd = req->cmd;
	if (cmd == SOCKS5_CONNECT) {
		/* nothing to do */
	} else if (cmd == SOCKS5_UDP_ASSOCIATE) {
		ln->state |= SS_UDP;
		/* add memory for udp */
		ln->text = realloc(ln->text, UDP_TEXT_BUF_SIZE);
		if (ln->text == NULL)
			return -1;

		ln->cipher = realloc(ln->cipher, UDP_CIPHER_BUF_SIZE);
		if (ln->cipher == NULL)
			return -1;
	} else {
		sock_warn(sockfd, "%s: CMD(%d) isn't supported", cmd);
		return -1;
	}

	if (req->rsv != 0x00) {
		sock_warn(sockfd, "%s: RSV(%d) is not 0x00");
		return -1;
	}

	atyp = req->atyp;
	if (atyp == SOCKS5_ADDR_IPV4) {
		if (ln->text_len < 10)
			goto too_short;
	} else if (atyp == SOCKS5_ADDR_DOMAIN) {
		if (ln->text_len < 7 + req->dst[0])
			goto too_short;
	} else if (atyp == SOCKS5_ADDR_IPV6) {
		if (ln->text_len < 22)
			goto too_short;
	} else {
		sock_warn(sockfd, "%s: ATYP(%d) isn't legal");
		return -1;
	}

	/* remove VER, CMD, RSV for shadowsocks protocol */
	if (rm_data(sockfd, ln, "text", 3) == -1)
		return -1;

	return 0;

too_short:
	sock_warn(sockfd, "%s: text is too short",
		  __func__);
	pr_text(ln);
	return -1;
}

int check_socks5_udp_request(int sockfd, struct link *ln)
{
}

int add_ss_header(int sockfd, struct link *ln)
{
	int ret = add_data(sockfd, ln, "text",
			   ln->udp_header, ln->udp_header_len);

	if (ret == -1)
		sock_warn(sockfd, "%s: failed", __func__);

	return ret;
}

int create_socks5_auth_reply(int sockfd, struct link *ln, bool ok)
{
	struct socks5_auth_reply rep;

	rep.ver = 0x05;

	if (ok)
		rep.method = SOCKS5_METHOD_NOT_REQUIRED;
	else
		rep.method = SOCKS5_METHOD_ERROR;

	ln->text_len = 0;

	if (add_data(sockfd, ln, "text", (void *)&rep, sizeof(rep)) == -1)
		return -1;

	return 0;
}

int create_socks5_cmd_reply(int sockfd, struct link *ln, int cmd)
{
	unsigned short port;
	void *addrptr;
	int addr_len;
	struct sockaddr_storage ss_addr;
	int len = sizeof(struct sockaddr_storage);
	struct socks5_cmd_reply *rep = (void *)ln->cipher;

	rep->ver = 0x05;
	rep->rep = cmd;
	rep->rsv = 0x00;

	if (getsockname(sockfd, (struct sockaddr *)&ss_addr,
			&len) == -1) {
		sock_warn(sockfd, "%s: getsockname() %s",
			  __func__, strerror(errno));
		return -1;
	}

	if (ss_addr.ss_family == AF_INET) {
		rep->atyp = SOCKS5_ADDR_IPV4;
		port = ((struct sockaddr_in *)&ss_addr)->sin_port;
		addrptr = &((struct sockaddr_in *)&ss_addr)->sin_addr;
		addr_len = sizeof(struct in_addr);
	} else {
		rep->atyp = SOCKS5_ADDR_IPV6;
		port = ((struct sockaddr_in6 *)&ss_addr)->sin6_port;
		addrptr = &((struct sockaddr_in6 *)&ss_addr)->sin6_addr;
		addr_len = sizeof(struct in6_addr);
	}

	memcpy(rep->bnd, addrptr, addr_len);
	memcpy(rep->bnd + addr_len, (void *)&port, sizeof(short));

	len = sizeof(rep) + addr_len + 2;
	ln->cipher_len = 0;
	if (add_data(sockfd, ln, "cipher", (void *)rep, len) == -1)
		return -1;

	return 0;
}

static int do_read(int sockfd, struct link *ln, const char *type)
{
	int ret, len;
	unsigned char *buf;

	if (strcmp(type, "text") == 0) {
		buf = ln->text;

		if (ln->state & SS_UDP)
			len = UDP_TEXT_BUF_SIZE;
		else
			len = TCP_TEXT_BUF_SIZE;
	} else if (strcmp(type, "cipher") == 0) {
		buf = ln->cipher;

		if (ln->state & SS_UDP)
			len = UDP_CIPHER_BUF_SIZE;
		else
			len = TCP_CIPHER_BUF_SIZE;
	} else {
		sock_warn(sockfd, "%s: unknown type %s",
			  __func__, type);
		return -2;
	}

	ret = recv(sockfd, buf, len, 0);
	if (ret == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			sock_warn(sockfd, "%s(%s): recv() %s",
				  __func__, type, strerror(errno));
			return -2;
		}
		poll_add(sockfd, POLLIN);
		sock_info(sockfd, "%s(%s): recv() %s",
			  __func__, type, strerror(errno));
		return -1;
	} else if (ret == 0) {
		/* recv() returned 0 means the peer has shut down,
		 * return -2 to let the caller do the closing work */
		sock_info(sockfd, "%s(%s): the peer has shut down",
			  __func__, type);
		return -2;
	}

	if (strcmp(type, "text") == 0) {
		ln->text_len = ret;
	} else if (strcmp(type, "cipher") == 0) {
		ln->cipher_len = ret;
	}

	sock_debug(sockfd, "%s(%s): recv() returned %d",
		   __func__, type, ret);
	return ret;
}

int do_text_read(int sockfd, struct link *ln)
{
	int ret = do_read(sockfd, ln, "text");

	pr_text(ln);

	return ret;
}

int do_cipher_read(int sockfd, struct link *ln)
{
	int ret = do_read(sockfd, ln, "cipher");

	pr_cipher(ln);

	return ret;
}

static int do_send(int sockfd, struct link *ln, const char *type)
{
	int ret, state, len;
	unsigned char *buf;

	if (strcmp(type, "text") == 0) {
		buf = ln->text;
		len = ln->text_len;
		state = TEXT_PENDING;
	} else if (strcmp(type, "cipher") == 0) {
		buf = ln->cipher;
		len = ln->cipher_len;
		state = CIPHER_PENDING;
	} else {
		sock_warn(sockfd, "%s: unknown type %s",
			  __func__, type);
		return -2;
	}

	ret = send(sockfd, buf, len, 0);
	if (ret == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK &&
		    errno != ENOTCONN) {
			sock_warn(sockfd, "%s(%s): send() %s",
				  __func__, type, strerror(errno));
			return -2;
		} else {
			/* wait for unblocking send, or wait for
			 * connection finished */
			poll_add(sockfd, POLLOUT);
			ln->state |= state;
			sock_info(sockfd, "%s(%s): send() %s",
				  __func__, type, strerror(errno));
			return -1;
		}
	}

	if (ret < ln->text_len) {
		rm_data(sockfd, ln, type, ret);
		poll_add(sockfd, POLLOUT);
		ln->state |= state;
		sock_info(sockfd, "%s(%s): send() partial send(%d/%d)",
			  __func__, type, ret, len);
		return -1;
	}
		
	ln->state &= ~state;
	poll_rm(sockfd, POLLOUT);
	poll_add(sockfd, POLLIN);
	sock_debug(sockfd, "%s(%s): send() returned %d",
		   __func__, type, ret);
	return ret;
}

int do_text_send(int sockfd, struct link *ln)
{
	int ret = do_send(sockfd, ln, "text");

	pr_text(ln);

	return ret;
}

int do_cipher_send(int sockfd, struct link *ln)
{
	int ret;

	ret = do_send(sockfd, ln, "cipher");

	return ret;
}
