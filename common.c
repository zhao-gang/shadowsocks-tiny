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
	char state_str[42] = {'\0'};

	if (state & LINK_LOCAL && state & LINK_SERVER)
		strcat(state_str, "linked");
	else if (state & LINK_LOCAL)
		strcat(state_str, "local");
	else if (state & LINK_SERVER)
		strcat(state_str, "server");

	if (state & LINK_IV_EXCHANGED)
		strcat(state_str, ", iv exchanged");

	if (state & LINK_CIPHER_PENDING)
		strcat(state_str, ", cipher_pending");
	else if (state & LINK_PLAIN_PENDING)
		strcat(state_str, ", plain pending");

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

struct link *create_link(int sockfd)
{
	struct link *ln;
	struct link *head = link_head;

	ln = calloc(1, sizeof(*ln));
	if (ln == NULL)
		goto err;

	ln->state = LINK_LOCAL;
	ln->local_sockfd = sockfd;
	ln->server_sockfd = -1;

	if (head) {
		while (head->next != NULL)
			head = head->next;
		head->next = ln;
	} else {
		link_head = ln;
	}

	pr_link_info(ln);
	sock_info(sockfd, "%s: added to link", __func__);
	return ln;

err:
	sock_warn(sockfd, "%s: can't allocate memory for link", __func__);
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
	if ((unlink_link(ln)) == -1) {
		pr_link_warn(ln);
		pr_warn("%s: unlink_link failed\n", __func__);
	}

	if (ln->ctx)
		EVP_CIPHER_CTX_free(ln->ctx);

	if (ln->server)
		freeaddrinfo(ln->server);

	free(ln);
	pr_debug("%s: succeeded\n", __func__);
}

void destroy_link(struct link *ln)
{
	poll_del(ln->local_sockfd);
	poll_del(ln->server_sockfd);
	close(ln->local_sockfd);
	close(ln->server_sockfd);
	free_link(ln);
}

int do_listen(struct addrinfo *info)
{
	int sockfd, type;
	struct addrinfo *lp = info;

	while (lp) {
		type = lp->ai_socktype;

		if (type == SOCK_STREAM) {
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

struct addrinfo *get_addr(struct link *ln)
{
}

int connect_server(struct link *ln, struct addrinfo *info)
{
	int sockfd, type, ret;
	struct addrinfo *sp = info;

	while (sp) {
		type = sp->ai_socktype;
		if (type == SOCK_STREAM) {
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
			ln->state |= LINK_SERVER;
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

int do_plain_read(int sockfd, struct link *ln)
{
	int ret;

	ret = recv(sockfd, ln->text, PLAIN_BUF_SIZE, 0);
	ln->text_len = ret;

	if (ret == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			perror("do_plain_read: recv() error");
			return -1;
		}
		poll_add(sockfd, POLLIN);
		sock_info(sockfd, "%s: recv() pending", __func__);
		return 0;
	} else if (ret == 0) {
		/* recv() returned 0 means the peer has shut down,
		 * return -1 to let the caller do the closing work */
		sock_info(sockfd, "%s: the peer has shut down", __func__);
		return -1;
	}

	pr_text(ln);
	sock_debug(sockfd, "%s: recv() returned %d", __func__, ret);
	return 0;
}

int do_cipher_read(int sockfd, struct link *ln)
{
	int ret;

	ret = recv(sockfd, ln->cipher, CIPHER_BUF_SIZE, 0);
	ln->cipher_len = ret;

	if (ret == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			perror("do_cipher_read: recv() error");
			return -1;
		}
		poll_add(sockfd, POLLIN);
		sock_info(sockfd, "%s: recv() pending", __func__);
		return 0;
	} else if (ret == 0) {
		/* recv() returned 0 means the peer has shut down,
		 * return -1 to let the caller do the closing work */
		sock_info(sockfd, "%s: the peer has shut down", __func__);
		return -1;
	}

	pr_cipher(ln);
	sock_debug(sockfd, "%s: recv() returned %d", __func__, ret);
	return 0;
}

int parse_ss_header(struct link *ln)
{

}

int parse_socks5_header(struct link *ln)
{
}

int add_ss_header(struct link *ln)
{
}

int add_socks5_header(struct link *ln)
{
}

int do_plain_send(int sockfd, struct link *ln)
{
	int ret;

	ret = send(sockfd, ln->text, ln->text_len, 0);
	if (ret == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK &&
		    errno != EPIPE && errno != ENOTCONN) {
			perror("do_plain_send error");
			return -1;
		} else {
			/* wait for unblocking send, or wait for
			 * connection finish */
			poll_add(sockfd, POLLOUT);
			ln->state |= LINK_PLAIN_PENDING;
			sock_info(sockfd, "%s: send() pending", __func__);
			perror("pending reason");
			return 0;
		}
	}

	ln->state &= ~LINK_PLAIN_PENDING;
	poll_rm(sockfd, POLLOUT);
	poll_add(sockfd, POLLIN);
	pr_text(ln);
	sock_debug(sockfd, "%s: send() returned %d", __func__, ret);
	return 0;
}

int do_cipher_send(int sockfd, struct link *ln)
{
	int ret;

	ret = send(sockfd, ln->cipher, ln->cipher_len, 0);
	if (ret == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK &&
		    errno != EPIPE && errno != ENOTCONN) {
			perror("do_cipher_send error");
			return -1;
		} else {
			/* wait for unblocking send */
			poll_add(sockfd, POLLOUT);
			ln->state |= LINK_CIPHER_PENDING;
			sock_info(sockfd, "%s: send() pending", __func__);
			perror("pending reason");
			return 0;
		}
	}

	ln->state &= ~LINK_CIPHER_PENDING;
	poll_rm(sockfd, POLLOUT);
	poll_add(sockfd, POLLIN);
	pr_cipher(ln);
	sock_debug(sockfd, "%s: send() returned %d", __func__, ret);
	return 0;
}
