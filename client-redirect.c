/*
 * Copyright (c) 2014 Zhao, Gang <gang.zhao.42@gmail.com>
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 */

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "common.h"
#include "crypto.h"
#include "log.h"

char rsv_frag[3] = {0x00, 0x00, 0x00};

static int get_ss_header(int sockfd, struct link *ln)
{
	int len, ret;
	char atyp;
	char addr[256];
	unsigned short port;
	SS ss;
	struct ss_header *req;

	len = sizeof(SS);
	req = ln->cipher;

	/* todo: ipv6 */
	ret = getsockopt(sockfd, SOL_IP, SO_ORIGINAL_DST,
			 &ss, (void *)&len);
	if (ret == -1) {
		sock_warn(sockfd, "%s: getsockopt err: %s",
			  __func__, strerror(errno));
		return -1;
	}

	atyp = SOCKS5_ADDR_IPV4;
	req->atyp = atyp;
	memcpy(req->dst, &((SA_IN *)&ss)->sin_addr,
	       sizeof(((SA_IN *)&ss)->sin_addr));
	memcpy(req->dst + sizeof(((SA_IN *)&ss)->sin_addr),
	       &((SA_IN *)&ss)->sin_port,
	       sizeof(((SA_IN *)&ss)->sin_port));
	ln->ss_header_len = 7;

	if (inet_ntop(AF_INET, &((SA_IN *)&ss)->sin_addr,
		      addr, sizeof(addr)) == NULL) {
		sock_warn(sockfd, "%s: inet_ntop() %s",
			  __func__, strerror(errno));
		return -1;
	}

	port = ntohs(((SA_IN *)&ss)->sin_port);
		
	sock_debug(sockfd, "%s: original address: %s, port: %d",
		   __func__, addr, port);

	return 0;
}

/* read text from local, encrypt and send to server */
int client_do_local_read(int sockfd, struct link *ln)
{
	int ret;

	if (ln->state & LOCAL_SEND_PENDING)
		return 0;

	ret = do_read(sockfd, ln, "text", 0);
	if (ret == -2) {
		goto out;
	} else if (ret == -1) {
		return 0;
	}

	if (ln->state & SS_UDP) {
		/* remove rsv(2) + frag(1) */
		if (rm_data(sockfd, ln, "text", 3) == -1)
			goto out;
	} else if (!(ln->state & SS_TCP_HEADER_SENT)) {
		ret = get_ss_header(sockfd, ln);
		if (ret == -1)
			goto out;

		if (add_data(sockfd, ln, "text",
			     ln->cipher, ln->ss_header_len) == -1)
			goto out;
	}

	if (encrypt(sockfd, ln) == -1)
		goto out;

	ret = do_send(ln->server_sockfd, ln, "cipher", 0);
	if (ret == -2) {
		sock_info(sockfd, "do_send returns -2");
		goto out;
	} else if (ret == -1) {
		sock_info(sockfd, "do_send returns -1, SERVER_SEND_PENDING");
		ln->state |= SERVER_SEND_PENDING;
	} else {
		if (!(ln->state & SS_TCP_HEADER_SENT)) {
			ln->state |= SS_TCP_HEADER_SENT;
			pr_link_debug(ln);
		}
	}

	return 0;
out:
	return -1;
}

/* read cipher from server, decrypt and send to local */
int client_do_server_read(int sockfd, struct link *ln)
{
	int ret;

	if (ln->state & SERVER_SEND_PENDING) {
		return 0;
	}

	/* if iv isn't received, wait to receive bigger than iv_len
	 * bytes before go to next step */
	if (ln->state & SERVER_READ_PENDING) {
		sock_debug(sockfd, "%s: server read pending", __func__);
		pr_link_debug(ln);

		ret = do_read(sockfd, ln, "cipher", ln->cipher_len);
		if (ret == -2) {
			goto out;
		} else if (ret == -1) {
			return 0;
		}

		if (ln->cipher_len <= iv_len) {
			return 0;
		} else {
			ln->state &= ~SERVER_READ_PENDING;
		}
	} else {
		ret = do_read(sockfd, ln, "cipher", 0);
		if (ret == -2) {
			goto out;
		} else if (ret == -1) {
			return 0;
		}

		if (!(ln->state & SS_IV_RECEIVED)) {
			if (ln->cipher_len <= iv_len) {
				ln->state |= SERVER_READ_PENDING;
				return 0;
			}
		}
	}

	if (decrypt(sockfd, ln) == -1)
		goto out;

	if (ln->state & SS_UDP) {
		if (add_data(sockfd, ln, "text",
			     rsv_frag, sizeof(rsv_frag)) == -1)
			goto out;
	}

	ret = do_send(ln->local_sockfd, ln, "text", 0);
	if (ret == -2) {
		goto out;
	} else if (ret == -1) {
		ln->state |= LOCAL_SEND_PENDING;
	}

	return 0;
out:
	return -1;
}

int client_do_pollin(int sockfd, struct link *ln)
{
	if (sockfd == ln->local_sockfd) {
		if (ln->state & SERVER_PENDING) {
			sock_debug(sockfd, "%s: server pending",
				   __func__);
			goto out;
		} else if (client_do_local_read(sockfd, ln) == -1) {
			goto clean;
		}
	} else if (sockfd == ln->server_sockfd) {
		if (ln->state & LOCAL_PENDING) {
			sock_debug(sockfd, "%s: local pending",
				   __func__);
			goto out;
		} else if (client_do_server_read(sockfd, ln) == -1) {
			goto clean;
		}
	}

out:
	return 0;
clean:
	sock_info(sockfd, "%s close", __func__);
	destroy_link(sockfd);
	return -1;
}

int client_do_pollout(int sockfd, struct link *ln)
{
	int ret, optval;
	int optlen = sizeof(optval);

	/* write to local */
	if (sockfd == ln->local_sockfd) {
		if (ln->state & LOCAL_SEND_PENDING) {
			ret = do_send(sockfd, ln, "text", 0);
			if (ret == -2) {
				goto clean;
			} else if (ret == -1) {
				goto out;
			} else {
				ln->state &= ~LOCAL_SEND_PENDING;
			}

			goto out;
		} else {
			poll_rm(sockfd, POLLOUT);
		}
	} else if (sockfd == ln->server_sockfd) {
		/* pending connect finished */
		if (!(ln->state & SERVER)) {
			if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR,
				       &optval, (void *)&optlen) == -1) {
				sock_warn(sockfd, "%s: getsockopt() %s",
					  __func__, strerror(errno));
				goto clean;
			}

			if (optval == 0) {
				sock_info(sockfd,
					  "%s: pending connect() finished",
					  __func__);
				ln->time = time(NULL);
				ln->state |= SERVER;
			} else {
				sock_warn(sockfd,
					  "%s: pending connect() failed",
					  __func__);
				goto clean;
			}
		}

		if (ln->state & SERVER_SEND_PENDING) {
			/* write to server */
			ret = do_send(sockfd, ln, "cipher", 0);
			if (ret == -2) {
				goto clean;
			} else if (ret == -1) {
				goto out;
			} else {
				ln->state &= ~SERVER_SEND_PENDING;

				if (!(ln->state & SS_TCP_HEADER_SENT))
					ln->state |= SS_TCP_HEADER_SENT;
				goto out;
			}
		} else {
			poll_rm(sockfd, POLLOUT);
		}
	}

out:
	return 0;
clean:
	sock_info(sockfd, "%s: close", __func__);
	destroy_link(sockfd);
	return -1;
}

int main(int argc, char **argv)
{
	short revents;
	int i, listenfd, sockfd;
	int ret = 0;
	struct link *ln;
	struct addrinfo *local_ai = NULL;
	struct addrinfo hint;

	check_ss_option(argc, argv, "client");

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(ss_opt.server_addr, ss_opt.server_port,
			  &hint, &server_ai);
	if (ret != 0) {
		pr_warn("getaddrinfo error: %s\n", gai_strerror(ret));
		goto out;
	}

	pr_ai_notice(server_ai, "server address");

	ret = getaddrinfo(ss_opt.local_addr, ss_opt.local_port, &hint, &local_ai);
	if (ret != 0) {
		pr_warn("getaddrinfo error: %s\n", gai_strerror(ret));
		goto out;
	}

	pr_ai_notice(local_ai, "listening address");

	if (crypto_init(ss_opt.password, ss_opt.method) == -1) {
		ret = -1;
		goto out;
	}

	ss_init();
	listenfd = do_listen(local_ai, "tcp");
	clients[0].fd = listenfd;
	clients[0].events = POLLIN;

	while (1) {
		pr_debug("start polling\n");
		ret = poll(clients, nfds, TCP_INACTIVE_TIMEOUT * 1000);
		if (ret == -1)
			err_exit("poll error");
		else if (ret == 0) {
			reaper();
			continue;
		}

		if (clients[0].revents & POLLIN) {
			sockfd = accept(clients[0].fd, NULL, NULL);
			if (sockfd == -1) {
				pr_warn("accept error\n");
			} else if (poll_set(sockfd, POLLIN) == -1) {
				close(sockfd);
			} else {
				ln = create_link(sockfd, "client");
				if (ln == NULL) {
					poll_del(sockfd);
					close(sockfd);
				} else {
					ln->server = server_ai;
				}
			}
		}

		for (i = 1; i < nfds; i++) {
			sockfd = clients[i].fd;
			if (sockfd == -1)
				continue;

			revents = clients[i].revents;
			if (revents == 0)
				continue;

			ln = get_link(sockfd);
			if (ln == NULL) {
				sock_warn(sockfd, "close: can't get link");
				close(sockfd);
				continue;
			}
			
			if (revents & POLLIN) {
				client_do_pollin(sockfd, ln);
			}

			if (revents & POLLOUT) {
				client_do_pollout(sockfd, ln);
			}

			/* suppress the noise */
			/* if (revents & POLLPRI) { */
			/* 	sock_warn(sockfd, "POLLPRI"); */
			/* } else if (revents & POLLERR) { */
			/* 	sock_warn(sockfd, "POLLERR"); */
			/* } else if (revents & POLLHUP) { */
			/* 	sock_warn(sockfd, "POLLHUP"); */
			/* } else if (revents & POLLNVAL) { */
			/* 	sock_warn(sockfd, "POLLNVAL"); */
			/* } */
		}

		reaper();
	}

out:
	crypto_exit();

	if (server_ai)
		freeaddrinfo(server_ai);

	if (local_ai)
		freeaddrinfo(local_ai);

	ss_exit();

	if (ret == -1)
		exit(EXIT_FAILURE);
	else
		exit(EXIT_SUCCESS);
}
