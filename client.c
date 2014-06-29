#include <getopt.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "common.h"
#include "crypto.h"
#include "log.h"

char rsv_frag[3] = {0x00, 0x00, 0x00};

void usage_client(const char *name)
{
	printf("Usage: %s [options]\n", name);
	printf("Options:\n");
	printf("\t-s,--server server\n");
	printf("\t-p,--server-port server port\n");
	printf("\t-l,--l local\n");
	printf("\t-b,--local-port local port\n");
	printf("\t-k,--password your password\n");
	printf("\t-m,--method encryption algorithm\n");
	printf("\t-d,--debug print debug information\n");
	printf("\t-v,--verbose print verbose information\n");
	printf("\t-h,--help print this help\n");
}

/* read text from local, encrypt and send to server */
int client_do_local_read(int sockfd, struct link *ln)
{
	int ret, cmd;


	if (do_text_read(sockfd, ln) == -2) {
		goto out;
	}

	if (!(ln->state & SOCKS5_AUTH_REQUEST_RECEIVED)) {
		ln->state |= SOCKS5_AUTH_REQUEST_RECEIVED;

		if (check_socks5_auth_header(sockfd, ln) == -1) {
			if (create_socks5_auth_reply(sockfd, ln, 0) == -1)
				goto out;
		} else {
			if (create_socks5_auth_reply(sockfd, ln, 1) == -1)
				goto out;
		}

		ret = do_text_send(sockfd, ln);
		if (ret == -2) {
			goto out;
		} else if (ret == -1) {
			return 0;
		} else {
			ln->state |= SOCKS5_AUTH_REPLY_SENT;
			return 0;
		}
	} else if (!(ln->state & SOCKS5_CMD_REQUEST_RECEIVED)) {
		ln->state |= SOCKS5_CMD_REQUEST_RECEIVED;

		if (check_socks5_cmd_header(sockfd, ln) == -1) {
			cmd = SOCKS5_CMD_REP_FAILED;
			if (create_socks5_cmd_reply(sockfd, ln, cmd) == -1)
				goto out;
		} else {
			cmd = SOCKS5_CMD_REP_SUCCEEDED;
			if (create_socks5_cmd_reply(sockfd, ln, cmd) == -1)
				goto out;
		}

		/* cmd reply to local */
		ret = do_text_send(sockfd, ln);
		if (ret == -2 || cmd == SOCKS5_CMD_REP_FAILED) {
			goto out;
		} else if (ret == -1) {
			return 0;
		} else {
			ln->state |= SOCKS5_CMD_REPLY_SENT;
			return 0;
		}
	}

	if (!(ln->state & SOCKS5_CMD_REPLY_SENT)) {
		return 0;
	}

	if (ln->state & SS_UDP) {
		/* remove rsv(2) + frag(1) */
		if (rm_data(sockfd, ln, "text", 3) == -1)
			goto out;
	} else if (!(ln->state & SS_TCP_HEADER_SENT)) {
		/* restore ss tcp header */
		ln->text -= ln->ss_header_len;
		ln->text_len += ln->ss_header_len;
	}

	if (encrypt(sockfd, ln) == -1)
		goto out;

	if (ln->state & SS_UDP) {
		if (add_iv(sockfd, ln) == -1)
			goto out;
	} else if (!(ln->state & SS_TCP_HEADER_SENT)) {
		if (add_iv(sockfd, ln) == -1)
			goto out;

		ln->state |= SS_TCP_HEADER_SENT;
	}

	if (do_cipher_send(ln->server_sockfd, ln) == -2)
		goto out;

	return 0;

out:
	return -1;
}

/* read encrypt from server, decrypt and send to local */
int client_do_server_read(int sockfd, struct link *ln)
{
	if (do_cipher_read(sockfd, ln) == -2)
		goto out;

	if (ln->state & SS_UDP) {
		if (receive_iv(sockfd, ln) == -1)
			goto out;
	}

	if (decrypt(sockfd, ln) == -1)
		goto out;

	if (ln->state & SS_UDP) {
		if (add_data(sockfd, ln, "text",
			     rsv_frag, sizeof(rsv_frag)) == -1)
			goto out;
	}

	if (do_text_send(ln->local_sockfd, ln) == -1)
		goto out;

	return 0;

out:
	return -1;
}

int client_do_pollin(int sockfd, struct link *ln)
{
	if (sockfd == ln->local_sockfd) {
		/* if (ln->state & WAITING) { */
		/* 	sock_info(sockfd, "%s: waiting for server data", */
		/* 		  __func__); */
		/* 	goto out; */
		if (ln->state & PENDING) {
			sock_info(sockfd, "%s: pending when pollin",
				  __func__);
			goto out;
		} else if (client_do_local_read(sockfd, ln) == -1) {
			goto clean;
		}
	} else if (sockfd == ln->server_sockfd) {
		if (ln->state & PENDING) {
			sock_info(sockfd, "%s: pending when pollin",
				  __func__);
			goto out;
		} else if (client_do_server_read(sockfd, ln) == -1) {
			goto clean;
		/* } else { */
		/* 	/\* read okay, we can continue to read from */
		/* 	 * local *\/ */
		/* 	ln->state &= ~WAITING; */
		/* 	goto out; */
		}
	}

out:
	return 0;
clean:
	sock_info(sockfd, "%s: closed", __func__);
	destroy_link(ln);
	return -1;
}

int client_do_pollout(int sockfd, struct link *ln)
{
	int ret, optval;
	int optlen = sizeof(optval);

	/* write to local */
	if (sockfd == ln->local_sockfd) {
		if (ln->state & SOCKS5_AUTH_REQUEST_RECEIVED &&
		    !(ln->state & SOCKS5_AUTH_REPLY_SENT)) {
			ret = do_text_send(sockfd, ln);
			if (ret == -2) {
				goto clean;
			} else if (ret == -1) {
				goto out;
			} else {
				ln->state |= SOCKS5_AUTH_REPLY_SENT;
				goto out;
			}
		}

		if (ln->state & SOCKS5_CMD_REQUEST_RECEIVED &&
		    !(ln->state & SOCKS5_CMD_REPLY_SENT) &&
		    ln->state & CIPHER_PENDING) {
			ret = do_text_send(sockfd, ln);
			if (ret == -2) {
				goto clean;
			} else if (ret == -1) {
				goto out;
			} else {
				ln->state |= SOCKS5_CMD_REPLY_SENT;
				goto out;
			}
		}

		if (ln->state & TEXT_PENDING) {
			ret = do_text_send(sockfd, ln);
			if (ret == -2) {
				goto clean;
			} else {
				goto out;
			}
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
				ln->state |= SERVER;
			} else {
				sock_warn(sockfd,
					  "%s: pending connect() failed",
					  __func__);
				goto clean;
			}
		}

		if (ln->state & CIPHER_PENDING) {
			/* write to server */
			if (do_cipher_send(sockfd, ln) == -2) {
				goto clean;
			} else {
				goto out;
			}
		} else {
			poll_rm(sockfd, POLLOUT);
		}
	}

out:
	sock_info(sockfd, "%s succeeded", __func__);
	return 0;
clean:
	sock_info(sockfd, "%s: closed", __func__);
	destroy_link(ln);
	return -1;
}

int main(int argc, char **argv)
{
	int i, opt, sockfd, listenfd, revents;
	int ret = 0;
	char *server = NULL;
	char *local = NULL;
	char *s_port = NULL;
	char *l_port = NULL;
	struct link *ln;
	struct addrinfo *s_info = NULL;
	struct addrinfo *l_info = NULL;

	struct option long_options[] = {
		{"server", required_argument, 0, 's'},
		{"server-port", required_argument, 0, 'p'},
		{"local", required_argument, 0, 'c'},
		{"port", required_argument, 0, 'b'},
		{"password", required_argument, 0, 'k'},
		{"method", required_argument, 0, 'm'},
		{"verbose", no_argument, 0, 'v'},
		{"debug", no_argument, 0, 'd'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "s:p:l:b:k:m:dvh",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 's':
			server = optarg;
			break;
		case 'p':
			s_port = optarg;
			break;
		case 'l':
			local = optarg;
			break;
		case 'b':
			l_port = optarg;
			break;
		case 'k':
			strncpy(passwd, optarg, MAX_KEY_LEN);
			passwd[MAX_KEY_LEN - 1] = '\0';
			break;
		case 'm':
			strncpy(method, optarg, MAX_METHOD_NAME_LEN);
			method[MAX_METHOD_NAME_LEN - 1] = '\0';
			break;
		case 'v':
			verbose = true;
			break;
		case 'd':
			debug = true;
			break;
		case 'h':
			usage_client(argv[0]);
			exit(EXIT_SUCCESS);
		case '?':
			usage_client(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (server && s_port) {
		ret = getaddrinfo(server, s_port, NULL, &s_info);
		if (ret != 0) {
			pr_warn("getaddrinfo error: %s\n", gai_strerror(ret));
			goto out_addrinfo;
		}
		pr_ai_debug(s_info, "server addrinfo");
	} else {
		pr_warn("Either server addr or server port is not specified\n");
		usage_client(argv[0]);
		ret = -1;
		goto out_addrinfo;
	}

	if (local && l_port) {
		ret = getaddrinfo(local, l_port, NULL, &l_info);
		if (ret != 0) {
			pr_warn("getaddrinfo error: %s\n", gai_strerror(ret));
			goto out_addrinfo;
		}
	} else {
		pr_warn("Either local addr or local port is not specified\n");
		usage_client(argv[0]);
		ret = -1;
		goto out_addrinfo;
	}

	if (crypto_init(passwd, method) == -1) {
		ret = -1;
		goto out_addrinfo;
	}

	poll_init();
	listenfd = do_listen(l_info, "tcp");
	clients[0].fd = listenfd;
	clients[0].events = POLLIN;

	while (1) {
		pr_debug("start polling\n");
		ret = poll(clients, nfds, -1);
		pr_debug("poll returned %d\n", ret);
		if (ret == -1)
			err_exit("poll error");

		/* can't happen, because we have set timeout to
		 * infinite, but as a paranoid... */
		if (ret == 0) {
			pr_warn("poll returned zero\n");
			continue;
		}

		if (clients[0].revents & POLLIN) {
			sockfd = accept(listenfd, NULL, NULL);
			if (sockfd == -1) {
				pr_warn("accept error\n");
			} else {
				sock_info(sockfd, "accept");
				if (poll_set(sockfd, POLLIN) == -1) {
					close(sockfd);
				} else {
					ln = create_link(sockfd);
					if (ln == NULL) {
						poll_del(sockfd);
						close(sockfd);
					} else {
						ln->server = s_info;
					}
				}
			}
		}

		for (i = 1; i < nfds; i++) {
			sockfd = clients[i].fd;
			if (sockfd == -1)
				continue;

			revents = clients[i].revents;
			if (revents & POLLIN) {
				sock_debug(sockfd, "POLLIN");
				ln = get_link(sockfd);
				if (ln == NULL) {
					sock_warn(sockfd, "pollin: no link");
					close(sockfd);
				} else {
					client_do_pollin(sockfd, ln);
				}
			}

			if (revents & POLLOUT) {
				sock_debug(sockfd, "POLLOUT");
				ln = get_link(sockfd);
				if (ln == NULL) {
					sock_warn(sockfd, "pollout: no link");
					close(sockfd);
				} else {
					client_do_pollout(sockfd, ln);
				}
			}

			if (revents & POLLERR || revents & POLLHUP ||
			    revents & POLLNVAL) {
				sock_warn(sockfd, "poll error");
			}
		}
	}

	crypto_exit();
out_addrinfo:
	if (s_info)
		freeaddrinfo(s_info);
	if (l_info)
		freeaddrinfo(l_info);

	free(clients);

	if (ret == -1)
		exit(EXIT_FAILURE);
	else
		exit(EXIT_SUCCESS);
}
