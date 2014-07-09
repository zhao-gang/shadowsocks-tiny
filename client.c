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

int parse_socks5_proto(int sockfd, struct link *ln)
{
	int ret, cmd;

	if (!(ln->state & SOCKS5_AUTH_REQUEST_RECEIVED)) {
		ln->state |= SOCKS5_AUTH_REQUEST_RECEIVED;

		if (check_socks5_auth_header(sockfd, ln) == -1) {
			if (create_socks5_auth_reply(sockfd, ln, 0) == -1)
				goto out;
		} else {
			if (create_socks5_auth_reply(sockfd, ln, 1) == -1)
				goto out;
		}

		ret = do_send(sockfd, ln, "text", 0);
		if (ret == -2) {
			goto out;
		} else if (ret == -1) {
			ln->state |= LOCAL_SEND_PENDING;
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
		ret = do_send(sockfd, ln, "text", 0);
		if (ret == -2 || cmd == SOCKS5_CMD_REP_FAILED) {
			goto out;
		} else if (ret == -1) {
			ln->state |= LOCAL_SEND_PENDING;
			return 0;
		} else {
			ln->state |= SOCKS5_CMD_REPLY_SENT;
			return 0;
		}
	}

	return 0;
out:
	return -1;
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

	if (!(ln->state & SOCKS5_CMD_REPLY_SENT)) {
		if (parse_socks5_proto(sockfd, ln) == -1)
			goto out;

		if (ln->state & LOCAL_SEND_PENDING ||
		    ln->text_len == 0)
			return 0;
	}

	if (ln->state & SS_UDP) {
		/* remove rsv(2) + frag(1) */
		if (rm_data(sockfd, ln, "text", 3) == -1)
			goto out;
	} else if (!(ln->state & SS_TCP_HEADER_SENT)) {
		if (add_data(sockfd, ln, "text",
			     ln->cipher, ln->ss_header_len) == -1)
			goto out;
	}

	if (encrypt(sockfd, ln) == -1)
		goto out;

	ret = do_send(ln->server_sockfd, ln, "cipher", 0);
	if (ret == -2) {
		goto out;
	} else if (ret == -1) {
		ln->state |= SERVER_SEND_PENDING;
	} else {
		if (!(ln->state & SS_TCP_HEADER_SENT))
			ln->state |= SS_TCP_HEADER_SENT;
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

			/* update socks5 state */
			if (!(ln->state & SOCKS5_AUTH_REPLY_SENT))
				ln->state &= SOCKS5_AUTH_REPLY_SENT;
			else if (!(ln->state & SOCKS5_CMD_REPLY_SENT))
				ln->state &= SOCKS5_CMD_REPLY_SENT;

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
	int i, listenfd, opt, sockfd;
	int ret = 0;
	char *server = NULL;
	char *local = NULL;
	char *s_port = NULL;
	char *l_port = NULL;
	struct link *ln;
	struct addrinfo *s_info = NULL;
	struct addrinfo *l_info = NULL;
	struct addrinfo hint;

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
			strncpy(password, optarg, MAX_PWD_LEN);
			password[MAX_PWD_LEN] = '\0';
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

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;

	if (server && s_port) {
		ret = getaddrinfo(server, s_port, &hint, &s_info);
		if (ret != 0) {
			pr_warn("getaddrinfo error: %s\n", gai_strerror(ret));
			goto out;
		}
		_pr_addrinfo("INFO", s_info, "server address", NULL);
	} else {
		pr_warn("Either server addr or server port is not specified\n");
		usage_client(argv[0]);
		ret = -1;
		goto out;
	}

	if (local && l_port) {
		ret = getaddrinfo(local, l_port, &hint, &l_info);
		if (ret != 0) {
			pr_warn("getaddrinfo error: %s\n", gai_strerror(ret));
			goto out;
		}
		_pr_addrinfo("INFO", l_info, "listening address", NULL);
	} else {
		pr_warn("Either local addr or local port is not specified\n");
		usage_client(argv[0]);
		ret = -1;
		goto out;
	}

	if (crypto_init(password, method) == -1) {
		ret = -1;
		goto out;
	}

	poll_init();
	listenfd = do_listen(l_info, "tcp");
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
					ln->server = s_info;
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
