#include <getopt.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "common.h"
#include "crypto.h"
#include "log.h"

unsigned char rsv_frag[3] = {0x00, 0x00, 0x00};

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

	if (do_text_read(sockfd, ln) == -2)
		goto out;

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
		ln->state = SOCKS5_CMD_REQUEST_RECEIVED;

		if (check_socks5_cmd_header(sockfd, ln) == -1) {
			cmd = SOCKS5_CMD_REP_FAILED;
			if (create_socks5_cmd_reply(sockfd, ln, cmd) == -1)
				goto out;
		} else {
			if (connect_server(ln) == -1)
				goto out;
			cmd = SOCKS5_CMD_REP_SUCCEEDED;
			if (create_socks5_cmd_reply(sockfd, ln, cmd) == -1)
				goto out;
		}

		/* cmd reply to local */
		ret = do_cipher_send(sockfd, ln);
		if (ret == -2 || cmd == SOCKS5_CMD_REP_FAILED) {
			goto out;
		} else if (ret == -1) {
			return 0;
		} else {
			ln->state |= SOCKS5_CMD_REPLY_SENT;
		}
	}

	if (!(ln->state & SOCKS5_CMD_REPLY_SENT)) {
		return 0;
	}

	if (!(ln->state & SS_UDP) && !(ln->state & SS_TCP_HEADER_SENT)) {
		if (encrypt(sockfd, ln) == -1)
			goto out;

		if (add_iv(sockfd, ln) == -1)
			goto out;

		ret = do_cipher_send(ln->server_sockfd, ln);
		if (ret == -2) {
			goto out;
		} else if (ret == -1) {
			return 0;
		} else {
			ln->state |= SS_TCP_HEADER_SENT;
			return 0;
		}
	}

	/* remove udp header for shadowsocks protocol */
	if (ln->state & SS_UDP) {
		if (rm_data(sockfd, ln, "text", 3) == -1)
			goto out;
	}

	if (encrypt(sockfd, ln) == -1)
		goto out;

	if (ln->state & SS_UDP) {
		if (add_iv(sockfd, ln) == -1)
			goto out;
	}

	if (do_cipher_send(ln->server_sockfd, ln) == -2)
		goto out;

	sock_debug(sockfd, "%s returned successfully", __func__);
	return 0;

out:
	sock_debug(sockfd, "%s returned prematurely", __func__);
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

	sock_debug(sockfd, "%s returned successfully", __func__);
	return 0;

out:
	sock_debug(sockfd, "%s returned prematurely", __func__);
	return -1;
}

int client_do_pollin(int sockfd, struct link *ln)
{
	if (sockfd == ln->local_sockfd) {
		if (client_do_local_read(sockfd, ln) == -1)
			goto clean;
		else
			goto out;
	} else if (sockfd == ln->server_sockfd) {
		if (client_do_server_read(sockfd, ln) == -1)
			goto clean;
		else
			goto out;
	}

out:
	sock_debug(sockfd, "%s succeeded", __func__);
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
		    !(ln->state & SOCKS5_CMD_REPLY_SENT)) {
			ret = do_cipher_send(sockfd, ln);
			if (ret == -2) {
				goto clean;
			} else if (ret == -1) {
				goto out;
			} else {
				ln->state |= SOCKS5_CMD_REPLY_SENT;
				goto out;
			}
		}

		ret = do_text_send(sockfd, ln);
		if (ret == -2) {
			goto clean;
		} else {
			goto out;
		}
	} else if (sockfd == ln->server_sockfd) {
		/* pending connect finished */
		if (!(ln->state & SERVER)) {
			if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR,
				       &optval, &optlen) == -1) {
				sock_warn(sockfd, "%s: getsockopt() %s",
					  __func__, strerror(errno));
				goto clean;
			}

			if (optval == 0) {
				sock_info(sockfd,
					  "%s: pending connect() finished",
					  __func__);
				ln->state |= SERVER;
				poll_rm(sockfd, POLLOUT);
				poll_add(sockfd, POLLIN);
				goto out;
			} else {
				sock_warn(sockfd,
					  "%s: pending connect() failed",
					  __func__);
				goto clean;
			}
		}

		if (ln->state & SOCKS5_CMD_REPLY_SENT &&
		    !(ln->state & SS_UDP) &&
		    !(ln->state & SS_TCP_HEADER_SENT)) {
			ret = do_cipher_send(ln->server_sockfd, ln);
			if (ret == -2) {
				goto clean;
			} else if (ret == -1) {
				return 0;
			} else {
				ln->state |= SS_TCP_HEADER_SENT;
				return 0;
			}
		}

		/* write to server */
		if (do_cipher_send(sockfd, ln) == -2) {
			goto clean;
		} else {
			goto out;
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
	int i, opt, sockfd, listenfd;
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

	if (poll_alloc() == NULL) {
		ret = -1;
		goto out_crypto;
	}

	poll_init();
	listenfd = do_listen(l_info, "tcp");
	clients[0].fd = listenfd;
	clients[0].events = POLLIN;

	while (1) {
		pr_debug("start polling\n");
		ret = poll(clients, nfds, -1);
		if (ret == -1)
			err_exit("poll error");
		pr_info("poll returned %d\n", ret);

		/* can't happen, because we have set timeout to
		 * infinite, but as a paranoid... */
		if (ret == 0) {
			pr_warn("poll returned zero\n");
			continue;
		}

		if (clients[0].revents & POLLIN) {
			sockfd = accept(listenfd, NULL, NULL);
			if (sockfd == -1)
				pr_warn("accept error\n");

			sock_info(sockfd, "accept");
			if (poll_set(sockfd, POLLIN) == -1)
				close(sockfd);

			ln = create_link(sockfd, "tcp");
			if (ln == NULL) {
				sock_debug(sockfd, "create_link failed");
				poll_del(sockfd);
				close(sockfd);
			}

			ln->server = s_info;
		}

		for (i = 1; i < nfds; i++) {
			sockfd = clients[i].fd;
			if (sockfd == -1)
				continue;

			if (clients[i].revents & POLLIN) {
				ln = get_link(sockfd);
				if (ln == NULL) {
					sock_warn(sockfd, "pollin: no link");
					close(sockfd);
					continue;
				}

				if (ln->state & PENDING)
					continue;

				client_do_pollin(sockfd, ln);
			}


			if (clients[i].revents & POLLOUT) {
				ln = get_link(sockfd);
				if (ln == NULL) {
					sock_warn(sockfd, "pollout: no link");
					close(sockfd);
					continue;
				}

				client_do_pollout(sockfd, ln);
			}
		}
	}

out_crypto:
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
