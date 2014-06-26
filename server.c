#include <getopt.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "common.h"
#include "crypto.h"
#include "log.h"

void usage_server(const char *name)
{
	printf("Usage: %s [options]\n", name);
	printf("Options:\n");
	printf("\t-l,--local local\n");
	printf("\t-b,--local-port local port\n");
	printf("\t-k,--password your password\n");
	printf("\t-m,--method encryption algorithm\n");
	printf("\t-d,--debug print debug information\n");
	printf("\t-v,--verbose print verbose information\n");
	printf("\t-h,--help print this help information\n");
}

/* read text from remote, encrypt and send to local */
int server_do_remote_read(int sockfd, struct link *ln)
{
	if (do_text_read(sockfd, ln) == -2)
		goto out;

	if (ln->state & SS_UDP) {
		if (add_ss_header(sockfd, ln) == -1)
			goto out;
	}

	if (encrypt(sockfd, ln) == -1)
		goto out;

	if (ln->state & SS_UDP) {
		if (add_iv(sockfd, ln) == -1)
			goto out;
	}

	if (do_cipher_send(ln->local_sockfd, ln) == -2)
		goto out;

	sock_info(sockfd, "%s succeeded", __func__);
	return 0;

out:
	sock_info(sockfd, "%s failed", __func__);
	return -1;
}

/* read encrypt from local, decrypt and send to remote */
int server_do_local_read(int sockfd, struct link *ln)
{
	if (do_cipher_read(sockfd, ln) == -2)
		goto out;

	if (ln->state & SS_UDP) {
		if (receive_iv(sockfd, ln) == -1)
			goto out;
	} else if (!(ln->state & SS_TCP_HEADER_RECEIVED)) {
		if (receive_iv(sockfd, ln) == -1)
			goto out;
	}

	if (decrypt(sockfd, ln) == -1)
		goto out;

	if (ln->state & SS_UDP) {
		memcpy(ln->udp_header, ln->text, ln->text_len);
		ln->udp_header_len = ln->text_len;
	}

	if (ln->state & SS_UDP || !(ln->state & SS_TCP_HEADER_RECEIVED)) {
		if (check_ss_header(sockfd, ln) == -1)
			goto out;
	}

	if (connect_server(ln) == -1)
		goto out;

	if (do_text_send(ln->server_sockfd, ln) == -2)
		goto out;

	sock_info(sockfd, "%s succeeded", __func__);
	return 0;

out:
	sock_info(sockfd, "%s failed", __func__);
	return -1;
}

int server_do_pollin(int sockfd, struct link *ln)
{
	if (sockfd == ln->local_sockfd) {
		if (!(ln->state & SERVER))
			sock_info(sockfd, "%s: connect() in progress",
				  __func__);

		if (server_do_local_read(sockfd, ln) == -1)
			goto clean;
		else
			goto out;
	} else {
		if (server_do_remote_read(sockfd, ln) == -1)
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

int server_do_pollout(int sockfd, struct link *ln)
{
	int optval;
	int optlen = sizeof(optval);

	/* write to local */
	if (sockfd == ln->local_sockfd) {
		if (do_cipher_send(sockfd, ln) == -2)
			goto clean;
		else
			goto out;
	} else {
		/* pending connect finished */
		if (!(ln->state & SERVER)) {
			if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR,
				       &optval, &optlen) == -1) {
				sock_warn(sockfd, "%s: getsockopt() %s",
					  __func__, strerror(errno));
				return -1;
			}

			if (optval == 0) {
				sock_info(sockfd,
					  "%s: pending connect() finished",
					  __func__);
				ln->state |= SERVER;
				goto out;
			} else {
				sock_warn(sockfd,
					  "%s: pending connect() failed",
					  __func__);
				goto clean;
			}

		}

		/* write to server */
		if (do_text_send(sockfd, ln) == -2)
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

int main(int argc, char **argv)
{
	int i, opt, sockfd, listenfd;
	int ret = 0;
	char *local = NULL;
	char *l_port = NULL;
	struct link *ln;
	struct addrinfo *s_info = NULL;
	struct addrinfo *l_info = NULL;

	struct option long_options[] = {
		{"local", required_argument, 0, 'c'},
		{"local-port", required_argument, 0, 'b'},
		{"password", required_argument, 0, 'k'},
		{"method", required_argument, 0, 'm'},
		{"verbose", no_argument, 0, 'v'},
		{"debug", no_argument, 0, 'd'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "l:b:k:m:vdh",
				  long_options, NULL)) != -1) {
		switch (opt) {
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
			usage_server(argv[0]);
			exit(EXIT_SUCCESS);
		case '?':
			usage_server(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (local && l_port) {
		ret = getaddrinfo(local, l_port, NULL, &l_info);
		if (ret != 0) {
			printf("getaddrinfo error: %s\n", gai_strerror(ret));
			goto out_addrinfo;
		}
	} else {
		printf("Either local addr or local port is not specified\n");
		usage_server(argv[0]);
		ret = -1;
		goto out_addrinfo;
	}

	if (crypto_init(passwd, method) == -1) {
		ret = -1;
		goto out_addrinfo;
	}

	poll_alloc();
	poll_init();
	listenfd = do_listen(l_info, "tcp");
	clients[0].fd = listenfd;
	clients[0].events = POLLIN;
	listenfd = do_listen(l_info, "udp");
	clients[1].fd = listenfd;
	clients[1].events = POLLIN;

	while (1) {
		pr_debug("start polling\n");
		ret = poll(clients, nfds, -1);
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
			if (sockfd == -1)
				pr_warn("accept error\n");

			if (poll_set(sockfd, POLLIN) == -1) {
				sock_warn(sockfd, "add to poll failed");
				close(sockfd);
			}

			ln = create_link(sockfd, "tcp");
			if (ln == NULL) {
				poll_del(sockfd);
				close(sockfd);
			}
		}

		if (clients[1].revents & POLLIN) {
			sockfd = accept(listenfd, NULL, NULL);
			if (sockfd == -1)
				pr_warn("accept error\n");

			if (poll_set(sockfd, POLLIN) == -1) {
				sock_warn(sockfd, "add to poll failed");
				close(sockfd);
			}

			ln = create_link(sockfd, "udp");
			if (ln == NULL) {
				poll_del(sockfd);
				close(sockfd);
			}
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

				server_do_pollin(sockfd, ln);
			}

			if (clients[i].revents & POLLOUT) {
				ln = get_link(sockfd);
				if (ln == NULL) {
					sock_warn(sockfd, "pollout: no link");
					close(sockfd);
					continue;
				}

				server_do_pollout(sockfd, ln);
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

	if (ret == -1)
		exit(EXIT_FAILURE);
	else
		exit(EXIT_SUCCESS);
}
