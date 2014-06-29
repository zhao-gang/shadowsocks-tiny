#include <getopt.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

	return 0;

out:
	return -1;
}

/* read encrypt from local, decrypt */
int server_do_local_read(int sockfd, struct link *ln)
{
	if (do_cipher_read(sockfd, ln) == -2) {
		goto out;
	}

	if (ln->state & SS_UDP ||
	    !(ln->state & SS_TCP_HEADER_RECEIVED)) {
		if (receive_iv(sockfd, ln) == -1)
			goto out;
	}

	if (decrypt(sockfd, ln) == -1)
		goto out;

	if (ln->state & SS_UDP) {
		if (check_ss_header(sockfd, ln) == -1)
			goto out;
	} else if (!(ln->state & SS_TCP_HEADER_RECEIVED)) {
		if (check_ss_header(sockfd, ln) == -1)
			goto out;

		ln->state |= SS_TCP_HEADER_RECEIVED;
	}

	if (do_text_send(ln->server_sockfd, ln) == -2)
		goto out;

	return 0;

out:
	return -1;
}

int server_do_pollin(int sockfd, struct link *ln)
{
	if (sockfd == ln->local_sockfd) {
		if (!(ln->state & SERVER))
			sock_info(sockfd, "%s: connect() in progress",
				  __func__);

		if (ln->state & PENDING) {
			sock_info(sockfd, "%s: pending when pollin",
				  __func__);
			goto out;
		} else if (server_do_local_read(sockfd, ln) == -1) {
			goto clean;
		} else {
			goto out;
		}
	} else {
		if (ln->state & PENDING) {
			sock_info(sockfd, "%s: pending when pollin",
				  __func__);
			goto out;
		} else if (server_do_remote_read(sockfd, ln) == -1) {
			goto clean;
		} else {
			goto out;
		}
	}

out:
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
		if (ln->state & CIPHER_PENDING) {
			if (do_cipher_send(sockfd, ln) == -2)
				goto clean;
			else
				goto out;
		} else {
			poll_rm(sockfd, POLLOUT);
		}
	} else {
		/* pending connect finished */
		if (!(ln->state & SERVER)) {
			ln->time = time(NULL);
			if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR,
				       &optval, (void *)&optlen) == -1) {
				sock_warn(sockfd, "%s: getsockopt() %s",
					  __func__, strerror(errno));
				return -1;
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

		if (ln->state & TEXT_PENDING) {
			/* write to remote */
			if (do_text_send(sockfd, ln) == -2) {
				goto clean;
			} else {
				goto out;
			}
		} else {
			poll_rm(sockfd, POLLOUT);
		}
	}

out:
	return 0;
clean:
	sock_info(sockfd, "%s: closed", __func__);
	destroy_link(ln);
	return -1;
}

int main(int argc, char **argv)
{
	short revents;
	int i, listenfd, opt, sockfd;
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
		pr_ai_debug(l_info, "server listening address:");
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

	poll_init();
	listenfd = do_listen(l_info, "tcp");
	clients[0].fd = listenfd;
	clients[0].events = POLLIN;
	listenfd = do_listen(l_info, "udp");
	clients[1].fd = listenfd;
	clients[1].events = POLLIN;

	while (1) {
		ret = poll(clients, nfds, TCP_READ_TIMEOUT * 1000);
		if (ret == -1) {
			err_exit("poll error");
		} else if (ret == 0) {
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
				ln = create_link(sockfd);
				if (ln == NULL) {
					poll_del(sockfd);
					close(sockfd);
				}
			}
		}

		if (clients[1].revents & POLLIN) {
			pr_warn("udp socks5 not supported(for now)\n");
			/* ln = create_link(sockfd); */
			/* if (ln != NULL) { */
			/* 	check_ss_header(sockfd, ln); */
			/* } */
		}

		for (i = 2; i < nfds; i++) {
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
			}

			if (revents & POLLIN) {
				server_do_pollin(sockfd, ln);
			}

			if (revents & POLLOUT) {
				server_do_pollout(sockfd, ln);
			}

			if (revents & POLLPRI) {
				sock_warn(sockfd, "POLLERR");
			} else if (revents & POLLERR) {
				sock_warn(sockfd, "POLLERR");
			} else if (revents & POLLHUP) {
				sock_warn(sockfd, "POLLHUP");
			} else if (revents & POLLNVAL) {
				sock_warn(sockfd, "POLLNVAL");
			}
		}

		reaper();
	}

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
