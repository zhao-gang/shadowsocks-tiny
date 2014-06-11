#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "common.h"
#include "log.h"

void usage_test(const char *name)
{
	printf("Usage: %s [options]\n", name);
	printf("Options:\n");
	printf("\t-s,--server server\n");
	printf("\t-p,--server-port server port\n");
	printf("\t-t,--text data you want to send\n");
	printf("\t-d,--debug print debug information\n");
	printf("\t-v,--verbose print verbose information\n");
	printf("\t-h,--help print this help\n");
}

int main(int argc, char **argv)
{
	int opt, sockfd, size;
	int ret = 0;
	char text[2048];
	char result[2048];
	char *server = NULL;
	char *local = NULL;
	char *s_port = NULL;
	struct addrinfo *s_info;
	struct sockaddr_storage ss;
	int addrlen = sizeof(ss);

	struct option long_options[] = {
		{"server", required_argument, 0, 's'},
		{"server-port", required_argument, 0, 'p'},
		{"text", required_argument, 0, 't'},
		{"debug", no_argument, 0, 'd'},
		{"verbose", no_argument, 0, 'v'},
		{0, 0, 0, 0},
	};

	while ((opt = getopt_long(argc, argv, "s:p:t:dvh",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 's':
			server = optarg;
			break;
		case 'p':
			s_port = optarg;
			break;
		case 't':
			strcpy(text, optarg);
			break;
		case 'd':
			debug = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 'h':
			usage_test(argv[0]);
			exit(EXIT_SUCCESS);
		case '?':
			pr_exit("unkown option: %s\n", argv[optind]);
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
		usage_test(argv[0]);
		ret = -1;
		goto out_addrinfo;
	}

	sockfd = socket(s_info->ai_family, s_info->ai_socktype, 0);
	if (sockfd == -1)
		err_exit("socket");

	if (connect(sockfd, s_info->ai_addr, s_info->ai_addrlen) == -1)
		pr_warn("connect failed\n");

	if (getsockname(sockfd, (struct sockaddr *)&ss, &addrlen) != 0)
		err_exit("getsockname");

	if (ss.ss_family == AF_INET) {
		printf("port %d\n",
		       ntohs(((struct sockaddr_in *)&ss)->sin_port));
	}

	size = send(sockfd, text, strlen(text) + 1, 0);
	if (size == -1)
		err_exit("send");

	pr_debug("send: %s, len: %d\n", text, size);

	size = recv(sockfd, result, 2048, 0);
	if (size == -1)
		err_exit("result");

	result[size] = '\0';

	pr_debug("received: %s, len: %d\n", result, size);

out_addrinfo:
	if (s_info)
		freeaddrinfo(s_info);

	if (ret == -1)
		exit(EXIT_FAILURE);
	else
		exit(EXIT_SUCCESS);
}
