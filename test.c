#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "common.h"
#include "crypto.h"
#include "log.h"

int main(int argc, char **argv)
{
	int ret;
	struct addrinfo *ai = NULL;
	void *addrptr;
	char addr[INET6_ADDRSTRLEN];
	unsigned short port;

	ret = getaddrinfo(argv[1], argv[2], NULL, &ai);
	if (ret != 0) {
		printf("getaddrinfo error\n");
		exit(1);
	}

	while (ai) {
		if (ai->ai_family == AF_INET) {
			addrptr = &((struct sockaddr_in *)ai->ai_addr)->sin_addr;
			port = ntohs(((struct sockaddr_in *)ai->ai_addr)->sin_port);
		} else if (ai->ai_family == AF_INET6) {
			addrptr = &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
			port = ntohs(((struct sockaddr_in6 *)ai->ai_addr)->sin6_port);
		}

		if (inet_ntop(ai->ai_family, addrptr, addr,
			      INET6_ADDRSTRLEN) == NULL) {
			perror("inet_ntop");
			exit(1);
		}

		printf("%s:%d(socktype: %d)\n", addr, port, ai->ai_socktype);
		ai = ai->ai_next;
	}

	return 0;
}
