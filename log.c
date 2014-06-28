#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "log.h"

bool debug;
bool verbose;

void pr_fun(const char *level, const char *fmt, va_list ap)
{
	printf("%s: ", level);
	vprintf(fmt, ap);
}

void pr_debug(const char *fmt, ...)
{
	va_list ap;

	if (!debug)
		return;

	va_start(ap, fmt);
	pr_fun("debug", fmt, ap);
	va_end(ap);
}

void pr_info(const char *fmt, ...)
{
	va_list ap;

	if (!verbose)
		return;

	va_start(ap, fmt);
	pr_fun("info", fmt, ap);
	va_end(ap);
}

static int _pr_addrinfo(const char *level, struct addrinfo *info,
			const char *fmt, va_list ap)
{
	struct addrinfo *ai = info;
	void *addrptr;
	char addr[INET6_ADDRSTRLEN];
	unsigned short port;

	printf("%s: ", level);
	vprintf(fmt, ap);
	printf(":");

	while (ai) {
		if (ai->ai_family == AF_INET) {
			addrptr = &((struct sockaddr_in *)ai->ai_addr)->sin_addr;
			port = ntohs(((struct sockaddr_in *)ai->ai_addr)->sin_port);
		} else {
			addrptr = &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
			port = ntohs(((struct sockaddr_in6 *)ai->ai_addr)->sin6_port);
		}

		if (inet_ntop(ai->ai_family, addrptr, addr,
			      INET6_ADDRSTRLEN) == NULL) {
			return errno;
		}

		if (ai->ai_socktype == SOCK_STREAM)
			printf(" %s:%d(tcp)", addr, port);
		else if (ai->ai_socktype == SOCK_DGRAM)
			printf(" %s:%d(udp)", addr, port);
		ai = ai->ai_next;
	}

	printf("\n");

	return 0;
}

void pr_ai_debug(struct addrinfo *info, const char *fmt, ...)
{
	int ret;
	va_list ap;

	if (!debug)
		return;

	va_start(ap, fmt);

	ret = _pr_addrinfo("debug", info, fmt, ap);
	if (ret != 0)
		pr_warn("%s: %s\n", __func__, strerror(ret));

	va_end(ap);
}

void pr_ai_info(struct addrinfo *info, const char *fmt, ...)
{
	int ret;
	va_list ap;

	if (!verbose)
		return;

	va_start(ap, fmt);

	ret = _pr_addrinfo("info", info, fmt, ap);
	if (ret != 0)
		pr_warn("%s: %s\n", __func__, strerror(ret));

	va_end(ap);
}

void pr_ai_warn(struct addrinfo *info, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);

	ret = _pr_addrinfo("WARNING", info, fmt, ap);
	if (ret != 0)
		pr_warn("%s: %s\n", __func__, strerror(ret));

	va_end(ap);
}

int sock_addr(int sockfd, char *str)
{
	void *addrptr;
	struct sockaddr_storage ss_addr;
	int len = sizeof(struct sockaddr_storage);

	if (getsockname(sockfd, (struct sockaddr *)&ss_addr,
			(void *)&len) == -1)
		goto err;

	if (ss_addr.ss_family == AF_INET)
		addrptr = &((struct sockaddr_in *)&ss_addr)->sin_addr;
	else
		addrptr = &((struct sockaddr_in6 *)&ss_addr)->sin6_addr;

	if (inet_ntop(ss_addr.ss_family, addrptr, str,
		      INET6_ADDRSTRLEN) == NULL)
		goto err;

	return 0;

err:
	perror("sock_addr");
	return -1;
}

static int _sock_peer_addr(int sockfd, char *str)
{
	void *addrptr;
	struct sockaddr_storage ss_addr;
	int len = sizeof(struct sockaddr_storage);

	if (getpeername(sockfd, (struct sockaddr *)&ss_addr,
			(void *)&len) == -1)
		goto err;

	if (ss_addr.ss_family == AF_INET)
		addrptr = &((struct sockaddr_in *)&ss_addr)->sin_addr;
	else
		addrptr = &((struct sockaddr_in6 *)&ss_addr)->sin6_addr;

	if (inet_ntop(ss_addr.ss_family, addrptr, str,
		      INET6_ADDRSTRLEN) == NULL)
		goto err;

	return 0;

err:
	return -1;
}

static int _sock_addr(int sockfd, char *str)
{
	int ret;

	ret = _sock_peer_addr(sockfd, str);
	if (ret == 0)
		return 0;
	else
		return sock_addr(sockfd, str);
}

int sock_port(int sockfd)
{
	struct sockaddr_storage ss_addr;
	int len = sizeof(struct sockaddr_storage);

	if (getsockname(sockfd, (struct sockaddr *)&ss_addr,
			(void *)&len) == -1)
		goto err;

	if (ss_addr.ss_family == AF_INET)
		return ntohs(((struct sockaddr_in *)&ss_addr)->sin_port);
	else
		return ntohs(((struct sockaddr_in6 *)&ss_addr)->sin6_port);

err:
	perror("sock_port");
	return -1;
}

static int _sock_peer_port(int sockfd)
{
	struct sockaddr_storage ss_addr;
	int len = sizeof(struct sockaddr_storage);

	if (getpeername(sockfd, (struct sockaddr *)&ss_addr,
			(void *)&len) == -1)
		goto err;

	if (ss_addr.ss_family == AF_INET)
		return ntohs(((struct sockaddr_in *)&ss_addr)->sin_port);
	else
		return ntohs(((struct sockaddr_in6 *)&ss_addr)->sin6_port);

err:
	return -1;
}

static int _sock_port(int sockfd)
{
	int port;

	port = _sock_peer_port(sockfd);
	if (port != -1)
		return port;
	else
		return sock_port(sockfd);
}

static void sock_print(int sockfd, char *level, const char *fmt, va_list ap)
{
	char str[INET6_ADDRSTRLEN];

	_sock_addr(sockfd, str);
	printf("%s: ", level);
	vprintf(fmt, ap);
	printf(" (%s:%d)\n", str, _sock_port(sockfd));
}

void sock_debug(int sockfd, const char *fmt, ...)
{
	va_list ap;

	if (!debug)
		return;

	va_start(ap, fmt);
	sock_print(sockfd, "debug", fmt, ap);
	va_end(ap);
}

void sock_info(int sockfd, const char *fmt, ...)
{
	va_list ap;

	if (!verbose)
		return;

	va_start(ap, fmt);
	sock_print(sockfd, "info", fmt, ap);
	va_end(ap);
}

void sock_warn(int sockfd, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sock_print(sockfd, "WARNING", fmt, ap);
	va_end(ap);
}
