/*
 * Copyright (c) 2014 Zhao, Gang <gang.zhao.42@gmail.com>
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 */

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "log.h"

static int _pr_addrinfo(int level, struct addrinfo *info,
			const char *fmt, va_list ap)
{
	unsigned short port;
	int offset;
	char log[1024];
	char addr[INET6_ADDRSTRLEN];
	struct addrinfo *ai = info;
	void *addrptr;

	vsprintf(log, fmt, ap);
	strcat(log, ":");
	offset = strlen(log);

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
			sprintf(log + offset, " %s:%d(tcp)", addr, port);
		else if (ai->ai_socktype == SOCK_DGRAM)
			sprintf(log + offset, " %s:%d(udp)", addr, port);
		ai = ai->ai_next;
	}

	strcat(log, "\n");
	syslog(level, "%s", log);

	return 0;
}

void pr_ai_debug(struct addrinfo *info, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);

	ret = _pr_addrinfo(LOG_DEBUG, info, fmt, ap);
	if (ret != 0)
		pr_warn("%s: %s\n", __func__, strerror(ret));

	va_end(ap);
}

void pr_ai_info(struct addrinfo *info, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);

	ret = _pr_addrinfo(LOG_INFO, info, fmt, ap);
	if (ret != 0)
		pr_warn("%s: %s\n", __func__, strerror(ret));

	va_end(ap);
}

void pr_ai_notice(struct addrinfo *info, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);

	ret = _pr_addrinfo(LOG_NOTICE, info, fmt, ap);
	if (ret != 0)
		pr_warn("%s: %s\n", __func__, strerror(ret));

	va_end(ap);
}

static int get_sock_addr(int sockfd, char *str, int *port, const char *type)
{
	void *addrptr;
	struct sockaddr_storage ss_addr;
	int len = sizeof(struct sockaddr_storage);

	if (strcmp(type, "peer") == 0) {
		if (getpeername(sockfd, (struct sockaddr *)&ss_addr,
				(void *)&len) == -1)
			goto err;
	} else if (strcmp(type, "sock") == 0) {
		if (getsockname(sockfd, (struct sockaddr *)&ss_addr,
				(void *)&len) == -1)
			goto err;
	}

	if (ss_addr.ss_family == AF_INET) {
		addrptr = &((struct sockaddr_in *)&ss_addr)->sin_addr;
		*port = ntohs(((struct sockaddr_in *)&ss_addr)->sin_port);
	} else if (ss_addr.ss_family == AF_INET6) {
		addrptr = &((struct sockaddr_in6 *)&ss_addr)->sin6_addr;
		*port = ntohs(((struct sockaddr_in6 *)&ss_addr)->sin6_port);
	}

	if (inet_ntop(ss_addr.ss_family, addrptr, str,
		      INET6_ADDRSTRLEN) == NULL)
		goto err;

	return 0;

err:
	return -1;
}

static void sock_print(int sockfd, int level, const char *fmt, va_list ap)
{
	int offset, port;
	char *type;
	char str[INET6_ADDRSTRLEN] = {'\0'};
	char log[1024];

	if (get_sock_addr(sockfd, str, &port, "peer") == 0)
		type = "peer";
	else if (get_sock_addr(sockfd, str, &port, "sock") == 0)
		type = "sock";
	else
		type = "sockfd";
		
	vsprintf(log, fmt, ap);
	offset = strlen(log);

	if (strcmp(type, "peer") == 0)
		sprintf(log + offset, "  (peer)%s:%d\n", str, port);
	else if (strcmp(type, "sock") == 0)
		sprintf(log + offset, "  %s:%d\n", str, port);
	else if (strcmp(type, "sockfd") == 0)
		sprintf(log + offset, "  (sockfd)%d\n", sockfd);

	syslog(level, "%s", log);
}

void sock_debug(int sockfd, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sock_print(sockfd, LOG_DEBUG, fmt, ap);
	va_end(ap);
}

void sock_info(int sockfd, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sock_print(sockfd, LOG_INFO, fmt, ap);
	va_end(ap);
}

void sock_notice(int sockfd, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sock_print(sockfd, LOG_NOTICE, fmt, ap);
	va_end(ap);
}

void sock_warn(int sockfd, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sock_print(sockfd, LOG_WARNING, fmt, ap);
	va_end(ap);
}

void sock_err(int sockfd, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sock_print(sockfd, LOG_ERR, fmt, ap);
	va_end(ap);
}
