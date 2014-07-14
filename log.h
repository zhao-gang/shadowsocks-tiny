/*
 * Copyright (c) 2014 Zhao, Gang <gang.zhao.42@gmail.com>
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 */

#ifndef SS_LOG_H
#define SS_LOG_H

#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>

#define pr_debug(fmt, args...) do {\
		syslog(LOG_DEBUG, fmt, ## args); } while (0)
#define pr_info(fmt, args...) do {\
		syslog(LOG_INFO, fmt, ## args); } while (0)
#define pr_notice(fmt, args...) do {\
		syslog(LOG_NOTICE, fmt, ## args); } while (0)
#define pr_warn(fmt, args...) do {\
		syslog(LOG_WARNING, fmt, ## args); } while (0)
#define pr_err(fmt, args...) do {\
		syslog(LOG_ERR, fmt, ## args); } while (0)
#define pr_exit(fmt, args...) do {\
		syslog(LOG_ERR, fmt, ## args); exit(EXIT_FAILURE); } while (0)
#define err_exit(msg) do {\
		syslog(LOG_ERR, "%s: %s", msg, strerror(errno));\
		exit(EXIT_FAILURE); } while (0)

void pr_ai_debug(struct addrinfo *info, const char *fmt, ...);
void pr_ai_info(struct addrinfo *info, const char *fmt, ...);
void pr_ai_notice(struct addrinfo *info, const char *fmt, ...);
void pr_ai_warn(struct addrinfo *info, const char *fmt, ...);
void sock_debug(int sockfd, const char *fmt, ...);
void sock_info(int sockfd, const char *fmt, ...);
void sock_notice(int sockfd, const char *fmt, ...);
void sock_warn(int sockfd, const char *fmt, ...);
void sock_err(int sockfd, const char *fmt, ...);

#endif
