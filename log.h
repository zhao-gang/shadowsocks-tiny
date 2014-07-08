#ifndef SS_LOG_H
#define SS_LOG_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

extern bool debug;
extern bool verbose;

#define pr_exit(fmt, args...) do \
	{ printf(fmt, ## args); exit(EXIT_FAILURE); } while (0)
#define err_exit(msg) do { perror(msg); exit(EXIT_FAILURE); } while (0)
#define pr_warn(fmt, args...) printf("WARNING: " fmt, ## args)

void pr_debug(const char *fmt, ...);
int _pr_addrinfo(const char *level, struct addrinfo *info,
		 const char *fmt, va_list ap);
void pr_info(const char *fmt, ...);
void pr_ai_debug(struct addrinfo *info, const char *fmt, ...);
void pr_ai_info(struct addrinfo *info, const char *fmt, ...);
void pr_ai_warn(struct addrinfo *info, const char *fmt, ...);
void sock_debug(int sockfd, const char *fmt, ...);
void sock_info(int sockfd, const char *fmt, ...);
void sock_warn(int sockfd, const char *fmt, ...);

#endif
