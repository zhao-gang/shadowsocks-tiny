#ifndef SS_COMMON_H
#define SS_COMMON_H

#include <poll.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "log.h"

#define SA struct sockaddr
#define SA_IN struct sockaddr_in
#define SA_IN6 struct sockaddr_in6
#define SS struct sockaddr_storage

#define MAX_CONNECTION 64
#define TEXT_BUF_SIZE 65536
#define CIPHER_BUF_SIZE (TEXT_BUF_SIZE + EVP_MAX_BLOCK_LENGTH + \
			     EVP_MAX_IV_LENGTH)

enum link_state {
	LOCAL = 1 << 1,
	SERVER = 1 << 2,
	WAITING = 1 << 3,
	TEXT_PENDING = 1 << 4,
	CIPHER_PENDING = 1 << 5,
	SOCKS5_AUTH_REQUEST_RECEIVED = 1 << 6,
	SOCKS5_AUTH_REPLY_SENT = 1 << 7,
	SOCKS5_CMD_REQUEST_RECEIVED = 1 << 8,
	SOCKS5_CMD_REPLY_SENT = 1 << 9,
	SS_TCP_HEADER_SENT = 1 << 10,
	SS_TCP_HEADER_RECEIVED = 1 << 11,
	SS_UDP = 1 << 12,
};

#define	LINKED (LOCAL | SERVER)
#define PENDING (TEXT_PENDING | CIPHER_PENDING)

struct link {
	enum link_state state;
	int local_sockfd;
	int server_sockfd;
	int text_len;
	int cipher_len;
	int ss_header_len;
	const EVP_CIPHER *evp_cipher;
	EVP_CIPHER_CTX *ctx;
	struct addrinfo *server;
	char *text;
	char *cipher;
	char *ss_header;
	struct link *next;
	char iv[EVP_MAX_IV_LENGTH];
	char key[EVP_MAX_KEY_LENGTH];
};

#define SOCKS5_METHOD_NOT_REQUIRED 0x00
#define SOCKS5_METHOD_ERROR 0XFF

#define SOCKS5_CONNECT 0x01
#define SOCKS5_UDP_ASSOCIATE 0x03

#define SOCKS5_ADDR_IPV4 0X01
#define SOCKS5_ADDR_DOMAIN 0X03
#define SOCKS5_ADDR_IPV6 0X04

#define SOCKS5_CMD_REP_SUCCEEDED 0x00
#define SOCKS5_CMD_REP_FAILED 0x11

struct socks5_auth_request {
	char ver;
	char nmethods;
	char methods[];
};

struct socks5_auth_reply {
	char ver;
	char method;
};

struct socks5_cmd_request {
	char ver;
	char cmd;
	char rsv;
	char atyp;
	char dst[];
};

struct socks5_cmd_reply {
	char ver;
	char rep;
	char rsv;
	char atyp;
	char bnd[];
};

struct socks5_udp_header {
	char rsv[2];
	char frag;
	char atyp;
	char dst[];
};

struct ss_header {
	 char atyp;
	 char dst[];
};

extern struct pollfd *clients;
extern int nfds;
extern struct link *link_head;

void pr_link_debug(struct link *ln);
void pr_link_info(struct link *ln);
void pr_link_warn(struct link *ln);
void pr_iv(struct link *ln);
void pr_key(struct link *ln);
void pr_text(struct link *ln);
void pr_cipher(struct link *ln);
void poll_init(void);
int poll_set(int sockfd, short events);
int poll_add(int sockfd, short events);
int poll_rm(int sockfd, short events);
int poll_del(int sockfd);
struct link *create_link(int sockfd);
struct link *get_link(int sockfd);
void destroy_link(struct link *ln);
struct addrinfo *get_addr(struct link *ln);
int do_listen(struct addrinfo *info, const char *type);
int connect_server(struct link *ln);
int add_data(int sockfd, struct link *ln,
	     const char *type, char *data, int size);
int rm_data(int sockfd, struct link *ln, const char *type, int size);
int check_ss_header(int sockfd, struct link *ln);
int check_socks5_auth_header(int sockfd, struct link *ln);
int check_socks5_cmd_header(int sockfd, struct link *ln);
int add_ss_header(int sockfd, struct link *ln);
int create_socks5_auth_reply(int sockfd, struct link *ln, bool ok);
int create_socks5_cmd_reply(int sockfd, struct link *ln, int cmd);
int do_text_read(int sockfd, struct link *ln);
int do_cipher_read(int sockfd, struct link *ln);
int do_text_send(int sockfd, struct link *ln);
int do_cipher_send(int sockfd, struct link *ln);

#endif
