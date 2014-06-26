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

#define DEFAULT_MAX_CONNECTION 1024
#define TCP_TEXT_BUF_SIZE 1024
#define TCP_CIPHER_BUF_SIZE TCP_TEXT_BUF_SIZE + EVP_MAX_BLOCK_LENGTH + \
	EVP_MAX_IV_LENGTH
#define UDP_TEXT_BUF_SIZE 65000
#define UDP_HEADER_SIZE UDP_TEXT_BUF_SIZE
#define UDP_CIPHER_BUF_SIZE UDP_TEXT_BUF_SIZE + EVP_MAX_BLOCK_LENGTH + \
	EVP_MAX_IV_LENGTH

enum link_state {
	LOCAL = 1 << 1,
	SERVER = 1 << 2,
	TEXT_PENDING = 1 << 3,
	CIPHER_PENDING = 1 << 4,
	SOCKS5_AUTH_REQUEST_RECEIVED = 1 << 5,
	SOCKS5_AUTH_REPLY_SENT = 1 << 6,
	SOCKS5_CMD_REQUEST_RECEIVED = 1 << 7,
	SOCKS5_CMD_REPLY_SENT = 1 << 8,
	SS_TCP_HEADER_SENT = 1 << 9,
	SS_TCP_HEADER_RECEIVED = 1 << 10,
	SS_UDP = 1 << 11,
};

#define	LINKED LOCAL | SERVER
#define PENDING TEXT_PENDING | CIPHER_PENDING

struct link {
	enum link_state state;
	int local_sockfd;
	int server_sockfd;
	int text_len;
	int cipher_len;
	int udp_header_len;
	const EVP_CIPHER *evp_cipher;
	EVP_CIPHER_CTX *ctx;
	struct addrinfo *server;
	unsigned char *text;
	unsigned char *cipher;
	unsigned char *udp_header;
	struct link *next;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char key[EVP_MAX_KEY_LENGTH];
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
	unsigned char ver;
	unsigned char nmethods;
	unsigned char methods[];
};

struct socks5_auth_reply {
	unsigned char ver;
	unsigned char method;
};

struct socks5_cmd_request {
	unsigned char ver;
	unsigned char cmd;
	unsigned char rsv;
	unsigned char atyp;
	unsigned char dst[];
};

struct socks5_cmd_reply {
	unsigned char ver;
	unsigned char rep;
	unsigned char rsv;
	unsigned char atyp;
	unsigned char bnd[];
};

struct socks5_udp_header {
	unsigned char rsv[2];
	unsigned char frag;
	unsigned char atyp;
	unsigned char dst[];
};

struct ss_header {
	unsigned char atyp;
	unsigned char dst[];
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
struct pollfd *poll_alloc(void);
void poll_init(void);
int poll_set(int sockfd, short events);
int poll_add(int sockfd, short events);
int poll_rm(int sockfd, short events);
int poll_del(int sockfd);
struct link *create_link(int sockfd, const char *type);
struct link *get_link(int sockfd);
void destroy_link(struct link *ln);
struct addrinfo *get_addr(struct link *ln);
int connect_server(struct link *ln);
int do_listen(struct addrinfo *info, const char *type);
int do_text_send(int sockfd, struct link *ln);
int do_cipher_send(int sockfd, struct link *ln);

#endif
