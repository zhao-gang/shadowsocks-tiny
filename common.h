#ifndef SS_COMMON_H
#define SS_COMMON_H

#include <poll.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "log.h"

#define SA struct sockaddr
#define SA_IN struct sockaddr_in
#define SA_IN6 struct sockaddr_in6
#define SS struct sockaddr_storage

#define TCP_INACTIVE_TIMEOUT 120
#define TCP_CONNECT_TIMEOUT 15
#define MAX_CONNECTION 1024
#define TEXT_BUF_SIZE (1024 * 8)
#define CIPHER_BUF_SIZE (TEXT_BUF_SIZE + EVP_MAX_BLOCK_LENGTH + \
			 EVP_MAX_IV_LENGTH)
#define MAX_DOMAIN_LEN 255
#define MAX_PORT_STRING_LEN 5
#define MAX_PWD_LEN 16
#define MAX_METHOD_NAME_LEN 16

struct ss_option {
	char server_address[MAX_DOMAIN_LEN + 1];
	char local_address[MAX_DOMAIN_LEN + 1];
	char server_port[MAX_PORT_STRING_LEN + 1];
	char local_port[MAX_PORT_STRING_LEN + 1];
	char password[MAX_PWD_LEN + 1];
	char method[MAX_METHOD_NAME_LEN + 1];
	bool daemon;
};

#define BITS(x) (1 << (x))

enum link_state {
	LOCAL = BITS(1),
	SERVER = BITS(2),
	LOCAL_READ_PENDING = BITS(3),
	LOCAL_SEND_PENDING = BITS(4),
	SERVER_READ_PENDING = BITS(5),
	SERVER_SEND_PENDING = BITS(6),
	SOCKS5_AUTH_REQUEST_RECEIVED = BITS(7),
	SOCKS5_AUTH_REPLY_SENT = BITS(8),
	SOCKS5_CMD_REQUEST_RECEIVED = BITS(9),
	SOCKS5_CMD_REPLY_SENT = BITS(10),
	SS_TCP_HEADER_SENT = BITS(11),
	SS_TCP_HEADER_RECEIVED = BITS(12),
	SS_IV_SENT = BITS(13),
	SS_IV_RECEIVED = BITS(14),
	SS_UDP = BITS(15),
};

#define	LINKED (LOCAL | SERVER)
#define LOCAL_PENDING (LOCAL_READ_PENDING | LOCAL_SEND_PENDING)
#define SERVER_PENDING (SERVER_READ_PENDING | SERVER_SEND_PENDING)

struct link {
	enum link_state state;
	time_t time;
	int local_sockfd;
	int server_sockfd;
	int text_len;
	int cipher_len;
	int ss_header_len;
	EVP_CIPHER_CTX *local_ctx;
	EVP_CIPHER_CTX *server_ctx;
	struct addrinfo *server;
	void *text;
	void *cipher;
	char local_iv[EVP_MAX_IV_LENGTH];
	char server_iv[EVP_MAX_IV_LENGTH];
	struct link *next;
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
extern struct link *link_head[MAX_CONNECTION];

void pr_data(FILE *fp, const char *name, char *data, int len);
void pr_link_debug(struct link *ln);
void pr_link_info(struct link *ln);
void pr_link_warn(struct link *ln);
void poll_init(void);
int poll_set(int sockfd, short events);
int poll_add(int sockfd, short events);
int poll_rm(int sockfd, short events);
int poll_del(int sockfd);
int get_events(int sockfd);
void reaper(void);
struct link *create_link(int sockfd, const char *type);
struct link *get_link(int sockfd);
void destroy_link(int sockfd);
int do_listen(struct addrinfo *info, const char *type);
int connect_server(int sockfd);
int add_data(int sockfd, struct link *ln,
	     const char *type, char *data, int size);
int rm_data(int sockfd, struct link *ln, const char *type, int size);
int check_ss_header(int sockfd, struct link *ln);
int check_socks5_auth_header(int sockfd, struct link *ln);
int check_socks5_cmd_header(int sockfd, struct link *ln);
int create_socks5_auth_reply(int sockfd, struct link *ln, bool ok);
int create_socks5_cmd_reply(int sockfd, struct link *ln, int cmd);
int do_read(int sockfd, struct link *ln, const char *type, int offset);
int do_send(int sockfd, struct link *ln, const char *type, int offset);

#endif
