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
#define PLAIN_BUF_SIZE 1024
#define CIPHER_BUF_SIZE PLAIN_BUF_SIZE + EVP_MAX_BLOCK_LENGTH + EVP_MAX_IV_LENGTH

enum link_state {
	LINK_DISCONNECTED = 1 << 0,
	LINK_LOCAL = 1 << 1,
	LINK_SERVER = 1 << 2,
	LINK_IV_EXCHANGED = 1 << 3,
	LINK_PLAIN_PENDING = 1 << 4,
	LINK_CIPHER_PENDING = 1 << 5,
};

#define	LINK_LINKED LINK_LOCAL | LINK_SERVER

struct link {
	enum link_state state;
	int local_sockfd;
	int server_sockfd;
	int text_len;
	int cipher_len;
	const EVP_CIPHER *evp_cipher;
	EVP_CIPHER_CTX *ctx;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned char text[PLAIN_BUF_SIZE];
	unsigned char cipher[CIPHER_BUF_SIZE];
	struct link *next;
};

extern struct pollfd *clients;
extern int nfds;
extern struct link *link_head;

struct socks5_auth_request {
	unsigned char ver;
	unsigned char nmethods;
	unsigned char methods[];
};

struct socks5_auth_reply {
	unsigned char ver;
	unsigned char method;
};

struct socks5_request {
	unsigned char ver;
	unsigned char cmd;
	unsigned char rsv;
	unsigned char atyp;
	unsigned char dst[];
};

struct socks5_reply {
	unsigned char ver;
	unsigned char rep;
	unsigned char rsv;
	unsigned char atyp;
	unsigned char bnd[];
};

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
struct link *create_link(int sockfd);
struct link *get_link(int sockfd);
int unlink_link(struct link *ln);
void destroy_link(struct link *ln);
struct addrinfo *get_addr(struct link *ln);
int connect_server(struct link *ln, struct addrinfo *info);
int do_listen(struct addrinfo *info);
int do_plain_send(int sockfd, struct link *ln);
int do_cipher_send(int sockfd, struct link *ln);

#endif
