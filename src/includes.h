#ifndef INCLUDES_H
#define INCLUDES_H

#include <config.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
//#include <ctype.h>
//#include <termios.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#ifdef DEBUG
#include <stdio.h>
#undef DEBUG
#define DEBUG(...) fprintf(stderr, "[DEBUG] %s: ", __func__); fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG(...) /* debug statement removed */
#endif

struct init_data {
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr_un un;
	} sockaddr;
	size_t sockaddr_len;

	int domain;
	int style;
	int protocol;

	int ssl;
};

int strdiff (const char *s1, const char *s2);
int socket_parse_address(const char *address, struct init_data *data);

#endif
