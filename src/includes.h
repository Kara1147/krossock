#include <config.h>
#include <errno.h>

#ifndef INCLUDES_H
#define INCLUDES_H

#ifdef DEBUG
#include <stdio.h>
#undef DEBUG
#define DEBUG(...) printf("[DEBUG] "__VA_ARGS__)
#else
#define DEBUG(...) /* debug statement removed */
#endif

struct krossock_t {
	enum { SOCKET, SSL_SOCKET } type;
	void *data;
};

#endif
