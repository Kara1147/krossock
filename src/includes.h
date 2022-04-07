#include <config.h>
#include <errno.h>

#ifndef INCLUDES_H
#define INCLUDES_H

struct krossock_t {
	enum type { SOCKET, SSL_SOCKET };
	void *data;
};

#endif
