#include "includes.h"
#include "krossock.h"
#include "krossock_ssl.h"

#include <sys/socket.h>
#include <regex.h>

typedef struct socket_stuff {
	int namespace;
	int style;
	int protocol;
	union {
		struct sockaddr_in in_name;
		struct sockaddr_un un_name;
	};
	int sock;
} *socket_stuff;

socket_stuff socket_init()
{
	socket_stuff data;

	if ((data = malloc(sizeof(struct socket_stuff))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	memset(data, 0, sizeof(struct socket_stuff));

	/* create a socket */
	if ((data->sock = socket(data->namespace, data->style, data->protocol)) < 0) {
		free(data);
		return NULL;
	}

	return data;
}

void socket_destroy(socket_stuff data)
{
	/* delete socket stuff */
	free(data);
}

int krossock_parseaddr(const char* addr, socket_stuff data)
{
	/* TODO: determine namespace, style, protocol, family, port, and address from char *addr */

	/* 
	 * NAMESPACE:
	 *  proto:
	 *   file -> PF_LOCAL (takes precedence)
	 *  host:
	 *   existing file -> PF_LOCAL
	 *   dnsname -> PF_INET
	 *   ipv4 -> PF_INET
	 *   ipv6 -> PF_INET6
	 * 
	 * STYLE: (just use SOCK_STREAM for now)
	 * 
	 * PROTOCOL: (just use 0 for now)
	 * 
	 * FAMILY:
	 *  namespace:
	 *   PF_LOCAL -> AF_LOCAL
	 *   PF_INET -> AF_INET
	 *   PF_INET6 -> AF_INET6
	 *
	 * PORT:
	 *  port: whatever port is if it exists, otherwise default to the proper port for the proto
	 *  proto:
	 *   http -> 80
	 *   https -> 443
	 *   ftp(s) -> 21
	 *   telnet -> 23
	 *   ssh -> 22
	 *   smtp -> 25
	 *   file -> unset
	 *
	 * ADDERSS: host
	 */

	// regex here:

	// if proto is 'https', return 1 here to promote connection

	// start down here:

	errno = ENOSYS;
	return -1;
}

krossock_t krossock_connect(const char* addr)
{
	krossock_t ks;
	socket_stuff data;
	int promote;

	/* initialize socket stuff */
	if ((data = socket_init()) == NULL)
		return NULL;

	if ((promote = krossock_parseaddr(addr, data)) < 0) {
		socket_destroy(data);
		return NULL;
	}

	/* needs promotion? */
	if (promote) {
		socket_destroy(data);
		return krossock_connect_ssl(addr);
	}

	/* initialize krossock */
	if ((ks = malloc(sizeof(struct krossock_t))) == NULL) {
		errno = ENOMEM;
		socket_destroy(data);
		return NULL;
	}

	ks->type = SOCKET;
	ks->data = data;

	/* do the connection part */
	if (krossock_redial(ks) < 0) {
		socket_destroy(data);
		free(ks);
		return NULL;
	}

	return ks;
}

void krossock_disconnect(krossock_t ks)
{
	if (ks->type == SSL_SOCKET)
		return krossock_disconnect_ssl(ks);

	/* close any connections */
	krossock_hangup(ks);

	/* cleanup the socket stuff */
	socket_destroy(ks->data);

	/* free mem */
	free(ks);
}

int krossock_redial(krossock_t ks)
{
	if (ks->type == SSL_SOCKET)
		return krossock_redial_ssl(ks);
	errno = ENOSYS;
	return -1;
}

int krossock_hangup(krossock_t ks)
{
	if (ks->type == SSL_SOCKET)
		return krossock_hangup_ssl(ks);
	errno = ENOSYS;
	return -1;
}

int krossock_send(krossock_t ks)
{
	if (ks->type == SSL_SOCKET)
		return krossock_send_ssl(ks);
	errno = ENOSYS;
	return -1;
}

int krossock_recv(krossock_t ks)
{
	if (ks->type == SSL_SOCKET)
		return krossock_recv_ssl(ks);
	errno = ENOSYS;
	return -1;
}
