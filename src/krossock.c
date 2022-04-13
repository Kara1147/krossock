#include "includes.h"
#include "krossock.h"
#include "krossock_ssl.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

typedef struct krossock_socket {
	int sock;
} *krossock_socket;

struct socket_data {
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr_un un;
	} sockaddr;
	size_t sockaddr_len;

	int domain;
	int style;
	int protocol;
};

krossock_socket socket_init(struct socket_data *data)
{
	krossock_socket ksocket;

	if (data == NULL) {
		DEBUG("socket_init: data was NULL\n");
		errno = EINVAL;
		return NULL;
	}

	if ((ksocket = malloc(sizeof(struct krossock_socket))) == NULL) {
		DEBUG("socket_init: malloc() failed for ksocket\n");
		errno = ENOMEM;
		return NULL;
	}
	
	DEBUG("socket_init: krossock_socket (%lx) allocated\n", (unsigned long int)(ksocket));

	memset(ksocket, 0, sizeof(struct krossock_socket));

	/* create a socket */
	if ((ksocket->sock = socket(data->domain, data->style, data->protocol)) < 0) {
		DEBUG("socket_init: socket() failed\n");
		free(ksocket);
		return NULL;
	}

	DEBUG("socket_init: socket (%d) created\n", ksocket->sock);

	return ksocket;
}

void socket_destroy(krossock_socket ksocket)
{
	if (ksocket == NULL) {
		DEBUG("socket_destroy: ksocket was NULL");
		errno = EINVAL;
		return;
	}

	/* delete socket stuff */
	free(ksocket);
	DEBUG("socket_destroy: krossock_socket (%lx) free'd\n", (unsigned long int)(ksocket));
}

int socket_parse_address(const char *address, struct socket_data *data)
{
	char *buffer;
	char *bufp;
	
	char *c;
	int i;

	struct hostent *he;

	union {
		struct in_addr in;
		struct in6_addr in6;
	} addr;

	unsigned short int port;

	if ((address == NULL) || (data == NULL)) {
		DEBUG("socket_parse_address: address or data was NULL\n");
		errno = EINVAL;
		return -1;
	}

	if ((buffer = malloc(strlen(address) + 1)) == NULL) {
		DEBUG("socket_parse_address: malloc() failed for buffer\n");
		errno = ENOMEM;
		return -1;
	}

	strcpy(buffer, address);
	bufp = buffer;

	/* 
	 * NAMESPACE:
	 *  proto:
	 *   http   -> PF_INET
	 *   file   -> PF_LOCAL
	 *   unix   -> PF_LOCAL
	 *   ftp    -> PF_INET
	 *   telnet -> PF_INET
	 *   ssh    -> PF_INET
	 *   smtp   -> PF_INET
	 */
	if ((c = strstr(buffer, "://")) != NULL) {
		/* we expect to find a protocol here */
		*c = 0;

		/*
		 * PORT:
		 *  proto:
		 *   http   -> 80
		 *   ftp    -> 21
		 *   telnet -> 23
		 *   ssh    -> 22
		 *   smtp   -> 25
		 *   file   -> don't care
		 */
		if ((i = strcmp(bufp, "http")) == 's') {
			/* if proto is 'https', return 1 to promote connection to ssl */
			free(buffer);
			return 1;
		} else if (i == 0) {
			data->domain = AF_INET;
			port = htons((unsigned short int)80); /* default */
		} else if ((strcmp(bufp, "unix") == 0) || (strcmp(bufp, "file") == 0)) {
			/* we're opening a file as a socket here so we're pretty much done */
			data->domain = AF_LOCAL;
			port = -1;
		} else {
			/* protocol not supported */
			DEBUG("socket_parse_address: unsupported protocol '%s': result is '%c'(%d)\n", bufp, (char)i, i);
			errno = EINVAL;
			goto die;
		}

		bufp = c + 3;
	}
	/*
	 * STYLE: (just use SOCK_STREAM for now)
	 */
	data->style = SOCK_STREAM;

	/*	
	 * PROTOCOL: (just use TCP for now)
	 */
	data->protocol = IPPROTO_TCP;

	/*
	 * ADDRESS:
	 *  namespace:
	 *   AF_LOCAL -> filesystem (precedence)
	 *   AF_INET  -> ipv4, ipv6, or hostname
	 */
	if (data->domain == AF_INET) {
		DEBUG("socket_parse_address: domain is AF_INET (internet)\n");
		/* we're connecting to a server here so we need to figure out a lot of internet stuff */

		/* look for any forward slashes (marks the end of the address) */
		if ((c = strchr(bufp, '/')) != NULL)
			*c = 0;

		/*
		 * PORT: (update)
		 *  override default port with specified port
		 */
		if ((c = strrchr(bufp, ':')) != NULL) {
			*(c++) = 0;
			port = htons((unsigned short int)strtoul(c, NULL, 10));
		}
	
		/* attempt to find hostent for what we have */
		if ((he = gethostbyname(bufp)) == NULL) {
			DEBUG("socket_parse_address: gethostbyname() lookup failed for hostname '%s'\n", bufp);
			errno = EINVAL;
			goto die;
		}

		DEBUG("socket_parse_address: hostname is '%s'\n", he->h_name);
		DEBUG("krossock_connect: port is '%hu'\n", ntohs(port));

		/* 
		 * NAMESPACE: (update)
		 *  family:
		 *   AF_INET  -> AF_INET
		 *   AF_INET6 -> AF_INET6
		 */
		/*
		 * FAMILY:
		 *  addrtype from hostent
		 */
		if (he->h_addrtype == AF_INET6) {
			DEBUG("socket_parse_address: addrtype is AF_INET6 (ipv4)\n");
			data->domain = AF_INET6;
			data->sockaddr.in6.sin6_family = AF_INET6;
			data->sockaddr.in6.sin6_addr = *(struct in6_addr *)(he->h_addr);
			data->sockaddr.in6.sin6_flowinfo = 0;
			data->sockaddr.in6.sin6_port = port;
			data->sockaddr_len = sizeof(struct sockaddr_in6);
		} else {
			DEBUG("socket_parse_address: addrtype is AF_INET (ipv4)\n");
			data->sockaddr.in.sin_family = AF_INET;
			data->sockaddr.in.sin_addr = *(struct in_addr *)(he->h_addr);
			data->sockaddr.in.sin_port = port;
			data->sockaddr_len = sizeof(struct sockaddr_in);
		}

	} else if (data->domain == AF_LOCAL) {
		DEBUG("socket_parse_address: domain is AF_LOCAL (socket)\n");
		/*
		 * FAMILY: AF_LOCAL
		 */
		data->sockaddr.un.sun_family = AF_LOCAL;
		strncpy(data->sockaddr.un.sun_path, bufp, sizeof(data->sockaddr.un.sun_path));

		data->sockaddr_len = SUN_LEN(&(data->sockaddr.un));
	} else {
		DEBUG("socket_parse_address: unknown domain\n");
		errno = EINVAL;
		goto die;
	}

	free(buffer);
	return 0;
die:
	free(buffer);
	return -1;
}

krossock_t krossock_connect(const char* address)
{
	krossock_t ks;
	krossock_socket ksocket;
	struct socket_data data;
	int promote;

	if (address == NULL) {
		DEBUG("krossock_connect: address was NULL\n");
		errno = EINVAL;
		return NULL;
	}

	if ((promote = socket_parse_address(address, &data)) < 0) {
		DEBUG("krossock_connect: socket_parse_address() failed for address '%s'\n", address);
		return NULL;
	}

	if (promote) {
		DEBUG("krossock_connect: going ssl\n");
		return krossock_connect_ssl(address);
	}

	/* create socket */
	if ((ksocket = socket_init(&data)) == NULL) {
		DEBUG("krossock_connect: socket_init() failed for ksocket\n");
		return NULL;
	}

	/* connect */
	if (connect(ksocket->sock, (struct sockaddr *) &(data.sockaddr), data.sockaddr_len) < 0) {
		DEBUG("krossock_connect: connect() failed for ksocket\n");
		socket_destroy(ksocket);
		return NULL;
	}

	DEBUG("krossock_connect: socket (%d) connected\n", ksocket->sock);

	/* initialize krossock */
	if ((ks = malloc(sizeof(struct krossock_t))) == NULL) {
		DEBUG("krossock_connect: malloc() failed for ks\n");
		errno = ENOMEM;
		socket_destroy(ksocket);
		return NULL;
	}

	ks->type = SOCKET;
	ks->data = (void *)ksocket;

	DEBUG("krossock_connect: krossock (%lx) allocated and initialized\n", (unsigned long int)(ks));

	return ks;
}

void krossock_disconnect(krossock_t ks)
{
	krossock_socket ksocket;

	if (ks == NULL) {
		DEBUG("krossock_disconnect: ks was NULL\n");
		errno = EINVAL;
		return;
	}

	if (ks->type == SSL_SOCKET) {
		DEBUG("krossock_disconnect: going ssl\n");
		return krossock_disconnect_ssl(ks);
	}

	ksocket = (krossock_socket)ks->data;

	close(ksocket->sock);
	DEBUG("krossock_disconnect: socket (%d) disconnected\n", ksocket->sock);

	/* cleanup the socket stuff */
	socket_destroy(ksocket);

	/* free mem */
	free(ks);
	DEBUG("krossock_disconnect: krossock (%lx) free'd\n", (unsigned long int)(ks));
}

int krossock_send(krossock_t ks)
{
	if (ks == NULL) {
		DEBUG("krossock_send: ks was NULL\n");
		errno = EINVAL;
		return -1;
	}

	if (ks->type == SSL_SOCKET) {
		DEBUG("krossock_send: going ssl\n");
		return krossock_send_ssl(ks);
	}
	
	DEBUG("krossock_send: not implemented\n");
	errno = ENOSYS;
	return -1;
}

int krossock_recv(krossock_t ks)
{
	if (ks == NULL) {
		DEBUG("krossock_recv: ks was NULL\n");
		errno = EINVAL;
		return -1;
	}

	if (ks->type == SSL_SOCKET) {
		DEBUG("krossock_recv: going ssl\n");
		return krossock_recv_ssl(ks);
	}

	DEBUG("krossock_recv: not implemented\n");
	errno = ENOSYS;
	return -1;
}
