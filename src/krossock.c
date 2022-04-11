#include "includes.h"
#include "krossock.h"
#include "krossock_ssl.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

typedef struct krossock_socket {
	int sock;
} *krossock_socket;

krossock_socket socket_init(int namespace, int style, int protocol)
{
	krossock_socket data;

	if ((data = malloc(sizeof(struct krossock_socket))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	memset(data, 0, sizeof(struct krossock_socket));

	/* create a socket */
	if ((data->sock = socket(namespace, style, protocol)) < 0) {
		free(data);
		return NULL;
	}

	return data;
}

void socket_destroy(krossock_socket data)
{
	/* delete socket stuff */
	free(data);
}

struct socket_data {
	char address[254] = { 0 };
	int namespace, style, protocol, family;
	uint16_t port;
	union {
		struct sockaddr addr;
		struct sockaddr_in in_addr;
		struct sockaddr_un un_addr;
	};
	socklen_t addr_len;
};

void print_regex_error(int err)
{
	switch (err) {
	case REG_BADBR:
		fputs("Content of \"\{\}\" invalid: not a number, number too large, more than two numbers, first larger than second.", stderr);
		break;
	case REG_BADPAT:
		fputs("Invalid regular expression.", stderr);
		break;
	case REG_BADRPT:
		fputs("'?', '*', or '+' not preceded by valid regular expression.", stderr);
		break;
	case REG_EBRACE:
		fputs("\"\\{\\}\" imbalance.", stderr);
		break;
	case REG_EBRACK:
		fputs("\"[]\" imbalance.", stderr);
		break;
	case REG_ECOLLATE:
		fputs("Invalid collating element referenced.", stderr);
		break;
	case REG_ECTYPE:
		fputs("Invalid character class type referenced.", stderr);
		break;
	case REG_EESCAPE:
		fputs("Trailing <backslash> character in pattern.", stderr);
		break;
	case REG_EPAREN:
		fputs("\"\\(\\)\" or \"()\" imbalance.", stderr);
		break;
	case REG_ERANGE:
		fputs("Invalid endpoint in range expression.", stderr);
		break;
	case REG_ESPACE:
		fputs("Out of memory.", stderr);
		break;
	case REG_ESUBREG:
		fputs("Number in \"\\digit\" invalid or in error.", stderr);
		break;
	case REG_NOMATCH:
		fputs("regexec() failed to match.", stderr);
		break;
	}
}

int krossock_parseaddr(const char* addr, struct socket_data *data)
{
	/* 
	 * NAMESPACE:
	 *  proto:
	 *   file -> PF_LOCAL (takes precedence)
	 *  host:
	 *   existing file -> PF_LOCAL ( only if proto is unix: or file: )
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
	
	// start down here:
	
	char *buffer;
	char *bufp;
	
	char *c;
	int i;

	struct {
		int port :1;
	} flags = { 0 };

	unsigned long port = 80; /* default is http */

	size_t host_len;

	if ((addr == NULL) || (data == NULL)) {
		errno = EINVAL;
		return -1;
	}

	if ((buffer = malloc(strlen(addr) + 1)) == NULL) {
		errno = ENOMEM;
		return -1;
	}

	strcpy(buffer, addr);
	bufp = buffer;

	if ((c = strstr(buffer, "://")) != NULL) {
		/* we expect to find a protocol here */
		*c = 0;

		if ((i = strcmp(bufp, "http")) == 's') {
			/* if proto is 'https', return 1 to promote connection to ssl */
			free(buffer);
			return 1;
		} else if (i == ':') {
			data->namespace = PF_INET;
			//port = 80; /* default */
			break;
		} else if ((strcmp(bufp, "unix") == ':') || (strcmp(bufp, "file") == ':')) {
			/* we're opening a file as a socket here so we're pretty much done */
			data->namespace = PF_LOCAL;
			flags.unix == 1;
		} else {
			/* protocol not supported */
			free(buffer);
			errno = ENOSYS;
			return -1;
		}

		bufp = c + 3;
	}

	// TODO: add support for unix: and file:
	if (data->namespace == PF_INET) {
		/* we're connecting to a server here so we need to figure out a lot of internet stuff */

		// TODO: determine namespace, style, protocol, family, port, and address from char *addr


		/* look for any forward slashes (marks the end of the address) */
		if ((c = strchr(bufp, '/')) != NULL)
			*c = 0;

		/* check for ipv6 */
		if (bufp[0] == '[') {
			/* this is probably an ipv6 with a port */
			data->namespace = PF_INET6;
			flags.port = 1;
			bufp++;
		}

		i = 0;
		c = bufp;
		while ((c = strchr(++c, ':')) != NULL)
			i++;

		if (i > 7) {
			/* bad syntax */
			free(buffer);
			errno = EINVAL;
			return -1;
		}

		if (i >= 2) {
			/* this looks like an ipv6 */
			data->namespace = PF_INET6;
		} else if (flags.ipv6) {
			/* if there's not at least two occurrences of ':' and we thought this was an ipv4 */
			free(buffer);
			errno = EINVAL;
			return -1;
		}

		if (i == 1)
			flags.port = 1; /* wouldn't be ipv6, but definitely has a port */

		if (flags.port) {
			if ((c = strrchr(bufp, ':')) != NULL) {
				if (data->namespace == PF_INET6)
					*(c-1) = 0; /* get rid of trailing ']' */
				*(c++) = 0;
				port = strtoul(c, NULL, 10);
			}
		}

		data->port = (uint16_t)port; /* this is the port */

		host_len = strlen(bufp);

		if (data->namespace == PF_INET6) {
			/* check span for ipv6 */
			if (strspn(bufp, "01234567890ABCDEFabcdef:") != hostlen) {
				/* bad syntax */
				free(buffer);
				errno = EINVAL;
				return -1;
			} else {
				/* in_addr6 (ipv6) */
				// TODO
			}
		} else {
			/* check span for ipv4 */
			if (strspn(bufp, "0123456789.") != hostlen) {
				/* hostent (hostname) */
				// TODO
			} else {
				/* in_addr (ipv4) */
				// TODO
			}
		}
	}

	// TODO
	switch(data->namespace) {
	case AF_LOCAL:
		data->addr_len = sizeof(struct sockaddr_un);
		break;
	case AF_INET:
		__attribute__((fallthrough));
	case AF_INET6:
		data->addr_len = sizeof(struct sockaddr_in);
		break;
	}

	errno = ENOSYS;
	return -1;
}

krossock_t krossock_connect(const char* addr)
{
	krossock_t ks;
	struct socket_data data;
	krossock_socket socket;
	int promote;

	/* initialize socket stuff */
	if ((promote = krossock_parseaddr(addr, &data)) < 0) {
		return NULL;
	}

	/* needs promotion? */
	if (promote) {
		return krossock_connect_ssl(addr);
	}

	/* create socket */
	if ((socket = socket_init(data->namespace, data->style, data->protocol)) == NULL)
		return NULL;

	/* do the connection part */
	if (connect(socket->sock, data->addr, data->addr_len) < 0) {
		socket_destroy((krossock_socket)socket);
		free(ks);
		return NULL;
	}

	/* initialize krossock */
	if ((ks = malloc(sizeof(struct krossock_t))) == NULL) {
		errno = ENOMEM;
		socket_destroy((krossock_socket)socket);
		return NULL;
	}

	ks->type = SOCKET;
	ks->data = (void *)socket;

	return ks;
}

void krossock_disconnect(krossock_t ks)
{
	krossock_socket socket;

	if (ks->type == SSL_SOCKET)
		return krossock_disconnect_ssl(ks);

	socket = ks->data;

	close(socket->sock);

	/* cleanup the socket stuff */
	socket_destroy((krossock_socket)socket);

	/* free mem */
	free(ks);
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
