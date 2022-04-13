/*
 * MIT License
 * 
 * Copyright (c) 2022 Kara
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "includes.h"

int strdiff(const char *s1, const char *s2)
{
	int diff;

	do {
		diff = ((unsigned short int)(*s1) - (unsigned short int)(*s2));
	} while (!diff && *(s1++) && *(s2++));

	return diff;
}

int socket_parse_address(const char *address, struct init_data *data)
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
		DEBUG("address or data was NULL\n");
		errno = EINVAL;
		return -1;
	}

	memset((void *)data, 0, sizeof(struct init_data));

	if ((buffer = malloc(strlen(address) + 1)) == NULL) {
		DEBUG("malloc() failed for buffer\n");
		errno = ENOMEM;
		return -1;
	}

	strcpy(buffer, address);
	bufp = buffer;

	/* 
	 * NAMESPACE:
	 *  proto:
	 *   http(s)-> PF_INET
	 *   file   -> PF_LOCAL
	 *   unix   -> PF_LOCAL
	 *   ftp    -> PF_INET
	 *   telnet -> PF_INET
	 *   ssh    -> PF_INET
	 *   smtp   -> PF_INET
	 */

	data->domain = AF_INET; /* default */
	port = htons((unsigned short int)80); /* default */

	if ((c = strstr(buffer, "://")) != NULL) {
		/* we expect to find a protocol here */
		*c = 0;

		/*
		 * PORT:
		 *  proto:
		 *   http   -> 80
		 *   https  -> 443
		 *   ftp    -> 21
		 *   telnet -> 23
		 *   ssh    -> 22
		 *   smtp   -> 25
		 *   file   -> don't care
		 */
		if ((i = strdiff(bufp, "http")) == 's') {
			data->ssl = 1;
			port = htons((unsigned short int)443);
		} else if (i == 0) {
			/* http trap, everything's already set up */
		} else if ((strdiff(bufp, "unix") == 0) ||
			   (strdiff(bufp, "file") == 0)) {
			/* we're opening a file as a socket here so we're pretty much done */
			data->domain = AF_LOCAL;
			port = -1;
		} else {
			/* protocol not supported */
			DEBUG("unsupported protocol '%s': result is '%c'(%d)\n",
			      bufp, (char)i, i);
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
		DEBUG("domain is AF_INET (internet)\n");
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
			DEBUG("gethostbyname() lookup failed for hostname '%s'\n",
			      bufp);
			errno = EINVAL;
			goto die;
		}

		DEBUG("hostname is '%s'\n", he->h_name);
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
			DEBUG("addrtype is AF_INET6 (ipv4)\n");
			data->domain = AF_INET6;
			data->sockaddr.in6.sin6_family = AF_INET6;
			data->sockaddr.in6.sin6_addr =
				*(struct in6_addr *)(he->h_addr);
			data->sockaddr.in6.sin6_flowinfo = 0;
			data->sockaddr.in6.sin6_port = port;
			data->sockaddr_len = sizeof(struct sockaddr_in6);
		} else {
			DEBUG("addrtype is AF_INET (ipv4)\n");
			data->sockaddr.in.sin_family = AF_INET;
			data->sockaddr.in.sin_addr =
				*(struct in_addr *)(he->h_addr);
			data->sockaddr.in.sin_port = port;
			data->sockaddr_len = sizeof(struct sockaddr_in);
		}

	} else if (data->domain == AF_LOCAL) {
		DEBUG("domain is AF_LOCAL (socket)\n");
		/*
		 * FAMILY: AF_LOCAL
		 */
		data->sockaddr.un.sun_family = AF_LOCAL;
		strncpy(data->sockaddr.un.sun_path, bufp,
			sizeof(data->sockaddr.un.sun_path));

		data->sockaddr_len = SUN_LEN(&(data->sockaddr.un));
	} else {
		DEBUG("unknown domain\n");
		errno = EINVAL;
		goto die;
	}

	free(buffer);
	return 0;
die:
	free(buffer);
	return -1;
}
