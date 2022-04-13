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
#include <poll.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#ifdef DEBUG
#include <stdio.h>
#undef DEBUG
#define DEBUG(...)                                                             \
	fprintf(stderr, "[DEBUG] %s: ", __func__);                             \
	fprintf(stderr, __VA_ARGS__)
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

int strdiff(const char *s1, const char *s2);
int socket_parse_address(const char *address, struct init_data *data);

#endif
