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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include <krossock.h>
//#include <includes.h>

int main()
{
	char msg[] =
		"GET / HTTP/1.1\r\nHost: icanhazip.com\r\nConnection: close\r\n\r\n";
	char buffer[1048576] = { 0 };
	krossock_t ks = NULL;
	int ret = 0;

	ks = krossock_connect("https://icanhazip.com");

	if (ks == NULL) {
		fputs("connection FAILED!\n", stderr);
		fputs(strerror(errno), stderr);
		fputs("\n", stderr);
		return errno;
	}

	fputs("connected!\n", stderr);

	if (krossock_write(ks, msg, sizeof(msg)) < 0) {
		fputs("write FAILED!\n", stderr);
		goto die;
	}

	if (krossock_read(ks, buffer, sizeof(buffer)) < 0) {
		fputs("read FAILED!\n", stderr);
		goto die;
	}

	puts("read:");
	puts(buffer);

	krossock_disconnect(ks);
	return 0;
die:
	ret = errno;
	krossock_disconnect(ks);
	fputs(strerror(ret), stderr);
	fputs("\n", stderr);
	return ret;
}
