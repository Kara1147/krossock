#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include <krossock.h>
//#include <includes.h>

int main()
{
	char msg[] = "GET / HTTP/1.1\r\nHost: icanhazip.com\r\nConnection: close\r\n\r\n";
	char buffer[1048576] = { 0 };
	krossock_t ks = NULL;
	int ret = 0;

	ks = krossock_connect("icanhazip.com");

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
