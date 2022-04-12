#include <stdio.h>
#include <krossock.h>
#include <errno.h>
#include <string.h>

int main()
{
	krossock_t ks = krossock_connect("http://127.0.0.1:80/");
	if (ks == NULL) {
		puts(strerror(errno));
		return errno;
	}
	krossock_disconnect(ks);
	return 0;
}
