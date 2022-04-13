#include "includes.h"
#include "krossock.h"

typedef struct krossock_t {
	enum { SOCKET, SSL_SOCKET } type;
	struct {
		int eof;
		int sock;
	} ksock;
	struct {
		SSL_CTX *ctx;
		SSL *ssl;
		BIO *bio;
	} kssl;
} *krossock_t;

krossock_t krossock_init(struct init_data *data)
{
	krossock_t ks;

	if (data == NULL) {
		DEBUG("socket_init: data was NULL\n");
		errno = EINVAL;
		return NULL;
	}

	/* initialize krossock */
	if ((ks = malloc(sizeof(struct krossock_t))) == NULL) {
		DEBUG("malloc() failed for ks\n");
		errno = ENOMEM;
		return NULL;
	}

	DEBUG("krossock (%lx) allocated\n", (unsigned long int)(ks));

	/* create a socket */
	if ((ks->ksock.sock = socket(data->domain, data->style, data->protocol)) < 0) {
		DEBUG("socket() failed\n");
		goto die;
	}

	DEBUG("socket (%d) created\n", ks->ksock.sock);

	ks->type = SOCKET;

	if (data->ssl) {
		ks->type = SSL_SOCKET;

		/* set up ssl things */
		SSL_library_init();
		SSL_load_error_strings();
		//ERR_load_SSL_strings();
		OpenSSL_add_all_algorithms();

		/* create bio */
		if ((ks->kssl.bio = BIO_new_socket(ks->ksock.sock, 0)) == NULL) {
			DEBUG("BIO_new_socket() failed\n");
			goto die;
		}

		DEBUG("bio (%lx) created\n", (unsigned long int)(ks->kssl.bio));

		/* create ctx */
		if ((ks->kssl.ctx = SSL_CTX_new(TLS_client_method())) == NULL) {
			DEBUG("SSL_CTX_new() failed\n");
			goto die;
		}

		DEBUG("ctx (%lx) created\n", (unsigned long int)(ks->kssl.ctx));

		/* create ssl */
		if ((ks->kssl.ssl = SSL_new(ks->kssl.ctx)) == NULL) {
			DEBUG("SSL_new() failed\n");
			goto die;
		}

		DEBUG("ssl (%lx) created\n", (unsigned long int)(ks->kssl.ssl));

		SSL_set_bio(ks->kssl.ssl, ks->kssl.bio, ks->kssl.bio);

		/* set ssl mode */
		//SSL_set_mode(kssl->ssl, SSL_MODE_AUTO_RETRY);
	}
	
	DEBUG("krossock (%lx) initialized\n", (unsigned long int)(ks));

	return ks;
die:
	free(ks);
	return NULL;
}

void krossock_destroy(krossock_t ks)
{
	if (ks == NULL) {
		DEBUG("ks was NULL");
		errno = EINVAL;
		return;
	}

	/* delete socket stuff */
	if (ks->type == SSL_SOCKET) {
		//BIO_free_all(ks->kssl.bio);
		//DEBUG("bio (%lx) free'd\n", (unsigned long int)(ks->kssl.bio));
		SSL_CTX_free(ks->kssl.ctx);
		DEBUG("ctx (%lx) free'd\n", (unsigned long int)(ks->kssl.ctx));
		SSL_free(ks->kssl.ssl);
		DEBUG("ssl (%lx) free'd\n", (unsigned long int)(ks->kssl.ssl));
		DEBUG("bio (%lx) free'd\n", (unsigned long int)(ks->kssl.bio));
	}

	free(ks);

	DEBUG("krossock (%lx) free'd\n", (unsigned long int)(ks));
}

krossock_t krossock_connect(const char* address)
{
	krossock_t ks;
	struct init_data data;

	if (address == NULL) {
		DEBUG("address was NULL\n");
		errno = EINVAL;
		return NULL;
	}

	if (socket_parse_address(address, &data) < 0) {
		DEBUG("socket_parse_address() failed for address '%s'\n", address);
		return NULL;
	}

	/* create krossock */
	if ((ks = krossock_init(&data)) == NULL) {
		DEBUG("krossock_init() failed\n");
		return NULL;
	}

	/* connect */
	if (connect(ks->ksock.sock, (struct sockaddr *) &(data.sockaddr), data.sockaddr_len) < 0) {
		DEBUG("connect() failed\n");
		krossock_destroy(ks);
		return NULL;
	}
	DEBUG("socket (%d) connected\n", ks->ksock.sock);

	if (ks->type == SSL_SOCKET) {
		if (SSL_connect(ks->kssl.ssl) <= 0) {
			DEBUG("SSL_connect() failed\n");
			krossock_destroy(ks);
			return NULL;
		}
		DEBUG("ssl (%lx) connected\n", (unsigned long int)(ks->kssl.ssl));
	}

	return ks;
}

void krossock_disconnect(krossock_t ks)
{
	if (ks == NULL) {
		DEBUG("ks was NULL\n");
		errno = EINVAL;
		return;
	}

	if (ks->type == SSL_SOCKET) {
		SSL_shutdown(ks->kssl.ssl);
		DEBUG("ssl (%lx) disconnected\n", (unsigned long int)(ks->kssl.ssl));
	}

	close(ks->ksock.sock);
	DEBUG("socket (%d) disconnected\n", ks->ksock.sock);

	/* cleanup */
	krossock_destroy(ks);
}

ssize_t krossock_peek(krossock_t ks, void *buf, size_t nbyte)
{
	struct pollfd fds;
	ssize_t read;

	if (ks == NULL) {
		DEBUG("ks was NULL\n");
		errno = EINVAL;
		return -1;
	}

	fds.fd = ks->ksock.sock;
	fds.events = POLLHUP;

	if (ks->type == SSL_SOCKET) {
		DEBUG("using ssl method\n");
		DEBUG("not fully implemented\n");
		/* peek incoming message */
		SSL_peek_ex(ks->kssl.ssl, buf, nbyte, &read);
	} else {
		read = recv(ks->ksock.sock, buf, nbyte, MSG_PEEK);
	}

	if (read <= 0) {
		if (poll(&fds, 1, 200)) {
			if (fds.revents & POLLHUP) {
				DEBUG("EOF reached\n");
				ks->ksock.eof = 1;
			}
		}
	}

	DEBUG("read %ld of %ld\n", read, nbyte);

	return read;
}

ssize_t krossock_read(krossock_t ks, void *buf, size_t nbyte)
{
	struct pollfd fds;
	ssize_t read;

	if (ks == NULL) {
		DEBUG("ks was NULL\n");
		errno = EINVAL;
		return -1;
	}

	fds.fd = ks->ksock.sock;
	fds.events = POLLHUP;

	if (ks->type == SSL_SOCKET) {
		DEBUG("using ssl method\n");
		DEBUG("not fully implemented\n");
		/* read incoming message */
		SSL_read_ex(ks->kssl.ssl, buf, nbyte, &read);
	} else {
		read = recv(ks->ksock.sock, buf, nbyte, 0);
	}

	if (read <= 0) {
		if (poll(&fds, 1, 200)) {
			if (fds.revents & POLLHUP) {
				DEBUG("EOF reached\n");
				ks->ksock.eof = 1;
			}
		}
	}

	DEBUG("read %ld of %ld\n", read, nbyte);

	return read;
}

ssize_t krossock_write(krossock_t ks, const void *buf, size_t nbyte)
{
	struct pollfd fds;
	ssize_t wrote;

	if (ks == NULL) {
		DEBUG("ks was NULL\n");
		errno = EINVAL;
		return -1;
	}

	fds.fd = ks->ksock.sock;
	fds.events = POLLHUP;

	if (ks->type == SSL_SOCKET) {
		DEBUG("using ssl method\n");
		DEBUG("not fully implemented\n");
		/* write message */
		SSL_write_ex(ks->kssl.ssl, buf, nbyte, &wrote);
	} else {
		wrote = send(ks->ksock.sock, buf, nbyte, 0);
	}

	if (wrote <= 0) {
		if (poll(&fds, 1, 200)) {
			if (fds.revents & POLLHUP) {
				DEBUG("EOF reached\n");
				ks->ksock.eof = 1;
			}
		}
	}

	DEBUG("wrote %ld of %ld\n", wrote, nbyte);

	return wrote;
}

int krossock_eof(krossock_t ks)
{
	if (ks == NULL) {
		DEBUG("krossock_eof: ks was NULL\n");
		errno = EINVAL;
		return -1;
	}

	if (ks->type == SSL_SOCKET) {
		DEBUG("using ssl method\n");
		DEBUG("not implemented\n");
		errno = ENOSYS;
		return -1;
	} else {
		return ks->ksock.eof;
	}
}

