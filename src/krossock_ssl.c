#include "includes.h"
#include "krossock_ssl.h"

#include <ctype.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

typedef struct krossock_ssl {
	/* things you need to hold onto until the connection closes */
	SSL_CTX *ctx;
	BIO *bio;
	SSL *ssl;
} *krossock_ssl;

struct ssl_data {
	/* things you need in order to initialize or connect */
};

krossock_ssl ssl_init(struct ssl_data *data)
{
	krossock_ssl kssl;

	/* initialize */
	if ((kssl = malloc(sizeof(struct krossock_ssl))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	memset(kssl, 0, sizeof(struct krossock_ssl));

	/* set up ssl things */
	SSL_library_init();
	SSL_load_error_strings();
	
	ERR_load_SSL_strings();
	
	OpenSSL_add_all_algorithms();

	kssl->ctx = SSL_CTX_new(SSLv23_method());
	kssl->bio = BIO_new_ssl_connect(kssl->ctx);

	/* initialize ssl */
	BIO_get_ssl(kssl->bio, &(kssl->ssl));

	if (!(kssl->ssl)) {
#ifdef SSL_HELPER_DEBUG
		fputs("ssl_init: BIO_get_ssl: ", stderr);
		ERR_print_errors_fp(stderr);
#endif
		fputs("Can't initialize ssl.\n", stderr);
		fflush(stderr);
		free(data);
		return NULL;
	}

	/* set ssl mode */
	SSL_set_mode(kssl->ssl, SSL_MODE_AUTO_RETRY);

	return kssl;
}

void ssl_destroy(krossock_ssl kssl)
{
	/* delete socket stuff */
	SSL_CTX_free(kssl->ctx);
	BIO_free_all(kssl->bio);
	free(kssl);
}

/* add helper functions here to fill out the ssl_data structure */

int krossock_dial_ssl(krossock_ssl kssl)
{
	int ret = 0;
	X509 *cert = NULL;

	/* initial connection */
	if (BIO_do_connect(kssl->bio) <= 0) {
#ifdef SSL_HELPER_DEBUG
		fputs("krossock_dial_ssl: BIO_do_connect: ", stderr);
		ERR_print_errors_fp(stderr);
#endif
		fputs("Connection failed.\n", stderr);
		fflush(stderr);
		return 1;
	}

	/* establish ssl handshake ? */

	/* set up defaults */
	if (SSL_CTX_set_default_verify_paths(kssl->ctx) < 1) {
#ifdef SSL_HELPER_DEBUG
		fputs("krossock_dial_ssl: SSL_CTX_set_default_verify_paths: ",
		      stderr);
		ERR_print_errors_fp(stderr);
#endif
		fputs("Could not get default CA path.\n", stderr);
		fflush(stderr);
		return 1;
	}

	/* validate ssl */
	if ((ret = SSL_get_verify_result(kssl->ssl)) != X509_V_OK) {
#ifdef SSL_HELPER_DEBUG
		fputs("krossock_dial_ssl: BIO_get_verify_result: ", stderr);
		ERR_print_errors_fp(stderr);
#endif
		fputs("SSL verification failed.\n", stderr);
		fputc('\n', stderr);
		fflush(stderr);
		/* show certificate details */
		if ((cert = SSL_get_peer_certificate(kssl->ssl)) == NULL)
			return 1;
		//ssl_helper_print_certificate(cert);
		X509_free(cert);
		/* do you want to continue anyway? */

		// TODO: what is this
		({
			char response;
			static struct termios oldt, newt;
			tcgetattr(STDIN_FILENO, &oldt);
			newt = oldt;
			newt.c_lflag &= ~(ICANON);
			tcsetattr(STDIN_FILENO, TCSANOW, &newt);
			do {
				fputs("Do you want to trust this certificate? (yn)",
				      stdout);
				fflush(stdout);
				if ((response = tolower(getchar())) == 'n')
					return 1;
			} while (putchar('\n'), response != 'y');
			tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
		});
	}

	// *connects in ssl*
	if ((ret = SSL_connect(kssl->ssl)) == 0) {
		/* handle shutdown */
		ret = SSL_get_error(kssl->ssl, ret);
		fprintf(stderr, "Connection closed by peer. (%d)", ret);
		if ((SSL_get_shutdown(kssl->ssl) &
		     SSL_RECEIVED_SHUTDOWN) == SSL_RECEIVED_SHUTDOWN)
			SSL_shutdown(kssl->ssl);
		return 1;
	} else if (ret < 0) {
		/* handle error */
		ret = SSL_get_error(kssl->ssl, ret);
		fprintf(stderr, "Connection closed unexpectedly. (%d)", ret);
		return 1;
	}

	return 0;
}

krossock_t krossock_connect_ssl(const char* address)
{
	krossock_t ks;
	krossock_ssl kssl;
	struct ssl_data data;

	if (!address) {
		errno = EINVAL;
		return NULL;
	}

	/* initialize data */

	/* create ssl */
	if ((kssl = ssl_init(&data)) == NULL)
		return NULL;

	/* connect ssl */

	/* set hostname and port */
	BIO_set_conn_hostname(kssl->bio, address);
	
	/* do the connection part */
	if (krossock_dial_ssl(kssl) < 0) {
		ssl_destroy(kssl);
		return NULL;
	}

	/* initialize krossock */
	if ((ks = malloc(sizeof(struct krossock_t))) == NULL) {
		errno = ENOMEM;
		ssl_destroy(kssl);
		return NULL;
	}

	ks->type = SSL_SOCKET;
	ks->data = (void *)kssl;

	return ks;
}

#define SSL_BUFFER_SIZE (1024 * 1024)
void krossock_disconnect_ssl(krossock_t ks)
{
	int ret;

	char buf[SSL_BUFFER_SIZE + 1] = { 0 };
	size_t bytes_read;

	errno = 0;

	krossock_ssl kssl;

	if (ks->type == SOCKET)
		return krossock_disconnect(ks);

	kssl = (krossock_ssl)ks->data;

	/* read everything */
	if (SSL_pending(kssl->ssl)) {
		do {
			if ((ret = SSL_read_ex(kssl->ssl, buf,
					       SSL_BUFFER_SIZE,
					       &bytes_read)) == 0) {
				ret = SSL_get_error(kssl->ssl, ret);
				fputs("Read error: ", stderr);
				ERR_print_errors_fp(stderr);
				fprintf(stderr, "\nerrno: %d\n", errno);
				fflush(stderr);
				/*
				 * if (ret == SSL_ERROR_SSL ||ret == SSL_ERROR_SYSCALL)
				 * 	return;
				 */
			}
		} while (bytes_read != 0);
	}

	/* close connection */
	if ((ret = SSL_shutdown(kssl->ssl)) == 0) {
		/* bidirectional shutdown, I guess. */
		SSL_read(kssl->ssl, buf, SSL_BUFFER_SIZE);
	} else if (ret < 0) {
		ret = SSL_get_error(kssl->ssl, ret);
		fputs("shutdown error: ", stderr);
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "\nerrno: %d\n", errno);
		fflush(stderr);
	}

	/* cleanup the socket stuff */
	ssl_destroy(kssl);

	/* free mem */
	free(ks);
}

int krossock_send_ssl(krossock_t ks)
{
	if (ks->type == SOCKET)
		return krossock_send(ks);

	errno = ENOSYS;
	return -1;
}

int krossock_recv_ssl(krossock_t ks)
{
	if (ks->type == SOCKET)
		return krossock_recv(ks);

	errno = ENOSYS;
	return -1;
}

