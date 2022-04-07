#include "includes.h"
#include "krossock_ssl.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

typedef struct ssl_stuff {
	SSL_CTX *ctx;
	BIO *bio;
	SSL *ssl;
} *ssl_stuff;

ssl_stuff ssl_init()
{
	ssl_stuff data;

	if ((data = malloc(sizeof(struct ssl_stuff))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	memset(data, 0, sizeof(struct ssl_stuff));

	/* set up ssl things */
	SSL_library_init();
	SSL_load_error_strings();
	
	ERR_load_SSL_strings();
	
	OpenSSL_add_all_algorithms();

	data->ctx = SSL_CTX_new(SSLv23_method());
	data->bio = BIO_new_ssl_connect(data->ctx);

	/* initialize ssl */
	BIO_get_ssl(data->bio, &(data->ssl));

	if (!(data->ssl)) {
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
	SSL_set_mode(data->ssl, SSL_MODE_AUTO_RETRY);
	return data;
}

void ssl_destroy(ssl_stuff data)
{
	SSL_CTX_free(data->ctx);
	BIO_free_all(data->bio);
	free(data);
}

krossock_t krossock_connect_ssl(const char* addr)
{
	krossock_t ks;
	ssl_stuff data;

	if (!addr) {
		errno = EINVAL;
		return NULL;
	}

	/* initialize data */
	if ((data = ssl_init()) == NULL)
		return NULL;

	/* set hostname and port */
	BIO_set_conn_hostname(data->bio, addr);

	/* initialize krossock */
	if ((ks = malloc(sizeof(struct krossock_t))) == NULL) {
		errno = ENOMEM;
		ssl_destroy(data);
		return NULL;
	}

	ks->type = SSL_SOCKET;
	ks->data = data;
	
	/* do the connection part */
	if (krossock_redial_ssl(ks) < 0) {
		ssl_destroy(data);
		free(ks);
		return NULL;
	}

	return ks;
}

void krossock_disconnect_ssl(krossock_t ks)
{
	/* close any connections */
	krossock_hangup_ssl(ks);

	/* cleanup the socket stuff */
	ssl_destroy(ks->data);

	/* free mem */
	free(ks);
}

int krossock_redial_ssl(krossock_t ks)
{
	int ret = 0;
	X509 *cert = NULL;

	if (ks->type != SSL_SOCK)
		ks

	/* initial connection */
	if (BIO_do_connect(ssl_struct->bio) <= 0) {
#ifdef SSL_HELPER_DEBUG
		fputs("ssl_helper_connect: BIO_do_connect: ", stderr);
		ERR_print_errors_fp(stderr);
#endif
		fputs("Connection failed.\n", stderr);
		fflush(stderr);
		return 1;
	}

	/* establish ssl handshake ? */

	/* set up defaults */
	if (SSL_CTX_set_default_verify_paths(ssl_struct->ctx) < 1) {
#ifdef SSL_HELPER_DEBUG
		fputs("ssl_helper_connect: SSL_CTX_set_default_verify_paths: ",
		      stderr);
		ERR_print_errors_fp(stderr);
#endif
		fputs("Could not get default CA path.\n", stderr);
		fflush(stderr);
		return 1;
	}

	/* validate ssl */
	if ((ret = SSL_get_verify_result(ssl_struct->ssl)) != X509_V_OK) {
#ifdef SSL_HELPER_DEBUG
		fputs("ssl_helper_connect: BIO_get_verify_result: ", stderr);
		ERR_print_errors_fp(stderr);
#endif
		fputs("SSL verification issue: ", stderr);
		fputs(ssl_helper_get_err_code(verify_codes, VERIFY_CODES_SIZE,
					      ret),
		      stderr);
		fputc('\n', stderr);
		fflush(stderr);
		/* show certificate details */
		if ((cert = SSL_get_peer_certificate(ssl_struct->ssl)) == NULL)
			return 1;
		ssl_helper_print_certificate(cert);
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
	if ((ret = SSL_connect(ssl_struct->ssl)) == 0) {
		/* handle shutdown */
		ret = SSL_get_error(ssl_struct->ssl, ret);
		fprintf(stderr, "Connection closed by peer. (%d)", ret);
		if ((SSL_get_shutdown(ssl_struct->ssl) &
		     SSL_RECEIVED_SHUTDOWN) == SSL_RECEIVED_SHUTDOWN)
			SSL_shutdown(ssl_struct->ssl);
		return 1;
	} else if (ret < 0) {
		/* handle error */
		ret = SSL_get_error(ssl_struct->ssl, ret);
		fprintf(stderr, "Connection closed unexpectedly. (%d)", ret);
		return 1;
	}

	return 0;
}

int krossock_hangup_ssl(krossock_t ks)
{
	errno = ENOSYS;
	return -1;
}

int krossock_send_ssl(krossock_t ks)
{
	errno = ENOSYS;
	return -1;
}

int krossock_recv_ssl(krossock_t ks)
{
	errno = ENOSYS;
	return -1;
}

void ssl_helper_shutdown(ssl_helper_t *ssl_struct)
{
	int ret;

	char buf[SSL_HELPER_BUFFER_SIZE + 1] = { 0 };
	size_t bytes_read;

	errno = 0;

	/* read everything */
	if (SSL_pending(ssl_struct->ssl)) {
		do {
			if ((ret = SSL_read_ex(ssl_struct->ssl, buf,
					       SSL_HELPER_BUFFER_SIZE,
					       &bytes_read)) == 0) {
				ret = SSL_get_error(ssl_struct->ssl, ret);
				fputs("Read error: ", stderr);
				fputs(ssl_helper_get_err_code(
					      ssl_codes, SSL_CODES_SIZE, ret),
				      stderr);
				fprintf(stderr, "\nerrno: %d\n", errno);
				fflush(stderr);

				if (ret == SSL_ERROR_SSL ||
				    ret == SSL_ERROR_SYSCALL)
					return;
			}
		} while (bytes_read != 0);
	}

	if ((ret = SSL_shutdown(ssl_struct->ssl)) == 0) {
		/* bidirectional shutdown, I guess. */
		SSL_read(ssl_struct->ssl, buf, SSL_HELPER_BUFFER_SIZE);
	} else if (ret < 0) {
		ret = SSL_get_error(ssl_struct->ssl, ret);
		fputs("shutdown error: ", stderr);
		fputs(ssl_helper_get_err_code(ssl_codes, SSL_CODES_SIZE, ret),
		      stderr);
		fprintf(stderr, "\nerrno: %d\n", errno);
		fflush(stderr);
	}
}

