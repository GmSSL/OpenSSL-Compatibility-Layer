/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/mem.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>


int OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
{
	return 1;
}

// The default timeout of OpenSSL is 300s (5 minutes)
// When a `SSL` is timeout, the SESSION data will be removed, client have to do a full Handshake with server.
// GmSSL 3.1 does not support SSL_SESSION and timeout, so timeout is always 0
long SSL_CTX_set_timeout(SSL_CTX *ctx, long timeout_seconds)
{
	return 0;
}

long SSL_CTX_get_timeout(SSL_CTX *ctx)
{
	return 0;
}

// a typical cipher list is ""HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";"
// so we omit the input `str`
int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str)
{
	const int ciphers[] = {
		TLS_cipher_ecdhe_sm4_cbc_sm3,
	};

	if (!ctx || !str) {
		error_print();
		return 0;
	}

	if (tls_ctx_set_cipher_suites(ctx, ciphers, sizeof(ciphers)/sizeof(ciphers[0])) != 1) {
		error_print();
		return 0;
	}

	return 1;
}

// GmSSL does not support options
uint64_t SSL_CTX_set_options(SSL_CTX *ctx, uint64_t options)
{
	uint64_t bitmask = 0;
	return bitmask;
}

uint64_t SSL_CTX_clear_options(SSL_CTX *ctx, uint64_t options)
{
	uint64_t bitmask = 0;
	return bitmask;
}

uint64_t SSL_set_options(SSL *ssl, uint64_t options)
{
	uint64_t bitmask = 0;
	return bitmask;
}

uint64_t SSL_clear_options(SSL *ssl, uint64_t options)
{
	uint64_t bitmask = 0;
	return bitmask;
}

// GmSSL does not support different mode (such as SSL_MODE_ENABLE_PARTIAL_WRITE)
long SSL_CTX_set_mode(SSL_CTX *ctx, long mode)
{
	return 0;
}

int SSL_CTX_set_min_proto_version(SSL_CTX *ctx, int version)
{
	return 1;
}

int SSL_CTX_set_max_proto_version(SSL_CTX *ctx, int version)
{
	return 1;
}

void SSL_CTX_set_cert_cb(SSL_CTX *c, int (*cert_cb)(SSL *ssl, void *arg), void *arg)
{
}

// `SSL_CTX_set_read_ahead` is useful in DTLS, GmSSL does not support read ahead
long SSL_CTX_set_read_ahead(SSL_CTX *ctx, int yes)
{
	return 1; // How about return 0	?			
}

void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb verify_callback)
{
}

void SSL_set_verify(SSL *ssl, int mode, SSL_verify_cb verify_callback)
{
}

void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth)
{
}

void SSL_set_verify_depth(SSL *ssl, int depth)
{
}

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath)
{
	int verify_depth = 4;
	tls_ctx_set_ca_certificates(ctx, CAfile, verify_depth);
	return 1;
}

STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file)
{
	return (STACK_OF(X509_NAME) *)"Not implemented";
}

void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *list)
{
}

// Nginx use `SSL_get1_peer_certificate` to get client_verify certificate
// `SSL_get1_peer_certificate` works fine when caller is the server.
// But if the caller is the client, `SSL_get1_peer_certificate` only returns the signing cert
X509 *SSL_get1_peer_certificate(const SSL *ssl)
{
	const uint8_t *certs;
	size_t certslen;
	const uint8_t *cert;
	size_t certlen;
	X509 *x509;

	if (ssl->is_client) {
		certs = ssl->server_certs;
		certslen = ssl->server_certs_len;
	} else {
		certs = ssl->client_certs;
		certslen = ssl->client_certs_len;
	}

	if (x509_cert_from_der(&cert, &certlen, &certs, &certslen) != 1) {
		error_print();
		return NULL;
	}
	if (certlen > X509_MAX_SIZE) {
		error_print();
		return NULL;
	}
	if (!(x509 = X509_new())) {
		error_print();
		return NULL;
	}

	memcpy(x509->d, cert, certlen);
	x509->dlen = certlen;
	return x509;
}

// Sometimes even is handshake is success, `SSL_get_verify_result` still return error for some reasons
// 	* SSL_CTX_set_verify use `SSL_VERIFY_NONE`
//	* The server hostname does not match the certificate subject
// In Ngnix, `SSL_get_verify_result` is typically used with client_verify, so we assume GmSSL will handle
// all the verification. We assume that is handshake is ok, verify result is ok
long SSL_get_verify_result(const SSL *ssl)
{
	return X509_V_OK;
}

const char *X509_verify_cert_error_string(long n)
{
	if (n) {
		return "error";
	} else {
		return "ok";
	}
}

// TODO: sk_X509_NAME_new, push ... have not been implemented yet!
STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return NULL;
	}

	// TODO: parse ctx->cacerts, ctx->cacertslen to parse every CA certs
	// and then get subject, and push into STACK_OF(X509_NAME)

	return NULL;
}

// GmSSL 3.1 always verify peer's certificate
int SSL_CTX_get_verify_mode(const SSL_CTX *ctx)
{
	return SSL_VERIFY_PEER;
}

const SSL_METHOD *SSLv23_method(void)
{
	return NULL;
}

SSL_CTX *SSL_CTX_new(const SSL_METHOD *method)
{
	TLS_CTX *ctx;
	const int is_client = 0;

	if (!(ctx = (TLS_CTX *)malloc(sizeof(TLS_CTX)))) {
		error_print();
		return NULL;
	}

	if (tls_ctx_init(ctx, TLS_protocol_tlcp, is_client) != 1) {
		error_print();
		free(ctx); // try do free  			
		return NULL;
	}

	return ctx;
}

void SSL_CTX_free(SSL_CTX *ctx)
{
	if (ctx) {
		gmssl_secure_clear(ctx, sizeof(*ctx));
		free(ctx);				
	}
}

int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x509)
{
	if (ctx->certs) {
		free(ctx->certs);			
	}
	if (!(ctx->certs = (uint8_t *)malloc(x509->dlen))) {
		error_print();
		return 0;
	}
	memcpy(ctx->certs, x509->d, x509->dlen);
	ctx->certslen = x509->dlen;
	return 1;
}

// `SSL_CTX_set0_chain` is a macro of `SSL_CTX_ctrl` in OpenSSL
int _SSL_CTX_set0_chain(SSL_CTX *ctx, STACK_OF(X509) *sk)
{
	size_t total_len = ctx->certslen;
	int i;

	if (!ctx || !sk) {
		error_print();
		return 0;
	}

	for (i = 0; i < sk->top; i++) {
		total_len += sk->values[i].dlen;
	}

	if (!(ctx->certs = realloc(ctx->certs, total_len))) {
		error_print();
		return 0;
	}

	for (i = 0; i < sk->top; i++) {
		memcpy(ctx->certs + ctx->certslen, sk->values[i].d, sk->values[i].dlen);
		ctx->certslen += sk->values[i].dlen;
	}

	return 1;
}

int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)
{
	if (!ctx || !pkey) {
		error_print();
		return 0;
	}
	ctx->signkey = pkey->signkey;
	ctx->kenckey = pkey->kenckey;
	return 1;
}

// `SSL_CTX_set1_group_list` is a macro os `SSL_CTX_ctrl` in OpenSSL
int _SSL_CTX_set1_group_list(SSL_CTX *ctx, char *list)
{
	if (strcmp(list, "sm2p256v1") != 0) {
		error_print();
		return 0;
	}
	return 1;
}

// `SSL_CTX_set_tmp_dh` is a macro os `SSL_CTX_ctrl` in OpenSSL
long _SSL_CTX_set_tmp_dh(SSL_CTX *ctx, DH *dh)
{
	return 0;
}

int SSL_CTX_set0_tmp_dh_pkey(SSL_CTX *ctx, EVP_PKEY *dhpkey)
{
	return 0;
}

// OpenSSL use `X509_STORE` as the database of CA certificates
X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx)
{
	return NULL;
}

int SSL_CTX_get_ex_new_index(long argl, void *argp,
	CRYPTO_EX_new *new_func,
	CRYPTO_EX_dup *dup_func,
	CRYPTO_EX_free *free_func)
{
	return 1;
}

int SSL_CTX_set_ex_data(SSL_CTX *ctx, int idx, void *arg)
{
	return 1;
}

void *SSL_CTX_get_ex_data(const SSL_CTX *d, int idx)
{
	return NULL;
}

long _SSL_CTX_set_session_cache_mode(SSL_CTX *ctx, long mode)
{
	return 0;
}

int SSL_CTX_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid_ctx, unsigned int sid_ctx_len)
{
	return 1;
}

void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx, int (*new_session_cb)(SSL *, SSL_SESSION *))
{
}

long _SSL_CTX_sess_set_cache_size(SSL_CTX *ctx, long t)
{
	return 1;
}

int SSL_CTX_remove_session(SSL_CTX *ctx, SSL_SESSION *c)
{
	return 1;
}

void SSL_CTX_sess_set_get_cb(SSL_CTX *ctx,
	SSL_SESSION *(*get_session_cb)(SSL *, const unsigned char *, int, int *))
{
}

void SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx,
	void (*remove_session_cb)(SSL_CTX *ctx, SSL_SESSION *))
{
}

int SSL_session_reused(const SSL *ssl)
{
	return 0;
}

int SSL_set_session(SSL *ssl, SSL_SESSION *session)
{
	return 1;
}

SSL_SESSION *SSL_get1_session(SSL *ssl)
{
	return NULL;
}

SSL_SESSION *SSL_get0_session(const SSL *ssl)
{
	return NULL;
}

void SSL_SESSION_free(SSL_SESSION *session)
{
	if (session) {
		free(session);
	}
}

const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s, unsigned int *len)
{
	return NULL;
}

int i2d_SSL_SESSION(SSL_SESSION *in, unsigned char **pp)
{
	return 0;
}

SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp, long length)
{
	return NULL;
}

SSL *SSL_new(SSL_CTX *ctx)
{
	SSL *ssl;

	if (!(ssl = (SSL *)malloc(sizeof(*ssl)))) {
		error_print();
		return NULL;
	}
	if (tls_init(ssl, ctx) != 1) {
		error_print();
		free(ssl); //FIXME 			
		return NULL;
	}
	return ssl;
}

void SSL_free(SSL *ssl)
{
	if (ssl) {
		gmssl_secure_clear(ssl, sizeof(*ssl));
		free(ssl);//FIXME			
	}
}

int SSL_is_server(const SSL *ssl)
{
	if (ssl->is_client) {
		return 0;
	} else {
		return 1;
	}
}

const char *SSL_get_version(const SSL *ssl)
{
	if (!ssl) {
		error_print();
		return NULL;
	}
	return tls_protocol_name(ssl->protocol);
}

const char *SSL_get_cipher_name(const SSL *ssl)
{
	if (!ssl) {
		error_print();
		return NULL;
	}
	return tls_cipher_suite_name(ssl->cipher_suite);
}

char *SSL_get_shared_ciphers(const SSL *ssl, char *buf, int buflen)
{
	if (!ssl) {
		error_print();
		return NULL;
	}
	strncpy(buf, tls_cipher_suite_name(TLS_cipher_ecdhe_sm4_cbc_sm3), buflen);
	return buf;
}

void SSL_set_connect_state(SSL *ssl)
{
	ssl->is_client = 1;
}

void SSL_set_accept_state(SSL *ssl)
{
	ssl->is_client = 0;
}

int SSL_set_fd(SSL *ssl, int fd)
{
	int opts;

	if (tls_set_socket(ssl, fd) != 1) {
		error_print();
		return 0;
	}

	opts = fcntl(ssl->sock, F_GETFL, 0);
	opts &= ~O_NONBLOCK;
	fcntl(ssl->sock, F_SETFL, opts);

	return 1;
}

int SSL_do_handshake(SSL *ssl)
{
	int opts;

	if (tls_do_handshake(ssl) != 1) {
		error_print();
		return 0;
	}

	opts = fcntl(ssl->sock, F_GETFL, 0);
	opts |= O_NONBLOCK;
	fcntl(ssl->sock, F_SETFL, opts);

	return 1;
}

int SSL_read(SSL *ssl, void *buf, int num)
{
	int ret;
	size_t outlen;

	ret = tls_recv(ssl, buf, num, &outlen);
	if (ret > 0) {
		return (int)outlen;
	} else if (ret == -EAGAIN) {
		return -2;
	} else {
		return ret;
	}
}

int SSL_write(SSL *ssl, const void *buf, int num)
{
	int ret;
	size_t outlen;

	ret = tls_send(ssl, buf, num, &outlen);

	if (ret > 0) {
		return (int)outlen;
	} else if (ret == -EAGAIN) {
		return -3;
	} else {
		return ret;
	}
}

int SSL_in_init(const SSL *ssl)
{
	return 0;
}

void SSL_set_quiet_shutdown(SSL *ssl, int mode)
{
}

void SSL_set_shutdown(SSL *ssl, int mode)
{
}

int SSL_get_ex_data_X509_STORE_CTX_idx(void)
{
	return 0;
}

// OpenSSL return SSL_SENT_SHUTDOWN, SSL_RECEIVED_SHUTDOWN
int SSL_get_shutdown(const SSL *ssl)
{
	return 1;
}

int SSL_shutdown(SSL *ssl)
{
	// when client Ctrl+c close connections, the socket is closed, so server shutdown will not return 1
	if (tls_shutdown(ssl) != 1) {
		error_print();
		return 0;
	}
	return 1;
}

int SSL_get_ex_new_index(long argl, void *argp,
	CRYPTO_EX_new *new_func,
	CRYPTO_EX_dup *dup_func,
	CRYPTO_EX_free *free_func)
{
	return 1;
}

int SSL_set_ex_data(SSL *ssl, int idx, void *arg)
{
	return 1;
}

void *SSL_get_ex_data(const SSL *ssl, int idx)
{
	return NULL;
}

int SSL_get_error(const SSL *ssl, int ret)
{
	switch (ret) {
	case -2: return SSL_ERROR_WANT_READ;
	case -3: return SSL_ERROR_WANT_WRITE;
	}
	return SSL_ERROR_NONE;
}

void SSL_CTX_set_info_callback(SSL_CTX *ctx,
	void (*callback) (const SSL *ssl, int type, int val))
{
}

BIO *SSL_get_rbio(const SSL *ssl)
{
	return NULL;
}

BIO *SSL_get_wbio(const SSL *ssl)
{
	return NULL;
}

long BIO_set_write_buffer_size(BIO *bio, long size)
{
	return 1;
}

const SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl)
{
	return NULL;
}

char *SSL_CIPHER_description(const SSL_CIPHER *cipher, char *buf, int size)
{
	return "SSL_CIPHER_description()";
}

int SSL_use_certificate(SSL *ssl, X509 *x509)
{
	return 1;
}

int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey)
{
	return 1;
}

int SSL_set0_chain(SSL *ssl, STACK_OF(X509) *sk)
{
	return 1;
}
