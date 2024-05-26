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
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <openssl/x509.h>


X509 *X509_new(void)
{
	X509 *x509;

	if (!(x509 = (X509 *)malloc(sizeof(X509)))) {
		error_print();
		return NULL;
	}
	memset(x509, 0, sizeof(X509));

	if (!(x509->d = (uint8_t *)malloc(X509_MAX_SIZE))) {
		free(x509);
		error_print();
		return NULL;
	}
	return x509;
}

void X509_free(X509 *x509)
{
	if (x509) {
		if (x509->d) {
			free(x509->d);
		}
		free(x509);
	}
}

// `X509_get_serialNumber` return an internal pointer of `x509` and MUST NOT be freed.
ASN1_INTEGER *X509_get_serialNumber(X509 *x509)
{
	if (!x509) {
		error_print();
		return NULL;
	}
	return &x509->serial;
}

// `X509_get_subject_name` return an internal pointer of `x509` and MUST NOT be freed.
X509_NAME *X509_get_subject_name(const X509 *x509)
{
	if (!x509) {
		error_print();
		return NULL;
	}
	return (X509_NAME *)&x509->subject;
}

// `X509_get_issuer_name` return an internal pointer of `x509` and MUST NOT be freed.
X509_NAME *X509_get_issuer_name(const X509 *x509)
{
	if (!x509) {
		error_print();
		return NULL;
	}
	return (X509_NAME *)&x509->issuer;
}

// `X509_get0_notBefore` return an internal pointer of `x509` and MUST NOT be freed.
const ASN1_TIME *X509_get0_notBefore(const X509 *x509)
{
	if (!x509) {
		error_print();
		return NULL;
	}
	return &x509->not_before;
}

// `X509_get0_notAfter` return an internal pointer of `x509` and MUST NOT be freed.
const ASN1_TIME *X509_get0_notAfter(const X509 *x509)
{
	if (!x509) {
		error_print();
		return NULL;
	}
	return &x509->not_after;
}

int X509_NAME_print_ex(BIO *bio, const X509_NAME *name, int indent, unsigned long flags)
{
	x509_name_print(bio,0, indent, "X509_NAME", name->d, name->dlen);
	return 1;
}

// TODO:			
// `X509_NAME_oneline` return a string and might be freed by `OPENSSL_free`
char *X509_NAME_oneline(const X509_NAME *mame, char *buf, int buflen)
{
	if (!buf) {
		return strdup("X509_NAME_oneline() called");
	} else {
		strncpy(buf, "X509_NAME_oneline() called", buflen);
		return buf;
	}
}

int X509_NAME_digest(const X509_NAME *name, const EVP_MD *md, unsigned char *dgst, unsigned int *dgstlen)
{
	SM3_CTX sm3_ctx;

	if (!name || !dgst || !dgstlen) {
		error_print();
		return 0;
	}
	if (!name->d || !name->dlen) {
		error_print();
		return 0;
	}

	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, name->d, name->dlen);
	sm3_finish(&sm3_ctx, dgst);
	*dgstlen = 32;
	return 1;
}

void *X509_STORE_CTX_get_ex_data(const X509_STORE_CTX *ctx, int idx)
{
	return NULL;
}

X509 *X509_STORE_CTX_get_current_cert(const X509_STORE_CTX *ctx)
{
	return NULL;
}

int X509_STORE_CTX_get_error(const X509_STORE_CTX *ctx)
{
	return 0;
}

int X509_STORE_CTX_get_error_depth(const X509_STORE_CTX *ctx)
{
	return 0;
}

void *X509_get_ex_data(const X509 *x509, int idx)
{
	return NULL;
}

int X509_check_host(X509 *x509, const char *name, size_t namelen, unsigned int flags, char **peername)
{
	return 0;
}

int X509_digest(const X509 *x509, const EVP_MD *md, unsigned char *dgst, unsigned int *dgstlen)
{
	SM3_CTX sm3_ctx;

	if (!x509 || !dgst || !dgstlen) {
		error_print();
		return 0;
	}
	if (!x509->d || !x509->dlen) {
		error_print();
		return 0;
	}

	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, x509->d, x509->dlen);
	sm3_finish(&sm3_ctx, dgst);
	*dgstlen = 32;
	return 1;
}

int X509_set_ex_data(X509 *d, int idx, void *arg)
{
	return 1;
}

int X509_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
	return 1;
}

X509_NAME *sk_X509_NAME_value(const STACK_OF(X509_NAME) *sk, int idx)
{
	return NULL;
}

int sk_X509_NAME_num(const STACK_OF(X509_NAME) *sk)
{
	if (!sk) {
		error_print();
		return 0;
	}
	return sk->top;
}

STACK_OF(X509) *sk_X509_new_null()
{
	STACK_OF(X509) *sk;

	if (!(sk = (STACK_OF(X509) *)malloc(sizeof(*sk)))) {
		error_print();
		return NULL;
	}

	sk->top = 0;
	return sk;
}

int sk_X509_num(const STACK_OF(X509) *sk)
{
	if (!sk) {
		error_print();
		return 0;
	}
	return sk->top;
}

int sk_X509_push(STACK_OF(X509) *sk, const X509 *x509)
{
	if (!sk || !x509) {
		error_print();
		return 0;
	}
	if (sk->top >= STACK_OF_X509_MAX_NUM) {
		error_print();
		return 0;
	}

	sk->values[sk->top] = *x509;
	sk->top += 1;
	return 1;
}

void sk_X509_pop_free(STACK_OF(X509) *sk, void (*func)(X509 *))
{
	if (!sk) {
		error_print();
	}
	if (sk->top > 0) {
		sk->top -= 1;
	}
}
