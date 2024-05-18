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


ASN1_INTEGER *X509_get_serialNumber(X509 *x509)
{
	ASN1_INTEGER *serial = &x509->serial;

	if (x509_cert_get_details(x509->d, x509->dlen,
		NULL,
		(const uint8_t **)&serial->d, &serial->dlen,
		NULL,
		NULL, NULL,
		NULL, NULL,
		NULL, NULL,
		NULL,
		NULL, NULL,
		NULL, NULL,
		NULL, NULL,
		NULL,
		NULL, NULL) != 1) {
		error_print();
		return NULL;
	}

	return serial;
}

X509_NAME *X509_get_subject_name(const X509 *x509)
{
	X509_NAME *name = (X509_NAME *)&x509->subject;

	if (x509_cert_get_subject(x509->d, x509->dlen, (const uint8_t **)&name->d, &name->dlen) != 1) {
		error_print();
		return NULL;
	}

	return name;
}

X509_NAME *X509_get_issuer_name(const X509 *x509)
{
	X509_NAME *name = (X509_NAME *)&x509->issuer;

	if (x509_cert_get_issuer(x509->d, x509->dlen, (const uint8_t **)&name->d, &name->dlen) != 1) {
		error_print();
		return NULL;
	}

	return name;
}

int X509_NAME_print_ex(BIO *bio, const X509_NAME *name, int indent, unsigned long flags)
{
	x509_name_print(bio,0, indent, "X509_NAME", name->d, name->dlen);
	return 1;
}

char *X509_NAME_oneline(const X509_NAME *mame, char *buf, int buflen)
{
	return "not supported";
}

int X509_NAME_digest(const X509_NAME *name, const EVP_MD *md, unsigned char *dgst, unsigned int *dgstlen)
{
	// FIXME: do digest
	*dgstlen = 32;
	return 1;
}

const ASN1_TIME *X509_get0_notBefore(const X509 *x509)
{
	time_t *not_before = (time_t *)&x509->not_before;

	// 在OpenSSL中，X509_get0_notBefore 直接返回X509的一个属性，但是在这个项目中，X509可能还没有解析
	// 因此X509中的not_before可能还没有被赋值
	// 可能要在其他某个函数中完成这个任务
	if (x509_cert_get_details(x509->d, x509->dlen,
		NULL,
		NULL, NULL,
		NULL,
		NULL, NULL,
		not_before, NULL,
		NULL, NULL,
		NULL,
		NULL, NULL,
		NULL, NULL,
		NULL, NULL,
		NULL,
		NULL, NULL) != 1) {
		error_print();
		return NULL;
	}
	return not_before;
}

const ASN1_TIME *X509_get0_notAfter(const X509 *x509)
{
	time_t *not_after = (time_t *)&x509->not_after;
	// 同notBefore

	if (x509_cert_get_details(x509->d, x509->dlen,
		NULL,
		NULL, NULL,
		NULL,
		NULL, NULL,
		NULL, not_after,
		NULL, NULL,
		NULL,
		NULL, NULL,
		NULL, NULL,
		NULL, NULL,
		NULL,
		NULL, NULL) != 1) {
		error_print();
		return NULL;
	}
	return not_after;
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
	*dgstlen = 32;
	return 0;
}


int X509_set_ex_data(X509 *d, int idx, void *arg)
{
	return 1;
}

int X509_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
	return 1;
}

void X509_free(X509 *x509)
{
	if (x509) {
		free(x509);
	}
}



X509_NAME *sk_X509_NAME_value(const STACK_OF(X509_NAME) *sk, int idx)
{
	return NULL;
}

int sk_X509_NAME_num(const STACK_OF(X509_NAME) *sk)
{
	return 0;
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

int sk_X509_push(STACK_OF(X509) *sk, const X509 *x509)
{
	if (sk->top >= STACK_OF_X509_MAX_NUM) {
		error_print();
		return 0;
	}

	sk->values[sk->top] = *x509;
	sk->top += 1;
	return 1;
}

void sk_X509_pop_free(STACK_OF(X509) *sk, void (*func)(void *))
{
	if (sk->top > 0) {
		sk->top -= 1;
	}
}
