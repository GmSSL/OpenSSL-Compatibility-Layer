/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OPENSSL_X509_H
#define OPENSSL_X509_H

#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	uint8_t *d;
	size_t dlen;
} X509_NAME;

int X509_NAME_digest(const X509_NAME *name, const EVP_MD *md, unsigned char *dgst, unsigned int *dgstlen);
int X509_NAME_print_ex(BIO *bio, const X509_NAME *name, int indent, unsigned long flags);
char *X509_NAME_oneline(const X509_NAME *mame, char *buf, int buflen);


#define STACK_OF(TYPE) STACK_OF_##TYPE


#define STACK_OF_X509_NAME_MAX_NUM 16

typedef struct {
	X509_NAME values[16];
	int top;
} STACK_OF_X509_NAME;

int sk_X509_NAME_num(const STACK_OF(X509_NAME) *sk);
X509_NAME *sk_X509_NAME_value(const STACK_OF(X509_NAME) *sk, int idx);


typedef struct {
	uint8_t *d;
	size_t dlen;
	ASN1_INTEGER serial;
	X509_NAME subject;
	X509_NAME issuer;
	time_t not_before;
	time_t not_after;
} X509;

void X509_free(X509 *x509);

ASN1_INTEGER *X509_get_serialNumber(X509 *x509);
X509_NAME *X509_get_subject_name(const X509 *x509);
X509_NAME *X509_get_issuer_name(const X509 *x509);
const ASN1_TIME *X509_get0_notBefore(const X509 *x509);
const ASN1_TIME *X509_get0_notAfter(const X509 *x509);

int X509_check_host(X509 *x509, const char *name, size_t namelen, unsigned int flags, char **peername);


int X509_digest(const X509 *x509, const EVP_MD *md, unsigned char *dgst, unsigned int *dgstlen);



#define X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT 0x01

// Nginx通过解析文件或者直接解析数据两种不同方式解析证书，在解析之后将原始数据（DER或文件名）再放到X509对象中
// 我觉得这个功能没有用处

int X509_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int X509_set_ex_data(X509 *x509, int idx, void *arg);
void *X509_get_ex_data(const X509 *x509, int idx);



const char *X509_verify_cert_error_string(long n);



#define STACK_OF_X509_MAX_NUM 16

typedef struct {
	X509 values[STACK_OF_X509_MAX_NUM];
	int top;
} STACK_OF_X509;

STACK_OF(X509) *sk_X509_new_null();
int  sk_X509_push(STACK_OF(X509) *sk, const X509 *x509);
void sk_X509_pop_free(STACK_OF(X509) *sk, void (*func)(void *));


typedef void X509_STORE;
typedef void X509_STORE_CTX;

// 这几个函数仅用于ngx_ssl_verify_callback记录当前证书验证信息
// 如果Nginx未设置NGX_DEBUG --with-debug，那么不会调用这几个函数
void *X509_STORE_CTX_get_ex_data(const X509_STORE_CTX *d, int idx);
X509 *X509_STORE_CTX_get_current_cert(const X509_STORE_CTX *ctx);
int   X509_STORE_CTX_get_error(const X509_STORE_CTX *ctx);
int   X509_STORE_CTX_get_error_depth(const X509_STORE_CTX *ctx);



#ifdef __cplusplus
}
#endif
#endif
