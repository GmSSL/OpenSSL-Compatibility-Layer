/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OPENSSL_EVP_H
#define OPENSSL_EVP_H

#include <gmssl/sm2.h>
#include <gmssl/sm3.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef void ENGINE;


// make `const EVP_MD *` into `const char *` string
typedef char EVP_MD;

typedef SM3_DIGEST_CTX EVP_MD_CTX;


#define EVP_MAX_MD_SIZE 64

const EVP_MD *EVP_sm3(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha256(void);

EVP_MD_CTX *EVP_MD_CTX_new(void);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *engine);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md,unsigned int *s);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);

#define EVP_MD_CTX_create() EVP_MD_CTX_new()
#define EVP_MD_CTX_destroy(ctx) EVP_MD_CTX_free(ctx);




typedef struct {
	SM2_KEY signkey;
	SM2_KEY kenckey;
} EVP_PKEY;

void EVP_PKEY_free(EVP_PKEY *key);




#ifdef __cplusplus
}
#endif
#endif
