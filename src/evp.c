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
#include <gmssl/error.h>
#include <openssl/evp.h>


const EVP_MD *EVP_sha1(void) {
	return "sha1";
}

const EVP_MD *EVP_sha256(void) {
	return "sha256";
}

const EVP_MD *EVP_sm3(void) {
	return "sm3";
}

EVP_MD_CTX *EVP_MD_CTX_new(void)
{
	EVP_MD_CTX *md_ctx;

	if (!(md_ctx = (EVP_MD_CTX *)malloc(sizeof(*md_ctx)))) {
		error_print();
		return NULL;
	}

	return md_ctx;
}

// Do we need to check if md is SM3 or SHA256?			
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *md, ENGINE *engine)
{
	if (sm3_digest_init(ctx, NULL, 0) != 1) {
		error_print();
		return 0;
	}
	return 1;
}

int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
	if (sm3_digest_update(ctx, d, cnt) != 1) {
		error_print();
		return 0;
	}
	return 1;
}

int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *dgst, unsigned int *dgstlen)
{
	if (sm3_digest_finish(ctx, dgst) != 1) {
		error_print();
		return 0;
	}
	*dgstlen = 32;
	return 1;
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
	if (ctx) {
		free(ctx);
	}
}

void EVP_PKEY_free(EVP_PKEY *pkey)
{
	if (pkey) {
		gmssl_secure_clear(pkey, sizeof(EVP_PKEY));
		free(pkey);
	}
}



