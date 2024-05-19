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
#include <openssl/evp.h>


int main(void)
{
	int ret = 1;
	EVP_MD_CTX *ctx = NULL;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen, i;

	if (!(ctx = EVP_MD_CTX_create())) {
		fprintf(stderr, "%s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (EVP_DigestInit_ex(ctx, EVP_sm3(), NULL) != 1) {
		goto end;
	}
	if (EVP_DigestUpdate(ctx, "abc", 3) != 1) {
		goto end;
	}
	if (EVP_DigestFinal_ex(ctx, dgst, &dgstlen) != 1) {
		goto end;
	}

	for (i = 0; i < dgstlen; i++) {
		printf("%02x", dgst[i]);
	}
	printf("\n");

	ret = 0;
end:
	EVP_MD_CTX_destroy(ctx);
	return ret;
}
