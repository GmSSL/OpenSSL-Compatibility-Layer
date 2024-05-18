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
#include <gmssl/error.h>
#include <openssl/asn1.h>


int i2a_ASN1_INTEGER(BIO *bio, const ASN1_INTEGER *a)
{
	size_t i;
	for (i = 0; i < a->dlen; i++) {
		fprintf(bio, "%02x", a->d[i]);
	}
	return 1; // 这个返回值对吗？
}

int ASN1_TIME_print(BIO *bio, const ASN1_TIME *tm)
{
	fprintf(bio, "%s", ctime(tm));
	return 1;
}
