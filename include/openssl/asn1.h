/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OPENSSL_ASN1_H
#define OPENSSL_ASN1_H

#include <time.h>
#include <string.h>
#include <stdint.h>
#include <openssl/bio.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	uint8_t *d;
	size_t dlen;
} ASN1_INTEGER;

int i2a_ASN1_INTEGER(BIO *bp, const ASN1_INTEGER *a);


typedef time_t ASN1_TIME;

int ASN1_TIME_print(BIO *bio, const ASN1_TIME *tm);


#ifdef __cplusplus
}
#endif
#endif
