/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OPENSSL_BIO_H
#define OPENSSL_BIO_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void BIO_METHOD;

const BIO_METHOD *BIO_s_mem(void);


typedef FILE BIO;

BIO *BIO_new(const BIO_METHOD *meth);
BIO *BIO_new_mem_buf(const void *buf, int len);
BIO *BIO_new_file(const char *filename, const char *mode);
int BIO_read(BIO *bio, void *buf, int len);
int BIO_write(BIO *bio, const void *buf, int len);
int BIO_pending(BIO *bio);
int BIO_reset(BIO *bio);
int BIO_get_mem_data(BIO *bio, char **pp);
int BIO_free(BIO *bio);


#ifdef __cplusplus
}
#endif
#endif
