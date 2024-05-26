/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OPENSSL_PEM_H
#define OPENSSL_PEM_H

#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef int (pem_password_cb)(char *buf, int size, int rwflag, void *u);

EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bio, EVP_PKEY **pkey, pem_password_cb *cb, void *pass);
EVP_PKEY *PEM_read_bio_Parameters(BIO *bio, EVP_PKEY **pkey);

X509 *PEM_read_bio_X509(BIO *bio, X509 **x509, pem_password_cb *cb, void *u);
X509 *PEM_read_bio_X509_AUX(BIO *bio, X509 **x509, pem_password_cb *cb, void *u);
int PEM_write_bio_X509(BIO *bio, X509 *x509);

DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u);


#ifdef __cplusplus
}
#endif
#endif
