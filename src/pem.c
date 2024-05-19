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
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <openssl/pem.h>


EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bio, EVP_PKEY **pp, pem_password_cb *cb, void *u)
{
	EVP_PKEY *ret;
	char pass[1024] = {0};

	cb(pass, sizeof(pass), 0, u);

	if (sm2_private_key_info_decrypt_from_pem(&ret->signkey, pass, bio) != 1) {
		error_print();
		return NULL;
	}
	if (sm2_private_key_info_decrypt_from_pem(&ret->kenckey, pass, bio) != 1) {
		error_print();
		return NULL;
	}

	return ret;
}

DH *PEM_read_bio_DHparams(BIO *bio, DH **dh, pem_password_cb *cb, void *u)
{
	error_print();
	return NULL;
}

EVP_PKEY *PEM_read_bio_Parameters(BIO *bio, EVP_PKEY **pkey)
{
	error_print();
	return NULL;
}

// 如果x509 && *x509，说明调用方传入了一个已经申请的x509对象，否则我们得自己申请一个
X509 *PEM_read_bio_X509(BIO *bio, X509 **pp, pem_password_cb *cb, void *u)
{
	X509 *x509;

	if (pp && *pp) {
		x509 = *pp;
		if (x509->d) {
			free(x509->d);
			x509->d = NULL;
		}
	} else {
		if (!(x509 = (X509 *)malloc(sizeof(X509)))) {
			error_print();
			return NULL;
		}
	}

	if (!(x509->d = (uint8_t *)malloc(X509_MAX_SIZE))) {
		error_print();
		free(x509);
		return NULL;
	}

	if (x509_cert_from_pem(x509->d, &x509->dlen, X509_MAX_SIZE, bio) != 1) {
		error_print();
		free(x509->d);
		free(x509);
		return NULL;
	}

	return x509;
}

X509 *PEM_read_bio_X509_AUX(BIO *bio, X509 **pp, pem_password_cb *cb, void *u)
{
	X509 *x509;

	if (!(x509 = PEM_read_bio_X509(bio, pp, cb, u))) {
		error_print();
		return NULL;
	}

	return x509;
}

int PEM_write_bio_X509(BIO *bio, X509 *x509)
{
	if (x509_cert_to_pem(x509->d, x509->dlen, bio) != 1) {
		error_print();
		return 0;
	}
	return 1;
}


