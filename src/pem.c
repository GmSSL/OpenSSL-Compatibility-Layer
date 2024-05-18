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
#include <gmssl/error.h>
#include <openssl/pem.h>




// 这个函数实现的不对				
EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bio, EVP_PKEY **pkey, pem_password_cb *cb, void *pass)
{
	EVP_PKEY *ret;
	char buf[1024] = {0};

	cb(buf, sizeof(buf), 0, pass)



	if (sm2_private_key_info_decrypt_from_pem(&ret->signkey, buf, bio) != 1) {
		error_print();
		return -1;
	}

	if (sm2_private_key_info_decrypt_from_pem(&ret->kenckey, buf, bio) != 1) {
		error_print();
		return -1;
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



