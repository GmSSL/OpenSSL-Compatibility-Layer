/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OPENSSL_CRYPTO_H
#define OPENSSL_CRYPTO_H

#include <openssl/opensslv.h>

#ifdef __cplusplus
extern "C" {
#endif


void OPENSSL_free(void *p);

typedef struct {
	const char *appname;
} OPENSSL_INIT_SETTINGS;

#define OPENSSL_INIT_LOAD_CONFIG (0x00000040L)

OPENSSL_INIT_SETTINGS *OPENSSL_INIT_new(void);
int OPENSSL_INIT_set_config_appname(OPENSSL_INIT_SETTINGS *init, const char* name);
void OPENSSL_INIT_free(OPENSSL_INIT_SETTINGS *init);


typedef void CRYPTO_EX_DATA;

typedef void CRYPTO_EX_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp);
typedef void CRYPTO_EX_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp);
typedef int CRYPTO_EX_dup(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from, void **from_d, int idx, long argl, void *argp);


#ifdef __cplusplus
}
#endif
#endif
