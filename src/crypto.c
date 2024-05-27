/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdlib.h>
#include <gmssl/error.h>
#include <openssl/crypto.h>


void OPENSSL_free(void *p)
{
	if (p) {
		free(p);
	}
}

OPENSSL_INIT_SETTINGS *OPENSSL_INIT_new(void)
{
	OPENSSL_INIT_SETTINGS *init = NULL;

	if (!(init = (OPENSSL_INIT_SETTINGS *)malloc(sizeof(*init)))) {
		error_print();
		return NULL;
	}
	init->appname = NULL;
	return init;
}

int OPENSSL_INIT_set_config_appname(OPENSSL_INIT_SETTINGS *init, const char *name)
{
	if (!init || !name) {
		error_print();
		return 0;
	}

	init->appname = name;
	return 1;
}

void OPENSSL_INIT_free(OPENSSL_INIT_SETTINGS *init)
{
	if (init) {
		free(init);
	}
}
