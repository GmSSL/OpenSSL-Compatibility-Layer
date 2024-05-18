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
#include <openssl/x509_vfy.h>


X509_LOOKUP_METHOD *X509_LOOKUP_file(void)
{
	return NULL;
}

int X509_LOOKUP_load_file(X509_LOOKUP *ctx, char *name, long type)
{
	return 1;
}

X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *store, X509_LOOKUP_METHOD *meth)
{
	return NULL;
}

int X509_STORE_set_flags(X509_STORE *xs, unsigned long flags)
{
	return 1;
}
