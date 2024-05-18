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
#include "openssl/bio.h"


const BIO_METHOD *BIO_s_mem(void)
{
	return NULL;
}

BIO *BIO_new(const BIO_METHOD *meth)
{
	FILE *fp;

	if (!(fp = tmpfile())) {
		error_print();
		return NULL;
	}
	return fp;
}

BIO *BIO_new_mem_buf(const void *buf, int len)
{
	FILE *fp;

	if (!(fp = tmpfile())) {
		error_print();
		return NULL;
	}
	return fp;
}

BIO *BIO_new_file(const char *filename, const char *mode)
{
	FILE *fp;

	if (!(fp = fopen(filename, mode))) {
		error_print();
		return NULL;
	}
	return fp;
}

int BIO_read(BIO *bio, void *buf, int len)
{
	size_t n;

	n = fread(buf, 1, len, bio);

	return (int)n;
}

int BIO_write(BIO *bio, const void *buf, int len)
{
	size_t n;

	n = fwrite(buf, 1, len, bio);

	return (int)n;
}


// FIXME: 这个函数的功能是什么？是怎么用的？
int BIO_pending(BIO *bio)
{
	ftell(bio);
	rewind(bio);
	return 1;
}

int BIO_reset(BIO *bio)
{
	rewind(bio);
	return 1;
}

int BIO_free(BIO *bio)
{
	if (bio) {
		fclose(bio);
	}
	return 1;
}

// FIXME
int BIO_get_mem_data(BIO *bio, unsigned char **pp)
{
	*(pp) = NULL;
	return -1;
}

