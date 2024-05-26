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
#include <openssl/bio.h>


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

// BIO_write() returns -2 if the "write" operation is not implemented by the BIO or -1 on other errors.
// Otherwise it returns the number of bytes written.  This may be 0 if the BIO b is NULL or dlen <= 0.
int BIO_write(BIO *bio, const void *buf, int len)
{
	size_t n;

	n = fwrite(buf, 1, len, bio);

	return (int)n;
}

// `BIO_pending` return the pending data size in the internal buffer.
// When `bio` is written, the `BIO_pending` result is the written size.
// As `FILE *` in C lang share the same read/write pointer, `fread` can read nothing after `fwrite`
// So this implementation rewind file ptr
int BIO_pending(BIO *bio)
{
	int ret;
	if (!bio) {
		error_print();
		return -1; // from OpenSSL: BIO_pending() and BIO_wpending() return negative value or 0 on error.
	}

	ret = (int)ftell(bio);
	rewind(bio);
	return ret;
}

int BIO_reset(BIO *bio)
{
	if (!bio) {
		error_print();
		return 0;
	}
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

// Nginx call `ASN1_TIME_print` to print not_before, not_after into `bio`
// And then use `BIO_get_mem_data` to get the string ptr, and then parse the string with `ngx_parse_http_time`
// But as in OCL the BIO is a FILE, so it can not return a buffer ptr.
int BIO_get_mem_data(BIO *bio, char **pp)
{
	if (!bio || !pp) {
		error_print();
		return 0;
	}
	*(pp) = NULL;
	return 1;
}

