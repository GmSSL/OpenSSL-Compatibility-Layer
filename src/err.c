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
#include "openssl/err.h"


// 0 means no error
unsigned long ERR_get_error(void)
{
	return 0;
}

unsigned long ERR_peek_error(void)
{
	return 0;
}

unsigned long ERR_peek_last_error(void)
{
	return 0;
}

unsigned long ERR_peek_error_data(const char **data, int *flags)
{
	if (data) *data = NULL;
	if (flags) *flags = 0;
	return 0;
}

unsigned long ERR_peek_error_line_data(const char **file, int *line, const char **data, int *flags)
{
	if (file) *file = NULL;
	if (line) *line = 0;
	if (data) *data = NULL;
	if (flags) *flags = 0;
	return 0;
}

void ERR_error_string_n(unsigned long e, char *buf, size_t len)
{
	buf[0] = 0;
}

void ERR_clear_error(void)
{
}

// Nginx `PEM_read_bio_X509`, when `eof(bio)`, check this to clear error
int ERR_GET_LIB(unsigned long e)
{
	return ERR_LIB_PEM;
}

// Nginx `PEM_read_bio_X509`, when `eof(bio)`, check this to clear error
int ERR_GET_REASON(unsigned long e)
{
	return PEM_R_NO_START_LINE;
}
