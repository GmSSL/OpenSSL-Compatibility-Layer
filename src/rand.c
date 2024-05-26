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
#include <openssl/rand.h>


int RAND_bytes(unsigned char *buf, int num)
{
	if (!buf) {
		error_print();
		return 0;
	}

	if (rand_bytes(buf, (size_t)num) != 1) {
		error_print();
		return 0;
	}
	return 1;
}
