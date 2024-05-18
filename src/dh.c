/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdlib.h>
#include <openssl/dh.h>


void DH_free(DH *dh)
{
	if (dh) {
		free(dh);
	}
}
