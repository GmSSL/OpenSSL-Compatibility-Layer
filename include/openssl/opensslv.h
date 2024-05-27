/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OPENSSL_OPENSSLV_H
#define OPENSSL_OPENSSLV_H

#include <gmssl/version.h>

#ifdef __cplusplus
extern "C" {
#endif


#define GMSSL_OCL_VERSION_STR	"GmSSL OCL 0.8.1"

#define OPENSSL_VERSION_NUMBER	0x30000000L
#define OPENSSL_VERSION_TEXT	GMSSL_VERSION_STR
#define OpenSSL_version(num)	GMSSL_VERSION_STR
#define SSLeay_version(num)	GMSSL_VERSION_STR

#ifdef __cplusplus
}
#endif
#endif
