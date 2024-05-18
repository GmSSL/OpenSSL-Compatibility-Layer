/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OPENSSL_DH_H
#define OPENSSL_DH_H


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	int a;
} DH;

void DH_free(DH *);



#ifdef __cplusplus
}
#endif
#endif
