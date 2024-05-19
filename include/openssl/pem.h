/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OPENSSL_PEM_H
#define OPENSSL_PEM_H

#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef int (pem_password_cb)(char *buf, int size, int rwflag, void *u);

//int pem_password_cb(char *buf, int size, int rwflag, void *u);

EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bio, EVP_PKEY **pkey, pem_password_cb *cb, void *pass);
EVP_PKEY *PEM_read_bio_Parameters(BIO *bio, EVP_PKEY **pkey);

DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u);

/*
 * Nginx 通过`PEM_read_bio_X509_AUX`读取`BIO`中的终端证书，放入`X509`对象，
 * 然后再多次调用`PEM_read_bio_X509`读取`BIO`中后续的中间CA证书，放入`STACK_OF(X509)`对象
 * 最后通过`SSL_CTX_use_certificate`和`SSL_CTX_set0_chain`将所有证书加载到`SSL_CTX`中
 *
 * 在GmSSL中，`TLS_CTX`并没有分别存储终端证书和中间CA证书链，而是放到连续的缓冲中
 * 因此当Nginx配置为从一个连续的PEM文件中读取证书时，不管其中包含单终端证书还是TLCP的双证书
 * 经过这个默认的流程之后，在`TLS_CTX`中都是完整的终端证书链
 * 因此不需要针对TLS/TLCP协议做特殊的证书读取操作
 */



X509 *PEM_read_bio_X509(BIO *bio, X509 **x509, pem_password_cb *cb, void *u);
X509 *PEM_read_bio_X509_AUX(BIO *bio, X509 **x509, pem_password_cb *cb, void *u);
int PEM_write_bio_X509(BIO *bio, X509 *x509);


#ifdef __cplusplus
}
#endif
#endif
