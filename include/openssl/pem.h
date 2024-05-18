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

#ifdef __cplusplus
extern "C" {
#endif


#define pem_password_cb	void
typedef int (*pem_password_callback)(char *buf, int size, int rwflag, void *u);


DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u);

EVP_PKEY *PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x);



EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bio, EVP_PKEY **pkey, pem_password_cb *cb, void *pass);


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
#define PEM_read_bio_X509(bio,outpp,password_cb,args)		\
({								\
	X509 *ret = (X509 *)malloc(sizeof(*ret));		\
	assert((outpp) == NULL);				\
	if (ret) {						\
		ret->d = (uint8_t *)malloc(X509_MAX_SIZE);	\
		if (ret->d) {					\
			if (x509_cert_from_pem(ret->d, &ret->dlen, X509_MAX_SIZE, bio) != 1) { \
				printf("x509_cert_from_pem error\n");	\
				free(ret->d);			\
				free(ret);			\
				ret = NULL;			\
			}					\
		} else {					\
			printf("mallo error\n");		\
			free(ret);				\
			ret = NULL;				\
		}						\
	}							\
	printf("PEM_read_bio_X509 OK %d\n", ret != NULL);	\
	ret;							\
})
#define PEM_read_bio_X509_AUX(bio,outpp,password_cb,args) \
	PEM_read_bio_X509(bio,outpp,password_cb,args)

#define PEM_write_bio_X509(bio,x509) \
	(x509_cert_to_pem((x509)->d,(x509)->dlen,(bio)) == 1 ? 1 : 0)




#ifdef __cplusplus
}
#endif
#endif
