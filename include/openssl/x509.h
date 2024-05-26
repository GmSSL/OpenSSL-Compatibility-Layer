/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OPENSSL_X509_H
#define OPENSSL_X509_H

#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif


#define X509_MAX_SIZE (64*1024)

typedef struct {
	uint8_t *d;
	size_t dlen;
} X509_NAME;

int X509_NAME_digest(const X509_NAME *name, const EVP_MD *md, unsigned char *dgst, unsigned int *dgstlen);


int X509_NAME_print_ex(BIO *bio, const X509_NAME *name, int indent, unsigned long flags);


# define XN_FLAG_SEP_MASK        (0xf << 16)
# define XN_FLAG_COMPAT          0/* Traditional; use old X509_NAME_print */
# define XN_FLAG_SEP_COMMA_PLUS  (1 << 16)/* RFC2253 ,+ */
# define XN_FLAG_SEP_CPLUS_SPC   (2 << 16)/* ,+ spaced: more readable */
# define XN_FLAG_SEP_SPLUS_SPC   (3 << 16)/* ;+ spaced */
# define XN_FLAG_SEP_MULTILINE   (4 << 16)/* One line per field */
# define XN_FLAG_DN_REV          (1 << 20)/* Reverse DN order */
# define XN_FLAG_FN_MASK         (0x3 << 21)
# define XN_FLAG_FN_SN           0/* Object short name */
# define XN_FLAG_FN_LN           (1 << 21)/* Object long name */
# define XN_FLAG_FN_OID          (2 << 21)/* Always use OIDs */
# define XN_FLAG_FN_NONE         (3 << 21)/* No field names */
# define XN_FLAG_SPC_EQ          (1 << 23)/* Put spaces round '=' */
# define XN_FLAG_DUMP_UNKNOWN_FIELDS (1 << 24)
# define XN_FLAG_FN_ALIGN        (1 << 25)/* Align field names to 20 */
# define ASN1_STRFLGS_RFC2253 0
# define XN_FLAG_RFC2253 (ASN1_STRFLGS_RFC2253 | \
                        XN_FLAG_SEP_COMMA_PLUS | \
                        XN_FLAG_DN_REV | \
                        XN_FLAG_FN_SN | \
                        XN_FLAG_DUMP_UNKNOWN_FIELDS)
# define XN_FLAG_ONELINE (ASN1_STRFLGS_RFC2253 | \
                        ASN1_STRFLGS_ESC_QUOTE | \
                        XN_FLAG_SEP_CPLUS_SPC | \
                        XN_FLAG_SPC_EQ | \
                        XN_FLAG_FN_SN)
# define XN_FLAG_MULTILINE (ASN1_STRFLGS_ESC_CTRL | \
                        ASN1_STRFLGS_ESC_MSB | \
                        XN_FLAG_SEP_MULTILINE | \
                        XN_FLAG_SPC_EQ | \
                        XN_FLAG_FN_LN | \
                        XN_FLAG_FN_ALIGN)



char *X509_NAME_oneline(const X509_NAME *mame, char *buf, int buflen);


#define STACK_OF(TYPE) STACK_OF_##TYPE


#define STACK_OF_X509_NAME_MAX_NUM 16

typedef struct {
	X509_NAME values[16];
	int top;
} STACK_OF_X509_NAME;

int sk_X509_NAME_num(const STACK_OF(X509_NAME) *sk);
X509_NAME *sk_X509_NAME_value(const STACK_OF(X509_NAME) *sk, int idx);


typedef struct {
	uint8_t *d;
	size_t dlen;
	ASN1_INTEGER serial;
	X509_NAME issuer;
	time_t not_before;
	time_t not_after;
	X509_NAME subject;
} X509;

X509 *X509_new(void);
void X509_free(X509 *x509);

// `X509_get_serialNumber` return an internal pointer of `x509` and MUST NOT be freed.
ASN1_INTEGER *X509_get_serialNumber(X509 *x509);

// `X509_get_subject_name` return an internal pointer of `x509` and MUST NOT be freed.
X509_NAME *X509_get_subject_name(const X509 *x509);

// `X509_get_issuer_name` return an internal pointer of `x509` and MUST NOT be freed.
X509_NAME *X509_get_issuer_name(const X509 *x509);

// `X509_get0_notBefore` return an internal pointer of `x509` and MUST NOT be freed.
const ASN1_TIME *X509_get0_notBefore(const X509 *x509);

// `X509_get0_notAfter` return an internal pointer of `x509` and MUST NOT be freed.
const ASN1_TIME *X509_get0_notAfter(const X509 *x509);

int X509_check_host(X509 *x509, const char *name, size_t namelen, unsigned int flags, char **peername);


int X509_digest(const X509 *x509, const EVP_MD *md, unsigned char *dgst, unsigned int *dgstlen);



#define X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT 0x01


// Nginx use `ex_data` to save the DER raw_data or filename into `X509` object
int X509_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int X509_set_ex_data(X509 *x509, int idx, void *arg);
void *X509_get_ex_data(const X509 *x509, int idx);


const char *X509_verify_cert_error_string(long n);


#define STACK_OF_X509_MAX_NUM 16

typedef struct {
	X509 values[STACK_OF_X509_MAX_NUM];
	int top;
} STACK_OF_X509;

STACK_OF(X509) *sk_X509_new_null();



int sk_X509_num(const STACK_OF(X509) *sk);

int  sk_X509_push(STACK_OF(X509) *sk, const X509 *x509);
void sk_X509_pop_free(STACK_OF(X509) *sk, void (*func)(X509 *));


typedef void X509_STORE;
typedef void X509_STORE_CTX;

// used in ngx_ssl_verify_callback to save the verification info
// If Nginx is not configured `--with-debug`, i.e. define `NGX_DEBUG`, these `X509_STORE_CTX_` functions will not called
void *X509_STORE_CTX_get_ex_data(const X509_STORE_CTX *d, int idx);
X509 *X509_STORE_CTX_get_current_cert(const X509_STORE_CTX *ctx);
int   X509_STORE_CTX_get_error(const X509_STORE_CTX *ctx);
int   X509_STORE_CTX_get_error_depth(const X509_STORE_CTX *ctx);



#ifdef __cplusplus
}
#endif
#endif
