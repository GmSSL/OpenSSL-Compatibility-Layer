/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OPENSSL_SSL_H
#define OPENSSL_SSL_H

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/dh.h>
#include <openssl/pem.h>

#include <gmssl/tls.h>

#ifdef __cplusplus
extern "C" {
#endif


int OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings);


typedef void SSL_METHOD;

const SSL_METHOD *SSLv23_method(void);


typedef TLS_CTX		SSL_CTX;
typedef TLS_CONNECT	SSL;

// init TLS_CTX as 'server' by default
SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
void SSL_CTX_free(SSL_CTX *ctx);

int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x509);


int _SSL_CTX_set0_chain(SSL_CTX *ctx, STACK_OF(X509) *sk);
#define SSL_CTX_set0_chain(ctx,sk) _SSL_CTX_set0_chain(ctx,sk)


int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);
long SSL_CTX_get_timeout(SSL_CTX *ctx);

// the origina `SSL_CTX_set1_group_list` is a macro of `SSL_CTX_ctrl`
int _SSL_CTX_set1_group_list(SSL_CTX *ctx, char *list);
#define SSL_CTX_set1_curves_list(ctx,list) SSL_CTX_set1_group_list(ctx,list)
#define SSL_CTX_set1_group_list(ctx,list) _SSL_CTX_set1_group_list(ctx,list)



// called by ngx_ssl_session_id_context
STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *ctx);


// nginx-1.18
long _SSL_CTX_set_tmp_dh(SSL_CTX *ctx, DH *dh);
#define SSL_CTX_set_tmp_dh(ctx,dh) _SSL_CTX_set_tmp_dh(ctx,dh)


int SSL_CTX_set0_tmp_dh_pkey(SSL_CTX *ctx, EVP_PKEY *pkey); // function


int  SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int  SSL_CTX_set_ex_data(SSL_CTX *ctx, int idx, void *arg);
void *SSL_CTX_get_ex_data(const SSL_CTX *d, int idx);


typedef int SSL_SESSION;

#define SSL_SESS_CACHE_OFF			0x0000
#define SSL_SESS_CACHE_CLIENT			0x0001
#define SSL_SESS_CACHE_SERVER			0x0002
#define SSL_SESS_CACHE_BOTH			(SSL_SESS_CACHE_CLIENT|SSL_SESS_CACHE_SERVER)
#define SSL_SESS_CACHE_NO_AUTO_CLEAR		0x0080
#define SSL_SESS_CACHE_NO_INTERNAL_LOOKUP	0x0100
#define SSL_SESS_CACHE_NO_INTERNAL_STORE	0x0200
#define SSL_SESS_CACHE_NO_INTERNAL		(SSL_SESS_CACHE_NO_INTERNAL_LOOKUP|SSL_SESS_CACHE_NO_INTERNAL_STORE)
#define SSL_SESS_CACHE_UPDATE_TIME		0x0400


int SSL_set_session(SSL *ssl, SSL_SESSION *session);
int SSL_session_reused(const SSL *ssl);
SSL_SESSION *SSL_get1_session(SSL *ssl);
SSL_SESSION *SSL_get0_session(const SSL *ssl);


void SSL_SESSION_free(SSL_SESSION *session);
const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s, unsigned int *len);
int i2d_SSL_SESSION(SSL_SESSION *in, unsigned char **pp);
SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp, long length);




#define SSL_SENT_SHUTDOWN 2
#define SSL_RECEIVED_SHUTDOWN 1
#define SSL_CB_ACCEPT_LOOP 1



SSL *SSL_new(SSL_CTX *ctx);
void SSL_free(SSL *ssl);
int  SSL_is_server(const SSL *ssl);
const char *SSL_get_version(const SSL *ssl);
const char *SSL_get_cipher_name(const SSL *s);
char *SSL_get_shared_ciphers(const SSL *s, char *buf, int size);
void SSL_set_connect_state(SSL *ssl);
void SSL_set_accept_state(SSL *ssl);
int  SSL_set_fd(SSL *ssl, int fd);
int  SSL_do_handshake(SSL *ssl);
int  SSL_read(SSL *ssl, void *buf, int num);
int  SSL_write(SSL *ssl, const void *buf, int num);
int  SSL_in_init(const SSL *ssl);
void SSL_set_quiet_shutdown(SSL *ssl, int mode);
void SSL_set_shutdown(SSL *ssl, int mode);
int  SSL_get_shutdown(const SSL *ssl);
int  SSL_shutdown(SSL *ssl);
int  SSL_get_error(const SSL *ssl, int ret);

int SSL_get_ex_new_index(long argl, void *argp,
	CRYPTO_EX_new *new_func,
	CRYPTO_EX_dup *dup_func,
	CRYPTO_EX_free *free_func);
int SSL_set_ex_data(SSL *ssl, int idx, void *arg);
void *SSL_get_ex_data(const SSL *ssl, int idx);



# define SSL_ERROR_NONE                  0
# define SSL_ERROR_SSL                   1
# define SSL_ERROR_WANT_READ             2
# define SSL_ERROR_WANT_WRITE            3
# define SSL_ERROR_WANT_X509_LOOKUP      4
# define SSL_ERROR_SYSCALL               5
# define SSL_ERROR_ZERO_RETURN           6
# define SSL_ERROR_WANT_CONNECT          7
# define SSL_ERROR_WANT_ACCEPT           8
# define SSL_ERROR_WANT_ASYNC            9
# define SSL_ERROR_WANT_ASYNC_JOB       10
# define SSL_ERROR_WANT_CLIENT_HELLO_CB 11
# define SSL_ERROR_WANT_RETRY_VERIFY    12


long _SSL_CTX_set_session_cache_mode(SSL_CTX *ctx, long mode);
#define SSL_CTX_set_session_cache_mode(ctx,mode) _SSL_CTX_set_session_cache_mode(ctx,mode)
int  SSL_CTX_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid_ctx, unsigned int sid_ctx_len); // func
void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx, int (*new_session_cb)(SSL *, SSL_SESSION *)); // func
void SSL_CTX_sess_set_get_cb(SSL_CTX *ctx, SSL_SESSION *(*get_session_cb)(SSL *, const unsigned char *, int, int *));
void SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx, void (*remove_session_cb)(SSL_CTX *ctx, SSL_SESSION *));

long _SSL_CTX_sess_set_cache_size(SSL_CTX *ctx, long t);
#define SSL_CTX_sess_set_cache_size(ctx,t) _SSL_CTX_sess_set_cache_size(ctx,t) 


int SSL_CTX_remove_session(SSL_CTX *ctx, SSL_SESSION *c);


// Nginx use `SSL_CTX_set_info_callback` to change the SSL handshake buffer size
// Nginx use SSL_get_rbio(ssl) != SSL_get_wbio(ssl) to check if current state is handshake
// But GmSSL does not use FILE as SSL/TLS bio, nor GmSSL support caller-defined buffer size
// So `SSL_CTX_set_info_callback` and `BIO_set_write_buffer_size` will do nothing
// `SSL_get_rbio` and `SSL_get_wbio` will return NULL
void SSL_CTX_set_info_callback(SSL_CTX *ctx,
	void (*callback) (const SSL *ssl, int type, int val));
BIO *SSL_get_rbio(const SSL *ssl);
BIO *SSL_get_wbio(const SSL *ssl);
long BIO_set_write_buffer_size(BIO *bio, long size);


typedef void SSL_CIPHER;

const SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl);
char *SSL_CIPHER_description(const SSL_CIPHER *cipher, char *buf, int size);





long SSL_CTX_set_timeout(SSL_CTX *ctx, long timeout_seconds);
int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);


// GmSSL OCL does not support options, only some SSL_OP_ options are listed here to make compile success
#define SSL_OP_NO_COMPRESSION	1
#define SSL_OP_NO_RENEGOTIATION	1

#define SSL_OP_SINGLE_DH_USE	1
#define SSL_OP_SINGLE_ECDH_USE	1

#define SSL_OP_NO_SSLv2		1
#define SSL_OP_NO_SSLv3		1
#define SSL_OP_NO_TLSv1		1
#define SSL_OP_NO_SSLv2		1
#define SSL_OP_NO_SSLv3		1
#define SSL_OP_NO_TLSv1		1

#define SSL_OP_CIPHER_SERVER_PREFERENCE 1


uint64_t SSL_CTX_set_options(SSL_CTX *ctx, uint64_t options);
uint64_t SSL_CTX_clear_options(SSL_CTX *ctx, uint64_t options);
uint64_t SSL_set_options(SSL *ssl, uint64_t options);
uint64_t SSL_clear_options(SSL *ssl, uint64_t options);

long SSL_CTX_set_mode(SSL_CTX *ctx, long mode);
int SSL_CTX_set_min_proto_version(SSL_CTX *ctx, int version);
int SSL_CTX_set_max_proto_version(SSL_CTX *ctx, int version);
void SSL_CTX_set_cert_cb(SSL_CTX *c, int (*cert_cb)(SSL *ssl, void *arg), void *arg);

long SSL_CTX_set_read_ahead(SSL_CTX *ctx, int yes);


// client verify CA
void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth);
int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath);
STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file);
void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *list);


X509 *SSL_get1_peer_certificate(const SSL *ssl);
#define SSL_get_peer_certificate(ssl) SSL_get1_peer_certificate(ssl)


long SSL_get_verify_result(const SSL *ssl);



# define SSL_VERIFY_NONE                 0x00
# define SSL_VERIFY_PEER                 0x01
# define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
# define SSL_VERIFY_CLIENT_ONCE          0x04
# define SSL_VERIFY_POST_HANDSHAKE       0x08

int SSL_get_ex_data_X509_STORE_CTX_idx(void);



typedef int (*SSL_verify_cb)(int preverify_ok, X509_STORE_CTX *x509_ctx);

void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb verify_callback);
int SSL_CTX_get_verify_mode(const SSL_CTX *ctx);

X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx);


#undef SSL_R_CERT_CB_ERROR

int SSL_use_certificate(SSL *ssl, X509 *x509);
int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey);
int SSL_set0_chain(SSL *ssl, STACK_OF(X509) *sk);


// from <openssl/sslerr.h>
# define SSL_R_APPLICATION_DATA_AFTER_CLOSE_NOTIFY        291
# define SSL_R_APP_DATA_IN_HANDSHAKE                      100
# define SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT 272
# define SSL_R_AT_LEAST_TLS_1_2_NEEDED_IN_SUITEB_MODE     158
# define SSL_R_BAD_CHANGE_CIPHER_SPEC                     103
# define SSL_R_BAD_CIPHER                                 186
# define SSL_R_BAD_DATA                                   390
# define SSL_R_BAD_DATA_RETURNED_BY_CALLBACK              106
# define SSL_R_BAD_DECOMPRESSION                          107
# define SSL_R_BAD_DH_VALUE                               102
# define SSL_R_BAD_DIGEST_LENGTH                          111
# define SSL_R_BAD_EARLY_DATA                             233
# define SSL_R_BAD_ECC_CERT                               304
# define SSL_R_BAD_ECPOINT                                306
# define SSL_R_BAD_EXTENSION                              110
# define SSL_R_BAD_HANDSHAKE_LENGTH                       332
# define SSL_R_BAD_HANDSHAKE_STATE                        236
# define SSL_R_BAD_HELLO_REQUEST                          105
# define SSL_R_BAD_HRR_VERSION                            263
# define SSL_R_BAD_KEY_SHARE                              108
# define SSL_R_BAD_KEY_UPDATE                             122
# define SSL_R_BAD_LEGACY_VERSION                         292
# define SSL_R_BAD_LENGTH                                 271
# define SSL_R_BAD_PACKET                                 240
# define SSL_R_BAD_PACKET_LENGTH                          115
# define SSL_R_BAD_PROTOCOL_VERSION_NUMBER                116
# define SSL_R_BAD_PSK                                    219
# define SSL_R_BAD_PSK_IDENTITY                           114
# define SSL_R_BAD_RECORD_TYPE                            443
# define SSL_R_BAD_RSA_ENCRYPT                            119
# define SSL_R_BAD_SIGNATURE                              123
# define SSL_R_BAD_SRP_A_LENGTH                           347
# define SSL_R_BAD_SRP_PARAMETERS                         371
# define SSL_R_BAD_SRTP_MKI_VALUE                         352
# define SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST           353
# define SSL_R_BAD_SSL_FILETYPE                           124
# define SSL_R_BAD_VALUE                                  384
# define SSL_R_BAD_WRITE_RETRY                            127
# define SSL_R_BINDER_DOES_NOT_VERIFY                     253
# define SSL_R_BIO_NOT_SET                                128
# define SSL_R_BLOCK_CIPHER_PAD_IS_WRONG                  129
# define SSL_R_BN_LIB                                     130
# define SSL_R_CALLBACK_FAILED                            234
# define SSL_R_CANNOT_CHANGE_CIPHER                       109
# define SSL_R_CANNOT_GET_GROUP_NAME                      299
# define SSL_R_CA_DN_LENGTH_MISMATCH                      131
# define SSL_R_CA_KEY_TOO_SMALL                           397
# define SSL_R_CA_MD_TOO_WEAK                             398
# define SSL_R_CCS_RECEIVED_EARLY                         133
# define SSL_R_CERTIFICATE_VERIFY_FAILED                  134
# define SSL_R_CERT_CB_ERROR                              377
# define SSL_R_CERT_LENGTH_MISMATCH                       135
# define SSL_R_CIPHERSUITE_DIGEST_HAS_CHANGED             218
# define SSL_R_CIPHER_CODE_WRONG_LENGTH                   137
# define SSL_R_CLIENTHELLO_TLSEXT                         226
# define SSL_R_COMPRESSED_LENGTH_TOO_LONG                 140
# define SSL_R_COMPRESSION_DISABLED                       343
# define SSL_R_COMPRESSION_FAILURE                        141
# define SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE    307
# define SSL_R_COMPRESSION_LIBRARY_ERROR                  142
# define SSL_R_CONNECTION_TYPE_NOT_SET                    144
# define SSL_R_CONTEXT_NOT_DANE_ENABLED                   167
# define SSL_R_COOKIE_GEN_CALLBACK_FAILURE                400
# define SSL_R_COOKIE_MISMATCH                            308
# define SSL_R_COPY_PARAMETERS_FAILED                     296
# define SSL_R_CUSTOM_EXT_HANDLER_ALREADY_INSTALLED       206
# define SSL_R_DANE_ALREADY_ENABLED                       172
# define SSL_R_DANE_CANNOT_OVERRIDE_MTYPE_FULL            173
# define SSL_R_DANE_NOT_ENABLED                           175
# define SSL_R_DANE_TLSA_BAD_CERTIFICATE                  180
# define SSL_R_DANE_TLSA_BAD_CERTIFICATE_USAGE            184
# define SSL_R_DANE_TLSA_BAD_DATA_LENGTH                  189
# define SSL_R_DANE_TLSA_BAD_DIGEST_LENGTH                192
# define SSL_R_DANE_TLSA_BAD_MATCHING_TYPE                200
# define SSL_R_DANE_TLSA_BAD_PUBLIC_KEY                   201
# define SSL_R_DANE_TLSA_BAD_SELECTOR                     202
# define SSL_R_DANE_TLSA_NULL_DATA                        203
# define SSL_R_DATA_BETWEEN_CCS_AND_FINISHED              145
# define SSL_R_DATA_LENGTH_TOO_LONG                       146
# define SSL_R_DECRYPTION_FAILED                          147
# define SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC        281
# define SSL_R_DH_KEY_TOO_SMALL                           394
# define SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG            148
# define SSL_R_DIGEST_CHECK_FAILED                        149
# define SSL_R_DTLS_MESSAGE_TOO_BIG                       334
# define SSL_R_DUPLICATE_COMPRESSION_ID                   309
# define SSL_R_ECC_CERT_NOT_FOR_SIGNING                   318
# define SSL_R_ECDH_REQUIRED_FOR_SUITEB_MODE              374
# define SSL_R_EE_KEY_TOO_SMALL                           399
# define SSL_R_EMPTY_SRTP_PROTECTION_PROFILE_LIST         354
# define SSL_R_ENCRYPTED_LENGTH_TOO_LONG                  150
# define SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST              151
# define SSL_R_ERROR_SETTING_TLSA_BASE_DOMAIN             204
# define SSL_R_EXCEEDS_MAX_FRAGMENT_SIZE                  194
# define SSL_R_EXCESSIVE_MESSAGE_SIZE                     152
# define SSL_R_EXTENSION_NOT_RECEIVED                     279
# define SSL_R_EXTRA_DATA_IN_MESSAGE                      153
# define SSL_R_EXT_LENGTH_MISMATCH                        163
# define SSL_R_FAILED_TO_INIT_ASYNC                       405
# define SSL_R_FRAGMENTED_CLIENT_HELLO                    401
# define SSL_R_GOT_A_FIN_BEFORE_A_CCS                     154
# define SSL_R_HTTPS_PROXY_REQUEST                        155
# define SSL_R_HTTP_REQUEST                               156
# define SSL_R_ILLEGAL_POINT_COMPRESSION                  162
# define SSL_R_ILLEGAL_SUITEB_DIGEST                      380
# define SSL_R_INAPPROPRIATE_FALLBACK                     373
# define SSL_R_INCONSISTENT_COMPRESSION                   340
# define SSL_R_INCONSISTENT_EARLY_DATA_ALPN               222
# define SSL_R_INCONSISTENT_EARLY_DATA_SNI                231
# define SSL_R_INCONSISTENT_EXTMS                         104
# define SSL_R_INSUFFICIENT_SECURITY                      241
# define SSL_R_INVALID_ALERT                              205
# define SSL_R_INVALID_CCS_MESSAGE                        260
# define SSL_R_INVALID_CERTIFICATE_OR_ALG                 238
# define SSL_R_INVALID_COMMAND                            280
# define SSL_R_INVALID_COMPRESSION_ALGORITHM              341
# define SSL_R_INVALID_CONFIG                             283
# define SSL_R_INVALID_CONFIGURATION_NAME                 113
# define SSL_R_INVALID_CONTEXT                            282
# define SSL_R_INVALID_CT_VALIDATION_TYPE                 212
# define SSL_R_INVALID_KEY_UPDATE_TYPE                    120
# define SSL_R_INVALID_MAX_EARLY_DATA                     174
# define SSL_R_INVALID_NULL_CMD_NAME                      385
# define SSL_R_INVALID_SEQUENCE_NUMBER                    402
# define SSL_R_INVALID_SERVERINFO_DATA                    388
# define SSL_R_INVALID_SESSION_ID                         999
# define SSL_R_INVALID_SRP_USERNAME                       357
# define SSL_R_INVALID_STATUS_RESPONSE                    328
# define SSL_R_INVALID_TICKET_KEYS_LENGTH                 325
# define SSL_R_LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED    333
# define SSL_R_LENGTH_MISMATCH                            159
# define SSL_R_LENGTH_TOO_LONG                            404
# define SSL_R_LENGTH_TOO_SHORT                           160
# define SSL_R_LIBRARY_BUG                                274
# define SSL_R_LIBRARY_HAS_NO_CIPHERS                     161
# define SSL_R_MISSING_DSA_SIGNING_CERT                   165
# define SSL_R_MISSING_ECDSA_SIGNING_CERT                 381
# define SSL_R_MISSING_FATAL                              256
# define SSL_R_MISSING_PARAMETERS                         290
# define SSL_R_MISSING_PSK_KEX_MODES_EXTENSION            310
# define SSL_R_MISSING_RSA_CERTIFICATE                    168
# define SSL_R_MISSING_RSA_ENCRYPTING_CERT                169
# define SSL_R_MISSING_RSA_SIGNING_CERT                   170
# define SSL_R_MISSING_SIGALGS_EXTENSION                  112
# define SSL_R_MISSING_SIGNING_CERT                       221
# define SSL_R_MISSING_SRP_PARAM                          358
# define SSL_R_MISSING_SUPPORTED_GROUPS_EXTENSION         209
# define SSL_R_MISSING_TMP_DH_KEY                         171
# define SSL_R_MISSING_TMP_ECDH_KEY                       311
# define SSL_R_MIXED_HANDSHAKE_AND_NON_HANDSHAKE_DATA     293
# define SSL_R_NOT_ON_RECORD_BOUNDARY                     182
# define SSL_R_NOT_REPLACING_CERTIFICATE                  289
# define SSL_R_NOT_SERVER                                 284
# define SSL_R_NO_APPLICATION_PROTOCOL                    235
# define SSL_R_NO_CERTIFICATES_RETURNED                   176
# define SSL_R_NO_CERTIFICATE_ASSIGNED                    177
# define SSL_R_NO_CERTIFICATE_SET                         179
# define SSL_R_NO_CHANGE_FOLLOWING_HRR                    214
# define SSL_R_NO_CIPHERS_AVAILABLE                       181
# define SSL_R_NO_CIPHERS_SPECIFIED                       183
# define SSL_R_NO_CIPHER_MATCH                            185
# define SSL_R_NO_CLIENT_CERT_METHOD                      331
# define SSL_R_NO_COMPRESSION_SPECIFIED                   187
# define SSL_R_NO_COOKIE_CALLBACK_SET                     287
# define SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER           330
# define SSL_R_NO_METHOD_SPECIFIED                        188
# define SSL_R_NO_PEM_EXTENSIONS                          389
# define SSL_R_NO_PRIVATE_KEY_ASSIGNED                    190
# define SSL_R_NO_PROTOCOLS_AVAILABLE                     191
# define SSL_R_NO_RENEGOTIATION                           339
# define SSL_R_NO_REQUIRED_DIGEST                         324
# define SSL_R_NO_SHARED_CIPHER                           193
# define SSL_R_NO_SHARED_GROUPS                           410
# define SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS             376
# define SSL_R_NO_SRTP_PROFILES                           359
# define SSL_R_NO_SUITABLE_DIGEST_ALGORITHM               297
# define SSL_R_NO_SUITABLE_GROUPS                         295
# define SSL_R_NO_SUITABLE_KEY_SHARE                      101
# define SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM            118
# define SSL_R_NO_VALID_SCTS                              216
# define SSL_R_NO_VERIFY_COOKIE_CALLBACK                  403
# define SSL_R_NULL_SSL_CTX                               195
# define SSL_R_NULL_SSL_METHOD_PASSED                     196
# define SSL_R_OCSP_CALLBACK_FAILURE                      305
# define SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED            197
# define SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED 344
# define SSL_R_OVERFLOW_ERROR                             237
# define SSL_R_PACKET_LENGTH_TOO_LONG                     198
# define SSL_R_PARSE_TLSEXT                               227
# define SSL_R_PATH_TOO_LONG                              270
# define SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE          199
# define SSL_R_PEM_NAME_BAD_PREFIX                        391
# define SSL_R_PEM_NAME_TOO_SHORT                         392
# define SSL_R_PIPELINE_FAILURE                           406
# define SSL_R_POST_HANDSHAKE_AUTH_ENCODING_ERR           278
# define SSL_R_PRIVATE_KEY_MISMATCH                       288
# define SSL_R_PROTOCOL_IS_SHUTDOWN                       207
# define SSL_R_PSK_IDENTITY_NOT_FOUND                     223
# define SSL_R_PSK_NO_CLIENT_CB                           224
# define SSL_R_PSK_NO_SERVER_CB                           225
# define SSL_R_READ_BIO_NOT_SET                           211
# define SSL_R_READ_TIMEOUT_EXPIRED                       312
# define SSL_R_RECORD_LENGTH_MISMATCH                     213
# define SSL_R_RECORD_TOO_SMALL                           298
# define SSL_R_RENEGOTIATE_EXT_TOO_LONG                   335
# define SSL_R_RENEGOTIATION_ENCODING_ERR                 336
# define SSL_R_RENEGOTIATION_MISMATCH                     337
# define SSL_R_REQUEST_PENDING                            285
# define SSL_R_REQUEST_SENT                               286
# define SSL_R_REQUIRED_CIPHER_MISSING                    215
# define SSL_R_REQUIRED_COMPRESSION_ALGORITHM_MISSING     342
# define SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING           345
# define SSL_R_SCT_VERIFICATION_FAILED                    208
# define SSL_R_SERVERHELLO_TLSEXT                         275
# define SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED           277
# define SSL_R_SHUTDOWN_WHILE_IN_INIT                     407
# define SSL_R_SIGNATURE_ALGORITHMS_ERROR                 360
# define SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE      220
# define SSL_R_SRP_A_CALC                                 361
# define SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES           362
# define SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG      363
# define SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE            364
# define SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH       232
# define SSL_R_SSL3_EXT_INVALID_SERVERNAME                319
# define SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE           320
# define SSL_R_SSL3_SESSION_ID_TOO_LONG                   300
# define SSL_R_SSLV3_ALERT_BAD_CERTIFICATE                1042
# define SSL_R_SSLV3_ALERT_BAD_RECORD_MAC                 1020
# define SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED            1045
# define SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED            1044
# define SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN            1046
# define SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE          1030
# define SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE              1040
# define SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER              1047
# define SSL_R_SSLV3_ALERT_NO_CERTIFICATE                 1041
# define SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE             1010
# define SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE        1043
# define SSL_R_SSL_COMMAND_SECTION_EMPTY                  117
# define SSL_R_SSL_COMMAND_SECTION_NOT_FOUND              125
# define SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION         228
# define SSL_R_SSL_HANDSHAKE_FAILURE                      229
# define SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS                 230
# define SSL_R_SSL_NEGATIVE_LENGTH                        372
# define SSL_R_SSL_SECTION_EMPTY                          126
# define SSL_R_SSL_SECTION_NOT_FOUND                      136
# define SSL_R_SSL_SESSION_ID_CALLBACK_FAILED             301
# define SSL_R_SSL_SESSION_ID_CONFLICT                    302
# define SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG            273
# define SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH              303
# define SSL_R_SSL_SESSION_ID_TOO_LONG                    408
# define SSL_R_SSL_SESSION_VERSION_MISMATCH               210
# define SSL_R_STILL_IN_INIT                              121
# define SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED          1116
# define SSL_R_TLSV13_ALERT_MISSING_EXTENSION             1109
# define SSL_R_TLSV1_ALERT_ACCESS_DENIED                  1049
# define SSL_R_TLSV1_ALERT_DECODE_ERROR                   1050
# define SSL_R_TLSV1_ALERT_DECRYPTION_FAILED              1021
# define SSL_R_TLSV1_ALERT_DECRYPT_ERROR                  1051
# define SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION             1060
# define SSL_R_TLSV1_ALERT_INAPPROPRIATE_FALLBACK         1086
# define SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY          1071
# define SSL_R_TLSV1_ALERT_INTERNAL_ERROR                 1080
# define SSL_R_TLSV1_ALERT_NO_RENEGOTIATION               1100
# define SSL_R_TLSV1_ALERT_PROTOCOL_VERSION               1070
# define SSL_R_TLSV1_ALERT_RECORD_OVERFLOW                1022
# define SSL_R_TLSV1_ALERT_UNKNOWN_CA                     1048
# define SSL_R_TLSV1_ALERT_USER_CANCELLED                 1090
# define SSL_R_TLSV1_BAD_CERTIFICATE_HASH_VALUE           1114
# define SSL_R_TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE      1113
# define SSL_R_TLSV1_CERTIFICATE_UNOBTAINABLE             1111
# define SSL_R_TLSV1_UNRECOGNIZED_NAME                    1112
# define SSL_R_TLSV1_UNSUPPORTED_EXTENSION                1110
# define SSL_R_TLS_ILLEGAL_EXPORTER_LABEL                 367
# define SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST             157
# define SSL_R_TOO_MANY_KEY_UPDATES                       132
# define SSL_R_TOO_MANY_WARN_ALERTS                       409
# define SSL_R_TOO_MUCH_EARLY_DATA                        164
# define SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS             314
# define SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS       239
# define SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES           242
# define SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES          243
# define SSL_R_UNEXPECTED_CCS_MESSAGE                     262
# define SSL_R_UNEXPECTED_END_OF_EARLY_DATA               178
# define SSL_R_UNEXPECTED_EOF_WHILE_READING               294
# define SSL_R_UNEXPECTED_MESSAGE                         244
# define SSL_R_UNEXPECTED_RECORD                          245
# define SSL_R_UNINITIALIZED                              276
# define SSL_R_UNKNOWN_ALERT_TYPE                         246
# define SSL_R_UNKNOWN_CERTIFICATE_TYPE                   247
# define SSL_R_UNKNOWN_CIPHER_RETURNED                    248
# define SSL_R_UNKNOWN_CIPHER_TYPE                        249
# define SSL_R_UNKNOWN_CMD_NAME                           386
# define SSL_R_UNKNOWN_COMMAND                            139
# define SSL_R_UNKNOWN_DIGEST                             368
# define SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE                  250
# define SSL_R_UNKNOWN_PKEY_TYPE                          251
# define SSL_R_UNKNOWN_PROTOCOL                           252
# define SSL_R_UNKNOWN_SSL_VERSION                        254
# define SSL_R_UNKNOWN_STATE                              255
# define SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED       338
# define SSL_R_UNSOLICITED_EXTENSION                      217
# define SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM          257
# define SSL_R_UNSUPPORTED_ELLIPTIC_CURVE                 315
# define SSL_R_UNSUPPORTED_PROTOCOL                       258
# define SSL_R_UNSUPPORTED_SSL_VERSION                    259
# define SSL_R_UNSUPPORTED_STATUS_TYPE                    329
# define SSL_R_USE_SRTP_NOT_NEGOTIATED                    369
# define SSL_R_VERSION_TOO_HIGH                           166
# define SSL_R_VERSION_TOO_LOW                            396
# define SSL_R_WRONG_CERTIFICATE_TYPE                     383
# define SSL_R_WRONG_CIPHER_RETURNED                      261
# define SSL_R_WRONG_CURVE                                378
# define SSL_R_WRONG_SIGNATURE_LENGTH                     264
# define SSL_R_WRONG_SIGNATURE_SIZE                       265
# define SSL_R_WRONG_SIGNATURE_TYPE                       370
# define SSL_R_WRONG_SSL_VERSION                          266
# define SSL_R_WRONG_VERSION_NUMBER                       267
# define SSL_R_X509_LIB                                   268
# define SSL_R_X509_VERIFICATION_SETUP_PROBLEMS           269




#ifdef __cplusplus
}
#endif
#endif
