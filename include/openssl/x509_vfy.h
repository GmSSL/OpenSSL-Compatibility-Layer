/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OPENSSL_X509_VFY_H
#define OPENSSL_X509_VFY_H

#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef void X509_LOOKUP_METHOD;
typedef void X509_LOOKUP;


// from openssl/x509_vfy.h of openssl-3.1.4
/* Certificate verify flags */
# ifndef OPENSSL_NO_DEPRECATED_1_1_0
#  define X509_V_FLAG_CB_ISSUER_CHECK             0x0   /* Deprecated */
# endif
/* Use check time instead of current time */
# define X509_V_FLAG_USE_CHECK_TIME              0x2
/* Lookup CRLs */
# define X509_V_FLAG_CRL_CHECK                   0x4
/* Lookup CRLs for whole chain */
# define X509_V_FLAG_CRL_CHECK_ALL               0x8
/* Ignore unhandled critical extensions */
# define X509_V_FLAG_IGNORE_CRITICAL             0x10
/* Disable workarounds for broken certificates */
# define X509_V_FLAG_X509_STRICT                 0x20
/* Enable proxy certificate validation */
# define X509_V_FLAG_ALLOW_PROXY_CERTS           0x40
/* Enable policy checking */
# define X509_V_FLAG_POLICY_CHECK                0x80
/* Policy variable require-explicit-policy */
# define X509_V_FLAG_EXPLICIT_POLICY             0x100
/* Policy variable inhibit-any-policy */
# define X509_V_FLAG_INHIBIT_ANY                 0x200
/* Policy variable inhibit-policy-mapping */
# define X509_V_FLAG_INHIBIT_MAP                 0x400
/* Notify callback that policy is OK */
# define X509_V_FLAG_NOTIFY_POLICY               0x800
/* Extended CRL features such as indirect CRLs, alternate CRL signing keys */
# define X509_V_FLAG_EXTENDED_CRL_SUPPORT        0x1000
/* Delta CRL support */
# define X509_V_FLAG_USE_DELTAS                  0x2000
/* Check self-signed CA signature */
# define X509_V_FLAG_CHECK_SS_SIGNATURE          0x4000
/* Use trusted store first */
# define X509_V_FLAG_TRUSTED_FIRST               0x8000
/* Suite B 128 bit only mode: not normally used */
# define X509_V_FLAG_SUITEB_128_LOS_ONLY         0x10000
/* Suite B 192 bit only mode */
# define X509_V_FLAG_SUITEB_192_LOS              0x20000
/* Suite B 128 bit mode allowing 192 bit algorithms */
# define X509_V_FLAG_SUITEB_128_LOS              0x30000
/* Allow partial chains if at least one certificate is in trusted store */
# define X509_V_FLAG_PARTIAL_CHAIN               0x80000
/*
 * If the initial chain is not trusted, do not attempt to build an alternative
 * chain. Alternate chain checking was introduced in 1.1.0. Setting this flag
 * will force the behaviour to match that of previous versions.
 */
# define X509_V_FLAG_NO_ALT_CHAINS               0x100000
/* Do not check certificate/CRL validity against current time */
# define X509_V_FLAG_NO_CHECK_TIME               0x200000

# define X509_VP_FLAG_DEFAULT                    0x1
# define X509_VP_FLAG_OVERWRITE                  0x2
# define X509_VP_FLAG_RESET_FLAGS                0x4
# define X509_VP_FLAG_LOCKED                     0x8
# define X509_VP_FLAG_ONCE                       0x10

/* Internal use: mask of policy related options */
# define X509_V_FLAG_POLICY_MASK (X509_V_FLAG_POLICY_CHECK \
                                | X509_V_FLAG_EXPLICIT_POLICY \
                                | X509_V_FLAG_INHIBIT_ANY \
                                | X509_V_FLAG_INHIBIT_MAP)


int X509_STORE_set_flags(X509_STORE *store, unsigned long flags);













X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *store, X509_LOOKUP_METHOD *meth);
X509_LOOKUP_METHOD *X509_LOOKUP_file(void);



// `type` :
# define X509_FILETYPE_PEM       1
# define X509_FILETYPE_ASN1      2
# define X509_FILETYPE_DEFAULT   3
int X509_LOOKUP_load_file(X509_LOOKUP *ctx, char *name, long type);



# define X509_V_OK                                       0
# define X509_V_ERR_UNSPECIFIED                          1
# define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT            2
# define X509_V_ERR_UNABLE_TO_GET_CRL                    3
# define X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE     4
# define X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE      5
# define X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY   6
# define X509_V_ERR_CERT_SIGNATURE_FAILURE               7
# define X509_V_ERR_CRL_SIGNATURE_FAILURE                8
# define X509_V_ERR_CERT_NOT_YET_VALID                   9
# define X509_V_ERR_CERT_HAS_EXPIRED                     10
# define X509_V_ERR_CRL_NOT_YET_VALID                    11
# define X509_V_ERR_CRL_HAS_EXPIRED                      12
# define X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD       13
# define X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD        14
# define X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD       15
# define X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD       16
# define X509_V_ERR_OUT_OF_MEM                           17
# define X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT          18
# define X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN            19
# define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY    20
# define X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE      21
# define X509_V_ERR_CERT_CHAIN_TOO_LONG                  22
# define X509_V_ERR_CERT_REVOKED                         23
# define X509_V_ERR_NO_ISSUER_PUBLIC_KEY                 24
# define X509_V_ERR_PATH_LENGTH_EXCEEDED                 25
# define X509_V_ERR_INVALID_PURPOSE                      26
# define X509_V_ERR_CERT_UNTRUSTED                       27
# define X509_V_ERR_CERT_REJECTED                        28
# define X509_V_ERR_SUBJECT_ISSUER_MISMATCH              29
# define X509_V_ERR_AKID_SKID_MISMATCH                   30
# define X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH          31
# define X509_V_ERR_KEYUSAGE_NO_CERTSIGN                 32
# define X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER             33
# define X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION         34
# define X509_V_ERR_KEYUSAGE_NO_CRL_SIGN                 35
# define X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION     36
# define X509_V_ERR_INVALID_NON_CA                       37
# define X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED           38
# define X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE        39
# define X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED       40
# define X509_V_ERR_INVALID_EXTENSION                    41
# define X509_V_ERR_INVALID_POLICY_EXTENSION             42
# define X509_V_ERR_NO_EXPLICIT_POLICY                   43
# define X509_V_ERR_DIFFERENT_CRL_SCOPE                  44
# define X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE        45
# define X509_V_ERR_UNNESTED_RESOURCE                    46
# define X509_V_ERR_PERMITTED_VIOLATION                  47
# define X509_V_ERR_EXCLUDED_VIOLATION                   48
# define X509_V_ERR_SUBTREE_MINMAX                       49
# define X509_V_ERR_APPLICATION_VERIFICATION             50
# define X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE          51
# define X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX        52
# define X509_V_ERR_UNSUPPORTED_NAME_SYNTAX              53
# define X509_V_ERR_CRL_PATH_VALIDATION_ERROR            54
# define X509_V_ERR_PATH_LOOP                            55
# define X509_V_ERR_SUITE_B_INVALID_VERSION              56
# define X509_V_ERR_SUITE_B_INVALID_ALGORITHM            57
# define X509_V_ERR_SUITE_B_INVALID_CURVE                58
# define X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM  59
# define X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED              60
# define X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 61
# define X509_V_ERR_HOSTNAME_MISMATCH                    62
# define X509_V_ERR_EMAIL_MISMATCH                       63
# define X509_V_ERR_IP_ADDRESS_MISMATCH                  64
# define X509_V_ERR_DANE_NO_MATCH                        65
# define X509_V_ERR_EE_KEY_TOO_SMALL                     66
# define X509_V_ERR_CA_KEY_TOO_SMALL                     67
# define X509_V_ERR_CA_MD_TOO_WEAK                       68
# define X509_V_ERR_INVALID_CALL                         69
# define X509_V_ERR_STORE_LOOKUP                         70
# define X509_V_ERR_NO_VALID_SCTS                        71
# define X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION         72
# define X509_V_ERR_OCSP_VERIFY_NEEDED                   73
# define X509_V_ERR_OCSP_VERIFY_FAILED                   74
# define X509_V_ERR_OCSP_CERT_UNKNOWN                    75
# define X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM      76
# define X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH         77
# define X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY    78
# define X509_V_ERR_INVALID_CA                           79
# define X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA           80
# define X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN     81
# define X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA  82
# define X509_V_ERR_ISSUER_NAME_EMPTY                    83
# define X509_V_ERR_SUBJECT_NAME_EMPTY                   84
# define X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER     85
# define X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER       86
# define X509_V_ERR_EMPTY_SUBJECT_ALT_NAME               87
# define X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL       88
# define X509_V_ERR_CA_BCONS_NOT_CRITICAL                89
# define X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL    90
# define X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL      91
# define X509_V_ERR_CA_CERT_MISSING_KEY_USAGE            92
# define X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3         93
# define X509_V_ERR_EC_KEY_EXPLICIT_PARAMS               94


#ifdef __cplusplus
}
#endif
#endif
