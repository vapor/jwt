#ifndef C_JWTKIT_OPENSSL_H
#define C_JWTKIT_OPENSSL_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

EVP_MD_CTX *jwtkit_EVP_MD_CTX_new(void);
void jwtkit_EVP_MD_CTX_free(EVP_MD_CTX *ctx);
HMAC_CTX *jwtkit_HMAC_CTX_new(void);
void jwtkit_HMAC_CTX_free(HMAC_CTX *ctx);
int jwtkit_ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
const BIGNUM *jwtkit_ECDSA_SIG_get0_r(const ECDSA_SIG *sig);
const BIGNUM *jwtkit_ECDSA_SIG_get0_s(const ECDSA_SIG *sig);
void jwtkit_RSA_set0_key(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d);
#endif
