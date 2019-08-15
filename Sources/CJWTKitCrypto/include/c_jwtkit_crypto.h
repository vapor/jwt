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
int jwtkit_RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
HMAC_CTX *jwtkit_HMAC_CTX_new(void);
void jwtkit_HMAC_CTX_free(HMAC_CTX *ctx);

#endif
