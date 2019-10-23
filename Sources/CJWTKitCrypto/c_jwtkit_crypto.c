#include "include/c_jwtkit_crypto.h"

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
int jwtkit_ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
    sig->r = r;
    sig->s = s;
    return 1;
}

const BIGNUM *jwtkit_ECDSA_SIG_get0_r(const ECDSA_SIG *sig) {
    return sig->r;
};

const BIGNUM *jwtkit_ECDSA_SIG_get0_s(const ECDSA_SIG *sig) {
    return sig->s;
};

EVP_MD_CTX *jwtkit_EVP_MD_CTX_new(void) {
    return EVP_MD_CTX_create();
};

void jwtkit_EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
    EVP_MD_CTX_cleanup(ctx);
    free(ctx);
};

HMAC_CTX *jwtkit_HMAC_CTX_new(void) {
    HMAC_CTX *ptr = malloc(sizeof(HMAC_CTX));
    HMAC_CTX_init(ptr);
    return ptr;
};

void jwtkit_HMAC_CTX_free(HMAC_CTX *ctx) {
    HMAC_CTX_cleanup(ctx);
    free(ctx);
};

void jwtkit_RSA_set0_key(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
    rsa->n = n;
    rsa->e = e;
    rsa->d = d;
}
#else
int jwtkit_ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
    return ECDSA_SIG_set0(sig, r, s);
}

const BIGNUM *jwtkit_ECDSA_SIG_get0_r(const ECDSA_SIG *sig) {
    return ECDSA_SIG_get0_r(sig);
};

const BIGNUM *jwtkit_ECDSA_SIG_get0_s(const ECDSA_SIG *sig) {
    return ECDSA_SIG_get0_s(sig);
};

EVP_MD_CTX *jwtkit_EVP_MD_CTX_new(void) {
    return EVP_MD_CTX_new();
};

void jwtkit_EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
    EVP_MD_CTX_free(ctx);
};

HMAC_CTX *jwtkit_HMAC_CTX_new(void) {
    return HMAC_CTX_new();
};

void jwtkit_HMAC_CTX_free(HMAC_CTX *ctx) {
    HMAC_CTX_free(ctx);
};
void jwtkit_RSA_set0_key(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
    RSA_set0_key(rsa, n, e, d);
}
#endif
