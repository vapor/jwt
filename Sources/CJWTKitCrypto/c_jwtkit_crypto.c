#include "include/c_jwtkit_crypto.h"

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
EVP_MD_CTX *EVP_MD_CTX_new(void) {
    return EVP_MD_CTX_create();
};

void EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
    EVP_MD_CTX_cleanup(ctx);
    free(ctx);
};

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
    r->n = n;
    r->e = e;
    r->d = d;
    return 0;
};

HMAC_CTX *HMAC_CTX_new(void) {
    HMAC_CTX *ptr = malloc(sizeof(HMAC_CTX));
    HMAC_CTX_init(ptr);
    return ptr;
};

void HMAC_CTX_free(HMAC_CTX *ctx) {
    HMAC_CTX_cleanup(ctx);
    free(ctx);
};
#endif
