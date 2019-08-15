#include "include/c_jwtkit_crypto.h"

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
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
#else
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
#endif
