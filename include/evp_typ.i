%{
#include <openssl/engine.h>
#ifndef HEADER_ENVELOPE_H
#include <openssl.evp.h>
#endif
%}
/*
 * From openssl/engine.h
 */

typedef struct engine_st ENGINE;

/*
 * From openssl/evp.h
 */

typedef struct env_md_st EVP_MD;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

typedef struct env_md_ctx_st {
    const EVP_MD *digest;
    ENGINE *engine;             /* functional reference if 'digest' is
                                 * ENGINE-provided */
    unsigned long flags;
    void *md_data;
    /* Public key context for sign/verify */
    EVP_PKEY_CTX *pctx;
    /* Update function: usually copied from EVP_MD */
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
} EVP_MD_CTX;