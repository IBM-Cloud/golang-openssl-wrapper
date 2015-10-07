%module digest

%{
#include <openssl/evp.h>
%}

%include "typemaps.i"
%include "cmalloc.i"
%include "../include/ossl_typemaps.i"
%include "../include/evp_typ.i"

// %malloc(EVP_MD_CTX)
// %free(EVP_MD_CTX)
%allocators(EVP_MD_CTX)
void EVP_MD_CTX_init(EVP_MD_CTX *ctx);
EVP_MD_CTX *EVP_MD_CTX_create(void);

int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx);
/*
 * EVP_MD_CTX_destroy() should *only* be used on a context created
 * using EVP_MD_CTX_create().  The alternative is to create thus:
 *
 * ctx := Malloc_EVP_MD_CTX
 * EVP_MD_CTX_init(ctx)
 *
 * You may then deallocate/free thus:
 *
 * EVP_MD_CTX_cleanup(ctx)
 * Free_EVP_MD_CTX(ctx)
 */
void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);

/* FIPS-approved digest/hash algorithms */
const EVP_MD *EVP_sha(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);