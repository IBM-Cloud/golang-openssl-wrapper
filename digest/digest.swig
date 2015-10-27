%module digest

%{
#include <openssl/evp.h>
%}

%include "cmalloc.i"
%include "../include/ossl_typemaps.i"
%include "../include/evp_typ.i"
%apply char *CHARBUF {unsigned char *outbuf};

/*
 * Constants
 */

#define EVP_MAX_MD_SIZE                 64

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

int EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in);

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
%typemap(gotype) const void *d %{string%}
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *outbuf, unsigned int *s);

/*
 * With these functions, ctx does not need to be initialized, and EVP_DigestFinal
 * cleans up the context as well, so you do not need to call _cleanup or _destroy
 * on it.
 */
int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *outbuf, unsigned int *s);

/*
 * Return digest and block sizes
 */
int EVP_MD_size(const EVP_MD *md);
int EVP_MD_block_size(const EVP_MD *md);
int EVP_MD_CTX_size(EVP_MD_CTX *ctx);
int EVP_MD_CTX_block_size(EVP_MD_CTX *ctx);

/* FIPS-approved digest/hash algorithms */
const EVP_MD *EVP_sha(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);

/* Digest/hash algos not allowed under FIPS */
const EVP_MD *EVP_md5(void);