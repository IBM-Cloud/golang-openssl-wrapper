/*
 * SWIG interface file for libcrypto
 * Headers referenced here include:
 *	openssl/crypto.h	- core crypto routines
 *	openssl/err.h		- error routines
 *	openssl/evp.h		- high-level OpenSSL API for cryptography
 *	openssl/...
 */
%module crypto
%{
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>

/*
 * Macros for manipulating argument type to EVP_CIPHER_CTX_ctrl()
 */

#define SET_TAG_GCM(ctx, type, arg, ptr) EVP_CIPHER_CTX_ctrl(ctx, type, arg, ptr)
#define GET_TAG_GCM(ctx, type, arg, ptr) EVP_CIPHER_CTX_ctrl(ctx, type, arg, ptr)
%}

// %include "typemaps.i"
%include "../include/ossl_typemaps.i"
%include "../include/evp_typ.i"


/*
 * From openssl/conf.h
 */

/* Functions */

extern void OPENSSL_config(const char *config_name);
extern void OPENSSL_no_config(void);

/*
 * From openssl/crypto.h
 */

/* Functions */

extern int FIPS_mode_set(int r);
extern int FIPS_mode(void);

/*
 * From openssl/err.h
 */

/* Functions */

extern void ERR_load_crypto_strings(void);
extern void ERR_free_strings(void);

/*
 * From openssl/evp.h
 */

/* Types */
typedef struct evp_cipher_st {
    int nid;
    int block_size;
    /* Default value for variable length ciphers */
    int key_len;
    int iv_len;
    /* Various flags */
    unsigned long flags;
    /* init key */
    int (*init) (EVP_CIPHER_CTX *ctx, const unsigned char *key,
                 const unsigned char *iv, int enc);
    /* encrypt/decrypt data */
    int (*do_cipher) (EVP_CIPHER_CTX *ctx, unsigned char *out,
                      const unsigned char *in, size_t inl);
    /* cleanup ctx */
    int (*cleanup) (EVP_CIPHER_CTX *);
    /* how big ctx->cipher_data needs to be */
    int ctx_size;
    /* Populate a ASN1_TYPE with parameters */
    int (*set_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Get parameters from a ASN1_TYPE */
    int (*get_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Miscellaneous operations */
    int (*ctrl) (EVP_CIPHER_CTX *, int type, int arg, void *ptr);
    /* Application data */
    void *app_data;
} EVP_CIPHER;

typedef struct evp_cipher_ctx_st {
    const EVP_CIPHER *cipher;
    ENGINE *engine;             /* functional reference if 'cipher' is
                                 * ENGINE-provided */
    int encrypt;                /* encrypt or decrypt */
    int buf_len;                /* number we have left */
    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
    unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    int num;                    /* used by cfb/ofb/ctr mode */
    void *app_data;             /* application stuff */
    int key_len;                /* May change for variable length cipher */
    unsigned long flags;        /* Various flags */
    void *cipher_data;          /* per EVP data */
    int final_used;
    int block_mask;
    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */
} EVP_CIPHER_CTX;


/* Functions */

extern void OpenSSL_add_all_algorithms(void);
extern void EVP_cleanup(void);

/* Allocate and free up a cipher context */
/*
 * A note - I am only including EVP_CIPHER_CTX_new() because ctx := new(EVP_CIPHER_CTX) is
 * causing a panic when I then pass ctx into EVP_CIPHER_CTX_init().  If someone can suggest
 * how to fix this, we should really remove EVP_CIPHER_CTX_new(), since my understanding is
 * that it is now deprecated from the OpenSSL API (it is not included in the manpages, either)
 */
extern EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
extern void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
extern int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);

extern int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

%apply void *VOIDSTRINGBUF { void *ptr };
extern int SET_TAG_GCM(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
%apply char *CHARBUF { char *ptr };
extern int GET_TAG_GCM(EVP_CIPHER_CTX *ctx, int type, int arg, char *ptr);

/*
 * Constants for EVP_CIPHER_CTX_ctrl()
 */
#define         EVP_CTRL_GCM_GET_TAG            0x10
#define         EVP_CTRL_GCM_SET_TAG            0x11

/*
 * As of now, for the standard use of EVP_EncryptInit_ex(), in which you pass null in for the engine,
 * you would pass in SwigcptrStruct_SS_engine_st(0) in go.  At some point we should make the API cleaner.
 * Example:
 * r := EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), SwigcptrStruct_SS_engine_st(0), "somekey", "someiv")
 */
extern int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
	 ENGINE *impl, unsigned char *key, unsigned char *iv);


%apply char *CHARBUF { unsigned char *out };
%apply int *OUTLEN { int *outl };
extern int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
         int *outl, unsigned char *in, int inl);

extern int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

extern int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
	 ENGINE *impl, unsigned char *key, unsigned char *iv);

extern int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
        int *outl, unsigned char *in, int inl); 

extern  int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
        int *outl);

/* Ciphers */
const EVP_CIPHER *EVP_aes_256_cbc(void);
const EVP_CIPHER *EVP_aes_256_cfb(void);
const EVP_CIPHER *EVP_aes_256_gcm(void);
const EVP_CIPHER *EVP_des_cbc(void);
