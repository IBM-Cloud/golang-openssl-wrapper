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
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
%}

/* We may not need this, but we'll keep it here just in case */
%import "openssl/ossl_typ.h"
%include <typemaps.i>

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
 * From openssl/engine.h
 */

/* Types */

typedef struct engine_st ENGINE;

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

// %malloc(EVP_CIPHER_CTX)
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

/*
 * As of now, for the standard use of EVP_EncryptInit_ex(), in which you pass null in for the engine,
 * you would pass in SwigcptrStruct_SS_engine_st(0) in go.  At some point we should make the API cleaner.
 * Example:
 * r := EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), SwigcptrStruct_SS_engine_st(0), "somekey", "someiv")
 */
extern int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
	 ENGINE *impl, unsigned char *key, unsigned char *iv);

%apply unsigned char *OUTPUT {unsigned char *out};
%apply int *OUTPUT {int *outl};
/* %rename(wrapped_EVP_EncryptUpdate) EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int intl); */
extern int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
         int *outl, unsigned char *in, int inl);
/* %insert(go_wrapper) %{
func EVP_EncryptUpdate(ctx EVP_CIPHER_CTX, plaintext string) (encrypted string, err error) {
	buf_encrypt := make([]byte, len(plaintext) + ctx.GetCipher().GetBlock_size())
	c_len := []int{0}
	r := Wrapped_EVP_EncryptUpdate(ctx, buf_encrypt, c_len, plaintext, len(plaintext))
	if (1 != r) {
		err := errors.New("Encryption failed")
		return "", err
	}

	return bytes.NewBuffer(buf_encrypt).String(), nil
}
%} */
extern int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

extern int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
	 ENGINE *impl, unsigned char *key, unsigned char *iv);
// %apply unsigned char *OUTPUT {unsigned char *in}
/*%apply (char *STRING, int len) {(unsigned char *in, int inl)}
extern int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
         int *outl, unsigned char *in, int inl); */
/* Ciphers */
const EVP_CIPHER *EVP_aes_256_cbc(void);
const EVP_CIPHER *EVP_aes_256_cfb(void);
const EVP_CIPHER *EVP_des_cbc(void);
