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
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
%}

/* We may not need this, but we'll keep it here just in case */
%import "openssl/ossl_typ.h"
%include "typemaps.i"

/*
 * From openssl/bio.h
 */

/* Constants */

/* connect BIO stuff */
#define BIO_CONN_S_BEFORE               1
#define BIO_CONN_S_GET_IP               2
#define BIO_CONN_S_GET_PORT             3
#define BIO_CONN_S_CREATE_SOCKET        4
#define BIO_CONN_S_CONNECT              5
#define BIO_CONN_S_OK                   6
#define BIO_CONN_S_BLOCKED_CONNECT      7
#define BIO_CONN_S_NBIO                 8
/*
 * #define BIO_CONN_get_param_hostname BIO_ctrl
 */

#define BIO_C_SET_CONNECT                       100
#define BIO_C_DO_STATE_MACHINE                  101
#define BIO_C_SET_NBIO                          102
#define BIO_C_SET_PROXY_PARAM                   103
#define BIO_C_SET_FD                            104
#define BIO_C_GET_FD                            105
#define BIO_C_SET_FILE_PTR                      106
#define BIO_C_GET_FILE_PTR                      107
#define BIO_C_SET_FILENAME                      108
#define BIO_C_SET_SSL                           109
#define BIO_C_GET_SSL                           110
#define BIO_C_SET_MD                            111
#define BIO_C_GET_MD                            112
#define BIO_C_GET_CIPHER_STATUS                 113
#define BIO_C_SET_BUF_MEM                       114
#define BIO_C_GET_BUF_MEM_PTR                   115
#define BIO_C_GET_BUFF_NUM_LINES                116
#define BIO_C_SET_BUFF_SIZE                     117
#define BIO_C_SET_ACCEPT                        118
#define BIO_C_SSL_MODE                          119
#define BIO_C_GET_MD_CTX                        120
#define BIO_C_GET_PROXY_PARAM                   121
#define BIO_C_SET_BUFF_READ_DATA                122/* data to read first */
#define BIO_C_GET_CONNECT                       123
#define BIO_C_GET_ACCEPT                        124
#define BIO_C_SET_SSL_RENEGOTIATE_BYTES         125
#define BIO_C_GET_SSL_NUM_RENEGOTIATES          126
#define BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT       127
#define BIO_C_FILE_SEEK                         128
#define BIO_C_GET_CIPHER_CTX                    129
#define BIO_C_SET_BUF_MEM_EOF_RETURN            130/* return end of input
                                                     * value */
#define BIO_C_SET_BIND_MODE                     131
#define BIO_C_GET_BIND_MODE                     132
#define BIO_C_FILE_TELL                         133
#define BIO_C_GET_SOCKS                         134
#define BIO_C_SET_SOCKS                         135

#define BIO_C_SET_WRITE_BUF_SIZE                136/* for BIO_s_bio */
#define BIO_C_GET_WRITE_BUF_SIZE                137
#define BIO_C_MAKE_BIO_PAIR                     138
#define BIO_C_DESTROY_BIO_PAIR                  139
#define BIO_C_GET_WRITE_GUARANTEE               140
#define BIO_C_GET_READ_REQUEST                  141
#define BIO_C_SHUTDOWN_WR                       142
#define BIO_C_NREAD0                            143
#define BIO_C_NREAD                             144
#define BIO_C_NWRITE0                           145
#define BIO_C_NWRITE                            146
#define BIO_C_RESET_READ_REQUEST                147
#define BIO_C_SET_MD_CTX                        148

#define BIO_C_SET_PREFIX                        149
#define BIO_C_GET_PREFIX                        150
#define BIO_C_SET_SUFFIX                        151
#define BIO_C_GET_SUFFIX                        152

#define BIO_C_SET_EX_ARG                        153
#define BIO_C_GET_EX_ARG                        154

/* Types */
typedef struct bio_st {
    BIO_METHOD *method;
    /* bio, mode, argp, argi, argl, ret */
    long (*callback) (struct bio_st *, int, const char *, int, long, long);
    char *cb_arg;               /* first argument for the callback */
    int init;
    int shutdown;
    int flags;                  /* extra storage */
    int retry_reason;
    int num;
    void *ptr;
    struct bio_st *next_bio;    /* used by filter BIOs */
    struct bio_st *prev_bio;    /* used by filter BIOs */
    int references;
    unsigned long num_read;
    unsigned long num_write;
    CRYPTO_EX_DATA ex_data;
} BIO;
typedef struct bio_method_st BIO_METHOD;

/* Functions and macros */

extern int BIO_free(BIO *a);

/* File */
extern BIO *BIO_new_file(const char *filename, const char *mode);
extern int BIO_puts(BIO *bp, const char *buf);
//%apply unsigned char *OUTPUT {char *buf}
%typemap(gotype) char *outbuf %{[]byte%}
%typemap(in) char *outbuf {
	char tbuf[sizeof($input)];
	$1 = (char *)&tbuf;
}

%typemap(argout) char *outbuf {
//	printf("We have: %s\n", $1);
	memcpy($input.array, $1, $input.cap);
	$input.len = strlen($1);
}
//extern int BIO_gets(BIO *bp, char *buf, int size);
extern int BIO_gets(BIO *bp, char *outbuf, int size);
extern long BIO_seek(BIO *bp, int ofs);
extern long BIO_flush(BIO *bp);

/* Connect */
extern BIO *BIO_new_connect(char *name);
extern long BIO_do_connect(BIO *bp);

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
