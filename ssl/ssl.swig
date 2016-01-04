/*
 * SWIG interface file for libssl
 */
%module ssl
%{
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>
#include <openssl/bio.h>
#include <openssl/tls1.h>
#include <openssl/x509.h>
%}

%include "../include/ossl_typemaps.i"

#define SSL_FILETYPE_PEM    1
#define SSL_FILETYPE_ASN1   2

/*
 * Conditional compilation directives for stuff we don't want to support yet
 */

#define OPENSSL_NO_KRB5

void SSL_load_error_strings(void);
int SSL_library_init(void);

SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
void SSL_CTX_free(SSL_CTX *ctx);

const SSL_METHOD *SSLv3_method(void); /* SSLv3 */
const SSL_METHOD *SSLv3_server_method(void); /* SSLv3 */
const SSL_METHOD *SSLv3_client_method(void); /* SSLv3 */

const SSL_METHOD *SSLv23_method(void); /* SSLv3 */
const SSL_METHOD *SSLv23_server_method(void); /* SSLv3 */
const SSL_METHOD *SSLv23_client_method(void); /* SSLv3 */

// The at https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_new.html say
// that the SSLv23_*method functions are deprecated, use TLS* instead, but
// TLS* is not present in the most recent ssl.h nor in libssl itself.  be
// wary of OpenSSL docs...
// const SSL_METHOD *TLS_method(void);
// const SSL_METHOD *TLS_server_method(void);
// const SSL_METHOD *TLS_client_method(void);

/* Constants for the mode argument to SSL_CTX_set_verify */
#define SSL_VERIFY_NONE                 0x00
#define SSL_VERIFY_PEER                 0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
#define SSL_VERIFY_CLIENT_ONCE          0x04

void SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
                        int (*callback) (int, X509_STORE_CTX *));
void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth);

long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);

// long SSL_CTX_set_options(SSL_CTX *ctx, long op);


// #define SSL_OP_NO_SSLv2                                 0x01000000L
// #define SSL_OP_NO_SSLv3                                 0x02000000L
// #define SSL_OP_NO_COMPRESSION                           0x00020000L

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                    const char *CApath);

SSL *SSL_new(SSL_CTX *ctx);
int SSL_accept(SSL *ssl);

void SSL_free(SSL *ssl);
int SSL_set_cipher_list(SSL *ssl, const char *str);
long SSL_set_tlsext_host_name(SSL *ssl, char *name);
int SSL_connect(SSL *ssl);
int SSL_get_error(SSL *ssl, int ret);
int SSL_set_fd(SSL *ssl, int fd);
int SSL_get_fd(SSL *ssl);

int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_check_private_key(const SSL_CTX *ctx);

%typemap(gotype) const void *buf %{[]byte%}
int SSL_write(SSL *ssl, const void *buf, int num);

%apply char *CHARBUF { void *buf };
int SSL_read(SSL *ssl, void *buf, int num);
