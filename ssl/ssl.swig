/*
 * SWIG interface file for libssl
 */
%module ssl
%{
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>
%}
typedef struct ssl_ctx_st SSL_CTX;

int SSL_library_init(void);
const SSL_METHOD *SSLv3_method(void); /* SSLv3 */
const SSL_METHOD *SSLv3_server_method(void); /* SSLv3 */
const SSL_METHOD *SSLv3_client_method(void); /* SSLv3 */
SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
#define SSL_VERIFY_NONE                 0x00
#define SSL_VERIFY_PEER                 0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
#define SSL_VERIFY_CLIENT_ONCE          0x04
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
                        int (*callback) (int, X509_STORE_CTX *));
void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth);
#define SSL_OP_NO_SSLv2                                 0x01000000L
#define SSL_OP_NO_SSLv3                                 0x02000000L
#define SSL_OP_NO_COMPRESSION                           0x00020000L