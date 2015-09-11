/*
 * SWIG interface file for libssl
 */
%module ssl
%{
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>
#include <openssl/bio.h>
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
#define SSL_CTX_set_options(ctx,op) \
        SSL_CTX_ctrl((ctx),SSL_CTRL_OPTIONS,(op),NULL);
long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);

long SSL_CTX_set_options() {
	SSL_CTX_ctrl((ctx),SSL_CTRL_OPTIONS,(op),NULL);
}


#define SSL_OP_NO_SSLv2                                 0x01000000L
#define SSL_OP_NO_SSLv3                                 0x02000000L
#define SSL_OP_NO_COMPRESSION                           0x00020000L
int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                  const char *CApath);
BIO_METHOD *BIO_f_ssl(void);
BIO *BIO_new_ssl(SSL_CTX *ctx, int client);
BIO *BIO_new_ssl_connect(SSL_CTX *ctx);
BIO *BIO_new_buffer_ssl_connect(SSL_CTX *ctx);
int BIO_ssl_copy_session_id(BIO *to, BIO *from);
void BIO_ssl_shutdown(BIO *ssl_bio);
int SSL_CTX_set_cipher_list(SSL_CTX *, const char *str);
int SSL_set_cipher_list(SSL *s, const char *str);

BIO_METHOD *BIO_s_connect(void);
BIO *BIO_new_connect(const char *host_port);
#define BIO_get_ssl(b,sslp)     BIO_ctrl(b,BIO_C_GET_SSL,0,(char *)sslp)
long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);
#define BIO_set_conn_hostname(b,name) BIO_ctrl(b,BIO_C_SET_CONNECT,0,(char *)name)
#define BIO_set_conn_port(b,port) BIO_ctrl(b,BIO_C_SET_CONNECT,1,(char *)port)
#define BIO_set_conn_ip(b,ip)     BIO_ctrl(b,BIO_C_SET_CONNECT,2,(char *)ip)
#define BIO_set_conn_int_port(b,port) BIO_ctrl(b,BIO_C_SET_CONNECT,3,(char *)port)
#define BIO_get_conn_hostname(b)  BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,0)
#define BIO_get_conn_port(b)      BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,1)
#define BIO_get_conn_ip(b)               BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,2)
#define BIO_get_conn_int_port(b) BIO_int_ctrl(b,BIO_C_GET_CONNECT,3,0)
#define BIO_set_nbio(b,n)       BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL)