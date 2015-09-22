%module bio

%{
#include <openssl/bio.h>
#include <openssl/ssl.h>
%}

/*
 * From openssl/bio.h
 */

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

/* Functions and macros */

BIO_METHOD *   BIO_s_mem(void);
BIO_METHOD *   BIO_s_file(void);

extern int BIO_free(BIO *a);
extern BIO *BIO_new(BIO_METHOD *method);
// extern int BIO_make_bio_pair(BIO *bp1, BIO *bp2);

/* File */
extern BIO *BIO_new_file(const char *filename, const char *mode);
extern int BIO_puts(BIO *bp, const char *buf);

int BIO_read_filename(BIO *b, char *name);
int BIO_write_filename(BIO *b, char *name);
int BIO_append_filename(BIO *b, char *name);
int BIO_rw_filename(BIO *b, char *name);

int BIO_printf(BIO *bio, const char *format, ...);

%typemap(gotype) char *outbuf %{[]byte%}
%typemap(in) char *outbuf {
	char tbuf[sizeof($input.array)*sizeof(char*)];
	$1 = (char *)&tbuf;
}

%typemap(argout) char *outbuf {
	memcpy($input.array, $1, $input.cap);
	$input.len = strlen($1);
}

extern int BIO_gets(BIO *bp, char *outbuf, int size);
extern long BIO_seek(BIO *bp, int ofs);
extern long BIO_flush(BIO *bp);

%typemap(gotype) void *buf %{[]byte%}
%typemap(in) void *buf {
    char tbuf[sizeof($input.array)*sizeof(char*)];
    $1 = (void*)&tbuf;
}
%typemap(argout) void *buf {
    memcpy($input.array, $1, $input.cap);
    $input.len = strlen($1);
}

int BIO_read(BIO *b, void *buf, int len);

/* Connect */
// BIO_METHOD *BIO_s_connect(void);
extern BIO *BIO_new_connect(char *name);
extern long BIO_do_connect(BIO *bp);
// extern long BIO_do_handshake(BIO *bp);

/*
 * From openssl/ssl.h
 */
// More BIO_ctrl() macros...
extern long BIO_set_conn_hostname(BIO *bp, char *name);
extern char *BIO_get_conn_hostname(BIO *bp);
extern long BIO_get_ssl(BIO *bp, SSL *sp);
extern long BIO_set_ssl_mode(BIO *bp, int client);
/* Functions */

BIO *BIO_new_ssl_connect(SSL_CTX *ctx);
BIO_METHOD *BIO_f_ssl(void);
// BIO_METHOD *BIO_f_ssl(void);
// BIO *BIO_new_ssl(SSL_CTX *ctx, int client);
// BIO *BIO_new_buffer_ssl_connect(SSL_CTX *ctx);
// int BIO_ssl_copy_session_id(BIO *to, BIO *from);
// void BIO_ssl_shutdown(BIO *ssl_bio);
// int SSL_CTX_set_cipher_list(SSL_CTX *, const char *str);
// int SSL_set_cipher_list(SSL *s, const char *str);

// BIO_METHOD *BIO_s_connect(void);
// BIO *BIO_new_connect(const char *host_port);
// #define BIO_get_ssl(b,sslp)     BIO_ctrl(b,BIO_C_GET_SSL,0,(char *)sslp)
// long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);
// #define BIO_set_conn_hostname(b,name) BIO_ctrl(b,BIO_C_SET_CONNECT,0,(char *)name)
// #define BIO_set_conn_port(b,port) BIO_ctrl(b,BIO_C_SET_CONNECT,1,(char *)port)
// #define BIO_set_conn_ip(b,ip)     BIO_ctrl(b,BIO_C_SET_CONNECT,2,(char *)ip)
// #define BIO_set_conn_int_port(b,port) BIO_ctrl(b,BIO_C_SET_CONNECT,3,(char *)port)
// #define BIO_get_conn_hostname(b)  BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,0)
// #define BIO_get_conn_port(b)      BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,1)
// #define BIO_get_conn_ip(b)               BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,2)
// #define BIO_get_conn_int_port(b) BIO_int_ctrl(b,BIO_C_GET_CONNECT,3,0)
// #define BIO_set_nbio(b,n)       BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL)
