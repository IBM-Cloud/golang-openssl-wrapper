%module bio

%{
#include <openssl/bio.h>
#include <openssl/ssl.h>
%}

/*
 * From openssl/bio.h
 */

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

/* General BIO */
BIO_METHOD *   BIO_s_mem(void);
BIO_METHOD *   BIO_s_file(void);

extern int BIO_free(BIO *a);
extern void BIO_free_all(BIO *a);
extern BIO *BIO_new(BIO_METHOD *method);
// extern int BIO_make_bio_pair(BIO *bp1, BIO *bp2);

/* File */
extern BIO *BIO_new_file(const char *filename, const char *mode);
extern int BIO_puts(BIO *bp, const char *buf);

int BIO_read_filename(BIO *b, char *name);
int BIO_write_filename(BIO *b, char *name);
int BIO_append_filename(BIO *b, char *name);
int BIO_rw_filename(BIO *b, char *name);

BIO *BIO_new(BIO_METHOD *method);
int BIO_free(BIO *a);
// int BIO_make_bio_pair(BIO *bp1, BIO *bp2);
int BIO_puts(BIO *bp, const char *buf);
int BIO_printf(BIO *bio, const char *format, ...);
long BIO_seek(BIO *bp, int ofs);
long BIO_flush(BIO *bp);
int BIO_reset(BIO *b);

%typemap(gotype) char *outbuf %{[]byte%}
%typemap(in) char *outbuf {
    $1 = (char*)malloc($input.cap);
}
%typemap(argout) char *outbuf {
    memcpy($input.array, $1, $input.cap);
}
%typemap(freearg) char *outbuf {
    free($1);
}

int BIO_gets(BIO *bp, char *outbuf, int size);

%apply char *outbuf { void *buf }

int BIO_read(BIO *b, void *buf, int len);

%typemap(gotype) const void *buf %{string%}
%typemap(in) const void *buf {
    $1 = (void*)malloc($input.n);
    memcpy($1, $input.p, $input.n);
}
%typemap(argout) const void *buf {
    $input.p = $1;
}
%typemap(freearg) const void *buf {
    free($1);
}

int BIO_write(BIO *b, const void *buf, int len);


/* File storage */
BIO_METHOD *   BIO_s_file(void);
BIO *BIO_new_file(const char *filename, const char *mode);

int BIO_read_filename(BIO *b, char *name);
int BIO_write_filename(BIO *b, char *name);
int BIO_append_filename(BIO *b, char *name);
int BIO_rw_filename(BIO *b, char *name);

/* Connect */
BIO_METHOD *BIO_s_connect(void);
extern BIO *BIO_new_connect(char *name);
extern long BIO_do_connect(BIO *bp);
extern long BIO_do_handshake(BIO *bp);

long BIO_set_conn_hostname(BIO *b, char *name);
long BIO_set_conn_port(BIO *b, char *port);
// long BIO_set_conn_ip(BIO *b, char *ip);
// long BIO_set_conn_int_port(BIO *b, char *port);
char *BIO_get_conn_hostname(BIO *b);
char *BIO_get_conn_port(BIO *b);
// char *BIO_get_conn_ip(BIO *b, dummy);
// long BIO_get_conn_int_port(BIO *b, int port);

/*
 * From openssl/ssl.h
 */
// More BIO_ctrl() macros...
long BIO_get_ssl(BIO *bp, SSL *sp);
long BIO_set_ssl_mode(BIO *bp, int client);

BIO_METHOD *BIO_f_ssl(void);
BIO *BIO_new_ssl_connect(SSL_CTX *ctx);
// long BIO_do_handshake(BIO *bp);
// BIO_METHOD *BIO_f_ssl(void);
// BIO *BIO_new_ssl(SSL_CTX *ctx, int client);
// BIO *BIO_new_buffer_ssl_connect(SSL_CTX *ctx);
// int BIO_ssl_copy_session_id(BIO *to, BIO *from);
// void BIO_ssl_shutdown(BIO *ssl_bio);
// int SSL_CTX_set_cipher_list(SSL_CTX *, const char *str);
// int SSL_set_cipher_list(SSL *s, const char *str);

// #define BIO_get_ssl(b,sslp)     BIO_ctrl(b,BIO_C_GET_SSL,0,(char *)sslp)
