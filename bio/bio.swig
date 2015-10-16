%module bio

%{
#include <openssl/bio.h>
#include <openssl/ssl.h>
%}

%include "typemaps.i"
%include "../include/ossl_typemaps.i"

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

%apply char *CHARBUF { char *outbuf };
int BIO_gets(BIO *bp, char *outbuf, int size);

%apply char *CHARBUF { void *buf };
int BIO_read(BIO *b, void *buf, int len);

%apply void *VOIDSTRINGBUF { const void *buf };
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
