/* SWIG interface file for openssl/x509.h */
%module x509
%{
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
%}

%include <typemaps.i>

/*
 * From openssl/x509.h
 */

// X509 *X509_new(void);
// void X509_free(X509 *a);

// typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);

// %typemap(gotype) void *u %{string%}
// %typemap(gotype) X509 **x %{*X509%}

// // TODO[Colton]: Works with nil X509**, doesn't work when supplied existing X509**
// // that was created with X509_new.
// X509 *PEM_read_bio_X509(BIO *b, X509 **x, pem_password_cb *cb, void *u);
