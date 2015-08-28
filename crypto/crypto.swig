/* SWIG interface file for openssl/crypto.h */
%module crypto
%{
#include <openssl/crypto.h>
%}

/* We may not need this, but we'll keep it here just in case */
%include <typemaps.i>

/* From openssl/crypto.h */
extern int FIPS_mode_set(int r);
