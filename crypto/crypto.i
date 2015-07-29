/* SWIG interface file for openssl/evp.h */
%insert(go_wrapper) %{
// #cgo LDFLAGS: -lcrypto
%}
%module crypto
%{
#include <openssl/crypto.h>
#include <openssl/evp.h>
%}

/* From openssl/crypto.h */
extern int FIPS_mode_set(int r);

/* From openssl/evp.h */
extern void OpenSSL_add_all_algorithms(void);
extern void EVP_cleanup(void);
