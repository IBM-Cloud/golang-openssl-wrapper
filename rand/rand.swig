%module rand

%{
#include <openssl/rand.h>
%}

%include "../include/ossl_typemaps.i"

%apply char *CHARBUF { unsigned char *outbuf };

// %typemap(gotype) (unsigned char *outbuf, int num) %{[]byte, int%}
// %typemap(gotype) unsigned char *outbuf %{[]byte%}

// %typemap(in) (unsigned char *outbuf) {
//    $1 = (char*)malloc($input.cap);
// }
// %typemap(argout) (unsigned char *outbuf) {
//     memcpy($input.array, $1, $input.cap);
// }
// %typemap(freearg) (unsigned char *outbuf) {
//     free($1);
// }
int  RAND_bytes(unsigned char *outbuf, int num);