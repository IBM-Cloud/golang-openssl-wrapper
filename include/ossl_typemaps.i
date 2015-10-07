%include "typemaps.i"

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

%typemap(gotype) int *outl %{*int%}
