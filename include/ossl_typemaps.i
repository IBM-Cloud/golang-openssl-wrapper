%include "typemaps.i"

%typemap(gotype) char *outbuf %{[]byte%}
%typemap(in) char *outbuf {
    if ($input.len <= 0 || $input.cap <= 0) $1 = NULL;
    else $1 = (char*)malloc($input.cap);
}
%typemap(argout) char *outbuf {
    if ($1 != NULL) memcpy($input.array, $1, $input.cap);
}
%typemap(freearg) char *outbuf {
    if ($1 != NULL) free($1);
}

%typemap(gotype) int *outl %{*int%}
