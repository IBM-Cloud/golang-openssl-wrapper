%include "typemaps.i"

/*
 * Use for writeable buffers of type char* passed as arguments
 */
%typemap(gotype) char *CHARBUF %{[]byte%}
%typemap(in) char *CHARBUF {
    if ($input.len <= 0 || $input.cap <= 0) $1 = NULL;
    else $1 = (char*)malloc($input.cap);
}
%typemap(argout) char *CHARBUF {
    if ($1 != NULL) memcpy($input.array, $1, $input.cap);
}
%typemap(freearg) char *CHARBUF {
    if ($1 != NULL) free($1);
}

%typemap(gotype) void *VOIDSTRINGBUF %{string%}
%typemap(in) void *VOIDSTRINGBUF {
    $1 = (void*)malloc($input.n);
    memcpy($1, $input.p, $input.n);
}
%typemap(argout) void *VOIDSTRINGBUF {
    $input.p = $1;
}
%typemap(freearg) void *VOIDSTRINGBUF {
    free($1);
}

%typemap(gotype) int *OUTLEN %{*int%}
