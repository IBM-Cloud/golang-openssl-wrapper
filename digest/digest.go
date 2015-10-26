package digest

// #cgo CFLAGS: -I/usr/local/ssl/include
// #cgo LDFLAGS: -L /usr/local/ssl/lib -lcrypto
import "C"

import (
	"io"
)

type Digest struct {
	io.Writer
	context EVP_MD_CTX
}

func (d *Digest) Write(p []byte) (int, error) {
	ret := EVP_DigestUpdate(d.context, string(p), int64(len(p)))
	if ret != 1 {
		return 0, nil
	}
	return len(p), nil
}

func (d *Digest) Sum(p []byte) []byte {
	var (
		l uint
	)
	/*
	 * We make a copy so that the user can still write/sum using the original
	 */
	ctx := Malloc_EVP_MD_CTX()
	EVP_MD_CTX_copy(ctx, d.context)

	buf := make([]byte, EVP_MAX_MD_SIZE)
	EVP_DigestFinal_ex(ctx, buf, &l)

	Free_EVP_MD_CTX(ctx)

	if p != nil {
		return append(p, buf...)
	}

	return buf
}

func NewSHA256() *Digest {
	ctx := EVP_MD_CTX_create()

	if ctx == nil {
		return nil
	}

	EVP_MD_CTX_init(ctx)
	EVP_DigestInit_ex(ctx, EVP_sha256(), SwigcptrStruct_SS_engine_st(0))

	return &Digest{
		context: ctx,
	}
}

// func (d *Digest) ctx() EVP_MD_CTX {
// 	return *d.context
// }
