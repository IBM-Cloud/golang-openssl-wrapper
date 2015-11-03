package digest

import (
	"io"
)

// Digest represents a single message digest.
// It implements the hash.Hash interface.
type Digest struct {
	io.Writer
	context EVP_MD_CTX
}

// Write stores the contents of p in the digest.
// p is a slice of bytes representing the message used to calculate the checksum/hash.
// Write returns the number of bytes written and an error (which is always nil).
func (d *Digest) Write(p []byte) (int, error) {
	ret := EVP_DigestUpdate(d.context, string(p), int64(len(p)))
	if ret != 1 {
		return 0, nil
	}
	return len(p), nil
}

// Sum returns the current checksum value for the Digest.
// If p is nil, the bare checksum is returned.
// If p is not nil, the checksum is appended to p, which is then returned.
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

// Size returns the the length of the Digest's checksum (what Sum() will return)
func (d *Digest) Size() int {
	return EVP_MD_CTX_size(d.context)
}

// BlockSize returns the underlying block size for the Digest.
func (d *Digest) BlockSize() int {
	return EVP_MD_CTX_block_size(d.context)
}

// NewSHA256 returns a pointer to a Digest configured to use the SHA256 algorithm.
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
