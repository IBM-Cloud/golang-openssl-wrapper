package digest_test

import (
	"bytes"
	"github.com/IBM-Bluemix/golang-openssl-wrapper/crypto"
	. "github.com/IBM-Bluemix/golang-openssl-wrapper/digest"
	"github.com/IBM-Bluemix/golang-openssl-wrapper/rand"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"strings"
)

var _ = Describe("Digest", func() {
	Context("Creating and destroying a context", func() {
		It("Creates and destroys using the built-in (de)allocation mechanism", func() {
			ctx := EVP_MD_CTX_create()
			Expect(ctx).NotTo(BeNil())
			EVP_MD_CTX_init(ctx)
			EVP_MD_CTX_destroy(ctx)
		})

		It("Creates and destroys using user-controlled (de)allocation", func() {
			ctx := Malloc_EVP_MD_CTX()
			Expect(ctx).NotTo(BeNil())
			EVP_MD_CTX_init(ctx)
			Expect(EVP_MD_CTX_cleanup(ctx)).To(Equal(1))
			Free_EVP_MD_CTX(ctx)
		})

		It("Initializes and deallocates directly", func() {
			ctx := Malloc_EVP_MD_CTX()
			Expect(EVP_DigestInit(ctx, EVP_sha256())).To(Equal(1))
			buf := make([]byte, 50)
			var l uint
			Expect(EVP_DigestFinal(ctx, buf, &l)).To(Equal(1))
		})
	})

	Context("With FIPS mode enabled", func() {
		var ctx EVP_MD_CTX

		BeforeEach(func() {
			crypto.FIPS_mode_set(1)
			Expect(crypto.FIPS_mode()).To(Equal(1))
			ctx = Malloc_EVP_MD_CTX()
			Expect(ctx).NotTo(BeNil())
			EVP_MD_CTX_init(ctx)
		})

		AfterEach(func() {
			crypto.FIPS_mode_set(0)
			Expect(crypto.FIPS_mode()).To(Equal(0))
			EVP_MD_CTX_cleanup(ctx)
			Free_EVP_MD_CTX(ctx)
		})

		It("Allows use of SHA* but disallows MD5", func() {
			Expect(EVP_DigestInit_ex(ctx, EVP_md5(), SwigcptrStruct_SS_engine_st(0))).To(Equal(0))
			Expect(EVP_DigestInit_ex(ctx, EVP_sha256(), SwigcptrStruct_SS_engine_st(0))).To(Equal(1))
		})
	})

	Context("Hashing binary data", func() {
		Context("Using the OpenSSL digest API", func() {
			var ctx EVP_MD_CTX
			var data []byte
			var buf []byte
			var seqlen int
			var l uint

			BeforeEach(func() {
				ctx = Malloc_EVP_MD_CTX()
				Expect(ctx).NotTo(BeNil())
				EVP_MD_CTX_init(ctx)
				Expect(EVP_DigestInit_ex(ctx, EVP_sha256(), SwigcptrStruct_SS_engine_st(0))).To(Equal(1))

				seqlen = 50
				data = make([]byte, seqlen)
				Expect(rand.RAND_bytes(data, seqlen)).To(Equal(1))
				buf = make([]byte, seqlen)
			})

			AfterEach(func() {
				EVP_MD_CTX_cleanup(ctx)
				Free_EVP_MD_CTX(ctx)
			})

			It("Returns the correct digest size", func() {
				s1 := EVP_MD_CTX_size(ctx)
				s2 := EVP_MD_size(EVP_sha256())
				Expect(s1).To(BeNumerically(">", 0))
				Expect(s2).To(Equal(s1))
			})

			It("Returns the correct block size", func() {
				s1 := EVP_MD_CTX_block_size(ctx)
				s2 := EVP_MD_block_size(EVP_sha256())
				Expect(s1).To(BeNumerically(">", 0))
				Expect(s2).To(Equal(s1))
			})

			It("Produces identical hash values from the same binary data", func() {
				ctx2 := Malloc_EVP_MD_CTX()
				buf2 := make([]byte, seqlen)
				var l2 uint

				Expect(EVP_MD_CTX_copy(ctx2, ctx)).To(Equal(1))
				Expect(EVP_DigestUpdate(ctx, string(data), int64(seqlen))).To(Equal(1))
				Expect(EVP_DigestFinal_ex(ctx, buf, &l)).To(Equal(1))

				Expect(EVP_DigestUpdate(ctx2, string(data), int64(seqlen))).To(Equal(1))
				Expect(EVP_DigestFinal_ex(ctx2, buf2, &l2)).To(Equal(1))

				h1 := string(buf)
				h2 := string(buf2)

				Expect(len(h1)).To(BeNumerically(">", 0))
				Expect(len(h2)).To(BeNumerically(">", 0))
				Expect(h2).To(Equal(h1))

				EVP_MD_CTX_cleanup(ctx2)
				Free_EVP_MD_CTX(ctx2)
			})
		}) // END Context for OpenSSL digest

		Context("Emulating the golang native crypto/sha256 API", func() {
			var (
				ret        int
				err        error
				data, key1 []byte
				seqlen     int
				hasher1    *Digest
			)

			BeforeEach(func() {
				seqlen = 50
				data = make([]byte, seqlen)
				Expect(rand.RAND_bytes(data, seqlen)).To(Equal(1))

				hasher1 = NewSHA256()
				Expect(hasher1).NotTo(BeNil())
				ret, err = hasher1.Write(data)
				Expect(ret).To(Equal(len(data)))
				Expect(err).NotTo(HaveOccurred())
				key1 = hasher1.Sum(nil)

				Expect(len(key1)).To(BeNumerically(">", 0))
			})

			It("Returns the correct digest length", func() {
				s := EVP_MD_size(EVP_sha256())
				Expect(s).To(BeNumerically(">", 0))
				Expect(hasher1.Size()).To(Equal(s))
			})

			It("Returns the correct block size", func() {
				s := EVP_MD_block_size(EVP_sha256())
				Expect(s).To(BeNumerically(">", 0))
				Expect(hasher1.BlockSize()).To(Equal(s))
			})

			It("Produces identical hash values from the same binary data", func() {
				hasher2 := NewSHA256()
				Expect(hasher2).NotTo(BeNil())
				ret, err = hasher2.Write(data)
				Expect(ret).To(Equal(len(data)))
				Expect(err).NotTo(HaveOccurred())
				key2 := hasher2.Sum(nil)

				Expect(len(key2)).To(BeNumerically(">", 0))

				Expect(bytes.Equal(key1, key2)).To(BeTrue())
			})

			It("Produces different hash values from different inputs", func() {
				data2 := make([]byte, seqlen)
				Expect(rand.RAND_bytes(data2, seqlen)).To(Equal(1))

				hasher2 := NewSHA256()
				Expect(hasher2).NotTo(BeNil())
				ret, err = hasher2.Write(data2)
				Expect(ret).To(Equal(len(data2)))
				Expect(err).NotTo(HaveOccurred())
				key2 := hasher2.Sum(nil)

				Expect(len(key2)).To(BeNumerically(">", 0))

				Expect(bytes.Equal(key1, key2)).To(BeFalse())
			})

			It("Appends to an existing hash key", func() {
				newKey := hasher1.Sum(key1)
				Expect(strings.HasPrefix(string(newKey), string(key1))).To(BeTrue())
			})
		})
	})
})
