package digest_test

import (
	"github.com/ScarletTanager/openssl/crypto"
	. "github.com/ScarletTanager/openssl/digest"
	"github.com/ScarletTanager/openssl/rand"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
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
	})
})
